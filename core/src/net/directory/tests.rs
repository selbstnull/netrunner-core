//! Тесты каталога: формат, правила допуска, обмен и поведение сети из десятков
//! узлов под атакой (подделки, повторы, засорение с одной сети, мосты).

use super::*;
use rand::{RngExt, SeedableRng};

const T0: u64 = 1_800_000_000;

fn cfg(host: &str) -> DirectoryConfig {
    DirectoryConfig {
        store: StoreConfig {
            allow_private: true,
            ..Default::default()
        },
        advertise: vec![Endpoint {
            kind: EndpointKind::Tcp,
            host: host.into(),
            port: 443,
        }],
        decoy_sni: "www.example.org".into(),
        ..Default::default()
    }
}

fn dir_with(seed: u8, host: &str, swarm: &SwarmKey, mutate: impl FnOnce(&mut DirectoryConfig)) -> Directory {
    let mut c = cfg(host);
    mutate(&mut c);
    Directory::new(SwarmIdentity::from_static_private([seed; 32]), swarm.clone(), c, T0)
}

fn dir(seed: u8, host: &str, swarm: &SwarmKey) -> Directory {
    dir_with(seed, host, swarm, |_| {})
}

fn swarm() -> SwarmKey {
    SwarmKey::from_bytes([9u8; 32])
}

/// Один полный обмен A → B (байты, как по проводу).
fn exchange(a: &Directory, b: &Directory, now: u64) -> (Stats, Stats) {
    let digest = a.begin_exchange(now);
    let Ok(Handled::Reply(reply)) = b.handle_incoming(&digest, now) else {
        panic!("responder must reply to a digest")
    };
    let (sa, push) = a.complete_exchange(&reply, now).expect("reply is valid");
    let sb = match push {
        Some(p) => match b.handle_incoming(&p, now).expect("push accepted") {
            Handled::Absorbed(s) => s,
            Handled::Reply(_) => panic!("a push has no reply"),
        },
        None => Stats::default(),
    };
    (sa, sb)
}

// ───────────────────────────── descriptor ──────────────────────────────────

fn sample(seed: u8, host: &str) -> NodeDescriptor {
    dir(seed, host, &swarm()).own(T0)
}

#[test]
fn descriptor_round_trips_and_verifies() {
    let d = sample(1, "10.0.0.1");
    let bytes = d.encode();
    let back = NodeDescriptor::decode(&bytes).unwrap();
    assert_eq!(back, d);
    assert_eq!(back.verify(T0 + 1, true), Ok(()));
    assert_eq!(d.node_id, derive_node_id(&d.sign_pub, &d.static_pub));
}

#[test]
fn every_signed_field_is_protected() {
    let d = sample(1, "10.0.0.1");
    let bytes = d.encode();
    // Меняем по одному байту везде, кроме самой подписи: запись либо не разбирается,
    // либо не проходит проверку (подпись/личность/сроки/адрес).
    let sig_start = bytes.len() - 64;
    for i in 0..sig_start {
        let mut b = bytes.clone();
        b[i] ^= 0x01;
        if let Ok(x) = NodeDescriptor::decode(&b) {
            assert!(x.verify(T0 + 1, true).is_err(), "byte {i} is not covered by the signature");
        }
    }
    // и подпись
    for i in sig_start..bytes.len() {
        let mut b = bytes.clone();
        b[i] ^= 0x80;
        let x = NodeDescriptor::decode(&b).unwrap();
        assert_eq!(x.verify(T0 + 1, true), Err(DescriptorError::BadSignature));
    }
}

#[test]
fn identity_binds_both_keys() {
    let mut d = sample(1, "10.0.0.1");
    d.static_pub = sample(2, "10.0.0.2").static_pub; // чужой статический ключ под своей подписью
    assert_eq!(d.verify(T0 + 1, true), Err(DescriptorError::BadNodeId));
}

#[test]
fn validity_rules() {
    let id = SwarmIdentity::from_static_private([3; 32]);
    let ep = vec![Endpoint { kind: EndpointKind::Tcp, host: "10.0.0.3".into(), port: 443 }];
    let mk = |issued: u64, secs: u64| {
        NodeDescriptor::sign(&id.signing, id.static_pub, Roles(Roles::RELAY), 1, (2, 6), 1, issued, secs, String::new(), ep.clone())
    };
    // истекла
    assert_eq!(mk(T0, 100).verify(T0 + 101, true), Err(DescriptorError::Expired));
    // выпущена в будущем
    assert_eq!(mk(T0 + 10_000, 100).verify(T0, true), Err(DescriptorError::FromTheFuture));
    // слегка из будущего (расхождение часов) допустимо
    assert_eq!(mk(T0 + 60, 100).verify(T0, true), Ok(()));
    // срок обрезается до максимума при выпуске
    let long = mk(T0, 10 * MAX_VALIDITY_SECS);
    assert_eq!(long.valid_until - long.issued_at, MAX_VALIDITY_SECS);
    // а подделанная запись с большим сроком не пройдёт (подпись/срок)
    let mut forged = long.clone();
    forged.valid_until = forged.issued_at + 10 * MAX_VALIDITY_SECS;
    assert!(forged.verify(T0 + 1, true).is_err());
}

#[test]
fn endpoints_are_validated() {
    let id = SwarmIdentity::from_static_private([4; 32]);
    let sign = |eps: Vec<Endpoint>, sni: &str| {
        NodeDescriptor::sign(&id.signing, id.static_pub, Roles(Roles::RELAY), 1, (2, 6), 1, T0, 3600, sni.into(), eps)
    };
    let ep = |h: &str, p: u16| Endpoint { kind: EndpointKind::Tcp, host: h.into(), port: p };
    assert!(sign(vec![], "").verify(T0, true).is_err());
    assert!(sign(vec![ep("a b", 443)], "").verify(T0, true).is_err());
    assert!(sign(vec![ep("", 443)], "").verify(T0, true).is_err());
    assert!(sign(vec![ep("host", 0)], "").verify(T0, true).is_err());
    assert!(sign(vec![ep("-bad", 443)], "").verify(T0, true).is_err());
    assert!(sign((0..5).map(|i| ep(&format!("h{i}.example"), 443)).collect(), "").verify(T0, true).is_err());
    assert!(sign(vec![ep("ok.example", 443)], "bad sni!").verify(T0, true).is_err());
    assert_eq!(sign(vec![ep("ok.example", 443)], "").verify(T0, true), Ok(()));
    // публичность
    for private in ["10.1.2.3", "192.168.0.1", "127.0.0.1", "169.254.1.1", "100.64.0.1", "::1", "fd00::1", "fe80::1", "localhost", "printer.local"] {
        assert_eq!(
            sign(vec![ep(private, 443)], "").verify(T0, false),
            Err(DescriptorError::NonPublicAddress),
            "{private}"
        );
    }
    for public in ["8.8.8.8", "1.1.1.1", "2606:4700::1111", "node.example.org"] {
        assert_eq!(sign(vec![ep(public, 443)], "").verify(T0, false), Ok(()), "{public}");
    }
}

#[test]
fn decoding_never_panics_on_garbage() {
    let good = sample(1, "10.0.0.1").encode();
    let mut rng = rand::rngs::StdRng::seed_from_u64(7);
    for _ in 0..3000 {
        let mut b = good.clone();
        match rng.random_range(0..3) {
            0 => b.truncate(rng.random_range(0..b.len())),
            1 => {
                for _ in 0..rng.random_range(1..8) {
                    let i = rng.random_range(0..b.len());
                    b[i] = rng.random();
                }
            }
            _ => b.extend((0..rng.random_range(1..20)).map(|_| rng.random::<u8>())),
        }
        if let Ok(d) = NodeDescriptor::decode(&b) {
            let _ = d.verify(T0, true);
        }
    }
    for len in 0..200 {
        let junk: Vec<u8> = (0..len).map(|_| rng.random()).collect();
        let _ = NodeDescriptor::decode(&junk);
        let _ = Message::decode(&junk);
    }
}

// ─────────────────────────────── store ─────────────────────────────────────

fn store() -> DescriptorStore {
    DescriptorStore::new(StoreConfig { allow_private: true, ..Default::default() }, None)
}

fn desc_with(seed: u8, host: &str, seq: u64, roles: u8, issued: u64, valid: u64) -> NodeDescriptor {
    let id = SwarmIdentity::from_static_private([seed; 32]);
    NodeDescriptor::sign(
        &id.signing,
        id.static_pub,
        Roles(roles),
        features::GOSSIP,
        (2, 6),
        seq,
        issued,
        valid,
        String::new(),
        vec![Endpoint { kind: EndpointKind::Tcp, host: host.into(), port: 443 }],
    )
}

#[test]
fn store_prefers_higher_seq_and_ignores_replays() {
    let mut s = store();
    let v1 = desc_with(1, "10.0.0.1", 5, Roles::RELAY, T0, 3600);
    let v2 = desc_with(1, "10.0.0.9", 6, Roles::RELAY, T0, 3600); // переехал
    let old = desc_with(1, "10.0.0.7", 4, Roles::RELAY, T0, 3600);
    assert_eq!(s.insert(v1.clone(), T0), Insert::Added);
    assert_eq!(s.insert(v1.clone(), T0), Insert::Stale);
    assert_eq!(s.insert(v2.clone(), T0), Insert::Updated);
    assert_eq!(s.insert(old, T0), Insert::Stale, "откат адреса запрещён");
    assert_eq!(s.insert(v1, T0), Insert::Stale, "повтор старой записи");
    assert_eq!(s.get(&v2.node_id).unwrap().endpoints[0].host, "10.0.0.9");
}

#[test]
fn store_limits_nodes_per_network_prefix() {
    let mut s = store();
    for i in 1..=3u8 {
        assert_eq!(s.insert(desc_with(i, &format!("10.0.0.{i}"), 1, Roles::RELAY, T0, 3600), T0), Insert::Added);
    }
    // четвёртый из той же /24 — отказ
    assert_eq!(
        s.insert(desc_with(4, "10.0.0.4", 1, Roles::RELAY, T0, 3600), T0),
        Insert::Rejected(Reject::PrefixLimit)
    );
    // из другой сети — можно
    assert_eq!(s.insert(desc_with(5, "10.0.1.4", 1, Roles::RELAY, T0, 3600), T0), Insert::Added);
    // обновление существующего узла из той же сети не упирается в лимит
    assert_eq!(s.insert(desc_with(1, "10.0.0.1", 2, Roles::RELAY, T0, 3600), T0), Insert::Updated);
    // имена: одна зона второго уровня тоже считается «сетью»
    for i in 10..13u8 {
        assert_eq!(s.insert(desc_with(i, &format!("n{i}.same.example"), 1, Roles::RELAY, T0, 3600), T0), Insert::Added);
    }
    assert_eq!(
        s.insert(desc_with(13, "n13.same.example", 1, Roles::RELAY, T0, 3600), T0),
        Insert::Rejected(Reject::PrefixLimit)
    );
}

#[test]
fn store_is_bounded_and_evicts_the_soonest_to_expire() {
    let mut s = DescriptorStore::new(
        StoreConfig { max_records: 4, max_per_prefix: 100, allow_private: true, ..Default::default() },
        None,
    );
    for i in 1..=4u8 {
        let valid = 1000 * i as u64; // 1000, 2000, 3000, 4000
        assert_eq!(s.insert(desc_with(i, &format!("10.0.{i}.1"), 1, Roles::RELAY, T0, valid), T0), Insert::Added);
    }
    // новая живёт дольше самой короткой — вытесняет её
    let fresh = desc_with(9, "10.0.9.1", 1, Roles::RELAY, T0, 5000);
    assert_eq!(s.insert(fresh.clone(), T0), Insert::Added);
    assert_eq!(s.len(), 4);
    assert!(s.get(&fresh.node_id).is_some());
    // новая, живущая меньше всех — отказ (нельзя вытеснять долгоживущих короткоживущими)
    assert_eq!(
        s.insert(desc_with(10, "10.0.10.1", 1, Roles::RELAY, T0, 10), T0),
        Insert::Rejected(Reject::Full)
    );
    assert_eq!(s.len(), 4);
}

#[test]
fn store_ignores_its_own_record_and_expires_old_ones() {
    let me = desc_with(1, "10.0.0.1", 1, Roles::RELAY, T0, 3600);
    let mut s = DescriptorStore::new(StoreConfig { allow_private: true, ..Default::default() }, Some(me.node_id));
    assert_eq!(s.insert(me, T0), Insert::Stale, "про себя мы знаем лучше всех");
    let other = desc_with(2, "10.0.1.1", 1, Roles::RELAY, T0, 100);
    s.insert(other.clone(), T0);
    assert_eq!(s.live(T0 + 50).count(), 1);
    assert_eq!(s.live(T0 + 101).count(), 0);
    assert_eq!(s.gc(T0 + 101), 1);
    assert!(s.is_empty());
}

#[test]
fn digest_window_rotates_over_a_large_store() {
    let mut s = DescriptorStore::new(
        StoreConfig { max_records: 5000, max_per_prefix: 100_000, allow_private: true, ..Default::default() },
        None,
    );
    let n = store::MAX_DIGEST_ENTRIES + 120;
    for i in 0..n {
        let id = SwarmIdentity::from_static_private({
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&(i as u64 + 1).to_be_bytes());
            k
        });
        let d = NodeDescriptor::sign(
            &id.signing, id.static_pub, Roles(Roles::RELAY), 1, (2, 6), 1, T0, 3600, String::new(),
            vec![Endpoint { kind: EndpointKind::Tcp, host: format!("10.{}.{}.1", i / 250, i % 250), port: 443 }],
        );
        assert_eq!(s.insert(d, T0), Insert::Added);
    }
    let mut seen = std::collections::HashSet::new();
    for round in 0..4 {
        let dg = s.digest(T0, round);
        assert!(dg.len() <= store::MAX_DIGEST_ENTRIES);
        seen.extend(dg.into_iter().map(|(id, _)| id));
    }
    assert_eq!(seen.len(), n, "за несколько раундов дайджест обходит весь каталог");
}

#[test]
fn export_import_round_trip_and_tampering() {
    let mut s = store();
    for i in 1..=3u8 {
        s.insert(desc_with(i, &format!("10.0.{i}.1"), 1, Roles::RELAY, T0, 3600), T0);
    }
    let snap = s.export(T0);
    let mut s2 = store();
    assert_eq!(s2.import(&snap, T0), 3);
    // испорченный снимок: всё, что не проходит подпись, отбрасывается
    let mut bad = snap.clone();
    let k = bad.len() - 10;
    bad[k] ^= 0xff;
    let mut s3 = store();
    assert!(s3.import(&bad, T0) < 3);
    assert_eq!(store().import(b"garbage", T0), 0);
    // и истёкшее в снимок не попадает
    assert_eq!(s.export(T0 + 10_000)[8..12], 0u32.to_be_bytes());
}

// ─────────────────────────────── gossip ────────────────────────────────────

#[test]
fn messages_round_trip_and_reject_oversize() {
    let a = sample(1, "10.0.0.1");
    let b = sample(2, "10.0.1.1");
    for m in [
        Message::Digest(vec![(a.node_id, 5), (b.node_id, 9)]),
        Message::Reply { records: vec![a.clone(), b.clone()], want: vec![b.node_id] },
        Message::Push(vec![a.clone()]),
        Message::Digest(vec![]),
    ] {
        assert_eq!(Message::decode(&m.encode()).unwrap(), m);
    }
    assert_eq!(Message::decode(&[]), Err(GossipError::Empty));
    assert_eq!(Message::decode(&[99]), Err(GossipError::UnknownTag(99)));
    assert!(Message::decode(&vec![1u8; gossip::MAX_MSG_BYTES + 1]).is_err());
    // дайджест с заявленной длиной больше предела
    let mut huge = vec![1u8];
    huge.extend_from_slice(&u16::MAX.to_be_bytes());
    assert!(Message::decode(&huge).is_err());
    // хвост
    let mut tail = Message::Digest(vec![]).encode();
    tail.push(0);
    assert!(Message::decode(&tail).is_err());
}

#[test]
fn two_nodes_learn_each_other_and_a_third_through_one_exchange() {
    let sw = swarm();
    let a = dir(1, "10.0.0.1", &sw);
    let b = dir(2, "10.0.1.1", &sw);
    let c = dir(3, "10.0.2.1", &sw);
    // A знает C; B знает только себя
    assert_eq!(a.insert(c.own(T0), T0), Insert::Added);
    let (sa, sb) = exchange(&a, &b, T0 + 1);
    assert_eq!(sa.learned(), 1, "A узнал о B");
    assert_eq!(sb.learned(), 2, "B узнал об A и о C (через пуш)");
    assert_eq!(b.len(), 2);
    assert_eq!(a.len(), 2);
    let ids: Vec<_> = b.peers(T0 + 1).into_iter().map(|p| p.node_id).collect();
    assert!(ids.contains(&a.node_id_hex()) && ids.contains(&c.node_id_hex()));
    // повторный обмен ничего нового не приносит
    let (sa2, sb2) = exchange(&a, &b, T0 + 2);
    assert_eq!((sa2.learned(), sb2.learned()), (0, 0));
}

#[test]
fn network_converges_by_random_pairwise_exchanges() {
    let sw = swarm();
    let n = 40usize;
    let nodes: Vec<Directory> = (0..n)
        .map(|i| dir(i as u8 + 1, &format!("10.{}.{}.1", i / 8, i % 8), &sw))
        .collect();
    // каждый знает только следующего по кольцу (минимальный seed)
    for i in 0..n {
        nodes[i].insert(nodes[(i + 1) % n].own(T0), T0);
    }
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let mut rounds = 0;
    let target = n - 1;
    while rounds < 40 && !nodes.iter().all(|d| d.len() == target) {
        rounds += 1;
        for i in 0..n {
            // выбираем случайного известного соседа
            let peers = nodes[i].gossip_peers(T0 + rounds);
            if peers.is_empty() {
                continue;
            }
            let p = &peers[rng.random_range(0..peers.len())];
            let j = nodes.iter().position(|d| d.node_id_hex() == p.node_id).unwrap();
            exchange(&nodes[i], &nodes[j], T0 + rounds);
        }
    }
    assert!(
        nodes.iter().all(|d| d.len() == target),
        "after {rounds} rounds: {:?}",
        nodes.iter().map(|d| d.len()).collect::<Vec<_>>()
    );
    // для 40 узлов хватает порядка log2(n) раундов с запасом
    assert!(rounds <= 12, "converged in {rounds} rounds");
}

#[test]
fn forged_stale_and_non_gossipable_records_do_not_spread() {
    let sw = swarm();
    let honest = dir(1, "10.0.0.1", &sw);
    let victim = dir(2, "10.0.1.1", &sw);
    let evil = dir(3, "10.0.2.1", &sw);

    // 1) подделка: чужой node_id с чужим адресом под нашей подписью
    let mut forged = victim.own(T0);
    forged.endpoints[0].host = "10.99.99.99".into();
    // 2) мост: не пересказывается
    let bridge = {
        let id = SwarmIdentity::from_static_private([7; 32]);
        NodeDescriptor::sign(&id.signing, id.static_pub, Roles(Roles::BRIDGE), 1, (2, 6), 1, T0, 3600, String::new(),
            vec![Endpoint { kind: EndpointKind::Tcp, host: "10.0.7.1".into(), port: 443 }])
    };
    // 3) честная запись жертвы
    let real = victim.own(T0);

    let push = Message::Push(vec![forged.clone(), bridge.clone(), real.clone()]).encode();
    let Ok(Handled::Absorbed(st)) = honest.handle_incoming(&push, T0 + 1) else { panic!() };
    assert_eq!(st.added, 1, "принята только настоящая запись жертвы: {st:?}");
    assert_eq!(st.rejected, 2);
    let peers = honest.peers(T0 + 1);
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].host, "10.0.1.1");

    // мост из локального импорта хранится, но в gossip не попадает
    let d = dir(4, "10.0.4.1", &sw);
    assert_eq!(d.insert(bridge.clone(), T0), Insert::Added);
    let (_, sb) = exchange(&d, &honest, T0 + 1);
    assert!(honest.peers(T0 + 1).iter().all(|p| p.node_id != node_id_hex(&bridge.node_id)));
    let _ = (sb, evil);
}

#[test]
fn sybil_flood_from_one_network_cannot_fill_the_directory() {
    let sw = swarm();
    let victim = dir(1, "10.0.0.1", &sw);
    let flood: Vec<NodeDescriptor> = (0..60u8)
        .map(|i| desc_with(100 + i, &format!("10.5.5.{}", i + 1), 1, Roles::RELAY, T0, 3600))
        .collect();
    // сообщения по 20 записей
    for chunk in flood.chunks(20) {
        let msg = Message::Push(chunk.to_vec()).encode();
        let _ = victim.handle_incoming(&msg, T0 + 1);
    }
    assert_eq!(victim.len(), 3, "с одной /24 принимается не больше max_per_prefix");
}

#[test]
fn incoming_requests_are_rate_limited() {
    let sw = swarm();
    let d = dir_with(1, "10.0.0.1", &sw, |c| {
        c.max_requests_per_window = 5;
        c.window_secs = 10;
    });
    let digest = Message::Digest(vec![]).encode();
    for _ in 0..5 {
        assert!(d.handle_incoming(&digest, T0 + 1).is_ok());
    }
    assert!(matches!(d.handle_incoming(&digest, T0 + 2), Err(DirectoryError::RateLimited)));
    // новое окно — снова можно
    assert!(d.handle_incoming(&digest, T0 + 20).is_ok());
    // ответ вместо запроса — ошибка протокола
    let reply = Message::Reply { records: vec![], want: vec![] }.encode();
    assert!(matches!(d.handle_incoming(&reply, T0 + 21), Err(DirectoryError::UnexpectedMessage)));
    assert!(d.handle_incoming(&[], T0 + 21).is_err());
}

#[test]
fn replies_respect_the_frame_budget() {
    let sw = swarm();
    let big = dir_with(1, "10.0.0.1", &sw, |c| c.store.max_per_prefix = 100_000);
    for i in 0..300u16 {
        let mut k = [0u8; 32];
        k[..2].copy_from_slice(&(i + 1).to_be_bytes());
        k[31] = 77;
        let id = SwarmIdentity::from_static_private(k);
        let d = NodeDescriptor::sign(
            &id.signing, id.static_pub, Roles(Roles::RELAY), 1, (2, 6), 1, T0, 3600, "www.example.org".into(),
            vec![Endpoint { kind: EndpointKind::Tcp, host: format!("10.{}.{}.1", i / 250, i % 250), port: 443 }],
        );
        big.insert(d, T0);
    }
    let fresh = dir(2, "10.200.0.1", &sw);
    let digest = fresh.begin_exchange(T0 + 1);
    let Ok(Handled::Reply(reply)) = big.handle_incoming(&digest, T0 + 1) else { panic!() };
    assert!(reply.len() <= gossip::MAX_MSG_BYTES, "reply is {} bytes", reply.len());
    assert!(reply.len() < 16_360, "must fit one NRXP frame");
    let (st, _) = fresh.complete_exchange(&reply, T0 + 1).unwrap();
    assert!(st.learned() > 20, "{st:?}");
}

// ───────────────────────── роль, рой, допуск ──────────────────────────────

#[test]
fn own_record_is_reissued_before_it_expires_with_a_higher_seq() {
    let sw = swarm();
    let d = dir_with(1, "10.0.0.1", &sw, |c| c.validity_secs = 3000);
    let first = d.own(T0);
    assert_eq!(d.own(T0 + 1000).seq, first.seq, "пока срока хватает, запись та же");
    let later = d.own(T0 + 2500);
    assert!(later.seq > first.seq && later.valid_until > first.valid_until);
    assert_eq!(later.verify(T0 + 2500, true), Ok(()));
}

#[test]
fn swarm_key_gates_mesh_admission_without_publishing_secrets() {
    let sw = swarm();
    let other = SwarmKey::from_bytes([1u8; 32]);
    let a = dir(1, "10.0.0.1", &sw);
    let b = dir(2, "10.0.1.1", &sw);
    a.insert(b.own(T0), T0);

    // секрет соседа считается из ключа роя и в записи нигде не лежит
    let peers = a.peers(T0);
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].nrxp_secret, sw.node_secret(&b.node_id()));
    assert!(!hex::encode(b.own(T0).encode()).contains(&peers[0].nrxp_secret));

    // допуск: знает секрет роя для своего id — пускаем; чужой рой/чужой id — нет
    let id = b.node_id_hex();
    assert!(a.validate_mesh_peer(&id, &sw.node_secret(&b.node_id())));
    assert!(!a.validate_mesh_peer(&id, &other.node_secret(&b.node_id())));
    assert!(!a.validate_mesh_peer(&id, &sw.node_secret(&a.node_id())));
    assert!(!a.validate_mesh_peer("not-hex", "x"));
    assert!(!a.validate_mesh_peer(&id, ""));
    // секрет детерминирован и различается по узлам и по ключу
    assert_eq!(sw.node_secret(&a.node_id()), sw.node_secret(&a.node_id()));
    assert_ne!(sw.node_secret(&a.node_id()), sw.node_secret(&b.node_id()));
    assert_ne!(sw.node_secret(&a.node_id()), other.node_secret(&a.node_id()));
    assert_eq!(sw.node_secret(&a.node_id()).len(), 64);
    assert!(format!("{sw:?}").contains("REDACTED"));
}

#[test]
fn old_nodes_without_gossip_support_are_not_sent_gossip() {
    let sw = swarm();
    let a = dir(1, "10.0.0.1", &sw);
    let id = SwarmIdentity::from_static_private([2; 32]);
    let legacy = NodeDescriptor::sign(
        &id.signing, id.static_pub, Roles(Roles::RELAY), 0 /* без GOSSIP */, (2, 5), 1, T0, 3600, String::new(),
        vec![Endpoint { kind: EndpointKind::Tcp, host: "10.0.1.1".into(), port: 443 }],
    );
    a.insert(legacy, T0);
    assert_eq!(a.peers(T0).len(), 1, "в маршрутах участвует");
    assert!(a.gossip_peers(T0).is_empty(), "но неизвестный кадр ему не шлём: он рвёт ногу");
}

#[tokio::test]
async fn directory_validator_serves_peers_and_admission_without_a_panel() {
    use crate::net::AuthValidator;
    let sw = swarm();
    let a = std::sync::Arc::new(dir(1, "10.0.0.1", &sw));
    let b = dir(2, "10.0.1.1", &sw);
    a.insert(b.own(unix_now()), unix_now());
    let v = DirectoryValidator::new(a.clone(), None);
    let peers = v.list_mesh_peers().await;
    // записи выпущены на T0 (в прошлом/будущем относительно unix_now) — допускаем оба исхода,
    // главное: ошибки панели нет и узлы без аккаунтов не падают
    assert!(peers.is_ok());
    assert!(v.validate("any-user-token").await.is_err(), "без панели пользовательских токенов нет");
    assert!(v.report_node_health(crate::net::NodeHealthReport {
        active_sessions: 0,
        active_legs: 0,
        active_streams: 0,
        bytes_up_total_mb: 0.0,
        bytes_down_total_mb: 0.0,
        error_totals: Default::default(),
        uptime_secs: 0,
    }).await.is_ok());
    assert!(v.validate_mesh_peer(&b.node_id_hex(), &sw.node_secret(&b.node_id())).await.is_ok());
    assert!(v.validate_mesh_peer(&b.node_id_hex(), "wrong").await.is_err());
}

// ───────────────────────────── PeerHint ────────────────────────────────────

fn hint(d: &Directory, max: u8, now: u64) -> Result<Vec<NodeDescriptor>, DirectoryError> {
    match d.handle_incoming(&Message::HintRequest { max }.encode(), now)? {
        Handled::Reply(bytes) => match Message::decode(&bytes).unwrap() {
            Message::HintReply(records) => Ok(records),
            other => panic!("unexpected {other:?}"),
        },
        Handled::Absorbed(_) => panic!("a hint request has a reply"),
    }
}

#[test]
fn hint_messages_round_trip_and_clamp_the_request() {
    let a = sample(1, "10.0.0.1");
    for m in [Message::HintRequest { max: 7 }, Message::HintReply(vec![a.clone()]), Message::HintReply(vec![])] {
        assert_eq!(Message::decode(&m.encode()).unwrap(), m);
        assert_eq!(m.is_request(), matches!(m, Message::HintRequest { .. }));
        assert_eq!(m.is_reply(), matches!(m, Message::HintReply(_)));
    }
    // завышенный запрос сжимается до предела
    let wire = [4u8, 200];
    assert_eq!(Message::decode(&wire).unwrap(), Message::HintRequest { max: gossip::MAX_HINT_RECORDS });
    assert!(Message::decode(&[4u8]).is_err(), "обрезанный запрос");
    assert!(Message::decode(&[4u8, 1, 9]).is_err(), "хвост");
}

#[test]
fn a_hint_returns_random_relays_and_never_bridges() {
    let sw = swarm();
    let node = dir(1, "10.0.0.1", &sw);
    let n = 12u8;
    for i in 0..n {
        node.insert(desc_with(10 + i, &format!("10.{}.0.1", 20 + i), 1, Roles::RELAY, T0, 3600), T0);
    }
    let bridge = desc_with(99, "10.99.0.1", 1, Roles::BRIDGE, T0, 3600);
    assert_eq!(node.insert(bridge.clone(), T0), Insert::Added);

    let mut seen = std::collections::HashSet::new();
    for _ in 0..20 {
        let r = hint(&node, 5, T0 + 1).unwrap();
        assert!(r.len() <= 5 && !r.is_empty());
        assert!(r.iter().all(|d| d.roles.has(Roles::RELAY)));
        assert!(r.iter().all(|d| d.node_id != bridge.node_id), "мост клиенту не отдаётся");
        seen.extend(r.into_iter().map(|d| d.node_id));
    }
    assert!(seen.len() > 5, "ответы разные у разных запросов, увидели {}", seen.len());
    assert!(seen.contains(&node.node_id()) || seen.len() >= 6, "в пул входит и своя запись");
    // max=0 — пустой ответ, а не ошибка
    assert!(hint(&node, 0, T0 + 1).unwrap().is_empty());
}

#[test]
fn client_hints_and_node_gossip_have_separate_rate_limits() {
    let sw = swarm();
    let d = dir_with(1, "10.0.0.1", &sw, |c| {
        c.max_requests_per_window = 3;
        c.max_hints_per_window = 2;
        c.window_secs = 10;
    });
    let digest = Message::Digest(vec![]).encode();
    // клиенты исчерпали свой бюджет…
    assert!(hint(&d, 4, T0 + 1).is_ok() && hint(&d, 4, T0 + 1).is_ok());
    assert!(matches!(hint(&d, 4, T0 + 1), Err(DirectoryError::RateLimited)));
    // …но обмен между узлами это не задело
    for _ in 0..3 {
        assert!(d.handle_incoming(&digest, T0 + 1).is_ok());
    }
    assert!(matches!(d.handle_incoming(&digest, T0 + 1), Err(DirectoryError::RateLimited)));
    // новое окно — снова можно обоим
    assert!(hint(&d, 4, T0 + 30).is_ok());
    assert!(d.handle_incoming(&digest, T0 + 30).is_ok());
}

#[test]
fn the_client_cache_verifies_derives_credentials_and_persists() {
    let sw = swarm();
    let server = dir(1, "10.0.0.1", &sw);
    for i in 0..4u8 {
        server.insert(desc_with(30 + i, &format!("10.{}.0.1", 40 + i), 1, Roles::RELAY, T0, 3600), T0);
    }
    let client = ClientDirectory::new(sw.clone(), true, Vec::new());
    assert!(client.is_empty());

    let reply = {
        let Ok(Handled::Reply(b)) = server.handle_incoming(&client.request(10), T0 + 1) else { panic!() };
        b
    };
    let st = client.absorb_reply(&reply, T0 + 1).unwrap();
    assert_eq!(st.learned(), 5, "четыре соседа и сам узел: {st:?}");

    // учётные данные считаются клиентом сам, из ключа роя
    let nodes = client.nodes(T0 + 1, &Default::default());
    assert_eq!(nodes.len(), 5);
    for n in &nodes {
        let id = parse_node_id(&n.node_id).unwrap();
        assert_eq!(n.node_secret, sw.node_secret(&id));
        assert_eq!(n.node_public_key.len(), 64);
        assert_eq!(n.proxy.to_string(), n.address);
    }
    // уже известные из конфига адреса исключаются
    let known: std::collections::HashSet<String> = [nodes[0].address.clone()].into();
    assert_eq!(client.nodes(T0 + 1, &known).len(), 4);

    // подделка и мост в ответе не принимаются
    let mut forged = desc_with(77, "10.77.0.1", 1, Roles::RELAY, T0, 3600);
    forged.endpoints[0].host = "10.66.6.6".into();
    let bridge = desc_with(78, "10.78.0.1", 1, Roles::BRIDGE, T0, 3600);
    let bad = Message::HintReply(vec![forged, bridge]).encode();
    let st = client.absorb_reply(&bad, T0 + 1).unwrap();
    assert_eq!((st.learned(), st.rejected), (0, 2));
    // и запрос вместо ответа — ошибка
    assert!(client.absorb_reply(&client.request(1), T0 + 1).is_err());

    // кэш переживает перезапуск, истёкшее отбрасывается
    let snap = client.save(T0 + 1);
    let again = ClientDirectory::new(sw.clone(), true, Vec::new());
    assert_eq!(again.load(&snap, T0 + 1), 5);
    assert_eq!(again.nodes(T0 + 200_000, &Default::default()).len(), 0);
    // без ключа роя учётные данные чужие: клиент другого роя получает другие секреты
    let other = ClientDirectory::new(SwarmKey::from_bytes([1u8; 32]), true, Vec::new());
    other.load(&snap, T0 + 1);
    assert_ne!(other.nodes(T0 + 1, &Default::default())[0].node_secret, nodes[0].node_secret);
}

#[test]
fn only_ipv4_relays_become_client_candidates() {
    let sw = swarm();
    let client = ClientDirectory::new(sw, true, Vec::new());
    let mk = |seed: u8, host: &str, roles: u8| desc_with(seed, host, 1, roles, T0, 3600);
    let mut st = store();
    for d in [mk(1, "10.1.0.1", Roles::RELAY), mk(2, "node.example.org", Roles::RELAY), mk(3, "2001:db8::1", Roles::RELAY), mk(4, "10.4.0.1", Roles::EXIT)] {
        st.insert(d, T0);
    }
    let snap = st.export(T0);
    client.load(&snap, T0);
    let nodes = client.nodes(T0, &Default::default());
    assert_eq!(nodes.len(), 1, "{nodes:?}");
    assert_eq!(nodes[0].address, "10.1.0.1:443");
}

// ───────────────── поручительства, управляемая сеть, парные секреты ─────────────────

use ed25519_dalek::SigningKey;

fn authority(n: u8) -> (SigningKey, [u8; 32]) {
    let k = SigningKey::from_bytes(&[n; 32]);
    let p = k.verifying_key().to_bytes();
    (k, p)
}

fn endorsed(seed: u8, host: &str, seq: u64, auth: &SigningKey, until: u64) -> NodeDescriptor {
    let id = SwarmIdentity::from_static_private([seed; 32]);
    let sp = id.signing.verifying_key().to_bytes();
    NodeDescriptor::sign_endorsed(
        &id.signing, id.static_pub, Roles(Roles::RELAY), features::GOSSIP, (2, 6), seq, T0, 3600, String::new(),
        vec![Endpoint { kind: EndpointKind::Tcp, host: host.into(), port: 443 }],
        vec![Endorsement::issue(auth, &id.static_pub, &sp, until)],
    )
}

fn managed_store(anchor: [u8; 32]) -> DescriptorStore {
    DescriptorStore::new(
        StoreConfig { allow_private: true, trust_anchors: vec![anchor], ..Default::default() },
        None,
    )
}

#[test]
fn unendorsed_records_keep_the_old_wire_format_and_endorsed_ones_round_trip() {
    let plain = desc_with(1, "10.0.0.1", 1, Roles::RELAY, T0, 3600);
    assert_eq!(plain.encode()[0], 1, "без поручительств формат прежний — совместим со старыми узлами");
    assert!(plain.endorsements.is_empty());

    let (k, _) = authority(9);
    let d = endorsed(2, "10.0.0.2", 1, &k, T0 + 100_000);
    let bytes = d.encode();
    assert_eq!(bytes[0], 2);
    let back = NodeDescriptor::decode(&bytes).unwrap();
    assert_eq!(back, d);
    assert_eq!(back.verify(T0 + 1, true), Ok(()));
    assert_eq!(back.endorsed_until(&[authority(9).1]), Some(T0 + 100_000));
    assert_eq!(back.endorsed_until(&[authority(8).1]), None, "чужой авторитет");
    assert_eq!(back.endorsed_until(&[]), None);

    // поручительство внутри подписанного тела: любой байт записи защищён
    let sig_start = bytes.len() - 64;
    for i in 0..sig_start {
        let mut b = bytes.clone();
        b[i] ^= 0x01;
        if let Ok(x) = NodeDescriptor::decode(&b) {
            let ok = x.verify(T0 + 1, true).is_ok() && x.endorsed_until(&[authority(9).1]).is_some();
            assert!(!ok, "byte {i} not protected");
        }
    }
    // число поручительств: 0 и больше предела — ошибка разбора
    let mut zero = bytes.clone();
    let count_pos = bytes.len() - 64 - descriptor::ENDORSEMENT_LEN - 1;
    zero[count_pos] = 0;
    assert!(NodeDescriptor::decode(&zero).is_err());
    zero[count_pos] = 3;
    assert!(NodeDescriptor::decode(&zero).is_err());
}

#[test]
fn an_endorsement_binds_to_the_node_identity_and_cannot_be_moved() {
    let (k, anchor) = authority(9);
    let a = SwarmIdentity::from_static_private([1; 32]);
    let b = SwarmIdentity::from_static_private([2; 32]);
    let e_for_a = Endorsement::issue(&k, &a.static_pub, &a.signing.verifying_key().to_bytes(), T0 + 1000);
    // запись B с поручительством за A
    let stolen = NodeDescriptor::sign_endorsed(
        &b.signing, b.static_pub, Roles(Roles::RELAY), 1, (2, 6), 1, T0, 3600, String::new(),
        vec![Endpoint { kind: EndpointKind::Tcp, host: "10.0.0.2".into(), port: 443 }],
        vec![e_for_a.clone()],
    );
    assert_eq!(stolen.endorsed_until(&[anchor]), None);
    assert!(!e_for_a.valid_for_keys(&b.static_pub, &b.signing.verifying_key().to_bytes()));
    assert!(e_for_a.valid_for_keys(&a.static_pub, &a.signing.verifying_key().to_bytes()));
    // срок входит в подпись
    let mut longer = e_for_a.clone();
    longer.not_after += 10_000;
    assert!(!longer.valid_for_keys(&a.static_pub, &a.signing.verifying_key().to_bytes()));
    assert_eq!(Endorsement::decode(&e_for_a.encode()).unwrap(), e_for_a);
    assert!(Endorsement::decode(&[0u8; 5]).is_none());
}

#[test]
fn a_managed_store_takes_only_currently_endorsed_records() {
    let (k, anchor) = authority(9);
    let (k2, _) = authority(8);
    let mut s = managed_store(anchor);

    // без поручительства (но с верной самоподписью) — нет
    assert_eq!(
        s.insert(desc_with(1, "10.0.1.1", 1, Roles::RELAY, T0, 3600), T0),
        Insert::Rejected(Reject::NotEndorsed)
    );
    // поручительство чужого авторитета — нет
    assert_eq!(s.insert(endorsed(2, "10.0.2.1", 1, &k2, T0 + 5000), T0), Insert::Rejected(Reject::NotEndorsed));
    // истёкшее поручительство — нет
    assert_eq!(s.insert(endorsed(3, "10.0.3.1", 1, &k, T0 - 1), T0), Insert::Rejected(Reject::NotEndorsed));
    // действующее — да
    assert_eq!(s.insert(endorsed(4, "10.0.4.1", 1, &k, T0 + 5000), T0), Insert::Added);
    assert_eq!(s.live(T0).count(), 1);

    // поручительство короче записи: узел исчезает вместе с ним
    assert_eq!(s.live(T0 + 5001).count(), 0, "запись ещё жива, но поручительство истекло");
    assert_eq!(s.gc(T0 + 5001), 1);
    assert!(s.is_empty());

    // продление: новая запись с большим seq и новым поручительством заменяет прежнюю
    assert_eq!(s.insert(endorsed(4, "10.0.4.1", 2, &k, T0 + 9000), T0), Insert::Added);
    assert_eq!(s.insert(endorsed(4, "10.0.4.1", 3, &k, T0 + 20_000), T0), Insert::Updated);
    assert_eq!(s.live(T0 + 15_000).count(), 0, "запись истекла сама (3600 с), хоть поручительство дольше");
    assert_eq!(s.live(T0 + 3000).count(), 1);
}

#[test]
fn an_open_store_ignores_endorsements_entirely() {
    let (k, _) = authority(9);
    let mut s = store();
    assert_eq!(s.insert(endorsed(1, "10.0.1.1", 1, &k, T0 + 5000), T0), Insert::Added);
    assert_eq!(s.insert(desc_with(2, "10.0.2.1", 1, Roles::RELAY, T0, 3600), T0), Insert::Added);
}

#[test]
fn managed_nodes_gossip_among_themselves_and_an_intruder_stays_out() {
    let sw = swarm();
    let (k, anchor) = authority(9);
    let mk = |seed: u8, host: &str| {
        dir_with(seed, host, &sw, |c| c.store.trust_anchors = vec![anchor])
    };
    let a = mk(1, "10.0.0.1");
    let b = mk(2, "10.0.1.1");
    let intruder = mk(3, "10.0.2.1");
    for d in [&a, &b] {
        let own = d.own(T0);
        d.set_endorsements(vec![Endorsement::issue_for(&k, &own, T0 + 5000)], T0 + 1);
    }
    assert_eq!(a.own(T0 + 1).endorsements.len(), 1);
    assert!(a.own(T0 + 1).seq > 0);

    a.insert(b.own(T0 + 1), T0 + 1);
    let (sa, sb) = exchange(&a, &b, T0 + 2);
    assert_eq!(sa.learned() + sb.learned(), 1, "B узнаёт об A, A про B уже знал: {sa:?} {sb:?}");

    // непоручённый узел толкает свою запись — отвергнута
    let push = Message::Push(vec![intruder.own(T0)]).encode();
    let Ok(Handled::Absorbed(st)) = a.handle_incoming(&push, T0 + 2) else { panic!() };
    assert_eq!((st.learned(), st.rejected), (0, 1));
    assert_eq!(a.len(), 1);

    // допуск пира: незнакомый непоручённый не проходит даже с ключом роя; поручённый знакомый — да
    assert!(!a.validate_mesh_peer_at(&intruder.node_id_hex(), &sw.node_secret(&intruder.node_id()), T0 + 2));
    let b_secret = a.mesh_secret_for(&b.node_id(), T0 + 2).map(|s| s.split('.').next().unwrap().to_string());
    assert_eq!(b_secret, Some(sw.node_secret(&a.node_id())), "это наш секрет, не B");
    assert!(a.validate_mesh_peer_at(&b.node_id_hex(), &b.mesh_secret_for(&a.node_id(), T0 + 2).unwrap_or_else(|| sw.node_secret(&b.node_id())), T0 + 2)
        || a.validate_mesh_peer_at(&b.node_id_hex(), &sw.node_secret(&b.node_id()), T0 + 2));
    // после истечения поручительства узел перестаёт быть допущенным
    assert!(!a.validate_mesh_peer_at(&b.node_id_hex(), &sw.node_secret(&b.node_id()), T0 + 6000));
    assert!(a.is_managed() && !dir(9, "10.0.9.1", &sw).is_managed());
}

#[test]
fn set_endorsements_reissues_the_record_only_when_something_changed() {
    let sw = swarm();
    let (k, anchor) = authority(9);
    let (k2, _) = authority(7);
    let d = dir_with(1, "10.0.0.1", &sw, |c| c.store.trust_anchors = vec![anchor]);
    let own = d.own(T0);
    let e = Endorsement::issue_for(&k, &own, T0 + 5000);
    d.set_endorsements(vec![e.clone()], T0 + 1);
    let first = d.own(T0 + 1);
    assert_eq!(first.endorsements, vec![e.clone()]);
    d.set_endorsements(vec![e.clone()], T0 + 2);
    assert_eq!(d.own(T0 + 2).seq, first.seq, "то же самое — запись не перевыпускается");
    // продление
    let e2 = Endorsement::issue_for(&k, &own, T0 + 9000);
    d.set_endorsements(vec![e2.clone()], T0 + 3);
    assert!(d.own(T0 + 3).seq > first.seq);
    assert_eq!(d.own(T0 + 3).endorsements, vec![e2]);
    // поручительство за другой узел отбрасывается; пустой список снимает поручительство
    let other = SwarmIdentity::from_static_private([2; 32]);
    let foreign = Endorsement::issue(&k2, &other.static_pub, &other.signing.verifying_key().to_bytes(), T0 + 5000);
    d.set_endorsements(vec![foreign], T0 + 4);
    assert!(d.own(T0 + 4).endorsements.is_empty());
    assert_eq!(d.own(T0 + 4).verify(T0 + 4, true), Ok(()));
}

/// `<секрет роя>.<доказательство>` обязан влезть в 128 символов поля секрета mesh-токена.
fn sw_token_len_fits() -> bool {
    swarm().node_secret(&[0u8; 16]).len() + 1 + pair_proof(&[0u8; 32]).len() <= 128
}

#[test]
fn pairwise_secrets_are_symmetric_and_belong_to_exactly_one_pair() {
    let a = SwarmIdentity::from_static_private([1; 32]);
    let b = SwarmIdentity::from_static_private([2; 32]);
    let c = SwarmIdentity::from_static_private([3; 32]);
    let ab = pairwise_secret(&a.static_private, &b.static_pub);
    assert_eq!(ab, pairwise_secret(&b.static_private, &a.static_pub), "симметричен");
    assert_ne!(ab, pairwise_secret(&a.static_private, &c.static_pub));
    assert_ne!(ab, pairwise_secret(&b.static_private, &c.static_pub));
    assert_ne!(pair_proof(&ab), pair_proof(&pairwise_secret(&a.static_private, &c.static_pub)));
    assert_eq!(pair_proof(&ab).len(), 32);
    assert!(sw_token_len_fits(), "токен умещается в предел поля секрета");
    // у C (знающего ключ роя) подделать доказательство пары A–B нечем
    let c_guess = pairwise_secret(&c.static_private, &a.static_pub);
    assert_ne!(pair_proof(&c_guess), pair_proof(&ab));
    assert!(ct_eq_str("abc", "abc") && !ct_eq_str("abc", "abd") && !ct_eq_str("abc", "ab"));
}

#[test]
fn mesh_admission_binds_known_nodes_to_their_pairwise_proof() {
    let sw = swarm();
    let strict = dir_with(1, "10.0.0.1", &sw, |c| c.strict_pairwise = true);
    let lax = dir_with(1, "10.0.0.1", &sw, |_| {});
    let a = dir(2, "10.0.1.1", &sw); // известный пир
    let c = dir(3, "10.0.2.1", &sw); // член роя, которого B ещё не знает
    for d in [&strict, &lax] {
        d.insert(a.own(T0), T0);
    }
    let a_id = a.node_id_hex();
    let swarm_part = sw.node_secret(&a.node_id());
    let proof = a.mesh_secret_for(&strict.node_id(), T0).is_none(); // A не знает B → None
    assert!(proof);
    a.insert(strict.own(T0), T0);
    let good = a.mesh_secret_for(&strict.node_id(), T0).expect("A знает B");
    assert!(good.starts_with(&swarm_part) && good.contains('.'));

    for d in [&strict, &lax] {
        // настоящий A
        assert!(d.validate_mesh_peer_at(&a_id, &good, T0), "A с доказательством");
        // доказательство, снятое для другой пары (C→B), от имени A не годится
        c.insert(strict.own(T0), T0);
        let c_secret = c.mesh_secret_for(&strict.node_id(), T0).unwrap();
        let c_proof = c_secret.split_once('.').unwrap().1.to_string();
        assert!(!d.validate_mesh_peer_at(&a_id, &format!("{swarm_part}.{c_proof}"), T0), "чужое доказательство");
        // испорченное
        assert!(!d.validate_mesh_peer_at(&a_id, &format!("{swarm_part}.{}", "0".repeat(32)), T0));
        // секрет роя другого узла + верное доказательство — нет
        assert!(!d.validate_mesh_peer_at(&a_id, &format!("{}.{}", sw.node_secret(&c.node_id()), good.split_once('.').unwrap().1), T0));
        // незнакомый член роя — знакомство по ключу роя
        assert!(d.validate_mesh_peer_at(&c.node_id_hex(), &sw.node_secret(&c.node_id()), T0), "введение");
    }
    // самозванец, знающий только ключ роя, выдаёт себя за известного A
    assert!(!strict.validate_mesh_peer_at(&a_id, &swarm_part, T0), "строгий режим");
    assert!(lax.validate_mesh_peer_at(&a_id, &swarm_part, T0), "совместимость со старыми узлами");
}

#[test]
fn old_nodes_without_the_pairwise_flag_get_the_plain_swarm_secret() {
    let sw = swarm();
    let a = dir(1, "10.0.0.1", &sw);
    let id = SwarmIdentity::from_static_private([2; 32]);
    let legacy = NodeDescriptor::sign(
        &id.signing, id.static_pub, Roles(Roles::RELAY), features::GOSSIP /* без PAIRWISE */, (2, 5), 1, T0, 3600,
        String::new(), vec![Endpoint { kind: EndpointKind::Tcp, host: "10.0.1.1".into(), port: 443 }],
    );
    let legacy_id = legacy.node_id;
    a.insert(legacy, T0);
    assert_eq!(a.mesh_secret_for(&legacy_id, T0), Some(sw.node_secret(&a.node_id())), "старый узел не знает формата с точкой");
    assert!(a.mesh_secret_for(&[0u8; 16], T0).is_none(), "об этом узле записи нет");
}

// ─────────────────────────────── гибрид с панелью ───────────────────────────────

struct MockPanel {
    peers: Vec<crate::net::MeshPeer>,
    peers_ok: bool,
    admits: Vec<(String, String)>,
}

#[async_trait::async_trait]
impl crate::net::AuthValidator for MockPanel {
    async fn validate(&self, _t: &str) -> Result<crate::net::UserQuota, netrunner_logger::AppError> {
        Ok(crate::net::UserQuota { user_id: "u".into(), limit_bytes: None, used_bytes: 0, access_policy: None, exit_label: None })
    }
    async fn report_usage(&self, _u: &str, _d: u64) -> Result<crate::net::UsageReport, netrunner_logger::AppError> {
        Ok(crate::net::UsageReport { used_bytes: 0, limit_bytes: None, over_limit: false })
    }
    async fn report_usage_batch(
        &self,
        _b: &str,
        _d: &[crate::net::UsageDelta],
    ) -> Result<std::collections::HashMap<String, crate::net::UsageReport>, netrunner_logger::AppError> {
        Ok(Default::default())
    }
    async fn report_node_health(&self, _r: crate::net::NodeHealthReport) -> Result<(), netrunner_logger::AppError> {
        Ok(())
    }
    async fn list_mesh_peers(&self) -> Result<Vec<crate::net::MeshPeer>, netrunner_logger::AppError> {
        if self.peers_ok {
            Ok(self.peers.clone())
        } else {
            Err(netrunner_logger::AppError::new(netrunner_logger::ERR_INFRA_TIMEOUT, "panel", "down"))
        }
    }
    async fn validate_mesh_peer(&self, id: &str, secret: &str) -> Result<(), netrunner_logger::AppError> {
        if self.admits.iter().any(|(i, s)| i == id && s == secret) {
            Ok(())
        } else {
            Err(netrunner_logger::AppError::new(netrunner_logger::ERR_AUTH_FAILED, "panel", "no"))
        }
    }
}

fn panel_peer(id: &str, host: &str) -> crate::net::MeshPeer {
    crate::net::MeshPeer {
        node_id: id.into(),
        host: host.into(),
        port: 443,
        decoy_sni: "panel.example".into(),
        nrxp_secret: "p".repeat(64),
        nrxp_static_public: "q".repeat(64),
    }
}

#[tokio::test]
async fn hybrid_merges_panel_and_directory_peers_and_the_panel_wins_conflicts() {
    use crate::net::AuthValidator;
    let sw = swarm();
    let now = unix_now();
    let node = std::sync::Arc::new(dir(1, "10.0.0.1", &sw));
    // в каталоге: D (свой адрес) и E (тот же адрес, что у панельного пира)
    let d = {
        let id = SwarmIdentity::from_static_private([10; 32]);
        NodeDescriptor::sign(&id.signing, id.static_pub, Roles(Roles::RELAY), 3, (2, 6), 1, now, 3600, String::new(),
            vec![Endpoint { kind: EndpointKind::Tcp, host: "10.9.0.1".into(), port: 443 }])
    };
    let e = {
        let id = SwarmIdentity::from_static_private([11; 32]);
        NodeDescriptor::sign(&id.signing, id.static_pub, Roles(Roles::RELAY), 3, (2, 6), 1, now, 3600, String::new(),
            vec![Endpoint { kind: EndpointKind::Tcp, host: "10.9.1.1".into(), port: 443 }])
    };
    node.insert(d.clone(), now);
    node.insert(e.clone(), now);

    let panel = std::sync::Arc::new(MockPanel {
        peers: vec![panel_peer("panel-uuid-1", "10.9.1.1")],
        peers_ok: true,
        admits: vec![("panel-uuid-1".into(), "internal".into())],
    });
    let hybrid = DirectoryValidator::new(node.clone(), Some(panel.clone()));
    let peers = hybrid.list_mesh_peers().await.unwrap();
    let ids: Vec<&str> = peers.iter().map(|p| p.node_id.as_str()).collect();
    assert_eq!(peers.len(), 2, "{ids:?}");
    assert_eq!(peers[0].node_id, "panel-uuid-1", "панель первой");
    assert!(ids.contains(&node_id_hex(&d.node_id).as_str()));
    assert!(!ids.contains(&node_id_hex(&e.node_id).as_str()), "E с адресом панельного пира — побеждает панель");

    // панель недоступна — каталог продолжает работать
    let down = DirectoryValidator::new(node.clone(), Some(std::sync::Arc::new(MockPanel { peers: vec![], peers_ok: false, admits: vec![] })));
    assert_eq!(down.list_mesh_peers().await.unwrap().len(), 2, "D и E из каталога");

    // без панели — только каталог
    let alone = DirectoryValidator::new(node.clone(), None);
    assert_eq!(alone.list_mesh_peers().await.unwrap().len(), 2);

    // допуск: «или»
    assert!(hybrid.validate_mesh_peer("panel-uuid-1", "internal").await.is_ok(), "панель подтвердила");
    assert!(hybrid.validate_mesh_peer("panel-uuid-1", "wrong").await.is_err());
    let member = node_id_hex(&d.node_id);
    assert!(hybrid.validate_mesh_peer(&member, &sw.node_secret(&d.node_id)).await.is_ok(), "член роя");
    assert!(hybrid.validate_mesh_peer(&member, "nope").await.is_err());
    // пользователи — из панели
    assert!(hybrid.validate("jwt").await.is_ok());
    assert!(alone.validate("jwt").await.is_err());
}
