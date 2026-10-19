//! # Каталог узлов без панели (этап A децентрализации)
//!
//! Узлы знают друг о друге из подписанных самоописаний ([`descriptor`]), хранят их
//! по ограниченным правилам допуска ([`store`]) и обмениваются ими по уже
//! аутентифицированным mesh-сессиям ([`gossip`]). Панель остаётся для учётных
//! записей и биллинга, но не нужна для того, чтобы узел нашёл соседей.
//!
//! Подробности, модель угроз и дальнейшие этапы — `docs/DECENTRALIZATION.md`.
//!
//! ```text
//!   seed-узлы ─▶ Directory ◀── gossip (Digest / Reply / Push) ──▶ соседи
//!                   │
//!                   ├─ peers()               → NodeMesh::update_peers   (вместо list_mesh_peers панели)
//!                   └─ validate_mesh_peer()  → допуск пира               (вместо /mesh/validate панели)
//! ```

pub mod client;
pub mod descriptor;
pub mod gossip;
pub mod store;
pub mod swarm;
mod validator;

#[cfg(test)]
mod net_tests;
#[cfg(test)]
mod tests;

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub use descriptor::{
    derive_node_id, Endorsement, features, host_is_public, node_id_hex, parse_node_id, DescriptorError,
    Endpoint, EndpointKind, NodeDescriptor, NodeId, Roles, MAX_VALIDITY_SECS,
};
pub use client::{ClientDirectory, LearnedNode};
pub use gossip::{GossipError, Message, Stats};
pub use store::{DescriptorStore, Insert, Reject, StoreConfig};
pub use swarm::{ct_eq_str, pair_proof, pairwise_secret, SwarmIdentity, SwarmKey};
pub use validator::DirectoryValidator;

use super::auth::MeshPeer;

/// Текущее время Unix, секунды.
pub fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Настройки каталога узла.
#[derive(Debug, Clone)]
pub struct DirectoryConfig {
    pub store: StoreConfig,
    /// Публичные адреса этого узла (попадают в его запись).
    pub advertise: Vec<Endpoint>,
    pub decoy_sni: String,
    pub roles: u8,
    /// Диапазон принимаемых версий NRXP.
    pub proto: (u8, u8),
    /// Поручительства авторитетов за этот узел (управляемая сеть).
    pub endorsements: Vec<Endorsement>,
    /// Строгий допуск: о ком в каталоге уже есть запись, тот обязан предъявить парное
    /// доказательство (иначе любой член роя мог бы выдать себя за него). Выключено по
    /// умолчанию ради совместимости с узлами, не знающими `PAIRWISE`.
    pub strict_pairwise: bool,
    /// Срок жизни своей записи.
    pub validity_secs: u64,
    /// Не чаще одного входящего обмена за столько секунд на весь узел.
    pub max_requests_per_window: u32,
    pub window_secs: u64,
    /// Запросов `PeerHint` от клиентов за окно (отдельно от обмена между узлами).
    pub max_hints_per_window: u32,
}

impl Default for DirectoryConfig {
    fn default() -> Self {
        Self {
            store: StoreConfig::default(),
            advertise: Vec::new(),
            decoy_sni: String::new(),
            roles: Roles::RELAY,
            proto: (2, 6),
            endorsements: Vec::new(),
            strict_pairwise: false,
            validity_secs: 24 * 3600,
            max_requests_per_window: 60,
            window_secs: 10,
            max_hints_per_window: 30,
        }
    }
}

struct Inner {
    store: DescriptorStore,
    own: NodeDescriptor,
    /// Действующие поручительства: подмешиваются в каждую перевыпущенную запись.
    endorsements: Vec<Endorsement>,
    round: u64,
    window_start: u64,
    window_count: u32,
    hint_window_start: u64,
    hint_count: u32,
}

/// Каталог одного узла. Все методы принимают `now` (Unix, секунды), чтобы
/// поведение было детерминированным в тестах.
pub struct Directory {
    identity: SwarmIdentity,
    swarm: SwarmKey,
    cfg: DirectoryConfig,
    inner: Mutex<Inner>,
}

/// Итог входящего обмена.
#[derive(Debug)]
pub enum Handled {
    /// Нужно ответить этими байтами.
    Reply(Vec<u8>),
    /// Ответа нет (получили `Push`).
    Absorbed(Stats),
}

#[derive(Debug, PartialEq, Eq)]
pub enum DirectoryError {
    Gossip(GossipError),
    RateLimited,
    /// Ждали запрос, пришёл ответ (или наоборот).
    UnexpectedMessage,
}

impl std::fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Gossip(e) => write!(f, "{e}"),
            Self::RateLimited => write!(f, "gossip rate limit exceeded"),
            Self::UnexpectedMessage => write!(f, "unexpected gossip message"),
        }
    }
}

impl std::error::Error for DirectoryError {}

impl From<GossipError> for DirectoryError {
    fn from(e: GossipError) -> Self {
        Self::Gossip(e)
    }
}

impl Directory {
    pub fn new(identity: SwarmIdentity, swarm: SwarmKey, cfg: DirectoryConfig, now: u64) -> Self {
        let store = DescriptorStore::new(cfg.store.clone(), Some(identity.node_id));
        let endorsements = cfg.endorsements.clone();
        let own = Self::sign_own(&identity, &cfg, &endorsements, now, now);
        Self {
            identity,
            swarm,
            cfg,
            inner: Mutex::new(Inner {
                store,
                own,
                endorsements,
                round: 0,
                window_start: now,
                window_count: 0,
                hint_window_start: now,
                hint_count: 0,
            }),
        }
    }

    fn sign_own(
        identity: &SwarmIdentity,
        cfg: &DirectoryConfig,
        endorsements: &[Endorsement],
        seq: u64,
        now: u64,
    ) -> NodeDescriptor {
        NodeDescriptor::sign_endorsed(
            &identity.signing,
            identity.static_pub,
            Roles(cfg.roles),
            features::GOSSIP | features::PAIRWISE,
            cfg.proto,
            seq,
            now,
            cfg.validity_secs,
            cfg.decoy_sni.clone(),
            cfg.advertise.clone(),
            endorsements.to_vec(),
        )
    }

    /// Подставляет новые (продлённые) поручительства и сразу перевыпускает запись.
    /// Поручительства за чужой ключ отбрасываются, лишние сверх предела — тоже.
    pub fn set_endorsements(&self, list: Vec<Endorsement>, now: u64) {
        let mut g = self.inner.lock().unwrap();
        let mine: Vec<Endorsement> = list
            .into_iter()
            // Принимаем только поручительства именно за этот узел.
            .filter(|e| e.valid_for_keys(&self.identity.static_pub, &self.identity.signing.verifying_key().to_bytes()))
            .take(descriptor::MAX_ENDORSEMENTS)
            .collect();
        if mine == g.endorsements {
            return;
        }
        g.endorsements = mine;
        let seq = (g.own.seq + 1).max(now);
        g.own = Self::sign_own(&self.identity, &self.cfg, &g.endorsements, seq, now);
    }

    /// Живая запись об узле из каталога (не о нас самих).
    pub fn lookup(&self, id: &NodeId, now: u64) -> Option<NodeDescriptor> {
        self.inner.lock().unwrap().store.live_get(id, now).cloned()
    }

    pub fn node_id(&self) -> NodeId {
        self.identity.node_id
    }

    pub fn node_id_hex(&self) -> String {
        self.identity.node_id_hex()
    }

    pub fn identity(&self) -> &SwarmIdentity {
        &self.identity
    }

    pub fn swarm(&self) -> &SwarmKey {
        &self.swarm
    }

    /// Своя запись; перевыпускается, когда осталось меньше трети срока.
    pub fn own(&self, now: u64) -> NodeDescriptor {
        let mut g = self.inner.lock().unwrap();
        let remaining = g.own.valid_until.saturating_sub(now);
        if remaining < self.cfg.validity_secs.min(MAX_VALIDITY_SECS) / 3 {
            let seq = (g.own.seq + 1).max(now);
            g.own = Self::sign_own(&self.identity, &self.cfg, &g.endorsements, seq, now);
        }
        g.own.clone()
    }

    /// Принимает запись (из файла, seed, чужого gossip) по общим правилам хранилища.
    pub fn insert(&self, d: NodeDescriptor, now: u64) -> Insert {
        self.inner.lock().unwrap().store.insert(d, now)
    }

    /// Принимает запись в бинарной форме.
    pub fn insert_bytes(&self, b: &[u8], now: u64) -> Insert {
        match NodeDescriptor::decode(b) {
            Ok(d) => self.insert(d, now),
            Err(e) => Insert::Rejected(Reject::Invalid(e)),
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().store.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Снимок живых записей (для панели управления).
    pub fn records(&self, now: u64) -> Vec<NodeDescriptor> {
        let g = self.inner.lock().unwrap();
        let mut v: Vec<NodeDescriptor> = g.store.live(now).cloned().collect();
        v.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        v
    }

    pub fn gc(&self, now: u64) -> usize {
        self.inner.lock().unwrap().store.gc(now)
    }

    pub fn export(&self, now: u64) -> Vec<u8> {
        self.inner.lock().unwrap().store.export(now)
    }

    pub fn import(&self, bytes: &[u8], now: u64) -> usize {
        self.inner.lock().unwrap().store.import(bytes, now)
    }

    fn peer_of(&self, d: &NodeDescriptor) -> Option<MeshPeer> {
        let tcp = d.endpoint(EndpointKind::Tcp)?;
        Some(MeshPeer {
            node_id: node_id_hex(&d.node_id),
            host: tcp.host.clone(),
            port: tcp.port,
            decoy_sni: d.decoy_sni.clone(),
            nrxp_secret: self.swarm.node_secret(&d.node_id),
            nrxp_static_public: hex::encode(d.static_pub),
        })
    }

    /// Живые соседи в виде, который понимает `NodeMesh` (себя там нет).
    pub fn peers(&self, now: u64) -> Vec<MeshPeer> {
        let g = self.inner.lock().unwrap();
        let mut v: Vec<MeshPeer> = g
            .store
            .live(now)
            .filter(|d| d.roles.has(Roles::RELAY))
            .filter_map(|d| self.peer_of(d))
            .collect();
        v.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        v
    }

    /// Соседи, которым можно слать gossip (старым узлам неизвестный кадр рвёт ногу).
    pub fn gossip_peers(&self, now: u64) -> Vec<MeshPeer> {
        let g = self.inner.lock().unwrap();
        g.store
            .live(now)
            .filter(|d| d.supports_gossip())
            .filter_map(|d| self.peer_of(d))
            .collect()
    }

    /// Допуск mesh-пира: он знает секрет роя для своего `node_id`. В управляемой
    /// сети (заданы ключи авторитетов) он к тому же обязан быть в каталоге с
    /// действующим поручительством.
    pub fn validate_mesh_peer(&self, peer_id: &str, secret: &str) -> bool {
        self.validate_mesh_peer_at(peer_id, secret, unix_now())
    }

    pub fn validate_mesh_peer_at(&self, peer_id: &str, secret: &str, now: u64) -> bool {
        let Some(id) = parse_node_id(peer_id) else {
            return false;
        };
        // Секрет: `<секрет роя>` либо `<секрет роя>.<парное доказательство>`.
        let (swarm_part, proof_part) = match secret.split_once('.') {
            Some((s, p)) => (s, Some(p)),
            None => (secret, None),
        };
        if !self.swarm.check_node_secret(&id, swarm_part) {
            return false;
        }
        match self.lookup(&id, now) {
            // Узел уже в каталоге: его личность держит парный секрет, а не ключ роя.
            Some(known) => match proof_part {
                Some(p) => ct_eq_str(&self.expected_proof(&known), p),
                None => !self.cfg.strict_pairwise,
            },
            // Незнакомый: знакомство по ключу роя — но не в управляемой сети, где
            // допускаются только поручённые авторитетом.
            None => self.cfg.store.trust_anchors.is_empty(),
        }
    }

    fn expected_proof(&self, peer: &NodeDescriptor) -> String {
        pair_proof(&pairwise_secret(&self.identity.static_private, &peer.static_pub))
    }

    /// Секрет для mesh-токена при подключении к `peer`: наш секрет роя, а узлам с
    /// признаком `PAIRWISE` — ещё и парное доказательство (`<роя>.<парное>`).
    /// `None` — об этом узле в каталоге нет записи (токен выбирает вызывающий).
    pub fn mesh_secret_for(&self, peer: &NodeId, now: u64) -> Option<String> {
        let known = self.lookup(peer, now)?;
        let base = self.swarm.node_secret(&self.identity.node_id);
        Some(if known.features & features::PAIRWISE != 0 {
            format!("{base}.{}", self.expected_proof(&known))
        } else {
            base
        })
    }

    /// Работает ли сеть под авторитетом (заданы ключи).
    pub fn is_managed(&self) -> bool {
        !self.cfg.store.trust_anchors.is_empty()
    }

    /// Первое сообщение обмена (дайджест). Счётчик раундов сдвигает окно дайджеста.
    pub fn begin_exchange(&self, now: u64) -> Vec<u8> {
        let own = self.own(now);
        let mut g = self.inner.lock().unwrap();
        g.round += 1;
        let round = g.round;
        gossip::build_digest(&g.store, Some(&own), now, round).encode()
    }

    /// Входящее сообщение: `Digest` → ответ, `Push` → поглощено.
    pub fn handle_incoming(&self, payload: &[u8], now: u64) -> Result<Handled, DirectoryError> {
        let msg = Message::decode(payload)?;
        let own = self.own(now);
        let mut g = self.inner.lock().unwrap();
        // Обмен узлов и запросы клиентов считаются в разных окнах: наплыв клиентов
        // не должен глушить gossip.
        if matches!(msg, Message::Digest(_) | Message::Push(_)) {
            if now.saturating_sub(g.window_start) >= self.cfg.window_secs {
                g.window_start = now;
                g.window_count = 0;
            }
            g.window_count += 1;
            if g.window_count > self.cfg.max_requests_per_window {
                return Err(DirectoryError::RateLimited);
            }
        }
        match msg {
            Message::Digest(remote) => {
                Ok(Handled::Reply(gossip::respond(&g.store, Some(&own), &remote, now).encode()))
            }
            Message::Push(_) => Ok(Handled::Absorbed(gossip::absorb(&mut g.store, msg, now)?)),
            Message::HintRequest { max } => {
                // Клиентам — отдельный бюджет: их наплыв не должен глушить обмен узлов.
                if now.saturating_sub(g.hint_window_start) >= self.cfg.window_secs {
                    g.hint_window_start = now;
                    g.hint_count = 0;
                }
                g.hint_count += 1;
                if g.hint_count > self.cfg.max_hints_per_window {
                    return Err(DirectoryError::RateLimited);
                }
                let records = gossip::hint_records(&g.store, Some(&own), max, now);
                Ok(Handled::Reply(Message::HintReply(records).encode()))
            }
            Message::Reply { .. } | Message::HintReply(_) => Err(DirectoryError::UnexpectedMessage),
        }
    }

    /// Ответ на наш дайджест: принять записи, подготовить `Push` с запрошенным.
    pub fn complete_exchange(
        &self,
        reply: &[u8],
        now: u64,
    ) -> Result<(Stats, Option<Vec<u8>>), DirectoryError> {
        let msg = Message::decode(reply)?;
        let own = self.own(now);
        let mut g = self.inner.lock().unwrap();
        let (stats, push) = gossip::finish(&mut g.store, Some(&own), msg, now)?;
        Ok((stats, push.map(|m| m.encode())))
    }
}
