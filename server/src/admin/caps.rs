//! Доверенности (токены-способности) для доступа к mesh-сети — этап B из
//! `docs/DECENTRALIZATION.md`, пока только на стороне панели.
//!
//! Доверенность — подписанный сертификат: «`issuer` поручает `holder` действовать в сети
//! `mesh` с такими-то ролями, на таких-то узлах, в такой-то срок и (возможно) передоверять
//! это дальше». Корень цепочки подписан корневым ключом сети; каждый следующий сертификат
//! подписан ключом держателя предыдущего и обязан быть **не шире** родительского
//! (роли ⊆, узлы ⊆, срок ⊆, глубина передоверия строго меньше). Поэтому проверка идёт
//! офлайн, зная только публичный корень сети и список отозванных серийных номеров.
//!
//! Подписывается не JSON, а фиксированный текстовый вид ([`Cert::signing_bytes`]): его
//! просто воспроизвести в другой реализации, без канонизации.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Допустимые роли (см. таблицу ролей в `docs/DECENTRALIZATION.md` §4).
pub const ROLES: &[&str] = &["client", "guard", "relay", "egress", "operator"];
/// Максимум сертификатов в цепочке (корневая доверенность + передоверия).
pub const MAX_CHAIN: usize = 4;
/// Допуск расхождения часов, секунды.
pub const CLOCK_SKEW: u64 = 300;

const DOMAIN: &str = "nrxp-cap1";
const TOKEN_PREFIX: &str = "nrxp-cap1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cert {
    pub mesh: String,
    pub serial: String,
    /// Публичный ключ подписанта (hex): корень сети либо держатель родителя.
    pub issuer: String,
    /// Публичный ключ получателя доверенности (hex).
    pub holder: String,
    /// Отсортированные уникальные роли из [`ROLES`].
    pub roles: Vec<String>,
    /// Отсортированные `node_id` (32 hex) либо `None` — любые узлы сети.
    pub nodes: Option<Vec<String>>,
    pub nbf: u64,
    pub exp: u64,
    /// Сколько ещё уровней передоверия разрешено ниже этого сертификата.
    pub delegate: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedCert {
    pub cert: Cert,
    pub sig: String,
}

impl Cert {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let nodes = match &self.nodes {
            None => "*".to_string(),
            Some(n) => n.join(","),
        };
        format!(
            "{DOMAIN}\nmesh={}\nserial={}\nissuer={}\nholder={}\nroles={}\nnodes={}\nnbf={}\nexp={}\ndelegate={}\n",
            self.mesh,
            self.serial,
            self.issuer,
            self.holder,
            self.roles.join(","),
            nodes,
            self.nbf,
            self.exp,
            self.delegate
        )
        .into_bytes()
    }

    pub fn sign(self, key: &SigningKey) -> SignedCert {
        let sig = hex::encode(key.sign(&self.signing_bytes()).to_bytes());
        SignedCert { cert: self, sig }
    }
}

/// Приводит роли/узлы к каноническому виду и проверяет синтаксис.
pub fn normalize(
    roles: &[String],
    nodes: Option<&[String]>,
) -> Result<(Vec<String>, Option<Vec<String>>), String> {
    let mut roles: Vec<String> = roles.iter().map(|r| r.trim().to_ascii_lowercase()).collect();
    roles.sort();
    roles.dedup();
    if roles.is_empty() {
        return Err("нужна хотя бы одна роль".into());
    }
    if let Some(bad) = roles.iter().find(|r| !ROLES.contains(&r.as_str())) {
        return Err(format!("неизвестная роль «{bad}»"));
    }
    let nodes = match nodes {
        None => None,
        Some(list) => {
            let mut v: Vec<String> = list.iter().map(|n| n.trim().to_ascii_lowercase()).collect();
            v.sort();
            v.dedup();
            if v.is_empty() {
                return Err("список узлов пуст: уберите ограничение или укажите узлы".into());
            }
            if v.len() > 64 {
                return Err("не больше 64 узлов в одной доверенности".into());
            }
            if let Some(bad) = v
                .iter()
                .find(|n| n.len() != 32 || !n.bytes().all(|b| b.is_ascii_hexdigit()))
            {
                return Err(format!("node_id «{bad}»: ожидается 32 hex-символа"));
            }
            Some(v)
        }
    };
    Ok((roles, nodes))
}

fn is_subset(child: &[String], parent: &[String]) -> bool {
    child.iter().all(|c| parent.contains(c))
}

/// Проверяет, что `child` не шире `parent`.
pub fn check_attenuation(parent: &Cert, child: &Cert) -> Result<(), String> {
    if child.mesh != parent.mesh {
        return Err("доверенность относится к другой сети".into());
    }
    if parent.delegate == 0 {
        return Err("родительская доверенность не разрешает передоверие".into());
    }
    if child.delegate >= parent.delegate {
        return Err("глубина передоверия должна быть меньше родительской".into());
    }
    if !is_subset(&child.roles, &parent.roles) {
        return Err("роли шире родительских".into());
    }
    match (&parent.nodes, &child.nodes) {
        (None, _) => {}
        (Some(_), None) => return Err("родитель ограничен узлами, потомок — нет".into()),
        (Some(p), Some(c)) => {
            if !is_subset(c, p) {
                return Err("узлы шире родительских".into());
            }
        }
    }
    if child.nbf < parent.nbf || child.exp > parent.exp {
        return Err("срок выходит за пределы родительского".into());
    }
    Ok(())
}

/// Результат успешной проверки цепочки.
#[derive(Clone, Debug, Serialize)]
pub struct Verified {
    pub effective: Cert,
    pub depth: usize,
    pub serials: Vec<String>,
}

fn parse_pub(hex_key: &str) -> Result<VerifyingKey, String> {
    let b: [u8; 32] = hex::decode(hex_key)
        .map_err(|_| "ключ не hex".to_string())?
        .try_into()
        .map_err(|_| "ключ должен быть 32 байта".to_string())?;
    VerifyingKey::from_bytes(&b).map_err(|_| "некорректный публичный ключ".to_string())
}

/// Проверяет цепочку: подписи, связность, ослабление, сроки, отзыв.
///
/// `roots` — публичные ключи, которым сеть сейчас доверяет (текущий корень и корни в
/// переходном периоде), `is_revoked` — отзыв по серийному номеру.
pub fn verify_chain(
    chain: &[SignedCert],
    mesh: &str,
    roots: &[String],
    is_revoked: &dyn Fn(&str) -> bool,
    now: u64,
) -> Result<Verified, String> {
    if chain.is_empty() {
        return Err("пустая цепочка".into());
    }
    if chain.len() > MAX_CHAIN {
        return Err(format!("цепочка длиннее {MAX_CHAIN}"));
    }
    for (i, link) in chain.iter().enumerate() {
        let c = &link.cert;
        if c.mesh != mesh {
            return Err(format!("звено {}: другая сеть", i + 1));
        }
        let (roles, nodes) = normalize(&c.roles, c.nodes.as_deref())
            .map_err(|e| format!("звено {}: {e}", i + 1))?;
        if roles != c.roles || nodes != c.nodes {
            return Err(format!("звено {}: роли/узлы не в каноническом виде", i + 1));
        }
        if i == 0 {
            if !roots.iter().any(|r| r.eq_ignore_ascii_case(&c.issuer)) {
                return Err("корень цепочки не доверенный (ключ сети сменён или чужая сеть)".into());
            }
        } else {
            let parent = &chain[i - 1].cert;
            if c.issuer != parent.holder {
                return Err(format!("звено {}: подписант не держатель предыдущего", i + 1));
            }
            check_attenuation(parent, c).map_err(|e| format!("звено {}: {e}", i + 1))?;
        }
        let sig: [u8; 64] = hex::decode(&link.sig)
            .map_err(|_| format!("звено {}: подпись не hex", i + 1))?
            .try_into()
            .map_err(|_| format!("звено {}: подпись должна быть 64 байта", i + 1))?;
        parse_pub(&c.issuer)?
            .verify_strict(&c.signing_bytes(), &Signature::from_bytes(&sig))
            .map_err(|_| format!("звено {}: подпись неверна", i + 1))?;
        if now + CLOCK_SKEW < c.nbf {
            return Err(format!("звено {}: ещё не действует", i + 1));
        }
        if now > c.exp + CLOCK_SKEW {
            return Err(format!("звено {}: срок истёк", i + 1));
        }
        if is_revoked(&c.serial) {
            return Err(format!("звено {}: отозвано ({})", i + 1, c.serial));
        }
    }
    Ok(Verified {
        effective: chain[chain.len() - 1].cert.clone(),
        depth: chain.len(),
        serials: chain.iter().map(|l| l.cert.serial.clone()).collect(),
    })
}

// ── Токен: ключ держателя + цепочка ────────────────────────────────────────

pub fn encode_token(holder_seed: &[u8; 32], chain: &[SignedCert]) -> String {
    let json = serde_json::to_vec(chain).expect("chain serializes");
    format!("{TOKEN_PREFIX}.{}.{}", b64_encode(holder_seed), b64_encode(&json))
}

pub fn decode_token(token: &str) -> Result<([u8; 32], Vec<SignedCert>), String> {
    let mut parts = token.trim().split('.');
    if parts.next() != Some(TOKEN_PREFIX) {
        return Err(format!("ожидается префикс «{TOKEN_PREFIX}.»"));
    }
    let (Some(seed), Some(body), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err("токен должен состоять из трёх частей".into());
    };
    let seed: [u8; 32] = b64_decode(seed)?
        .try_into()
        .map_err(|_| "ключ держателя должен быть 32 байта".to_string())?;
    let chain: Vec<SignedCert> =
        serde_json::from_slice(&b64_decode(body)?).map_err(|e| format!("цепочка: {e}"))?;
    Ok((seed, chain))
}

/// Публичный ключ (hex) для seed.
pub fn pub_hex(seed: &[u8; 32]) -> String {
    hex::encode(SigningKey::from_bytes(seed).verifying_key().to_bytes())
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |a, (i, b)| a | (*b as u32) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(B64[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = B64
            .iter()
            .position(|&b| b == c)
            .ok_or_else(|| "недопустимый символ в токене".to_string())? as u32;
        acc = acc << 6 | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if bits >= 6 {
        return Err("обрезанный токен".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MESH: &str = "m1";
    const NOW: u64 = 1_000_000;

    fn key(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }
    fn pubh(k: &SigningKey) -> String {
        hex::encode(k.verifying_key().to_bytes())
    }
    fn cert(issuer: &SigningKey, holder: &SigningKey, serial: &str) -> Cert {
        Cert {
            mesh: MESH.into(),
            serial: serial.into(),
            issuer: pubh(issuer),
            holder: pubh(holder),
            roles: vec!["client".into(), "relay".into()],
            nodes: None,
            nbf: NOW - 10,
            exp: NOW + 1000,
            delegate: 2,
        }
    }
    fn never(_: &str) -> bool {
        false
    }

    #[test]
    fn chain_with_attenuation_verifies() {
        let (root, a, b) = (key(1), key(2), key(3));
        let c1 = cert(&root, &a, "s1").sign(&root);
        let mut child = cert(&a, &b, "s2");
        child.roles = vec!["client".into()];
        child.delegate = 1;
        child.exp = NOW + 500;
        let c2 = child.sign(&a);
        let v = verify_chain(&[c1, c2], MESH, &[pubh(&root)], &never, NOW).unwrap();
        assert_eq!(v.effective.serial, "s2");
        assert_eq!(v.depth, 2);
    }

    #[test]
    fn widening_is_rejected() {
        let (root, a, b) = (key(1), key(2), key(3));
        let c1 = cert(&root, &a, "s1").sign(&root);
        for tweak in [
            |c: &mut Cert| c.roles.push("egress".into()),
            |c: &mut Cert| c.exp += 1,
            |c: &mut Cert| c.delegate = 2,
        ] {
            let mut child = cert(&a, &b, "s2");
            child.delegate = 1;
            tweak(&mut child);
            child.roles.sort();
            let c2 = child.sign(&a);
            assert!(verify_chain(&[c1.clone(), c2], MESH, &[pubh(&root)], &never, NOW).is_err());
        }
    }

    #[test]
    fn node_scope_cannot_be_dropped() {
        let (root, a, b) = (key(1), key(2), key(3));
        let mut p = cert(&root, &a, "s1");
        p.nodes = Some(vec!["a".repeat(32)]);
        let mut c = cert(&a, &b, "s2");
        c.delegate = 1;
        assert!(check_attenuation(&p, &c).is_err());
        c.nodes = Some(vec!["a".repeat(32)]);
        assert!(check_attenuation(&p, &c).is_ok());
    }

    #[test]
    fn tamper_revoke_expiry_and_untrusted_root() {
        let (root, a, evil) = (key(1), key(2), key(9));
        let c1 = cert(&root, &a, "s1").sign(&root);
        let roots = [pubh(&root)];
        assert!(verify_chain(&[c1.clone()], MESH, &roots, &never, NOW).is_ok());

        let mut t = c1.clone();
        t.cert.exp += 1;
        assert!(verify_chain(&[t], MESH, &roots, &never, NOW).is_err());

        assert!(verify_chain(&[c1.clone()], MESH, &roots, &|s| s == "s1", NOW).is_err());
        assert!(verify_chain(&[c1.clone()], MESH, &roots, &never, NOW + 5000).is_err());
        assert!(verify_chain(&[c1.clone()], MESH, &roots, &never, NOW - 5000).is_err());
        assert!(verify_chain(&[c1.clone()], "other", &roots, &never, NOW).is_err());

        let forged = cert(&evil, &a, "s1").sign(&evil);
        assert!(verify_chain(&[forged], MESH, &roots, &never, NOW).is_err());
    }

    #[test]
    fn revoked_ancestor_kills_descendants() {
        let (root, a, b) = (key(1), key(2), key(3));
        let c1 = cert(&root, &a, "s1").sign(&root);
        let mut ch = cert(&a, &b, "s2");
        ch.delegate = 1;
        let c2 = ch.sign(&a);
        let r = verify_chain(&[c1, c2], MESH, &[pubh(&root)], &|s| s == "s1", NOW);
        assert!(r.is_err());
    }

    #[test]
    fn token_roundtrip() {
        let (root, a) = (key(1), key(2));
        let chain = vec![cert(&root, &a, "s1").sign(&root)];
        let t = encode_token(&[2; 32], &chain);
        let (seed, back) = decode_token(&t).unwrap();
        assert_eq!(seed, [2; 32]);
        assert_eq!(back, chain);
        assert!(decode_token("nrxp-cap1.x").is_err());
        assert!(decode_token(&t.replace("nrxp-cap1", "bad")).is_err());
    }

    #[test]
    fn b64_roundtrip_all_lengths() {
        for n in 0..40u8 {
            let data: Vec<u8> = (0..n).map(|i| i.wrapping_mul(37)).collect();
            assert_eq!(b64_decode(&b64_encode(&data)).unwrap(), data);
        }
    }

    #[test]
    fn normalize_rejects_garbage() {
        assert!(normalize(&[], None).is_err());
        assert!(normalize(&["root".into()], None).is_err());
        assert!(normalize(&["client".into()], Some(&[])).is_err());
        assert!(normalize(&["client".into()], Some(&["zz".into()])).is_err());
        let (r, n) = normalize(&["Relay".into(), "client".into(), "relay".into()], None).unwrap();
        assert_eq!(r, vec!["client", "relay"]);
        assert!(n.is_none());
    }
}
