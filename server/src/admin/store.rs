//! Состояние панели: mesh-сети, их ключи, выданные доверенности, отзывы. Хранится одним
//! JSON-файлом (`0600`, запись атомарной заменой) и журналом аудита рядом.
//!
//! Все операции над [`State`] — чистые функции от `now`, без ввода-вывода, чтобы их можно
//! было проверять тестами; файл трогает только [`Store`].

use super::caps::{self, Cert, SignedCert, MAX_CHAIN};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const DAY: u64 = 86_400;
const MAX_TTL: u64 = 365 * DAY;
const MIN_TTL: u64 = 60;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct State {
    pub meshes: Vec<Mesh>,
    /// Когда последний раз снимали резервную копию (для напоминания на обзоре).
    #[serde(default)]
    pub last_backup: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Mesh {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub note: String,
    pub created: u64,
    /// Ключ роя (`PROXY_SWARM_KEY` узлов этой сети), hex.
    pub swarm_key: String,
    pub swarm_epoch: u32,
    pub swarm_prev: Option<PrevSwarm>,
    /// Seed корневого ключа подписи доверенностей, hex.
    pub root_seed: String,
    pub root_epoch: u32,
    pub root_prev: Vec<PrevRoot>,
    pub revoked: Vec<Revoked>,
    pub grants: Vec<Grant>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrevSwarm {
    pub key: String,
    pub until: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrevRoot {
    pub public: String,
    pub epoch: u32,
    pub until: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Revoked {
    pub serial: String,
    #[serde(default)]
    pub label: String,
    pub at: u64,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Grant {
    pub serial: String,
    pub label: String,
    #[serde(default)]
    pub note: String,
    pub parent: Option<String>,
    pub created: u64,
    /// Ключ держателя. Панель хранит его, чтобы уметь выдавать передоверия от его имени
    /// и перевыпускать цепочку при ротации корня.
    pub holder_seed: String,
    pub chain: Vec<SignedCert>,
    pub root_epoch: u32,
}

#[derive(Debug, Deserialize)]
pub struct IssueRequest {
    pub label: String,
    pub parent: Option<String>,
    pub roles: Vec<String>,
    pub nodes: Option<Vec<String>>,
    pub ttl_secs: u64,
    #[serde(default)]
    pub delegate: u8,
}

// ── Вспомогательное ────────────────────────────────────────────────────────

fn rand_hex<const N: usize>() -> String {
    hex::encode(rand::random::<[u8; N]>())
}

/// Короткий отпечаток секрета/ключа для сверки глазами, не раскрывающий значение.
pub fn fingerprint(hex_value: &str) -> String {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest([b"nrxp-admin-fp1".as_slice(), hex_value.as_bytes()].concat());
    hex::encode(&d[..8]).as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap_or("")).collect::<Vec<_>>().join("-")
}

fn seed_of(hex_seed: &str) -> Result<[u8; 32], String> {
    hex::decode(hex_seed)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| "повреждён ключ в хранилище".to_string())
}

fn clean_text(s: &str, what: &str, max: usize) -> Result<String, String> {
    let s = s.trim();
    if s.is_empty() || s.chars().count() > max || s.chars().any(char::is_control) {
        return Err(format!("{what}: от 1 до {max} символов, без управляющих"));
    }
    Ok(s.to_string())
}

impl Mesh {
    pub fn root_key(&self) -> Result<SigningKey, String> {
        Ok(SigningKey::from_bytes(&seed_of(&self.root_seed)?))
    }

    pub fn root_pub(&self) -> Result<String, String> {
        Ok(hex::encode(self.root_key()?.verifying_key().to_bytes()))
    }

    /// Корни, которым сеть доверяет сейчас: текущий и ещё не истёкшие прежние.
    pub fn accepted_roots(&self, now: u64) -> Result<Vec<String>, String> {
        let mut v = vec![self.root_pub()?];
        v.extend(self.root_prev.iter().filter(|r| r.until > now).map(|r| r.public.clone()));
        Ok(v)
    }

    pub fn is_revoked(&self, serial: &str) -> bool {
        self.revoked.iter().any(|r| r.serial == serial)
    }

    fn grant(&self, serial: &str) -> Result<&Grant, String> {
        self.grants
            .iter()
            .find(|g| g.serial == serial)
            .ok_or_else(|| "доверенность не найдена".to_string())
    }

    fn revoke_serial(&mut self, serial: &str, reason: &str, now: u64) {
        if !self.is_revoked(serial) {
            let label = self.grants.iter().find(|g| g.serial == serial).map(|g| g.label.clone()).unwrap_or_default();
            self.revoked.push(Revoked {
                serial: serial.to_string(),
                label,
                at: now,
                reason: reason.to_string(),
            });
        }
    }

    /// Состояние доверенности для UI: `active | stale | expired | revoked | invalid`.
    pub fn grant_state(&self, g: &Grant, now: u64) -> (&'static str, String) {
        if self.is_revoked(&g.serial) {
            return ("revoked", self.revoked.iter().find(|r| r.serial == g.serial).map(|r| r.reason.clone()).unwrap_or_default());
        }
        let roots = match self.accepted_roots(now) {
            Ok(r) => r,
            Err(e) => return ("invalid", e),
        };
        match caps::verify_chain(&g.chain, &self.id, &roots, &|s| self.is_revoked(s), now) {
            Ok(_) if g.root_epoch != self.root_epoch => {
                ("stale", "подписана прежним корнем — перевыпустите цепочку".into())
            }
            Ok(_) => ("active", String::new()),
            Err(e) => {
                let last = &g.chain[g.chain.len() - 1].cert;
                if now > last.exp {
                    ("expired", "срок истёк".into())
                } else if g.chain.iter().any(|l| self.is_revoked(&l.cert.serial)) {
                    ("revoked", "отозван вышестоящий".into())
                } else {
                    ("invalid", e)
                }
            }
        }
    }

    /// Перевыпускает сертификаты потомков `parent` (серийные номера и ключи держателей
    /// сохраняются), подписывая ключом текущего держателя-родителя.
    fn resign_children(&mut self, parent: Option<&str>) -> Result<(), String> {
        let (signer, parent_chain, parent_pub): (SigningKey, Vec<SignedCert>, String) = match parent {
            None => {
                let k = self.root_key()?;
                let p = hex::encode(k.verifying_key().to_bytes());
                (k, vec![], p)
            }
            Some(s) => {
                let g = self.grant(s)?;
                let k = SigningKey::from_bytes(&seed_of(&g.holder_seed)?);
                let p = hex::encode(k.verifying_key().to_bytes());
                (k, g.chain.clone(), p)
            }
        };
        let epoch = self.root_epoch;
        let kids: Vec<String> = self
            .grants
            .iter()
            .filter(|g| g.parent.as_deref() == parent)
            .map(|g| g.serial.clone())
            .collect();
        for serial in kids {
            let g = self.grants.iter_mut().find(|g| g.serial == serial).expect("listed above");
            let mut cert = g.chain[g.chain.len() - 1].cert.clone();
            cert.issuer = parent_pub.clone();
            let mut chain = parent_chain.clone();
            chain.push(cert.sign(&signer));
            g.chain = chain;
            g.root_epoch = epoch;
            self.resign_children(Some(&serial))?;
        }
        Ok(())
    }
}

impl State {
    /// Проверка целостности (перед восстановлением из копии): ключи, привязка ключей
    /// держателей к сертификатам, согласованность цепочек.
    pub fn validate(&self) -> Result<(), String> {
        let mut ids = std::collections::HashSet::new();
        for m in &self.meshes {
            if !ids.insert(&m.id) {
                return Err(format!("повторяется id сети {}", m.id));
            }
            clean_text(&m.name, "название сети", 64)?;
            if hex::decode(&m.swarm_key).map_or(true, |b| b.len() != 32) {
                return Err(format!("«{}»: некорректный ключ роя", m.name));
            }
            m.root_key().map_err(|_| format!("«{}»: некорректный корневой ключ", m.name))?;
            for g in &m.grants {
                let seed = seed_of(&g.holder_seed).map_err(|_| format!("«{}»: повреждена доверенность {}", m.name, g.serial))?;
                let last = g.chain.last().ok_or_else(|| format!("«{}»: пустая цепочка у {}", m.name, g.serial))?;
                if g.chain.len() > MAX_CHAIN || last.cert.serial != g.serial || last.cert.holder != caps::pub_hex(&seed) || last.cert.mesh != m.id {
                    return Err(format!("«{}»: цепочка {} не согласована с ключом держателя", m.name, g.serial));
                }
            }
        }
        Ok(())
    }

    pub fn mesh(&self, id: &str) -> Result<&Mesh, String> {
        self.meshes.iter().find(|m| m.id == id).ok_or_else(|| "сеть не найдена".to_string())
    }

    pub fn mesh_mut(&mut self, id: &str) -> Result<&mut Mesh, String> {
        self.meshes.iter_mut().find(|m| m.id == id).ok_or_else(|| "сеть не найдена".to_string())
    }

    /// Сеть, в которой лежит доверенность с этим серийным номером.
    pub fn mesh_of_grant_mut(&mut self, serial: &str) -> Result<&mut Mesh, String> {
        self.meshes
            .iter_mut()
            .find(|m| m.grants.iter().any(|g| g.serial == serial))
            .ok_or_else(|| "доверенность не найдена".to_string())
    }

    pub fn create_mesh(&mut self, name: &str, now: u64) -> Result<String, String> {
        self.create_mesh_with_key(name, None, now)
    }

    /// Создаёт сеть; `swarm_key` — подхватить уже работающий рой вместо нового ключа.
    pub fn create_mesh_with_key(&mut self, name: &str, swarm_key: Option<&str>, now: u64) -> Result<String, String> {
        let name = clean_text(name, "название сети", 64)?;
        if self.meshes.iter().any(|m| m.name == name) {
            return Err("сеть с таким названием уже есть".into());
        }
        let swarm_key = match swarm_key {
            None => rand_hex::<32>(),
            Some(k) => {
                let k = k.trim().to_ascii_lowercase();
                if k.len() != 64 || !k.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err("ключ роя: 64 hex-символа".into());
                }
                if self.meshes.iter().any(|m| m.swarm_key == k) {
                    return Err("сеть с таким ключом роя уже есть".into());
                }
                k
            }
        };
        let id = rand_hex::<8>();
        self.meshes.push(Mesh {
            id: id.clone(),
            name,
            note: String::new(),
            created: now,
            swarm_key,
            swarm_epoch: 1,
            swarm_prev: None,
            root_seed: rand_hex::<32>(),
            root_epoch: 1,
            root_prev: vec![],
            revoked: vec![],
            grants: vec![],
        });
        Ok(id)
    }

    pub fn delete_mesh(&mut self, id: &str, confirm: &str) -> Result<(), String> {
        let m = self.mesh(id)?;
        if m.name != confirm {
            return Err("для удаления введите точное название сети".into());
        }
        self.meshes.retain(|m| m.id != id);
        Ok(())
    }

    /// Новый ключ роя. Прежний запоминается на `grace_secs` — только как справка для
    /// оператора (какие узлы ещё не переведены); узел принимает один ключ роя, поэтому
    /// переход делается перезапуском узлов с новым `PROXY_SWARM_KEY`.
    pub fn rotate_swarm(&mut self, id: &str, grace_secs: u64, now: u64) -> Result<(), String> {
        let m = self.mesh_mut(id)?;
        m.swarm_prev = (grace_secs > 0).then(|| PrevSwarm { key: m.swarm_key.clone(), until: now + grace_secs });
        m.swarm_key = rand_hex::<32>();
        m.swarm_epoch += 1;
        Ok(())
    }

    pub fn rotate_root(&mut self, id: &str, grace_secs: u64, now: u64) -> Result<(), String> {
        let m = self.mesh_mut(id)?;
        m.root_prev.retain(|r| r.until > now);
        if grace_secs > 0 {
            m.root_prev.push(PrevRoot { public: m.root_pub()?, epoch: m.root_epoch, until: now + grace_secs });
        }
        m.root_seed = rand_hex::<32>();
        m.root_epoch += 1;
        Ok(())
    }

    /// Перевыпускает все доверенности сети под текущим корнем. Ключи держателей и серийные
    /// номера не меняются — токены нужно только раздать заново.
    pub fn reissue(&mut self, id: &str) -> Result<usize, String> {
        let m = self.mesh_mut(id)?;
        m.resign_children(None)?;
        Ok(m.grants.len())
    }

    pub fn issue(&mut self, mesh_id: &str, req: IssueRequest, now: u64) -> Result<String, String> {
        let label = clean_text(&req.label, "метка", 80)?;
        let (roles, nodes) = caps::normalize(&req.roles, req.nodes.as_deref())?;
        if !(MIN_TTL..=MAX_TTL).contains(&req.ttl_secs) {
            return Err("срок: от минуты до 365 суток".into());
        }
        if req.delegate as usize >= MAX_CHAIN {
            return Err(format!("глубина передоверия не больше {}", MAX_CHAIN - 1));
        }
        let m = self.mesh_mut(mesh_id)?;
        let (signer, parent_chain, issuer_pub) = match req.parent.as_deref() {
            None => {
                let k = m.root_key()?;
                let p = m.root_pub()?;
                (k, vec![], p)
            }
            Some(ps) => {
                let p = m.grant(ps)?;
                let (st, why) = m.grant_state(p, now);
                if st != "active" && st != "stale" {
                    return Err(format!("родительская доверенность не действует ({st}{})", if why.is_empty() { String::new() } else { format!(": {why}") }));
                }
                let k = SigningKey::from_bytes(&seed_of(&p.holder_seed)?);
                let pk = hex::encode(k.verifying_key().to_bytes());
                (k, p.chain.clone(), pk)
            }
        };
        let holder_seed: [u8; 32] = rand::random();
        let serial = rand_hex::<8>();
        let cert = Cert {
            mesh: m.id.clone(),
            serial: serial.clone(),
            issuer: issuer_pub,
            holder: caps::pub_hex(&holder_seed),
            roles,
            nodes,
            nbf: now,
            exp: now + req.ttl_secs,
            delegate: req.delegate,
        };
        if let Some(parent) = parent_chain.last() {
            caps::check_attenuation(&parent.cert, &cert)?;
        }
        let mut chain = parent_chain;
        chain.push(cert.sign(&signer));
        m.grants.push(Grant {
            serial: serial.clone(),
            label,
            note: String::new(),
            parent: req.parent,
            created: now,
            holder_seed: hex::encode(holder_seed),
            chain,
            root_epoch: m.root_epoch,
        });
        Ok(serial)
    }

    pub fn rename_mesh(&mut self, id: &str, name: &str, note: &str) -> Result<(), String> {
        let name = clean_text(name, "название сети", 64)?;
        if self.meshes.iter().any(|m| m.id != id && m.name == name) {
            return Err("сеть с таким названием уже есть".into());
        }
        let note = note.trim();
        if note.chars().count() > 500 {
            return Err("заметка: не больше 500 символов".into());
        }
        let m = self.mesh_mut(id)?;
        m.name = name;
        m.note = note.to_string();
        Ok(())
    }

    pub fn set_grant_meta(&mut self, serial: &str, label: &str, note: &str) -> Result<(), String> {
        let label = clean_text(label, "метка", 80)?;
        let note = note.trim();
        if note.chars().count() > 500 {
            return Err("заметка: не больше 500 символов".into());
        }
        let m = self.mesh_of_grant_mut(serial)?;
        let g = m.grants.iter_mut().find(|g| g.serial == serial).expect("found above");
        g.label = label;
        g.note = note.to_string();
        Ok(())
    }

    /// Продлевает доверенность: тот же ключ и серийный номер, новый срок. Старые токены
    /// остаются в силе до прежнего срока. Нельзя выйти за срок родителя или стать короче
    /// потомков.
    pub fn extend(&mut self, serial: &str, ttl_secs: u64, now: u64) -> Result<u64, String> {
        if !(MIN_TTL..=MAX_TTL).contains(&ttl_secs) {
            return Err("срок: от минуты до 365 суток".into());
        }
        let m = self.mesh_of_grant_mut(serial)?;
        if m.is_revoked(serial) {
            return Err("отозванную доверенность продлить нельзя".into());
        }
        let old = m.grant(serial)?.clone();
        let mut cert = old.chain[old.chain.len() - 1].cert.clone();
        cert.exp = now + ttl_secs;
        if let Some(longest) = m.grants.iter().filter(|g| g.parent.as_deref() == Some(serial)).map(|g| g.chain[g.chain.len() - 1].cert.exp).max() {
            if cert.exp < longest {
                return Err("новый срок короче, чем у выданных от неё передоверий".into());
            }
        }
        let (signer, parent_chain) = match old.parent.as_deref() {
            None => (m.root_key()?, vec![]),
            Some(ps) => {
                let p = m.grant(ps)?;
                (SigningKey::from_bytes(&seed_of(&p.holder_seed)?), p.chain.clone())
            }
        };
        if let Some(parent) = parent_chain.last() {
            caps::check_attenuation(&parent.cert, &cert)?;
        }
        cert.issuer = hex::encode(signer.verifying_key().to_bytes());
        let exp = cert.exp;
        let mut chain = parent_chain;
        chain.push(cert.sign(&signer));
        let epoch = m.root_epoch;
        let g = m.grants.iter_mut().find(|g| g.serial == serial).expect("found above");
        g.chain = chain;
        g.root_epoch = epoch;
        m.resign_children(Some(serial))?;
        Ok(exp)
    }

    /// Отзывает доверенность. Потомки перестают проходить проверку сами: их цепочка
    /// содержит отозванный серийный номер.
    pub fn revoke(&mut self, serial: &str, reason: &str, now: u64) -> Result<(), String> {
        let reason = if reason.trim().is_empty() { "отозвана".to_string() } else { clean_text(reason, "причина", 120)? };
        self.mesh_of_grant_mut(serial)?.revoke_serial(serial, &reason, now);
        Ok(())
    }

    /// Меняет ключ и серийный номер доверенности; прежняя отзывается. Потомки сохраняют
    /// свои ключи, но их токены надо выдать заново (цепочка теперь через новое звено).
    pub fn rotate_grant(&mut self, serial: &str, now: u64) -> Result<(String, usize), String> {
        let m = self.mesh_of_grant_mut(serial)?;
        let old = m.grant(serial)?.clone();
        let last = old.chain[old.chain.len() - 1].cert.clone();
        if m.is_revoked(serial) || now > last.exp {
            return Err("нельзя ротировать отозванную или просроченную доверенность".into());
        }
        let new_seed: [u8; 32] = rand::random();
        let new_serial = rand_hex::<8>();
        let (signer, parent_chain, issuer_pub) = match old.parent.as_deref() {
            None => (m.root_key()?, vec![], m.root_pub()?),
            Some(ps) => {
                let p = m.grant(ps)?;
                let k = SigningKey::from_bytes(&seed_of(&p.holder_seed)?);
                let pk = hex::encode(k.verifying_key().to_bytes());
                (k, p.chain.clone(), pk)
            }
        };
        let cert = Cert { serial: new_serial.clone(), issuer: issuer_pub, holder: caps::pub_hex(&new_seed), ..last };
        let mut chain = parent_chain;
        chain.push(cert.sign(&signer));
        let epoch = m.root_epoch;
        let kids = m.grants.iter().filter(|g| g.parent.as_deref() == Some(serial)).count();
        m.revoke_serial(serial, "заменена при ротации", now);
        for g in m.grants.iter_mut() {
            if g.serial == serial {
                g.serial = new_serial.clone();
                g.holder_seed = hex::encode(new_seed);
                g.chain = chain.clone();
                g.root_epoch = epoch;
            } else if g.parent.as_deref() == Some(serial) {
                g.parent = Some(new_serial.clone());
            }
        }
        m.resign_children(Some(&new_serial))?;
        Ok((new_serial, kids))
    }
}

// ── Файл ───────────────────────────────────────────────────────────────────

pub struct Store {
    state_path: PathBuf,
    audit_path: PathBuf,
    state: Mutex<State>,
}

/// Создаёт файл с правами `0600` (на unix) и пишет в него.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

impl Store {
    pub fn open(dir: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let state_path = dir.join("state.json");
        let state = match std::fs::read(&state_path) {
            Ok(b) => serde_json::from_slice(&b)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{}: {e}", state_path.display())))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
            Err(e) => return Err(e),
        };
        Ok(Self { state_path, audit_path: dir.join("audit.log"), state: Mutex::new(state) })
    }

    pub fn read<R>(&self, f: impl FnOnce(&State) -> R) -> R {
        f(&self.state.lock().unwrap_or_else(|p| p.into_inner()))
    }

    /// Применяет изменение к копии и сохраняет её; в памяти остаётся прежнее, если
    /// операция или запись не удались.
    pub fn mutate<R>(&self, f: impl FnOnce(&mut State) -> Result<R, String>) -> Result<R, String> {
        let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let mut next = guard.clone();
        let out = f(&mut next)?;
        let json = serde_json::to_vec_pretty(&next).map_err(|e| e.to_string())?;
        let tmp = self.state_path.with_extension("json.tmp");
        write_private(&tmp, &json)
            .and_then(|_| std::fs::rename(&tmp, &self.state_path))
            .map_err(|e| format!("не удалось сохранить состояние: {e}"))?;
        *guard = next;
        Ok(out)
    }

    /// Строка в журнал аудита. Секретов сюда не попадает.
    pub fn audit(&self, now: u64, action: &str, target: &str, detail: &str) {
        let line = serde_json::json!({"ts": now, "action": action, "target": target, "detail": detail}).to_string() + "\n";
        let mut opts = std::fs::OpenOptions::new();
        opts.append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        if let Err(e) = opts.open(&self.audit_path).and_then(|mut f| f.write_all(line.as_bytes())) {
            netrunner_logger::warn!(error = %e, "admin: не удалось записать аудит");
        }
    }

    pub fn audit_tail(&self, n: usize) -> Vec<serde_json::Value> {
        let text = std::fs::read_to_string(&self.audit_path).unwrap_or_default();
        let mut v: Vec<serde_json::Value> =
            text.lines().rev().take(n).filter_map(|l| serde_json::from_str(l).ok()).collect();
        v.shrink_to_fit();
        v
    }

    pub fn dir(&self) -> &Path {
        self.state_path.parent().unwrap_or(Path::new("."))
    }
}

pub fn write_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    write_private(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_000_000;

    fn req(label: &str, parent: Option<&str>, roles: &[&str], delegate: u8) -> IssueRequest {
        IssueRequest {
            label: label.into(),
            parent: parent.map(String::from),
            roles: roles.iter().map(|s| s.to_string()).collect(),
            nodes: None,
            ttl_secs: 10_000,
            delegate,
        }
    }

    fn verify(m: &Mesh, serial: &str, now: u64) -> Result<(), String> {
        let g = m.grant(serial).unwrap();
        caps::verify_chain(&g.chain, &m.id, &m.accepted_roots(now).unwrap(), &|s| m.is_revoked(s), now).map(|_| ())
    }

    fn setup() -> (State, String) {
        let mut s = State::default();
        let id = s.create_mesh("main", NOW).unwrap();
        (s, id)
    }

    #[test]
    fn issue_delegate_and_attenuation() {
        let (mut s, id) = setup();
        let a = s.issue(&id, req("alice", None, &["client", "relay"], 2), NOW).unwrap();
        let b = s.issue(&id, req("bob", Some(&a), &["client"], 1), NOW).unwrap();
        assert!(s.issue(&id, req("eve", Some(&a), &["egress"], 0), NOW).is_err());
        let m = s.mesh(&id).unwrap();
        verify(m, &a, NOW).unwrap();
        verify(m, &b, NOW).unwrap();
        assert_eq!(m.grant_state(m.grant(&b).unwrap(), NOW).0, "active");
        // родитель без права передоверия
        let mut s2 = s.clone();
        let leaf = s2.issue(&id, req("leaf", None, &["client"], 0), NOW).unwrap();
        assert!(s2.issue(&id, req("x", Some(&leaf), &["client"], 0), NOW).is_err());
    }

    #[test]
    fn revoke_cascades_through_chain() {
        let (mut s, id) = setup();
        let a = s.issue(&id, req("a", None, &["client"], 2), NOW).unwrap();
        let b = s.issue(&id, req("b", Some(&a), &["client"], 1), NOW).unwrap();
        s.revoke(&a, "тест", NOW).unwrap();
        let m = s.mesh(&id).unwrap();
        assert_eq!(m.grant_state(m.grant(&a).unwrap(), NOW).0, "revoked");
        assert_eq!(m.grant_state(m.grant(&b).unwrap(), NOW).0, "revoked");
        assert!(s.issue(&id, req("c", Some(&a), &["client"], 0), NOW).is_err());
    }

    #[test]
    fn root_rotation_grace_and_reissue() {
        let (mut s, id) = setup();
        let a = s.issue(&id, req("a", None, &["client"], 2), NOW).unwrap();
        let b = s.issue(&id, req("b", Some(&a), &["client"], 1), NOW).unwrap();
        let seed_b = s.mesh(&id).unwrap().grant(&b).unwrap().holder_seed.clone();

        s.rotate_root(&id, 100, NOW).unwrap();
        let m = s.mesh(&id).unwrap();
        verify(m, &a, NOW + 50).unwrap();
        assert_eq!(m.grant_state(m.grant(&a).unwrap(), NOW + 50).0, "stale");
        assert!(verify(m, &a, NOW + 150).is_err());

        assert_eq!(s.reissue(&id).unwrap(), 2);
        let m = s.mesh(&id).unwrap();
        verify(m, &a, NOW + 150).unwrap();
        verify(m, &b, NOW + 150).unwrap();
        assert_eq!(m.grant_state(m.grant(&b).unwrap(), NOW + 150).0, "active");
        assert_eq!(m.grant(&b).unwrap().holder_seed, seed_b, "ключ держателя не меняется");
    }

    #[test]
    fn hard_root_rotation_invalidates_everything() {
        let (mut s, id) = setup();
        let a = s.issue(&id, req("a", None, &["client"], 0), NOW).unwrap();
        s.rotate_root(&id, 0, NOW).unwrap();
        assert!(verify(s.mesh(&id).unwrap(), &a, NOW).is_err());
    }

    #[test]
    fn grant_rotation_replaces_serial_and_keeps_children_valid_after_resign() {
        let (mut s, id) = setup();
        let a = s.issue(&id, req("a", None, &["client", "relay"], 2), NOW).unwrap();
        let b = s.issue(&id, req("b", Some(&a), &["client"], 1), NOW).unwrap();
        let (a2, kids) = s.rotate_grant(&a, NOW + 1).unwrap();
        assert_eq!(kids, 1);
        let m = s.mesh(&id).unwrap();
        assert!(m.is_revoked(&a));
        assert!(m.grant(&a).is_err());
        verify(m, &a2, NOW + 1).unwrap();
        verify(m, &b, NOW + 1).unwrap();
        assert_eq!(m.grant(&b).unwrap().parent.as_deref(), Some(a2.as_str()));
    }

    #[test]
    fn swarm_rotation_keeps_previous_for_grace() {
        let (mut s, id) = setup();
        let old = s.mesh(&id).unwrap().swarm_key.clone();
        s.rotate_swarm(&id, 3600, NOW).unwrap();
        let m = s.mesh(&id).unwrap();
        assert_ne!(m.swarm_key, old);
        assert_eq!(m.swarm_prev.as_ref().unwrap().key, old);
        assert_eq!(m.swarm_epoch, 2);
        s.rotate_swarm(&id, 0, NOW).unwrap();
        assert!(s.mesh(&id).unwrap().swarm_prev.is_none());
    }

    #[test]
    fn extend_keeps_key_and_respects_parent_and_children() {
        let (mut s, id) = setup();
        let mut r = req("a", None, &["client"], 1);
        r.ttl_secs = 10_000;
        let a = s.issue(&id, r, NOW).unwrap();
        let mut r = req("b", Some(&a), &["client"], 0);
        r.ttl_secs = 5_000;
        let b = s.issue(&id, r, NOW).unwrap();
        let seed = s.mesh(&id).unwrap().grant(&a).unwrap().holder_seed.clone();
        // короче потомка — нельзя
        assert!(s.extend(&a, 4_000, NOW).is_err());
        let exp = s.extend(&a, 50_000, NOW + 1).unwrap();
        assert_eq!(exp, NOW + 1 + 50_000);
        let m = s.mesh(&id).unwrap();
        assert_eq!(m.grant(&a).unwrap().holder_seed, seed);
        verify(m, &a, NOW + 20_000).unwrap();
        verify(m, &b, NOW + 2).unwrap();
        // потомка нельзя продлить дальше родителя
        assert!(s.extend(&b, 100_000, NOW + 2).is_err());
        s.revoke(&a, "x", NOW).unwrap();
        assert!(s.extend(&a, 100, NOW).is_err());
    }

    #[test]
    fn meta_rename_fingerprint_and_validate() {
        let (mut s, id) = setup();
        let a = s.issue(&id, req("a", None, &["client"], 0), NOW).unwrap();
        s.set_grant_meta(&a, "Алиса", "ноутбук").unwrap();
        assert_eq!(s.mesh(&id).unwrap().grant(&a).unwrap().note, "ноутбук");
        assert!(s.set_grant_meta(&a, "", "").is_err());
        s.create_mesh("other", NOW).unwrap();
        assert!(s.rename_mesh(&id, "other", "").is_err());
        s.rename_mesh(&id, "main2", "заметка").unwrap();
        assert_eq!(s.mesh(&id).unwrap().note, "заметка");
        let fp = fingerprint(&s.mesh(&id).unwrap().swarm_key);
        assert_eq!(fp.len(), 19);
        assert_ne!(fp, fingerprint(&s.mesh(&id).unwrap().root_seed));
        s.validate().unwrap();
        // порча ключа держателя ловится при проверке резервной копии
        s.mesh_mut(&id).unwrap().grants[0].holder_seed = "00".repeat(32);
        assert!(s.validate().is_err());
    }

    #[test]
    fn rotation_remembers_label_in_revocation_list() {
        let (mut s, id) = setup();
        let a = s.issue(&id, req("alice", None, &["client"], 0), NOW).unwrap();
        s.rotate_grant(&a, NOW).unwrap();
        assert_eq!(s.mesh(&id).unwrap().revoked[0].label, "alice");
    }

    #[test]
    fn mesh_can_adopt_an_existing_swarm_key() {
        let mut s = State::default();
        let key = "ab".repeat(32);
        let id = s.create_mesh_with_key("adopted", Some(&key.to_uppercase()), NOW).unwrap();
        assert_eq!(s.mesh(&id).unwrap().swarm_key, key);
        assert!(s.create_mesh_with_key("dup", Some(&key), NOW).is_err());
        assert!(s.create_mesh_with_key("short", Some("abcd"), NOW).is_err());
        assert!(s.create_mesh_with_key("nothex", Some(&"zz".repeat(32)), NOW).is_err());
    }

    #[test]
    fn mesh_names_and_deletion() {
        let (mut s, id) = setup();
        assert!(s.create_mesh("main", NOW).is_err());
        assert!(s.create_mesh("  ", NOW).is_err());
        assert!(s.delete_mesh(&id, "nope").is_err());
        s.delete_mesh(&id, "main").unwrap();
        assert!(s.meshes.is_empty());
    }

    #[test]
    fn bad_ttl_and_depth_rejected() {
        let (mut s, id) = setup();
        let mut r = req("a", None, &["client"], 0);
        r.ttl_secs = 5;
        assert!(s.issue(&id, r, NOW).is_err());
        assert!(s.issue(&id, req("a", None, &["client"], 9), NOW).is_err());
    }

    #[test]
    fn store_persists_and_files_are_private() {
        let dir = std::env::temp_dir().join(format!("nr-admin-test-{}", rand_hex::<4>()));
        let store = Store::open(&dir).unwrap();
        let id = store.mutate(|s| s.create_mesh("persist", NOW)).unwrap();
        assert!(store.mutate(|s| s.create_mesh("persist", NOW)).is_err());
        store.audit(NOW, "test", &id, "");
        drop(store);
        let again = Store::open(&dir).unwrap();
        assert_eq!(again.read(|s| s.meshes.len()), 1);
        assert_eq!(again.audit_tail(10).len(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for f in ["state.json", "audit.log"] {
                let mode = std::fs::metadata(dir.join(f)).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600, "{f}");
            }
            assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
