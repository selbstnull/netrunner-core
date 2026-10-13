//! Мост панели к работающему узлу: то, что про узел можно показать и (немногое) сделать.
//! Секретов в ответы не попадает, кроме явно запрошенного клиентского конфига.

use netrunner_core::net::directory::{Directory, EndpointKind, Insert, Roles};
use netrunner_core::net::NodeMesh;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio_util::sync::CancellationToken;

/// Учётные данные, которые узел выдаёт своим клиентам (`client.toml`).
#[derive(Clone)]
pub struct ClientCreds {
    pub secret: String,
    pub public_key: String,
}

pub struct NodeView {
    /// `swarm` | `panel` | `standalone`.
    pub mode: &'static str,
    /// Эффективная конфигурация (без секретов), собирается в `main`.
    pub config: Value,
    pub started: u64,
    pub directory: Option<Arc<Directory>>,
    pub mesh: Option<Arc<NodeMesh>>,
    pub active_connections: Arc<AtomicU64>,
    pub metrics: Option<metrics_exporter_prometheus::PrometheusHandle>,
    pub shutdown: CancellationToken,
    pub creds: Option<ClientCreds>,
    pub advertise: Option<String>,
    pub decoy_host: String,
    pub strict: bool,
    /// `false` — панель без живого узла (тесты): нет ни логгера, ни периодических задач.
    attached: bool,
    log_level: Mutex<String>,
}

pub struct NodeParts {
    pub mode: &'static str,
    pub config: Value,
    pub directory: Option<Arc<Directory>>,
    pub mesh: Option<Arc<NodeMesh>>,
    pub active_connections: Arc<AtomicU64>,
    pub metrics: Option<metrics_exporter_prometheus::PrometheusHandle>,
    pub shutdown: CancellationToken,
    pub creds: Option<ClientCreds>,
    pub advertise: Option<String>,
    pub decoy_host: String,
    pub strict: bool,
}

impl NodeView {
    pub fn new(p: NodeParts) -> Self {
        Self {
            mode: p.mode,
            config: p.config,
            started: super::now(),
            directory: p.directory,
            mesh: p.mesh,
            active_connections: p.active_connections,
            metrics: p.metrics,
            shutdown: p.shutdown,
            creds: p.creds,
            advertise: p.advertise,
            decoy_host: p.decoy_host,
            strict: p.strict,
            attached: true,
            log_level: Mutex::new("info".into()),
        }
    }

    /// Пустой вид «узла нет» — для тестов и режима без привязки.
    pub fn detached() -> Self {
        let mut v = Self::new(NodeParts {
            mode: "standalone",
            config: json!({}),
            directory: None,
            mesh: None,
            active_connections: Arc::new(AtomicU64::new(0)),
            metrics: None,
            shutdown: CancellationToken::new(),
            creds: None,
            advertise: None,
            decoy_host: "www.debian.org".into(),
            strict: false,
        });
        v.attached = false;
        v
    }

    /// Ключ роя этого узла (hex), если узел в режиме роя.
    pub fn swarm_key_hex(&self) -> Option<String> {
        self.directory.as_ref().map(|d| d.swarm().to_hex())
    }

    pub fn healthy(&self) -> bool {
        !self.attached || crate::network::periodic_task_is_healthy()
    }

    pub fn log_level(&self) -> String {
        self.log_level.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    pub fn set_log_level(&self, level: &str) -> Result<(), String> {
        if !["error", "warn", "info", "debug"].contains(&level) {
            return Err("уровень: error, warn, info или debug".into());
        }
        if self.attached {
            netrunner_logger::Logger::global().set_level(level);
        }
        *self.log_level.lock().unwrap_or_else(|p| p.into_inner()) = level.to_string();
        Ok(())
    }

    pub async fn status(&self, now: u64) -> Value {
        let mesh_peers = match &self.mesh {
            Some(m) => m.peer_count().await,
            None => 0,
        };
        let (node_id, static_public) = match &self.directory {
            Some(d) => (Some(d.node_id_hex()), Some(hex::encode(d.identity().static_pub))),
            None => (None, self.creds.as_ref().map(|c| c.public_key.clone())),
        };
        json!({
            "mode": self.mode,
            "healthy": self.healthy(),
            "uptime": now.saturating_sub(self.started),
            "active_connections": self.active_connections.load(Ordering::Relaxed),
            "node_id": node_id,
            "static_public": static_public,
            "strict": self.strict,
            "advertise": self.advertise,
            "decoy_host": self.decoy_host,
            "directory_records": self.directory.as_ref().map(|d| d.len()),
            "mesh": { "enabled": self.mesh.is_some(), "peers": mesh_peers },
            "log_level": self.log_level(),
            "metrics": self.metrics.is_some(),
            "config": self.config,
        })
    }

    /// Соседи: из каталога роя (с ролями и сроками), иначе — из mesh-каталога панели.
    pub async fn peers(&self, now: u64) -> Value {
        let rtt = |id: &str| self.mesh.as_ref().and_then(|m| m.peer_rtt_ms(id));
        if let Some(dir) = &self.directory {
            let own = dir.node_id_hex();
            let list: Vec<Value> = dir
                .records(now)
                .iter()
                .map(|d| {
                    let id = netrunner_core::net::directory::node_id_hex(&d.node_id);
                    let mut roles = vec![];
                    if d.roles.has(Roles::RELAY) { roles.push("relay"); }
                    if d.roles.has(Roles::EXIT) { roles.push("exit"); }
                    if d.roles.has(Roles::BRIDGE) { roles.push("bridge"); }
                    json!({
                        "node_id": id, "is_self": id == own,
                        "static_public": hex::encode(d.static_pub),
                        "roles": roles, "gossip": d.supports_gossip(),
                        "proto": [d.proto_min, d.proto_max], "seq": d.seq,
                        "issued_at": d.issued_at, "valid_until": d.valid_until,
                        "sni": d.decoy_sni,
                        "endpoints": d.endpoints.iter().map(|e| json!({
                            "kind": if e.kind == EndpointKind::Tcp { "tcp" } else { "quic" },
                            "address": format!("{}:{}", e.host, e.port),
                        })).collect::<Vec<_>>(),
                        "rtt_ms": rtt(&id),
                    })
                })
                .collect();
            return json!({ "source": "directory", "peers": list });
        }
        let list: Vec<Value> = match &self.mesh {
            Some(m) => m
                .ordered_peers()
                .await
                .into_iter()
                .map(|p| json!({
                    "node_id": p.node_id, "is_self": false, "static_public": p.nrxp_static_public,
                    "roles": [], "sni": p.decoy_sni,
                    "endpoints": [{"kind": "tcp", "address": p.address()}],
                    "rtt_ms": rtt(&p.node_id),
                }))
                .collect(),
            None => vec![],
        };
        json!({ "source": if self.mesh.is_some() { "panel" } else { "none" }, "peers": list })
    }

    pub fn own_descriptor(&self, now: u64) -> Result<Value, String> {
        let d = self.directory.as_ref().ok_or("самоописание есть только у узла в режиме роя (--swarm-key)")?;
        let own = d.own(now);
        Ok(json!({
            "node_id": d.node_id_hex(), "descriptor": hex::encode(own.encode()),
            "valid_until": own.valid_until, "seq": own.seq,
        }))
    }

    pub fn add_seed(&self, hex_desc: &str, now: u64) -> Result<Value, String> {
        let d = self.directory.as_ref().ok_or("каталог есть только у узла в режиме роя")?;
        let bytes = hex::decode(hex_desc.trim()).map_err(|_| "самоописание — это hex-строка")?;
        let (state, why) = match d.insert_bytes(&bytes, now) {
            Insert::Added => ("added", String::new()),
            Insert::Updated => ("updated", String::new()),
            Insert::Stale => ("stale", "такая или более новая запись уже есть".into()),
            Insert::Rejected(r) => return Err(format!("запись отвергнута: {r:?}")),
        };
        Ok(json!({ "result": state, "reason": why, "records": d.len() }))
    }

    pub fn gc(&self, now: u64) -> Result<usize, String> {
        Ok(self.directory.as_ref().ok_or("каталог есть только у узла в режиме роя")?.gc(now))
    }

    /// Готовый `client.toml` для клиентов этого узла.
    pub fn client_config(&self, remote: Option<&str>, sni: Option<&str>) -> Result<String, String> {
        let c = self.creds.as_ref().ok_or("у узла не заданы PROXY_NRXP_SECRET/PROXY_NRXP_PRIVATE_KEY — клиентам нечего выдать")?;
        let ok = |s: &str| !s.is_empty() && s.len() <= 255 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._:-[]".contains(&b));
        let remote = remote.filter(|r| !r.is_empty()).or(self.advertise.as_deref()).unwrap_or("IP_УЗЛА:443");
        let sni = sni.filter(|s| !s.is_empty()).unwrap_or(&self.decoy_host);
        if !ok(remote.replace("IP_УЗЛА", "x").as_str()) || !ok(sni) {
            return Err("адрес и SNI: латиница, цифры и . : - _ [ ]".into());
        }
        Ok(format!(
            "remote_address     = \"{remote}\"\nsni                = \"{sni}\"\nnode_secret        = \"{}\"\nnode_public_key    = \"{}\"\nkillswitch_enabled = true\n",
            c.secret, c.public_key
        ))
    }
}
