//! Клиентская сторона `PeerHint`: узнать другие узлы у живого узла.
//!
//! Клиент, подключённый к узлу роя, раз в несколько минут спрашивает у него
//! несколько соседей ([`Message::HintRequest`]) и хранит ответ в своём кэше. Если
//! узел, к которому клиент привык, заблокируют, при следующем запуске есть из чего
//! выбрать: кэш подаётся в тот же выбор узла, что и `[[nodes]]` из конфига.
//!
//! **Доверие.** Подпись записи доказывает «этот ключ живёт по этому адресу», а не
//! «этому узлу можно верить». Клиент роя знает `swarm_key` (этап A — общий секрет
//! сети) и сам считает для каждого узла `node_secret`; без ключа роя клиент учётных
//! данных присланного узла вывести не может, поэтому подсунутый чужой адрес не даёт
//! ему ничего, кроме неудачного хендшейка. Токены вместо ключа роя — этап B.
//!
//! **Совместимость.** Узлу без каталога кадр `PeerGossip` безвреден (молча
//! отбрасывается), но узел старого выпуска порвёт на нём ногу, поэтому клиент шлёт
//! запрос только когда оператор явно включил рой (`swarm_key` в конфиге).

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;

use super::descriptor::{node_id_hex, EndpointKind, NodeDescriptor, Roles};
use super::gossip::{self, GossipError, Message, Stats, MAX_HINT_RECORDS};
use super::store::{DescriptorStore, StoreConfig};
use super::swarm::SwarmKey;

/// Узел, найденный через `PeerHint`, с вычисленными учётными данными.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LearnedNode {
    pub node_id: String,
    /// `ip:port` (пока только IPv4, как и основной `remote_address`).
    pub address: String,
    pub proxy: SocketAddr,
    pub sni: String,
    pub node_secret: String,
    pub node_public_key: String,
    pub valid_until: u64,
}

/// Кэш клиента: проверенные записи и ключ роя.
pub struct ClientDirectory {
    swarm: SwarmKey,
    store: Mutex<DescriptorStore>,
}

impl ClientDirectory {
    pub fn new(swarm: SwarmKey, allow_private: bool) -> Self {
        Self {
            swarm,
            store: Mutex::new(DescriptorStore::new(
                StoreConfig {
                    allow_private,
                    // Клиенту хватает небольшого запаса адресов.
                    max_records: 256,
                    ..Default::default()
                },
                None,
            )),
        }
    }

    pub fn len(&self) -> usize {
        self.store.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Загружает снимок с диска; каждая запись проверяется заново.
    pub fn load(&self, bytes: &[u8], now: u64) -> usize {
        self.store.lock().unwrap().import(bytes, now)
    }

    pub fn save(&self, now: u64) -> Vec<u8> {
        self.store.lock().unwrap().export(now)
    }

    /// Тело запроса `PeerHint`.
    pub fn request(&self, max: u8) -> Vec<u8> {
        Message::HintRequest { max: max.min(MAX_HINT_RECORDS) }.encode()
    }

    /// Принимает ответ узла по обычным правилам хранилища (подпись, срок, лимит на сеть).
    pub fn absorb_reply(&self, reply: &[u8], now: u64) -> Result<Stats, GossipError> {
        let msg = Message::decode(reply)?;
        let mut g = self.store.lock().unwrap();
        gossip::absorb_hint_reply(&mut g, msg, now)
    }

    /// Узлы, к которым можно подключиться: ретрансляторы с IPv4-адресом TCP. Порядок
    /// детерминирован (дольше живущие первыми), `exclude` — адреса, которые уже в конфиге.
    pub fn nodes(&self, now: u64, exclude: &HashSet<String>) -> Vec<LearnedNode> {
        let g = self.store.lock().unwrap();
        let mut v: Vec<LearnedNode> = g
            .live(now)
            .filter(|d| d.roles.has(Roles::RELAY))
            .filter_map(|d| self.node_of(d))
            .filter(|n| !exclude.contains(&n.address))
            .collect();
        v.sort_by(|a, b| b.valid_until.cmp(&a.valid_until).then_with(|| a.node_id.cmp(&b.node_id)));
        v
    }

    fn node_of(&self, d: &NodeDescriptor) -> Option<LearnedNode> {
        let tcp = d.endpoint(EndpointKind::Tcp)?;
        let ip: IpAddr = tcp.host.parse().ok()?;
        if !ip.is_ipv4() {
            return None;
        }
        let proxy = SocketAddr::new(ip, tcp.port);
        Some(LearnedNode {
            node_id: node_id_hex(&d.node_id),
            address: proxy.to_string(),
            proxy,
            sni: d.decoy_sni.clone(),
            node_secret: self.swarm.node_secret(&d.node_id),
            node_public_key: hex::encode(d.static_pub),
            valid_until: d.valid_until,
        })
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use session::{learn_nodes, run_learning};

#[cfg(not(target_arch = "wasm32"))]
mod session {
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    use bytes::Bytes;
    use netrunner_logger::{AppError, ERR_INFRA_TIMEOUT};
    use tokio::sync::mpsc;

    use super::{ClientDirectory, Stats};
    use crate::net::directory::unix_now;
    use crate::net::{Muxer, NetworkConfig};
    use crate::nrxp::FrameType;

    /// Один запрос `PeerHint` по живой сессии: открывает короткий поток, ждёт ответ.
    pub async fn learn_nodes(
        muxer: &Arc<Muxer>,
        dir: &ClientDirectory,
        max: u8,
    ) -> Result<Stats, AppError> {
        let stream_id = muxer.next_stream_id();
        let cap = NetworkConfig::global().channel_capacity;
        let (tx, mut rx) = mpsc::channel::<Bytes>(cap.min(8));
        muxer.register_stream_with_backlog_cap(stream_id, tx, crate::net::SERVER_STREAM_BACKLOG_MAX_BYTES);
        let result = async {
            muxer
                .send_control(stream_id, FrameType::PeerGossip, Bytes::from(dir.request(max)))
                .await?;
            let reply = tokio::time::timeout(Duration::from_secs(8), rx.recv())
                .await
                .ok()
                .flatten()
                .ok_or_else(|| {
                    AppError::new(ERR_INFRA_TIMEOUT, "PeerHint timeout", "The node did not answer the hint request")
                })?;
            dir.absorb_reply(&reply, unix_now())
                .map_err(|e| AppError::new(ERR_INFRA_TIMEOUT, "PeerHint rejected", e.to_string()))
        }
        .await;
        muxer.remove_stream(stream_id);
        result
    }

    /// Фоновая задача сессии: пока сессия жива и есть хотя бы одна нога, раз в
    /// `interval` (±30 %) спрашивает соседей и сохраняет кэш при изменении.
    pub async fn run_learning(
        muxer: Arc<Muxer>,
        dir: Arc<ClientDirectory>,
        path: Option<PathBuf>,
        interval: Duration,
    ) {
        let weak = Arc::downgrade(&muxer);
        drop(muxer);
        let mut first = true;
        loop {
            let Some(m) = weak.upgrade() else { return };
            if m.is_fatal() {
                return;
            }
            if m.active_legs_count() == 0 {
                drop(m);
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
            if first {
                // Дать туннелю подняться и не совпадать с первым трафиком клиента.
                tokio::time::sleep(Duration::from_secs(3)).await;
                first = false;
            }
            match learn_nodes(&m, &dir, super::MAX_HINT_RECORDS).await {
                Ok(stats) => {
                    netrunner_logger::debug!(
                        learned = stats.learned(),
                        rejected = stats.rejected,
                        known = dir.len(),
                        "PeerHint answered"
                    );
                    if stats.learned() > 0 {
                        if let Some(p) = &path {
                            let tmp = p.with_extension("tmp");
                            let _ = std::fs::write(&tmp, dir.save(unix_now()))
                                .and_then(|()| std::fs::rename(&tmp, p));
                        }
                    }
                }
                Err(e) => netrunner_logger::debug!(error = %e.internal_msg, "PeerHint failed"),
            }
            drop(m);
            let jitter = rand::random::<f64>() * 0.6 + 0.7;
            tokio::time::sleep(interval.mul_f64(jitter)).await;
        }
    }
}
