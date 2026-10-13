//! # netrunner-server — серверная часть прокси
//!
//! Тонкая обвязка вокруг ядра ([`netrunner_core`]): парсит аргументы, поднимает
//! логгер и tokio-рантайм и запускает [`Network`](crate::network::Network),
//! которая слушает TCP, принимает замаскированные TLS-соединения и отдаёт каждое
//! в `ServerHandler` ядра (хендшейк → аутентификация → проксирование или
//! stealth-fallback). Бизнес-логика целиком в ядре; здесь — точка входа и
//! серверная диагностика ([`diagnostics`](crate::diagnostics)).

// Workaround for rustc 1.94 ICE in check_mod_deathness (dead-code MIR pass).
#![allow(dead_code)]

mod backend_client;
mod decoy_site;
mod diagnostics;
mod health;
mod metrics_server;
mod network;
use clap::Parser;
use netrunner_core::net::AuthValidator;
use netrunner_core::{Identity, LocalIdentity};
use netrunner_logger::{error, info, Logger};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

use crate::backend_client::BackendClient;
use crate::network::Network;

/// reqwest enables AWS-LC while Quinn enables Ring in this binary. Rustls
/// therefore cannot infer which process-wide provider to use from features.
/// Select Ring before any tokio task can build a TLS or QUIC config.
fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Ждёт SIGTERM (docker stop/systemctl stop) или SIGINT (Ctrl+C) и отменяет
/// токен — раньше этой функции не было вообще: сервер получал сигнал прямо
/// от ОС мимо CancellationToken'а, и вся drain-логика в `Network::run` была
/// мертва, ни разу не срабатывая на реальном шатдауне.
async fn shutdown_signal(token: CancellationToken) {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Не удалось установить обработчик Ctrl+C");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Не удалось установить обработчик SIGTERM")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("🛑 Получен SIGINT (Ctrl+C). Останавливаемся..."),
        _ = terminate => info!("🛑 Получен SIGTERM. Останавливаемся..."),
    }
    token.cancel();
}

/// Аргументы командной строки сервера.
#[derive(Parser, Debug)]
#[command(author, version, about = "Netrunner Proxy Server")]
struct Args {
    /// Порт прослушивания.
    #[arg(short, long, default_value_t = 8080)]
    port: u16,

    /// Адрес привязки.
    #[arg(long, default_value = "0.0.0.0")]
    host: String,

    /// Домен-декой: под кого притворяется этот узел для «не наших» подключений
    /// (stealth-fallback прозрачно проксирует туда трафик сканеров/чужих
    /// клиентов). Раньше было жёстко зашито на `ubuntu.com` в коде ядра — теперь
    /// атрибут ноды, можно задавать разный на каждом развёртывании.
    #[arg(long, default_value = netrunner_core::net::DEFAULT_DECOY_HOST)]
    decoy_host: String,

    /// Имя витрины-пресета, под которую маскируется узел (`clipforge`,
    /// `hauler`, `logdrain`). SNI пресета обязан входить в каталог доменов
    /// узла (`NETRUNNER_DECOY_DOMAINS`) — иначе узел не поднимется: под домен,
    /// которым он не владеет, нет валидного сертификата. Не задан — узел
    /// работает как раньше (сборка витрины пропускается).
    #[arg(long)]
    decoy_preset: Option<String>,

    /// Режим маскировки: `relay` (REALITY-style — ретрансляция на чужой
    /// реальный сайт, историческое поведение по умолчанию) или `self-hosted`
    /// (узел сам обслуживает свою витрину под своим доменом). Не задан —
    /// `relay`, обратная совместимость.
    #[arg(long, default_value = "relay")]
    decoy_mode: String,

    /// Только для `--decoy-mode self-hosted`: адрес локального TLS-терминатора
    /// (co-located nginx/caddy с сертификатом своего домена), который отдаёт
    /// собранную витрину. Fallback ретранслируется СЮДА, а не на внешний сайт.
    #[arg(long, default_value = "127.0.0.1:8443")]
    decoy_local_site: String,

    /// Только для `--decoy-mode self-hosted`: домен узла (SNI и CN сертификата).
    /// Обязан входить в каталог `NETRUNNER_DECOY_DOMAINS`. Не задан — берётся
    /// SNI из самого пресета. Именно этот домен, а не захардкоженный в пресете,
    /// делает витрину «своей» для конкретного узла.
    #[arg(long)]
    decoy_sni: Option<String>,

    /// Длины TLS-записей первого flight'а узла (`EncryptedExtensions`,
    /// `Certificate`, `CertificateVerify`, `Finished`): список через запятую
    /// (`27,4342,537,69`) либо путь к JSON-файлу, который пишет
    /// `netrunner-client profile record --flight-out`. Снимите их с настоящего
    /// ответа своего домена — тогда cover-flight совпадает с тем, что отдаёт
    /// сайт узла, а не со «средней» цепочкой. Не задан — типовая цепочка.
    #[arg(long, env = "NETRUNNER_COVER_FLIGHT")]
    cover_flight: Option<String>,

    /// JSON-профиль браузера с блоком `shape` (его пишет
    /// `netrunner-client profile record`): длины TLS-записей узла
    /// (направление сервер → клиент) выравниваются по наблюдавшимся у браузера.
    /// Остальное содержимое файла узлом не используется. Не задан —
    /// синтетическое распределение длин.
    #[arg(long, env = "NETRUNNER_SHAPE_PROFILE")]
    shape_profile: Option<String>,

    /// Ключ роя (hex, 32 байта): узел работает **без панели** — соседей находит из
    /// подписанных самоописаний (обмен с другими узлами), а входной секрет каждого
    /// узла выводится из ключа роя. Нужны `PROXY_NRXP_PRIVATE_KEY` и `--advertise`;
    /// `PROXY_NRXP_SECRET`, `PROXY_NODE_ID` и бэкенд не требуются. Сгенерировать
    /// ключ: `openssl rand -hex 32`, один на всю сеть. См. docs/DECENTRALIZATION.md.
    #[arg(long, env = "PROXY_SWARM_KEY", hide_env_values = true)]
    swarm_key: Option<String>,

    /// Публичный адрес этого узла `host:port` (NRXP, TCP) — попадает в его
    /// самоописание. Обязателен с `--swarm-key`.
    #[arg(long, env = "NETRUNNER_ADVERTISE")]
    advertise: Option<String>,

    /// Самоописания соседей для начального знакомства: hex-строка либо путь к
    /// файлу (по записи в строке). Получить: `--print-descriptor` на соседе.
    #[arg(long, env = "NETRUNNER_DIRECTORY_SEED", value_delimiter = ',')]
    directory_seed: Vec<String>,

    /// Файл, в котором узел хранит каталог между перезапусками.
    #[arg(long, env = "NETRUNNER_DIRECTORY_FILE")]
    directory_file: Option<std::path::PathBuf>,

    /// Раз в сколько секунд обмениваться записями с соседями (с разбросом ±30 %).
    #[arg(long, default_value_t = 15)]
    directory_gossip_interval: u64,

    /// Принимать записи с частными адресами (LAN, стенды). В боевой сети не нужен.
    #[arg(long)]
    directory_allow_private: bool,

    /// Напечатать самоописание этого узла (для `--directory-seed` соседей) и выйти.
    #[arg(long)]
    print_descriptor: bool,

    /// Публичный ключ авторитета (hex, Ed25519). Задан — сеть **управляемая**: узел
    /// принимает только записи с действующим поручительством этого авторитета
    /// (панель или иной подписант). Не задан — открытая сеть (рой). Можно несколько.
    #[arg(long, env = "NETRUNNER_TRUST_ANCHOR", value_delimiter = ',')]
    trust_anchor: Vec<String>,

    /// Поручительство авторитета за этот узел: hex либо путь к файлу (по записи в
    /// строке). Файл перечитывается каждый раунд — продление подхватывается без
    /// перезапуска. Получить: `--authority-endorse`.
    #[arg(long, env = "NETRUNNER_ENDORSEMENT", value_delimiter = ',')]
    endorsement: Vec<String>,

    /// Строгий допуск пиров: о ком в каталоге уже есть запись, тот обязан предъявить
    /// парное доказательство личности. Включайте, когда все узлы роя обновлены.
    #[arg(long)]
    swarm_strict: bool,

    /// Создать пару ключей авторитета (секрет — храните, публичный — в `--trust-anchor`) и выйти.
    #[arg(long)]
    authority_keygen: bool,

    /// Выдать поручительство за узел с этим самоописанием (hex из `--print-descriptor`),
    /// ключом `--authority-key`, на `--endorse-days` дней, и выйти.
    #[arg(long, value_name = "DESCRIPTOR_HEX")]
    authority_endorse: Option<String>,

    /// Секретный ключ авторитета (hex, 32 байта) для `--authority-endorse`.
    #[arg(long, env = "NETRUNNER_AUTHORITY_KEY", hide_env_values = true)]
    authority_key: Option<String>,

    #[arg(long, default_value_t = 7)]
    endorse_days: u64,

    /// Напечатать приглашение к подключению этого узла и выйти:
    /// `nrxp://host:port?pk=…&secret=…&token=…&sni=…&name=…`. Адрес — `--advertise`
    /// (или `--invite-addr`), ключи — из `PROXY_NRXP_PRIVATE_KEY` / `PROXY_NRXP_SECRET`
    /// (в рое секрет выводится из `--swarm-key`). **Приглашение — секрет**: передавайте
    /// по закрытому каналу.
    #[arg(long)]
    invite: bool,
    /// Имя приглашения для списка в приложении (например, «мой телефон»).
    #[arg(long, requires = "invite")]
    invite_name: Option<String>,
    /// Bearer-токен клиента для узлов с `--require-auth`.
    #[arg(long, env = "NETRUNNER_INVITE_TOKEN", hide_env_values = true, requires = "invite")]
    invite_token: Option<String>,
    /// Домен-декой в приглашении (по умолчанию `--decoy-host`).
    #[arg(long, requires = "invite")]
    invite_sni: Option<String>,
    /// Публичный адрес `host:port` в приглашении (по умолчанию `--advertise`).
    #[arg(long, requires = "invite")]
    invite_addr: Option<String>,
    /// Формат вывода: `uri` — одна строка `nrxp://…`, `toml` — блок для `client.toml`.
    #[arg(long, default_value = "uri", value_parser = ["uri", "toml"], requires = "invite")]
    invite_format: String,

    /// Требовать валидный Bearer-токен (выданный `netrunner-backend`) от
    /// каждого клиента и отчитываться о расходе трафика для динамических
    /// лимитов. Выключено по умолчанию — включается по инстансу, не меняя
    /// поведение уже развёрнутых нод без этого флага.
    #[arg(long, default_value_t = false)]
    require_auth: bool,

    /// Enable authenticated peer routing. This node can accept mesh traffic
    /// and route local client streams according to --mesh-max-hops.
    #[arg(long, default_value_t = false)]
    mesh_enabled: bool,

    /// Maximum proxy-node count in a route: 1 = direct, 2 = RTT-weighted
    /// rotating healthy egress, 3..=8 = per-flow random length up to the limit
    /// with a pinned healthy egress.
    #[arg(long, default_value_t = 2)]
    mesh_max_hops: u8,

    /// UDP port for real QUIC between proxy nodes. Clients still connect to
    /// ingress through the existing quiceng datagram transport on --port.
    #[arg(
        long,
        env = "MESH_QUIC_PORT",
        default_value_t = netrunner_core::net::DEFAULT_MESH_QUIC_PORT
    )]
    mesh_quic_port: u16,

    /// URL control-plane бэкенда для проверки токенов/отчётов о трафике.
    /// Обязателен, если включён `--require-auth` или `--mesh-enabled`.
    #[arg(long)]
    backend_url: Option<String>,

    /// Порт для внутреннего HTTP `/health` (биндится только на 127.0.0.1 —
    /// не для публичного доступа, только supervisor/docker healthcheck на
    /// этой же машине). Не задан — health-эндпоинт выключен.
    #[arg(long)]
    health_port: Option<u16>,

    /// Порт для `/metrics` (Prometheus text exposition) — в отличие от
    /// `--health-port`, биндится на 0.0.0.0 (нужен для скрейпа удалённым
    /// центральным Prometheus), ОБЯЗАТЕЛЬНО зафайрволить на IP
    /// observability-VPS. Не задан — метрики выключены.
    #[arg(long)]
    metrics_port: Option<u16>,
}

fn main() {
    install_crypto_provider();

    // Приватность/стабильность: НЕ пишем JSON-лог на диск ноды — раньше это
    // (`Some("./logs")`) дважды забивало диск и вешало прокси (см. историю
    // инцидентов на proxy-fr1). JSON уходит в stdout — виден через
    // `docker logs`, централизованный сбор состояния тоннеля идёт отдельным
    // push-каналом на control-plane (см. `report_node_health` в network.rs).
    let args = Args::parse();
    // Приглашение печатается без логгера: в stdout только строка, которую забирает скрипт.
    if args.invite {
        invite_tool(&args);
        return;
    }
    Logger::init(None, true);
    Logger::global().set_level("info");

    if !(1..=netrunner_core::net::MAX_MESH_HOPS).contains(&args.mesh_max_hops) {
        panic!(
            "--mesh-max-hops must be between 1 and {}",
            netrunner_core::net::MAX_MESH_HOPS
        );
    }

    if args.authority_keygen || args.authority_endorse.is_some() {
        authority_tool(&args);
        return;
    }

    // Рой без панели: каталог узла строится из подписанных самоописаний.
    let swarm_directory: Option<Arc<netrunner_core::net::directory::Directory>> = args
        .swarm_key
        .as_deref()
        .map(|key| build_directory(&args, key));
    if args.print_descriptor {
        let dir = swarm_directory
            .as_ref()
            .expect("--print-descriptor требует --swarm-key (и --advertise)");
        let own = dir.own(netrunner_core::net::directory::unix_now());
        println!("node_id        {}", dir.node_id_hex());
        println!("static_public  {}", hex::encode(own.static_pub));
        // Для клиентов этого узла (`node_secret` / `node_public_key` в client.toml).
        println!("nrxp_secret    {}", dir.swarm().node_secret(&dir.node_id()));
        println!("descriptor     {}", hex::encode(own.encode()));
        return;
    }
    let swarm_mode = swarm_directory.is_some();
    // В режиме роя панель по умолчанию не нужна. Задан `--backend-url` — гибрид:
    // пользователи, пиры и допуск берутся и из панели, и из каталога.
    let hybrid_panel = swarm_mode && args.backend_url.is_some();
    let auth_required_by_node = args.require_auth || (args.mesh_enabled && !swarm_mode) || hybrid_panel;
    let backend_url = if auth_required_by_node {
        Some(
            args.backend_url
                .clone()
                .expect("--require-auth/--mesh-enabled требуют --backend-url"),
        )
    } else {
        None
    };
    let internal_secret = if auth_required_by_node {
        Some(
            std::env::var("PROXY_INTERNAL_SECRET")
                .expect("--require-auth/--mesh-enabled требуют PROXY_INTERNAL_SECRET"),
        )
    } else {
        None
    };
    let panel: Option<Arc<dyn AuthValidator>> = if auth_required_by_node {
        let backend_url = backend_url.expect("backend URL checked above");
        let internal_secret = internal_secret.as_ref().expect("secret checked above");
        Some(Arc::new(BackendClient::new(
            backend_url,
            internal_secret.clone(),
        )))
    } else {
        None
    };
    // Каталог и допуск пиров — из роя; учётные записи — из панели, если она есть.
    let auth: Option<Arc<dyn AuthValidator>> = match &swarm_directory {
        Some(dir) => Some(Arc::new(netrunner_core::net::directory::DirectoryValidator::new(
            dir.clone(),
            panel,
        ))),
        None => panel,
    };

    let mesh = if let Some(dir) = &swarm_directory {
        // Основной идентификатор для пиров панели — как у обычного узла (если узел в
        // панели зарегистрирован); пирам роя узел представляется роевым.
        let (mesh_id, node_secret) = match (hybrid_panel, std::env::var("PROXY_NODE_ID"), &internal_secret) {
            (true, Ok(panel_id), Some(secret)) => (panel_id, secret.clone()),
            _ => (dir.node_id_hex(), dir.swarm().node_secret(&dir.node_id())),
        };
        let mesh = Arc::new(netrunner_core::net::NodeMesh::with_max_hops_and_quic_port(
            mesh_id,
            node_secret,
            args.mesh_max_hops,
            args.mesh_quic_port,
        ));
        mesh.set_directory(dir.clone());
        Some(mesh)
    } else if args.mesh_enabled {
        let node_id = std::env::var("PROXY_NODE_ID")
            .expect("--mesh-enabled requires PROXY_NODE_ID from netrunner-backend");
        let node_secret = internal_secret
            .as_ref()
            .expect("mesh requires PROXY_INTERNAL_SECRET")
            .clone();
        Some(Arc::new(
            netrunner_core::net::NodeMesh::with_max_hops_and_quic_port(
                node_id,
                node_secret,
                args.mesh_max_hops,
                args.mesh_quic_port,
            ),
        ))
    } else {
        None
    };

    // Долговременные учётные данные ноды: секрет входа и приватная половина
    // статической пары X25519. Заводятся в админке бэкенда, сюда приезжают
    // провижинингом рядом с PROXY_INTERNAL_SECRET — но это РАЗНЫЕ секреты с
    // разным уровнем доступа: internal_secret пускает в control-plane и
    // клиентам не отдаётся никогда, а публичная половина статической пары,
    // наоборот, раздаётся каждому клиенту (см. crypto::identity).
    //
    // Обе переменные либо заданы вместе, либо не заданы вовсе: нода с одной
    // половиной конфигурации — это тихо сломанная нода, поэтому падаем на
    // старте, а не на каждом хендшейке.
    //
    // Флаги для метрик: сам `Identity` их наружу не отдаёт, а видеть, с чем
    // РЕАЛЬНО поднята нода, нужно — строка в БД бэкенда может от неё отстать
    // (например, `.env` уехал не тот). Расхождение видно сравнением
    // `netrunner_nrxp_*` с ноды и `node_nrxp_*` с бэкенда.
    let mut nrxp_strict_flag = false;
    // В рое входной секрет не настраивается, а выводится из ключа роя и личности
    // узла — так же, как его считают соседи.
    let nrxp_env = match &swarm_directory {
        Some(dir) => {
            let derived = dir.swarm().node_secret(&dir.node_id());
            if let Ok(explicit) = std::env::var("PROXY_NRXP_SECRET") {
                if !explicit.trim().eq_ignore_ascii_case(&derived) {
                    panic!(
                        "PROXY_NRXP_SECRET не совпадает с секретом, выведенным из --swarm-key: \
                         соседи не смогут подключиться. Уберите переменную — в рое он выводится сам"
                    );
                }
            }
            (
                Some(derived),
                Some(hex::encode(dir.identity().static_private)),
            )
        }
        None => (
            std::env::var("PROXY_NRXP_SECRET").ok(),
            std::env::var("PROXY_NRXP_PRIVATE_KEY").ok(),
        ),
    };
    let identity = match nrxp_env {
        (Some(secret), Some(private_key)) => {
            // Пока false, нода принимает и клиентов старой анонимной схемы —
            // это нужно ровно на время раскатки, пока бэкенд не раздал ключи
            // всем приложениям. Оставлять так навсегда нельзя: активному
            // посреднику достаточно переписать заявленную версию в
            // ClientHello, чтобы увести соединение на неаутентифицированную
            // схему. Финальный шаг раскатки — PROXY_NRXP_STRICT=true.
            let strict = std::env::var("PROXY_NRXP_STRICT")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);

            let local = LocalIdentity::from_hex(&secret, &private_key, strict)
                .expect("PROXY_NRXP_SECRET/PROXY_NRXP_PRIVATE_KEY: 32 байта hex каждый");

            // Публичную половину печатаем при старте: оператор сверяет её с
            // тем, что показывает админка для этой ноды. Разошлись — клиенты
            // не подключатся, и увидеть это в логе старта дешевле, чем в
            // графике неудачных хендшейков через сутки.
            netrunner_logger::info!(
                nrxp_public_key = %local.public_key_hex(),
                strict,
                "NRXP identity loaded"
            );
            nrxp_strict_flag = strict;
            Some(Identity::Local(local))
        }
        (None, None) => {
            netrunner_logger::warn!(
                "NRXP identity not configured: анонимный хендшейк, аутентификации сервера нет"
            );
            None
        }
        _ => panic!(
            "PROXY_NRXP_SECRET и PROXY_NRXP_PRIVATE_KEY задаются только вместе: \
             нода с половиной учётных данных не сможет аутентифицировать себя клиентам"
        ),
    };

    if (args.mesh_enabled || swarm_mode) && identity.is_none() {
        panic!("--mesh-enabled requires PROXY_NRXP_SECRET and PROXY_NRXP_PRIVATE_KEY");
    }
    if let (Some(mesh), Some(Identity::Local(local))) = (mesh.as_ref(), identity.as_ref()) {
        mesh.set_onion_identity(local.clone());
    }

    // Регистрируется один раз, до первого metrics::counter!/gauge!/histogram! —
    // если --metrics-port не задан, вызовы макросов молча уходят в
    // no-op recorder по умолчанию (штатное поведение крейта metrics).
    let nrxp_configured_flag = identity.is_some();

    let metrics_handle = args
        .metrics_port
        .map(|_| metrics_server::install_recorder());

    // Только после install_recorder: до него макросы metrics! уходят в
    // no-op-рекордер по умолчанию и значение бы потерялось.
    metrics::gauge!("netrunner_nrxp_identity_configured").set(nrxp_configured_flag as u8 as f64);
    metrics::gauge!("netrunner_nrxp_strict").set(nrxp_strict_flag as u8 as f64);

    // ── Витрина узла и допустимые SNI ──────────────────────────────────────
    //
    // Каталог доменов приходит из окружения (тот же список, что и у админки).
    // Если задан --decoy-preset, собираем его страницу ОДИН РАЗ здесь, на
    // старте, и на этом же шаге проверяем, что SNI пресета принадлежит узлу:
    // это и есть барьер «нельзя указать любой SNI» — валидный сертификат есть
    // только под свой домен.
    // ── Режим маскировки ──────────────────────────────────────────────────
    //
    // Два взаимоисключающих режима (см. DecoyMode). Relay — исторический
    // REALITY-style: ретрансляция «не наших» соединений на чужой реальный
    // сайт (--decoy-host). SelfHosted — узел сам обслуживает витрину под своим
    // доменом: fallback ведёт на ЛОКАЛЬНЫЙ сайт (--decoy-local-site), витрина
    // собирается здесь один раз, а SNI обязан принадлежать узлу.
    let decoy_mode = netrunner_core::decoy::DecoyMode::parse(&args.decoy_mode)
        .unwrap_or_else(|e| panic!("--decoy-mode: {e}"));
    let decoy_catalog = netrunner_core::decoy::DecoyCatalog::from_env();

    // Куда ретранслируется fallback и учитывать ли запрошенный SNI — зависит
    // от режима. Дефолт (Relay + внешний decoy_host + honor=true) идентичен
    // прежнему поведению узла.
    let (fallback_host, honor_requested_sni): (String, bool) = match decoy_mode {
        netrunner_core::decoy::DecoyMode::Relay => {
            // Собрать витрину всё равно можно (например, узел и владеет
            // доменом, и одновременно одалживает чужой) — но по умолчанию в
            // Relay витрина не нужна: сайт отдаёт заимствованный decoy_host.
            if args.decoy_preset.is_some() {
                info!("ℹ️  --decoy-preset в режиме relay игнорируется: fallback идёт на внешний --decoy-host");
            } else if decoy_catalog.is_empty() {
                info!(
                    "ℹ️  режим relay (REALITY-style): маскировка под внешний --decoy-host {}",
                    args.decoy_host
                );
            }
            (args.decoy_host.clone(), decoy_mode.honor_requested_sni())
        }
        netrunner_core::decoy::DecoyMode::SelfHosted => {
            // SelfHosted требует пресет витрины и владение его SNI: собрать и
            // проверить здесь, на старте, иначе узел не поднимется.
            let preset_name = args.decoy_preset.as_deref().unwrap_or_else(|| {
                panic!(
                    "--decoy-mode self-hosted требует --decoy-preset (какую витрину обслуживать)"
                )
            });
            let preset = decoy_site::preset::Preset::load(preset_name)
                .unwrap_or_else(|e| panic!("не удалось загрузить пресет '{preset_name}': {e}"));
            // SNI узла: явный --decoy-sni (домен ЭТОГО узла) важнее захардкоженного
            // в пресете. Пресет даёт только КОНТЕНТ витрины; под каким доменом её
            // показывать — атрибут узла. Домен обязан принадлежать узлу (каталог).
            let sni_str = args.decoy_sni.as_deref().unwrap_or(&preset.sni);
            let sni = decoy_catalog.validate(sni_str).unwrap_or_else(|e| {
                panic!(
                    "self-hosted: домен '{sni_str}' которым узел не владеет: {e}. \
                     Добавьте его в {}",
                    netrunner_core::decoy::DECOY_DOMAINS_ENV
                )
            });
            let decoy = netrunner_core::decoy::Decoy {
                sni,
                elements: preset.elements.clone(),
            };
            let page = preset
                .render()
                .unwrap_or_else(|e| panic!("сборка витрины '{preset_name}': {e}"));

            // Витрина отдаётся локальным TLS-терминатором своего домена;
            // публикуем собранную страницу туда, где его конфиг её заберёт.
            // Один раз при деплое, не на каждый запрос.
            let out = std::env::var("NETRUNNER_DECOY_SITE_OUT")
                .unwrap_or_else(|_| "/var/www/netrunner-decoy/index.html".to_string());
            if let Some(parent) = std::path::Path::new(&out).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            match std::fs::write(&out, &page) {
                Ok(()) => info!(
                    preset = preset_name, sni = %decoy.sni, blocks = decoy.elements.len(),
                    bytes = page.len(), out = %out,
                    "🪧 SelfHosted: витрина собрана, SNI подтверждён, страница опубликована"
                ),
                Err(e) => info!(
                    error = %e, out = %out,
                    "⚠️  SelfHosted: не удалось записать витрину (локальный сайт отдаст своё содержимое); продолжаю"
                ),
            }
            // Fallback — на локальный сайт узла; запрошенный SNI игнорируется.
            (
                args.decoy_local_site.clone(),
                decoy_mode.honor_requested_sni(),
            )
        }
    };

    // Форма трафика: узел отправляет направление `down`.
    netrunner_core::nrxp::shape::set_server_role(true);
    if let Some(path) = &args.shape_profile {
        match netrunner_core::browser_profile::load_shape_file(path) {
            Ok((up, down)) => info!("shape-profile: {path}: клиент→сервер {up}, сервер→клиент {down} значений"),
            Err(e) => panic!("--shape-profile: {e}"),
        }
    }

    // Cover-flight — один на весь узел, детерминированный (см. ServerHandler).
    // Измеренный (--cover-flight) либо типовая цепочка Let's Encrypt.
    let cover_flight: std::sync::Arc<[usize]> = match args.cover_flight.as_deref() {
        Some(spec) => {
            let text = if std::path::Path::new(spec).is_file() {
                std::fs::read_to_string(spec)
                    .unwrap_or_else(|e| panic!("--cover-flight: не удалось прочитать {spec}: {e}"))
            } else {
                spec.to_owned()
            };
            let (flight, warnings) = netrunner_core::decoy::CoverFlight::parse(&text)
                .unwrap_or_else(|e| panic!("--cover-flight: {e}"));
            for w in warnings {
                netrunner_logger::warn!("cover-flight: {w}");
            }
            info!("cover-flight: измеренный, записи {:?}", flight.as_records());
            flight.as_records().to_vec().into()
        }
        None => netrunner_core::decoy::CoverFlight::node_default()
            .as_records()
            .to_vec()
            .into(),
    };

    let net = Network::new(
        args.host.clone(),
        args.port,
        fallback_host,
        auth,
        args.require_auth,
        args.mesh_enabled || swarm_mode,
        mesh,
        args.mesh_quic_port,
        args.health_port,
        identity,
        cover_flight,
        honor_requested_sni,
    )
    .with_directory(args.directory_file.clone(), args.directory_gossip_interval)
    .with_endorsements(args.endorsement.clone());

    let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");

    rt.block_on(async {
        let token = CancellationToken::new();
        let run_token = token.clone();
        // net.run() спавним отдельной задачей и дожидаемся её ПОСЛЕ сигнала —
        // tokio::select! между сигналом и run() тут не подходит: select
        // дропает недовершившуюся ветку целиком, оборвав drain-фазу в
        // Network::run в момент получения самого сигнала, вместо того чтобы
        // дать ей отработать.
        let run_handle = tokio::spawn(async move {
            net.run(run_token).await;
        });

        if let (Some(port), Some(handle)) = (args.metrics_port, metrics_handle) {
            let metrics_token = token.clone();
            tokio::spawn(metrics_server::run(
                "0.0.0.0".to_string(),
                port,
                handle,
                metrics_token,
            ));
        }

        shutdown_signal(token).await;
        if let Err(e) = run_handle.await {
            error!(error = ?e, "Задача сервера завершилась с паникой при остановке");
        }
    });
}

/// Собирает каталог роя из флагов: личность из `PROXY_NRXP_PRIVATE_KEY`, адрес из
/// `--advertise`, начальные записи из `--directory-seed` и файла каталога.
fn build_directory(args: &Args, swarm_key: &str) -> Arc<netrunner_core::net::directory::Directory> {
    use netrunner_core::net::directory::{
        unix_now, Directory, DirectoryConfig, Endpoint, EndpointKind, StoreConfig, SwarmIdentity,
        SwarmKey,
    };
    let swarm = SwarmKey::from_hex(swarm_key).unwrap_or_else(|e| panic!("--swarm-key: {e}"));
    let private = std::env::var("PROXY_NRXP_PRIVATE_KEY")
        .expect("--swarm-key требует PROXY_NRXP_PRIVATE_KEY (статический ключ узла, hex)");
    let identity = SwarmIdentity::from_private_hex(&private)
        .unwrap_or_else(|e| panic!("PROXY_NRXP_PRIVATE_KEY: {e}"));
    let advertise = args
        .advertise
        .as_deref()
        .expect("--swarm-key требует --advertise host:port (публичный адрес узла)");
    let (host, port) = advertise
        .rsplit_once(':')
        .and_then(|(h, p)| Some((h.trim_matches(|c| c == '[' || c == ']'), p.parse::<u16>().ok()?)))
        .unwrap_or_else(|| panic!("--advertise: ожидается host:port, получено {advertise:?}"));
    let now = unix_now();
    let directory = Directory::new(
        identity,
        swarm,
        DirectoryConfig {
            store: StoreConfig {
                allow_private: args.directory_allow_private,
                trust_anchors: parse_anchors(&args.trust_anchor),
                ..Default::default()
            },
            endorsements: load_endorsements(&args.endorsement),
            strict_pairwise: args.swarm_strict,
            advertise: vec![Endpoint {
                kind: EndpointKind::Tcp,
                host: host.to_string(),
                port,
            }],
            decoy_sni: args.decoy_host.clone(),
            ..Default::default()
        },
        now,
    );
    // Своя запись обязана быть валидной сразу: иначе соседи её отвергнут.
    if let Err(e) = directory.own(now).verify(now, args.directory_allow_private) {
        panic!(
            "самоописание узла не проходит проверку ({e}); для частных адресов нужен \
             --directory-allow-private"
        );
    }
    if let Some(path) = &args.directory_file {
        if let Ok(bytes) = std::fs::read(path) {
            let n = directory.import(&bytes, now);
            netrunner_logger::info!(path = %path.display(), records = n, "directory loaded");
        }
    }
    for seed in &args.directory_seed {
        let text = std::fs::read_to_string(seed).unwrap_or_else(|_| seed.clone());
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
            let bytes = hex::decode(line).unwrap_or_else(|e| panic!("--directory-seed: {e}"));
            if let netrunner_core::net::directory::Insert::Rejected(why) =
                directory.insert_bytes(&bytes, now)
            {
                netrunner_logger::warn!(?why, "seed descriptor rejected")
            }
        }
    }
    netrunner_logger::info!(
        node_id = %directory.node_id_hex(),
        advertise = %advertise,
        records = directory.len(),
        "swarm directory ready"
    );
    Arc::new(directory)
}

/// Публичные ключи авторитетов из флага (hex, 32 байта).
fn parse_anchors(list: &[String]) -> Vec<[u8; 32]> {
    list.iter()
        .filter(|s| !s.trim().is_empty())
        .map(|s| {
            hex::decode(s.trim())
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .unwrap_or_else(|| panic!("--trust-anchor: ожидается 32 байта в hex, получено {s:?}"))
        })
        .collect()
}

/// Поручительства из флага: hex либо файл с записью в строке; битые пропускаются с
/// предупреждением (узел продолжает работать и без них — соседи просто его не примут).
pub(crate) fn load_endorsements(sources: &[String]) -> Vec<netrunner_core::net::directory::Endorsement> {
    let mut out = Vec::new();
    for src in sources.iter().filter(|s| !s.trim().is_empty()) {
        let text = std::fs::read_to_string(src).unwrap_or_else(|_| src.clone());
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
            match hex::decode(line).ok().and_then(|b| netrunner_core::net::directory::Endorsement::decode(&b)) {
                Some(e) => out.push(e),
                None => netrunner_logger::warn!("endorsement: запись не разобрана, пропущена"),
            }
        }
    }
    out
}

/// `--invite`: печатает приглашение `nrxp://…` (или блок `client.toml`) для этого узла.
/// Результат — только в stdout; пояснения — в stderr, чтобы вывод можно было забрать
/// подстановкой команды. Ошибки — понятное сообщение и код 2.
fn invite_tool(args: &Args) {
    use netrunner_core::invite::Invite;
    use netrunner_core::net::directory::{SwarmIdentity, SwarmKey};
    let fail = |msg: String| -> ! {
        eprintln!("--invite: {msg}");
        std::process::exit(2)
    };
    let private = std::env::var("PROXY_NRXP_PRIVATE_KEY")
        .unwrap_or_else(|_| fail("нужен PROXY_NRXP_PRIVATE_KEY (статический ключ узла, hex)".into()));
    let identity = SwarmIdentity::from_private_hex(&private).unwrap_or_else(|e| fail(format!("PROXY_NRXP_PRIVATE_KEY: {e}")));
    let public_key = hex::encode(identity.static_pub);
    // В рое входной секрет выводится из ключа роя, иначе задаётся явно.
    let secret = match args.swarm_key.as_deref() {
        Some(key) => {
            let derived = SwarmKey::from_hex(key)
                .unwrap_or_else(|e| fail(format!("--swarm-key: {e}")))
                .node_secret(&identity.node_id);
            if let Ok(explicit) = std::env::var("PROXY_NRXP_SECRET") {
                if !explicit.trim().eq_ignore_ascii_case(&derived) {
                    fail("PROXY_NRXP_SECRET не совпадает с секретом, выведенным из --swarm-key".into());
                }
            }
            derived
        }
        None => std::env::var("PROXY_NRXP_SECRET")
            .unwrap_or_else(|_| fail("нужен PROXY_NRXP_SECRET (или --swarm-key)".into())),
    };
    let addr = args
        .invite_addr
        .as_deref()
        .or(args.advertise.as_deref())
        .unwrap_or_else(|| fail("укажите публичный адрес: --advertise или --invite-addr host:port".into()));
    let sni = args.invite_sni.as_deref().unwrap_or(&args.decoy_host);
    let invite = Invite::new(addr, &public_key, &secret, args.invite_token.as_deref(), Some(sni), args.invite_name.as_deref())
        .unwrap_or_else(|e| fail(e.to_string()));
    if args.require_auth && invite.token.is_none() {
        eprintln!("--invite: предупреждение: узел с --require-auth, а токен не задан (--invite-token)");
    }
    match args.invite_format.as_str() {
        "toml" => print!("{}", invite.to_toml()),
        _ => println!("{}", invite.to_uri()),
    }
    eprintln!("Приглашение содержит секрет узла — передавайте только по закрытому каналу.");
}

/// `--authority-keygen` и `--authority-endorse`: инструмент авторитета.
fn authority_tool(args: &Args) {
    use ed25519_dalek::SigningKey;
    use netrunner_core::net::directory::{unix_now, Endorsement, NodeDescriptor};
    if args.authority_keygen {
        let secret: [u8; 32] = rand::random();
        let key = SigningKey::from_bytes(&secret);
        println!("authority_secret  {}", hex::encode(secret));
        println!("authority_public  {}   # в --trust-anchor узлов и клиентов", hex::encode(key.verifying_key().to_bytes()));
        return;
    }
    let desc_hex = args.authority_endorse.as_deref().expect("checked by caller");
    let secret = args
        .authority_key
        .as_deref()
        .expect("--authority-endorse требует --authority-key (или NETRUNNER_AUTHORITY_KEY)");
    let secret: [u8; 32] = hex::decode(secret.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .expect("--authority-key: 32 байта в hex");
    let desc = hex::decode(desc_hex.trim())
        .ok()
        .and_then(|b| NodeDescriptor::decode(&b).ok())
        .expect("--authority-endorse: ожидается hex самоописания из --print-descriptor");
    let now = unix_now();
    desc.verify(now, true).unwrap_or_else(|e| panic!("самоописание не проходит проверку: {e}"));
    let e = Endorsement::issue_for(&SigningKey::from_bytes(&secret), &desc, now + args.endorse_days * 86_400);
    println!("# поручительство за {} до {} (Unix)", hex::encode(desc.node_id), e.not_after);
    println!("{}", hex::encode(e.encode()));
}

#[cfg(test)]
mod tests {
    use super::install_crypto_provider;

    #[test]
    fn rustls_builder_works_with_both_ring_and_aws_lc_enabled() {
        install_crypto_provider();

        let _client_config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
    }
}
