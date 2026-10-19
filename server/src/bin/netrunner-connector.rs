//! Коннектор организации: агент во внутренней сети клиента.
//!
//! Сервисы компании (закрытый git, 1С, базы) часто недостижимы с VPN-ноды:
//! они за NAT, во внутренней сети или у другого хостера. Коннектор решает это
//! без единого открытого входящего порта: он сам, исходящим соединением,
//! подключается к ноде организации и становится выходом для тех потоков,
//! которые политика пользователя помечает «через коннектор». Дальше всё как
//! у обычного туннеля: сотрудник → нода → коннектор → сервис.
//!
//! Что коннектор НЕ делает: не пускает UDP (только TCP), не принимает входящих
//! соединений, не выходит в интернет по своей воле — каждый поток ему
//! открывает нода, и только тот, который прошёл политику доступа сотрудника.
//!
//! Запуск (значения показывает консоль организации при создании коннектора):
//!
//! ```text
//! netrunner-connector --node 203.0.113.10:443 --token nrc_... --label c1a2... \
//!     --nrxp-secret <hex> --nrxp-public <hex> --decoy-host www.debian.org
//! ```
//!
//! Сеть (LAN) включена намеренно — ради неё коннектор и ставят. Периметр
//! задаёт не коннектор, а ресурсы организации: сквозь него пройдёт только то,
//! что выдано сотруднику.

use std::time::Duration;

use clap::Parser;
use netrunner_core::net::{ClientHandler, EgressPolicy};
use netrunner_core::{Identity, PeerIdentity};

#[derive(Parser, Debug)]
#[command(name = "netrunner-connector", version)]
struct Args {
    /// Адрес ноды организации `host:port`.
    #[arg(long, env = "NR_CONNECTOR_NODE")]
    node: String,

    /// Токен коннектора из консоли организации. Через переменную окружения,
    /// а не аргумент: аргументы видны в `ps` любому на этой машине.
    #[arg(long, env = "NR_CONNECTOR_TOKEN", hide_env_values = true)]
    token: String,

    /// Метка коннектора (из консоли) — по ней нода выбирает, кому отдать поток.
    #[arg(long, env = "NR_CONNECTOR_LABEL")]
    label: String,

    /// `nrxp_secret` ноды — по нему коннектор отличает свою ноду от чужой.
    #[arg(long, env = "NR_CONNECTOR_NRXP_SECRET")]
    nrxp_secret: String,

    /// `nrxp_static_public` ноды.
    #[arg(long, env = "NR_CONNECTOR_NRXP_PUBLIC")]
    nrxp_public: String,

    /// SNI-маскировка соединения (decoy-домен ноды).
    #[arg(long, env = "NR_CONNECTOR_DECOY_HOST", default_value = "www.debian.org")]
    decoy_host: String,

    /// Сколько потоков коннектор обслуживает одновременно (0 — без лимита).
    #[arg(long, env = "NR_CONNECTOR_MAX_STREAMS", default_value_t = 512)]
    max_streams: usize,
}

const RECONNECT_MIN: Duration = Duration::from_secs(2);
const RECONNECT_MAX: Duration = Duration::from_secs(60);
const LIVENESS_POLL: Duration = Duration::from_secs(5);
/// Столько подряд без живых ног — соединение считается потерянным.
const DEAD_AFTER_POLLS: u32 = 3;

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let identity = match PeerIdentity::from_hex(&args.nrxp_secret, &args.nrxp_public) {
        Ok(peer) => Identity::Peer(peer),
        Err(e) => {
            eprintln!("Некорректные NRXP-ключи ноды: {}", e.internal_msg);
            std::process::exit(2);
        }
    };
    let policy = EgressPolicy {
        allow_private: true,
        max_streams: (args.max_streams > 0).then_some(args.max_streams),
    };

    let mut backoff = RECONNECT_MIN;
    loop {
        eprintln!("connector: подключаюсь к {}", args.node);
        match ClientHandler::connect_egress(
            &args.node,
            args.decoy_host.as_str(),
            Some(args.token.clone()),
            &args.label,
            Some(identity.clone()),
            policy.clone(),
        )
        .await
        {
            Ok(muxer) => {
                eprintln!("connector: на связи");
                backoff = RECONNECT_MIN;
                let mut dead_polls = 0u32;
                loop {
                    tokio::time::sleep(LIVENESS_POLL).await;
                    if muxer.is_fatal() {
                        eprintln!("connector: нода отвергла токен — проверьте токен и метку");
                        break;
                    }
                    if muxer.active_legs_count() == 0 {
                        dead_polls += 1;
                        if dead_polls >= DEAD_AFTER_POLLS {
                            eprintln!("connector: связь потеряна");
                            break;
                        }
                    } else {
                        dead_polls = 0;
                    }
                }
            }
            Err(e) => eprintln!("connector: не удалось подключиться: {}", e.internal_msg),
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(RECONNECT_MAX);
    }
}
