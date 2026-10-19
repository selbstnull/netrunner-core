//! Локальная панель управления mesh-сетями: ключи роя, корневые ключи, доверенности,
//! ротация, отзыв, аудит. Один HTML-шаблон (`ui/`) и небольшой JSON-API.
//!
//! # Почему снаружи недоступна
//!
//! * Слушает **только** `127.0.0.1` — адрес не настраивается, флага «открыть наружу» нет.
//!   С другой машины до порта нельзя дотянуться (на сервере — через `ssh -L`).
//! * Любое соединение не с loopback-адреса отбрасывается ещё до чтения запроса.
//! * Заголовок `Host` обязан быть `127.0.0.1:<порт>` или `localhost:<порт>` — иначе
//!   страница, открытая в браузере на чужом сайте, не сможет достучаться через DNS rebinding.
//! * Изменяющие запросы с чужим `Origin` отклоняются, API требует токен в заголовке
//!   `Authorization` (cookie нет, поэтому CSRF невозможен по построению).
//! * Токен панели — случайные 32 байта в файле `admin.token` (`0600`): пустить в панель
//!   может только тот, кто может прочитать каталог данных.

pub mod api;
pub mod attention;
pub mod caps;
pub mod http;
pub mod live;
pub mod node;
pub mod store;

use netrunner_logger::{info, warn};
use node::NodeView;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use subtle::ConstantTimeEq;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

pub const DEFAULT_DIR: &str = "./netrunner-admin";
const TOKEN_FILE: &str = "admin.token";
const MAX_CONNECTIONS: usize = 32;

/// Статика панели: путь → (тип, содержимое). Ничего внешнего не грузится.
const ASSETS: &[(&str, &str, &[u8])] = &[
    ("/", "text/html; charset=utf-8", include_bytes!("ui/index.html")),
    ("/app.css", "text/css; charset=utf-8", include_bytes!("ui/app.css")),
    ("/favicon.svg", "image/svg+xml", include_bytes!("ui/favicon.svg")),
    ("/fonts/nunito-latin.woff2", "font/woff2", include_bytes!("ui/fonts/nunito-latin.woff2")),
    ("/fonts/nunito-cyrillic.woff2", "font/woff2", include_bytes!("ui/fonts/nunito-cyrillic.woff2")),
    ("/js/theme.js", "text/javascript; charset=utf-8", include_bytes!("ui/js/theme.js")),
    ("/js/main.js", "text/javascript; charset=utf-8", include_bytes!("ui/js/main.js")),
    ("/js/api.js", "text/javascript; charset=utf-8", include_bytes!("ui/js/api.js")),
    ("/js/ui.js", "text/javascript; charset=utf-8", include_bytes!("ui/js/ui.js")),
    ("/js/icons.js", "text/javascript; charset=utf-8", include_bytes!("ui/js/icons.js")),
    ("/js/charts.js", "text/javascript; charset=utf-8", include_bytes!("ui/js/charts.js")),
    ("/js/overview.js", "text/javascript; charset=utf-8", include_bytes!("ui/js/overview.js")),
    ("/js/meshes.js", "text/javascript; charset=utf-8", include_bytes!("ui/js/meshes.js")),
    ("/js/nodes.js", "text/javascript; charset=utf-8", include_bytes!("ui/js/nodes.js")),
    ("/js/tools.js", "text/javascript; charset=utf-8", include_bytes!("ui/js/tools.js")),
];

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Общее состояние обработчиков.
pub struct Ctx {
    pub store: store::Store,
    token: Mutex<String>,
    pub port: u16,
    pub started: u64,
    /// Живой узел: каталог роя, mesh, счётчики, метрики.
    pub node: Arc<NodeView>,
    pub live: live::Live,
}

impl Ctx {
    pub fn token_ok(&self, presented: &str) -> bool {
        let t = self.token.lock().unwrap_or_else(|p| p.into_inner());
        t.as_bytes().ct_eq(presented.as_bytes()).into()
    }

    /// Выпускает новый токен панели и записывает его в файл; прежний перестаёт действовать.
    pub fn rotate_token(&self) -> Result<String, String> {
        let fresh = hex::encode(rand::random::<[u8; 32]>());
        store::write_private_file(&self.store.dir().join(TOKEN_FILE), format!("{fresh}\n").as_bytes())
            .map_err(|e| format!("не удалось записать токен: {e}"))?;
        *self.token.lock().unwrap_or_else(|p| p.into_inner()) = fresh.clone();
        Ok(fresh)
    }
}

fn load_or_create_token(dir: &std::path::Path) -> std::io::Result<String> {
    let path = dir.join(TOKEN_FILE);
    if let Ok(t) = std::fs::read_to_string(&path) {
        let t = t.trim();
        if t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Ok(t.to_string());
        }
    }
    let fresh = hex::encode(rand::random::<[u8; 32]>());
    store::write_private_file(&path, format!("{fresh}\n").as_bytes())?;
    Ok(fresh)
}

/// Единственное место, где панель занимает порт: адрес зашит, настроить его нельзя.
async fn bind(port: u16) -> std::io::Result<TcpListener> {
    TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)).await
}

/// Запускает панель на `127.0.0.1:port` и работает до отмены `cancel`.
pub async fn run(port: u16, dir: PathBuf, node: Arc<NodeView>, cancel: CancellationToken) {
    let listener = match bind(port).await {
        Ok(l) => l,
        Err(e) => {
            netrunner_logger::error!(error = %e, port, "admin: не удалось занять порт панели");
            return;
        }
    };
    let ctx = match open_ctx(&dir, listener.local_addr().map(|a| a.port()).unwrap_or(port), node) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            netrunner_logger::error!(error = %e, dir = %dir.display(), "admin: не удалось открыть каталог данных");
            return;
        }
    };
    info!(
        "🛠  Панель управления: http://localhost:{}/ (только loopback; токен — в {})",
        ctx.port,
        dir.join(TOKEN_FILE).display()
    );
    tokio::spawn(sampler(ctx.clone(), cancel.clone()));
    serve(listener, ctx, cancel).await;
}

fn open_ctx(dir: &std::path::Path, port: u16, node: Arc<NodeView>) -> std::io::Result<Ctx> {
    let store = store::Store::open(dir)?;
    let token = load_or_create_token(dir)?;
    Ok(Ctx { store, token: Mutex::new(token), port, started: now(), node, live: live::Live::default() })
}

/// Раз в несколько секунд снимает показатели узла для графиков обзора.
async fn sampler(ctx: Arc<Ctx>, cancel: CancellationToken) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(live::INTERVAL_SECS));
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tick.tick() => ctx.live.record(&ctx.node, now()),
        }
    }
}

pub async fn serve(listener: TcpListener, ctx: Arc<Ctx>, cancel: CancellationToken) {
    let limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            res = listener.accept() => {
                let Ok((stream, peer)) = res else { continue };
                // Слушаем только loopback, но проверка стоит и здесь — на случай, если
                // кто-то поменяет адрес привязки.
                if !peer.ip().is_loopback() {
                    warn!(%peer, "admin: соединение не с loopback отброшено");
                    continue;
                }
                let Ok(permit) = limit.clone().try_acquire_owned() else { continue };
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    let _ = tokio::time::timeout(http::IO_TIMEOUT, handle(stream, &ctx)).await;
                    drop(permit);
                });
            }
        }
    }
    info!("Панель управления остановлена.");
}

async fn handle(mut stream: TcpStream, ctx: &Ctx) {
    let resp = match http::read_request(&mut stream).await {
        Ok(req) => dispatch(ctx, &req).await,
        Err(e) => http::Response::error(400, &e),
    };
    let _ = http::write_response(&mut stream, &resp).await;
}

/// Защита от запросов из браузера, инициированных чужими сайтами.
fn origin_guard(ctx: &Ctx, req: &http::Request) -> Result<(), http::Response> {
    let host = req.header("host").unwrap_or("");
    let ok_hosts = [format!("127.0.0.1:{}", ctx.port), format!("localhost:{}", ctx.port)];
    if !ok_hosts.iter().any(|h| h.eq_ignore_ascii_case(host)) {
        return Err(http::Response::error(403, "недопустимый Host"));
    }
    if req.method != "GET" && req.method != "HEAD" {
        if let Some(origin) = req.header("origin") {
            if !origin.eq_ignore_ascii_case(&format!("http://{host}")) {
                return Err(http::Response::error(403, "недопустимый Origin"));
            }
        }
        if let Some(site) = req.header("sec-fetch-site") {
            if site != "same-origin" && site != "none" {
                return Err(http::Response::error(403, "кросс-сайтовый запрос"));
            }
        }
        let json = req.header("content-type").is_some_and(|c| c.starts_with("application/json"));
        if !json {
            return Err(http::Response::error(400, "ожидается Content-Type: application/json"));
        }
    }
    Ok(())
}

pub async fn dispatch(ctx: &Ctx, req: &http::Request) -> http::Response {
    if let Err(r) = origin_guard(ctx, req) {
        return r;
    }
    if req.method == "GET" {
        let path = if req.path == "/index.html" { "/" } else { req.path.as_str() };
        if let Some((_, ct, body)) = ASSETS.iter().find(|(p, _, _)| *p == path) {
            return http::Response::asset(ct, body);
        }
    }
    if !req.path.starts_with("/api/") {
        return http::Response::error(404, "не найдено");
    }
    let presented = req.header("authorization").and_then(|v| v.strip_prefix("Bearer ")).unwrap_or("");
    if !ctx.token_ok(presented) {
        return http::Response::error(401, "нужен токен панели");
    }
    api::route(ctx, req).await
}

#[cfg(test)]
mod tests;
