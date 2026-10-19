use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Harness {
    node: Arc<node::NodeView>,
    port: u16,
    token: String,
    cancel: CancellationToken,
    dir: PathBuf,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.cancel.cancel();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn start() -> Harness {
    let dir = std::env::temp_dir().join(format!("nr-admin-it-{}", hex::encode(rand::random::<[u8; 4]>())));
    let listener = bind(0).await.unwrap();
    assert!(listener.local_addr().unwrap().ip().is_loopback(), "панель обязана слушать только loopback");
    let port = listener.local_addr().unwrap().port();
    let node = Arc::new(node::NodeView::detached());
    let ctx = Arc::new(open_ctx(&dir, port, node.clone()).unwrap());
    let token = ctx.token.lock().unwrap().clone();
    let cancel = CancellationToken::new();
    tokio::spawn(serve(listener, ctx, cancel.clone()));
    Harness { node, port, token, cancel, dir }
}

/// Сырой HTTP-запрос; возвращает (статус, заголовки, тело).
async fn raw(port: u16, request: String) -> (u16, String, String) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(request.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.unwrap();
    let text = String::from_utf8_lossy(&out).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head.split(' ').nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    (status, head.to_string(), body.to_string())
}

impl Harness {
    async fn call(&self, method: &str, path: &str, body: Option<serde_json::Value>) -> (u16, serde_json::Value) {
        self.call_with(method, path, body, Some(&self.token), &format!("127.0.0.1:{}", self.port), &[]).await
    }

    async fn call_with(
        &self,
        method: &str,
        path: &str,
        body: Option<serde_json::Value>,
        token: Option<&str>,
        host: &str,
        extra: &[(&str, &str)],
    ) -> (u16, serde_json::Value) {
        let body = body.map(|b| b.to_string());
        let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n");
        if let Some(t) = token {
            req += &format!("Authorization: Bearer {t}\r\n");
        }
        for (k, v) in extra {
            req += &format!("{k}: {v}\r\n");
        }
        if method != "GET" {
            req += "Content-Type: application/json\r\n";
        }
        let b = body.unwrap_or_default();
        req += &format!("Content-Length: {}\r\n\r\n{b}", b.len());
        let (status, _, body) = raw(self.port, req).await;
        (status, serde_json::from_str(&body).unwrap_or(serde_json::Value::Null))
    }
}

#[tokio::test]
async fn static_assets_need_no_token_and_carry_security_headers() {
    let h = start().await;
    let (status, head, body) = raw(h.port, format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n", h.port)).await;
    assert_eq!(status, 200);
    assert!(body.contains("<title>"));
    let head = head.to_ascii_lowercase();
    assert!(head.contains("content-security-policy: default-src 'none'; script-src 'self'"));
    assert!(head.contains("x-frame-options: deny"));
    assert!(head.contains("cache-control: no-store"));
}

#[tokio::test]
async fn every_asset_is_served_and_every_js_import_resolves() {
    let h = start().await;
    for (path, ct, body) in ASSETS {
        let (status, head, _) = raw(h.port, format!("GET {path} HTTP/1.1\r\nHost: localhost:{}\r\n\r\n", h.port)).await;
        assert_eq!(status, 200, "{path}");
        assert!(head.to_ascii_lowercase().contains(&format!("content-type: {}", ct.to_ascii_lowercase())), "{path}");
        assert!(!body.is_empty(), "{path}");
        if let Some(name) = path.strip_prefix("/js/") {
            // относительные импорты вида `from './x.js'` обязаны вести на отдаваемый файл
            let src = std::str::from_utf8(body).unwrap();
            for part in src.split("from './").skip(1).chain(src.split("import('./").skip(1)) {
                let target = part.split(['\'', '"']).next().unwrap();
                assert!(ASSETS.iter().any(|(p, ..)| *p == format!("/js/{target}")), "{name} импортирует /js/{target}, которого нет в ASSETS");
            }
        }
    }
    // Именованные импорты обязаны существовать: браузер при несовпадении молча не запускает
    // всё приложение (ошибка линковки модулей даже не попадает в консоль страницы).
    for (path, _, body) in ASSETS.iter().filter(|(p, ..)| p.starts_with("/js/")) {
        let src = std::str::from_utf8(body).unwrap();
        for chunk in src.split("import {").skip(1) {
            let Some((names, rest)) = chunk.split_once('}') else { continue };
            let Some(target) = rest.trim_start().strip_prefix("from './").and_then(|r| r.split('\'').next()) else { continue };
            let (_, _, tsrc) = ASSETS.iter().find(|(p, ..)| *p == format!("/js/{target}")).unwrap();
            let tsrc = std::str::from_utf8(tsrc).unwrap();
            for name in names.split(',').map(|n| n.trim().split(" as ").next().unwrap().trim()).filter(|n| !n.is_empty()) {
                let word_after = |pat: &str| tsrc.match_indices(pat).any(|(i, _)| !tsrc[i + pat.len()..].starts_with(|c: char| c.is_alphanumeric() || c == '_'));
                let declared = ["function", "async function", "const", "let", "class"].iter().any(|k| word_after(&format!("export {k} {name}")))
                    || tsrc.lines().any(|l| l.starts_with("export {") && l.split(['{', '}', ',']).any(|x| x.trim() == name));
                assert!(declared, "{path} импортирует {name} из ./{target}, а тот его не экспортирует");
            }
        }
    }
    // страница не тянет ничего внешнего
    let html = std::str::from_utf8(ASSETS[0].2).unwrap();
    assert!(!html.contains("http://") && !html.contains("https://"));
}

#[tokio::test]
async fn api_requires_the_exact_token() {
    let h = start().await;
    let host = format!("127.0.0.1:{}", h.port);
    assert_eq!(h.call_with("GET", "/api/status", None, None, &host, &[]).await.0, 401);
    assert_eq!(h.call_with("GET", "/api/status", None, Some("deadbeef"), &host, &[]).await.0, 401);
    let near = format!("{}0", &h.token[..63]);
    assert_eq!(h.call_with("GET", "/api/status", None, Some(&near), &host, &[]).await.0, 401);
    assert_eq!(h.call("GET", "/api/status", None).await.0, 200);
    assert_eq!(h.call("GET", "/api/nope", None).await.0, 404);
}

#[tokio::test]
async fn foreign_host_and_origin_are_refused() {
    let h = start().await;
    // DNS rebinding: браузер шлёт запрос на 127.0.0.1, но с Host чужого домена.
    let (s, _) = h.call_with("GET", "/api/status", None, Some(&h.token), "evil.example", &[]).await;
    assert_eq!(s, 403);
    let (s, _) = h.call_with("GET", "/api/status", None, Some(&h.token), "127.0.0.1:1", &[]).await;
    assert_eq!(s, 403);
    let host = format!("localhost:{}", h.port);
    let (s, _) = h.call_with("GET", "/api/status", None, Some(&h.token), &host, &[]).await;
    assert_eq!(s, 200);

    let host = format!("127.0.0.1:{}", h.port);
    let body = Some(serde_json::json!({"name": "x"}));
    let (s, _) = h.call_with("POST", "/api/meshes", body.clone(), Some(&h.token), &host, &[("Origin", "https://evil.example")]).await;
    assert_eq!(s, 403);
    let (s, _) = h.call_with("POST", "/api/meshes", body.clone(), Some(&h.token), &host, &[("Sec-Fetch-Site", "cross-site")]).await;
    assert_eq!(s, 403);
    let own = format!("http://{host}");
    let (s, _) = h.call_with("POST", "/api/meshes", body, Some(&h.token), &host, &[("Origin", &own)]).await;
    assert_eq!(s, 200);
    assert_eq!(h.call("GET", "/api/meshes", None).await.1["meshes"].as_array().unwrap().len(), 1, "отклонённые запросы ничего не создали");
}

#[tokio::test]
async fn non_json_post_is_refused() {
    let h = start().await;
    let req = format!(
        "POST /api/meshes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {}\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\n{{}}",
        h.port, h.token
    );
    assert_eq!(raw(h.port, req).await.0, 400);
}

#[tokio::test]
async fn full_flow_issue_delegate_verify_rotate_revoke() {
    use serde_json::json;
    let h = start().await;
    let (s, r) = h.call("POST", "/api/meshes", Some(json!({"name": "alpha"}))).await;
    assert_eq!(s, 200);
    let mesh = r["id"].as_str().unwrap().to_string();

    // секреты не утекают в списки
    let (_, list) = h.call("GET", "/api/meshes", None).await;
    let list_text = list.to_string();
    let (_, key) = h.call("GET", &format!("/api/meshes/{mesh}/swarm-key"), None).await;
    let swarm = key["swarm_key"].as_str().unwrap();
    assert_eq!(swarm.len(), 64);
    assert!(!list_text.contains(swarm));

    let (s, root) = h.call("POST", &format!("/api/meshes/{mesh}/grants"), Some(json!({
        "label": "alice", "roles": ["client", "relay"], "ttl_hours": 24, "delegate": 1
    }))).await;
    assert_eq!(s, 200, "{root}");
    let root_serial = root["serial"].as_str().unwrap().to_string();
    let root_token = root["token"].as_str().unwrap().to_string();

    let (_, v) = h.call("POST", "/api/verify", Some(json!({"token": root_token}))).await;
    assert_eq!(v["valid"], true, "{v}");

    // потомок не может быть шире
    let (s, e) = h.call("POST", &format!("/api/meshes/{mesh}/grants"), Some(json!({
        "label": "bob", "parent": root_serial, "roles": ["egress"], "ttl_hours": 1
    }))).await;
    assert_eq!(s, 400, "{e}");
    let (s, child) = h.call("POST", &format!("/api/meshes/{mesh}/grants"), Some(json!({
        "label": "bob", "parent": root_serial, "roles": ["client"], "ttl_hours": 1
    }))).await;
    assert_eq!(s, 200, "{child}");
    let child_token = child["token"].as_str().unwrap().to_string();
    assert_eq!(h.call("POST", "/api/verify", Some(json!({"token": child_token}))).await.1["valid"], true);

    // ротация корня с переходным периодом: старые токены живут, затем перевыпуск
    h.call("POST", &format!("/api/meshes/{mesh}/rotate-root"), Some(json!({"grace_hours": 1}))).await;
    let v = h.call("POST", "/api/verify", Some(json!({"token": child_token}))).await.1;
    assert_eq!(v["valid"], true, "в переходный период старые токены ещё действуют: {v}");
    let (_, d) = h.call("POST", &format!("/api/meshes/{mesh}/reissue"), None).await;
    assert_eq!(d["counts"]["active"], 2, "{d}");

    // отзыв родителя убивает потомка
    let (s, _) = h.call("POST", &format!("/api/grants/{root_serial}/revoke"), Some(json!({"reason": "test"}))).await;
    assert_eq!(s, 200);
    let v = h.call("POST", "/api/verify", Some(json!({"token": child_token}))).await.1;
    assert_eq!(v["valid"], false);

    // мусор вместо токена — не паника, а отказ
    assert_eq!(h.call("POST", "/api/verify", Some(json!({"token": "x"}))).await.1["valid"], false);

    // аудит без секретов
    let (_, a) = h.call("GET", "/api/audit", None).await;
    let text = a.to_string();
    assert!(text.contains("grant.issue") && text.contains("grant.revoke"));
    assert!(!text.contains(swarm) && !text.contains("nrxp-cap1."));

    // ротация токена панели: старый перестаёт работать
    let (_, t) = h.call("POST", "/api/admin-token/rotate", None).await;
    let new = t["token"].as_str().unwrap();
    assert_ne!(new, h.token);
    assert_eq!(h.call("GET", "/api/status", None).await.0, 401);
    let host = format!("127.0.0.1:{}", h.port);
    assert_eq!(h.call_with("GET", "/api/status", None, Some(new), &host, &[]).await.0, 200);
    assert_eq!(std::fs::read_to_string(h.dir.join("admin.token")).unwrap().trim(), new);
}

#[tokio::test]
async fn token_file_is_private_and_reused() {
    let h = start().await;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(h.dir.join("admin.token")).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    assert_eq!(load_or_create_token(&h.dir).unwrap(), h.token);
}


#[tokio::test]
async fn node_endpoints_in_detached_mode() {
    use serde_json::json;
    let h = start().await;
    let (s, n) = h.call("GET", "/api/node", None).await;
    assert_eq!(s, 200);
    assert_eq!(n["mode"], "standalone");
    assert_eq!(n["healthy"], true);
    let (_, mt) = h.call("GET", "/api/metrics", None).await;
    assert_eq!(mt["available"], false);
    let (_, l) = h.call("GET", "/api/live", None).await;
    assert_eq!(l["metrics"], false);
    assert!(l["points"].is_array());
    let (_, p) = h.call("GET", "/api/node/peers", None).await;
    assert_eq!(p["source"], "none");
    // без роя и ключей узла нечего выдавать / добавлять
    assert_eq!(h.call("GET", "/api/node/client-config", None).await.0, 400);
    assert_eq!(h.call("GET", "/api/node/descriptor", None).await.0, 400);
    assert_eq!(h.call("POST", "/api/node/seed", Some(json!({"descriptor": "00"}))).await.0, 400);
    assert_eq!(h.call("POST", "/api/node/directory/gc", None).await.0, 400);
    assert_eq!(h.call("POST", "/api/node/log-level", Some(json!({"level": "loud"}))).await.0, 400);
    assert_eq!(h.call("POST", "/api/node/log-level", Some(json!({"level": "debug"}))).await.0, 200);
    assert_eq!(h.call("GET", "/api/node", None).await.1["log_level"], "debug");
    // подхватить ключ узла можно только в режиме роя
    assert_eq!(h.call("POST", "/api/meshes", Some(json!({"name": "adopt", "from_node": true}))).await.0, 400);
    let own = "ab".repeat(32);
    assert_eq!(h.call("POST", "/api/meshes", Some(json!({"name": "own", "swarm_key": own}))).await.0, 200);
    assert_eq!(h.call("POST", "/api/meshes", Some(json!({"name": "own2", "swarm_key": own}))).await.0, 400);
}

#[tokio::test]
async fn shutdown_requires_the_word_and_then_cancels() {
    use serde_json::json;
    let h = start().await;
    assert_eq!(h.call("POST", "/api/node/shutdown", Some(json!({"confirm": "stop"}))).await.0, 400);
    assert!(!h.node.shutdown.is_cancelled());
    assert_eq!(h.call("POST", "/api/node/shutdown", Some(json!({"confirm": "STOP"}))).await.0, 200);
    tokio::time::timeout(std::time::Duration::from_secs(3), h.node.shutdown.cancelled()).await.expect("узел получил сигнал остановки");
}

#[tokio::test]
async fn client_config_is_generated_validated_and_audited() {
    let dir = std::env::temp_dir().join(format!("nr-admin-cc-{}", hex::encode(rand::random::<[u8; 4]>())));
    let mut parts = node::NodeParts {
        mode: "standalone", config: serde_json::json!({}), directory: None, mesh: None,
        active_connections: Arc::new(std::sync::atomic::AtomicU64::new(0)), metrics: None,
        shutdown: CancellationToken::new(),
        creds: Some(node::ClientCreds { secret: "ab".repeat(32), public_key: "cd".repeat(32) }),
        advertise: Some("203.0.113.9:443".into()), decoy_host: "www.debian.org".into(), strict: true,
    };
    parts.config = serde_json::json!({});
    let node = Arc::new(node::NodeView::new(parts));
    let toml = node.client_config(None, None).unwrap();
    assert!(toml.contains("remote_address     = \"203.0.113.9:443\""));
    assert!(toml.contains(&format!("node_secret        = \"{}\"", "ab".repeat(32))));
    assert!(toml.contains("sni                = \"www.debian.org\""));
    // внедрение кавычек/строк в TOML невозможно
    assert!(node.client_config(Some("1.2.3.4:443\"\nevil = 1"), None).is_err());
    assert!(node.client_config(None, Some("a b")).is_err());
    assert!(node.client_config(Some("[::1]:443"), Some("example.com")).is_ok());
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn backup_restore_extend_meta_attention() {
    use serde_json::json;
    let h = start().await;
    let (_, m) = h.call("POST", "/api/meshes", Some(json!({"name": "alpha"}))).await;
    let mesh = m["id"].as_str().unwrap().to_string();
    let (_, g) = h.call("POST", &format!("/api/meshes/{mesh}/grants"), Some(json!({"label": "alice", "note": "ноутбук", "roles": ["client"], "ttl_hours": 48}))).await;
    let serial = g["serial"].as_str().unwrap().to_string();

    // истекающая доверенность и отсутствие копии попадают в «внимание»
    let (_, a) = h.call("GET", "/api/attention", None).await;
    let codes: Vec<&str> = a["items"].as_array().unwrap().iter().map(|i| i["code"].as_str().unwrap()).collect();
    assert!(codes.contains(&"no-backup") && codes.contains(&"grant-expiring"), "{a}");

    let (_, d) = h.call("GET", &format!("/api/meshes/{mesh}"), None).await;
    assert_eq!(d["grants"][0]["note"], "ноутбук");
    assert_eq!(d["swarm_fp"].as_str().unwrap().len(), 19);
    assert!(!d.to_string().contains(&h.call("GET", &format!("/api/meshes/{mesh}/swarm-key"), None).await.1["swarm_key"].as_str().unwrap().to_string()));

    let (s, e) = h.call("POST", &format!("/api/grants/{serial}/extend"), Some(json!({"ttl_hours": 24 * 30}))).await;
    assert_eq!(s, 200, "{e}");
    assert_eq!(h.call("POST", "/api/verify", Some(json!({"token": e["token"]}))).await.1["valid"], true);
    assert_eq!(h.call("POST", &format!("/api/grants/{serial}/meta"), Some(json!({"label": "Алиса", "note": ""}))).await.0, 200);
    assert_eq!(h.call("POST", &format!("/api/meshes/{mesh}/rename"), Some(json!({"name": "beta", "note": "n"}))).await.0, 200);

    // копия → порча → восстановление
    let (s, b) = h.call("GET", "/api/backup", None).await;
    assert_eq!(s, 200);
    assert_eq!(b["format"], "nrxp-admin-backup/1");
    let codes: Vec<String> = h.call("GET", "/api/attention", None).await.1["items"].as_array().unwrap().iter().map(|i| i["code"].as_str().unwrap().to_string()).collect();
    assert!(!codes.contains(&"no-backup".to_string()), "после копии напоминание снимается");

    assert_eq!(h.call("POST", "/api/backup/restore", Some(json!({"backup": b, "confirm": "no"}))).await.0, 400);
    let mut broken = b.clone();
    broken["state"]["meshes"][0]["grants"][0]["holder_seed"] = json!("00".repeat(32));
    assert_eq!(h.call("POST", "/api/backup/restore", Some(json!({"backup": broken, "confirm": "RESTORE"}))).await.0, 400);
    assert_eq!(h.call("POST", "/api/backup/restore", Some(json!({"backup": {"format": "x"}, "confirm": "RESTORE"}))).await.0, 400);

    h.call("POST", &format!("/api/meshes/{mesh}/delete"), Some(json!({"confirm": "beta"}))).await;
    assert_eq!(h.call("GET", "/api/meshes", None).await.1["meshes"].as_array().unwrap().len(), 0);
    let (s, r) = h.call("POST", "/api/backup/restore", Some(json!({"backup": b, "confirm": "RESTORE"}))).await;
    assert_eq!(s, 200, "{r}");
    let (_, list) = h.call("GET", "/api/meshes", None).await;
    assert_eq!(list["meshes"][0]["name"], "beta");
    assert!(h.dir.join("state.prev.json").exists());
    // выданный токен пережил восстановление
    assert_eq!(h.call("POST", "/api/verify", Some(json!({"token": e["token"]}))).await.1["valid"], true);
}
