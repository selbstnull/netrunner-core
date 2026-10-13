//! JSON-API панели. Все маршруты уже прошли проверку токена в [`super::dispatch`].

use super::caps;
use super::http::{Request, Response};
use super::store::{fingerprint, Grant, IssueRequest, Mesh, State};
use super::{attention, now, Ctx};
use serde::Deserialize;
use serde_json::{json, Value};

type Res = Result<Response, (u16, String)>;

fn bad(msg: impl Into<String>) -> (u16, String) {
    (400, msg.into())
}

fn body<T: for<'de> Deserialize<'de>>(req: &Request) -> Result<T, (u16, String)> {
    let raw = if req.body.is_empty() { b"{}".as_slice() } else { &req.body };
    serde_json::from_slice(raw).map_err(|e| bad(format!("тело запроса: {e}")))
}

fn ok(v: Value) -> Res {
    Ok(Response::json(200, &v))
}

fn hex_byte(two: &[u8]) -> Option<u8> {
    u8::from_str_radix(std::str::from_utf8(two).ok()?, 16).ok()
}

/// Значение параметра запроса (с разбором `%XX` и `+`).
fn query_param(req: &Request, name: &str) -> Option<String> {
    req.query.split('&').filter_map(|kv| kv.split_once('=')).find(|(k, _)| *k == name).map(|(_, v)| {
        let b = v.as_bytes();
        let mut out = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            match b[i] {
                b'+' => out.push(b' '),
                b'%' if i + 2 < b.len() && hex_byte(&b[i + 1..i + 3]).is_some() => {
                    out.push(hex_byte(&b[i + 1..i + 3]).unwrap_or(b'?'));
                    i += 2;
                }
                c => out.push(c),
            }
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    })
}

pub async fn route(ctx: &Ctx, req: &Request) -> Response {
    let segs: Vec<&str> = req.path.trim_start_matches("/api/").split('/').filter(|s| !s.is_empty()).collect();
    let out = match (req.method.as_str(), segs.as_slice()) {
        ("GET", ["status"]) => status(ctx),
        ("GET", ["attention"]) => attention_list(ctx),
        ("GET", ["live"]) => ok(ctx.live.snapshot(&ctx.node)),
        ("GET", ["metrics"]) => ok(super::live::all_metrics(&ctx.node)),
        ("GET", ["audit"]) => ok(json!({ "entries": ctx.store.audit_tail(200) })),
        ("POST", ["admin-token", "rotate"]) => rotate_admin_token(ctx),
        ("POST", ["verify"]) => verify(ctx, req),
        ("GET", ["backup"]) => backup(ctx),
        ("POST", ["backup", "restore"]) => restore(ctx, req),

        ("GET", ["node"]) => ok(ctx.node.status(now()).await),
        ("GET", ["node", "peers"]) => ok(ctx.node.peers(now()).await),
        ("GET", ["node", "descriptor"]) => ctx.node.own_descriptor(now()).map_err(bad).and_then(ok),
        ("POST", ["node", "seed"]) => node_seed(ctx, req),
        ("POST", ["node", "directory", "gc"]) => node_gc(ctx),
        ("GET", ["node", "client-config"]) => client_config(ctx, req),
        ("POST", ["node", "log-level"]) => log_level(ctx, req),
        ("POST", ["node", "shutdown"]) => shutdown(ctx, req),

        ("GET", ["meshes"]) => meshes(ctx),
        ("POST", ["meshes"]) => create_mesh(ctx, req),
        ("GET", ["meshes", id]) => mesh_detail(ctx, id),
        ("POST", ["meshes", id, "delete"]) => delete_mesh(ctx, id, req),
        ("POST", ["meshes", id, "rename"]) => rename_mesh(ctx, id, req),
        ("GET", ["meshes", id, "swarm-key"]) => swarm_key(ctx, id),
        ("GET", ["meshes", id, "bundle"]) => bundle(ctx, id),
        ("POST", ["meshes", id, "rotate-swarm"]) => rotate_swarm(ctx, id, req),
        ("POST", ["meshes", id, "rotate-root"]) => rotate_root(ctx, id, req),
        ("POST", ["meshes", id, "reissue"]) => reissue(ctx, id),
        ("POST", ["meshes", id, "grants"]) => issue(ctx, id, req),

        ("GET", ["grants", serial, "token"]) => grant_token(ctx, serial),
        ("POST", ["grants", serial, "revoke"]) => revoke(ctx, serial, req),
        ("POST", ["grants", serial, "rotate"]) => rotate_grant(ctx, serial),
        ("POST", ["grants", serial, "extend"]) => extend_grant(ctx, serial, req),
        ("POST", ["grants", serial, "meta"]) => grant_meta(ctx, serial, req),
        _ => Err((404, "не найдено".into())),
    };
    out.unwrap_or_else(|(status, msg)| Response::error(status, &msg))
}

// ── Представления (без секретов) ───────────────────────────────────────────

fn grant_view(m: &Mesh, g: &Grant, now: u64) -> Value {
    let (state, reason) = m.grant_state(g, now);
    let c = &g.chain[g.chain.len() - 1].cert;
    json!({
        "serial": g.serial, "label": g.label, "note": g.note, "parent": g.parent, "created": g.created,
        "state": state, "reason": reason,
        "roles": c.roles, "nodes": c.nodes, "nbf": c.nbf, "exp": c.exp,
        "delegate": c.delegate, "depth": g.chain.len(), "holder": c.holder, "issuer": c.issuer,
        "chain": g.chain.iter().map(|l| l.cert.serial.clone()).collect::<Vec<_>>(),
        "root_epoch": g.root_epoch,
    })
}

/// Какой ключ роя держит этот узел относительно сети: `current`, `previous` (ещё доживает
/// переходный период) или пусто (не совпал / узел не в режиме роя).
fn node_match(ctx: &Ctx, m: &Mesh) -> &'static str {
    let Some(key) = ctx.node.swarm_key_hex() else { return "" };
    if key == m.swarm_key {
        "current"
    } else if m.swarm_prev.as_ref().is_some_and(|p| p.key == key) {
        "previous"
    } else {
        ""
    }
}

fn mesh_summary(ctx: &Ctx, m: &Mesh, now: u64) -> Result<Value, (u16, String)> {
    let mut counts = json!({"active": 0, "stale": 0, "expired": 0, "revoked": 0, "invalid": 0});
    let mut expiring = 0;
    for g in &m.grants {
        let (st, _) = m.grant_state(g, now);
        counts[st] = json!(counts[st].as_u64().unwrap_or(0) + 1);
        if st == "active" && g.chain[g.chain.len() - 1].cert.exp.saturating_sub(now) <= 7 * super::store::DAY {
            expiring += 1;
        }
    }
    let root = m.root_pub().map_err(bad)?;
    Ok(json!({
        "id": m.id, "name": m.name, "note": m.note, "created": m.created,
        "swarm_epoch": m.swarm_epoch, "swarm_fp": fingerprint(&m.swarm_key),
        "swarm_prev_until": m.swarm_prev.as_ref().map(|p| p.until),
        "root_epoch": m.root_epoch, "root_fp": fingerprint(&root), "root_public": root,
        "root_prev": m.root_prev.iter().filter(|r| r.until > now).map(|r| json!({"epoch": r.epoch, "until": r.until})).collect::<Vec<_>>(),
        "revoked_total": m.revoked.len(),
        "counts": counts, "expiring": expiring,
        "on_this_node": node_match(ctx, m),
    }))
}

// ── Панель целиком ─────────────────────────────────────────────────────────

fn status(ctx: &Ctx) -> Res {
    let backup = ctx.store.read(|s| s.last_backup);
    ok(json!({
        "version": env!("CARGO_PKG_VERSION"), "now": now(), "started": ctx.started,
        "port": ctx.port, "data_dir": ctx.store.dir().display().to_string(),
        "mode": ctx.node.mode, "roles": caps::ROLES, "max_chain": caps::MAX_CHAIN,
        "last_backup": backup,
    }))
}

fn attention_list(ctx: &Ctx) -> Res {
    let items = ctx.store.read(|s| attention::compute(s, &ctx.node, now()));
    ok(json!({ "items": items }))
}

fn rotate_admin_token(ctx: &Ctx) -> Res {
    let t = ctx.rotate_token().map_err(|e| (500, e))?;
    ctx.store.audit(now(), "admin-token.rotate", "", "");
    ok(json!({ "token": t }))
}

/// Полная резервная копия состояния (с секретными ключами!) — отдаётся только по запросу
/// и всегда попадает в журнал.
fn backup(ctx: &Ctx) -> Res {
    let t = now();
    let state = ctx.store.mutate(|s| {
        s.last_backup = Some(t);
        Ok(s.clone())
    }).map_err(bad)?;
    ctx.store.audit(t, "backup.export", "", &format!("meshes={}", state.meshes.len()));
    ok(json!({ "format": "nrxp-admin-backup/1", "exported": t, "state": state }))
}

#[derive(Deserialize)]
struct Restore {
    backup: Value,
    confirm: String,
}

fn restore(ctx: &Ctx, req: &Request) -> Res {
    let b: Restore = body(req)?;
    if b.confirm != "RESTORE" {
        return Err(bad("для восстановления введите RESTORE"));
    }
    if b.backup.get("format").and_then(Value::as_str) != Some("nrxp-admin-backup/1") {
        return Err(bad("это не резервная копия панели (format)"));
    }
    let state: State = serde_json::from_value(b.backup.get("state").cloned().unwrap_or(Value::Null))
        .map_err(|e| bad(format!("состояние в копии: {e}")))?;
    state.validate().map_err(bad)?;
    // Прежнее состояние остаётся рядом — откат ручной, но возможный.
    let dir = ctx.store.dir();
    let _ = std::fs::copy(dir.join("state.json"), dir.join("state.prev.json"));
    let n = state.meshes.len();
    ctx.store.mutate(|s| {
        *s = state;
        Ok(())
    }).map_err(bad)?;
    ctx.store.audit(now(), "backup.restore", "", &format!("meshes={n}"));
    ok(json!({ "meshes": n }))
}

// ── Узел ───────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct Seed {
    descriptor: String,
}

fn node_seed(ctx: &Ctx, req: &Request) -> Res {
    let b: Seed = body(req)?;
    let r = ctx.node.add_seed(&b.descriptor, now()).map_err(bad)?;
    ctx.store.audit(now(), "node.seed.add", "", r["result"].as_str().unwrap_or(""));
    ok(r)
}

fn node_gc(ctx: &Ctx) -> Res {
    let n = ctx.node.gc(now()).map_err(bad)?;
    ctx.store.audit(now(), "node.directory.gc", "", &format!("removed={n}"));
    ok(json!({ "removed": n }))
}

/// Клиентский конфиг содержит входной секрет узла — каждая выдача в журнале.
fn client_config(ctx: &Ctx, req: &Request) -> Res {
    let toml = ctx
        .node
        .client_config(query_param(req, "remote").as_deref(), query_param(req, "sni").as_deref())
        .map_err(bad)?;
    ctx.store.audit(now(), "node.client-config.view", "", "");
    ok(json!({ "toml": toml }))
}

#[derive(Deserialize)]
struct Level {
    level: String,
}

fn log_level(ctx: &Ctx, req: &Request) -> Res {
    let b: Level = body(req)?;
    ctx.node.set_log_level(&b.level).map_err(bad)?;
    ctx.store.audit(now(), "node.log-level", "", &b.level);
    ok(json!({ "level": b.level }))
}

/// Останавливает узел штатно (с дрейном). Поднять его снова должен supervisor.
fn shutdown(ctx: &Ctx, req: &Request) -> Res {
    let b: Confirm = body(req)?;
    if b.confirm != "STOP" {
        return Err(bad("для остановки введите STOP"));
    }
    ctx.store.audit(now(), "node.shutdown", "", "");
    let token = ctx.node.shutdown.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        token.cancel();
    });
    ok(json!({}))
}

// ── Сети ───────────────────────────────────────────────────────────────────

fn meshes(ctx: &Ctx) -> Res {
    let t = now();
    let list = ctx.store.read(|s| s.meshes.iter().map(|m| mesh_summary(ctx, m, t)).collect::<Result<Vec<_>, _>>())?;
    ok(json!({ "meshes": list }))
}

fn mesh_detail(ctx: &Ctx, id: &str) -> Res {
    let t = now();
    ctx.store.read(|s| {
        let m = s.mesh(id).map_err(|e| (404, e))?;
        let grants: Vec<Value> = m.grants.iter().map(|g| grant_view(m, g, t)).collect();
        let mut v = mesh_summary(ctx, m, t)?;
        v["grants"] = json!(grants);
        v["revoked"] = json!(m.revoked.iter().rev().map(|r| json!({"serial": r.serial, "label": r.label, "at": r.at, "reason": r.reason})).collect::<Vec<_>>());
        ok(v)
    })
}

#[derive(Deserialize)]
struct CreateMesh {
    name: String,
    /// Подхватить ключ роя, с которым работает этот узел.
    #[serde(default)]
    from_node: bool,
    /// Либо вставить существующий ключ роя (hex).
    swarm_key: Option<String>,
}

fn create_mesh(ctx: &Ctx, req: &Request) -> Res {
    let b: CreateMesh = body(req)?;
    let t = now();
    let key = if b.from_node {
        Some(ctx.node.swarm_key_hex().ok_or_else(|| bad("узел работает не в режиме роя — у него нет ключа роя"))?)
    } else {
        b.swarm_key.clone().filter(|k| !k.trim().is_empty())
    };
    let how = if b.from_node { "ключ узла" } else if key.is_some() { "свой ключ" } else { "новый ключ" };
    let id = ctx.store.mutate(|s| s.create_mesh_with_key(&b.name, key.as_deref(), t)).map_err(bad)?;
    ctx.store.audit(t, "mesh.create", &id, &format!("{} ({how})", b.name.trim()));
    ok(json!({ "id": id }))
}

#[derive(Deserialize)]
struct Confirm {
    confirm: String,
}

fn delete_mesh(ctx: &Ctx, id: &str, req: &Request) -> Res {
    let b: Confirm = body(req)?;
    ctx.store.mutate(|s| s.delete_mesh(id, &b.confirm)).map_err(bad)?;
    ctx.store.audit(now(), "mesh.delete", id, "");
    ok(json!({}))
}

#[derive(Deserialize)]
struct Rename {
    name: String,
    #[serde(default)]
    note: String,
}

fn rename_mesh(ctx: &Ctx, id: &str, req: &Request) -> Res {
    let b: Rename = body(req)?;
    ctx.store.mutate(|s| s.rename_mesh(id, &b.name, &b.note)).map_err(bad)?;
    ctx.store.audit(now(), "mesh.rename", id, b.name.trim());
    mesh_detail(ctx, id)
}

/// Ключ роя отдаётся отдельным запросом — в списках и деталях его нет.
fn swarm_key(ctx: &Ctx, id: &str) -> Res {
    ctx.store.read(|s| {
        let m = s.mesh(id).map_err(|e| (404, e))?;
        ctx.store.audit(now(), "mesh.swarm-key.view", id, "");
        ok(json!({
            "swarm_key": m.swarm_key, "epoch": m.swarm_epoch,
            "previous": m.swarm_prev.as_ref().map(|p| json!({"key": p.key, "until": p.until})),
        }))
    })
}

/// Публичные данные для узлов: доверенные корни и отозванные серийные номера.
fn bundle(ctx: &Ctx, id: &str) -> Res {
    let t = now();
    ctx.store.read(|s| {
        let m = s.mesh(id).map_err(|e| (404, e))?;
        ok(json!({
            "format": "nrxp-cap-bundle/1", "mesh": m.id, "name": m.name, "generated": t,
            "roots": m.accepted_roots(t).map_err(bad)?,
            "root_epoch": m.root_epoch,
            "revoked": m.revoked.iter().map(|r| &r.serial).collect::<Vec<_>>(),
        }))
    })
}

#[derive(Deserialize)]
struct Grace {
    #[serde(default)]
    grace_hours: u64,
}

fn grace_secs(req: &Request) -> Result<u64, (u16, String)> {
    let g: Grace = body(req)?;
    if g.grace_hours > 24 * 90 {
        return Err(bad("переходный период не больше 90 суток"));
    }
    Ok(g.grace_hours * 3600)
}

fn rotate_swarm(ctx: &Ctx, id: &str, req: &Request) -> Res {
    let grace = grace_secs(req)?;
    let t = now();
    ctx.store.mutate(|s| s.rotate_swarm(id, grace, t)).map_err(bad)?;
    ctx.store.audit(t, "mesh.rotate-swarm", id, &format!("grace={grace}s"));
    mesh_detail(ctx, id)
}

fn rotate_root(ctx: &Ctx, id: &str, req: &Request) -> Res {
    let grace = grace_secs(req)?;
    let t = now();
    ctx.store.mutate(|s| s.rotate_root(id, grace, t)).map_err(bad)?;
    ctx.store.audit(t, "mesh.rotate-root", id, &format!("grace={grace}s"));
    mesh_detail(ctx, id)
}

fn reissue(ctx: &Ctx, id: &str) -> Res {
    let n = ctx.store.mutate(|s| s.reissue(id)).map_err(bad)?;
    ctx.store.audit(now(), "mesh.reissue", id, &format!("grants={n}"));
    mesh_detail(ctx, id)
}

// ── Доверенности ───────────────────────────────────────────────────────────

fn token_of(s: &State, serial: &str) -> Result<String, (u16, String)> {
    let g = s
        .meshes
        .iter()
        .flat_map(|m| m.grants.iter())
        .find(|g| g.serial == serial)
        .ok_or((404, "доверенность не найдена".to_string()))?;
    let seed: [u8; 32] = hex::decode(&g.holder_seed)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or((500, "повреждён ключ в хранилище".to_string()))?;
    Ok(caps::encode_token(&seed, &g.chain))
}

#[derive(Deserialize)]
struct IssueBody {
    label: String,
    #[serde(default)]
    note: String,
    parent: Option<String>,
    roles: Vec<String>,
    nodes: Option<Vec<String>>,
    ttl_hours: u64,
    #[serde(default)]
    delegate: u8,
}

fn issue(ctx: &Ctx, mesh_id: &str, req: &Request) -> Res {
    let b: IssueBody = body(req)?;
    let t = now();
    let parent = b.parent.clone().filter(|p| !p.is_empty());
    let r = IssueRequest {
        label: b.label.clone(),
        parent: parent.clone(),
        roles: b.roles,
        nodes: b.nodes.filter(|n| !n.is_empty()),
        ttl_secs: b.ttl_hours.saturating_mul(3600),
        delegate: b.delegate,
    };
    let note = b.note.clone();
    let serial = ctx
        .store
        .mutate(|s| {
            let serial = s.issue(mesh_id, r, t)?;
            if !note.trim().is_empty() {
                s.set_grant_meta(&serial, &b.label, &note)?;
            }
            Ok(serial)
        })
        .map_err(bad)?;
    ctx.store.audit(t, "grant.issue", &serial, &format!("mesh={mesh_id} label={} parent={}", b.label.trim(), parent.as_deref().unwrap_or("-")));
    let token = ctx.store.read(|s| token_of(s, &serial))?;
    ok(json!({ "serial": serial, "token": token }))
}

fn grant_token(ctx: &Ctx, serial: &str) -> Res {
    let token = ctx.store.read(|s| token_of(s, serial))?;
    ctx.store.audit(now(), "grant.token.view", serial, "");
    ok(json!({ "token": token }))
}

#[derive(Deserialize)]
struct Reason {
    #[serde(default)]
    reason: String,
}

fn revoke(ctx: &Ctx, serial: &str, req: &Request) -> Res {
    let b: Reason = body(req)?;
    let t = now();
    ctx.store.mutate(|s| s.revoke(serial, &b.reason, t)).map_err(bad)?;
    ctx.store.audit(t, "grant.revoke", serial, b.reason.trim());
    ok(json!({}))
}

fn rotate_grant(ctx: &Ctx, serial: &str) -> Res {
    let t = now();
    let (new_serial, kids) = ctx.store.mutate(|s| s.rotate_grant(serial, t)).map_err(bad)?;
    ctx.store.audit(t, "grant.rotate", serial, &format!("new={new_serial} children={kids}"));
    let token = ctx.store.read(|s| token_of(s, &new_serial))?;
    ok(json!({ "serial": new_serial, "token": token, "children_to_redistribute": kids }))
}

#[derive(Deserialize)]
struct Extend {
    ttl_hours: u64,
}

fn extend_grant(ctx: &Ctx, serial: &str, req: &Request) -> Res {
    let b: Extend = body(req)?;
    let t = now();
    let exp = ctx.store.mutate(|s| s.extend(serial, b.ttl_hours.saturating_mul(3600), t)).map_err(bad)?;
    ctx.store.audit(t, "grant.extend", serial, &format!("exp={exp}"));
    let token = ctx.store.read(|s| token_of(s, serial))?;
    ok(json!({ "exp": exp, "token": token }))
}

#[derive(Deserialize)]
struct Meta {
    label: String,
    #[serde(default)]
    note: String,
}

fn grant_meta(ctx: &Ctx, serial: &str, req: &Request) -> Res {
    let b: Meta = body(req)?;
    ctx.store.mutate(|s| s.set_grant_meta(serial, &b.label, &b.note)).map_err(bad)?;
    ctx.store.audit(now(), "grant.meta", serial, b.label.trim());
    ok(json!({}))
}

// ── Проверка токена ────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct VerifyBody {
    token: String,
}

/// Проверяет вставленный токен по всем известным сетям — так же, как это делал бы узел.
fn verify(ctx: &Ctx, req: &Request) -> Res {
    let b: VerifyBody = body(req)?;
    let (seed, chain) = match caps::decode_token(&b.token) {
        Ok(x) => x,
        Err(e) => return ok(json!({ "valid": false, "reason": e })),
    };
    let t = now();
    let mesh_id = chain.first().map(|l| l.cert.mesh.clone()).unwrap_or_default();
    ctx.store.read(|s| {
        let Ok(m) = s.mesh(&mesh_id) else {
            return ok(json!({ "valid": false, "reason": "сеть этого токена панели не известна" }));
        };
        let roots = m.accepted_roots(t).map_err(bad)?;
        let mut out = match caps::verify_chain(&chain, &m.id, &roots, &|x| m.is_revoked(x), t) {
            Ok(v) if caps::pub_hex(&seed) != v.effective.holder => {
                json!({ "valid": false, "reason": "ключ держателя в токене не соответствует последнему звену" })
            }
            Ok(v) => json!({ "valid": true, "effective": v.effective, "depth": v.depth, "serials": v.serials }),
            Err(e) => json!({ "valid": false, "reason": e }),
        };
        out["mesh"] = json!({ "id": m.id, "name": m.name });
        ok(out)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req_with(query: &str) -> Request {
        // Request строится только парсером; для проверки query достаточно разбора строки.
        let raw = format!("GET /x?{query} HTTP/1.1\r\n\r\n");
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        rt.block_on(async { super::super::http::read_request(&mut raw.as_bytes()).await.unwrap() })
    }

    #[test]
    fn query_params_are_percent_decoded() {
        let r = req_with("remote=203.0.113.5%3A443&sni=a+b&bad=%zz");
        assert_eq!(query_param(&r, "remote").as_deref(), Some("203.0.113.5:443"));
        assert_eq!(query_param(&r, "sni").as_deref(), Some("a b"));
        assert_eq!(query_param(&r, "bad").as_deref(), Some("%zz"));
        assert_eq!(query_param(&r, "nope"), None);
    }
}
