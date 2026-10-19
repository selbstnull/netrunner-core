//! «Требует внимания»: то, что оператору стоит сделать, вычисленное по состоянию панели и
//! узла. Показывается на обзоре сверху — чтобы главное не приходилось искать по разделам.

use super::node::NodeView;
use super::store::{State, DAY};
use serde::Serialize;

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Item {
    /// `crit` | `warn` | `info`.
    pub level: &'static str,
    pub code: &'static str,
    pub text: String,
    pub mesh: Option<String>,
    pub serial: Option<String>,
}

fn item(level: &'static str, code: &'static str, text: impl Into<String>, mesh: Option<&str>, serial: Option<&str>) -> Item {
    Item { level, code, text: text.into(), mesh: mesh.map(String::from), serial: serial.map(String::from) }
}

const EXPIRY_WARN: u64 = 7 * DAY;
const MAX_PER_GRANT: usize = 5;

pub fn compute(state: &State, node: &NodeView, now: u64) -> Vec<Item> {
    let mut out = vec![];
    if !node.healthy() {
        out.push(item("crit", "node-stalled", "Узел не отвечает на собственные проверки: периодическая задача не тикает", None, None));
    }
    if state.meshes.is_empty() {
        out.push(item("info", "no-meshes", "Сетей ещё нет — создайте первую, чтобы получить ключ роя и выдавать доступ", None, None));
    }
    match state.last_backup {
        None if !state.meshes.is_empty() => out.push(item("warn", "no-backup", "Резервной копии ключей ещё не снимали — потеря state.json означает потерю всех ключей", None, None)),
        Some(t) if now.saturating_sub(t) > 30 * DAY => out.push(item("info", "old-backup", "Резервная копия старше 30 суток", None, None)),
        _ => {}
    }
    let node_key = node.swarm_key_hex();
    let mut node_matched = false;
    for m in &state.meshes {
        let mid = Some(m.id.as_str());
        if let Some(k) = &node_key {
            if *k == m.swarm_key {
                node_matched = true;
            } else if m.swarm_prev.as_ref().is_some_and(|p| &p.key == k) {
                node_matched = true;
                out.push(item("warn", "node-old-key", format!("Узел работает на прежнем ключе роя сети «{}» — перезапустите его с новым PROXY_SWARM_KEY", m.name), mid, None));
            }
        }
        if let Some(p) = &m.swarm_prev {
            if p.until > now && p.until - now < DAY {
                out.push(item("info", "swarm-grace-ending", format!("«{}»: переходный период прежнего ключа роя заканчивается в течение суток", m.name), mid, None));
            }
        }
        if m.root_prev.iter().any(|r| r.until > now && r.until - now < DAY) {
            out.push(item("warn", "root-grace-ending", format!("«{}»: прежний корень доверенностей перестанет приниматься в течение суток", m.name), mid, None));
        }
        let mut stale = 0;
        let mut expiring: Vec<(&str, &str, u64)> = vec![];
        for g in &m.grants {
            let (st, _) = m.grant_state(g, now);
            let exp = g.chain[g.chain.len() - 1].cert.exp;
            match st {
                "stale" => stale += 1,
                "active" if exp.saturating_sub(now) <= EXPIRY_WARN => expiring.push((&g.serial, &g.label, exp)),
                _ => {}
            }
        }
        if stale > 0 {
            out.push(item("warn", "stale-grants", format!("«{}»: доверенностей, подписанных прежним корнем: {stale} — перевыпустите цепочки", m.name), mid, None));
        }
        expiring.sort_by_key(|e| e.2);
        for (serial, label, exp) in expiring.iter().take(MAX_PER_GRANT) {
            let days = (exp.saturating_sub(now)) / DAY;
            let when = if days == 0 { "сегодня".to_string() } else { format!("через {days} дн.") };
            out.push(item("warn", "grant-expiring", format!("«{}»: доверенность «{label}» истекает {when}", m.name), mid, Some(serial)));
        }
        if expiring.len() > MAX_PER_GRANT {
            out.push(item("warn", "grants-expiring-more", format!("«{}»: ещё {} доверенностей истекают в ближайшие 7 суток", m.name, expiring.len() - MAX_PER_GRANT), mid, None));
        }
    }
    if node_key.is_some() && !state.meshes.is_empty() && !node_matched {
        out.push(item("info", "node-key-unknown", "Ключ роя этого узла не совпадает ни с одной сетью панели — панель не управляет его доступом", None, None));
    }
    let rank = |l: &str| match l { "crit" => 0, "warn" => 1, _ => 2 };
    out.sort_by_key(|i| rank(i.level));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::store::IssueRequest;

    const NOW: u64 = 1_000_000;

    fn req(label: &str, ttl: u64) -> IssueRequest {
        IssueRequest { label: label.into(), parent: None, roles: vec!["client".into()], nodes: None, ttl_secs: ttl, delegate: 0 }
    }

    #[test]
    fn empty_state_asks_for_first_mesh() {
        let v = compute(&State::default(), &NodeView::detached(), NOW);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].code, "no-meshes");
    }

    #[test]
    fn flags_backup_expiring_and_stale() {
        let mut s = State::default();
        let id = s.create_mesh("m", NOW).unwrap();
        s.issue(&id, req("soon", 2 * DAY), NOW).unwrap();
        s.issue(&id, req("later", 60 * DAY), NOW).unwrap();
        let codes: Vec<_> = compute(&s, &NodeView::detached(), NOW).iter().map(|i| i.code).collect();
        assert!(codes.contains(&"no-backup"));
        assert_eq!(codes.iter().filter(|c| **c == "grant-expiring").count(), 1);

        s.last_backup = Some(NOW);
        s.rotate_root(&id, 3600, NOW).unwrap();
        let v = compute(&s, &NodeView::detached(), NOW);
        let codes: Vec<_> = v.iter().map(|i| i.code).collect();
        assert!(!codes.contains(&"no-backup"));
        assert!(codes.contains(&"stale-grants"));
        assert!(codes.contains(&"root-grace-ending"));
        // критичное и предупреждения идут раньше справочного
        assert!(v.windows(2).all(|w| w[0].level <= w[1].level || w[0].level == "warn"));
    }
}
