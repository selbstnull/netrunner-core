//! Применение `AccessPolicy` к новому потоку: резолв имён и вердикт.
//!
//! Сама логика (чистая, без сети) — в `net::access_policy`. Здесь только то,
//! что требует сети: узнать адреса имени назначения и адреса доменов из
//! правил (клиент резолвит домен-ресурс у себя и присылает литерал IP).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use tokio::net::lookup_host;
use tokio::time::timeout;

use crate::net::access_policy::{AccessPolicy, Destination, Host, Proto, Verdict};

const RESOLVE_TIMEOUT: Duration = Duration::from_secs(3);
/// Адреса доменов из правил переиспользуем недолго: достаточно, чтобы не
/// резолвить каждый поток, и достаточно мало, чтобы смена адреса сервера
/// подхватывалась быстро.
const DOMAIN_TTL: Duration = Duration::from_secs(30);
const CACHE_CAP: usize = 512;

fn cache() -> &'static Mutex<HashMap<String, (Instant, Vec<IpAddr>)>> {
    static CACHE: OnceLock<Mutex<HashMap<String, (Instant, Vec<IpAddr>)>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

async fn resolve(name: &str) -> Vec<IpAddr> {
    match timeout(RESOLVE_TIMEOUT, lookup_host((name, 0))).await {
        Ok(Ok(addrs)) => addrs.map(|a| a.ip()).collect(),
        // Не резолвится — адресов нет, и сетевые правила на такое имя не
        // сработают (см. `AccessPolicy::decide`): отказ, а не пропуск.
        _ => Vec::new(),
    }
}

async fn domain_addresses(name: &str) -> Vec<IpAddr> {
    if let Some((at, ips)) = cache().lock().unwrap().get(name) {
        if at.elapsed() < DOMAIN_TTL {
            return ips.clone();
        }
    }
    let ips = resolve(name).await;
    let mut guard = cache().lock().unwrap();
    if guard.len() >= CACHE_CAP {
        guard.retain(|_, (at, _)| at.elapsed() < DOMAIN_TTL);
        if guard.len() >= CACHE_CAP {
            guard.clear();
        }
    }
    guard.insert(name.to_string(), (Instant::now(), ips.clone()));
    ips
}

/// Что политика говорит про поток к `target`. Непонятное назначение — отказ.
pub(crate) async fn evaluate(policy: &AccessPolicy, target: &str, proto: Proto) -> Verdict {
    if policy.is_unrestricted() {
        return Verdict::Allow { via: None };
    }
    let Some(dest) = Destination::parse(target) else {
        return Verdict::Deny;
    };
    let target_ips: Vec<IpAddr> = match &dest.host {
        Host::Ip(ip) => vec![*ip],
        Host::Name(name) if policy.needs_target_addresses() => resolve(name).await,
        Host::Name(_) => Vec::new(),
    };
    let mut domain_ips = HashMap::new();
    if matches!(dest.host, Host::Ip(_)) {
        for domain in policy.rule_domains() {
            if !domain_ips.contains_key(domain) {
                domain_ips.insert(domain.to_string(), domain_addresses(domain).await);
            }
        }
    }
    policy.decide(&dest, proto, &target_ips, &domain_ips)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::access_policy::{AccessPolicy, AccessPolicyDto, RuleDto};

    fn policy(default_deny: bool, allow: &[(&str, &str)], deny: &[(&str, &str)]) -> AccessPolicy {
        let rules = |r: &[(&str, &str)]| {
            r.iter()
                .map(|(kind, value)| RuleDto {
                    kind: (*kind).into(),
                    value: (*value).into(),
                    ports: vec![],
                    protocol: "any".into(),
                    via: None,
                })
                .collect()
        };
        AccessPolicy::from_dto(&AccessPolicyDto {
            default_deny,
            allow: rules(allow),
            deny: rules(deny),
        })
    }

    async fn allowed(p: &AccessPolicy, target: &str, proto: Proto) -> bool {
        evaluate(p, target, proto).await.is_allowed()
    }

    #[tokio::test]
    async fn literal_targets_follow_the_policy() {
        let p = policy(true, &[("cidr", "10.0.0.0/8")], &[("cidr", "10.5.0.0/24")]);
        assert!(allowed(&p, "10.1.1.1:443", Proto::Tcp).await);
        assert!(!allowed(&p, "10.5.0.9:443", Proto::Tcp).await);
        assert!(!allowed(&p, "8.8.8.8:53", Proto::Udp).await);
    }

    #[tokio::test]
    async fn garbage_target_is_refused_under_a_policy() {
        let p = policy(true, &[("cidr", "10.0.0.0/8")], &[]);
        assert!(!allowed(&p, "not a target", Proto::Tcp).await);
    }

    #[tokio::test]
    async fn localhost_name_resolves_into_loopback_rules() {
        // `localhost` резолвится без сети — проверяем и путь «имя → адреса».
        let open_policy = policy(true, &[("cidr", "127.0.0.0/8"), ("cidr", "::1/128")], &[]);
        assert!(allowed(&open_policy, "localhost:80", Proto::Tcp).await);
        let denied = policy(false, &[], &[("cidr", "127.0.0.0/8"), ("cidr", "::1/128")]);
        assert!(!allowed(&denied, "localhost:80", Proto::Tcp).await);
    }

    #[tokio::test]
    async fn unrestricted_policy_skips_everything() {
        let p = policy(false, &[], &[]);
        assert!(allowed(&p, "whatever", Proto::Tcp).await);
    }
}
