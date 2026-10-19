//! Политика доступа пользователя к назначениям (ZTNA на стороне ноды).
//!
//! Бэкенд отдаёт её в ответе на проверку токена, только для сотрудников
//! организации. Раньше «доступ к ресурсу, а не к сети» обеспечивал один лишь
//! клиент (он заворачивал в туннель только объявленные подсети), то есть
//! держался на честности приложения. Здесь та же политика применяется на
//! ноде, к каждому новому потоку: клиент, который обошёл свою таблицу
//! маршрутов, всё равно получит отказ.
//!
//! Этот модуль — ЧИСТАЯ логика без сети (собирается и под wasm, потому что
//! `UserQuota` из `auth` живёт на всех таргетах). Резолв имён делает
//! вызывающая сторона (`connection::handler`) и передаёт готовые адреса.
//!
//! Правила вычисления:
//!
//! 1. Совпало хоть одно `deny` → отказ (запрет всегда сильнее разрешения).
//! 2. Иначе совпало хоть одно `allow` → разрешено.
//! 3. Иначе решает `default_deny` (режим туннеля `resources` — отказ; `all` и
//!    `bypass_lan` — разрешено).
//!
//! Имя назначения и его адреса проверяются строго:
//! - для `allow` по подсети нужно, чтобы В подсеть входили ВСЕ адреса, в
//!   которые имя резолвится (иначе имя с одним разрешённым и одним чужим
//!   адресом пропускало бы к чужому);
//! - для `deny` достаточно ОДНОГО попавшего адреса.
//!
//! Известное ограничение: нода резолвит имя для проверки, а затем ещё раз при
//! подключении, поэтому злонамеренный владелец DNS-зоны теоретически может
//! подменить ответ между двумя резолвами. Модель угроз здесь — сотрудник,
//! обходящий политику своей организации, а не атакующий с контролем над DNS
//! разрешённых имён; полная защита потребовала бы подключаться ровно к
//! проверенному адресу (`dial::connect_tcp` пока резолвит сам).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use serde::Deserialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

/// Формат правила в ответе бэкенда (`/internal/validate`, поле `access_policy`).
#[derive(Debug, Clone, Deserialize)]
pub struct RuleDto {
    /// `cidr` | `host` | `domain`
    pub kind: String,
    pub value: String,
    #[serde(default)]
    pub ports: Vec<u16>,
    /// `any` | `tcp` | `udp`
    #[serde(default)]
    pub protocol: String,
    /// Метка коннектора (`ReverseEgressRegistry`), через который идёт доступ
    /// к ресурсу: сервис стоит во внутренней сети клиента и с ноды
    /// недостижим, поэтому поток отдаётся коннектору, а тот соединяется
    /// изнутри. `None` — нода выходит сама.
    #[serde(default)]
    pub via: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AccessPolicyDto {
    pub default_deny: bool,
    #[serde(default)]
    pub allow: Vec<RuleDto>,
    #[serde(default)]
    pub deny: Vec<RuleDto>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    fn parse(value: &str) -> Option<Self> {
        let (addr, prefix) = match value.split_once('/') {
            Some((a, p)) => (a.parse::<IpAddr>().ok()?, p.parse::<u8>().ok()?),
            None => {
                let a = value.parse::<IpAddr>().ok()?;
                (a, if a.is_ipv4() { 32 } else { 128 })
            }
        };
        let max = if addr.is_ipv4() { 32 } else { 128 };
        (prefix <= max).then_some(Self { addr, prefix })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        // IPv4-mapped IPv6 (`::ffff:a.b.c.d`) считаем тем, чем он является,
        // иначе подсеть v4 не поймала бы тот же адрес в v6-записи.
        let ip = ip.to_canonical();
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(self.prefix))
                };
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - u32::from(self.prefix))
                };
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Matcher {
    Net(Cidr),
    /// Имя и все его поддомены.
    Domain(String),
}

#[derive(Debug, Clone)]
struct Rule {
    matcher: Matcher,
    ports: Vec<u16>,
    proto: Option<Proto>,
    via: Option<String>,
}

impl Rule {
    fn from_dto(dto: &RuleDto) -> Option<Self> {
        let matcher = match dto.kind.as_str() {
            "cidr" | "host" => Matcher::Net(Cidr::parse(dto.value.trim())?),
            "domain" => {
                let d = dto.value.trim().trim_end_matches('.').to_ascii_lowercase();
                if d.is_empty() {
                    return None;
                }
                Matcher::Domain(d)
            }
            _ => return None,
        };
        let proto = match dto.protocol.as_str() {
            "tcp" => Some(Proto::Tcp),
            "udp" => Some(Proto::Udp),
            _ => None,
        };
        // Метка кладётся в токен `egress:<метка>:<токен>` и ищется в реестре
        // по равенству; двоеточие или пустая строка — заведомо нерабочая.
        let via = match dto.via.as_deref() {
            None => None,
            Some(label) if !label.is_empty() && !label.contains(':') => Some(label.to_string()),
            Some(_) => return None,
        };
        Some(Self {
            matcher,
            ports: dto.ports.clone(),
            proto,
            via,
        })
    }

    fn port_proto_ok(&self, port: u16, proto: Proto) -> bool {
        (self.ports.is_empty() || self.ports.contains(&port))
            && self.proto.is_none_or(|p| p == proto)
    }
}

/// Куда идёт поток: литерал адреса или имя.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host {
    Ip(IpAddr),
    Name(String),
}

/// Разобранное назначение `host:port` / `[v6]:port`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    pub host: Host,
    pub port: u16,
}

impl Destination {
    pub fn parse(target: &str) -> Option<Self> {
        let (host, port) = if let Some(rest) = target.strip_prefix('[') {
            let (h, p) = rest.split_once("]:")?;
            (h, p)
        } else {
            target.rsplit_once(':')?
        };
        let port = port.parse::<u16>().ok()?;
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() {
            return None;
        }
        let host = match host.parse::<IpAddr>() {
            Ok(ip) => Host::Ip(ip),
            Err(_) => Host::Name(host),
        };
        Some(Self { host, port })
    }
}

/// Итог проверки назначения.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Deny,
    /// Разрешено. `via` — метка коннектора, через который открыть поток;
    /// `None` — выходить с самой ноды.
    Allow { via: Option<String> },
}

impl Verdict {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Verdict::Allow { .. })
    }
}

#[derive(Debug, Clone)]
pub struct AccessPolicy {
    default_deny: bool,
    allow: Vec<Rule>,
    deny: Vec<Rule>,
    /// Правило пришло, но не разобралось. Невалидное `deny` нельзя молча
    /// выбросить (запрет превратился бы в разрешение), поэтому при любой такой
    /// ошибке политика закрыта целиком.
    broken: bool,
}

impl AccessPolicy {
    pub fn from_dto(dto: &AccessPolicyDto) -> Self {
        let mut broken = false;
        let compile = |rules: &[RuleDto], broken: &mut bool| -> Vec<Rule> {
            rules
                .iter()
                .filter_map(|r| {
                    let rule = Rule::from_dto(r);
                    if rule.is_none() {
                        *broken = true;
                    }
                    rule
                })
                .collect()
        };
        let allow = compile(&dto.allow, &mut broken);
        let deny = compile(&dto.deny, &mut broken);
        Self {
            default_deny: dto.default_deny,
            allow,
            deny,
            broken,
        }
    }

    /// Можно ли вообще обойтись без резолва имён: ни одного правила не надо
    /// сверять с адресами, и решение не зависит от них.
    pub fn is_unrestricted(&self) -> bool {
        !self.broken && !self.default_deny && self.deny.is_empty()
    }

    /// Имена из доменных правил — их адреса нужны, чтобы узнать назначение,
    /// пришедшее литералом IP (клиент резолвит домен-ресурс у себя и шлёт
    /// уже адрес).
    pub fn rule_domains(&self) -> Vec<&str> {
        self.allow
            .iter()
            .chain(self.deny.iter())
            .filter_map(|r| match &r.matcher {
                Matcher::Domain(d) => Some(d.as_str()),
                Matcher::Net(_) => None,
            })
            .collect()
    }

    /// Нужны ли для решения адреса, в которые резолвится ИМЯ назначения.
    pub fn needs_target_addresses(&self) -> bool {
        self.allow
            .iter()
            .chain(self.deny.iter())
            .any(|r| matches!(r.matcher, Matcher::Net(_)))
            || self.default_deny
    }

    /// `target_ips` — адреса, в которые резолвится имя назначения (для
    /// литерала IP — он сам). `domain_ips` — адреса доменов из правил.
    pub fn decide(
        &self,
        dest: &Destination,
        proto: Proto,
        target_ips: &[IpAddr],
        domain_ips: &HashMap<String, Vec<IpAddr>>,
    ) -> Verdict {
        if self.broken {
            return Verdict::Deny;
        }
        let hit = |rule: &Rule, strict_all: bool| -> bool {
            if !rule.port_proto_ok(dest.port, proto) {
                return false;
            }
            match &rule.matcher {
                Matcher::Domain(d) => match &dest.host {
                    Host::Name(name) => name == d || name.ends_with(&format!(".{d}")),
                    // Литерал адреса попадает в доменное правило, если он —
                    // один из адресов этого домена.
                    Host::Ip(ip) => domain_ips
                        .get(d)
                        .is_some_and(|ips| ips.iter().any(|a| a.to_canonical() == ip.to_canonical())),
                },
                Matcher::Net(net) => {
                    if target_ips.is_empty() {
                        return false;
                    }
                    if strict_all {
                        target_ips.iter().all(|ip| net.contains(*ip))
                    } else {
                        target_ips.iter().any(|ip| net.contains(*ip))
                    }
                }
            }
        };

        if self.deny.iter().any(|r| hit(r, false)) {
            return Verdict::Deny;
        }
        // Первое совпавшее разрешение определяет и маршрут: если один адрес
        // выдан двумя ресурсами, один из которых «через коннектор», порядок
        // правил (по имени ресурса) решает, а не случайность.
        if let Some(rule) = self.allow.iter().find(|r| hit(r, true)) {
            return Verdict::Allow {
                via: rule.via.clone(),
            };
        }
        if self.default_deny {
            Verdict::Deny
        } else {
            Verdict::Allow { via: None }
        }
    }
}

/// Для отладки/метрик: приватные ли это адреса. Нужна вызывающему, когда
/// режим `bypass_lan` должен отличать LAN от внешнего мира.
pub fn is_lan(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4 == Ipv4Addr::BROADCAST
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            v6.is_loopback() || (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(kind: &str, value: &str, ports: &[u16], protocol: &str) -> RuleDto {
        RuleDto {
            kind: kind.into(),
            value: value.into(),
            ports: ports.to_vec(),
            protocol: protocol.into(),
            via: None,
        }
    }

    fn policy(default_deny: bool, allow: Vec<RuleDto>, deny: Vec<RuleDto>) -> AccessPolicy {
        AccessPolicy::from_dto(&AccessPolicyDto {
            default_deny,
            allow,
            deny,
        })
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn check(p: &AccessPolicy, target: &str, proto: Proto, ips: &[&str]) -> bool {
        let dest = Destination::parse(target).unwrap();
        let ips: Vec<IpAddr> = match &dest.host {
            Host::Ip(i) => vec![*i],
            Host::Name(_) => ips.iter().map(|s| ip(s)).collect(),
        };
        p.decide(&dest, proto, &ips, &HashMap::new()).is_allowed()
    }

    #[test]
    fn parses_destinations() {
        assert_eq!(
            Destination::parse("Git.Corp.Local.:443").unwrap(),
            Destination {
                host: Host::Name("git.corp.local".into()),
                port: 443
            }
        );
        assert_eq!(
            Destination::parse("[2001:db8::1]:22").unwrap().host,
            Host::Ip(ip("2001:db8::1"))
        );
        assert!(Destination::parse("nohostport").is_none());
        assert!(Destination::parse(":80").is_none());
        assert!(Destination::parse("host:99999").is_none());
    }

    #[test]
    fn resources_mode_denies_everything_not_granted() {
        let p = policy(true, vec![rule("cidr", "10.1.0.0/16", &[], "any")], vec![]);
        assert!(check(&p, "10.1.2.3:5432", Proto::Tcp, &[]));
        assert!(!check(&p, "10.2.0.1:5432", Proto::Tcp, &[]));
        assert!(!check(&p, "8.8.8.8:53", Proto::Udp, &[]));
    }

    #[test]
    fn deny_carves_a_hole_out_of_a_wide_allow() {
        // «Выдать широкую подсеть и вырезать боевой контур» — ровно то, что
        // обещает README организаций и чего не умеет разрешение на клиенте.
        let p = policy(
            true,
            vec![rule("cidr", "10.0.0.0/8", &[], "any")],
            vec![rule("cidr", "10.5.0.0/24", &[], "any")],
        );
        assert!(check(&p, "10.1.1.1:80", Proto::Tcp, &[]));
        assert!(!check(&p, "10.5.0.7:80", Proto::Tcp, &[]));
    }

    #[test]
    fn ports_and_protocol_are_enforced() {
        let p = policy(true, vec![rule("host", "10.0.0.5", &[1540], "tcp")], vec![]);
        assert!(check(&p, "10.0.0.5:1540", Proto::Tcp, &[]));
        assert!(!check(&p, "10.0.0.5:22", Proto::Tcp, &[]));
        assert!(!check(&p, "10.0.0.5:1540", Proto::Udp, &[]));
    }

    #[test]
    fn domain_rule_covers_subdomains_but_not_lookalikes() {
        let p = policy(true, vec![rule("domain", "corp.local", &[], "any")], vec![]);
        assert!(check(&p, "git.corp.local:443", Proto::Tcp, &[]));
        assert!(check(&p, "corp.local:443", Proto::Tcp, &[]));
        assert!(!check(&p, "evilcorp.local:443", Proto::Tcp, &[]));
        assert!(!check(&p, "corp.local.evil.com:443", Proto::Tcp, &[]));
    }

    #[test]
    fn ip_literal_of_an_allowed_domain_is_allowed() {
        // Клиент резолвит домен-ресурс у себя и присылает адрес.
        let p = policy(true, vec![rule("domain", "git.corp.local", &[], "any")], vec![]);
        let mut domains = HashMap::new();
        domains.insert("git.corp.local".to_string(), vec![ip("10.9.9.9")]);
        let dest = Destination::parse("10.9.9.9:443").unwrap();
        assert!(p.decide(&dest, Proto::Tcp, &[ip("10.9.9.9")], &domains).is_allowed());
        let other = Destination::parse("10.9.9.8:443").unwrap();
        assert!(!p.decide(&other, Proto::Tcp, &[ip("10.9.9.8")], &domains).is_allowed());
    }

    #[test]
    fn name_resolving_partly_outside_allowed_net_is_refused() {
        let p = policy(true, vec![rule("cidr", "10.0.0.0/8", &[], "any")], vec![]);
        // Один адрес внутри, другой снаружи: пропускать нельзя.
        assert!(!check(&p, "mixed.example:80", Proto::Tcp, &["10.0.0.1", "8.8.8.8"]));
        assert!(check(&p, "inner.example:80", Proto::Tcp, &["10.0.0.1", "10.0.0.2"]));
    }

    #[test]
    fn name_with_any_denied_address_is_refused() {
        let p = policy(false, vec![], vec![rule("cidr", "10.5.0.0/24", &[], "any")]);
        assert!(!check(&p, "x.example:80", Proto::Tcp, &["1.2.3.4", "10.5.0.9"]));
        assert!(check(&p, "y.example:80", Proto::Tcp, &["1.2.3.4"]));
    }

    #[test]
    fn name_that_does_not_resolve_cannot_match_network_rules() {
        let p = policy(true, vec![rule("cidr", "0.0.0.0/0", &[], "any")], vec![]);
        assert!(!check(&p, "nxdomain.example:80", Proto::Tcp, &[]));
    }

    #[test]
    fn default_allow_without_denies_is_unrestricted() {
        let p = policy(false, vec![], vec![]);
        assert!(p.is_unrestricted());
        assert!(check(&p, "anything.example:443", Proto::Tcp, &[]));
        assert!(!policy(true, vec![], vec![]).is_unrestricted());
    }

    #[test]
    fn broken_rule_closes_the_whole_policy() {
        // Нераспознанное запрещающее правило нельзя пропустить: запрет стал
        // бы разрешением.
        let p = policy(false, vec![], vec![rule("cidr", "not-a-cidr", &[], "any")]);
        assert!(!check(&p, "8.8.8.8:53", Proto::Udp, &[]));
        let q = policy(false, vec![], vec![rule("weird", "x", &[], "any")]);
        assert!(!check(&q, "8.8.8.8:53", Proto::Udp, &[]));
    }

    #[test]
    fn ipv4_mapped_v6_matches_v4_subnet() {
        let p = policy(true, vec![rule("cidr", "10.0.0.0/8", &[], "any")], vec![]);
        assert!(check(&p, "[::ffff:10.1.1.1]:80", Proto::Tcp, &[]));
        assert!(!check(&p, "[::ffff:8.8.8.8]:80", Proto::Tcp, &[]));
    }

    #[test]
    fn zero_prefix_matches_everything_of_that_family() {
        let p = policy(true, vec![rule("cidr", "0.0.0.0/0", &[], "any")], vec![]);
        assert!(check(&p, "93.184.216.34:443", Proto::Tcp, &[]));
        assert!(!check(&p, "[2001:db8::1]:443", Proto::Tcp, &[]));
    }

    #[test]
    fn allowed_resource_can_be_routed_through_a_connector() {
        let mut git = rule("domain", "git.corp.local", &[], "tcp");
        git.via = Some("c1".into());
        let p = policy(true, vec![git, rule("cidr", "10.0.0.0/8", &[], "any")], vec![]);
        let dest = Destination::parse("git.corp.local:22").unwrap();
        assert_eq!(
            p.decide(&dest, Proto::Tcp, &[], &HashMap::new()),
            Verdict::Allow { via: Some("c1".into()) }
        );
        // Прочее выданное выходит с самой ноды.
        let other = Destination::parse("10.1.1.1:22").unwrap();
        assert_eq!(
            p.decide(&other, Proto::Tcp, &[ip("10.1.1.1")], &HashMap::new()),
            Verdict::Allow { via: None }
        );
    }

    #[test]
    fn deny_beats_a_connector_route() {
        let mut wide = rule("cidr", "10.0.0.0/8", &[], "any");
        wide.via = Some("c1".into());
        let p = policy(true, vec![wide], vec![rule("cidr", "10.5.0.0/24", &[], "any")]);
        let dest = Destination::parse("10.5.0.1:22").unwrap();
        assert_eq!(
            p.decide(&dest, Proto::Tcp, &[ip("10.5.0.1")], &HashMap::new()),
            Verdict::Deny
        );
    }

    #[test]
    fn malformed_connector_label_closes_the_policy() {
        for bad in ["", "a:b"] {
            let mut r = rule("cidr", "10.0.0.0/8", &[], "any");
            r.via = Some(bad.into());
            let p = policy(false, vec![r], vec![]);
            assert!(!check(&p, "8.8.8.8:53", Proto::Udp, &[]), "{bad:?}");
        }
    }
}
