//! Приглашение к подключению: одна строка `nrxp://…`, из которой клиент получает всё,
//! что нужно для подключения к узлу.
//!
//! ```text
//! nrxp://203.0.113.7:443?pk=<64 hex>&secret=<64 hex>&token=<токен>&sni=www.debian.org&name=%D0%BC%D0%BE%D0%B9+%D1%82%D0%B5%D0%BB%D0%B5%D1%84%D0%BE%D0%BD
//! ```
//!
//! | Параметр | Смысл | Обязателен |
//! |---|---|:-:|
//! | адрес (до `?`) | `host:port` узла (IPv4, `[IPv6]` или имя) | да |
//! | `pk` | публичный статический ключ узла (X25519, 64 hex) — клиент проверяет им узел | да |
//! | `secret` | входной секрет узла (`nrxp_secret`, 64 hex) | да |
//! | `token` | Bearer-токен для узлов с `--require-auth` | нет |
//! | `sni` | домен-декой для `ClientHello` | нет |
//! | `name` | подпись для списка в приложении (UTF-8, процентное кодирование, пробел как `+`) | нет |
//!
//! **Приглашение — секрет.** В нём входной секрет узла и, возможно, токен: тот, кто его
//! увидел, может подключиться. Передавайте по закрытому каналу, не публикуйте и не
//! сохраняйте в логах. Неизвестные параметры игнорируются (формат расширяемый).

use std::fmt;

pub const SCHEME: &str = "nrxp";
const MAX_URI_LEN: usize = 8 * 1024;
const MAX_TOKEN_LEN: usize = 4096;
const MAX_NAME_CHARS: usize = 64;

/// Разобранное приглашение.
#[derive(Clone, PartialEq, Eq)]
pub struct Invite {
    /// `host:port`.
    pub addr: String,
    /// Публичный ключ узла, 64 hex (нижний регистр).
    pub public_key: String,
    /// Входной секрет узла, 64 hex (нижний регистр).
    pub secret: String,
    pub token: Option<String>,
    pub sni: Option<String>,
    pub name: Option<String>,
}

impl fmt::Debug for Invite {
    // Секрет и токен в отладочный вывод не попадают.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Invite")
            .field("addr", &self.addr)
            .field("public_key", &self.public_key)
            .field("secret", &"[redacted]")
            .field("token", &self.token.as_ref().map(|_| "[redacted]"))
            .field("sni", &self.sni)
            .field("name", &self.name)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InviteError {
    NotAnInvite,
    TooLong,
    BadAddress(&'static str),
    Missing(&'static str),
    BadHex(&'static str),
    BadValue(&'static str),
    Duplicate(String),
    BadEncoding,
}

impl fmt::Display for InviteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAnInvite => write!(f, "not an nrxp:// invitation"),
            Self::TooLong => write!(f, "invitation is too long"),
            Self::BadAddress(w) => write!(f, "bad address: {w}"),
            Self::Missing(p) => write!(f, "missing parameter `{p}`"),
            Self::BadHex(p) => write!(f, "`{p}` must be 64 hex characters"),
            Self::BadValue(p) => write!(f, "bad value of `{p}`"),
            Self::Duplicate(p) => write!(f, "parameter `{p}` given twice"),
            Self::BadEncoding => write!(f, "bad percent-encoding"),
        }
    }
}

impl std::error::Error for InviteError {}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Проверка `host:port`: порт 1..=65535; хост — IPv4, `[IPv6]` или имя из букв, цифр, `.` и `-`.
fn validate_addr(addr: &str) -> Result<(), InviteError> {
    let (host, port) = addr.rsplit_once(':').ok_or(InviteError::BadAddress("expected host:port"))?;
    match port.parse::<u16>() {
        Ok(p) if p != 0 => {}
        _ => return Err(InviteError::BadAddress("port")),
    }
    if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return inner
            .parse::<std::net::Ipv6Addr>()
            .map(|_| ())
            .map_err(|_| InviteError::BadAddress("IPv6 literal"));
    }
    let name_ok = !host.is_empty()
        && host.len() <= 253
        && !host.starts_with(['.', '-'])
        && !host.ends_with(['.', '-'])
        && host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    if name_ok {
        Ok(())
    } else {
        Err(InviteError::BadAddress("host"))
    }
}

fn validate_sni(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && !s.starts_with(['.', '-'])
        && !s.ends_with(['.', '-'])
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

/// Процентное кодирование значения: unreserved (RFC 3986) как есть, пробел — `+`.
fn encode_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn decode_component(s: &str) -> Result<String, InviteError> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' => {
                let hex = s.get(i + 1..i + 3).ok_or(InviteError::BadEncoding)?;
                out.push(u8::from_str_radix(hex, 16).map_err(|_| InviteError::BadEncoding)?);
                i += 3;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| InviteError::BadEncoding)
}

impl Invite {
    /// Собирает приглашение, проверяя поля так же, как разбор.
    pub fn new(
        addr: &str,
        public_key: &str,
        secret: &str,
        token: Option<&str>,
        sni: Option<&str>,
        name: Option<&str>,
    ) -> Result<Self, InviteError> {
        let inv = Self {
            addr: addr.trim().to_owned(),
            public_key: public_key.trim().to_ascii_lowercase(),
            secret: secret.trim().to_ascii_lowercase(),
            token: token.map(str::trim).filter(|t| !t.is_empty()).map(str::to_owned),
            sni: sni.map(str::trim).filter(|t| !t.is_empty()).map(str::to_owned),
            name: name.map(str::trim).filter(|t| !t.is_empty()).map(str::to_owned),
        };
        inv.validate()?;
        Ok(inv)
    }

    fn validate(&self) -> Result<(), InviteError> {
        validate_addr(&self.addr)?;
        if !is_hex64(&self.public_key) {
            return Err(InviteError::BadHex("pk"));
        }
        if !is_hex64(&self.secret) {
            return Err(InviteError::BadHex("secret"));
        }
        if let Some(t) = &self.token {
            if t.len() > MAX_TOKEN_LEN || t.chars().any(char::is_control) {
                return Err(InviteError::BadValue("token"));
            }
        }
        if let Some(s) = &self.sni {
            if !validate_sni(s) {
                return Err(InviteError::BadValue("sni"));
            }
        }
        if let Some(n) = &self.name {
            if n.chars().count() > MAX_NAME_CHARS || n.chars().any(char::is_control) {
                return Err(InviteError::BadValue("name"));
            }
        }
        Ok(())
    }

    /// Строка `nrxp://…`.
    pub fn to_uri(&self) -> String {
        let mut s = format!("{SCHEME}://{}?pk={}&secret={}", self.addr, self.public_key, self.secret);
        if let Some(t) = &self.token {
            s.push_str("&token=");
            s.push_str(&encode_component(t));
        }
        if let Some(v) = &self.sni {
            s.push_str("&sni=");
            s.push_str(&encode_component(v));
        }
        if let Some(n) = &self.name {
            s.push_str("&name=");
            s.push_str(&encode_component(n));
        }
        s
    }

    /// Блок для `client.toml` (те же поля, что в конфиге headless-клиента).
    pub fn to_toml(&self) -> String {
        let q = |s: &str| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""));
        let mut s = String::new();
        if let Some(n) = &self.name {
            s.push_str(&format!("# {}\n", n.replace('\n', " ")));
        }
        s.push_str(&format!("remote_address = {}\n", q(&self.addr)));
        if let Some(v) = &self.sni {
            s.push_str(&format!("sni = {}\n", q(v)));
        }
        if let Some(t) = &self.token {
            s.push_str(&format!("auth_token = {}\n", q(t)));
        }
        s.push_str(&format!("node_secret = {}\n", q(&self.secret)));
        s.push_str(&format!("node_public_key = {}\n", q(&self.public_key)));
        s
    }

    /// Разбирает строку `nrxp://…` (пробелы по краям допускаются).
    pub fn parse(input: &str) -> Result<Self, InviteError> {
        let input = input.trim();
        if input.len() > MAX_URI_LEN {
            return Err(InviteError::TooLong);
        }
        let rest = input
            .get(..SCHEME.len() + 3)
            .filter(|p| p.eq_ignore_ascii_case("nrxp://"))
            .map(|_| &input[SCHEME.len() + 3..])
            .ok_or(InviteError::NotAnInvite)?;
        let (addr, query) = rest.split_once('?').ok_or(InviteError::Missing("pk"))?;
        // Фрагмент (`#…`) не используется; отбрасываем, чтобы не попал в значение.
        let query = query.split('#').next().unwrap_or_default();
        let addr = addr.trim_end_matches('/');

        let (mut pk, mut secret, mut token, mut sni, mut name) = (None, None, None, None, None);
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let slot = match k {
                "pk" => &mut pk,
                "secret" => &mut secret,
                "token" => &mut token,
                "sni" => &mut sni,
                "name" => &mut name,
                _ => continue, // неизвестное — для будущих версий
            };
            if slot.is_some() {
                return Err(InviteError::Duplicate(k.to_owned()));
            }
            *slot = Some(decode_component(v)?);
        }
        Self::new(
            addr,
            pk.as_deref().ok_or(InviteError::Missing("pk"))?,
            secret.as_deref().ok_or(InviteError::Missing("secret"))?,
            token.as_deref(),
            sni.as_deref(),
            name.as_deref(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PK: &str = "abababababababababababababababababababababababababababababababab";
    const SECRET: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

    #[test]
    fn builds_the_documented_uri() {
        let inv = Invite::new("203.0.113.7:443", PK, SECRET, Some("efef"), Some("www.debian.org"), Some("мой телефон")).unwrap();
        assert_eq!(
            inv.to_uri(),
            format!("nrxp://203.0.113.7:443?pk={PK}&secret={SECRET}&token=efef&sni=www.debian.org&name=%D0%BC%D0%BE%D0%B9+%D1%82%D0%B5%D0%BB%D0%B5%D1%84%D0%BE%D0%BD")
        );
    }

    #[test]
    fn parses_back_exactly_and_ignores_unknown_parameters() {
        let inv = Invite::new("[2001:db8::1]:8443", PK, SECRET, Some("a.b-c_d~e"), Some("cdn.example"), Some("Офис №1 & ко")).unwrap();
        assert_eq!(Invite::parse(&inv.to_uri()).unwrap(), inv);
        let with_extra = format!("{}&future=1&x", inv.to_uri());
        assert_eq!(Invite::parse(&with_extra).unwrap(), inv);
        assert_eq!(Invite::parse(&format!("  {}\n", inv.to_uri())).unwrap(), inv, "пробелы по краям");
        // регистр схемы и hex не важны, hex нормализуется
        let upper = format!("NRXP://203.0.113.7:443?pk={}&secret={}", PK.to_uppercase(), SECRET.to_uppercase());
        let p = Invite::parse(&upper).unwrap();
        assert_eq!((p.public_key.as_str(), p.secret.as_str()), (PK, SECRET));
        assert!(p.token.is_none() && p.sni.is_none() && p.name.is_none());
    }

    #[test]
    fn rejects_malformed_invitations() {
        let ok = |q: &str| Invite::parse(&format!("nrxp://203.0.113.7:443?{q}"));
        assert_eq!(Invite::parse("https://x"), Err(InviteError::NotAnInvite));
        assert_eq!(Invite::parse(""), Err(InviteError::NotAnInvite));
        assert!(matches!(ok(&format!("secret={SECRET}")), Err(InviteError::Missing("pk"))));
        assert!(matches!(ok(&format!("pk={PK}")), Err(InviteError::Missing("secret"))));
        assert!(matches!(ok(&format!("pk=zz&secret={SECRET}")), Err(InviteError::BadHex("pk"))));
        assert!(matches!(ok(&format!("pk={PK}&secret={}", &SECRET[2..])), Err(InviteError::BadHex("secret"))));
        assert!(matches!(ok(&format!("pk={PK}&pk={PK}&secret={SECRET}")), Err(InviteError::Duplicate(_))));
        assert!(matches!(ok(&format!("pk={PK}&secret={SECRET}&sni=bad%20host")), Err(InviteError::BadValue("sni"))));
        assert!(matches!(ok(&format!("pk={PK}&secret={SECRET}&name=%FF")), Err(InviteError::BadEncoding)));
        assert!(matches!(ok(&format!("pk={PK}&secret={SECRET}&name=%4")), Err(InviteError::BadEncoding)));
        assert!(matches!(ok(&format!("pk={PK}&secret={SECRET}&token=a%0Ab")), Err(InviteError::BadValue("token"))));
        let long_name = "я".repeat(65);
        assert!(matches!(ok(&format!("pk={PK}&secret={SECRET}&name={long_name}")), Err(InviteError::BadValue("name"))));
        for bad in ["nrxp://203.0.113.7?pk=a", "nrxp://203.0.113.7:0", "nrxp://:443", "nrxp://a b:443", "nrxp://[::1:443", "nrxp://-x:443"] {
            let uri = format!("{bad}&pk={PK}&secret={SECRET}");
            let uri = if bad.contains('?') { uri } else { uri.replacen('&', "?", 1) };
            assert!(Invite::parse(&uri).is_err(), "{bad}");
        }
        assert_eq!(Invite::parse(&format!("nrxp://h:1?{}", "a".repeat(9000))), Err(InviteError::TooLong));
    }

    #[test]
    fn debug_output_never_shows_the_secret_or_token() {
        let inv = Invite::new("203.0.113.7:443", PK, SECRET, Some("tok-123"), None, None).unwrap();
        let d = format!("{inv:?}");
        assert!(!d.contains(SECRET) && !d.contains("tok-123") && d.contains("[redacted]"));
    }

    #[test]
    fn toml_block_matches_the_headless_client_config() {
        let inv = Invite::new("203.0.113.7:443", PK, SECRET, Some("tok\"en"), Some("www.debian.org"), Some("мой телефон")).unwrap();
        let t = inv.to_toml();
        assert!(t.contains("remote_address = \"203.0.113.7:443\"") && t.contains("sni = \"www.debian.org\""));
        assert!(t.contains(&format!("node_secret = \"{SECRET}\"")) && t.contains(&format!("node_public_key = \"{PK}\"")));
        assert!(t.contains("auth_token = \"tok\\\"en\"") && t.starts_with("# мой телефон"));
    }

    #[test]
    fn percent_coding_round_trips_arbitrary_text() {
        for s in ["", "plain", "a b+c%d", "ёж/ъ?#&=", "日本語", "~-._"] {
            assert_eq!(decode_component(&encode_component(s)).unwrap(), s, "{s:?}");
        }
        assert_eq!(encode_component("a b"), "a+b");
    }
}
