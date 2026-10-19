//! Минимальный HTTP/1.1 для панели — в том же духе, что `health.rs`/`metrics_server.rs`
//! (без фреймворка), но с разбором запроса: маршруты, тело JSON, жёсткие лимиты.
//! Одно соединение — один запрос (`Connection: close`).

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_HEAD: usize = 16 * 1024;
const MAX_BODY: usize = 64 * 1024;
pub const IO_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Request {
    pub method: String,
    pub path: String,
    pub query: String,
    headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

impl Response {
    pub fn json(status: u16, v: &serde_json::Value) -> Self {
        Self { status, content_type: "application/json; charset=utf-8", body: v.to_string().into_bytes() }
    }

    pub fn error(status: u16, msg: &str) -> Self {
        Self::json(status, &serde_json::json!({ "error": msg }))
    }

    pub fn asset(content_type: &'static str, body: &'static [u8]) -> Self {
        Self { status: 200, content_type, body: body.to_vec() }
    }
}

/// Читает один запрос. `Err` — текст ошибки для 400.
pub async fn read_request<S: AsyncReadExt + Unpin>(s: &mut S) -> Result<Request, String> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    let head_end = loop {
        if let Some(i) = find(&buf, b"\r\n\r\n") {
            break i;
        }
        if buf.len() > MAX_HEAD {
            return Err("заголовки слишком велики".into());
        }
        let n = s.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("соединение закрыто".into());
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = std::str::from_utf8(&buf[..head_end]).map_err(|_| "заголовки не UTF-8".to_string())?;
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or("").split(' ');
    let (Some(method), Some(target), Some(version), None) = (first.next(), first.next(), first.next(), first.next())
    else {
        return Err("некорректная стартовая строка".into());
    };
    if !version.starts_with("HTTP/1.") {
        return Err("поддерживается только HTTP/1.x".into());
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    let mut req = Request {
        method: method.to_string(),
        path: path.to_string(),
        query: query.to_string(),
        headers,
        body: Vec::new(),
    };
    if req.header("transfer-encoding").is_some() {
        return Err("Transfer-Encoding не поддерживается".into());
    }
    let len: usize = match req.header("content-length") {
        None => 0,
        Some(v) => v.parse().map_err(|_| "Content-Length некорректен".to_string())?,
    };
    if len > MAX_BODY {
        return Err("тело слишком велико".into());
    }
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < len {
        let n = s.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("тело оборвано".into());
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(len);
    req.body = body;
    Ok(req)
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        _ => "Internal Server Error",
    }
}

/// Заголовки безопасности: страница не встраивается, не грузит ничего внешнего, не кешируется.
pub async fn write_response<S: AsyncWriteExt + Unpin>(s: &mut S, r: &Response) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\
         Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\n\
         Referrer-Policy: no-referrer\r\nCross-Origin-Resource-Policy: same-origin\r\nCross-Origin-Opener-Policy: same-origin\r\n\
         Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; \
         img-src 'self' data:; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n\r\n",
        r.status,
        reason(r.status),
        r.content_type,
        r.body.len()
    );
    s.write_all(head.as_bytes()).await?;
    s.write_all(&r.body).await?;
    s.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn parse(raw: &str) -> Result<Request, String> {
        let mut r = raw.as_bytes();
        read_request(&mut r).await
    }

    #[tokio::test]
    async fn parses_get_with_query_and_headers() {
        let r = parse("GET /api/x?a=1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\nAuthorization: Bearer t\r\n\r\n").await.unwrap();
        assert_eq!((r.method.as_str(), r.path.as_str(), r.query.as_str()), ("GET", "/api/x", "a=1"));
        assert_eq!(r.header("authorization"), Some("Bearer t"));
    }

    #[tokio::test]
    async fn reads_body_by_content_length() {
        let r = parse("POST /p HTTP/1.1\r\nContent-Length: 4\r\n\r\n{\"a\"}extra").await.unwrap();
        assert_eq!(r.body, b"{\"a\"");
    }

    #[tokio::test]
    async fn rejects_oversize_chunked_and_truncated() {
        assert!(parse("POST /p HTTP/1.1\r\nContent-Length: 999999\r\n\r\n").await.is_err());
        assert!(parse("POST /p HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n").await.is_err());
        assert!(parse("POST /p HTTP/1.1\r\nContent-Length: 10\r\n\r\nab").await.is_err());
        assert!(parse("GARBAGE\r\n\r\n").await.is_err());
        assert!(parse("GET / HTTP/2\r\n\r\n").await.is_err());
    }
}
