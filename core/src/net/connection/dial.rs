//! Dialing a destination from an exit node: Happy Eyeballs (RFC 8305).
//!
//! The client usually sends a host name, not an address (it hands the app fake
//! IPs and keeps the name), so it is the exit node that resolves it. On a
//! dual-stack node the resolver puts IPv6 first, and the old code then
//!
//! * opened `TcpStream::connect(name)` under one 7 s deadline, so a slow IPv6
//!   first attempt used up the whole budget and IPv4 was never tried;
//! * took only the first resolved address for UDP, with no second chance.
//!
//! Either way one flaky IPv6 path made a flow hang or fail even though IPv4 to
//! the same site worked. Here every resolved address is used: addresses are
//! interleaved IPv4-first, TCP starts the next attempt after a short stagger (or
//! as soon as the previous one fails) and the first connection to succeed wins;
//! UDP walks the list until a socket can be connected.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::{lookup_host, TcpStream, UdpSocket};
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout, Instant};

use crate::net::trace::{DialKind, Family};

/// Resolution budget, as before.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);
/// Head start given to an attempt before the next address is raced against it.
const STAGGER: Duration = Duration::from_millis(250);

/// Interleaves resolved addresses IPv4-first: v4, v6, v4, v6, ...
///
/// IPv4 goes first because it is the path that works everywhere; IPv6 is kept as
/// the second attempt so a node (or destination) reachable only over IPv6 still
/// connects.
pub(crate) fn interleave(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let (v4, v6): (Vec<_>, Vec<_>) = addrs.into_iter().partition(SocketAddr::is_ipv4);
    let mut out = Vec::with_capacity(v4.len() + v6.len());
    let (mut v4, mut v6) = (v4.into_iter(), v6.into_iter());
    loop {
        match (v4.next(), v6.next()) {
            (None, None) => break,
            (a, b) => {
                out.extend(a);
                out.extend(b);
            }
        }
    }
    out
}

fn family_of(addr: &SocketAddr) -> Family {
    if addr.is_ipv6() {
        Family::V6
    } else {
        Family::V4
    }
}

/// Space that no public exit can reach and that a client only ever sends by
/// mistake: carrier-grade NAT `100.64.0.0/10` (the client hands apps fake IPs
/// from here and keeps the name; one that lost its name used to be dialed
/// literally, and every exit then sat out its 7 s timeout) and the benchmarking
/// range `198.18.0.0/15`. Refusing them answers in milliseconds instead of
/// after `3 x 7 s`.
pub(crate) fn is_unreachable_special(addr: &SocketAddr) -> bool {
    match addr.ip() {
        std::net::IpAddr::V4(ip) => {
            let o = ip.octets();
            (o[0] == 100 && (o[1] & 0xc0) == 64) || (o[0] == 198 && (o[1] & 0xfe) == 18)
        }
        std::net::IpAddr::V6(_) => false,
    }
}

/// Resolves `target` (`"host:port"`, `"ip:port"` or `"[v6]:port"`) to an
/// IPv4-first ordered list, without addresses no exit can reach.
pub(crate) async fn resolve(target: &str) -> Result<Vec<SocketAddr>, DialKind> {
    match timeout(RESOLVE_TIMEOUT, lookup_host(target)).await {
        Ok(Ok(addrs)) => {
            let all: Vec<SocketAddr> = addrs.collect();
            let reachable: Vec<SocketAddr> = all
                .iter()
                .copied()
                .filter(|addr| !is_unreachable_special(addr))
                .collect();
            if reachable.is_empty() {
                // Nothing resolved at all, or everything was unreachable space.
                return Err(if all.is_empty() {
                    DialKind::Resolve
                } else {
                    DialKind::Blocked
                });
            }
            Ok(interleave(reachable))
        }
        Ok(Err(_)) => Err(DialKind::Resolve),
        Err(_) => Err(DialKind::Timeout),
    }
}

/// Connects to `target`, racing its addresses Happy-Eyeballs style within `total`.
/// Returns the stream and the family that won.
pub(crate) async fn connect_tcp(
    target: &str,
    total: Duration,
) -> Result<(TcpStream, Family), DialKind> {
    let started = Instant::now();
    let addrs = resolve(target).await?;
    let deadline = started + total;

    let mut attempts: JoinSet<(Family, io::Result<TcpStream>)> = JoinSet::new();
    let mut remaining = addrs.into_iter();
    let mut last_error = DialKind::Other;
    let mut launched = 0u32;

    let launch = |attempts: &mut JoinSet<_>, addr: SocketAddr| {
        let family = family_of(&addr);
        attempts.spawn(async move { (family, TcpStream::connect(addr).await) });
    };

    if let Some(first) = remaining.next() {
        launch(&mut attempts, first);
        launched += 1;
    }
    let mut stagger_at = Instant::now() + STAGGER;

    loop {
        if attempts.is_empty() {
            match remaining.next() {
                Some(next) => {
                    launch(&mut attempts, next);
                    launched += 1;
                    stagger_at = Instant::now() + STAGGER;
                }
                None => return Err(last_error),
            }
        }
        let more = remaining.len() > 0;
        tokio::select! {
            joined = attempts.join_next() => match joined {
                Some(Ok((family, Ok(stream)))) => {
                    if launched > 1 {
                        metrics::counter!(
                            "netrunner_dial_race_won_total", "family" => family.as_str()
                        )
                        .increment(1);
                    }
                    return Ok((stream, family));
                }
                Some(Ok((_, Err(error)))) => {
                    last_error = DialKind::from_io(&error);
                    // A failed attempt starts the next one without waiting.
                    if let Some(next) = remaining.next() {
                        launch(&mut attempts, next);
                        launched += 1;
                        stagger_at = Instant::now() + STAGGER;
                    }
                }
                Some(Err(_)) | None => {}
            },
            _ = sleep(stagger_at.saturating_duration_since(Instant::now())), if more => {
                if let Some(next) = remaining.next() {
                    launch(&mut attempts, next);
                    launched += 1;
                }
                stagger_at = Instant::now() + STAGGER;
            }
            _ = sleep(deadline.saturating_duration_since(Instant::now())) => {
                return Err(DialKind::Timeout);
            }
        }
    }
}

/// Resolves `target`, binds a UDP socket of the right family and connects it to
/// the first address that accepts the connect (a route exists). Returns the
/// socket and the family used.
pub(crate) async fn connect_udp(target: &str) -> Result<(UdpSocket, Family), DialKind> {
    let addrs = resolve(target).await?;
    let mut last_error = DialKind::Other;
    for addr in addrs {
        let bind = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let socket = match UdpSocket::bind(bind).await {
            Ok(socket) => socket,
            Err(error) => {
                last_error = DialKind::from_io(&error);
                continue;
            }
        };
        match socket.connect(addr).await {
            Ok(()) => return Ok((socket, family_of(&addr))),
            Err(error) => last_error = DialKind::from_io(&error),
        }
    }
    Err(last_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn addresses_are_interleaved_ipv4_first() {
        let ordered = interleave(vec![
            a("[2001:db8::1]:443"),
            a("[2001:db8::2]:443"),
            a("192.0.2.1:443"),
        ]);
        assert_eq!(
            ordered,
            vec![a("192.0.2.1:443"), a("[2001:db8::1]:443"), a("[2001:db8::2]:443")]
        );
        assert!(interleave(vec![]).is_empty());
        assert_eq!(interleave(vec![a("[::1]:1")]), vec![a("[::1]:1")]);
    }

    #[test]
    fn carrier_grade_nat_and_benchmark_space_are_never_dialed() {
        assert!(is_unreachable_special(&a("100.64.0.1:443")));
        assert!(is_unreachable_special(&a("100.127.255.254:443")));
        assert!(is_unreachable_special(&a("198.18.0.9:443")));
        assert!(is_unreachable_special(&a("198.19.255.1:443")));
        assert!(!is_unreachable_special(&a("100.63.255.255:443")));
        assert!(!is_unreachable_special(&a("100.128.0.1:443")));
        assert!(!is_unreachable_special(&a("198.17.0.1:443")));
        assert!(!is_unreachable_special(&a("198.20.0.1:443")));
        assert!(!is_unreachable_special(&a("93.184.216.34:443")));
        assert!(!is_unreachable_special(&a("[2001:db8::1]:443")));
    }

    /// The fake-IP leak: the exit must answer at once, not after three timeouts.
    #[tokio::test]
    async fn a_leaked_fake_ip_is_refused_immediately() {
        let started = Instant::now();
        let error = connect_tcp("100.64.3.7:443", Duration::from_secs(7)).await.err().unwrap();
        assert_eq!(error, DialKind::Blocked);
        let error = connect_udp("100.64.3.7:443").await.err().unwrap();
        assert_eq!(error, DialKind::Blocked);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn tcp_connects_to_a_literal_address() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (_stream, family) = connect_tcp(&format!("127.0.0.1:{port}"), Duration::from_secs(3))
            .await
            .expect("loopback listener");
        assert_eq!(family, Family::V4);
    }

    /// `localhost` resolves to both ::1 and 127.0.0.1 on most hosts; the listener
    /// only exists on IPv4, so the attempt that must win is the IPv4 one whatever
    /// the resolver's order is.
    #[tokio::test]
    async fn tcp_falls_through_to_the_family_that_works() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (_stream, family) = connect_tcp(&format!("localhost:{port}"), Duration::from_secs(3))
            .await
            .expect("one of the localhost addresses is listening");
        assert_eq!(family, Family::V4);
    }

    #[tokio::test]
    async fn a_refused_port_reports_refused_not_a_timeout() {
        // Bind then drop to get a port nobody listens on.
        let port = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        };
        let started = Instant::now();
        let error = connect_tcp(&format!("127.0.0.1:{port}"), Duration::from_secs(3))
            .await
            .err()
            .expect("nothing listens there");
        assert_eq!(error, DialKind::Refused);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn udp_connects_to_a_literal_address_and_reports_the_family() {
        let (_socket, family) = connect_udp("127.0.0.1:9").await.expect("udp connect");
        assert_eq!(family, Family::V4);
    }

    #[tokio::test]
    async fn an_unresolvable_name_is_a_resolve_failure() {
        let error = connect_udp("definitely-not-a-host.invalid:443").await.err().unwrap();
        assert!(matches!(error, DialKind::Resolve | DialKind::Timeout));
    }
}
