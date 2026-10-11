//! Tunnel event tracing without personal data.
//!
//! A node must never record who talks to what: no client address, no account,
//! no destination host or IP. What is safe and still enough to debug a stall is
//! the *shape* of a flow: protocol, address family, how it was routed, how it
//! ended and why, how long it lived, how many bytes moved and how long it sat
//! blocked on flow control. Everything here is limited to those fields.
//!
//! Every stream the node opens on behalf of a client gets one [`StreamTrace`]
//! (kept by the `Muxer`) and exactly one closing line, `tunnel stream closed`,
//! plus the `netrunner_stream_*` metrics. Dial failures are additionally
//! classified by [`DialKind`] so "the exit had no IPv6 route" and "the site
//! refused the connection" can be told apart from a counter alone.

use std::net::SocketAddr;
use std::time::Instant;

/// Address family of a destination, derived from the `"ip:port"` string the
/// client sent. `Name` is a host name (family not known until it resolves).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Family {
    V4,
    V6,
    Name,
}

impl Family {
    pub fn as_str(self) -> &'static str {
        match self {
            Family::V4 => "v4",
            Family::V6 => "v6",
            Family::Name => "name",
        }
    }
}

/// Family of `target` (`"1.2.3.4:443"`, `"[2001:db8::1]:443"` or `"host:443"`).
/// Only the family leaves this function; the address itself is never kept.
pub fn target_family(target: &str) -> Family {
    if let Ok(addr) = target.parse::<SocketAddr>() {
        return if addr.is_ipv6() { Family::V6 } else { Family::V4 };
    }
    if let Some((host, _port)) = target.rsplit_once(':') {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            return if ip.is_ipv6() { Family::V6 } else { Family::V4 };
        }
    }
    Family::Name
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

/// How the exit of a flow was chosen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    /// Not decided yet (the stream was just registered).
    Pending,
    /// Dialed from this node.
    Local,
    /// Sent through an onion route to another node.
    Onion,
    /// Dialed locally first, failed, then handed to a backup exit.
    Failover,
    /// Handed to a reverse-egress dialer.
    Reverse,
    /// This node is a hop/exit for another node's flow.
    Relay,
}

impl Route {
    pub fn as_str(self) -> &'static str {
        match self {
            Route::Pending => "pending",
            Route::Local => "local",
            Route::Onion => "onion",
            Route::Failover => "failover",
            Route::Reverse => "reverse",
            Route::Relay => "relay",
        }
    }
}

/// Why a dial did not produce a connected socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DialKind {
    /// No route to the destination network (e.g. IPv6 on a host without it).
    NetUnreachable,
    HostUnreachable,
    Refused,
    Timeout,
    Resolve,
    Bind,
    Other,
}

impl DialKind {
    pub fn as_str(self) -> &'static str {
        match self {
            DialKind::NetUnreachable => "net_unreachable",
            DialKind::HostUnreachable => "host_unreachable",
            DialKind::Refused => "refused",
            DialKind::Timeout => "timeout",
            DialKind::Resolve => "resolve",
            DialKind::Bind => "bind",
            DialKind::Other => "other",
        }
    }

    pub fn from_io(error: &std::io::Error) -> Self {
        use std::io::ErrorKind as K;
        match error.kind() {
            K::NetworkUnreachable => DialKind::NetUnreachable,
            K::HostUnreachable => DialKind::HostUnreachable,
            K::ConnectionRefused => DialKind::Refused,
            K::TimedOut => DialKind::Timeout,
            // ENETUNREACH / EHOSTUNREACH sometimes arrive as `Uncategorized`.
            _ => match error.raw_os_error() {
                Some(101) => DialKind::NetUnreachable,
                Some(113) => DialKind::HostUnreachable,
                Some(111) => DialKind::Refused,
                Some(110) => DialKind::Timeout,
                _ => DialKind::Other,
            },
        }
    }

    /// Whether this failure says "this exit cannot reach that family at all",
    /// as opposed to a problem with one particular destination.
    pub fn is_route_level(self) -> bool {
        matches!(self, DialKind::NetUnreachable)
    }
}

/// Life record of one stream opened by a client through this node.
#[derive(Clone, Debug)]
pub struct StreamTrace {
    pub opened: Instant,
    pub proto: Proto,
    pub family: Family,
    pub route: Route,
    /// Client asked for the strong-privacy (onion-only) path.
    pub strong_privacy: bool,
    /// Why/how it ended; first writer wins, `None` means a plain close.
    pub outcome: Option<&'static str>,
    pub dial_kind: Option<DialKind>,
    /// Exit attempts made (primary + failovers).
    pub attempts: u8,
    /// Milliseconds from open to the first byte coming back, if any did.
    pub first_byte_ms: Option<u64>,
}

impl StreamTrace {
    pub fn new(proto: Proto, family: Family, strong_privacy: bool) -> Self {
        Self {
            opened: Instant::now(),
            proto,
            family,
            route: Route::Pending,
            strong_privacy,
            outcome: None,
            dial_kind: None,
            attempts: 0,
            first_byte_ms: None,
        }
    }
}

/// What the closing line reports besides the trace itself.
#[derive(Clone, Copy, Debug, Default)]
pub struct StreamTotals {
    /// Bytes from the client towards the destination.
    pub up_bytes: u64,
    /// Bytes from the destination towards the client.
    pub down_bytes: u64,
    /// Total time the sender spent blocked on the client's credit window.
    pub credit_stall_ms: u64,
    /// Number of separate credit stalls.
    pub credit_stalls: u32,
}

/// Emits the single closing line and the metrics for a finished stream.
pub fn emit_stream_closed(session_id: &str, stream_id: u32, trace: &StreamTrace, totals: StreamTotals) {
    let outcome = trace.outcome.unwrap_or("closed");
    let duration_ms = trace.opened.elapsed().as_millis() as u64;
    let proto = trace.proto.as_str();
    let family = trace.family.as_str();
    let route = trace.route.as_str();

    metrics::counter!(
        "netrunner_stream_closed_total",
        "proto" => proto, "family" => family, "route" => route, "outcome" => outcome
    )
    .increment(1);
    metrics::histogram!("netrunner_stream_duration_seconds", "proto" => proto, "outcome" => outcome)
        .record(duration_ms as f64 / 1000.0);
    if totals.credit_stalls > 0 {
        metrics::counter!("netrunner_stream_credit_stalled_total").increment(1);
    }

    let failed = !matches!(outcome, "closed" | "ok");
    let line = |level_warn: bool| {
        if level_warn {
            tracing::warn!(
                target: "netrunner_tunnel",
                session = session_id,
                stream_id,
                proto,
                family,
                route,
                outcome,
                dial = trace.dial_kind.map(DialKind::as_str).unwrap_or("-"),
                attempts = trace.attempts,
                strong_privacy = trace.strong_privacy,
                duration_ms,
                first_byte_ms = trace.first_byte_ms.map(|v| v as i64).unwrap_or(-1),
                up_bytes = totals.up_bytes,
                down_bytes = totals.down_bytes,
                credit_stall_ms = totals.credit_stall_ms,
                credit_stalls = totals.credit_stalls,
                "tunnel stream closed"
            );
        } else {
            tracing::info!(
                target: "netrunner_tunnel",
                session = session_id,
                stream_id,
                proto,
                family,
                route,
                outcome,
                dial = trace.dial_kind.map(DialKind::as_str).unwrap_or("-"),
                attempts = trace.attempts,
                strong_privacy = trace.strong_privacy,
                duration_ms,
                first_byte_ms = trace.first_byte_ms.map(|v| v as i64).unwrap_or(-1),
                up_bytes = totals.up_bytes,
                down_bytes = totals.down_bytes,
                credit_stall_ms = totals.credit_stall_ms,
                credit_stalls = totals.credit_stalls,
                "tunnel stream closed"
            );
        }
    };
    line(failed);
}

/// Counts a failed dial. Called once per failed attempt, whichever path made it.
pub fn count_dial_failure(proto: Proto, family: Family, kind: DialKind) {
    metrics::counter!(
        "netrunner_egress_dial_fail_total",
        "proto" => proto.as_str(), "family" => family.as_str(), "kind" => kind.as_str()
    )
    .increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_is_read_from_the_literal_without_keeping_it() {
        assert_eq!(target_family("93.184.216.34:443"), Family::V4);
        assert_eq!(target_family("[2a03:2880:f20a:e5::4420]:443"), Family::V6);
        assert_eq!(target_family("2a03:2880::1:443"), Family::V6);
        assert_eq!(target_family("example.com:443"), Family::Name);
    }

    #[test]
    fn os_errors_map_to_dial_kinds() {
        let net = std::io::Error::from_raw_os_error(101);
        assert_eq!(DialKind::from_io(&net), DialKind::NetUnreachable);
        assert!(DialKind::from_io(&net).is_route_level());
        let refused = std::io::Error::from_raw_os_error(111);
        assert_eq!(DialKind::from_io(&refused), DialKind::Refused);
        assert!(!DialKind::from_io(&refused).is_route_level());
        let timed = std::io::Error::new(std::io::ErrorKind::TimedOut, "t");
        assert_eq!(DialKind::from_io(&timed), DialKind::Timeout);
    }
}
