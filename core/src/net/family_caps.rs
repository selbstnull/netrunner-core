//! Which address families a node can actually reach, and who knows it.
//!
//! A flow to an IPv6 destination is only worth sending to an exit that has IPv6.
//! The exit picked for a flow used to be chosen without looking at the
//! destination's family, so on a mesh where some nodes have no IPv6 (several
//! providers hand out none) a share of flows landed on a node that could not dial
//! them. TCP then failed fast, but a UDP/QUIC flow just went quiet and the app
//! waited out its own timeout.
//!
//! Each node therefore probes its own reachability (a TCP connect to well-known
//! anycast addresses, no payload), and nodes learn each other's answers over the
//! existing mesh session with a plain `Heartbeat` frame: `CAPS?` is answered with
//! `CAPS:v4=1;v6=0`. A node that does not know the request replies with an empty
//! heartbeat like it does to any unknown payload, so a mixed fleet keeps working;
//! an unknown peer is treated as capable.

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::trace::Family;

/// Request payload (a `Heartbeat` frame on a fresh stream id).
pub(crate) const CAPS_REQUEST: &[u8] = b"CAPS?";
/// Reply prefix; the rest is `v4=<0|1>;v6=<0|1>`.
pub(crate) const CAPS_REPLY_PREFIX: &[u8] = b"CAPS:";

/// A peer's answer is trusted for this long; afterwards the peer is asked again,
/// and meanwhile treated as capable.
const PEER_CAPS_TTL: Duration = Duration::from_secs(15 * 60);
/// Consecutive failed probes before a family is declared down.
const DOWN_AFTER_FAILURES: u8 = 2;
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

const V4_PROBES: &[&str] = &["1.1.1.1:443", "8.8.8.8:443"];
const V6_PROBES: &[&str] = &["[2606:4700:4700::1111]:443", "[2001:4860:4860::8888]:443"];

#[derive(Clone, Copy)]
struct PeerCaps {
    v4: bool,
    v6: bool,
    at: Instant,
}

pub(crate) struct ExitCaps {
    local_v4: AtomicBool,
    local_v6: AtomicBool,
    v4_failures: AtomicU8,
    v6_failures: AtomicU8,
    /// Set once each family has been probed at least once.
    v4_probed: AtomicBool,
    v6_probed: AtomicBool,
    peers: DashMap<String, PeerCaps>,
}

impl Default for ExitCaps {
    fn default() -> Self {
        // Optimistic until the first probe says otherwise.
        Self {
            local_v4: AtomicBool::new(true),
            local_v6: AtomicBool::new(true),
            v4_failures: AtomicU8::new(0),
            v6_failures: AtomicU8::new(0),
            v4_probed: AtomicBool::new(false),
            v6_probed: AtomicBool::new(false),
            peers: DashMap::new(),
        }
    }
}

impl ExitCaps {
    pub(crate) fn local_supports(&self, family: Family) -> bool {
        match family {
            Family::V4 => self.local_v4.load(Ordering::Relaxed),
            Family::V6 => self.local_v6.load(Ordering::Relaxed),
            Family::Name => true,
        }
    }

    /// Whether `node_id` can dial `family`. Unknown or stale peers count as capable.
    pub(crate) fn peer_supports(&self, node_id: &str, family: Family) -> bool {
        let Some(caps) = self.peers.get(&node_id.to_ascii_lowercase()).map(|c| *c) else {
            return true;
        };
        if caps.at.elapsed() > PEER_CAPS_TTL {
            return true;
        }
        match family {
            Family::V4 => caps.v4,
            Family::V6 => caps.v6,
            Family::Name => true,
        }
    }

    pub(crate) fn peer_caps_stale(&self, node_id: &str) -> bool {
        self.peers
            .get(&node_id.to_ascii_lowercase())
            .is_none_or(|caps| caps.at.elapsed() > PEER_CAPS_TTL / 2)
    }

    pub(crate) fn set_peer(&self, node_id: &str, v4: bool, v6: bool) {
        let key = node_id.to_ascii_lowercase();
        let previous = self.peers.insert(
            key,
            PeerCaps {
                v4,
                v6,
                at: Instant::now(),
            },
        );
        if previous.is_none_or(|p| p.v4 != v4 || p.v6 != v6) {
            tracing::info!(
                target: "netrunner_tunnel",
                peer = node_id,
                v4,
                v6,
                "mesh peer address-family capability learned"
            );
        }
        self.publish_peer_gauges();
    }

    fn publish_peer_gauges(&self) {
        let (mut v4, mut v6) = (0usize, 0usize);
        for entry in self.peers.iter() {
            if entry.at.elapsed() <= PEER_CAPS_TTL {
                v4 += usize::from(entry.v4);
                v6 += usize::from(entry.v6);
            }
        }
        metrics::gauge!("netrunner_mesh_peers_family", "family" => "v4").set(v4 as f64);
        metrics::gauge!("netrunner_mesh_peers_family", "family" => "v6").set(v6 as f64);
    }

    /// `CAPS:v4=1;v6=0` describing this node.
    pub(crate) fn local_reply(&self) -> Vec<u8> {
        format!(
            "CAPS:v4={};v6={}",
            u8::from(self.local_v4.load(Ordering::Relaxed)),
            u8::from(self.local_v6.load(Ordering::Relaxed))
        )
        .into_bytes()
    }

    /// Parses a `CAPS:` reply into `(v4, v6)`.
    pub(crate) fn parse_reply(payload: &[u8]) -> Option<(bool, bool)> {
        let text = std::str::from_utf8(payload.strip_prefix(CAPS_REPLY_PREFIX)?).ok()?;
        let (mut v4, mut v6) = (None, None);
        for part in text.split(';') {
            match part.split_once('=')? {
                ("v4", value) => v4 = Some(value == "1"),
                ("v6", value) => v6 = Some(value == "1"),
                _ => {}
            }
        }
        Some((v4?, v6?))
    }

    /// Probes this node's own IPv4/IPv6 reachability and publishes the result.
    /// A family is declared down only after [`DOWN_AFTER_FAILURES`] failed
    /// rounds in a row, and up again on the first success.
    pub(crate) async fn probe_local(&self) {
        let (v4, v6) = tokio::join!(can_reach(V4_PROBES), can_reach(V6_PROBES));
        self.apply_probe(Family::V4, v4);
        self.apply_probe(Family::V6, v6);
    }

    #[cfg(test)]
    pub(crate) fn force_probe_result(&self, family: Family, reachable: bool) {
        self.apply_probe(family, reachable);
    }

    fn apply_probe(&self, family: Family, reachable: bool) {
        let (flag, failures, probed) = match family {
            Family::V4 => (&self.local_v4, &self.v4_failures, &self.v4_probed),
            Family::V6 => (&self.local_v6, &self.v6_failures, &self.v6_probed),
            Family::Name => return,
        };
        let was_up = flag.load(Ordering::Relaxed);
        // The very first probe replaces the optimistic default outright: a node
        // with no IPv6 at all must not keep claiming it for two probe rounds.
        let first = !probed.swap(true, Ordering::Relaxed);
        let now_up = if first {
            failures.store(u8::from(!reachable), Ordering::Relaxed);
            reachable
        } else if reachable {
            failures.store(0, Ordering::Relaxed);
            true
        } else {
            let n = failures.fetch_add(1, Ordering::Relaxed).saturating_add(1);
            if n >= DOWN_AFTER_FAILURES {
                false
            } else {
                was_up
            }
        };
        flag.store(now_up, Ordering::Relaxed);
        metrics::gauge!("netrunner_node_family_up", "family" => family.as_str())
            .set(if now_up { 1.0 } else { 0.0 });
        if was_up != now_up {
            tracing::warn!(
                target: "netrunner_tunnel",
                family = family.as_str(),
                up = now_up,
                "node address-family reachability changed"
            );
        }
    }
}

async fn can_reach(addrs: &[&str]) -> bool {
    for addr in addrs {
        if timeout(PROBE_TIMEOUT, TcpStream::connect(addr))
            .await
            .is_ok_and(|result| result.is_ok())
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_round_trips() {
        let caps = ExitCaps::default();
        caps.local_v6.store(false, Ordering::Relaxed);
        assert_eq!(ExitCaps::parse_reply(&caps.local_reply()), Some((true, false)));
        assert_eq!(ExitCaps::parse_reply(b"CAPS:v4=1"), None);
        assert_eq!(ExitCaps::parse_reply(b"PONG"), None);
        assert_eq!(ExitCaps::parse_reply(b""), None);
    }

    #[test]
    fn unknown_or_stale_peers_count_as_capable() {
        let caps = ExitCaps::default();
        assert!(caps.peer_supports("n1", Family::V6));
        caps.set_peer("N1", true, false);
        assert!(!caps.peer_supports("n1", Family::V6));
        assert!(caps.peer_supports("n1", Family::V4));
        assert!(caps.peer_supports("n1", Family::Name));
        assert!(caps.peer_supports("other", Family::V6));
    }

    #[test]
    fn the_first_probe_is_taken_at_face_value() {
        let caps = ExitCaps::default();
        caps.apply_probe(Family::V6, false);
        assert!(!caps.local_supports(Family::V6), "no IPv6 on the very first probe means none");
        assert!(caps.local_supports(Family::V4), "an unprobed family stays optimistic");
    }

    #[test]
    fn a_family_goes_down_only_after_repeated_failures() {
        let caps = ExitCaps::default();
        caps.apply_probe(Family::V6, true);
        caps.apply_probe(Family::V6, false);
        assert!(caps.local_supports(Family::V6), "one miss is not an outage");
        caps.apply_probe(Family::V6, false);
        assert!(!caps.local_supports(Family::V6));
        caps.apply_probe(Family::V6, true);
        assert!(caps.local_supports(Family::V6), "the first success brings it back");
    }
}
