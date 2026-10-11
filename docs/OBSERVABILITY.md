# Tunnel observability (no personal data)

A node never records who talks to what: **no client address, no account, no
destination host or IP**. What is logged is the *shape* of a flow, enough to tell
"the exit had no route", "the site refused", "the client stopped granting window"
and "the leg died" apart. Everything below uses the `netrunner_tunnel` log target
(`docker logs netrunner-proxy | grep netrunner_tunnel`) and Prometheus metrics on
the node's metrics port.

## One line per stream: `tunnel stream closed`

Emitted exactly once when a stream a client opened through this node goes away.
`WARN` when it ended badly, `INFO` otherwise.

| field | meaning |
| --- | --- |
| `session` | random per-connection id (not an account) |
| `stream_id` | id inside that session |
| `proto` | `tcp` / `udp` |
| `family` | `v4` / `v6` / `name` (host name: family unknown until the exit resolves it) |
| `route` | `local` (dialed here), `onion` (sent to another node), `failover` (local dial failed, backup exit used), `reverse`, `relay` (this node is a hop/exit for another node's flow) |
| `outcome` | `closed` (normal) or the reason: `dial_failed`, `egress_exhausted`, `no_egress_candidate`, `route_setup_deadline`, `route_rejected`, `rejected*`, `refused_*`, `cancelled` |
| `dial` | last dial failure kind: `net_unreachable`, `host_unreachable`, `refused`, `timeout`, `resolve`, `bind`, `other`, or `-` |
| `attempts` | exit attempts (primary + failovers) |
| `duration_ms`, `first_byte_ms` | lifetime; time to the first byte sent back (`-1` = none) |
| `up_bytes`, `down_bytes` | client→destination / destination→client |
| `credit_stall_ms`, `credit_stalls` | time the sender sat blocked on the client's flow-control window |

Reading it: a video that "hangs" shows up as a long `duration_ms` with a large
`credit_stall_ms` (the client stopped granting window), or `first_byte_ms=-1`
(nothing came back from the destination), or `outcome=dial_failed` with a `dial`
kind.

## Other events

* `tunnel leg closed` (WARN): a leg went away — `reason` (`health_check_timeout`,
  `health_control_closed`, `engine_exit`, ...), `age_ms`, bytes carried, last
  `rtt_ms`, `since_pong_ms`, queued bytes, TCP retransmits, `legs_left`.
* `credit stall: peer is not granting window` / `credit window closed: probing with
  one chunk` (WARN): a stream's window stayed closed (>2 s / >3 s). A probe lets one
  chunk through every 3 s so a lost grant costs seconds, not minutes.
* `mesh egress exhausted` / `no mesh peer can act as an exit for this address
  family` (WARN): carries `family`.
* `mesh peer address-family capability learned`, `node address-family reachability
  changed` (INFO/WARN): which families this node and its peers can dial.

## Metrics

* `netrunner_stream_closed_total{proto,family,route,outcome}`
* `netrunner_stream_duration_seconds{proto,outcome}`, `netrunner_stream_credit_stalled_total`
* `netrunner_egress_dial_fail_total{proto,family,kind}` — per failed dial
* `netrunner_dial_race_won_total{family}` — a later address won the Happy Eyeballs race
* `netrunner_credit_stall_seconds`, `netrunner_credit_probe_total`
* `netrunner_leg_closed_total{reason}`, `netrunner_leg_engine_failure_total`
* `netrunner_node_family_up{family}`, `netrunner_mesh_peers_family{family}`
* `netrunner_mesh_no_exit_for_family_total{family}`,
  `netrunner_mesh_exit_reselected_for_family_total{family}`

## Address families and exits

The client usually sends a *host name* (it keeps names behind fake IPs), so the
exit resolves it. `net::connection::dial` dials every resolved address,
IPv4-first, racing them Happy-Eyeballs style (250 ms stagger); UDP walks the list
until a socket connects. When the destination is a literal address, the exit is
chosen among peers that can dial that family (`family_caps`): peers announce it
with a `CAPS?` / `CAPS:v4=1;v6=0` heartbeat on the mesh session, unknown peers
count as capable so a mixed fleet keeps working.

On the client, a UDP flow the tunnel closes before any reply is answered with
ICMP(v6) "port unreachable" so a QUIC app falls back immediately.
