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
| `dial` | last dial failure kind: `net_unreachable`, `host_unreachable`, `refused`, `timeout`, `resolve`, `bind`, `blocked` (CGNAT/benchmark space, never dialed), `other`, or `-` |
| `attempts` | exit attempts (primary + failovers) |
| `duration_ms`, `first_byte_ms`, `first_up_ms` | lifetime; time to the first byte sent back; time to the first byte received from the peer (`-1` = none). A slow `first_byte_ms` with a small `first_up_ms` means the destination or the way back was slow; a `first_up_ms` as large as `first_byte_ms` means the client or the route was late with its first bytes |
| `leg` | leg the stream was bound to (`-1` = none): lets a slow stream be matched with that leg's retransmits |
| `up_bytes`, `down_bytes` | client→destination / destination→client (TCP and UDP datagrams) |
| `credit_stall_ms`, `credit_stalls` | time the sender sat blocked on the client's flow-control window |
| `end` | on a stream this node bridged to the destination: who ended it first and how — `dest_fin` (the site closed cleanly), `dest_reset` / `dest_broken_pipe` / `dest_timeout` / `dest_error` (the site's connection failed), `tunnel_closed` (the client/other side closed it), `write_timeout`, `legs_down`; `-` when this node only relayed the stream |
| `name_tag` | on failed streams with a host-name target only: keyed, daily-rotating tag of the host (see below), `-` otherwise |

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
* `netrunner_stream_end_total{proto,end}`
* `netrunner_stream_duration_seconds{proto,outcome}`, `netrunner_stream_credit_stalled_total`
* `netrunner_egress_dial_fail_total{proto,family,kind}` — per failed dial
* `netrunner_dial_resolve_seconds`, `netrunner_dial_connect_seconds{family}` — where an exit's time to a destination goes; a dial over 0.8 s also logs `slow dial` (`resolve_ms`, `connect_ms`, `candidates`, `attempts`)
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

## Fake IPs and "literal" targets

The client answers DNS with fake addresses from `100.64.0.0/10` and keeps the
name behind each one. A flow whose target shows up at an exit as a literal IPv4
(`family="v4"`) that every exit then fails to dial (`dial="timeout"`,
`outcome="egress_exhausted"`, ~7 s per exit) is the signature of a fake IP that lost
its name. The client now resets such a connection at once and the exit refuses
`100.64.0.0/10` and `198.18.0.0/15` outright (`dial="blocked"`).

## Which path does UDP/QUIC take?

Every UDP datagram is counted where the leg is chosen (`select_udp_leg`):

* `netrunner_udp_path_total{path,reason}`: `path` is `native` (the UDP leg or the
  mesh-QUIC DATAGRAM leg) or `tcp` (carried inside the reliable legs / QUIC stream);
  `reason` is `ok`, `no_leg` (no native leg in the session), `stale` (no pong on the
  native leg for 45 s) or `oversize` (payload larger than the leg's ceiling).
* `netrunner_udp_carrier_total{result}`: datagrams carried over TCP that used the reserved carrier leg (`carrier`)
  or skipped it because its queue stood for several RTTs (`overloaded`).
* `netrunner_udp_oversize_total{size}`: the same oversize datagrams by size class
  (`1201-1252`, `1253-1350`, `over-1350`), i.e. what the ceiling would have to be.
* TCP legs, sampled every 250 ms per leg: `netrunner_leg_tcp_retrans_segments_total`,
  `netrunner_leg_tcp_loss_samples_total` / `netrunner_leg_tcp_samples_total` (the share of samples that
  found a leg inside loss recovery) and the histogram `netrunner_leg_tcp_notsent_bytes` (kernel queue
  in front of the wire).
* `netrunner_mesh_datagram_ceiling_bytes`: current ceiling of the node-to-node leg.
* Client side: `netrunner_datagram_leg_rebuilds_total{result=restored|failed}` and the warning
  `UDP leg is dead: building a new one` (fields `silent_ms`, `had_leg`, `previous_failures`)
  show the supervisor rebuilding a UDP leg whose node went silent (e.g. restarted).

A node-to-node QUIC connection starts at ~1160 bytes per DATAGRAM and grows to
~1410 once its path MTU has been probed; the leg's ceiling used to be read once at
attach time (1100) and so sent every larger packet down the reliable stream. It now
follows the connection (re-read every 500 ms for 30 s, then every 10 s).

## Names of failed streams

Stream summaries never contain the destination. For a stream that failed to a
host *name* the line carries `name_tag = hex(HMAC-SHA256(PROXY_NRXP_SECRET,
"<days since epoch>:<lowercase host>"))[..12]`: the same host gives the same tag all
day on that node and a different one tomorrow or elsewhere. To check a suspect, run
`scripts/name-tag.sh example.com` on the node and grep the tag.
