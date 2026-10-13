# Decentralization: a network that knows itself

🇷🇺 [Русская версия](../DECENTRALIZATION.md)

This document describes how nodes and clients can learn about the network from the protocol itself
instead of from a control panel; which architectural schemes exist; and what is already implemented
(**stage A**, a prototype in this repository). Everything else is design, not code.

> Status: stage A is implemented and covered by tests (including three real nodes over loopback and
> three real `netrunner-server` binaries). Stages B–E are a proposal. The threat model and the
> limitations are at the end; read them before relying on anything here.

## 1. What there was, and the problem

| What | How it was (before stage A) | Why it is bad |
|---|---|---|
| The client knows a node | one `remote_address` + `node_secret` + `node_public_key` from the panel | the address gets blocked — the tunnel is dead |
| Nodes know each other | every 20 s `list_mesh_peers()` from the panel (`MeshPeer`: address, SNI, **`nrxp_secret`**, key) | the panel is a single point of failure and the root of trust; one compromised node learns every entry secret |
| Peer admission | `validate_mesh_peer()` in the panel | without the panel mesh does not work |
| Record authenticity | none: "a record from the panel" | no signed binding of "key ↔ address" |

The good news: the directory is already behind the `AuthValidator` trait (`list_mesh_peers`,
`validate_mesh_peer`), and the refresh loop in `server/src/network.rs` does not care where peers come
from. Stage A uses exactly that: it plugs in another source without touching routing, capsules or
failover.

## 2. Principles

1. **Authenticity is separate from availability.** A record is self-certifying (signed by the node's
   key), so it can travel by any channel — verification does not depend on who delivered it.
2. **Knowledge is bounded by construction.** A node holds only what it needs; bridge addresses are not
   relayed; no more than N nodes are accepted from one network.
3. **No secrets in public records.** A neighbour's entry secret is derived from the swarm key (stage A)
   and later from pairwise DH (stage C+).
4. **The first contact cannot be removed.** The app and the first entry key are a one-off trust event;
   it can be weakened (reproducible builds, several signers) but not eliminated.
5. **Sybil is solved by cost, not by an authority:** invitations, vouching, measured behaviour,
   per-network limits — not "who is in charge".

## 3. Layers

```text
Layer 4  Client access     signed tokens verified by the node offline                (stage B/E)
Layer 3  Frontier          several independent channels for a signed set             (stage C)
Layer 2  Dissemination     node-to-node gossip + frames inside the tunnel            ← stage A
Layer 1  Membership        who may be a node: swarm key → vouching                   ← A (swarm key), D
Layer 0  Identity          node_id = H(sign_pub ‖ static_pub), the record is signed  ← stage A
```

## 4. Roles and hybrid schemes

Anyone can become an operator, but with a **choice of role**; being public is a conscious choice, not
a side effect of connecting.

| Role | Who | Published? |
|---|---|---|
| **Leaf** | any client, especially behind NAT or censorship: outbound connections only | no |
| **Core** | dedicated public nodes with good bandwidth | yes |
| **Friend guard** | a user's node, entry by invitation only | by token |
| **Hidden operator** | a node without a public IP holding outbound links to rendezvous points | no |
| **Relay / exit** | volunteers; exit is enabled explicitly | yes, flagged |

Schemes are assembled from these blocks; choose by speed vs. safety priority:

| Scheme | Speed | User safety | Enumeration resistance | Code effort |
|---|---|---|---|---|
| 1. Core + friend guard | high | high | medium | low |
| 2. Two lanes (fast via core, private via x-hop) | maximal for bulk traffic | depends on rules | medium | medium |
| 3. Hidden operator (rendezvous) | low | maximal for the operator | high | high |
| 4. Multipath through different guards | maximal | medium | medium | low |
| 5. Clusters + measured capacity | high | medium | medium | high |

User presets: **Fast** (core, 1–2 hops, multipath), **Balanced** (friend guard → core → exit; sensitive
traffic in the private lane; the default), **Maximum** (leaf → guard → 2–3 relays → exit, mixing and
cover), **Help the network** (operator role by choice).

User-safety rules: separate keys and ports for client and operator on one device; leaf by default,
operator role by explicit choice; exit off by default; stable guards (weeks); bandwidth and stream
quotas; node-to-node links masked with the same browser profile as client-to-node; an emergency
ladder (friend → hidden operator → ephemeral bridges over WebRTC → an out-of-network channel).

## 5. Stage A: what is implemented

### 5.1 The node descriptor (`core/src/net/directory/descriptor.rs`)

A signed record: `node_id`, X25519 static key, Ed25519 signing key, roles, features (`GOSSIP`), the
supported NRXP version range, `seq`, `issued_at`, `valid_until` (≤ 72 h), the decoy SNI and up to 4
addresses. `node_id = SHA-256("nrxp-node-id-v1" ‖ sign_pub ‖ static_pub)[..16]` — a record cannot be
attributed to someone else's key. The signing key is derived with HKDF from the node's private static
key: no extra configuration. Verification: version, identity, signature (`verify_strict`), validity
(clocks may differ by 5 min), address syntax and publicness (`--directory-allow-private` for LAN).

Tests: every byte of the record is covered by the signature; swapping the static key is caught; parsing
fuzzing does not panic.

### 5.2 Store and admission (`store.rs`)

The higher `seq` wins; rolling back to an old address and replays are "stale". At most 3 nodes per
network (IPv4 /24, IPv6 /48, second-level domain); at most 2048 records, the one closest to expiry is
evicted (only if the new one lives longer). The on-disk snapshot is re-verified on load.

### 5.3 Exchange (`gossip.rs`) and the `PeerGossip` frame (0x0d)

```text
 initiator                              responder
  Digest{(id, seq)…}  ──────────────▶
                      ◀──────────────  Reply{records the initiator lacks; want: what we need}
  Push{want}          ──────────────▶  (no reply)
```

A message is ≤ 15,000 bytes (fits one NRXP frame). Bridge addresses (`Roles::BRIDGE`) are not relayed.
Incoming exchanges are rate-limited. The frame travels over an already authenticated mesh session
(`MeshPeerSession::gossip_exchange`) and is served only for a mesh peer.

**Compatibility.** Instead of bumping the handshake version, the `GOSSIP` feature flag in the record is
used: nodes without it are not sent the frame (an unknown type drops their leg). Old panel-managed
nodes keep working as before.

### 5.4 The swarm (`swarm.rs`) — instead of `nrxp_secret` in the directory

`swarm_key` is a shared 32-byte network key. A node's entry secret is `HKDF(swarm_key, "node-secret:" ‖
node_id)`. Records carry no secrets; a member computes a neighbour's barrier itself; anyone without the
key fails the `ClientHello` tag. Mesh-peer admission: the peer presents the secret derived for its
`node_id` (`DirectoryValidator::validate_mesh_peer`, constant-time comparison).

> **An interim link.** The swarm key is a shared secret; its leak removes the entry barrier of the
> network (but does not allow impersonating a node: identity is held by the static key in the
> handshake). The swarm key answers "are you a member of the network"; "are you exactly this node" is
> answered by the pairwise secret (below). Tokens instead of the swarm key — stage B.

**Pairwise identity.** For two nodes `A` and `B` a pairwise secret is computed from static DH
(`pairwise_secret = HKDF(X25519(a, B_pub) ‖ keys)`, symmetric); only the two of them know it. When
connecting to `B`, node `A` puts `<swarm secret>.<proof>` into the mesh token, where the proof is 128 bits
derived from the pairwise secret. For a node that already has a record in the directory `B` demands the
proof: a swarm member without the pairwise secret cannot pass for a known node, and an overheard proof is
useless for another pair. An unfamiliar swarm member is introduced by the swarm key (otherwise a new node
could not join). Compatibility:

* the proof is sent only to nodes with the `PAIRWISE` feature in their record; the rest get the old token
  with the swarm secret alone;
* **strict mode** (`--swarm-strict`) requires the proof from known nodes; while it is off the node also
  accepts the old token — turn it on once every swarm node is updated.
* the token with the proof fits the secret field limit (128 characters; checked by a test — the first
  version with a 64-character proof hit this limit and broke real sessions).

### 5.5 A node without the panel

`DirectoryValidator` implements `AuthValidator`: `list_mesh_peers` takes neighbours from the directory,
`validate_mesh_peer` checks the swarm secret, user accounts come from the panel if there is one
(otherwise there are no user tokens). The loop in `server/src/network.rs` did not change.

**Launch.** Once per network: `openssl rand -hex 32` → the swarm key. For every node: its own
`PROXY_NRXP_PRIVATE_KEY` (`openssl rand -hex 32`).

```bash
export PROXY_SWARM_KEY=<swarm key>
export PROXY_NRXP_PRIVATE_KEY=<node key>

# print the node's descriptor (for neighbours) and the data for clients
netrunner-server --port 443 --advertise 203.0.113.10:443 --print-descriptor
#   node_id / static_public / nrxp_secret / descriptor <hex>

# run a node that knows a neighbour by its descriptor
netrunner-server --port 443 --advertise 203.0.113.10:443 \
    --directory-seed <neighbour descriptor hex | path to a file> \
    --directory-file /var/lib/netrunner/directory.bin
```

| Flag (variable) | Meaning |
|---|---|
| `--swarm-key` (`PROXY_SWARM_KEY`) | enables swarm mode; `PROXY_NRXP_SECRET`, `PROXY_NODE_ID` and a backend are not needed |
| `--advertise` (`NETRUNNER_ADVERTISE`) | public `host:port` in the descriptor |
| `--directory-seed` (`NETRUNNER_DIRECTORY_SEED`) | neighbours' descriptors (hex or a file; one record per line) |
| `--directory-file` (`NETRUNNER_DIRECTORY_FILE`) | persist the directory across restarts |
| `--directory-gossip-interval` | exchange period, seconds (±30 %) |
| `--directory-allow-private` | accept private addresses (LAN, test beds) |
| `--print-descriptor` | print the descriptor and exit |

Metrics: `netrunner_directory_records`, `…_exchanges_total`, `…_exchange_failures_total`,
`…_records_learned_total`, `…_records_rejected_total`, `…_bad_messages_total`.

Verified by hand: three real binaries over loopback, an introduction chain 1→2→3, a few seconds later
every node holds two records and the directory is saved to a file.

### 5.6 Client: several nodes and startup selection

In `client.toml`:

```toml
remote_address = "203.0.113.10:443"
node_secret = "…"
node_public_key = "…"

[[nodes]]                       # backups; each with its own credentials
address = "203.0.113.20:443"
node_secret = "…"
node_public_key = "…"
sni = "www.debian.org"
```

At startup the client checks TCP reachability of all nodes at once and connects to the first live one
(the previously working node from `cache_dir/last_node` first). Switching nodes in the middle of a
session is **deliberately not done**: routes and the kill switch are bound to the node's address. If
all legs are dead for longer than `TUNNEL_DEAD_AFTER`, the engine exits by itself, the process ends with
an error and the service manager (systemd/procd) restarts the client — now choosing the next live node.

### 5.7 The client learns nodes itself: `PeerHint`

A swarm client (`swarm_key` set) asks the node it is connected to for a few neighbours about every 10
minutes: a `PeerGossip` frame carrying `HintRequest{max ≤ 32}`, answered with `HintReply` — random live
relay records (bridges are never handed out). Records go through the same checks as between nodes
(signature, validity, per-network limit), land in the cache `<cache_dir>/directory.bin` (or
`--directory-file`) and take part in the next start's node selection **after** the nodes from the
config. The client computes a found node's credentials itself from the swarm key; without the key a
received address is of no use to it.

```toml
remote_address = "203.0.113.10:443"
node_secret = "…"
node_public_key = "…"
swarm_key = "<swarm key, 64 hex>"       # enables swarm mode and list refresh
# directory_file = "/var/lib/netrunner/directory.bin"
# learn_nodes = false                   # or --no-learn-nodes: cache and [[nodes]] only
# trust_anchors = ["<authority key>"]   # managed swarm: endorsed nodes only (5.8)
```

Client requests are counted in a separate rate window (`max_hints_per_window`, 30 per 10 s) so a flood of
clients cannot starve node-to-node exchange. **Compatibility:** a node without a directory silently drops
the request, but a node of an older release drops the leg on the unknown frame — so the client sends
`PeerHint` only when the operator explicitly enabled the swarm (`swarm_key`). Verified with real binaries:
a client knew one node, learned the others, the primary node was stopped — the next start with the same
config connected to a learned node.

### 5.8 The centre as an option: hybrid and managed swarm

The swarm does not cancel the panel; it stands beside it. Modes are chosen by flags and are off by default.

| Mode | How to enable | Where peers come from | Peer admission |
|---|---|---|---|
| **Centre** (default) | no `--swarm-key` | the panel | the panel |
| **Hybrid** | `--swarm-key` + `--backend-url` | panel ∪ directory | the panel **or** a swarm member |
| **Swarm** | `--swarm-key` | the directory | a swarm member (+ pairwise identity) |
| **Managed swarm** | `--swarm-key` + `--trust-anchor` | the directory, endorsed nodes only | a swarm member **and** a valid endorsement |

* **Hybrid.** `DirectoryValidator` merges the panel's list and the directory's (on a matching address or
  id the panel wins; an unreachable panel does not switch the directory off); admission is "the panel
  confirmed or a swarm member". The node presents its panel identifier (`PROXY_NODE_ID`) to panel peers
  and its swarm identifier to swarm peers. Users and billing stay in the panel. Limitation: the old
  `mesh2/mesh3` routes (two-node, without onion capsules) use the main identity, so peers known only to the
  swarm are reached over onion (`mesh4`) routes.
* An **authority** is any holder of an Ed25519 key (a panel, a federation). Its public key is given to nodes
  and clients as `--trust-anchor` (for a client — `trust_anchors` in `client.toml`). It issues a node an
  **endorsement**: "this node's keys are admitted until `not_after`". The endorsement is bound to the
  node's identity (`node_id` and both keys), not to addresses, and lives inside the signed record (format
  version 2; records without endorsements stay version 1 and remain compatible with old nodes). A node takes
  from gossip and `PeerHint` only records with a valid endorsement; a record lives no longer than it.
  **Revocation** — stop renewing the endorsement. Renewal is picked up without a restart (`--endorsement`
  is re-read every round).
* The authority tooling is built into `netrunner-server`:

```bash
netrunner-server --authority-keygen                       # authority_secret / authority_public
netrunner-server --swarm-key … --advertise … --print-descriptor      # the node's descriptor <hex>
netrunner-server --authority-endorse <descriptor hex> --authority-key <secret> --endorse-days 7
netrunner-server … --trust-anchor <authority_public> --endorsement /etc/netrunner/endorsement.txt
```

Verified with real binaries: a mixed swarm of one node of the previous release and two new ones converged
(two records each); in a managed swarm the endorsed nodes found each other while a node without an
endorsement got no admission, neither by the swarm key nor through gossip.

### 5.9 Number of legs

In the same release the number of parallel TCP legs became a client setting: 1–10, default 4
(`--tunnel-legs`, `tunnel_legs`, `SessionParams.tunnel_legs`, a setting in the app). The limit of 10 is
the protocol's. Nodes older than this release accept at most 4 legs.

## 6. What next (design)

| Stage | What | What stops depending on a centre |
|---|---|---|
| B | capability tokens with attenuation (expiry, node subset, role), invitation quotas; Ed25519 is already there | client admission |
| C | encrypted descriptors in a table with per-epoch blinding; rendezvous points; pairwise secrets from static DH instead of the swarm key | node enumeration, the swarm key |
| D | membership by vouching of ≥K members, revocation along the invitation chain | authorities |
| E | relay credits, blind tokens | billing |

The client's frontier (bootstrap): a signed set is obtained from any of several independent channels (a
`PeerHint` frame inside a live connection; CDNs and cloud storage; DNS TXT/DoH with names derived from
the date and the network key; mail and a bot; neighbours on the local network; browser volunteers over
WebRTC). The set is downloaded as a whole — the channel host does not learn which nodes this client
needs.

## 7. Threat model

| Adversary | What stops it (stage A) | What remains |
|---|---|---|
| Record forgery | signature, `node_id` bound to the keys | — |
| Replay of an old record / address rollback | `seq`, lifetime | — |
| Directory flooding from one network | per-network limit, directory size, incoming rate | Sybil from different networks |
| Bridge enumeration through gossip | bridges are not relayed | handing out bridges in portions (stage B/C) |
| Outsider (no swarm key) | fails the `ClientHello` tag | leak of the swarm key |
| Captured node | it sees records but not secrets (they are derived) | the swarm key held by a member |
| Address harvester (joined as a node) | per-network limit; the directory is not published outside the swarm | the cost is the number of nodes, not zero |
| Address blocking | backup nodes in the client config | a dynamic frontier (stage C) |
| Global observer | — | not solved |

## 8. Prototype limitations

* The digest is a window of ≤ 480 pairs; thousands of nodes need a compact digest (IBLT/Merkle).
* Mesh-peer admission is "knows the swarm key", not "owns this node" (see 5.4).
* Records carry public addresses; for host names publicness cannot be checked.
* The client receives nodes through `PeerHint` (5.7), but only if it knows the `swarm_key`; that is the
  network's shared secret (tokens replace it in stage B). Only nodes with an IPv4 address are used for now.
* There is no node switch in the middle of a session: the node changes only by restarting the client.
* Time: records rely on clocks; the allowed skew is 5 minutes.
* Tests: the directory — format, admission rules, a 40-node network, attacks
  (`cargo test -p netrunner-core --lib -- directory`); four tests with real nodes over sockets (exchange,
  a foreign swarm key, bridges, an ordinary client); node selection in the client
  (`cargo test -p netrunner-client --features cli`).

## 9. What is left in stage A

* Gossip over connections the node dialled itself (behind NAT): today exchange goes only to nodes with a
  public address. The base exists — reverse egress — but it needs `validate_egress` in the backend/swarm.
* The `ClientHello` barrier is still derived from the swarm key (the pairwise identity stops impersonating a
  known node, but not an outsider with the swarm key entering: that needs tokens, stage B). A full
  challenge-response instead of the static proof — after tokens appear.
* A compact digest (IBLT/Merkle) for directories of thousands of nodes.
* `EXIT`/`BRIDGE` roles in routing (only `RELAY` is considered now).
* Masking of node-to-node links (mesh-QUIC with the ALPN `nrxp-mesh/1` differs from a browser).
* Switching nodes in the middle of a session.
