# Netrunner Core

A multiplexed VPN tunnel in Rust that camouflages its traffic as HTTPS over TLS 1.3. The built-in
default profile is based on Chrome 140; you can replace it with a profile captured from your browser.
Client (Linux/OpenWrt/Android via UniFFI) + server node.

🇷🇺 [Русская версия](README.ru.md)

> **💛 Support Netrunner Core.** The core is developed independently and relies on donations, not on revenue from the commercial product. If it is useful to you, please support it.
> USDT (TRC-20): `TQbts9Bj1LZJQE8oGbSbo1Qg6R3Co2k8jX` ([details](DONATE.md))
>
> <img src=".github/donate-usdt-trc20.png" alt="USDT TRC-20 QR code" width="140">

**Features**

- up to 4 parallel TCP "legs" per session, seamless stream failover;
- end-to-end credit flow control, adaptive buffers, BBR on legs;
- authenticated handshake (X25519 + node static key), forward secrecy, AEAD (AES-GCM / ChaCha20-Poly1305);
- camouflage: built-in Chrome 140 profile by default (JA3/JA4), server cover flight, irregular length
  padding and graceful handling of other TLS connections;
- custom browser profiles from JSON: `netrunner-client profile record` extracts TLS, QUIC Initial and
  traffic-shape parameters from the selected browser, checks that the engine reproduces them, and writes one file;
- optional: UDP leg (QUIC/WebRTC mimicry), multi-node mesh with onion routes;
- L3 VPN without TCP-in-TCP: TUN + userspace stack (`nrxp-smoltcp`), kill-switch, router mode.

Netrunner combines authenticated sessions, HTTPS-like traffic camouflage and multi-leg transport.

## Use a profile from your browser

The client includes a built-in default profile, and you can capture a separate profile from the browser
whose traffic you want to reproduce. Live recording uses a raw packet socket on Linux. You need the CLI
binary and `CAP_NET_RAW` permission (or run it as root).

```bash
# build the CLI if it is not available yet
cargo build --release -p netrunner-client --features cli --bin netrunner-client

# grant the binary packet-capture permission once
sudo setcap cap_net_raw+ep ./target/release/netrunner-client

# turn the VPN off, start capture, and open several HTTPS sites in the target browser
./target/release/netrunner-client profile record \
  --out browser.json --name my-browser --seconds 120 --stop-after 12 \
  --save-pcap browser.pcap

# validate the profile and start the client with it
./target/release/netrunner-client profile check browser.json
sudo ./target/release/netrunner-client --config client.toml --browser-profile browser.json
```

Keep QUIC enabled and visit sites that support HTTP/3 to capture a QUIC block. Use `--all` to capture
multiple browsers or JA4 fingerprints from the same recording; `--min-hellos` sets the minimum number of
connections per group. To build from an existing `.pcap`/`.pcapng` file, run
`netrunner-client profile build capture.pcapng --all --out profiles.json` (useful on Windows/macOS as well).
Combine JSON profiles with `profile merge first.json second.json --out pool.json`. Load a file with
`--browser-profile`, the `browser_profile` setting in `client.toml`, or `NETRUNNER_BROWSER_PROFILE`.

Capture with the VPN stopped, or the recording may contain the VPN tunnel itself. A pcap contains IP
addresses and site names (SNI); handle it as sensitive data and do not publish it. If the CLI reports that
capture limits were reached, make a fresh recording instead of treating the partial profile as complete.

## Quick start: your own node in 5 minutes

A Linux VPS with `tcp/443` and `udp/443` open, Rust ≥ 1.91 (or Docker).

```bash
git clone git@github.com:nineAp/netrunner-core.git && cd netrunner-core
cargo build --release -p netrunner-server

export PROXY_NRXP_SECRET=$(openssl rand -hex 32)        # shared with clients
export PROXY_NRXP_PRIVATE_KEY=$(openssl rand -hex 32)   # stays on the node
export PROXY_NRXP_STRICT=true

sudo -E ./target/release/netrunner-server --port 443 --decoy-host www.debian.org --health-port 9091
```

Find `"nrxp_public_key":"…"` in the log — the node's public key. Check:
`curl -s http://127.0.0.1:9091/` → `{"status":"ok",…}`.

**Client** (Linux/OpenWrt) — `client.toml` (`chmod 600`):

```toml
remote_address  = "NODE_IP:443"
sni             = "www.debian.org"            # = --decoy-host
node_secret     = "<PROXY_NRXP_SECRET>"
node_public_key = "<nrxp_public_key from the node log>"
killswitch_enabled = true
```

```bash
cargo build --release -p netrunner-client --features cli --bin netrunner-client
sudo ./target/release/netrunner-client --config client.toml
```
