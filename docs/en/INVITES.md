# Connection invitations

An invitation is a single `nrxp://…` string carrying everything a client needs to connect to a
node: address, node key, entry secret and, optionally, a token and a decoy domain. Send it in a
message, show it as a QR code, or drop it into `client.toml`.

> **An invitation is a secret.** It contains the node's entry secret (and the token, if any).
> Anyone who sees it can connect. Share it over a private channel, never publish it, keep it out
> of logs and shell history. To revoke, rotate the node secret/key or the token.

## Generate one on the server

```bash
PROXY_NRXP_PRIVATE_KEY=… PROXY_NRXP_SECRET=… \
netrunner-server --invite --advertise 203.0.113.7:443 \
    --invite-name "my phone" --invite-token "$TOKEN" --decoy-host www.debian.org
```

Output (stdout carries only this line):

```text
nrxp://203.0.113.7:443?pk=abab…ab&secret=cdcd…cd&token=efef…ef&sni=www.debian.org&name=my+phone
```

The command does not start the node; warnings go to stderr, so `URI=$(netrunner-server --invite …)`
is safe in scripts.

| Flag | Meaning |
|---|---|
| `--invite` | print the invitation and exit |
| `--advertise host:port` / `--invite-addr` | public address in the invitation |
| `--invite-name` | label for the app's list |
| `--invite-token` / `NETRUNNER_INVITE_TOKEN` | Bearer token for `--require-auth` nodes |
| `--invite-sni` | decoy domain (default: `--decoy-host`) |
| `--invite-format uri\|toml` | `toml` prints a `client.toml` field block instead |

Keys come from the same variables as a normal start: `PROXY_NRXP_PRIVATE_KEY` (the public key
`pk` is derived from it) and `PROXY_NRXP_SECRET`. In swarm mode (`--swarm-key`) the secret is
derived; an explicit `PROXY_NRXP_SECRET` that disagrees makes the command fail instead of
printing an invitation that would not work.

## Format

| Part | Meaning | Required |
|---|---|:-:|
| `host:port` (before `?`) | node address | yes |
| `pk` | node's static public key (64 hex) | yes |
| `secret` | node entry secret (64 hex) | yes |
| `token` | Bearer token | no |
| `sni` | decoy domain | no |
| `name` | label; UTF-8, percent-encoded, space as `+` | no, ≤ 64 chars |

Unknown parameters are ignored (the format is extensible). Duplicates, wrong hex length, port 0,
control characters in token/name and invitations over 8 KiB are rejected. Code:
`netrunner_core::invite::Invite` (`parse`, `to_uri`, `to_toml`).

## Connect a client

```bash
netrunner-client --invite 'nrxp://…'          # visible in ps — prefer:
NETRUNNER_INVITE='nrxp://…' netrunner-client
```

or in `client.toml`: `invite = "nrxp://…"`.

Precedence: explicit `--remote-address`, `--sni`, `--auth-token`, `--node-secret`,
`--node-public-key` beat the invitation; an invitation from CLI/environment beats the same TOML
fields; `invite` together with `remote_address`/`node_secret`/`node_public_key` in one TOML is an
error. The client currently accepts IPv4 node addresses only.
