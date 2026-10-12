#!/usr/bin/env bash
# Prints today's log tag(s) for a host name, to match against `name_tag` in the
# "tunnel stream closed" lines of a node (see docs/OBSERVABILITY.md).
#   scripts/name-tag.sh <host> [container]        run ON the node
# tag = hex(HMAC-SHA256(key = PROXY_NRXP_SECRET, msg = "<days since epoch>:<lowercase host>"))[..12]
set -eu
host="${1:?usage: name-tag.sh <host> [container]}"
container="${2:-netrunner-proxy}"
secret="$(docker inspect "$container" --format '{{range .Config.Env}}{{println .}}{{end}}' | sed -n 's/^PROXY_NRXP_SECRET=//p')"
[ -n "$secret" ] || { echo "no PROXY_NRXP_SECRET on $container: tags are random per process, nothing to compute" >&2; exit 1; }
host="$(printf %s "$host" | sed -E 's/:[0-9]+$//' | tr 'A-Z' 'a-z' | tr -d '[]')"
for offset in 0 -1; do
  day=$(( $(date -u +%s) / 86400 + offset ))
  tag="$(SECRET="$secret" MSG="$day:$host" python3 -c 'import hmac,hashlib,os;print(hmac.new(os.environ["SECRET"].encode(),os.environ["MSG"].encode(),hashlib.sha256).hexdigest()[:12])')"
  echo "day $day: $tag"
done
