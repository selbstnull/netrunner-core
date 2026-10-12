#!/bin/bash
# Where do UDP datagrams go (native UDP leg or TCP legs), and does the UDP leg come
# back after the node restarts? Runs in a throw-away user+network namespace:
#   scripts/netns-stand/udp_leg.sh <netrunner-client> <netrunner-server>
# Reads the server's own metrics (netrunner_udp_path_total / netrunner_udp_oversize_total).
CLIENT=$(readlink -f "$1"); SERVER=$(readlink -f "$2")
[ -n "$CLIENT" ] && [ -n "$SERVER" ] || { sed -n '2,6p' "$0"; exit 2; }
export CLIENT SERVER
exec unshare -Urnm bash "$(cd "$(dirname "$0")" && pwd)/udp_leg_inner.sh"
