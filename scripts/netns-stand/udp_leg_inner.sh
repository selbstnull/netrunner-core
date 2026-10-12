#!/bin/bash
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(mktemp -d /tmp/nr-udpleg.XXXXXX); D=${OUT:-$PWD/stand-out}; mkdir -p "$D"
cleanup() { kill $CPID $SPID $HPID $EPID 2>/dev/null; wait 2>/dev/null; rm -rf "$W"; }
trap cleanup EXIT
mount -t tmpfs tmpfs /run; mkdir -p /run/netns
ip link set lo up
ip netns add cl
ip link add vs type veth peer name vc
ip link set vc netns cl
ip addr add 198.18.0.1/24 dev vs; ip link set vs up
ip addr add 203.0.113.80/32 dev lo
ip netns exec cl sh -c "ip link set lo up; ip addr add 198.18.0.2/24 dev vc; ip link set vc up; ip route add default via 198.18.0.1"
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null
tc qdisc add dev vs root netem delay 20ms limit 400
ip netns exec cl tc qdisc add dev vc root netem delay 20ms limit 400
mkdir -p $W/www $W/nrcache; echo ok > $W/www/small
( cd $W/www && exec python3 -m http.server 8080 --bind 203.0.113.80 >/dev/null 2>&1 ) & HPID=$!
python3 $HERE/udp_echo.py 203.0.113.80 9999 & EPID=$!
cat > $W/c.toml <<CFG
remote_address = "198.18.0.1:18443"
sni = "www.debian.org"
auth_token = ""
node_secret = ""
node_public_key = ""
cache_dir = "$W/nrcache"
mtu = 1450
killswitch_enabled = false
log_level = "info"
tunnel_mode = "all"
router_mode = false
CFG
start_server() { $SERVER --host 198.18.0.1 --port 18443 --decoy-host www.debian.org --metrics-port 9093 >>$D/udpleg_server.log 2>&1 & SPID=$!; }
metrics() { curl -s -m 3 198.18.0.1:9093/metrics 2>/dev/null | grep -E '^netrunner_udp_(path|oversize)_total' | sed 's/^netrunner_//' | sort; }
probe() { echo "--- UDP probe ($1)"; ip netns exec cl python3 $HERE/udp_sizes.py 203.0.113.80 9999 20; echo "--- server path counters:"; metrics; }
start_server; sleep 1.5
ip netns exec cl $CLIENT --config $W/c.toml >$D/udpleg_client.log 2>&1 & CPID=$!
ok=0; for i in $(seq 1 40); do ip netns exec cl curl -s -m 3 -o /dev/null http://203.0.113.80:8080/small && { ok=1; break; }; sleep 0.5; done
[ $ok = 1 ] || { echo "tunnel did not come up"; tail -8 $D/udpleg_client.log; exit 1; }
sleep 4
echo "=== A. fresh session"; grep -ciE "UDP leg established" $D/udpleg_client.log | sed 's/^/client log: "UDP leg established" lines = /'
probe "fresh session"
echo; echo "=== B. restart the node (the client keeps running)"
kill $SPID; wait $SPID 2>/dev/null; sleep 2; : > /dev/null; start_server
for i in $(seq 1 60); do ip netns exec cl curl -s -m 3 -o /dev/null http://203.0.113.80:8080/small && break; sleep 1; done
echo "tunnel back after restart: attempts=$i"
T0=$(date +%s)
for wait_s in 10 60 130; do
  while [ $(( $(date +%s) - T0 )) -lt $wait_s ]; do sleep 2; done
  echo; echo "=== B+${wait_s}s after the node restart"
  grep -E "UDP leg established" $D/udpleg_client.log | wc -l | sed 's/^/client log "UDP leg established" total: /'
  probe "node restarted ${wait_s}s ago"
done
echo "--- node UDP leg events:"; grep -E "UDP leg" $D/udpleg_server.log | tail -4 | cut -c1-170
