#!/usr/bin/env python3
"""Sends UDP datagrams of several sizes through the tunnel to the echo server and
reports how many came back. usage: udp_sizes.py <host> <port> [per_size] [sizes,...]"""
import socket, sys, time

host, port = sys.argv[1], int(sys.argv[2])
per = int(sys.argv[3]) if len(sys.argv) > 3 else 20
sizes = [int(x) for x in sys.argv[4].split(",")] if len(sys.argv) > 4 else [200, 1000, 1100, 1150, 1200, 1252, 1350]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(0.5)
s.connect((host, port))
print("size  sent  echoed")
for size in sizes:
    got = 0
    for i in range(per):
        payload = bytes([i % 251]) * size
        try:
            s.send(payload)
            if s.recv(4096) == payload:
                got += 1
        except (socket.timeout, OSError):
            pass
        time.sleep(0.01)
    print("%4d  %4d  %6d" % (size, per, got))
