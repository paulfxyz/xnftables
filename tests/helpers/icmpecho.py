#!/usr/bin/env python3
# =============================================================================
# icmpecho.py — send ICMP echo-requests and report whether a reply came back
# =============================================================================
# Used as the fall-back for the ICMP tests when ping(8) is not installed (slim
# containers frequently omit iputils).  Behaviour matches what the tests need:
#
#   reply   → at least one echo-reply arrived  (exit 0)
#   noreply → nothing came back within the timeout (exit 1)
#   error   → could not send at all (no CAP_NET_RAW, bad address) (exit 2)
#
# Usage:
#   icmpecho.py --dst 10.10.0.1 [--src 10.10.0.2] [--count 2] [--timeout 2]
#
# rules/60-icmp.nft accepts echo-request from @MESH_PEERS and drops it from
# everywhere else, so "noreply" is the expected result for a public source and
# "reply" the expected result for a mesh source.
#
# SPDX-License-Identifier: MIT
# =============================================================================
import argparse
import os
import select
import socket
import struct
import sys
import time

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0


def checksum(data: bytes) -> int:
    """Internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def build_echo(ident: int, seq: int) -> bytes:
    payload = b"xnftables-test-probe"
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, ident, seq)
    csum = checksum(header + payload)
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, csum, ident, seq)
    return header + payload


def main() -> int:
    parser = argparse.ArgumentParser(description="ICMP echo probe")
    parser.add_argument("--src", help="source address to bind (optional)")
    parser.add_argument("--dst", required=True)
    parser.add_argument("--count", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=2.0)
    args = parser.parse_args()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except OSError as exc:
        print("error")
        print("raw ICMP socket unavailable: %s" % exc, file=sys.stderr)
        return 2

    if args.src:
        try:
            sock.bind((args.src, 0))
        except OSError as exc:
            print("error")
            print("cannot bind %s: %s" % (args.src, exc), file=sys.stderr)
            return 2

    ident = os.getpid() & 0xFFFF
    deadline = time.time() + args.timeout
    for seq in range(args.count):
        try:
            sock.sendto(build_echo(ident, seq), (args.dst, 0))
        except OSError as exc:
            print("error")
            print("send failed: %s" % exc, file=sys.stderr)
            return 2

    # Wait for any echo-reply carrying our identifier.
    while time.time() < deadline:
        ready, _, _ = select.select([sock], [], [], max(0.0, deadline - time.time()))
        if not ready:
            break
        packet, _addr = sock.recvfrom(2048)
        # Skip the 20-byte IPv4 header that raw sockets hand back.
        icmp = packet[20:28]
        if len(icmp) < 8:
            continue
        icmp_type, _code, _csum, reply_id, _seq = struct.unpack("!BBHHH", icmp)
        if icmp_type == ICMP_ECHO_REPLY and reply_id == ident:
            sock.close()
            print("reply")
            return 0
    sock.close()
    print("noreply")
    return 1


if __name__ == "__main__":
    sys.exit(main())
