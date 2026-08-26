#!/usr/bin/env python3
# =============================================================================
# tcpflags.py — craft TCP segments with arbitrary (illegal) flag combinations
# =============================================================================
# rules/10-antiscan.nft drops the classic stealth-scan flag patterns.  A normal
# socket API can never produce them, so we build the IP + TCP headers by hand
# and push them out through a raw socket (needs CAP_NET_RAW → run as root
# inside the test namespace).
#
# Patterns (mirroring the rule comments in 10-antiscan.nft):
#   null    flags = 0x00            → nmap -sN   → XNFT-TCPFL-NULL
#   xmas    FIN|PSH|URG             → nmap -sX   → XNFT-TCPFL-XMAS
#   synfin  SYN|FIN                 → impossible → XNFT-TCPFL-SYNFIN
#   synrst  SYN|RST                 → impossible → XNFT-TCPFL-SYNRST
#   fin     FIN only (new conn)     → nmap -sF   → XNFT-TCPFL-FIN
#   syn     SYN (control/reference)  → normal handshake opener
#
# Usage:
#   tcpflags.py --src 45.33.0.2 --dst 45.33.0.1 --dport 44444 --flags xmas
#   tcpflags.py ... --count 3 --sport 40000
#
# The source address is written into the IP header directly, so this can also
# be used to forge bogon/spoofed sources without configuring the address on an
# interface (useful when testing the BOGON_V4 filter from a namespace that has
# no bogon address of its own).
#
# Exit 0 = packets sent (says nothing about whether they were accepted — that
# is what the nft counters in lib.sh are for).
#
# SPDX-License-Identifier: MIT
# =============================================================================
import argparse
import random
import socket
import struct
import sys

# TCP flag bit values (RFC 9293 §3.1).
FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20

FLAG_SETS = {
    "null": 0x00,
    "xmas": FIN | PSH | URG,
    "synfin": SYN | FIN,
    "synrst": SYN | RST,
    "fin": FIN,
    "syn": SYN,
    "ack": ACK,
}


def checksum(data: bytes) -> int:
    """Standard internet 16-bit one's-complement checksum (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def build_packet(src: str, dst: str, sport: int, dport: int, flags: int) -> bytes:
    """Build a complete IPv4 + TCP datagram with no payload."""
    saddr = socket.inet_aton(src)
    daddr = socket.inet_aton(dst)

    # --- TCP header (20 bytes, no options) ---
    seq = random.randint(0, 0xFFFFFFFF)
    tcp = struct.pack(
        "!HHIIBBHHH",
        sport,
        dport,
        seq,
        0,  # ack number
        5 << 4,  # data offset 5 words, reserved = 0
        flags,
        1024,  # window
        0,  # checksum placeholder
        0,  # urgent pointer
    )
    # TCP checksum is computed over a pseudo-header + the segment.
    pseudo = saddr + daddr + struct.pack("!BBH", 0, socket.IPPROTO_TCP, len(tcp))
    csum = checksum(pseudo + tcp)
    tcp = tcp[:16] + struct.pack("!H", csum) + tcp[18:]

    # --- IPv4 header (20 bytes) ---
    total_len = 20 + len(tcp)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) | 5,  # version 4, IHL 5
        0,  # DSCP/ECN
        total_len,
        random.randint(0, 0xFFFF),  # identification
        0,  # flags + fragment offset (not fragmented)
        64,  # TTL
        socket.IPPROTO_TCP,
        0,  # header checksum (kernel fills it in with IP_HDRINCL, but we set it)
        saddr,
        daddr,
    )
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return ip + tcp


def main() -> int:
    parser = argparse.ArgumentParser(description="send TCP segments with raw flags")
    parser.add_argument("--src", required=True, help="source IP (may be forged)")
    parser.add_argument("--dst", required=True)
    parser.add_argument("--dport", type=int, required=True)
    parser.add_argument("--sport", type=int, default=0, help="0 = random ephemeral")
    parser.add_argument(
        "--flags",
        required=True,
        choices=sorted(FLAG_SETS),
        help="named flag combination to send",
    )
    parser.add_argument("--count", type=int, default=1)
    args = parser.parse_args()

    sport = args.sport or random.randint(32768, 60999)
    flags = FLAG_SETS[args.flags]

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except OSError as exc:
        print("raw socket unavailable: %s" % exc, file=sys.stderr)
        return 3

    packet = None
    for _ in range(args.count):
        packet = build_packet(args.src, args.dst, sport, args.dport, flags)
        try:
            sock.sendto(packet, (args.dst, 0))
        except OSError as exc:
            print("send failed: %s" % exc, file=sys.stderr)
            return 4
    sock.close()
    print("sent %d %s packet(s) %s:%d -> %s:%d"
          % (args.count, args.flags, args.src, sport, args.dst, args.dport))
    return 0


if __name__ == "__main__":
    sys.exit(main())
