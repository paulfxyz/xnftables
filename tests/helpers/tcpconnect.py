#!/usr/bin/env python3
# =============================================================================
# tcpconnect.py — classify what the firewall did to a connection attempt
# =============================================================================
# A firewall can react to an inbound connection in three distinguishable ways,
# and the difference matters a lot for a "stealth" policy like xnftables:
#
#   open      → the SYN was accepted and a listener answered  (SYN/ACK)
#   refused   → the packet was REJECTED or hit a closed port  (RST, instant)
#   filtered  → the packet was DROPPED — no answer at all     (timeout)
#
# xnftables must always produce "filtered" for non-mesh traffic: dropping,
# never rejecting.  A RST would confirm the host exists to a port scanner.
# That distinction is impossible to make with `nc -z` alone, hence this helper.
#
# Usage:
#   tcpconnect.py --dst 45.33.0.1 --port 22 [--src 45.33.0.2] [--timeout 3]
#   tcpconnect.py --proto udp --dst 45.33.0.1 --port 51820 --payload-size 148
#   tcpconnect.py --dst 10.10.0.1 --port 22 --send "probe" --expect-echo
#
# Prints exactly one status word on stdout and exits with:
#   0 open / sent / echo-ok        3 unreachable
#   1 refused                      4 echo-fail
#   2 filtered (timeout)           5 other error
#
# SPDX-License-Identifier: MIT
# =============================================================================
import argparse
import errno
import socket
import sys

RC = {
    "open": 0,
    "sent": 0,
    "echo-ok": 0,
    "refused": 1,
    "filtered": 2,
    "unreachable": 3,
    "echo-fail": 4,
    "error": 5,
}


def emit(status: str, detail: str = "") -> int:
    """Print the single-word status (plus optional detail on stderr)."""
    print(status)
    if detail:
        print(detail, file=sys.stderr)
    return RC.get(status, 5)


def tcp_probe(args) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(args.timeout)
    try:
        if args.src:
            # Binding the source address is how we choose which "world" the
            # packet appears to come from (mesh peer vs public vs bogon).
            sock.bind((args.src, 0))
        sock.connect((args.dst, args.port))
    except socket.timeout:
        # No response whatsoever within the timeout: the packet was dropped.
        return emit("filtered")
    except ConnectionRefusedError:
        # RST came back: either a reject rule or a closed port. Not a drop.
        return emit("refused")
    except OSError as exc:
        if exc.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH):
            return emit("unreachable", str(exc))
        if exc.errno == errno.EACCES:
            # Some stacks surface an admin-prohibited ICMP as EACCES.
            return emit("refused", str(exc))
        return emit("error", str(exc))
    finally:
        pass

    # Connected. Optionally exercise the established/related return path by
    # sending a payload and reading the echo back.
    if args.send is not None:
        try:
            sock.sendall(args.send.encode() + b"\n")
            data = sock.recv(4096)
        except OSError as exc:
            sock.close()
            return emit("echo-fail", str(exc))
        sock.close()
        if args.send.encode() in data:
            return emit("echo-ok")
        return emit("echo-fail", "got %r" % data)

    sock.close()
    return emit("open")


def udp_probe(args) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.timeout)
    payload = b"\x01" + b"\x00" * (args.payload_size - 1)
    try:
        if args.src:
            sock.bind((args.src, 0))
        sock.sendto(payload, (args.dst, args.port))
    except OSError as exc:
        return emit("error", str(exc))

    if not args.expect_reply:
        # UDP is connectionless: whether the datagram was accepted has to be
        # confirmed on the receiving side (nft counters / listener record).
        sock.close()
        return emit("sent")

    try:
        sock.recv(4096)
    except socket.timeout:
        sock.close()
        return emit("filtered")
    except ConnectionRefusedError:
        # ICMP port-unreachable was received.
        sock.close()
        return emit("refused")
    sock.close()
    return emit("open")


def main() -> int:
    parser = argparse.ArgumentParser(description="classify a connection attempt")
    parser.add_argument("--proto", choices=("tcp", "udp"), default="tcp")
    parser.add_argument("--src", help="source address to bind (optional)")
    parser.add_argument("--dst", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--send", help="payload to send once connected (TCP)")
    parser.add_argument(
        "--expect-echo",
        action="store_true",
        help="require the payload to be echoed back (established/related test)",
    )
    parser.add_argument("--payload-size", type=int, default=148)
    parser.add_argument(
        "--expect-reply",
        action="store_true",
        help="UDP: wait for a reply datagram instead of just sending",
    )
    args = parser.parse_args()
    if args.proto == "tcp":
        return tcp_probe(args)
    return udp_probe(args)


if __name__ == "__main__":
    sys.exit(main())
