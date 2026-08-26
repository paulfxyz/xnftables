#!/usr/bin/env python3
# =============================================================================
# listener.py — minimal TCP/UDP listener used as the "service" under test
# =============================================================================
# The firewall can only be tested meaningfully if something is actually
# listening: without a listener the kernel answers with RST and every test
# would report "refused" instead of "open", hiding the accept/drop difference.
#
# TCP mode: accepts connections and echoes back whatever it receives, which
#           doubles as the established/related return-path test.
# UDP mode: records every datagram it receives into --record (used for the
#           WireGuard UDP/51820 reachability test), optionally replying.
#
# Usage:
#   listener.py --proto tcp --port 22
#   listener.py --proto udp --port 51820 --record /tmp/wg.hits [--reply]
#
# Runs until killed (the harness kills it in teardown).
#
# SPDX-License-Identifier: MIT
# =============================================================================
import argparse
import os
import socket
import sys
import threading


def handle_tcp_client(conn: socket.socket) -> None:
    """Echo everything back, then close. One thread per connection."""
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            conn.sendall(data)
    except OSError:
        pass
    finally:
        conn.close()


def serve_tcp(bind: str, port: int) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind, port))
    sock.listen(16)
    print("tcp listener ready on %s:%d" % (bind, port), flush=True)
    while True:
        try:
            conn, _addr = sock.accept()
        except OSError:
            break
        threading.Thread(target=handle_tcp_client, args=(conn,), daemon=True).start()
    return 0


def serve_udp(bind: str, port: int, record: str, reply: bool) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind, port))
    print("udp listener ready on %s:%d" % (bind, port), flush=True)
    while True:
        try:
            data, addr = sock.recvfrom(65535)
        except OSError:
            break
        if record:
            # Append one line per datagram; the harness only checks for
            # non-emptiness, but the detail helps when debugging a failure.
            with open(record, "a", encoding="utf-8") as handle:
                handle.write("%s:%d %d bytes\n" % (addr[0], addr[1], len(data)))
                handle.flush()
                os.fsync(handle.fileno())
        if reply:
            try:
                sock.sendto(b"ack", addr)
            except OSError:
                pass
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="test listener")
    parser.add_argument("--proto", choices=("tcp", "udp"), default="tcp")
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--record", default="", help="UDP: file to append hits to")
    parser.add_argument("--reply", action="store_true", help="UDP: send 'ack' back")
    args = parser.parse_args()
    try:
        if args.proto == "tcp":
            return serve_tcp(args.bind, args.port)
        return serve_udp(args.bind, args.port, args.record, args.reply)
    except OSError as exc:
        print("listener failed: %s" % exc, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
