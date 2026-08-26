#!/usr/bin/env bash
# =============================================================================
# 10-public.sh — the public interface must be a black hole, except UDP/51820
# =============================================================================
# Policy under test:
#   rules/00-tables.nft       input policy drop
#   rules/40-services.nft     services are reachable from the mesh ONLY
#   rules/50-vpn-endpoint.nft UDP 51820 is the single public exception
#   rules/70-logging.nft      everything else: log + drop (never reject)
#
# Probes arrive on eth0 in the SUT namespace from 45.33.0.2 — a source address
# that is deliberately NOT in @BOGON_V4, so a failure here means the service
# policy leaked, not that the bogon filter fired.
#
# Sourced by run-tests.sh — do not execute directly.
# SPDX-License-Identifier: MIT
# =============================================================================

# ---------------------------------------------------------------------------
# SSH is open to the mesh only; from the public side it must be invisible.
# A LISTENER IS RUNNING on port 22 inside the SUT namespace, so "filtered"
# can only be the firewall's doing.
# ---------------------------------------------------------------------------
t_public_ssh_dropped() {
  local desc="public: TCP/22 (SSH) is dropped, not reachable"
  enforcement_guard "$desc" || return 0
  local status
  status="$(tcp_status "$CLI_NS" "$PUB_CLI_IP" "$PUB_SUT_IP" "$PORT_SSH")"
  tap_assert "$desc" "filtered" "$status" \
    "a listener is bound on 22 in the SUT ns; 'open' means the policy leaked"
}

# ---------------------------------------------------------------------------
# HTTP is commented out in 40-services.nft → must be dropped even though a
# listener is bound (this catches an accidental uncommented service rule).
# ---------------------------------------------------------------------------
t_public_http_dropped() {
  local desc="public: TCP/80 (HTTP) is dropped although a listener is bound"
  enforcement_guard "$desc" || return 0
  local status
  status="$(tcp_status "$CLI_NS" "$PUB_CLI_IP" "$PUB_SUT_IP" "$PORT_HTTP")"
  tap_assert "$desc" "filtered" "$status"
}

# ---------------------------------------------------------------------------
# A random high port with nothing listening.  Without a firewall the kernel
# answers RST → "refused".  With this ruleset the SYN is dropped → "filtered".
# ---------------------------------------------------------------------------
t_public_random_port_dropped() {
  local desc="public: random TCP port ($PORT_RANDOM) is dropped"
  enforcement_guard "$desc" || return 0
  local status
  status="$(tcp_status "$CLI_NS" "$PUB_CLI_IP" "$PUB_SUT_IP" "$PORT_RANDOM")"
  tap_assert "$desc" "filtered" "$status"
}

# ---------------------------------------------------------------------------
# Explicit stealth check: DROP, not REJECT.  Any RST (or ICMP admin-prohibited)
# confirms the host exists to a scanner and violates the design goal.
# ---------------------------------------------------------------------------
t_public_no_rst_leak() {
  local desc="public: closed port produces no RST/ICMP reject (stealth drop)"
  enforcement_guard "$desc" || return 0
  local status
  status="$(tcp_status "$CLI_NS" "$PUB_CLI_IP" "$PUB_SUT_IP" 33334)"
  case "$status" in
    filtered)
      tap_ok "$desc"
      ;;
    refused | unreachable)
      tap_not_ok "$desc" \
        "got '$status' — the host answered a scanner (reject, not drop)"
      ;;
    *)
      tap_not_ok "$desc" "unexpected status '$status'"
      ;;
  esac
}

# ---------------------------------------------------------------------------
# Counter proof: the SYN really did arrive at the host (pre counter) and really
# did not survive the filter (post counter).  This distinguishes "firewall
# dropped it" from "the packet never got there / test is broken".
# ---------------------------------------------------------------------------
t_public_counters_prove_drop() {
  local desc="public: nft counters confirm SSH SYN arrived and was dropped"
  enforcement_guard "$desc" || return 0
  probes_reset
  tcp_status "$CLI_NS" "$PUB_CLI_IP" "$PUB_SUT_IP" "$PORT_SSH" 2 > /dev/null
  assert_dropped "$desc" "ssh"
}

# ---------------------------------------------------------------------------
# UDP/51820: the one public exception.  We check both the observation counter
# (packet survived the filter) and the listener's record file (WireGuard's
# userspace equivalent actually received the datagram).
# ---------------------------------------------------------------------------
t_public_wireguard_udp_reachable() {
  local desc="public: UDP/$PORT_WG (WireGuard handshake) is accepted"
  enforcement_guard "$desc" || return 0
  probes_reset
  priv rm -f "$WG_HIT_FILE" > /dev/null 2>&1 || true
  udp_send "$CLI_NS" "$PUB_CLI_IP" "$PUB_SUT_IP" "$PORT_WG" 148 > /dev/null
  sleep 0.5
  local pre post
  pre="$(probe_count pre wg)"
  post="$(probe_count post wg)"
  if ((pre == 0)); then
    tap_not_ok "$desc" "handshake datagram never reached the host — setup problem"
    return 0
  fi
  if ((post > 0)) || priv test -s "$WG_HIT_FILE"; then
    tap_ok "$desc"
  else
    tap_not_ok "$desc" \
      "pre=$pre post=$post and no listener record — the handshake port is closed" \
      "check rules/50-vpn-endpoint.nft (note: the per-source meter allows 5/minute)"
  fi
}
