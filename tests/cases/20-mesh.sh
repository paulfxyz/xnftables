#!/usr/bin/env bash
# =============================================================================
# 20-mesh.sh — the mesh side of the trust boundary (rules/20-mesh.nft)
# =============================================================================
# Policy under test:
#   iifname "wg0" ip saddr != @MESH_PEERS   → log + drop   (anti-spoof, BUG 1A)
#   iifname "wg0"                            → jump mesh_input
#   mesh_input: invalid drop, established accept, @MESH_PEERS → jump services
#   services:   TCP/22 accept, rate-limited 6 new conn/minute
#
# The SUT-side interface really is named wg0, so these tests exercise the same
# code path a decrypted WireGuard packet would take.
#
# RATE-LIMIT CAUTION: rules/40-services.nft rate-limits *new* SSH connections
# to 6/minute (a shared bucket, not per-source).  This file therefore opens no
# more than two new port-22 connections per run.  See tests/README.md.
#
# Sourced by run-tests.sh — do not execute directly.
# SPDX-License-Identifier: MIT
# =============================================================================

# ---------------------------------------------------------------------------
# A legitimate mesh peer (10.10.0.2 on wg0) must reach SSH.
# ---------------------------------------------------------------------------
t_mesh_ssh_reachable() {
  local desc="mesh: peer 10.10.0.2 on wg0 reaches TCP/22 (SSH)"
  enforcement_guard "$desc" || return 0
  probes_reset
  local status
  status="$(tcp_status "$CLI_NS" "$MESH_CLI_IP" "$MESH_SUT_IP" "$PORT_SSH" 4)"
  if [[ "$status" == "open" ]]; then
    tap_ok "$desc"
  else
    tap_not_ok "$desc" "expected: open" "actual:   $status" \
      "if 'filtered', check @MESH_PEERS and the 6/minute SSH rate limit"
  fi
}

# ---------------------------------------------------------------------------
# Anti-spoof: a packet leaving wg0 with a source outside 10.10.0.0/24 must die.
# This is the regression test for BUG 1A (spoof rule placed after the jump was
# unreachable dead code).
# ---------------------------------------------------------------------------
t_mesh_spoof_blocked() {
  local desc="mesh: non-mesh source ($SPOOF_CLI_IP) on wg0 is blocked"
  enforcement_guard "$desc" || return 0
  probes_reset
  local status
  status="$(tcp_status "$CLI_NS" "$SPOOF_CLI_IP" "$SPOOF_SUT_IP" "$PORT_SSH" 3)"
  tap_assert "$desc" "filtered" "$status" \
    "a source outside @MESH_PEERS inside the tunnel must never reach a service"
}

t_mesh_spoof_counter() {
  local desc="mesh: nft counters confirm the spoofed wg0 packet was dropped"
  enforcement_guard "$desc" || return 0
  probes_reset
  tcp_status "$CLI_NS" "$SPOOF_CLI_IP" "$SPOOF_SUT_IP" "$PORT_SSH" 2 > /dev/null
  assert_dropped "$desc" "meshspoof"
}

# ---------------------------------------------------------------------------
# Established/related return path inside the mesh: connect, send a payload and
# require it echoed back.  Every packet after the SYN relies on
# "ct state { established, related } accept" inside mesh_input.
# ---------------------------------------------------------------------------
t_mesh_established_echo() {
  local desc="mesh: established/related return traffic passes (echo round-trip)"
  enforcement_guard "$desc" || return 0
  local status
  status="$(tcp_echo "$CLI_NS" "$MESH_CLI_IP" "$MESH_SUT_IP" "$PORT_SSH" "xnft-mesh-probe")"
  if [[ "$status" == "echo-ok" ]]; then
    tap_ok "$desc"
  else
    tap_not_ok "$desc" "expected: echo-ok" "actual:   $status" \
      "conntrack fast-path in mesh_input may be missing or SSH rate limit hit"
  fi
}
