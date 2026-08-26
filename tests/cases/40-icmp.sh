#!/usr/bin/env bash
# =============================================================================
# 40-icmp.sh — controlled ICMP policy (rules/60-icmp.nft)
# =============================================================================
# Policy under test:
#   echo-request from @MESH_PEERS   → accept (rate-limited 10/second)
#   echo-request from anywhere else → drop (never confirm the host exists)
#
# The probe presents itself as "public" (45.33.0.2 on eth0) or as a "mesh peer"
# (10.10.0.2 on wg0) by choosing the source address.  ping(8) is used when
# available, otherwise helpers/icmpecho.py (raw ICMP socket) takes over.
#
# Sourced by run-tests.sh — do not execute directly.
# SPDX-License-Identifier: MIT
# =============================================================================

t_icmp_public_no_reply() {
  local desc="icmp: echo-request from the public side gets no reply"
  enforcement_guard "$desc" || return 0
  if ! icmp_tool_available; then
    tap_skip "$desc" "no ICMP probe tool (ping / python3) available"
    return 0
  fi
  local rc
  icmp_ping "$CLI_NS" "$PUB_CLI_IP" "$PUB_SUT_IP" 2 && rc=0 || rc=$?
  case "$rc" in
    1) tap_ok "$desc" ;;
    0) tap_not_ok "$desc" "the host replied to a public ping — it is discoverable" ;;
    *) tap_skip "$desc" "ICMP probe could not run (rc=$rc)" ;;
  esac
}

t_icmp_public_counter_drop() {
  local desc="icmp: nft counters confirm public echo-request was dropped"
  enforcement_guard "$desc" || return 0
  if ! icmp_tool_available; then
    tap_skip "$desc" "no ICMP probe tool (ping / python3) available"
    return 0
  fi
  probes_reset
  icmp_ping "$CLI_NS" "$PUB_CLI_IP" "$PUB_SUT_IP" 2 || true
  sleep 0.3
  assert_dropped "$desc" "icmp_pub"
}

t_icmp_mesh_allowed() {
  local desc="icmp: echo-request from mesh peer 10.10.0.2 is answered"
  enforcement_guard "$desc" || return 0
  if ! icmp_tool_available; then
    tap_skip "$desc" "no ICMP probe tool (ping / python3) available"
    return 0
  fi
  probes_reset
  local rc
  icmp_ping "$CLI_NS" "$MESH_CLI_IP" "$MESH_SUT_IP" 2 && rc=0 || rc=$?
  case "$rc" in
    0) tap_ok "$desc" ;;
    1) tap_not_ok "$desc" \
      "mesh ping unanswered — check the @MESH_PEERS echo-request rule in rules/60-icmp.nft" \
      "post counter: $(probe_count post icmp_mesh)" ;;
    *) tap_skip "$desc" "ICMP probe could not run (rc=$rc)" ;;
  esac
}
