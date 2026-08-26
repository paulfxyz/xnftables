#!/usr/bin/env bash
# =============================================================================
# 50-loopback.sh — loopback must remain completely unaffected (05-loopback.nft)
# =============================================================================
# A deny-all policy that forgets loopback breaks local daemons in confusing
# ways: DNS stubs, database sockets over 127.0.0.1, health checks, systemd
# services.  The rule "iifname lo accept" must therefore stay first and
# unconditional, and these tests prove it from inside the SUT namespace.
#
# Sourced by run-tests.sh — do not execute directly.
# SPDX-License-Identifier: MIT
# =============================================================================

t_loopback_tcp_open() {
  local desc="loopback: TCP service on 127.0.0.1:$PORT_LOOPBACK is reachable"
  enforcement_guard "$desc" || return 0
  probes_reset
  local status
  status="$(tcp_status "$SUT_NS" 127.0.0.1 127.0.0.1 "$PORT_LOOPBACK" 3)"
  if [[ "$status" == "open" ]]; then
    tap_ok "$desc"
  else
    tap_not_ok "$desc" "expected: open" "actual:   $status" \
      "the loopback accept rule in rules/05-loopback.nft may be missing or ordered too late"
  fi
}

t_loopback_ping_ok() {
  local desc="loopback: ping to 127.0.0.1 still works"
  enforcement_guard "$desc" || return 0
  if ! icmp_tool_available; then
    tap_skip "$desc" "no ICMP probe tool (ping / python3) available"
    return 0
  fi
  local rc
  icmp_ping "$SUT_NS" - 127.0.0.1 2 && rc=0 || rc=$?
  case "$rc" in
    0) tap_ok "$desc" ;;
    1) tap_not_ok "$desc" "loopback ICMP was blocked — the ICMP rules are too broad" ;;
    *) tap_skip "$desc" "ICMP probe could not run (rc=$rc)" ;;
  esac
}
