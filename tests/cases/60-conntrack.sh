#!/usr/bin/env bash
# =============================================================================
# 60-conntrack.sh — established/related on the PUBLIC interface (30-established)
# =============================================================================
# The deny-all input policy would break every locally-initiated connection
# (package updates, WireGuard handshakes to other peers, monitoring pushes) if
# the conntrack fast-path were missing: the SYN/ACK coming back is an *inbound*
# packet on the public interface.
#
# Test: the SUT namespace connects OUT to a listener in the client namespace and
# requires a payload echo.  Every returning packet depends on
# "ct state { established, related } accept" in rules/30-established.nft.
#
# Sourced by run-tests.sh — do not execute directly.
# SPDX-License-Identifier: MIT
# =============================================================================

t_public_established_return() {
  local desc="conntrack: outbound connection's return traffic is accepted (public iface)"
  enforcement_guard "$desc" || return 0
  local status
  status="$(tcp_echo "$SUT_NS" "$PUB_SUT_IP" "$PUB_CLI_IP" "$PORT_CLI_ECHO" "xnft-ct-probe")"
  if [[ "$status" == "echo-ok" ]]; then
    tap_ok "$desc"
  else
    tap_not_ok "$desc" "expected: echo-ok" "actual:   $status" \
      "check the established/related accept rule in rules/30-established.nft"
  fi
}
