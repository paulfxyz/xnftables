#!/usr/bin/env bash
# =============================================================================
# 30-antiscan.sh — stealth-scan and bogon enforcement (rules/10-antiscan.nft)
# =============================================================================
# Policy under test:
#   tcp flags == 0x0                        → XNFT-TCPFL-NULL   + drop
#   tcp flags & (fin|psh|urg) == fin|psh|urg → XNFT-TCPFL-XMAS   + drop
#   tcp flags & (syn|fin) == syn|fin         → XNFT-TCPFL-SYNFIN + drop
#   tcp flags & (fin|ack) == fin, ct new     → XNFT-TCPFL-FIN    + drop
#   iifname != wg0, ip saddr @BOGON_V4       → XNFT-BOGON        + drop
#
# The malformed segments are built by helpers/tcpflags.py (raw socket), because
# no socket API can emit them.  Verification is counter-based: the observation
# table proves the segment reached the host and did not survive the ruleset.
#
# NOTE on the bare-FIN case: depending on conntrack, a bare FIN for an unknown
# flow may be classified "invalid" and dropped by rules/30-established.nft
# instead of by the antiscan FIN rule.  Either way the packet must not survive,
# which is exactly what the test asserts.
#
# Sourced by run-tests.sh — do not execute directly.
# SPDX-License-Identifier: MIT
# =============================================================================

# Shared body for the four malformed-flag cases.
# _scan_case <probe-name> <flag-kind> <human description>
_scan_case() {
  local name="$1" kind="$2" desc="$3"
  enforcement_guard "$desc" || return 0
  probes_reset
  if ! scan_send "$CLI_NS" "$PUB_CLI_IP" "$PUB_SUT_IP" "$PORT_SCAN" "$kind" 3; then
    tap_skip "$desc" "no raw-packet tool available (python3/hping3/nmap)"
    return 0
  fi
  sleep 0.4
  assert_dropped "$desc" "$name"
}

t_scan_null_dropped() {
  _scan_case null null "antiscan: TCP NULL scan (no flags) is dropped"
}

t_scan_xmas_dropped() {
  _scan_case xmas xmas "antiscan: TCP XMAS scan (FIN+PSH+URG) is dropped"
}

t_scan_synfin_dropped() {
  _scan_case synfin synfin "antiscan: TCP SYN+FIN segment is dropped"
}

t_scan_fin_dropped() {
  _scan_case finscan fin "antiscan: bare TCP FIN (FIN scan) is dropped"
}

# ---------------------------------------------------------------------------
# Bogon source: 192.0.2.5 (TEST-NET-1, an element of @BOGON_V4) arriving on the
# public interface must be dropped before any service rule is consulted.
# ---------------------------------------------------------------------------
t_bogon_status_filtered() {
  local desc="antiscan: bogon source ($BOGON_CLI_IP) gets no response"
  enforcement_guard "$desc" || return 0
  local status
  status="$(tcp_status "$CLI_NS" "$BOGON_CLI_IP" "$BOGON_SUT_IP" "$PORT_SSH" 3)"
  tap_assert "$desc" "filtered" "$status"
}

t_bogon_counter_drop() {
  local desc="antiscan: nft counters confirm bogon-source packet was dropped"
  enforcement_guard "$desc" || return 0
  probes_reset
  tcp_status "$CLI_NS" "$BOGON_CLI_IP" "$BOGON_SUT_IP" "$PORT_SSH" 2 > /dev/null
  assert_dropped "$desc" "bogon"
}

# ---------------------------------------------------------------------------
# Log verification.  netfilter's log statement goes through printk, so the
# XNFT-* prefixes show up in the HOST kernel ring buffer (dmesg / journalctl -k)
# even when the rule fired inside a namespace.  Where dmesg is not readable
# (unprivileged container, kernel.dmesg_restrict=1) the test SKIPs rather than
# failing — the counter-based tests above already prove enforcement.
# ---------------------------------------------------------------------------
t_scan_logs_present() {
  local desc="observability: XNFT-TCPFL-* log entries appear in the kernel log"
  enforcement_guard "$desc" || return 0
  # Re-send both patterns so the log lines are recent.
  scan_send "$CLI_NS" "$PUB_CLI_IP" "$PUB_SUT_IP" "$PORT_SCAN" null 2 || true
  scan_send "$CLI_NS" "$PUB_CLI_IP" "$PUB_SUT_IP" "$PORT_SCAN" xmas 2 || true
  sleep 0.6
  local rc
  kernel_log_has "XNFT-TCPFL-" && rc=0 || rc=$?
  case "$rc" in
    0) tap_ok "$desc" ;;
    2) tap_skip "$desc" "kernel log not readable here (dmesg_restrict / no privileges)" ;;
    *) tap_not_ok "$desc" \
      "no XNFT-TCPFL-* entry found in the last 2000 dmesg lines" \
      "log statements may have been removed from rules/10-antiscan.nft" ;;
  esac
}
