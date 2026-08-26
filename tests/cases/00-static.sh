#!/usr/bin/env bash
# =============================================================================
# 00-static.sh — structural tests: does the ruleset parse, load, and describe
#                the policy we think it describes?
# =============================================================================
# These run first because everything else is meaningless if the ruleset does not
# load.  They are cheap and catch the most common regression: someone edits a
# rules/*.nft file and breaks a set, a chain name, or a log prefix that the
# monitoring tooling greps for.
#
# Sourced by run-tests.sh — do not execute directly.
# SPDX-License-Identifier: MIT
# =============================================================================

# ---------------------------------------------------------------------------
# 1. Syntax: the full ruleset must pass a dry-run (nft -c -f).
# ---------------------------------------------------------------------------
t_syntax_dryrun() {
  local desc="syntax: full ruleset passes nft -c dry-run"
  local out rc
  if ! have nft; then
    tap_skip "$desc" "nft binary not installed"
    return 0
  fi
  out="$(dryrun_ruleset)" && rc=0 || rc=$?
  if ((rc == 0)); then
    tap_ok "$desc"
    return 0
  fi

  # Distinguish "your kernel cannot do this" from "your ruleset is wrong".
  # On a kernel without nf_tables inet support every statement fails with
  # "Operation not supported" and a cascade of "No such file or directory"
  # follow-ups.  Filter that noise out; anything left is a real ruleset error
  # (a bad set element, a typo, an unknown match) and must FAIL, not SKIP.
  local kernel_noise='Operation not supported|No such file or directory|did you mean table'
  local real_errors
  real_errors="$(printf '%s\n' "$out" | grep -F 'Error:' | grep -Ev "$kernel_noise" || true)"
  if [[ -n "$real_errors" ]]; then
    # Include the offending source lines to make the failure actionable.
    tap_not_ok "$desc" "nft -c reported ruleset errors:" \
      "$(printf '%s\n' "$real_errors" | head -n 6)" \
      "full output: $(printf '%s' "$out" | grep -c 'Error:') error line(s)"
    return 0
  fi
  if printf '%s' "$out" | grep -q "Operation not supported"; then
    tap_skip "$desc" "kernel has no nf_tables inet support (see README caveats)"
    return 0
  fi
  tap_not_ok "$desc" "nft -c failed:" "$(printf '%s' "$out" | head -n 12)"
}

# ---------------------------------------------------------------------------
# 2. Load: the ruleset must commit into the kernel inside the test namespace.
# ---------------------------------------------------------------------------
t_ruleset_loads() {
  local desc="load: ruleset commits into the test namespace"
  enforcement_guard "$desc" || return 0
  if [[ "$RULESET_LOADED" == "1" ]]; then
    tap_ok "$desc"
    return 0
  fi
  tap_not_ok "$desc" "nft -f failed:" "$(printf '%s' "${RULESET_LOAD_OUTPUT:-}" | head -n 12)"
}

# ---------------------------------------------------------------------------
# 3. Chains: the five chains the policy depends on must exist.
# ---------------------------------------------------------------------------
t_chains_present() {
  local desc="structure: input/forward/output/mesh_input/services chains exist"
  ruleset_guard "$desc" || return 0
  local dump missing=() chain
  dump="$(nft_sut list table inet filter 2> /dev/null || true)"
  for chain in input forward output mesh_input services; do
    printf '%s\n' "$dump" | grep -qE "chain ${chain} \{" || missing+=("$chain")
  done
  if ((${#missing[@]} == 0)); then
    tap_ok "$desc"
  else
    tap_not_ok "$desc" "missing chains: ${missing[*]}"
  fi
}

# ---------------------------------------------------------------------------
# 4. Named sets: MESH_PEERS / ADMIN_ALLOWLIST / BOGON_V4 with expected content.
# ---------------------------------------------------------------------------
t_sets_present() {
  local desc="structure: MESH_PEERS, ADMIN_ALLOWLIST, BOGON_V4 sets defined"
  ruleset_guard "$desc" || return 0
  local dump problems=()
  dump="$(nft_sut list table inet filter 2> /dev/null || true)"
  printf '%s\n' "$dump" | grep -q "set MESH_PEERS" || problems+=("MESH_PEERS missing")
  printf '%s\n' "$dump" | grep -q "set ADMIN_ALLOWLIST" || problems+=("ADMIN_ALLOWLIST missing")
  printf '%s\n' "$dump" | grep -q "set BOGON_V4" || problems+=("BOGON_V4 missing")
  # The mesh CIDR is the anchor of the whole policy — assert it explicitly.
  nft_sut list set inet filter MESH_PEERS 2> /dev/null | grep -q "10.10.0.0/24" ||
    problems+=("MESH_PEERS does not contain 10.10.0.0/24")
  # BOGON_V4 must at least cover the documentation range we probe with.
  nft_sut list set inet filter BOGON_V4 2> /dev/null | grep -q "192.0.2.0/24" ||
    problems+=("BOGON_V4 does not contain 192.0.2.0/24")
  if ((${#problems[@]} == 0)); then
    tap_ok "$desc"
  else
    tap_not_ok "$desc" "${problems[@]}"
  fi
}

# ---------------------------------------------------------------------------
# 5. Policies: deny-all really means policy drop on input and forward.
# ---------------------------------------------------------------------------
t_base_policies() {
  local desc="policy: input drop, forward drop, output accept"
  ruleset_guard "$desc" || return 0
  local dump problems=()
  dump="$(nft_sut list table inet filter 2> /dev/null || true)"
  printf '%s\n' "$dump" | grep -A2 "chain input {" | grep -q "policy drop" ||
    problems+=("input chain is not policy drop")
  printf '%s\n' "$dump" | grep -A2 "chain forward {" | grep -q "policy drop" ||
    problems+=("forward chain is not policy drop")
  printf '%s\n' "$dump" | grep -A2 "chain output {" | grep -q "policy accept" ||
    problems+=("output chain is not policy accept")
  if ((${#problems[@]} == 0)); then
    tap_ok "$desc"
  else
    tap_not_ok "$desc" "${problems[@]}"
  fi
}

# ---------------------------------------------------------------------------
# 6. Log prefixes: the monitoring tooling (scripts/monitor) greps for XNFT-*.
#    Renaming a prefix silently blinds the alerting, so pin the important ones.
# ---------------------------------------------------------------------------
t_log_prefixes() {
  local desc="observability: expected XNFT-* log prefixes present in ruleset"
  ruleset_guard "$desc" || return 0
  local dump missing=() prefix
  dump="$(nft_sut list table inet filter 2> /dev/null || true)"
  for prefix in \
    "XNFT-BOGON: " \
    "XNFT-TCPFL-NULL: " \
    "XNFT-TCPFL-XMAS: " \
    "XNFT-TCPFL-SYNFIN: " \
    "XNFT-MESH-SPOOF: " \
    "XNFT-MESH-INVALID: " \
    "XNFT-SSH-RATELIMIT: " \
    "XNFT-WG-RATELIMIT: " \
    "XNFT-ICMP4-DROP: " \
    "XNFT-DROP: " \
    "XNFT-FWD-DROP: "; do
    printf '%s\n' "$dump" | grep -qF "prefix \"$prefix\"" || missing+=("$prefix")
  done
  if ((${#missing[@]} == 0)); then
    tap_ok "$desc"
  else
    tap_not_ok "$desc" "missing log prefixes: ${missing[*]}"
  fi
}
