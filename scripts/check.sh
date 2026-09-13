#!/usr/bin/env bash
# =============================================================================
# check.sh — Validate all nft rule files (use as pre-commit hook or in CI)
# =============================================================================
# Runs nft -c (dry-run) on every .nft file and the main nftables.conf.
# Exit code 0 = all valid. Exit code 1 = at least one error.
#
# Install as a git pre-commit hook:
#   cp scripts/check.sh .git/hooks/pre-commit
#   chmod +x .git/hooks/pre-commit
#
# Use in GitHub Actions (see .github/workflows/validate.yml).
#
# Note: nft -c validates syntax but cannot fully simulate runtime state
# (named sets populated by other includes, meter state, etc.).
# The reload.sh script performs the definitive test against live state.
# =============================================================================

set -euo pipefail

PASS=0
FAIL=0
ERRORS=()

# Note: individual rule files are NOT checked in isolation — they are include
# fragments that reference sets/chains defined in 00-tables.nft, so nft -c on
# a single file always fails with missing-context errors. The full-ruleset
# dry-run below is the only meaningful syntax check.

echo "==> xnftables syntax check"
echo ""

# Full-ruleset dry-run is the most important check.
# Requires running as root (nft -c touches kernel interfaces).
CONF="$(dirname "$0")/../nftables.conf"
SKIPPED_ROOT_CHECK=false
if [[ -f "$CONF" ]]; then
  if [[ $EUID -eq 0 ]]; then
    echo "--- Full ruleset (nftables.conf) ---"
    if nft -c -f "$CONF"; then
      echo "  OK  nftables.conf (full ruleset)"
      ((PASS++)) || true
    else
      echo "  FAIL nftables.conf (full ruleset)"
      ERRORS+=("nftables.conf")
      ((FAIL++)) || true
    fi
  else
    echo "--- Skipping full ruleset check (requires root) ---"
    echo "    Run: sudo ./scripts/check.sh for complete validation"
    SKIPPED_ROOT_CHECK=true
  fi
fi

echo ""
echo "==> Results: ${PASS} passed, ${FAIL} failed"

if [[ ${#ERRORS[@]} -gt 0 ]]; then
  echo ""
  echo "Files with errors:"
  for f in "${ERRORS[@]}"; do
    echo "  - $f"
  done
  exit 1
fi

# BUG FIX (v4-06) — vacuous pass masqueraded as success:
#   When not run as root, the script performed ZERO checks (PASS=0, FAIL=0),
#   printed "Results: 0 passed, 0 failed", and exited 0 — identical to a
#   real all-green run. Installed as ".git/hooks/pre-commit" per this
#   script's own header instructions, every commit from a non-root dev
#   account silently skipped syntax validation entirely while still showing
#   a passing hook, and CI would only catch it if the runner happened to be
#   root. Fix: a run that skipped the only real check because it lacks root
#   is NOT a pass — exit 2 (distinct from the FAIL=1 exit code) so hooks/CI
#   treat "never actually checked" differently from "checked and clean".
if $SKIPPED_ROOT_CHECK && [[ ${#ERRORS[@]} -eq 0 ]]; then
  echo ""
  echo "NOTE: no syntax check actually ran (needs root) — not a verified pass."
  echo "      Re-run with sudo, or rely on CI's root-privileged run."
  exit 2
fi

exit 0
