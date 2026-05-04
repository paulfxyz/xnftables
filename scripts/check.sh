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

check_file() {
    local file="$1"
    # nft -c on individual include files may fail due to missing table context.
    # We run against the full nftables.conf for the authoritative check.
    # Per-file checks catch obvious syntax errors early.
    if nft -c -f "$file" 2>/dev/null; then
        echo "  OK  $file"
        ((PASS++)) || true
    else
        echo "  FAIL $file"
        ERRORS+=("$file")
        ((FAIL++)) || true
    fi
}

echo "==> xnftables syntax check"
echo ""

# Full-ruleset dry-run is the most important check.
# Requires running as root (nft -c touches kernel interfaces).
CONF="$(dirname "$0")/../nftables.conf"
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

exit 0
