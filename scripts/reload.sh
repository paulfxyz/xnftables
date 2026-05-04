#!/usr/bin/env bash
# =============================================================================
# reload.sh — Safe nftables ruleset reload with dry-run and auto-rollback
# =============================================================================
# BUG FIX (13A): Never apply a new ruleset without dry-running first.
#
# The problem with "nft -f /etc/nftables/nftables.conf" directly:
#   Our config starts with "add table / delete table" (scoped flush).
#   If ANY subsequent include has a syntax error, nft aborts after the
#   flush — the machine is left with no firewall rules.  Completely open.
#
# This script:
#   1. Validates the new config with "nft -c" (dry-run, no state change)
#   2. Saves a dump of the currently-loaded ruleset as rollback
#   3. Applies the new config
#   4. Optionally: waits 60 seconds and reverts automatically
#      (useful when testing rules on a remote server — prevents lockout)
#
# Usage:
#   sudo ./scripts/reload.sh                   # standard reload
#   sudo ./scripts/reload.sh --confirm-timeout 60  # auto-revert after 60s
#   sudo ./scripts/reload.sh --dry-run         # validate only, no apply
#
# Requirements: nft, bash >=4
# =============================================================================

set -euo pipefail

NFTABLES_CONF="${NFTABLES_CONF:-/etc/nftables/nftables.conf}"
ROLLBACK_FILE="/tmp/xnft-rollback-$(date +%s).nft"
AUTO_REVERT=false
CONFIRM_TIMEOUT=0
DRY_RUN=false

# ----------------------------------------------------------------------------
# Argument parsing
# ----------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --confirm-timeout)
            AUTO_REVERT=true
            CONFIRM_TIMEOUT="${2:?--confirm-timeout requires a value in seconds}"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        -h|--help)
            sed -n '/^# Usage:/,/^# Requirements:/p' "$0"
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

# ----------------------------------------------------------------------------
# Require root
# ----------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo "error: must run as root (try: sudo $0)" >&2
    exit 1
fi

# ----------------------------------------------------------------------------
# Check config file exists
# ----------------------------------------------------------------------------
if [[ ! -f "$NFTABLES_CONF" ]]; then
    echo "error: config not found: $NFTABLES_CONF" >&2
    exit 1
fi

# ----------------------------------------------------------------------------
# Step 1: Dry-run validation
# ----------------------------------------------------------------------------
echo "==> Validating config (dry-run): $NFTABLES_CONF"
if ! nft -c -f "$NFTABLES_CONF"; then
    echo "ABORT: Syntax errors detected. No rules were changed." >&2
    exit 1
fi
echo "    OK — syntax valid"

if $DRY_RUN; then
    echo "==> --dry-run: exiting without applying."
    exit 0
fi

# ----------------------------------------------------------------------------
# Step 2: Save current ruleset for rollback
# ----------------------------------------------------------------------------
echo "==> Saving current ruleset to: $ROLLBACK_FILE"
nft list ruleset > "$ROLLBACK_FILE"
echo "    OK — rollback saved"

# ----------------------------------------------------------------------------
# Step 3: Apply the new ruleset
# ----------------------------------------------------------------------------
echo "==> Applying: $NFTABLES_CONF"
if ! nft -f "$NFTABLES_CONF"; then
    echo "ERROR: nft -f failed. Attempting rollback..." >&2
    nft -f "$ROLLBACK_FILE" && echo "    Rollback successful." || echo "    ROLLBACK FAILED — check $ROLLBACK_FILE manually" >&2
    exit 1
fi
echo "    OK — ruleset loaded"

# Show a brief summary
echo ""
echo "==> Active chains:"
nft list chains | grep -E "chain|hook" | sed 's/^/    /'

# ----------------------------------------------------------------------------
# Step 4: Optional auto-revert (remote-safe testing)
# ----------------------------------------------------------------------------
if $AUTO_REVERT; then
    echo ""
    echo "==> AUTO-REVERT enabled: will revert to previous ruleset in ${CONFIRM_TIMEOUT}s"
    echo "    To keep the new rules, run in another terminal:"
    echo "    kill \$\$ (PID $$) or: sudo kill $(cat /tmp/xnft-revert.pid 2>/dev/null || echo '??')"
    echo ""

    # Write PID for the cancel instruction above
    echo $$ > /tmp/xnft-revert.pid

    # Sleep in background, then revert
    (
        sleep "$CONFIRM_TIMEOUT"
        echo "==> Auto-revert triggered after ${CONFIRM_TIMEOUT}s"
        nft -f "$ROLLBACK_FILE" && echo "==> Reverted to previous ruleset" || echo "==> REVERT FAILED" >&2
    ) &

    echo "    Revert scheduled (background PID: $!)"
    echo "    Press Ctrl-C or 'sudo kill $!' to cancel the revert."
fi

echo ""
echo "Done. Validate with: sudo nft list ruleset"
