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
#   2. Saves a snapshot of the currently-loaded ruleset as rollback
#   3. Applies the new config
#   4. Optionally: asks you to CONFIRM within N seconds, reverting if you
#      don't (remote-safe: if the new rules locked you out, you can't type,
#      so the revert happens and you get your session back)
#
# v3 SECURITY FIXES (found by the 5-model audit):
#   - Rollback snapshot moved from predictable, world-writable /tmp paths to
#     a root-only directory under /run (mode 700, mktemp).  A local user
#     could previously pre-create /tmp/xnft-rollback-<timestamp>.nft or
#     symlink it and have root clobber an arbitrary file (TOCTOU).
#   - Rollback now RESTORES instead of MERGES: "nft -f snapshot" on top of a
#     half-applied ruleset merges the two — the restore file now begins with
#     "flush ruleset" so the snapshot is applied atomically from a clean
#     slate (nft -f applies the whole file as one transaction).
#   - Auto-revert redesigned: v2 spawned a background sleeper whose kill
#     instructions printed the WRONG PID and which survived script exit.
#     v3 uses an interactive confirm (read -t): type "keep" to keep the new
#     rules; silence (or a severed SSH session) reverts automatically in the
#     same process.  No background job, nothing to hunt down and kill.
#
# Usage:
#   sudo ./scripts/reload.sh                        # standard reload
#   sudo ./scripts/reload.sh --confirm-timeout 60   # revert unless confirmed
#   sudo ./scripts/reload.sh --dry-run              # validate only, no apply
#
# Requirements: nft, bash >=4
# =============================================================================

set -euo pipefail

NFTABLES_CONF="${NFTABLES_CONF:-/etc/nftables/nftables.conf}"
RUN_DIR="/run/xnftables"
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
      [[ $CONFIRM_TIMEOUT =~ ^[0-9]+$ ]] || {
        echo "error: --confirm-timeout must be an integer (seconds)" >&2
        exit 1
      }
      shift 2
      ;;
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    -h | --help)
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
# Root-only directory under /run (tmpfs, cleared on boot) — never /tmp.
# The restore file starts with "flush ruleset" so applying it REPLACES the
# active ruleset atomically instead of merging into it.
install -d -m 700 "$RUN_DIR"
ROLLBACK_FILE=$(mktemp "$RUN_DIR/rollback.XXXXXX.nft")
chmod 600 "$ROLLBACK_FILE"

echo "==> Saving current ruleset to: $ROLLBACK_FILE"
{
  echo "flush ruleset"
  nft list ruleset
} > "$ROLLBACK_FILE"
echo "    OK — rollback snapshot saved"

rollback() {
  echo "==> Rolling back to previous ruleset..."
  if nft -f "$ROLLBACK_FILE"; then
    echo "==> Rollback successful."
  else
    echo "==> ROLLBACK FAILED — restore manually: nft -f $ROLLBACK_FILE" >&2
    exit 1
  fi
}

# ----------------------------------------------------------------------------
# Step 3: Apply the new ruleset
# ----------------------------------------------------------------------------
echo "==> Applying: $NFTABLES_CONF"
if ! nft -f "$NFTABLES_CONF"; then
  echo "ERROR: nft -f failed." >&2
  rollback
  exit 1
fi
echo "    OK — ruleset loaded"

# Show a brief summary
echo ""
echo "==> Active chains:"
nft list chains | grep -E "chain|hook" | sed 's/^/    /'

# ----------------------------------------------------------------------------
# Step 4: Optional confirm-or-revert (remote-safe testing)
# ----------------------------------------------------------------------------
# If the new rules cut your SSH session, you cannot type "keep" — the read
# times out (or stdin closes) and the previous ruleset is restored in this
# same process.  Reconnect and investigate.
if $AUTO_REVERT; then
  echo ""
  echo "==> CONFIRM REQUIRED: type 'keep' + Enter within ${CONFIRM_TIMEOUT}s"
  echo "    to keep the new rules. Anything else (or silence) reverts."
  answer=""
  if read -r -t "$CONFIRM_TIMEOUT" answer && [[ $answer == "keep" ]]; then
    echo "==> Confirmed — new ruleset kept."
  else
    echo ""
    echo "==> Not confirmed within ${CONFIRM_TIMEOUT}s."
    rollback
    exit 0
  fi
fi

echo ""
echo "Done. Validate with: sudo nft list ruleset"
echo "Rollback snapshot kept at: $ROLLBACK_FILE (cleared on reboot)"
