#!/usr/bin/env bash
# =============================================================================
# xnft-monitor.sh — Weekday security monitor for xnftables
# =============================================================================
# Scans nftables changelog, netfilter mailing list, and kernel.org release
# notes for new CVEs, netfilter patches, or nftables API changes that could
# affect this ruleset.  Flags security-relevant or breaking findings only.
# Optionally posts a digest to Slack, Discord, a Notion page, or email.
#
# USAGE
# -----
#   ./xnft-monitor.sh [--dry-run] [--notify slack|discord|email|notion|all|none]
#                     [--help]
#
#   --notify <channel>   Where to send HIGH/CRITICAL findings.  Overrides the
#                        NOTIFY_CHANNEL environment variable.  Also accepts
#                        --notify=<channel>.  Default: all.
#   --dry-run            Run every check and print the digest, but never send a
#                        notification.  Identical to DRY_RUN=1 in the env; the
#                        flag wins over whatever .env says.
#   --help               Print this usage block and exit 0.
#
# CRON EXAMPLE (weekdays at 08:00 local time)
# -------------------------------------------
#   0 8 * * 1-5 /opt/xnftables/scripts/monitor/xnft-monitor.sh >> /var/log/xnft-monitor.log 2>&1
#
# SETUP
# -----
#   1. Copy .env.example to .env and fill in your tokens.  Because this script
#      *sources* .env (shell code!) it refuses to read a .env that is not owned
#      by root or by the invoking user, or that is group/world-writable:
#          umask 077 && cp .env.example .env   # creates 0600
#          chmod 600 .env                      # if it already exists
#   2. chmod +x xnft-monitor.sh
#   3. Install dependencies: curl, jq
#   4. Add to crontab (see above) or deploy as a systemd timer
#      (see monitor.timer and monitor.service in this directory)
#
# ENVIRONMENT VARIABLES (set in .env or export before running)
# ------------------------------------------------------------
#   SLACK_WEBHOOK_URL     Slack incoming webhook URL
#   DISCORD_WEBHOOK_URL   Discord webhook URL
#   NOTIFY_EMAIL          Email address for findings (requires mail/sendmail)
#   NOTIFY_FROM_EMAIL     Sender address for email
#   NOTION_API_TOKEN      Notion integration token
#   NOTION_DATABASE_ID    Notion database ID to write findings to
#   NVD_API_KEY           Optional NVD API key (raises the rate limit)
#   GITHUB_REPO           e.g. "paulfxyz/xnftables" (used in finding links)
#   NOTIFY_CHANNEL        Default channel when --notify is not given
#   DRY_RUN               Set to "1" to print findings without notifying
#   XNFT_STATE_DIR        Directory for the findings JSON and the version
#                         state file.  When unset the historical layout is
#                         kept: findings in /tmp, state next to this script.
#                         The systemd unit sets it to /var/lib/xnft-monitor.
#
# SECRET HANDLING
# ---------------
# Tokens and webhook URLs are *never* passed as curl command-line arguments,
# because /proc/<pid>/cmdline is world-readable: any local user could read the
# Notion token or the Slack webhook out of the running process.  Instead every
# request URL and Authorization header is fed to `curl --config -` on stdin,
# which curl reads before it does anything else.  The JSON body stays on argv
# (it contains no secrets) so payloads remain visible for debugging.
#
# WHAT IT CHECKS
# --------------
#   1. kernel.org — latest stable kernel version (detect new releases)
#   2. netfilter.org — nftables release page (detect new nft versions)
#   3. Netfilter mailing list archive (lists.netfilter.org) — subject scan
#      for keywords: CVE, fix, regression, crash, panic, bypass, UAF, heap
#   4. NVD / NIST CVE feed — query for "nftables" and "netfilter" CVEs
#      published in the last 7 days
#   5. kernel.org git log for net/netfilter — scan recent commit subjects
#      for security-relevant keywords
#
# RULE FILE MAPPING
# -----------------
# When a finding matches a keyword, the script maps it to the affected rule
# file so the notification is actionable:
#
#   keyword              → rule file
#   ────────────────────────────────────────────────────────────────
#   conntrack / ct       → rules/30-established.nft
#   wireguard / wg       → rules/50-vpn-endpoint.nft + rules/20-mesh.nft
#   icmp / icmpv6        → rules/60-icmp.nft
#   meter / rate limit   → rules/50-vpn-endpoint.nft + rules/40-services.nft
#   set / map / element  → rules/00-tables.nft
#   forward / routing    → rules/70-logging.nft
#   log / nflog          → rules/70-logging.nft
#   nat / masquerade     → nftables.conf (flush scope)
#   flag / tcp           → rules/10-antiscan.nft
#   bogon / martian      → rules/10-antiscan.nft
#   fragment / frag      → rules/10-antiscan.nft
#
# OUTPUT
# ------
# Each run writes a JSON findings file to
# ${XNFT_STATE_DIR:-/tmp}/xnft-findings-YYYY-MM-DD.json and a human-readable
# digest to stdout.  Only findings with severity HIGH or CRITICAL trigger
# notifications (Notion also receives MEDIUM).
# =============================================================================

set -euo pipefail

# ----------------------------------------------------------------------------
# Utilities (defined first: the .env guard below already needs err())
# ----------------------------------------------------------------------------
TODAY="$(date +%Y-%m-%d)"
LOG_PREFIX="[xnft-monitor ${TODAY}]"

# log() writes to stdout, err() to stderr.  IMPORTANT: any function whose
# stdout is captured with $( ) must send its log lines to stderr, otherwise the
# log text ends up inside the captured value.  That exact mistake used to make
# `findings_json=$(build_report)` return "…Total findings: 3[{…}]", which then
# made jq fail and — under `set -e` — killed the run *before* a single
# notification was attempted.  See build_report().
log() { echo "${LOG_PREFIX} $*"; }
err() { echo "${LOG_PREFIX} ERROR: $*" >&2; }

usage() {
  # Reprint the USAGE block from this file's own header, so help can never
  # drift away from the documented interface.
  sed -n '/^# USAGE$/,/^# CRON EXAMPLE/p' "${BASH_SOURCE[0]}" |
    sed -e '$d' -e 's/^# \{0,1\}//'
}

require() {
  for cmd in "$@"; do
    command -v "$cmd" > /dev/null 2>&1 || {
      err "Required command not found: $cmd"
      exit 1
    }
  done
}

# Escape a value for use inside a curl config file:  key = "value"
# Backslashes first, then double quotes, so nothing can break out of the
# quoted string and inject an extra curl option.
config_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  printf '%s' "${s//\"/\\\"}"
}

# ----------------------------------------------------------------------------
# Load .env — but only if it is safe to execute
# ----------------------------------------------------------------------------
# `source` runs arbitrary shell code with this script's privileges (root, under
# the systemd unit).  A .env that anyone but root/the invoking user can write
# is therefore a root-code-execution primitive, and `cp .env.example .env`
# under the default umask produces a world-*readable* secret file too.  So:
# check ownership and the write bits before sourcing, and refuse loudly.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-${SCRIPT_DIR}/.env}"

load_env_file() {
  local file="$1" owner mode
  # %u = numeric owner uid, %a = octal permission bits
  if ! read -r owner mode < <(stat -c '%u %a' -- "$file"); then
    err "cannot stat $file"
    exit 1
  fi
  # Owner must be root (0) or the uid running this script.
  if [[ "$owner" != "0" && "$owner" != "$(id -u)" ]]; then
    err "refusing to source $file: owned by uid $owner, expected 0 or $(id -u)."
    err "Fix with: sudo chown root:root '$file' && sudo chmod 600 '$file'"
    exit 1
  fi
  # Reject group- or world-writable files (mode may be 3 or 4 digits).
  local perm="${mode: -3}"
  local group_w="${perm:1:1}" other_w="${perm:2:1}"
  if ((group_w % 4 >= 2 || other_w % 4 >= 2)); then
    err "refusing to source $file: mode $mode is group/world-writable."
    err "Fix with: chmod 600 '$file'"
    exit 1
  fi
  # Warn (but continue) when secrets are merely readable by others.
  if ((perm % 100 != 0)); then
    err "warning: $file is readable by group/other (mode $mode); chmod 600 recommended"
  fi
  # shellcheck source=/dev/null
  source "$file"
}

[[ -f "$ENV_FILE" ]] && load_env_file "$ENV_FILE"

# ----------------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------------
require curl jq

DRY_RUN="${DRY_RUN:-0}"
# Channel default resolution order: --notify flag (parsed below) >
# NOTIFY_CHANNEL from the environment/.env > "all".
NOTIFY_CHANNEL="${NOTIFY_CHANNEL:-all}"
GITHUB_REPO="${GITHUB_REPO:-paulfxyz/xnftables}"

# --- CLI parsing -------------------------------------------------------------
# A real while/case parser.  The old code did NOTIFY_CHANNEL="${1:-}", so the
# documented `--notify slack` stored the literal string "--notify", matched no
# case arm, and the script exited 0 having sent nothing.  Unknown arguments and
# unknown channels now exit non-zero so cron/systemd surface the failure.
while [[ $# -gt 0 ]]; do
  case "$1" in
    --notify)
      if [[ $# -lt 2 || -z "$2" ]]; then
        err "--notify requires a channel: slack|discord|email|notion|all|none"
        exit 2
      fi
      NOTIFY_CHANNEL="$2"
      shift 2
      ;;
    --notify=*)
      NOTIFY_CHANNEL="${1#*=}"
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    *)
      err "Unknown argument: $1"
      usage >&2
      exit 2
      ;;
  esac
done

case "$NOTIFY_CHANNEL" in
  slack | discord | email | notion | all | none) ;;
  *)
    err "Unknown channel: $NOTIFY_CHANNEL. Use slack|discord|email|notion|all|none"
    exit 2
    ;;
esac

# --- State locations --------------------------------------------------------
# XNFT_STATE_DIR lets the systemd unit keep everything under
# StateDirectory=xnft-monitor (/var/lib/xnft-monitor, 0700) instead of a
# world-writable /tmp path that root would otherwise open by predictable name.
# Unset ⇒ the historical layout is preserved for ad-hoc/cron use.
if [[ -n "${XNFT_STATE_DIR:-}" ]]; then
  STATE_DIR="$XNFT_STATE_DIR"
  # -m with -p would only apply to the deepest component, so chmod separately.
  if ! mkdir -p "$STATE_DIR"; then
    err "cannot create state directory $STATE_DIR"
    exit 1
  fi
  chmod 0700 "$STATE_DIR" || err "warning: could not chmod 0700 $STATE_DIR"
  FINDINGS_FILE="${STATE_DIR}/xnft-findings-${TODAY}.json"
  STATE_FILE="${STATE_DIR}/.last-seen-versions"
else
  STATE_DIR="/tmp"
  FINDINGS_FILE="/tmp/xnft-findings-${TODAY}.json"
  STATE_FILE="${SCRIPT_DIR}/.last-seen-versions"
fi

# Every write to those two paths goes through write_file(), which creates a
# private temp file in the same directory and rename(2)s it into place.  rename
# replaces a symlink instead of following it, so a pre-planted
# /tmp/xnft-findings-<date>.json -> /etc/shadow symlink cannot trick root into
# truncating another file, and readers never see a half-written JSON document.
write_file() {
  local dest="$1" tmp
  tmp="$(mktemp "$(dirname "$dest")/.xnft-monitor.XXXXXX")" || return 1
  chmod 600 "$tmp"
  cat > "$tmp"
  mv -f "$tmp" "$dest"
}

# Create the state file if missing (600: it is not secret, but it is ours).
if [[ ! -f "$STATE_FILE" ]]; then
  : | write_file "$STATE_FILE" || {
    err "cannot create state file $STATE_FILE"
    exit 1
  }
fi

# Replace one KEY=VALUE line in the state file atomically (the old code used
# `sed -i` plus an append, which is two non-atomic steps and loses the file on
# a read-only filesystem halfway through).
state_set() {
  local key="$1" value="$2" current
  current="$(grep -v "^${key}=" "$STATE_FILE" || true)"
  printf '%s%s=%s\n' "${current:+$current$'\n'}" "$key" "$value" | write_file "$STATE_FILE"
}

state_get() {
  grep "^$1=" "$STATE_FILE" 2> /dev/null | cut -d= -f2 || true
}

# Security keyword patterns (case-insensitive)
SECURITY_KEYWORDS="CVE|use.after.free|UAF|heap.overflow|buffer.overflow|out.of.bounds|OOB|privilege.escal|bypass|crash|panic|regression|null.deref|memory.leak|fix.*exploit|RCE|remote.code"
BREAKING_KEYWORDS="API.change|ABI.break|incompatible|deprecated|removed|rename|behaviour.change|behavior.change|nft_.*_ops|hook.priority"

# Rule file mapping (keyword → file)
declare -A RULE_MAP=(
  ["conntrack"]="rules/30-established.nft"
  [" ct "]="rules/30-established.nft"
  ["wireguard"]="rules/50-vpn-endpoint.nft, rules/20-mesh.nft"
  ["icmp"]="rules/60-icmp.nft"
  ["meter"]="rules/50-vpn-endpoint.nft, rules/40-services.nft"
  ["rate.limit"]="rules/50-vpn-endpoint.nft, rules/40-services.nft"
  ["set.*element"]="rules/00-tables.nft"
  ["forward"]="rules/70-logging.nft"
  ["nat"]="nftables.conf"
  ["tcp.*flag"]="rules/10-antiscan.nft"
  ["fragment"]="rules/10-antiscan.nft"
  ["bogon"]="rules/10-antiscan.nft"
  ["log"]="rules/70-logging.nft"
)

findings=()

add_finding() {
  local severity="$1" # CRITICAL HIGH MEDIUM LOW INFO
  local source="$2"
  local title="$3"
  local url="$4"
  local rule_files="$5"
  local body="$6"

  findings+=("$(
    jq -nc \
      --arg s "$severity" \
      --arg src "$source" \
      --arg t "$title" \
      --arg u "$url" \
      --arg r "$rule_files" \
      --arg b "$body" \
      --arg d "$TODAY" \
      '{severity:$s, source:$src, title:$t, url:$u, rule_files:$r, body:$b, date:$d}'
  )")
}

map_rule_files() {
  local text="${1,,}" # lowercase
  local matched=""
  for kw in "${!RULE_MAP[@]}"; do
    if echo "$text" | grep -qiE "$kw"; then
      matched="${matched:+$matched, }${RULE_MAP[$kw]}"
    fi
  done
  echo "${matched:-rules/ (review manually)}"
}

# ----------------------------------------------------------------------------
# Network helpers — every call is bounded and fault-tolerant
# ----------------------------------------------------------------------------
# Shared curl options.  --max-time/--connect-timeout stop a hung upstream from
# pinning the oneshot service in "activating" forever (which silently skips all
# later timer runs); --proto '=https' refuses a plaintext downgrade;
# --max-filesize caps how much HTML a compromised mirror can feed our greps.
CURL_COMMON=(
  --silent --show-error --fail
  --connect-timeout 5 --max-time 25
  --retry 2 --retry-delay 3
  --proto '=https' --tlsv1.2
  --max-filesize 8000000
)

# GET a URL.  The URL travels on curl's stdin config, not argv, so the same
# helper can carry a secret (NVD_API_KEY) without leaking it to /proc.
# Returns non-zero on any failure; callers must handle that (see the
# `if ! page=$(http_get …)` pattern below) — a bare `page=$(http_get …)` would
# abort the whole run under `set -e`.
http_get() {
  local url="$1" config
  config="url = \"$(config_escape "$url")\""
  config+=$'\n'"location"
  if [[ -n "${NVD_API_KEY:-}" && "$url" == https://services.nvd.nist.gov/* ]]; then
    config+=$'\n'"header = \"apiKey: $(config_escape "$NVD_API_KEY")\""
  fi
  curl "${CURL_COMMON[@]}" --config - <<< "$config"
}

# POST a JSON body.  $1 is extra curl-config lines (url + secret headers), $2
# is the JSON payload.  Note: no --location here — following a redirect would
# replay the webhook body, and its Authorization header, to another host.
http_post_json() {
  local config="$1" payload="$2"
  config+=$'\n'"header = \"Content-Type: application/json\""
  curl "${CURL_COMMON[@]}" \
    --request POST \
    --data-binary "$payload" \
    --output /dev/null \
    --config - <<< "$config"
}

# ----------------------------------------------------------------------------
# 1. Check kernel.org for new stable kernel releases
# ----------------------------------------------------------------------------
check_kernel_releases() {
  log "Checking kernel.org for new stable releases..."
  local releases
  if ! releases=$(http_get "https://www.kernel.org/releases.json"); then
    err "Failed to fetch kernel.org releases"
    return 0
  fi

  local latest_stable
  latest_stable=$(jq -r '.releases[]? | select(.moniker=="stable") | .version' <<< "$releases" 2> /dev/null | head -1 || true)
  if [[ -z "$latest_stable" ]]; then
    err "kernel.org returned no parseable stable release"
    return 0
  fi

  local last_seen
  last_seen=$(state_get kernel_stable)

  if [[ "$latest_stable" != "$last_seen" ]]; then
    log "New kernel stable: $latest_stable (was: ${last_seen:-unknown})"
    add_finding "MEDIUM" \
      "kernel.org" \
      "New stable kernel: $latest_stable" \
      "https://www.kernel.org/pub/linux/kernel/v${latest_stable%%.*}.x/ChangeLog-${latest_stable}" \
      "rules/30-established.nft, rules/10-antiscan.nft" \
      "New stable kernel $latest_stable released. Review the netfilter section of the changelog for relevant patches."

    # Only record the new version on a real run: a --dry-run that consumed the
    # state would make the next real run see "no change" and stay silent about
    # a genuine advisory.
    if [[ "$DRY_RUN" == "1" ]]; then
      log "DRY_RUN=1 — not recording kernel_stable=$latest_stable"
    else
      state_set kernel_stable "$latest_stable"
    fi
  else
    log "Kernel stable unchanged: ${latest_stable}"
  fi
}

# ----------------------------------------------------------------------------
# 2. Check netfilter.org for new nftables releases
# ----------------------------------------------------------------------------
check_nftables_releases() {
  log "Checking netfilter.org for nftables releases..."
  local page
  if ! page=$(http_get "https://www.netfilter.org/projects/nftables/downloads.html"); then
    err "Failed to fetch nftables download page"
    return 0
  fi

  local latest_version
  # LC_ALL=C keeps `sort -V` deterministic regardless of the host locale.
  latest_version=$(grep -oP 'nftables-\K[0-9]+\.[0-9]+\.[0-9]+' <<< "$page" |
    LC_ALL=C sort -V | tail -1 || true)
  if [[ -z "$latest_version" ]]; then
    err "could not parse a version from the nftables download page"
    return 0
  fi

  local last_seen
  last_seen=$(state_get nftables)

  if [[ "$latest_version" != "$last_seen" ]]; then
    log "New nftables release: $latest_version (was: ${last_seen:-unknown})"
    add_finding "MEDIUM" \
      "netfilter.org" \
      "New nftables release: $latest_version" \
      "https://www.netfilter.org/projects/nftables/files/changes-nftables-${latest_version}.txt" \
      "nftables.conf (review all files)" \
      "nftables $latest_version released. Review changelog for syntax changes, API deprecations, or security fixes that affect the ruleset."

    if [[ "$DRY_RUN" == "1" ]]; then
      log "DRY_RUN=1 — not recording nftables=$latest_version"
    else
      state_set nftables "$latest_version"
    fi
  else
    log "nftables unchanged: ${latest_version}"
  fi
}

# ----------------------------------------------------------------------------
# 3. Check NVD for new netfilter/nftables CVEs (last 7 days)
# ----------------------------------------------------------------------------
check_cves() {
  log "Checking NVD for recent netfilter/nftables CVEs..."
  local pub_start_date pub_end_date
  pub_start_date=$(date -d "7 days ago" +"%Y-%m-%dT00:00:00.000" 2> /dev/null ||
    date -v-7d +"%Y-%m-%dT00:00:00.000" 2> /dev/null ||
    echo "")
  pub_end_date=$(date +%Y-%m-%dT23:59:59.000)

  local keyword
  for keyword in "nftables" "netfilter"; do
    local response
    if ! response=$(http_get \
      "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${keyword}&pubStartDate=${pub_start_date}&pubEndDate=${pub_end_date}"); then
      err "NVD API request failed for $keyword (rate limit? set NVD_API_KEY)"
      continue
    fi

    # NVD answers rate limiting with HTML, which is not valid JSON — treat a jq
    # parse failure as "no data" instead of letting `set -e` end the run.
    local count
    if ! count=$(jq -r '.totalResults // 0' <<< "$response" 2> /dev/null); then
      err "NVD returned a non-JSON body for $keyword; skipping"
      continue
    fi
    log "NVD: $count CVE(s) found for '$keyword' in last 7 days"

    [[ "$count" =~ ^[0-9]+$ ]] || continue
    ((count > 0)) || continue

    local cve_json
    while IFS= read -r cve_json; do
      local cve_id severity description url rule_files
      cve_id=$(jq -r '.cve.id // "CVE-UNKNOWN"' <<< "$cve_json")
      severity=$(jq -r '
        .cve.metrics.cvssMetricV31[0].cvssData.baseSeverity //
        .cve.metrics.cvssMetricV30[0].cvssData.baseSeverity //
        "UNKNOWN"' <<< "$cve_json")
      description=$(jq -r '[.cve.descriptions[]? | select(.lang=="en") | .value][0] // ""' <<< "$cve_json")
      url="https://nvd.nist.gov/vuln/detail/${cve_id}"
      rule_files=$(map_rule_files "$description")

      add_finding "$severity" \
        "NVD" \
        "${cve_id}: ${description:0:120}…" \
        "$url" \
        "$rule_files" \
        "$description"
    done < <(jq -c '.vulnerabilities[]?' <<< "$response" 2> /dev/null || true)
  done
}

# ----------------------------------------------------------------------------
# 4. Scan netfilter mailing list archive for security-relevant subjects
# ----------------------------------------------------------------------------
check_mailing_list() {
  log "Checking netfilter mailing list..."
  local year month archive_url page
  year=$(date +%Y)
  # LC_ALL=C: pipermail archive paths use English month names. Without this a
  # de_DE host builds ".../2026-Mai/..." and the source is silently lost.
  month=$(LC_ALL=C date +%B)
  archive_url="https://lists.netfilter.org/pipermail/netfilter-devel/${year}-${month}/thread.html"

  if ! page=$(http_get "$archive_url"); then
    err "Failed to fetch mailing list archive (${year}-${month})"
    return 0
  fi

  # Extract subject lines and links
  local subject
  while IFS= read -r subject; do
    if echo "$subject" | grep -qiE "${SECURITY_KEYWORDS}|${BREAKING_KEYWORDS}"; then
      local severity="MEDIUM"
      echo "$subject" | grep -qiE "CVE|UAF|use.after.free|heap.overflow|bypass|RCE" && severity="HIGH"
      echo "$subject" | grep -qiE "CRITICAL|remote.code" && severity="CRITICAL"

      local rule_files
      rule_files=$(map_rule_files "$subject")

      add_finding "$severity" \
        "netfilter-devel mailing list" \
        "$subject" \
        "$archive_url" \
        "$rule_files" \
        "Security-relevant subject in netfilter-devel. Review full thread for impact on xnftables."
    fi
  done < <(grep -oP '(?<=<li>).{0,400}?(?=</li>)' <<< "$page" | sed 's/<[^>]*>//g' | grep -v '^$' || true)
}

# ----------------------------------------------------------------------------
# 5. Check kernel.org netfilter git for recent security commits
# ----------------------------------------------------------------------------
check_kernel_git() {
  log "Checking kernel.org netfilter git..."
  # Use the cgit plain log feed for net/netfilter
  local log_url="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/log/net/netfilter?h=master&qt=grep&q=fix"
  local page
  if ! page=$(http_get "$log_url"); then
    err "Failed to fetch kernel git log"
    return 0
  fi

  # Extract commit subjects from cgit HTML
  local commit_line
  while IFS= read -r commit_line; do
    if echo "$commit_line" | grep -qiE "${SECURITY_KEYWORDS}"; then
      local severity="MEDIUM"
      echo "$commit_line" | grep -qiE "CVE|UAF|use.after.free|heap.overflow|bypass|crash" && severity="HIGH"

      local rule_files
      rule_files=$(map_rule_files "$commit_line")

      add_finding "$severity" \
        "kernel.org/netfilter git" \
        "$commit_line" \
        "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/log/net/netfilter" \
        "$rule_files" \
        "Security-relevant netfilter commit. Check if the fix affects any xnftables rule behaviour."
    fi
  done < <(grep -oP '(?<=<td class="logsubject">).{0,400}?(?=</td>)' <<< "$page" | sed 's/<[^>]*>//g' || true)
}

# ----------------------------------------------------------------------------
# Build findings JSON
# ----------------------------------------------------------------------------
# stdout is *only* the JSON document — the log line goes to stderr, because the
# caller captures this function's stdout. One `jq -s` invocation replaces the
# old per-finding loop, and ${findings[@]+…} keeps `set -u` happy on bash < 4.4
# when there is nothing to report.
build_report() {
  local json_array
  json_array=$(printf '%s\n' ${findings[@]+"${findings[@]}"} | jq -s '[.[] | select(. != null)]')
  printf '%s\n' "$json_array" | write_file "$FINDINGS_FILE"

  local count
  count=$(jq 'length' <<< "$json_array")
  log "Total findings: $count — written to $FINDINGS_FILE" >&2
  printf '%s\n' "$json_array"
}

# ----------------------------------------------------------------------------
# Notify: stdout digest (always)
# ----------------------------------------------------------------------------
print_digest() {
  local findings_json="$1"
  local count
  count=$(jq 'length' <<< "$findings_json")

  echo ""
  echo "════════════════════════════════════════════════"
  echo "  xnftables Security Monitor — ${TODAY}"
  echo "  Repo: https://github.com/${GITHUB_REPO}"
  echo "════════════════════════════════════════════════"

  if [[ "$count" -eq 0 ]]; then
    echo "  ✓ No security-relevant findings today."
    echo "════════════════════════════════════════════════"
    return 0
  fi

  jq -r '.[] | "[\(.severity)] \(.source)\n  \(.title)\n  Rule files: \(.rule_files)\n  URL: \(.url)\n"' <<< "$findings_json"
  echo "════════════════════════════════════════════════"
}

# Shared severity gate: HIGH and CRITICAL are actionable for chat/email.
actionable_findings() {
  jq '[.[] | select(.severity == "CRITICAL" or .severity == "HIGH")]' <<< "$1"
}

# ----------------------------------------------------------------------------
# Notify: Slack
# ----------------------------------------------------------------------------
notify_slack() {
  local findings_json="$1"
  if [[ -z "${SLACK_WEBHOOK_URL:-}" ]]; then
    log "SLACK_WEBHOOK_URL not set, skipping"
    return 0
  fi

  local actionable count
  actionable=$(actionable_findings "$findings_json")
  count=$(jq 'length' <<< "$actionable")
  if [[ "$count" -eq 0 ]]; then
    log "No HIGH/CRITICAL findings for Slack"
    return 0
  fi

  # $TODAY / $GITHUB_REPO / $count are passed with --arg/--argjson instead of
  # being spliced into the jq program text: a value containing a quote or
  # backslash would otherwise corrupt or rewrite the filter.
  local payload
  payload=$(jq -c \
    --arg today "$TODAY" \
    --arg repo "$GITHUB_REPO" \
    --argjson count "$count" \
    '{
      blocks: (
        [
          {type:"section", text:{type:"mrkdwn", text:("*xnftables Security Monitor — " + $today + "*\n<https://github.com/" + $repo + "|" + $repo + ">\n" + ($count|tostring) + " HIGH/CRITICAL finding(s):")}}
        ]
        + [ .[] | {
            type: "section",
            text: {
              type: "mrkdwn",
              text: ("*[" + .severity + "] " + .source + "*\n" + .title + "\n_Rule files: " + .rule_files + "_\n<" + .url + "|View →>")
            }
          } ]
        + [ {type:"divider"} ]
      )
    }' <<< "$actionable")

  # The webhook URL is a bearer secret in URL form — keep it off argv.
  local config
  config="url = \"$(config_escape "$SLACK_WEBHOOK_URL")\""
  if http_post_json "$config" "$payload"; then
    log "Slack notification sent"
  else
    err "Slack notification failed"
  fi
}

# ----------------------------------------------------------------------------
# Notify: Discord
# ----------------------------------------------------------------------------
notify_discord() {
  local findings_json="$1"
  if [[ -z "${DISCORD_WEBHOOK_URL:-}" ]]; then
    log "DISCORD_WEBHOOK_URL not set, skipping"
    return 0
  fi

  local actionable count
  actionable=$(actionable_findings "$findings_json")
  count=$(jq 'length' <<< "$actionable")
  if [[ "$count" -eq 0 ]]; then
    log "No HIGH/CRITICAL findings for Discord"
    return 0
  fi

  local content
  content="**xnftables Security Monitor — ${TODAY}**\n<https://github.com/${GITHUB_REPO}>\n${count} HIGH/CRITICAL finding(s):\n\n"
  local finding
  while IFS= read -r finding; do
    local severity source title rule_files url
    severity=$(jq -r '.severity' <<< "$finding")
    source=$(jq -r '.source' <<< "$finding")
    title=$(jq -r '.title' <<< "$finding")
    rule_files=$(jq -r '.rule_files' <<< "$finding")
    url=$(jq -r '.url' <<< "$finding")
    content+="**[${severity}] ${source}**\n${title}\nRule files: \`${rule_files}\`\n${url}\n\n"
  done < <(jq -c '.[]' <<< "$actionable")

  local payload config
  payload=$(jq -nc --arg c "$content" '{content: $c}')
  config="url = \"$(config_escape "$DISCORD_WEBHOOK_URL")\""
  if http_post_json "$config" "$payload"; then
    log "Discord notification sent"
  else
    err "Discord notification failed"
  fi
}

# ----------------------------------------------------------------------------
# Notify: Email
# ----------------------------------------------------------------------------
notify_email() {
  local findings_json="$1"
  if [[ -z "${NOTIFY_EMAIL:-}" ]]; then
    log "NOTIFY_EMAIL not set, skipping"
    return 0
  fi
  if ! command -v mail > /dev/null 2>&1; then
    err "mail command not found"
    return 0
  fi

  local actionable count
  actionable=$(actionable_findings "$findings_json")
  count=$(jq 'length' <<< "$actionable")
  if [[ "$count" -eq 0 ]]; then
    log "No HIGH/CRITICAL findings for email"
    return 0
  fi

  local body
  body="xnftables Security Monitor — ${TODAY}
Repo: https://github.com/${GITHUB_REPO}
${count} HIGH/CRITICAL finding(s):

$(jq -r '.[] | "[\(.severity)] \(.source)\n  \(.title)\n  Rule files: \(.rule_files)\n  URL: \(.url)\n"' <<< "$actionable")

---
Full findings: ${FINDINGS_FILE}
"

  # ${NOTIFY_FROM_EMAIL:+-r …} must stay unquoted so it expands to nothing when
  # the variable is empty; shellcheck's SC2086 is expected here.
  # shellcheck disable=SC2086
  if echo "$body" | mail \
    -s "[xnftables] ${count} security finding(s) — ${TODAY}" \
    ${NOTIFY_FROM_EMAIL:+-r "$NOTIFY_FROM_EMAIL"} \
    "$NOTIFY_EMAIL"; then
    log "Email sent to $NOTIFY_EMAIL"
  else
    err "Email failed"
  fi
}

# ----------------------------------------------------------------------------
# Notify: Notion
# ----------------------------------------------------------------------------
notify_notion() {
  local findings_json="$1"
  if [[ -z "${NOTION_API_TOKEN:-}" ]]; then
    log "NOTION_API_TOKEN not set, skipping"
    return 0
  fi
  if [[ -z "${NOTION_DATABASE_ID:-}" ]]; then
    log "NOTION_DATABASE_ID not set, skipping"
    return 0
  fi

  # Notion is the archive, so it also receives MEDIUM findings.
  local actionable count
  actionable=$(jq '[.[] | select(.severity == "CRITICAL" or .severity == "HIGH" or .severity == "MEDIUM")]' <<< "$findings_json")
  count=$(jq 'length' <<< "$actionable")
  if [[ "$count" -eq 0 ]]; then
    log "No MEDIUM+ findings for Notion"
    return 0
  fi

  # Build the curl config once: URL, bearer token, and API version all travel
  # on stdin so the token never appears in /proc/<pid>/cmdline.
  local config
  config="url = \"https://api.notion.com/v1/pages\""
  config+=$'\n'"header = \"Authorization: Bearer $(config_escape "$NOTION_API_TOKEN")\""
  config+=$'\n'"header = \"Notion-Version: 2022-06-28\""

  local finding
  while IFS= read -r finding; do
    local title payload
    # Truncate with jq (UTF-8 aware) rather than `cut -c`, which can slice a
    # multibyte sequence in half and make the API reject the body.
    title=$(jq -r '.title[0:100]' <<< "$finding")

    payload=$(jq -c \
      --arg db "$NOTION_DATABASE_ID" \
      --arg title "$title" \
      '{
        parent: {database_id: $db},
        properties: {
          "Name":       {title:  [{text: {content: $title}}]},
          "Severity":   {select: {name: .severity}},
          "Source":     {rich_text: [{text: {content: .source}}]},
          "Rule Files": {rich_text: [{text: {content: .rule_files}}]},
          "URL":        {url: .url},
          "Date":       {date: {start: .date}}
        },
        children: [{
          object: "block",
          type: "paragraph",
          paragraph: {rich_text: [{text: {content: .body}}]}
        }]
      }' <<< "$finding")

    if http_post_json "$config" "$payload"; then
      log "Notion page created for: $title"
    else
      err "Notion API failed for: $title"
    fi
  done < <(jq -c '.[]' <<< "$actionable")
}

# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
main() {
  log "Starting xnftables security monitor"
  log "Repo: https://github.com/${GITHUB_REPO}"
  log "State dir: ${STATE_DIR} (findings: ${FINDINGS_FILE})"
  log "Notify channel: ${NOTIFY_CHANNEL}${DRY_RUN:+ (DRY_RUN=${DRY_RUN})}"

  # Each check is fault-tolerant on its own: a failed fetch logs and returns,
  # so one dead upstream never hides the other four sources.
  check_kernel_releases
  check_nftables_releases
  check_cves
  check_mailing_list
  check_kernel_git

  local findings_json
  findings_json=$(build_report)

  print_digest "$findings_json"

  if [[ "$DRY_RUN" == "1" ]]; then
    log "DRY_RUN=1 — skipping notifications"
    return 0
  fi

  # Dispatch notifications. NOTIFY_CHANNEL was validated during argument
  # parsing, so every arm here is reachable and the default really is "all".
  case "$NOTIFY_CHANNEL" in
    slack) notify_slack "$findings_json" ;;
    discord) notify_discord "$findings_json" ;;
    email) notify_email "$findings_json" ;;
    notion) notify_notion "$findings_json" ;;
    all)
      notify_slack "$findings_json"
      notify_discord "$findings_json"
      notify_email "$findings_json"
      notify_notion "$findings_json"
      ;;
    none) log "Notifications disabled (channel=none)" ;;
  esac

  log "Done"
}

# "$@" was already consumed by the parser above; main takes no arguments.
main
