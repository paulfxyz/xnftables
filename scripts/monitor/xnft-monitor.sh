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
#   ./xnft-monitor.sh [--dry-run] [--notify slack|discord|email|notion|all]
#
# CRON EXAMPLE (weekdays at 08:00 local time)
# -------------------------------------------
#   0 8 * * 1-5 /opt/xnftables/scripts/monitor/xnft-monitor.sh >> /var/log/xnft-monitor.log 2>&1
#
# SETUP
# -----
#   1. Copy .env.example to .env and fill in your tokens
#   2. chmod +x xnft-monitor.sh
#   3. Install dependencies: curl, jq, python3 (for HTML parsing)
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
#   GITHUB_REPO           e.g. "paulfxyz/xnftables" (used in finding links)
#   DRY_RUN               Set to "1" to print findings without notifying
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
#   flag / tcp           → rules/05-antiscan.nft
#   bogon / martian      → rules/05-antiscan.nft
#   fragment / frag      → rules/05-antiscan.nft
#
# OUTPUT
# ------
# Each run writes a JSON findings file to /tmp/xnft-findings-YYYY-MM-DD.json
# and a human-readable digest to stdout.
# Only findings with severity HIGH or CRITICAL trigger notifications.
# =============================================================================

set -euo pipefail

# ----------------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"
[[ -f "$ENV_FILE" ]] && source "$ENV_FILE"

DRY_RUN="${DRY_RUN:-0}"
NOTIFY_CHANNEL="${1:-}"  # --notify slack|discord|email|notion|all
GITHUB_REPO="${GITHUB_REPO:-paulfxyz/xnftables}"
TODAY="$(date +%Y-%m-%d)"
FINDINGS_FILE="/tmp/xnft-findings-${TODAY}.json"
STATE_FILE="${SCRIPT_DIR}/.last-seen-versions"
LOG_PREFIX="[xnft-monitor ${TODAY}]"

# Touch state file if it doesn't exist
[[ -f "$STATE_FILE" ]] || touch "$STATE_FILE"

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
  ["tcp.*flag"]="rules/05-antiscan.nft"
  ["fragment"]="rules/05-antiscan.nft"
  ["bogon"]="rules/05-antiscan.nft"
  ["log"]="rules/70-logging.nft"
)

# ----------------------------------------------------------------------------
# Utilities
# ----------------------------------------------------------------------------
log() { echo "${LOG_PREFIX} $*"; }
err() { echo "${LOG_PREFIX} ERROR: $*" >&2; }

require() {
  for cmd in "$@"; do
    command -v "$cmd" >/dev/null 2>&1 || { err "Required command not found: $cmd"; exit 1; }
  done
}

require curl jq

findings=()

add_finding() {
  local severity="$1"  # CRITICAL HIGH MEDIUM LOW INFO
  local source="$2"
  local title="$3"
  local url="$4"
  local rule_files="$5"
  local body="$6"

  findings+=("$(jq -nc \
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
  local text="${1,,}"  # lowercase
  local matched=""
  for kw in "${!RULE_MAP[@]}"; do
    if echo "$text" | grep -qiE "$kw"; then
      matched="${matched:+$matched, }${RULE_MAP[$kw]}"
    fi
  done
  echo "${matched:-rules/ (review manually)}"
}

# ----------------------------------------------------------------------------
# 1. Check kernel.org for new stable kernel releases
# ----------------------------------------------------------------------------
check_kernel_releases() {
  log "Checking kernel.org for new stable releases..."
  local releases
  releases=$(curl -fsSL "https://www.kernel.org/releases.json" 2>/dev/null) || {
    err "Failed to fetch kernel.org releases"; return
  }

  local latest_stable
  latest_stable=$(echo "$releases" | jq -r '.releases[] | select(.moniker=="stable") | .version' | head -1)

  local last_seen
  last_seen=$(grep "^kernel_stable=" "$STATE_FILE" 2>/dev/null | cut -d= -f2 || echo "")

  if [[ -n "$latest_stable" && "$latest_stable" != "$last_seen" ]]; then
    log "New kernel stable: $latest_stable (was: ${last_seen:-unknown})"
    add_finding "MEDIUM" \
      "kernel.org" \
      "New stable kernel: $latest_stable" \
      "https://www.kernel.org/pub/linux/kernel/v${latest_stable%%.*}.x/ChangeLog-${latest_stable}" \
      "rules/30-established.nft, rules/05-antiscan.nft" \
      "New stable kernel $latest_stable released. Review the netfilter section of the changelog for relevant patches."

    # Update state
    sed -i "/^kernel_stable=/d" "$STATE_FILE"
    echo "kernel_stable=${latest_stable}" >> "$STATE_FILE"
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
  page=$(curl -fsSL "https://www.netfilter.org/projects/nftables/downloads.html" 2>/dev/null) || {
    err "Failed to fetch nftables download page"; return
  }

  local latest_version
  latest_version=$(echo "$page" | grep -oP 'nftables-\K[0-9]+\.[0-9]+\.[0-9]+' | sort -V | tail -1 || echo "")

  local last_seen
  last_seen=$(grep "^nftables=" "$STATE_FILE" 2>/dev/null | cut -d= -f2 || echo "")

  if [[ -n "$latest_version" && "$latest_version" != "$last_seen" ]]; then
    log "New nftables release: $latest_version (was: ${last_seen:-unknown})"
    add_finding "MEDIUM" \
      "netfilter.org" \
      "New nftables release: $latest_version" \
      "https://www.netfilter.org/projects/nftables/files/changes-nftables-${latest_version}.txt" \
      "nftables.conf (review all files)" \
      "nftables $latest_version released. Review changelog for syntax changes, API deprecations, or security fixes that affect the ruleset."

    sed -i "/^nftables=/d" "$STATE_FILE"
    echo "nftables=${latest_version}" >> "$STATE_FILE"
  else
    log "nftables unchanged: ${latest_version}"
  fi
}

# ----------------------------------------------------------------------------
# 3. Check NVD for new netfilter/nftables CVEs (last 7 days)
# ----------------------------------------------------------------------------
check_cves() {
  log "Checking NVD for recent netfilter/nftables CVEs..."
  local pub_start_date
  pub_start_date=$(date -d "7 days ago" +"%Y-%m-%dT00:00:00.000" 2>/dev/null \
    || date -v-7d +"%Y-%m-%dT00:00:00.000" 2>/dev/null \
    || echo "")

  for keyword in "nftables" "netfilter"; do
    local response
    response=$(curl -fsSL \
      "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${keyword}&pubStartDate=${pub_start_date}&pubEndDate=$(date +%Y-%m-%dT23:59:59.000)" \
      2>/dev/null) || { err "NVD API request failed for $keyword"; continue; }

    local count
    count=$(echo "$response" | jq '.totalResults // 0')
    log "NVD: $count CVE(s) found for '$keyword' in last 7 days"

    if [[ "$count" -gt 0 ]]; then
      while IFS= read -r cve_json; do
        local cve_id severity description url rule_files
        cve_id=$(echo "$cve_json" | jq -r '.cve.id')
        severity=$(echo "$cve_json" | jq -r '
          .cve.metrics.cvssMetricV31[0].cvssData.baseSeverity //
          .cve.metrics.cvssMetricV30[0].cvssData.baseSeverity //
          "UNKNOWN"')
        description=$(echo "$cve_json" | jq -r '.cve.descriptions[] | select(.lang=="en") | .value' | head -1)
        url="https://nvd.nist.gov/vuln/detail/${cve_id}"
        rule_files=$(map_rule_files "$description")

        add_finding "$severity" \
          "NVD" \
          "${cve_id}: ${description:0:120}…" \
          "$url" \
          "$rule_files" \
          "$description"
      done < <(echo "$response" | jq -c '.vulnerabilities[]')
    fi
  done
}

# ----------------------------------------------------------------------------
# 4. Scan netfilter mailing list archive for security-relevant subjects
# ----------------------------------------------------------------------------
check_mailing_list() {
  log "Checking netfilter mailing list..."
  local year month archive_url page subjects
  year=$(date +%Y)
  month=$(date +%B)  # e.g. "May"
  archive_url="https://lists.netfilter.org/pipermail/netfilter-devel/${year}-${month}/thread.html"

  page=$(curl -fsSL "$archive_url" 2>/dev/null) || {
    err "Failed to fetch mailing list archive (${year}-${month})"; return
  }

  # Extract subject lines and links
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
  done < <(echo "$page" | grep -oP '(?<=<li>).*?(?=</li>)' | sed 's/<[^>]*>//g' | grep -v '^$')
}

# ----------------------------------------------------------------------------
# 5. Check kernel.org netfilter git for recent security commits
# ----------------------------------------------------------------------------
check_kernel_git() {
  log "Checking kernel.org netfilter git..."
  # Use the cgit plain log feed for net/netfilter
  local log_url="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/log/net/netfilter?h=master&qt=grep&q=fix"
  local page
  page=$(curl -fsSL "$log_url" 2>/dev/null) || {
    err "Failed to fetch kernel git log"; return
  }

  # Extract commit subjects from cgit HTML
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
  done < <(echo "$page" | grep -oP '(?<=<td class="logsubject">).*?(?=</td>)' | sed 's/<[^>]*>//g')
}

# ----------------------------------------------------------------------------
# Build findings JSON
# ----------------------------------------------------------------------------
build_report() {
  local json_array="[]"
  for f in "${findings[@]}"; do
    json_array=$(echo "$json_array" | jq --argjson item "$f" '. + [$item]')
  done
  echo "$json_array" > "$FINDINGS_FILE"

  local count
  count=$(echo "$json_array" | jq 'length')
  log "Total findings: $count — written to $FINDINGS_FILE"
  echo "$json_array"
}

# ----------------------------------------------------------------------------
# Notify: stdout digest (always)
# ----------------------------------------------------------------------------
print_digest() {
  local findings_json="$1"
  local count
  count=$(echo "$findings_json" | jq 'length')

  echo ""
  echo "════════════════════════════════════════════════"
  echo "  xnftables Security Monitor — ${TODAY}"
  echo "  Repo: https://github.com/${GITHUB_REPO}"
  echo "════════════════════════════════════════════════"

  if [[ "$count" -eq 0 ]]; then
    echo "  ✓ No security-relevant findings today."
    echo "════════════════════════════════════════════════"
    return
  fi

  echo "$findings_json" | jq -r '.[] | "[\(.severity)] \(.source)\n  \(.title)\n  Rule files: \(.rule_files)\n  URL: \(.url)\n"'
  echo "════════════════════════════════════════════════"
}

# ----------------------------------------------------------------------------
# Notify: Slack
# ----------------------------------------------------------------------------
notify_slack() {
  local findings_json="$1"
  [[ -z "${SLACK_WEBHOOK_URL:-}" ]] && { log "SLACK_WEBHOOK_URL not set, skipping"; return; }

  local actionable
  actionable=$(echo "$findings_json" | jq '[.[] | select(.severity == "CRITICAL" or .severity == "HIGH")]')
  local count
  count=$(echo "$actionable" | jq 'length')
  [[ "$count" -eq 0 ]] && { log "No HIGH/CRITICAL findings for Slack"; return; }

  local blocks
  blocks=$(echo "$actionable" | jq -r '
    [
      {"type":"section","text":{"type":"mrkdwn","text":"*xnftables Security Monitor — '"$TODAY"'*\n<https://github.com/'"$GITHUB_REPO"'|'"$GITHUB_REPO"'>\n'"$count"' HIGH/CRITICAL finding(s):"}},
      (.[] | {
        "type": "section",
        "text": {
          "type": "mrkdwn",
          "text": ("*[\(.severity)] \(.source)*\n\(.title)\n_Rule files: \(.rule_files)_\n<\(.url)|View →>")
        }
      }),
      {"type":"divider"}
    ]
  ')

  curl -fsSL -X POST -H "Content-type: application/json" \
    --data "{\"blocks\": $blocks}" \
    "$SLACK_WEBHOOK_URL" && log "Slack notification sent" || err "Slack notification failed"
}

# ----------------------------------------------------------------------------
# Notify: Discord
# ----------------------------------------------------------------------------
notify_discord() {
  local findings_json="$1"
  [[ -z "${DISCORD_WEBHOOK_URL:-}" ]] && { log "DISCORD_WEBHOOK_URL not set, skipping"; return; }

  local actionable
  actionable=$(echo "$findings_json" | jq '[.[] | select(.severity == "CRITICAL" or .severity == "HIGH")]')
  local count
  count=$(echo "$actionable" | jq 'length')
  [[ "$count" -eq 0 ]] && { log "No HIGH/CRITICAL findings for Discord"; return; }

  local content
  content="**xnftables Security Monitor — ${TODAY}**\n<https://github.com/${GITHUB_REPO}>\n${count} HIGH/CRITICAL finding(s):\n\n"
  while IFS= read -r finding; do
    local severity source title rule_files url
    severity=$(echo "$finding" | jq -r '.severity')
    source=$(echo "$finding" | jq -r '.source')
    title=$(echo "$finding" | jq -r '.title')
    rule_files=$(echo "$finding" | jq -r '.rule_files')
    url=$(echo "$finding" | jq -r '.url')
    content+="**[${severity}] ${source}**\n${title}\nRule files: \`${rule_files}\`\n${url}\n\n"
  done < <(echo "$actionable" | jq -c '.[]')

  curl -fsSL -X POST -H "Content-type: application/json" \
    --data "$(jq -nc --arg c "$content" '{"content": $c}')" \
    "$DISCORD_WEBHOOK_URL" && log "Discord notification sent" || err "Discord notification failed"
}

# ----------------------------------------------------------------------------
# Notify: Email
# ----------------------------------------------------------------------------
notify_email() {
  local findings_json="$1"
  [[ -z "${NOTIFY_EMAIL:-}" ]] && { log "NOTIFY_EMAIL not set, skipping"; return; }
  command -v mail >/dev/null 2>&1 || { err "mail command not found"; return; }

  local actionable
  actionable=$(echo "$findings_json" | jq '[.[] | select(.severity == "CRITICAL" or .severity == "HIGH")]')
  local count
  count=$(echo "$actionable" | jq 'length')
  [[ "$count" -eq 0 ]] && { log "No HIGH/CRITICAL findings for email"; return; }

  local body
  body="xnftables Security Monitor — ${TODAY}
Repo: https://github.com/${GITHUB_REPO}
${count} HIGH/CRITICAL finding(s):

$(echo "$actionable" | jq -r '.[] | "[\(.severity)] \(.source)\n  \(.title)\n  Rule files: \(.rule_files)\n  URL: \(.url)\n"')

---
Full findings: ${FINDINGS_FILE}
"

  echo "$body" | mail \
    -s "[xnftables] ${count} security finding(s) — ${TODAY}" \
    ${NOTIFY_FROM_EMAIL:+-r "$NOTIFY_FROM_EMAIL"} \
    "$NOTIFY_EMAIL" && log "Email sent to $NOTIFY_EMAIL" || err "Email failed"
}

# ----------------------------------------------------------------------------
# Notify: Notion
# ----------------------------------------------------------------------------
notify_notion() {
  local findings_json="$1"
  [[ -z "${NOTION_API_TOKEN:-}" ]] && { log "NOTION_API_TOKEN not set, skipping"; return; }
  [[ -z "${NOTION_DATABASE_ID:-}" ]] && { log "NOTION_DATABASE_ID not set, skipping"; return; }

  local actionable
  actionable=$(echo "$findings_json" | jq '[.[] | select(.severity == "CRITICAL" or .severity == "HIGH" or .severity == "MEDIUM")]')
  local count
  count=$(echo "$actionable" | jq 'length')
  [[ "$count" -eq 0 ]] && { log "No MEDIUM+ findings for Notion"; return; }

  while IFS= read -r finding; do
    local title severity source rule_files url body
    title=$(echo "$finding" | jq -r '.title' | cut -c1-100)
    severity=$(echo "$finding" | jq -r '.severity')
    source=$(echo "$finding" | jq -r '.source')
    rule_files=$(echo "$finding" | jq -r '.rule_files')
    url=$(echo "$finding" | jq -r '.url')
    body=$(echo "$finding" | jq -r '.body')

    local payload
    payload=$(jq -nc \
      --arg db "$NOTION_DATABASE_ID" \
      --arg title "$title" \
      --arg severity "$severity" \
      --arg source "$source" \
      --arg rule_files "$rule_files" \
      --arg url "$url" \
      --arg body "$body" \
      --arg date "$TODAY" \
      '{
        "parent": {"database_id": $db},
        "properties": {
          "Name":       {"title":  [{"text": {"content": $title}}]},
          "Severity":   {"select": {"name": $severity}},
          "Source":     {"rich_text": [{"text": {"content": $source}}]},
          "Rule Files": {"rich_text": [{"text": {"content": $rule_files}}]},
          "URL":        {"url": $url},
          "Date":       {"date": {"start": $date}}
        },
        "children": [{
          "object": "block",
          "type": "paragraph",
          "paragraph": {"rich_text": [{"text": {"content": $body}}]}
        }]
      }')

    curl -fsSL -X POST "https://api.notion.com/v1/pages" \
      -H "Authorization: Bearer ${NOTION_API_TOKEN}" \
      -H "Notion-Version: 2022-06-28" \
      -H "Content-type: application/json" \
      --data "$payload" >/dev/null && log "Notion page created for: $title" || err "Notion API failed"
  done < <(echo "$actionable" | jq -c '.[]')
}

# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
main() {
  log "Starting xnftables security monitor"
  log "Repo: https://github.com/${GITHUB_REPO}"

  check_kernel_releases
  check_nftables_releases
  check_cves
  check_mailing_list
  check_kernel_git

  local findings_json
  findings_json=$(build_report)

  print_digest "$findings_json"

  if [[ "${DRY_RUN}" == "1" ]]; then
    log "DRY_RUN=1 — skipping notifications"
    exit 0
  fi

  # Dispatch notifications based on --notify argument or NOTIFY_CHANNEL env
  local channel="${NOTIFY_CHANNEL:-${NOTIFY_CHANNEL_ENV:-all}}"
  case "$channel" in
    slack)   notify_slack   "$findings_json" ;;
    discord) notify_discord "$findings_json" ;;
    email)   notify_email   "$findings_json" ;;
    notion)  notify_notion  "$findings_json" ;;
    all)
      notify_slack   "$findings_json"
      notify_discord "$findings_json"
      notify_email   "$findings_json"
      notify_notion  "$findings_json"
      ;;
    none)    log "Notifications disabled (channel=none)" ;;
    *)       err "Unknown channel: $channel. Use slack|discord|email|notion|all|none" ;;
  esac

  log "Done"
}

main "$@"
