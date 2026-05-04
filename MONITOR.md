# xnft-monitor — upstream security scanner

> Stay ahead of CVEs, netfilter patches, and nftables API changes — automatically.

`xnft-monitor` is a weekday shell script that watches five upstream sources
for anything that could affect the `xnftables` ruleset.  When it finds something
relevant, it maps the finding to the exact rule file that may need updating and
sends a notification to whichever channel(s) you configure.

You run it once, set a cron or systemd timer, and forget about it until a
relevant finding lands in your inbox (or Slack, or Discord, or Notion).

---

## Table of contents

- [What it watches](#what-it-watches)
- [Severity and signal filtering](#severity-and-signal-filtering)
- [Rule file mapping](#rule-file-mapping)
- [Quick setup](#quick-setup)
- [Notification channels](#notification-channels)
- [Deploy: cron](#deploy-cron)
- [Deploy: systemd timer](#deploy-systemd-timer)
- [Testing](#testing)
- [Files](#files)
- [How findings look](#how-findings-look)
- [Extending the scanner](#extending-the-scanner)

---

## What it watches

| # | Source | How |
|---|---|---|
| 1 | [kernel.org stable releases](https://www.kernel.org/releases.json) | JSON API — compares latest stable version against last-seen state |
| 2 | [netfilter.org nftables releases](https://www.netfilter.org/projects/nftables/downloads.html) | HTML parse — detects new `nft` versions |
| 3 | [NVD CVE database](https://services.nvd.nist.gov/rest/json/cves/2.0) | REST API — queries `nftables` and `netfilter` CVEs published in the last 7 days |
| 4 | [netfilter-devel mailing list](https://lists.netfilter.org/pipermail/netfilter-devel/) | Monthly archive — scans thread subjects for security keywords |
| 5 | [kernel.org netfilter git](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/log/net/netfilter) | cgit log — scans recent `net/netfilter` commit subjects |

State is persisted in `.last-seen-versions` so you only receive an alert once
per unique event — not a repeat every morning for the same kernel version.

---

## Severity and signal filtering

The script classifies findings into four severity levels:

| Severity | Examples | Notification |
|---|---|---|
| **CRITICAL** | RCE, remote code execution, active exploit | All configured channels |
| **HIGH** | CVE confirmed, UAF, heap overflow, bypass, kernel panic | All configured channels |
| **MEDIUM** | New kernel/nftables release, API deprecation, breaking change | Notion only (informational) |
| **LOW / INFO** | No-op changes, administrative mailing list threads | stdout only |

**Security keywords** (trigger HIGH or CRITICAL):
```
CVE · use-after-free · UAF · heap overflow · buffer overflow
out-of-bounds · OOB · privilege escalation · bypass · crash
panic · regression · null deref · memory leak · RCE · remote code
```

**Breaking-change keywords** (trigger MEDIUM):
```
API change · ABI break · incompatible · deprecated · removed
renamed · behaviour change · nft_.*_ops · hook priority
```

---

## Rule file mapping

Every finding is automatically mapped to the rule file most likely to be
affected.  This makes the notification immediately actionable — you open the
right file, not the whole repo.

| Keyword in finding | Rule file(s) |
|---|---|
| `conntrack` / `ct` | `rules/30-established.nft` |
| `wireguard` / `wg` | `rules/20-mesh.nft`, `rules/50-vpn-endpoint.nft` |
| `icmp` / `icmpv6` | `rules/60-icmp.nft` |
| `meter` / `rate limit` | `rules/50-vpn-endpoint.nft`, `rules/40-services.nft` |
| `set` / `map` / `element` | `rules/00-tables.nft` |
| `forward` / `routing` | `rules/70-logging.nft` |
| `log` / `nflog` | `rules/70-logging.nft` |
| `nat` / `masquerade` | `nftables.conf` |
| `tcp` / `flag` | `rules/05-antiscan.nft` |
| `bogon` / `martian` / `fragment` | `rules/05-antiscan.nft` |

If no keyword matches, the finding is flagged with `rules/ (review manually)`.

---

## Quick setup

### 1. Clone and enter the monitor directory

```bash
git clone https://github.com/paulfxyz/xnftables.git
cd xnftables/scripts/monitor
```

### 2. Install dependencies

```bash
# Debian / Ubuntu
sudo apt-get install curl jq mailutils

# Arch Linux
sudo pacman -S curl jq s-nail

# macOS (for local testing only)
brew install curl jq
```

### 3. Configure credentials

```bash
cp .env.example .env
$EDITOR .env
```

Set whichever channels you want.  All fields are optional — leave unused ones
as-is and the script will skip them silently.

### 4. Make executable

```bash
chmod +x xnft-monitor.sh
```

### 5. Test (dry-run — no network writes, no notifications sent)

```bash
DRY_RUN=1 ./xnft-monitor.sh
```

---

## Notification channels

### Slack

Create an [Incoming Webhook](https://api.slack.com/messaging/webhooks) in your
workspace (Apps → Incoming Webhooks → Add to Slack → choose channel).

```bash
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/TXXXXXXXX/BXXXXXXXX/xxxxxxxx
```

The notification uses Block Kit with one section per finding.  Only HIGH and
CRITICAL findings are sent.

---

### Discord

Create a webhook in channel settings → Integrations → Webhooks → New Webhook.

```bash
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/000000000000/xxxxxxxx
```

---

### Email

Requires the `mail` command.  On a VPS with no local MTA, use
[msmtp](https://marlam.de/msmtp/) pointing at an SMTP relay:

```bash
# ~/.msmtprc
account default
host smtp.postmarkapp.com
port 587
auth on
user YOUR_API_TOKEN
password YOUR_API_TOKEN
tls on
tls_starttls on
```

Then set:
```bash
NOTIFY_EMAIL=you@yourdomain.com
NOTIFY_FROM_EMAIL=xnft-monitor@yourdomain.com
```

---

### Notion

The script creates one Notion database row per finding, with structured
properties for severity, source, rule files, URL, and date.

**Setup:**

1. Go to [notion.so/my-integrations](https://www.notion.so/my-integrations)
   and create an integration — give it any name.

2. Create a Notion database with these properties:

   | Property | Type |
   |---|---|
   | `Name` | Title |
   | `Severity` | Select (options: CRITICAL, HIGH, MEDIUM, LOW) |
   | `Source` | Text |
   | `Rule Files` | Text |
   | `URL` | URL |
   | `Date` | Date |

3. Open the database as a full page, click `...` → `Connections` →
   add your integration.

4. Copy the database ID from the URL:
   `https://notion.so/yourworkspace/`**`DATABASE_ID`**`?v=...`

5. Set in `.env`:
   ```bash
   NOTION_API_TOKEN=secret_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
   NOTION_DATABASE_ID=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
   ```

---

## Deploy: cron

The simplest deployment.  Runs as a root cron job on weekdays at 08:00.

```bash
sudo crontab -e
```

Add:
```
# xnftables security monitor — weekdays at 08:00
0 8 * * 1-5 /opt/xnftables/scripts/monitor/xnft-monitor.sh >> /var/log/xnft-monitor.log 2>&1
```

Rotate the log to avoid unbounded growth:

```bash
# /etc/logrotate.d/xnft-monitor
/var/log/xnft-monitor.log {
    weekly
    rotate 8
    compress
    missingok
    notifempty
}
```

---

## Deploy: systemd timer

More robust than cron: `Persistent=true` means the timer fires on the next
boot if the machine was off at 08:00, and `journald` gives you proper
structured logs.

```bash
# 1. Install the units (adjust path to your actual install location)
sudo cp monitor.service /etc/systemd/system/xnft-monitor.service
sudo cp monitor.timer   /etc/systemd/system/xnft-monitor.timer

# 2. Update the path in the service file
sudo sed -i 's|/opt/xnftables|/your/install/path|g' \
    /etc/systemd/system/xnft-monitor.service

# 3. Enable and start
sudo systemctl daemon-reload
sudo systemctl enable --now xnft-monitor.timer

# 4. Verify the timer is scheduled
systemctl list-timers xnft-monitor.timer
```

Checking logs:
```bash
# Last run output
journalctl -u xnft-monitor.service -n 100

# Follow in real time (for testing)
journalctl -u xnft-monitor.service -f
```

---

## Testing

```bash
# Dry-run: all checks, no notifications, prints digest to stdout
DRY_RUN=1 ./xnft-monitor.sh

# Test a specific channel without running all checks
DRY_RUN=0 ./xnft-monitor.sh --notify slack

# Force all channels
DRY_RUN=0 ./xnft-monitor.sh --notify all

# Stdout only (no notifications)
./xnft-monitor.sh --notify none
```

The findings JSON is always written to `/tmp/xnft-findings-YYYY-MM-DD.json`
regardless of `DRY_RUN`, so you can inspect what would have been sent:

```bash
cat /tmp/xnft-findings-$(date +%Y-%m-%d).json | jq .
```

---

## Files

```
scripts/monitor/
  xnft-monitor.sh          ← main script (571 lines, bash)
  .env.example             ← credential template (copy to .env)
  monitor.service          ← systemd service unit
  monitor.timer            ← systemd timer unit (Mon–Fri 08:00, Persistent)
  README.md                ← condensed setup guide
MONITOR.md                 ← this file (full documentation)
```

`.env` and `.last-seen-versions` are in `.gitignore` — never committed.

---

## How findings look

### stdout digest

```
════════════════════════════════════════════════
  xnftables Security Monitor — 2026-05-04
  Repo: https://github.com/paulfxyz/xnftables
════════════════════════════════════════════════
[HIGH] NVD
  CVE-2026-XXXXX: nftables: use-after-free in nft_set_destroy…
  Rule files: rules/00-tables.nft
  URL: https://nvd.nist.gov/vuln/detail/CVE-2026-XXXXX

[MEDIUM] kernel.org
  New stable kernel: 6.9.3
  Rule files: rules/30-established.nft, rules/05-antiscan.nft
  URL: https://www.kernel.org/pub/linux/kernel/…
════════════════════════════════════════════════
```

### JSON findings file

```json
[
  {
    "severity": "HIGH",
    "source": "NVD",
    "title": "CVE-2026-XXXXX: nftables: use-after-free in nft_set_destroy",
    "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-XXXXX",
    "rule_files": "rules/00-tables.nft",
    "body": "A use-after-free vulnerability was found in nftables...",
    "date": "2026-05-04"
  }
]
```

### Slack notification

Structured Block Kit message — one section per HIGH/CRITICAL finding with
severity label, source, title, affected rule file, and a link.

### Notion row

One database row per finding with `Severity` select, `Source` text,
`Rule Files` text, `URL` url, `Date` date, and full description in the page body.

---

## Extending the scanner

The script is structured so adding a new source is straightforward:

1. Add a `check_<source>()` function that calls `add_finding severity source title url rule_files body`
2. Call the function from `main()`
3. Add any new keywords to `RULE_MAP` in the config section

Example — adding a GitHub Security Advisories check:

```bash
check_ghsa() {
  log "Checking GitHub Security Advisories..."
  local response
  response=$(curl -fsSL \
    "https://api.github.com/advisories?type=reviewed&ecosystem=other&per_page=10" \
    2>/dev/null) || { err "GHSA API failed"; return; }

  while IFS= read -r advisory; do
    local summary severity ghsa_id url
    summary=$(echo "$advisory" | jq -r '.summary')
    echo "$summary" | grep -qiE "nftables|netfilter" || continue

    severity=$(echo "$advisory" | jq -r '.severity' | tr '[:lower:]' '[:upper:]')
    ghsa_id=$(echo "$advisory" | jq -r '.ghsa_id')
    url=$(echo "$advisory" | jq -r '.html_url')

    add_finding "$severity" "GitHub Security Advisories" \
      "${ghsa_id}: $summary" "$url" \
      "$(map_rule_files "$summary")" "$summary"
  done < <(echo "$response" | jq -c '.[]')
}
```

---

## Why not a GitHub Action?

A GitHub Action running on a schedule would work but has two limitations:

1. It runs in GitHub's cloud — outbound requests to NVD, mailing list archives,
   and kernel.org are fine, but it can't access a private Notion workspace
   or internal Slack without exposing credentials in repository secrets.
2. It adds a workflow that runs even on forks, which sends spurious notifications
   to the original channels.

For personal/team use, a server-side cron or systemd timer with local `.env`
credentials is simpler and more private.  If you want a GitHub Action anyway,
the script works as-is — just call it from a workflow step with secrets injected
as environment variables.
