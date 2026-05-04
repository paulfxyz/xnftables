# xnft-monitor — weekday security scanner

Scans upstream sources every weekday morning for security-relevant changes that
could affect the `xnftables` ruleset. Sends findings to Slack, Discord, email,
and/or Notion. Only HIGH and CRITICAL findings trigger notifications by default
(MEDIUM+ for Notion).

---

## What it checks

| Source | What |
|---|---|
| [kernel.org releases](https://www.kernel.org/releases.json) | New stable kernel versions (new releases may include netfilter patches) |
| [netfilter.org downloads](https://www.netfilter.org/projects/nftables/downloads.html) | New `nftables` / `nft` releases |
| [NVD CVE feed](https://services.nvd.nist.gov/rest/json/cves/2.0) | CVEs published in the last 7 days matching `nftables` or `netfilter` |
| [netfilter-devel mailing list](https://lists.netfilter.org/pipermail/netfilter-devel/) | Thread subjects matching security keywords |
| [kernel.org netfilter git](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/log/net/netfilter) | Recent commit subjects matching security keywords |

Security keywords scanned: `CVE`, `use-after-free`, `UAF`, `heap overflow`,
`buffer overflow`, `out-of-bounds`, `privilege escalation`, `bypass`, `crash`,
`panic`, `regression`, `null deref`, `memory leak`, `RCE`.

Breaking-change keywords: `API change`, `ABI break`, `incompatible`,
`deprecated`, `removed`, `behaviour change`.

---

## Rule file mapping

When a finding matches a keyword, the notification names the specific rule file
to review:

| Keyword | Rule file |
|---|---|
| conntrack / ct | `rules/30-established.nft` |
| wireguard / wg | `rules/50-vpn-endpoint.nft`, `rules/20-mesh.nft` |
| icmp / icmpv6 | `rules/60-icmp.nft` |
| meter / rate limit | `rules/50-vpn-endpoint.nft`, `rules/40-services.nft` |
| set / map / element | `rules/00-tables.nft` |
| forward / routing | `rules/70-logging.nft` |
| nat / masquerade | `nftables.conf` |
| tcp flag / bogon / fragment | `rules/05-antiscan.nft` |
| log | `rules/70-logging.nft` |

---

## Quick setup

### 1. Install dependencies

```bash
# Debian / Ubuntu
sudo apt-get install curl jq mailutils

# Arch
sudo pacman -S curl jq s-nail
```

### 2. Configure

```bash
cd scripts/monitor
cp .env.example .env
$EDITOR .env   # fill in your webhook URLs / tokens
```

### 3. Test (dry-run)

```bash
chmod +x xnft-monitor.sh
DRY_RUN=1 ./xnft-monitor.sh
```

### 4a. Deploy as a cron job (simplest)

```bash
# Edit crontab
crontab -e

# Add this line (weekdays at 08:00, adjust path):
0 8 * * 1-5 /opt/xnftables/scripts/monitor/xnft-monitor.sh >> /var/log/xnft-monitor.log 2>&1
```

### 4b. Deploy as a systemd timer (recommended for servers)

```bash
sudo cp monitor.service /etc/systemd/system/xnft-monitor.service
sudo cp monitor.timer   /etc/systemd/system/xnft-monitor.timer

# Edit the service to point to your install path
sudo sed -i 's|/opt/xnftables|/your/actual/path|g' /etc/systemd/system/xnft-monitor.service

sudo systemctl daemon-reload
sudo systemctl enable --now xnft-monitor.timer

# Check it's scheduled
systemctl list-timers xnft-monitor.timer

# Watch the last run
journalctl -u xnft-monitor.service -n 50 -f
```

---

## Notification channels

Configure in `.env`. Run with `--notify <channel>` to override:

```bash
./xnft-monitor.sh --notify slack
./xnft-monitor.sh --notify discord
./xnft-monitor.sh --notify email
./xnft-monitor.sh --notify notion
./xnft-monitor.sh --notify all    # all configured channels
./xnft-monitor.sh --notify none   # print to stdout only
```

### Slack

Create an [Incoming Webhook](https://api.slack.com/messaging/webhooks) and set `SLACK_WEBHOOK_URL`.

### Discord

Create a webhook in channel settings → Integrations → Webhooks and set `DISCORD_WEBHOOK_URL`.

### Email

Requires the `mail` command. For VPS without an MTA, install `msmtp` or `ssmtp` and point it at an SMTP relay (Postmark, SendGrid, etc.):

```bash
# msmtp example config at ~/.msmtprc
account default
host smtp.postmarkapp.com
port 587
auth on
user your-api-token
password your-api-token
tls on
```

### Notion

1. Go to [notion.so/my-integrations](https://www.notion.so/my-integrations) and create an integration
2. Create a database with these properties:
   - `Name` (title)
   - `Severity` (select: CRITICAL / HIGH / MEDIUM / LOW)
   - `Source` (text)
   - `Rule Files` (text)
   - `URL` (URL)
   - `Date` (date)
3. Share the database with your integration
4. Copy the integration token (`secret_…`) and the database ID (from the page URL: `notion.so/YOUR-WORKSPACE/DATABASE_ID?v=…`)
5. Set `NOTION_API_TOKEN` and `NOTION_DATABASE_ID` in `.env`

---

## Output

Each run produces:
- stdout digest (always)
- `/tmp/xnft-findings-YYYY-MM-DD.json` — machine-readable findings
- `/opt/xnftables/scripts/monitor/.last-seen-versions` — version state (prevents duplicate alerts)

---

## Severity levels

| Severity | Triggers notification |
|---|---|
| CRITICAL | All channels |
| HIGH | All channels |
| MEDIUM | Notion only (informational) |
| LOW / INFO | stdout only |

---

## Files

```
scripts/monitor/
  xnft-monitor.sh     ← main script
  .env.example        ← environment variable template (copy to .env)
  monitor.service     ← systemd service unit
  monitor.timer       ← systemd timer unit (weekdays 08:00)
  README.md           ← this file
```
