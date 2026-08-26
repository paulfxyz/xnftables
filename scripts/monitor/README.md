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
| tcp flag / bogon / fragment | `rules/10-antiscan.nft` |
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
umask 077 && cp .env.example .env   # 0600 — see the warning below
$EDITOR .env                        # fill in your webhook URLs / tokens
```

> **`.env` is sourced as shell code**, so it runs with the script's privileges
> (root under the systemd unit). The script *refuses to start* if `.env` is not
> owned by root or by the invoking user, or if it is group/world-writable — it
> checks `stat -c '%u %a'` before sourcing and prints the exact `chmod`/`chown`
> to run. It also warns when the file is merely readable by others, since it
> holds your tokens.
>
> On a server, prefer systemd's `EnvironmentFile=/etc/xnft-monitor.env`
> (root-owned, `0600`): systemd parses it as plain `KEY=VALUE` and never
> executes it. The shipped unit already reads it if present.
>
> All placeholders in `.env.example` are **empty**: a channel whose variable is
> empty is skipped, so a fresh copy notifies nobody until you fill it in.

### 3. Test (dry-run)

```bash
chmod +x xnft-monitor.sh
./xnft-monitor.sh --dry-run          # or: DRY_RUN=1 ./xnft-monitor.sh
```

`--dry-run` runs every check, writes the findings JSON, prints the digest, and
sends nothing. It also does **not** record new kernel/nftables versions in
`.last-seen-versions`, so a dry run can never "consume" the alert for a release
that the next real run would otherwise report.

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

# Optional but recommended: keep tokens out of the code directory
sudo install -m 600 /dev/null /etc/xnft-monitor.env
sudoedit /etc/xnft-monitor.env       # KEY=VALUE lines, parsed by systemd

sudo systemctl daemon-reload
sudo systemctl enable --now xnft-monitor.timer

# Check it's scheduled
systemctl list-timers xnft-monitor.timer

# Watch the last run
journalctl -u xnft-monitor.service -n 50 -f

# Score the sandbox after any edit to the unit
systemd-analyze security xnft-monitor.service
```

### What the unit does

The monitor is an internet-facing HTML/JSON parser, so the unit keeps root but
strips everything root can normally do:

| Directive | Why |
|---|---|
| `NoNewPrivileges=yes` | No setuid/setgid escalation from the script or its children |
| `CapabilityBoundingSet=` / `AmbientCapabilities=` | Empty — uid 0 with no capabilities at all |
| `ProtectSystem=strict` | Entire filesystem read-only, including `/opt/xnftables` — the service cannot rewrite its own script or `.env` |
| `ProtectHome=yes` | No access to user home directories |
| `PrivateTmp=yes` | Private `/tmp`, so the shared-`/tmp` symlink attack is unreachable |
| `StateDirectory=xnft-monitor` + `ReadWritePaths=/var/lib/xnft-monitor` | The only writable path, mode `0700` |
| `Environment=XNFT_STATE_DIR=/var/lib/xnft-monitor` | Points findings + version state at that directory |
| `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` | Outbound HTTPS plus journal/resolver sockets only |
| `MemoryDenyWriteExecute=yes` | No writable+executable memory |
| `SystemCallFilter=@system-service`, `SystemCallErrorNumber=EPERM` | Syscall allowlist for a normal service |
| `ProtectKernel{Tunables,Modules,Logs}`, `ProtectControlGroups`, `ProtectProc=invisible`, `ProcSubset=pid`, `RestrictNamespaces`, `LockPersonality`, `PrivateDevices` | No kernel/host surface, no other processes visible |
| `TimeoutStartSec=300` | A hung upstream cannot leave the oneshot in `activating` forever and silently skip later timer runs |
| `UMask=0077` | Findings and state are owner-only |
| `EnvironmentFile=-/etc/xnft-monitor.env` | Optional root-owned `0600` secrets file, parsed as `KEY=VALUE` and never executed |

`monitor.timer` intentionally has **no** `Requires=xnft-monitor.service` in
`[Unit]`: that would make the timer depend on the service and fire a run at
`systemctl enable --now` time. Scheduling comes from `Unit=` in `[Timer]`.

---

## Notification channels

Configure in `.env` (`NOTIFY_CHANNEL=`). Run with `--notify <channel>` to
override:

```bash
./xnft-monitor.sh --notify slack
./xnft-monitor.sh --notify discord
./xnft-monitor.sh --notify email
./xnft-monitor.sh --notify notion
./xnft-monitor.sh --notify all      # every configured channel (default)
./xnft-monitor.sh --notify none     # print to stdout only
./xnft-monitor.sh --notify=slack    # --notify=<channel> also works
./xnft-monitor.sh --dry-run         # check everything, notify nothing
./xnft-monitor.sh --help            # usage
```

### CLI contract

| Exit code | Meaning |
|---|---|
| 0 | Run completed (individual sources may have failed; those are logged as `ERROR` lines and never abort the run) |
| 1 | Refused to start: unreadable/unsafe `.env`, missing `curl`/`jq`, unusable state directory |
| 2 | Bad command line: unknown flag, `--notify` without a value, unknown channel |

An unknown channel or a missing `--notify` value is a **hard error**, so cron
and `systemctl status` show a failure instead of a green run that quietly sent
nothing.

Tokens and webhook URLs are handed to `curl` on stdin via `curl --config -`,
never as command-line arguments — `/proc/<pid>/cmdline` is world-readable, so
argv secrets are visible to every local user for the lifetime of the request.
Webhook POSTs also do not follow redirects, so a redirect cannot replay the
body (or an `Authorization` header) to a different host.

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
- `$XNFT_STATE_DIR/xnft-findings-YYYY-MM-DD.json` — machine-readable findings
- `$XNFT_STATE_DIR/.last-seen-versions` — version state (prevents duplicate alerts)

### State directory

`XNFT_STATE_DIR` controls where both files live:

| `XNFT_STATE_DIR` | Findings JSON | Version state |
|---|---|---|
| unset (ad-hoc / cron, historical layout) | `/tmp/xnft-findings-YYYY-MM-DD.json` | `scripts/monitor/.last-seen-versions` |
| set, e.g. `/var/lib/xnft-monitor` | `$XNFT_STATE_DIR/xnft-findings-YYYY-MM-DD.json` | `$XNFT_STATE_DIR/.last-seen-versions` |

The systemd unit sets `Environment=XNFT_STATE_DIR=/var/lib/xnft-monitor` and
creates it with `StateDirectory=xnft-monitor` (mode `0700`). Prefer that on any
multi-user host: a root process that opens a predictable path under a
world-writable `/tmp` can be pointed at another file with a pre-planted
symlink. Both files are written to a private temp file in the same directory
and then `rename(2)`d into place (mode `0600`) — `rename` replaces a symlink
instead of following it, and readers never see a partial JSON document.

Set `XNFT_STATE_DIR` for cron deployments too, so the state file does not live
inside (and dirty) the git checkout:

```bash
sudo install -d -m 0700 /var/lib/xnft-monitor
# crontab line:
0 8 * * 1-5 XNFT_STATE_DIR=/var/lib/xnft-monitor /opt/xnftables/scripts/monitor/xnft-monitor.sh --notify all >> /var/log/xnft-monitor.log 2>&1
```

---

## Network behaviour

Every outbound request runs with `--fail --silent --show-error
--connect-timeout 5 --max-time 25 --retry 2 --retry-delay 3 --proto '=https'
--tlsv1.2 --max-filesize 8000000`:

- bounded time, so one hung upstream cannot pin the service;
- HTTPS only, so no plaintext downgrade;
- a size cap on the HTML that gets pattern-matched.

Fetch failures are handled per source (`if ! page=$(http_get …)`), so a dead
kernel.org or a throttled NVD logs one `ERROR` line and the other four sources
still run — `set -euo pipefail` stays on for everything else. NVD answers
throttled requests with HTML rather than JSON; that is detected and skipped
instead of aborting the run. Set `NVD_API_KEY` to raise the quota (it is sent
as a header on stdin, not on argv).

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
