# xnftables

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![nftables](https://img.shields.io/badge/nftables-%E2%89%A50.9.3-orange?logo=linux&logoColor=white)](https://wiki.nftables.org/)
[![WireGuard](https://img.shields.io/badge/WireGuard-mesh--or--nothing-88171A?logo=wireguard&logoColor=white)](https://www.wireguard.com/)
[![Kernel](https://img.shields.io/badge/Linux%20kernel-%E2%89%A55.6-informational?logo=linux&logoColor=white)](https://www.kernel.org/)
[![CI](https://img.shields.io/github/actions/workflow/status/paulfxyz/xnftables/validate.yml?label=nft%20syntax)](https://github.com/paulfxyz/xnftables/actions)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/paulfxyz/xnftables/pulls)
[![Deny All](https://img.shields.io/badge/default%20policy-DROP-critical)](https://github.com/paulfxyz/xnftables)

---

> **If you are not inside the mesh, you see nothing.**
>
> Deny-all defaults. Every exception is explicit, documented and auditable.
> Least privilege at the network layer.

---

## Table of contents

- [The idea](#the-idea)
- [Concepts](#concepts)
- [File structure](#file-structure)
- [Packet flow](#packet-flow)
- [Quick start](#quick-start)
- [WireGuard server setup](#wireguard-server-setup-vpnyourdomaincom)
- [Reloading safely](#reloading-safely)
- [Adding and removing services](#adding-a-service)
- [Reading the logs](#reading-the-logs)
- [Auditing the ruleset](#auditing-the-ruleset)
- [Security model](#security-model)
- [Known bugs fixed in v2](#known-bugs-fixed-in-v2)
- [nftables primer](#nftables-primer)
- [Why nftables over iptables](#why-nftables-over-iptables)
- [Why WireGuard over OpenVPN / IPsec](#why-wireguard-over-openvpn--ipsec)
- [Threat modelling](#threat-modelling)
- [Docker / Podman / LXC interaction](#docker--podman--lxc-interaction)
- [Tailscale / Netbird / Headscale adaptation](#tailscale--netbird--headscale-adaptation)
- [Advanced patterns](#advanced-patterns)
- [Hardening checklist](#hardening-checklist)
- [Tested on](#tested-on)
- [References](#references)

---

## The idea

Most firewall configs are written backwards: start open, punch holes as problems appear, never clean them up. After a year you have a ruleset nobody fully understands, with ports open "just in case" and rules that reference services decommissioned in 2021.

`xnftables` inverts that. The only way traffic reaches this host is through a **WireGuard mesh**. The public internet sees exactly one thing: a UDP port for WireGuard handshakes. Everything else — SSH, HTTP, databases, monitoring — is invisible and unreachable unless you are an authenticated mesh peer.

This is a template policy, not a turnkey product. It is meant to be read, understood, and adapted. Every rule has a comment explaining *why* it exists, not just what it does.

---

## Concepts

### Deny-all default

```nft
chain input {
    type filter hook input priority filter; policy drop;
}
```

The kernel drops any packet that doesn't match a rule. There is no implicit "allow established", no loopback accept, nothing. Every `accept` is deliberate.

This feels uncomfortable the first time. It shouldn't. The alternative — "allow everything and block the bad stuff" — is an infinite game you will always lose. Attackers only need to find one gap. A deny-all policy means you define the entire surface.

### Mesh or nothing

[WireGuard](https://www.wireguard.com/) is a modern VPN protocol built into the Linux kernel since 5.6. Its key properties for this use case:

| Property | Implication |
|---|---|
| Cryptographic peer identity | A packet exiting `wg0` was decrypted with a session key derived from a pre-authorised peer keypair — it cannot be forged |
| Stealth on non-WireGuard traffic | Any datagram that doesn't decrypt correctly is silently dropped — the port appears closed to scanners |
| In-kernel performance | No userspace daemon overhead; same throughput as unencrypted kernel networking |
| Minimal attack surface | ~4,000 lines of code vs hundreds of thousands for OpenVPN/IPsec |

We trust the `wg0` interface at the network layer. A packet that arrived on `wg0` has already been cryptographically authenticated. We then perform a second check — source IP must be in the mesh CIDR — as defence-in-depth against misconfigured `AllowedIPs`.

### Explicit, named, auditable

Every rule carries a `comment` field. `nft list ruleset` shows them. Rules without comments are rejected in PR review.

Changes are committed to git with a message explaining *why* a service was added or removed. The git log is your audit trail. A CI workflow (`.github/workflows/validate.yml`) validates syntax on every push.

---

## File structure

```
nftables.conf                    ← entry point (scoped flush + includes)
rules/
  00-tables.nft                  ← table, chains, named sets (MESH_PEERS, BOGON_V4…)
  05-antiscan.nft                ← bogons, TCP flag abuse, SYN flood, fragments
  10-loopback.nft                ← loopback unconditional accept
  20-mesh.nft                    ← WireGuard trust boundary + break-glass
  30-established.nft             ← conntrack fast-path (public iface)
  40-services.nft                ← per-service allowlist (mesh peers only)
  50-vpn-endpoint.nft            ← WireGuard UDP port (per-source rate-limited)
  60-icmp.nft                    ← controlled ICMP/ICMPv6
  70-logging.nft                 ← catch-all log+drop (must stay last)
scripts/
  reload.sh                      ← safe reload with dry-run + auto-rollback
  check.sh                       ← syntax validator (pre-commit / CI)
.github/
  workflows/validate.yml         ← GitHub Actions CI pipeline
```

The include order matters. `05-antiscan` drops impossible packets first. Loopback and conntrack come before service rules. Logging is always last.

---

## Packet flow

```
Incoming packet
      │
      ▼
[05-antiscan]
  bogon source?          ──────────────────────────────► LOG + DROP
  TCP NULL/XMAS/SYN+FIN? ──────────────────────────────► LOG + DROP
  SYN flood per-source?  ──────────────────────────────► LOG + DROP
  IP fragment (public)?  ──────────────────────────────► LOG + DROP
      │
      ▼
[10-loopback]
  iifname == "lo"        ──────────────────────────────► ACCEPT
      │
      ▼
[20-mesh]
  ADMIN_ALLOWLIST + tcp/22 (break-glass, pre-wg0) ─────► ACCEPT (rate-limited)
  wg0 + saddr ∉ MESH_PEERS ────────────────────────────► LOG + DROP (spoof)
  wg0                    ──────────────────────────────► jump mesh_input
                                  │
                           mesh_input:
                           ct invalid ───────────────────► LOG + DROP
                           ct established ──────────────► ACCEPT (fast-path)
                           saddr ∈ MESH_PEERS ──────────► jump services
                                      │
                               services:
                               tcp/22  ─────────────────► ACCEPT (SSH, rate-limited)
                               tcp/443 ─────────────────► ACCEPT (if enabled)
                               …other explicit services…
                               no match ────────────────► fall-through
      │
      ▼
[30-established]  (public iface only — mesh handled above)
  ct invalid       ────────────────────────────────────► LOG + DROP
  ct established   ────────────────────────────────────► ACCEPT
      │
      ▼
[50-vpn-endpoint]
  udp/51820, per-source rate OK  ──────────────────────► ACCEPT (WireGuard)
  udp/51820, rate exceeded       ──────────────────────► LOG + DROP
      │
      ▼
[60-icmp]
  echo-request from MESH_PEERS   ──────────────────────► ACCEPT (rate-limited)
  echo-request from internet     ──────────────────────► DROP (stealth)
  PMTUD/traceroute types         ──────────────────────► ACCEPT (rate-limited)
  NDP (no nd-redirect)           ──────────────────────► ACCEPT (rate-limited)
  nd-redirect                    ──────────────────────► LOG + DROP (MITM vector)
  everything else                ──────────────────────► LOG + DROP
      │
      ▼
[70-logging]  catch-all
  log (rate-limited 30/s)        ──────────────────────► LOG + DROP
```

---

## Quick start

### Prerequisites

- Linux kernel ≥ 5.6 (WireGuard built-in)
- nftables ≥ 0.9.3 (`nft --version`)
- A running WireGuard server at `vpn.yourdomain.com`
- Your mesh CIDR (this template uses `10.10.0.0/24`)

### 1. Clone

```bash
git clone https://github.com/paulfxyz/xnftables.git
cd xnftables
```

### 2. Adapt to your topology

Open `rules/00-tables.nft` and update the `MESH_PEERS` set:

```nft
set MESH_PEERS {
    type ipv4_addr
    flags interval
    elements = { 10.10.0.0/24 }   # ← your mesh CIDR
}
```

Open `rules/20-mesh.nft` and verify the WireGuard interface name (`wg0`). Open `rules/50-vpn-endpoint.nft` and verify the listen port matches `ListenPort` in your `wg0.conf`.

### 3. Enable services

Open `rules/40-services.nft` and uncomment what this host exposes to mesh peers:

```nft
tcp dport 443  accept comment "service: HTTPS app (mesh-only)"
tcp dport 9100 accept comment "service: Prometheus node exporter (mesh-only)"
```

### 4. Install and reload

```bash
# Dry-run first
sudo nft -c -f nftables.conf

# Install
sudo cp -r rules/ /etc/nftables/
sudo cp nftables.conf /etc/nftables.conf
chmod +x scripts/reload.sh scripts/check.sh

# Safe reload (validates, saves rollback, applies)
sudo ./scripts/reload.sh

# Verify
sudo nft list ruleset
```

### 5. Persist across reboots

```bash
sudo systemctl enable nftables
sudo systemctl start nftables
```

### 6. Install pre-commit hook

```bash
cp scripts/check.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

From now on, every `git commit` that touches `.nft` files will fail if syntax is invalid.

---

## WireGuard server setup (vpn.yourdomain.com)

### /etc/wireguard/wg0.conf (server)

```ini
[Interface]
Address    = 10.10.0.1/24
ListenPort = 51820
PrivateKey = <SERVER_PRIVATE_KEY>

# Routing between mesh peers (hub-and-spoke — optional)
PostUp   = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
# workstation-alice
PublicKey  = <ALICE_PUBLIC_KEY>
AllowedIPs = 10.10.0.2/32

[Peer]
# server-prod-01
PublicKey  = <PROD01_PUBLIC_KEY>
AllowedIPs = 10.10.0.3/32
```

**AllowedIPs per peer** is WireGuard's first isolation layer — a peer assigned `10.10.0.2/32` cannot send traffic claiming to be `10.10.0.5`. Our `@MESH_PEERS` set is the second layer.

### /etc/wireguard/wg0.conf (client/peer)

```ini
[Interface]
Address    = 10.10.0.2/32
PrivateKey = <ALICE_PRIVATE_KEY>
DNS        = 10.10.0.1

[Peer]
PublicKey           = <SERVER_PUBLIC_KEY>
Endpoint            = vpn.yourdomain.com:51820
AllowedIPs          = 10.10.0.0/24   # route only mesh traffic through tunnel
PersistentKeepalive = 25
```

### Key generation

```bash
# Server key pair
wg genkey | tee server.key | wg pubkey > server.pub
chmod 600 server.key

# Peer key pair
wg genkey | tee peer.key | wg pubkey > peer.pub
chmod 600 peer.key

# Optional: pre-shared key (post-quantum resistance layer)
wg genpsk > peer.psk
chmod 600 peer.psk
```

Never commit private keys. Use a secrets manager (HashiCorp Vault, age-encrypted secrets, etc.).

### Peer revocation (without restarting WireGuard)

```bash
# Remove the [Peer] block from wg0.conf, then:
sudo wg syncconf wg0 <(wg-quick strip wg0)

# Verify the peer is gone
sudo wg show
```

---

## Reloading safely

**Never** run `sudo nft -f /etc/nftables/nftables.conf` directly without validating first. A syntax error in any include file after the table flush leaves the machine with **no firewall rules** — completely open.

### Safe reload script

```bash
sudo ./scripts/reload.sh
```

What it does:
1. Runs `nft -c` (dry-run — validates without touching state)
2. Saves a rollback dump of the current live ruleset
3. Applies the new config
4. If `nft -f` fails, auto-reverts to the saved dump

### Remote-safe testing (auto-rollback)

When testing new rules on a remote server where a lockout would be catastrophic:

```bash
# Apply rules, but auto-revert after 60 seconds unless you cancel
sudo ./scripts/reload.sh --confirm-timeout 60
# If the new rules work: kill the background revert job (script prints the PID)
# If you get locked out: wait 60 seconds, rules revert automatically
```

### Validate only (no apply)

```bash
sudo ./scripts/reload.sh --dry-run
# or directly:
sudo nft -c -f /etc/nftables/nftables.conf
```

---

## Adding a service

1. Uncomment or add a rule in `rules/40-services.nft`
2. Template: `tcp dport <PORT> accept comment "service: <NAME> — <PURPOSE> (mesh-only)"`
3. Dry-run: `sudo ./scripts/reload.sh --dry-run`
4. Reload: `sudo ./scripts/reload.sh`
5. Test from a mesh peer: `nc -zv 10.10.0.1 <PORT>`
6. Commit: `git commit -m "feat: open TCP/<PORT> for <NAME> on <host>"`

## Removing a service

Comment out the rule (don't delete it), reload, test, commit with a reason. The git diff is the audit trail.

---

## Reading the logs

All log lines are prefixed `XNFT-<CATEGORY>:` for easy filtering.

| Prefix | Meaning |
|---|---|
| `XNFT-DROP` | Catch-all drop — not matched by any allow rule |
| `XNFT-INVALID` | Conntrack invalid state (public iface) |
| `XNFT-MESH-INVALID` | Conntrack invalid state inside the mesh tunnel |
| `XNFT-MESH-SPOOF` | Packet inside `wg0` with source IP outside `@MESH_PEERS` |
| `XNFT-MESH-UNKNOWN` | Packet inside `wg0` from unrecognised source |
| `XNFT-WG-RATELIMIT` | WireGuard handshake per-source rate limit exceeded |
| `XNFT-BREAKGLASS-RATELIMIT` | Break-glass SSH rate limit exceeded (brute-force attempt) |
| `XNFT-BOGON` | Bogon/martian source IP on public interface |
| `XNFT-LOOPBACK-SPOOF` | 127.x / ::1 source on non-loopback interface |
| `XNFT-TCPFL-NULL` | TCP NULL scan (no flags) |
| `XNFT-TCPFL-XMAS` | TCP XMAS scan (FIN+PSH+URG) |
| `XNFT-TCPFL-SYNFIN` | TCP SYN+FIN (impossible combination) |
| `XNFT-TCPFL-SYNRST` | TCP SYN+RST (impossible combination) |
| `XNFT-TCPFL-FIN` | TCP FIN scan (bare FIN on new connection) |
| `XNFT-SYNFLOOD` | SYN flood per-source rate limit exceeded |
| `XNFT-FRAGMENT` | Fragmented IPv4 packet on public interface |
| `XNFT-SSH-RATELIMIT` | SSH new-connection rate limit exceeded (mesh peer) |
| `XNFT-ICMP4-DROP` | Unmatched IPv4 ICMP |
| `XNFT-ICMP4-EXCESS` | ICMP essential types rate limit exceeded |
| `XNFT-ICMP6-DROP` | Unmatched ICMPv6 |
| `XNFT-ICMP6-REDIRECT` | ICMPv6 nd-redirect dropped (MITM vector) |
| `XNFT-ICMP6-EXCESS` | ICMPv6 PMTUD rate limit exceeded |
| `XNFT-NDP-EXCESS` | NDP rate limit exceeded |
| `XNFT-FWD-DROP` | Forward chain drop |
| `XNFT-FWD-INVALID` | Forward chain invalid conntrack state |

### Live monitoring

```bash
# All xnftables events
journalctl -k -f | grep "XNFT-"

# Scan activity only
journalctl -k -f | grep -E "XNFT-(TCPFL|BOGON|SYNFLOOD|FRAGMENT)"

# Top source IPs in the catch-all (last 1000 lines)
journalctl -k -n 1000 | grep "XNFT-DROP" \
  | grep -oP 'SRC=\S+' | sort | uniq -c | sort -rn | head -20

# Decode a log line
# Apr 26 19:01:44 host kernel: XNFT-TCPFL-XMAS: IN=eth0 SRC=185.220.101.5
#   DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=443 FIN PSH URG
```

### SIEM / Loki forwarding

```
# /etc/rsyslog.conf — forward all XNFT events to remote syslog
:msg, contains, "XNFT-"  @your-siem-host:514

# Or write to a dedicated file
:msg, contains, "XNFT-"  /var/log/xnftables.log
& stop
```

---

## Auditing the ruleset

```bash
# Dump the full live ruleset
sudo nft list ruleset

# List only the services chain
sudo nft list chain inet filter services

# List named sets (peer CIDRs)
sudo nft list sets

# Live rule hit counters (add 'counter' to any rule first)
watch -n 1 'sudo nft list chain inet filter services'

# Validate without applying
sudo nft -c -f /etc/nftables/nftables.conf

# Trace a specific packet through the ruleset
sudo nft 'add rule inet filter input meta nftrace set 1'
sudo nft monitor trace
# remove the trace rule after:
sudo nft list chain inet filter input -a
sudo nft delete rule inet filter input handle <HANDLE>
```

---

## Security model

### What this policy protects against

| Threat | Mitigation |
|---|---|
| Port scanning from the internet | Default drop; only UDP/51820 responds, and only to valid WireGuard datagrams |
| Service enumeration | No ports respond to unauthenticated connections |
| Brute-force SSH | SSH is invisible to non-mesh traffic; rate-limited within mesh |
| Spoofed source IPs inside tunnel | WireGuard `AllowedIPs` + nftables `@MESH_PEERS` dual check |
| WireGuard handshake flood (DoS) | Per-source meter — attacker can only exhaust their own budget |
| TCP scan techniques (NULL/XMAS/FIN) | Detected and dropped in `05-antiscan.nft` with dedicated log prefixes |
| SYN flood | Per-source rate limit (+ kernel SYN cookies recommended) |
| Bogon / martian source addresses | `BOGON_V4` set blocks RFC1918/documentation/reserved ranges on public iface |
| IP fragmentation attacks | Fragments dropped on public interface |
| Invalid conntrack state (mesh) | Checked inside `mesh_input` before service rules — bugs 1B/2A fixed |
| PMTUD blackhole injection | ICMP dest-unreachable rate-limited to 10/s |
| ICMPv6 MITM via nd-redirect | `nd-redirect` explicitly dropped — bug 4B fixed |
| NDP neighbour-cache exhaustion | NDP rate-limited at 50/s |
| Unsafe reload (open window) | Scoped table flush + `reload.sh` dry-run guard |
| Docker NAT table destruction | Scoped flush instead of `flush ruleset` — bug 10A fixed |

### What this policy does NOT protect against

| Threat | Notes |
|---|---|
| Compromised mesh peer | A valid key can reach all open services. Use per-peer rules for isolation. |
| Application-layer vulnerabilities | nftables is L3/L4. Deploy a WAF for HTTP-level threats. |
| Egress data exfiltration | Output policy is `accept` by default. Add egress rules if needed. |
| Physical / hypervisor compromise | Out of scope for a network firewall. |

---

## Known bugs fixed in v2

This section documents every bug found in v1 and how it was fixed. Transparency about past mistakes is part of what makes a ruleset auditable.

### BUG 1A — Anti-spoof rule was dead code

**v1 code:**
```nft
chain input {
    iifname "wg0" jump mesh_input         # ← all wg0 packets diverted here
    iifname "wg0" ip saddr != @MESH_PEERS # ← DEAD: never reached
        log prefix "XNFT-MESH-SPOOF: " drop
}
```
`jump` transfers control to `mesh_input` which always terminates with `accept` or `drop`. The second rule was unreachable. `XNFT-MESH-SPOOF:` never appeared in logs. Any monitoring built on that prefix was silently broken.

**Fix:** Spoof check moved before the jump.

---

### BUG 1B / 2A — Conntrack invalid check bypassed for mesh traffic

All `wg0` packets entered `mesh_input` and hit `jump services` before the `ct state invalid drop` in `30-established.nft`. A compromised mesh peer could send invalid-state packets directly to services.

**Fix:** Conntrack checks (`ct invalid` drop + `ct established` accept) added at the top of `mesh_input`.

---

### BUG 3A — WireGuard rate limit was a single shared bucket

```nft
udp dport 51820 limit rate 20/minute accept  # global counter
```
One attacker sending 20 UDP/minute exhausted the entire budget. All other legitimate peers hit the rate limit for the rest of that minute window. Classic deny-of-service against the WireGuard endpoint itself.

**Fix:** Replaced with a `meter` — one independent token bucket per source IP.

---

### BUG 4B — `nd-redirect` accepted from any source (IPv6 MITM)

ICMPv6 Redirect (type 137) instructs the host to change its first-hop router for a destination. Accepting it from any source allowed an attacker on the same network segment to silently redirect IPv6 connections through their machine. RFC 4861 §8.1 requires redirects come from the current first-hop router only, which on a WireGuard mesh doesn't apply.

**Fix:** `nd-redirect` removed from the NDP accept list; explicit log+drop rule added.

---

### BUG 7A — Break-glass SSH was permanently unreachable

The `ADMIN_ALLOWLIST` SSH rule was inside the `services` chain, which is only reachable from `mesh_input`, which only fires for `iifname "wg0"` traffic. When WireGuard goes down (the exact scenario requiring break-glass), the rule never fired.

**Fix:** Break-glass rule moved to the `input` chain, before the `wg0` jump, with its own rate limit.

---

### BUG 9A — Forward chain dropped all established forwarded traffic

The forward chain had `policy drop` but no `ct state established accept`. WireGuard hub routing (where this host forwards traffic between mesh peers) silently dropped all forwarded connections.

**Fix:** `ct invalid` drop + `ct established` accept added to forward chain in `70-logging.nft`.

---

### BUG 10A — `flush ruleset` destroyed Docker/libvirt NAT rules

`flush ruleset` removes ALL tables across ALL families — including Docker's `ip nat` and `ip filter` tables. Docker doesn't reinject them until restart. After any nftables reload, container networking silently broke.

**Fix:** Replaced `flush ruleset` with scoped table operations:
```nft
add table inet filter
delete table inet filter
```
Only the `inet filter` table is touched. Docker's tables are untouched.

---

### BUG 13A — Unsafe reload left machine open on syntax error

`flush ruleset` (now fixed as 10A) executed immediately when encountered. A syntax error in any subsequent include caused: rules flushed, load aborted, machine left with no firewall.

**Fix:** `reload.sh` script validates with `nft -c` before applying. Scoped table flush means a failed load leaves the old rules intact rather than leaving nothing.

---

## nftables primer

### Tables and chains

In `iptables` the tables (`filter`, `nat`, `mangle`) are fixed. In nftables you create your own tables with any name, and define which hooks they attach to and at what priority.

```nft
table inet filter {        # "inet" = covers IPv4 + IPv6 simultaneously
    chain input {
        type filter        # hook type: filter, nat, or route
        hook input         # netfilter hook: input, forward, output, prerouting, postrouting
        priority filter;   # priority 0; use "raw" (-300) for early-exit optimisation
        policy drop;       # default verdict if no rule matches
    }
}
```

### Rule anatomy

```nft
[match expressions]  [statement]  [comment]

# Examples:
iifname "wg0"  ip protocol tcp  tcp dport 22  accept  comment "SSH from mesh"
ct state { established, related }  accept  comment "conntrack fast-path"
ip saddr @MESH_PEERS  jump services  comment "known peer"
meter syn_flood { ip saddr limit rate 30/second }  comment "SYN rate-limit"
limit rate 5/second  log prefix "DROP: "  drop  comment "rate-limited drop"
```

### Sets and meters

**Sets** match against lists or ranges in O(1):
```nft
set BOGON_V4 {
    type ipv4_addr
    flags interval
    elements = { 10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12 }
}
ip saddr @BOGON_V4 drop
```

**Meters** (named sets with `dynamic` flag) create per-source token buckets:
```nft
# Each source IP gets its own independent bucket
tcp flags syn  meter syn_flood { ip saddr timeout 10s limit rate 30/second }  accept
```
Without a meter, `limit rate 30/second` is a single global counter — one source exhausts the budget for everyone.

### Verdict maps

Route traffic to different chains based on a key — avoids long if/else chains:
```nft
tcp dport vmap {
    22   : jump ssh_chain,
    80   : jump http_chain,
    443  : jump https_chain
}
```

### Atomic reload

```bash
# This is atomic — old rules replaced in a single transaction:
nft -f /etc/nftables/nftables.conf
# If the file has errors, the old rules remain intact (with scoped flush).
```

### Priorities

| Alias | Value | Use case |
|---|---|---|
| `raw` | -300 | Before conntrack — drop malicious packets before they enter state table |
| `mangle` | -150 | Packet modification (TTL, DSCP) |
| `filter` | 0 | Standard filtering (this ruleset) |
| `security` | 50 | SELinux / AppArmor hooks |

Moving `ct state invalid drop` to a `raw` priority chain would prevent invalid packets from entering the conntrack table at all — a performance and resource gain. See the "Advanced patterns" section.

---

## Why nftables over iptables

| | iptables | nftables |
|---|---|---|
| IPv4 + IPv6 | Separate `iptables` / `ip6tables` | Single `inet` table |
| Rule evaluation | Linear scan | JIT bytecode, O(1) set lookups |
| Atomic reload | Not atomic | Fully atomic transactions |
| Named sets | Requires external `ipset` | Built-in, first-class |
| Per-source rate limit | Requires `hashlimit` module | Native `meter` |
| Rule comments | Not supported | `comment` field on every rule |
| Scripting | Shell string concatenation | Include system, variables, maps |
| Maintenance | Legacy — no new features | Actively developed |

`iptables` is now a compatibility shim over nftables on modern distros (`iptables-legacy` calls `nft` internally). There is no reason to use it for new deployments.

---

## Why WireGuard over OpenVPN / IPsec

| | OpenVPN | IPsec (strongSwan) | WireGuard |
|---|---|---|---|
| Codebase size | ~70,000 lines | ~400,000 lines | ~4,000 lines |
| Attack surface | Large (userspace TLS) | Very large | Minimal |
| Performance | ~200–400 Mbps | ~400–600 Mbps | Line-rate |
| Key exchange | TLS / certificates | IKEv1/IKEv2 | Noise Protocol |
| Configuration | Complex | Very complex | 5–10 lines per peer |
| Kernel integration | Userspace daemon | Partial | Native (kernel 5.6+) |
| Roaming | Limited | Limited | Automatic |

WireGuard's cryptographic primitives:
- **Curve25519** — Diffie-Hellman key exchange
- **ChaCha20-Poly1305** — authenticated encryption
- **BLAKE2s** — hashing
- **SipHash24** — hashtable keys

No negotiable cipher suites. No downgrade attacks. No BEAST/POODLE-class vulnerabilities.

---

## Threat modelling

### The internet scanner

They find your server IP (it's in DNS, BGP, certificate transparency logs). They run:
```
nmap -sS -sV -O -p- your.server.ip
```

With `xnftables` active:
```
Not shown: 65534 filtered tcp ports (no-response)
PORT      STATE         SERVICE
51820/udp open|filtered unknown
```

One port. No banner. No service version. No OS fingerprint.

Without it (default Ubuntu):
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu
80/tcp open  http    nginx 1.26.0
443/tcp open https   nginx 1.26.0
```

Three services, exact versions, ready for CVE matching.

### The TCP scanner

Stealth scanners use invalid TCP flag combinations to probe without completing a handshake:

```
nmap -sN your.server.ip   # NULL scan: no flags
nmap -sX your.server.ip   # XMAS scan: FIN+PSH+URG
nmap -sF your.server.ip   # FIN scan: bare FIN
```

`05-antiscan.nft` drops all of these with dedicated log prefixes, so you can see the scan attempt in logs and correlate with other activity.

### The compromised mesh peer

WireGuard guarantees authentication, not authorisation. A peer with a valid key pair can reach all services that `40-services.nft` opens. Mitigations:

1. **Per-peer sub-chains** (see Advanced patterns)
2. **Immediate revocation** — `wg syncconf wg0 <(wg-quick strip wg0)` without restart
3. **mTLS at the application layer** — client certificates for sensitive services
4. **Egress control** — if a peer is compromised, limit what it can reach from this host

### Off-path ICMP attacks

Even with the source restriction on `echo-request`, `destination-unreachable` must be accepted from the internet (required for PMTUD). An off-path attacker who knows a TCP connection's 4-tuple (src IP, src port, dst IP, dst port) can:

- Send a forged `type 3 code 4` (frag-needed) with `MTU=68` — forces retransmission at minimum size, crushing throughput
- Send a forged `type 3 code 1` (host unreachable) — can terminate a TCP connection

These attacks require knowing the 4-tuple (difficult but not impossible for long-lived connections). Mitigation: the rate limit on ICMP essential types (10/s) bounds the impact. For high-security environments, consider restricting `destination-unreachable` to `ct state established` only — at the cost of potential PMTUD issues for new connections.

---

## Docker / Podman / LXC interaction

Container runtimes inject their own nftables/iptables rules for NAT and forwarding. Understanding the interaction is critical.

### Docker

Docker manages two nftables-compatible tables in the `ip` family (IPv4 only):
- `ip nat` — DNAT for port forwarding (`-p 8080:80`), MASQUERADE for egress
- `ip filter` — the `DOCKER` and `DOCKER-USER` chains

**The `flush ruleset` problem (BUG 10A):** `flush ruleset` destroys ALL tables in ALL families, including Docker's. Container networking breaks silently. `xnftables` uses scoped flush (`add table / delete table`) to avoid this.

**Port exposure conflict:** If Docker exposes a container port (`-p 8080:80`), it adds DNAT rules to `ip nat` that bypass the `inet filter` table entirely. A container port published with `-p` is reachable from the internet even if `inet filter` drops port 8080.

To fix this: either use `--network=host` containers managed by nftables directly, or add DOCKER-USER rules:
```bash
# Block all container port-forward access from the internet
# (allow only from mesh peers or localhost)
iptables -I DOCKER-USER -i eth0 ! -s 10.10.0.0/24 -j DROP
```

Or use `docker run --network=none` / `--network=container:name` for containers that should only talk on the mesh.

**Best practice:** Run containers without `-p` port publishing. Access them via their mesh IP if the container host is a WireGuard peer, or via a reverse proxy on the mesh.

### Podman (rootless)

Rootless Podman uses `pasta` or `slirp4netns` for networking, which operates in user namespaces. It doesn't touch the host's nftables tables. No conflict.

Rootful Podman behaves like Docker and has the same DNAT bypass issue.

### LXC / LXD

LXD creates a bridge interface (`lxdbr0`) and manages forwarding via iptables-compat. The `flush ruleset` issue applies. Use scoped flush (already in `xnftables`) and add forwarding rules if needed:

```nft
chain forward {
    # Allow LXD container traffic
    iifname "lxdbr0" accept comment "forward: LXD bridge egress"
    oifname "lxdbr0" accept comment "forward: LXD bridge ingress"
}
```

---

## Tailscale / Netbird / Headscale adaptation

`xnftables` uses WireGuard directly. Tailscale, Netbird, and Headscale are control-plane layers on top of WireGuard — the nftables policy adapts with minimal changes.

### Tailscale

Tailscale manages WireGuard via its own daemon and creates a `tailscale0` interface. Replace `wg0` with `tailscale0`:

```nft
# 20-mesh.nft — change interface name
iifname "tailscale0" jump mesh_input

# 05-antiscan.nft — exclude tailscale interface from bogon filter
iifname != "tailscale0" ip saddr @BOGON_V4 drop
```

Tailscale assigns IPs from `100.64.0.0/10` (CGNAT space) by default. Update `MESH_PEERS`:
```nft
set MESH_PEERS {
    type ipv4_addr
    flags interval
    elements = { 100.64.0.0/10 }  # Tailscale CGNAT range
}
```

And remove `100.64.0.0/10` from `BOGON_V4` (it's in there by default as RFC6598).

WireGuard port: Tailscale uses ephemeral UDP ports, not 51820. Remove or comment out `50-vpn-endpoint.nft` — Tailscale manages its own NAT traversal.

### Netbird

Netbird also creates a WireGuard interface (typically `wt0`) with a configurable CIDR. Substitute `wt0` for `wg0` and your Netbird CIDR for `10.10.0.0/24`.

### Headscale (self-hosted Tailscale coordinator)

Interface is still `tailscale0`. Changes are identical to the Tailscale section above.

---

## Advanced patterns

### Per-peer isolation

Limit what each mesh peer can reach:

```nft
chain services {
    # Alice's workstation: SSH only
    ip saddr 10.10.0.2 tcp dport 22    accept comment "peer alice: SSH"
    ip saddr 10.10.0.2                 drop   comment "peer alice: deny all else"

    # CI server: PostgreSQL and node exporter only
    ip saddr 10.10.0.3 tcp dport 5432  accept comment "peer ci: PostgreSQL"
    ip saddr 10.10.0.3 tcp dport 9100  accept comment "peer ci: node exporter"
    ip saddr 10.10.0.3                 drop   comment "peer ci: deny all else"
}
```

### Output egress control

```nft
chain output {
    type filter hook output priority filter; policy drop;
    oifname "lo"                      accept comment "egress: loopback"
    ct state { established, related } accept comment "egress: established"
    ct state invalid                  drop   comment "egress: invalid state"
    udp dport 53                      accept comment "egress: DNS"
    tcp dport 53                      accept comment "egress: DNS/TCP"
    udp dport 123                     accept comment "egress: NTP"
    tcp dport { 80, 443 }             accept comment "egress: HTTP/HTTPS"
    udp dport 51820                   accept comment "egress: WireGuard"
    log prefix "XNFT-EGRESS-DROP: "   drop   comment "egress: catch-all"
}
```

### Mesh hub routing (WireGuard server forwards between peers)

```nft
chain forward {
    type filter hook forward priority filter; policy drop;
    ct state invalid  drop
    ct state { established, related }  accept
    iifname "wg0" oifname "wg0"
        ip saddr @MESH_PEERS ip daddr @MESH_PEERS
        accept comment "forward: mesh-to-mesh via hub"
    log prefix "XNFT-FWD-DROP: " drop
}
```

### Connection rate limiting per service

```nft
tcp dport 22 ct state new \
    limit rate 6/minute \
    accept comment "service: SSH new-conn rate-limit"
tcp dport 22 ct state new \
    log prefix "XNFT-SSH-RATELIMIT: " drop comment "service: SSH rate exceeded"
tcp dport 22 accept comment "service: SSH"
```

### Early invalid-drop at raw priority (performance)

Moving `ct state invalid` to the `raw` hook prevents invalid packets from entering the conntrack table at all, which is a significant resource saving under flood conditions:

```nft
table inet raw {
    chain prerouting {
        type filter hook prerouting priority raw; policy accept;
        ct state invalid  log prefix "XNFT-RAW-INVALID: " drop
        # Optional: notrack for high-volume UDP flows that don't need state
        # udp dport 51820  notrack
    }
}
```

### Port knocking (pure nftables)

Open SSH only after a specific sequence of connection attempts:

```nft
table inet portknock {
    set step1 { type ipv4_addr; flags dynamic, timeout; timeout 5s }
    set open  { type ipv4_addr; flags dynamic, timeout; timeout 30s }

    chain input {
        type filter hook input priority filter - 1; policy accept;
        tcp dport 7000 ct state new add @step1 { ip saddr } drop
        tcp dport 8000 ip saddr @step1 ct state new add @open { ip saddr } drop
        tcp dport 22   ip saddr != @open drop
    }
}
```

### Dynamic peer sync from WireGuard state

Keep `@MESH_PEERS` in sync with the actual WireGuard peer list:

```bash
#!/bin/bash
# scripts/sync-peers.sh
nft flush set inet filter MESH_PEERS
wg show wg0 allowed-ips | awk '{print $2}' | while read cidr; do
    nft add element inet filter MESH_PEERS "{ $cidr }"
done
```

Run via `PostUp` in `wg0.conf` or a systemd timer.

---

## Hardening checklist

```
Network layer
[ ] MESH_PEERS contains only your mesh CIDR — not 0.0.0.0/0
[ ] MESH_PEERS6 is either populated or explicitly documented as unused
[ ] BOGON_V4 in 00-tables.nft reviewed — no ranges removed without reason
[ ] WireGuard interface name matches across all rule files (wg0, wt0, tailscale0…)
[ ] ListenPort in wg0.conf matches udp dport in 50-vpn-endpoint.nft
[ ] Only services this host actually runs are uncommented in 40-services.nft
[ ] Every uncommented rule has a comment= field

WireGuard
[ ] Private keys are chmod 600 and not committed to git
[ ] Each peer uses AllowedIPs = <their IP>/32 (not 0.0.0.0/0 unless intentional)
[ ] PersistentKeepalive set on mobile/roaming peers
[ ] Pre-shared keys generated and used (post-quantum protection layer)

Break-glass
[ ] ADMIN_ALLOWLIST contains a real, routable IP (NOT 192.0.2.x/198.51.100.x/203.0.113.x)
[ ] The emergency back-door has been tested from the allowlist IP before you need it

Reload safety
[ ] nftables.service is enabled for boot persistence
[ ] reload.sh is used for all rule changes (not nft -f directly)
[ ] Pre-commit hook installed: cp scripts/check.sh .git/hooks/pre-commit

Kernel settings (complement to nftables rules)
[ ] net.ipv4.tcp_syncookies = 1  (SYN cookie protection)
[ ] net.ipv4.conf.all.rp_filter = 1  (kernel-level reverse-path filtering)
[ ] net.ipv4.conf.all.log_martians = 1  (kernel martian logging as second opinion)
[ ] net.ipv4.conf.all.accept_redirects = 0  (no ICMP redirects)
[ ] net.ipv6.conf.all.accept_redirects = 0

Logging
[ ] Log shipping configured (rsyslog/journald → SIEM or Loki)
[ ] Alert on XNFT-BREAKGLASS-RATELIMIT (someone is trying the emergency back-door)
[ ] Alert on XNFT-MESH-SPOOF (something suspicious inside the tunnel)

Testing
[ ] SSH from mesh peer works
[ ] SSH from public internet does NOT work
[ ] WireGuard handshake from new peer works
[ ] nmap from public internet shows only UDP/51820
[ ] nmap -sN/-sX/-sF shows all ports filtered (TCP scan protection working)
[ ] Container networking (if applicable) works after nftables reload
```

---

## Tested on

| Distro | Kernel | nftables |
|---|---|---|
| Debian 12 (Bookworm) | 6.1 | 1.0.6 |
| Ubuntu 24.04 LTS | 6.8 | 1.0.9 |
| Arch Linux (rolling) | 6.9+ | 1.1.x |

---

## References

- [nftables wiki](https://wiki.nftables.org/) — canonical reference
- [nftables Quick Reference](https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes)
- [WireGuard documentation](https://www.wireguard.com/)
- [WireGuard whitepaper](https://www.wireguard.com/papers/wireguard.pdf)
- [Noise Protocol Framework](https://noiseprotocol.org/) — WireGuard's cryptographic foundation
- [RFC 4861](https://www.rfc-editor.org/rfc/rfc4861) — IPv6 Neighbour Discovery (nd-redirect rules)
- [RFC 1918](https://www.rfc-editor.org/rfc/rfc1918) — private address space (BOGON_V4)
- [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737) — documentation IPs (never use in production)
- [Linux conntrack tuning](https://www.kernel.org/doc/html/latest/networking/nf_conntrack-sysctl.rst)
- [nft(8) man page](https://www.netfilter.org/projects/nftables/manpage.html)
- [ipverse country IP blocks](https://ipverse.net/ipblocks/data/countries/) — for geo-blocking

---

## License

MIT — use it, adapt it, share it.
If you improve it, send a PR.
