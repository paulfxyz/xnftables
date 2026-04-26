# xnftables

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![nftables](https://img.shields.io/badge/nftables-%E2%89%A50.9.3-orange?logo=linux&logoColor=white)](https://wiki.nftables.org/)
[![WireGuard](https://img.shields.io/badge/WireGuard-mesh--or--nothing-88171A?logo=wireguard&logoColor=white)](https://www.wireguard.com/)
[![Kernel](https://img.shields.io/badge/Linux%20kernel-%E2%89%A55.6-informational?logo=linux&logoColor=white)](https://www.kernel.org/)
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
- [Adding and removing services](#adding-a-service)
- [Reading the logs](#reading-the-logs)
- [Auditing the ruleset](#auditing-the-ruleset)
- [Security model](#security-model)
- [nftables primer](#nftables-primer)
- [Why nftables over iptables](#why-nftables-over-iptables)
- [Why WireGuard over OpenVPN / IPsec](#why-wireguard-over-openvpn--ipsec)
- [Threat modelling](#threat-modelling)
- [Advanced patterns](#advanced-patterns)
- [Hardening checklist](#hardening-checklist)
- [Tested on](#tested-on)
- [References](#references)

---

## The idea

Most firewall configs are written backwards: start open, punch holes as problems appear, never clean them up.  After a year you have a ruleset nobody fully understands, with ports open "just in case" and rules that reference services decommissioned in 2021.

`xnftables` inverts that.  The only way traffic reaches this host is through a **WireGuard mesh**.  The public internet sees exactly one thing: a UDP port for WireGuard handshakes.  Everything else — SSH, HTTP, databases, monitoring — is invisible and unreachable unless you are an authenticated mesh peer.

This is a template policy, not a turnkey product.  It is meant to be read, understood, and adapted.  Every rule has a comment explaining *why* it exists, not just what it does.

---

## Concepts

### Deny-all default

```nft
chain input {
    type filter hook input priority filter; policy drop;
}
```

The kernel drops any packet that doesn't match a rule.  There is no implicit "allow established", no loopback accept, nothing.  Every `accept` is deliberate.

This feels uncomfortable the first time.  It shouldn't.  The alternative — "allow everything and block the bad stuff" — is an infinite game you will always lose.  Attackers only need to find one gap.  A deny-all policy means you define the entire surface.

### Mesh or nothing

[WireGuard](https://www.wireguard.com/) is a modern VPN protocol built into the Linux kernel since 5.6.  Its key properties for this use case:

| Property | Implication |
|---|---|
| Cryptographic peer identity | A packet exiting `wg0` was decrypted with a session key derived from a pre-authorised peer keypair — it cannot be forged |
| Stealth on non-WireGuard traffic | Any datagram that doesn't decrypt correctly is silently dropped — the port appears closed to scanners |
| In-kernel performance | No userspace daemon overhead; same throughput as unencrypted kernel networking |
| Minimal attack surface | ~4,000 lines of code vs hundreds of thousands for OpenVPN/IPsec |

We trust the `wg0` interface at the network layer.  A packet that arrived on `wg0` has already been cryptographically authenticated.  We then perform a second check — source IP must be in the mesh CIDR — as defence-in-depth against misconfigured `AllowedIPs`.

### Explicit, named, auditable

Every rule carries a `comment` field.  `nft list ruleset` shows them.  Rules with no comment are rejected in PR.

Changes are committed to git with a message explaining *why* a service was added or removed.  The git log is your audit trail.

---

## File structure

```
nftables.conf              ← entry point (flush + include chain)
rules/
  00-tables.nft            ← table, chain definitions, named sets, default DROP
  10-loopback.nft          ← loopback unconditional accept
  20-mesh.nft              ← WireGuard interface trust + source validation
  30-established.nft       ← conntrack: established/related accept, invalid drop
  40-services.nft          ← per-service allowlist (mesh peers only)
  50-vpn-endpoint.nft      ← WireGuard UDP port (only public-internet rule)
  60-icmp.nft              ← controlled ICMP/ICMPv6
  70-logging.nft           ← catch-all log+drop (must stay last)
```

The include order matters.  Loopback and conntrack come before service rules so that established-connection packets short-circuit the full evaluation.  Logging always comes last so it only fires on packets that were not accepted anywhere.

---

## Packet flow

```
Incoming packet
      │
      ▼
[iifname == "lo"] ──────────────────────────────────────────► ACCEPT  (10-loopback)
      │
      ▼
[ct state invalid] ─────────────────────────────────────────► LOG + DROP  (30-established)
      │
      ▼
[ct state established/related] ─────────────────────────────► ACCEPT  (30-established)
      │
      ▼
[iifname == "wg0"] ──► [ip saddr ∈ @MESH_PEERS] ──► jump services
      │                          │                          │
      │                    else  └──────────────────────────► LOG + DROP (spoof)
      │                                                       (20-mesh)
      │
      │         ┌─ tcp dport 22   ──► ACCEPT  (SSH)
      │         ├─ tcp dport 443  ──► ACCEPT  (HTTPS, if enabled)
      └── wg0 ──┤─ tcp dport 9100 ──► ACCEPT  (Prometheus, if enabled)
                ├─ …any other explicit service…
                └─ no match      ──► fall-through → LOG + DROP  (70-logging)
      │
      ▼
[udp dport 51820, rate ≤ 20/min] ──────────────────────────► ACCEPT  (50-vpn-endpoint)
[udp dport 51820, rate > 20/min] ──────────────────────────► LOG + DROP
      │
      ▼
[ICMP essential types] ─────────────────────────────────────► ACCEPT  (60-icmp)
[ICMP echo-request, saddr ∈ @MESH_PEERS] ──────────────────► ACCEPT
[ICMP other] ───────────────────────────────────────────────► LOG + DROP
      │
      ▼
[everything else] ──────────────────────────────────────────► LOG + DROP  (70-logging)
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

Open `rules/20-mesh.nft` and verify the WireGuard interface name:

```nft
iifname "wg0" jump mesh_input   # ← your wg interface (wg0, wg1, tailscale0…)
```

Open `rules/50-vpn-endpoint.nft` and verify the listen port:

```nft
udp dport 51820   # ← must match ListenPort in /etc/wireguard/wg0.conf
```

### 3. Enable services

Open `rules/40-services.nft` and uncomment the services this host exposes to mesh peers.  Example — a host running an HTTPS app and Prometheus exporter:

```nft
tcp dport 443  accept comment "service: HTTPS app (mesh-only)"
tcp dport 9100 accept comment "service: Prometheus node exporter (mesh-only)"
```

### 4. Install

```bash
# Dry-run first — validates syntax without loading
sudo nft -c -f nftables.conf

# Install rules/ to system path
sudo cp -r rules/ /etc/nftables/
sudo cp nftables.conf /etc/nftables.conf

# Load
sudo nft -f /etc/nftables/nftables.conf

# Verify
sudo nft list ruleset
```

### 5. Persist across reboots

```bash
# systemd
sudo systemctl enable nftables
sudo systemctl start nftables
```

On Debian/Ubuntu, `nftables.service` reads `/etc/nftables.conf` on start.

---

## WireGuard server setup (vpn.yourdomain.com)

This section describes a minimal server configuration compatible with the mesh policy above.  Adapt IP ranges and interface names to your environment.

### /etc/wireguard/wg0.conf (server)

```ini
[Interface]
Address    = 10.10.0.1/24
ListenPort = 51820
PrivateKey = <SERVER_PRIVATE_KEY>

# Enable routing between mesh peers (optional — needed only if peers should
# reach each other, not just the server)
PostUp   = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# --- Peer: workstation-alice ---
[Peer]
PublicKey  = <ALICE_PUBLIC_KEY>
AllowedIPs = 10.10.0.2/32

# --- Peer: server-prod-01 ---
[Peer]
PublicKey  = <PROD01_PUBLIC_KEY>
AllowedIPs = 10.10.0.3/32
```

**AllowedIPs on the server** defines which source IPs are permitted per peer.  This is WireGuard's first layer of isolation — a peer assigned `10.10.0.2/32` cannot send traffic claiming to be `10.10.0.5`.  Our nftables `@MESH_PEERS` set is a second layer.

### /etc/wireguard/wg0.conf (client/peer)

```ini
[Interface]
Address    = 10.10.0.2/32
PrivateKey = <ALICE_PRIVATE_KEY>
DNS        = 10.10.0.1          # optional: use a resolver on the VPN server

[Peer]
PublicKey           = <SERVER_PUBLIC_KEY>
Endpoint            = vpn.yourdomain.com:51820
AllowedIPs          = 10.10.0.0/24   # route only mesh traffic through the tunnel
PersistentKeepalive = 25             # keep NAT mappings alive
```

### Key generation

```bash
# Generate server key pair
wg genkey | tee server.key | wg pubkey > server.pub

# Generate peer key pair
wg genkey | tee peer.key | wg pubkey > peer.pub

# Optional: pre-shared key for post-quantum resistance
wg genpsk > peer.psk
```

Store private keys with `chmod 600`.  Never commit them.  Use a secrets manager (Vault, age-encrypted secrets, etc.) for automation.

### Bringing the interface up/down

```bash
# Start
sudo wg-quick up wg0

# Stop
sudo wg-quick down wg0

# Status
sudo wg show

# Live peer stats (handshake times, transfer bytes)
watch -n 1 sudo wg show
```

---

## Adding a service

1. Uncomment or add a rule in `rules/40-services.nft`
2. Use the template:
   ```nft
   tcp dport <PORT> accept comment "service: <NAME> — <PURPOSE> (mesh-only)"
   ```
3. Reload: `sudo nft -f /etc/nftables/nftables.conf`
4. Test connectivity from a mesh peer: `nc -zv 10.10.0.1 <PORT>`
5. Verify the rule appears: `sudo nft list chain inet filter services`
6. Commit: `feat: open TCP/<PORT> for <NAME> on <hostname>`

Never add a rule without a `comment`.  The comment is the documentation.

## Removing a service

1. Comment out the rule in `rules/40-services.nft`
2. Reload
3. Test that the port is no longer reachable from a mesh peer
4. Commit: `feat: close TCP/<PORT> <NAME> — <reason>`

Prefer commenting out over deleting — the git diff becomes the audit log.

---

## Reading the logs

Log lines are prefixed with `XNFT-<CATEGORY>:` for easy filtering.

| Prefix | Meaning |
|---|---|
| `XNFT-DROP` | Catch-all drop — packet not matched by any allow rule |
| `XNFT-INVALID` | Conntrack invalid state (broken TCP, out-of-state RST…) |
| `XNFT-MESH-SPOOF` | Packet inside `wg0` with source IP outside `@MESH_PEERS` |
| `XNFT-MESH-UNKNOWN` | Packet inside `wg0` from an unrecognised peer |
| `XNFT-WG-RATELIMIT` | WireGuard handshake rate limit exceeded |
| `XNFT-ICMP4-DROP` | Unmatched IPv4 ICMP |
| `XNFT-ICMP6-DROP` | Unmatched ICMPv6 |
| `XNFT-FWD-DROP` | Packet dropped in the forward chain |
| `XNFT-EGRESS-DROP` | Packet dropped on output (if egress control is enabled) |

### Live monitoring

```bash
# All xnftables events
journalctl -k -f | grep "XNFT-"

# Only unexpected drops (ignore WireGuard noise)
journalctl -k -f | grep "XNFT-DROP"

# Top source IPs hitting the catch-all (last 1000 lines)
journalctl -k -n 1000 | grep "XNFT-DROP" \
  | grep -oP 'SRC=\S+' | sort | uniq -c | sort -rn | head

# Decode a full log line
# Example output:
# Apr 26 19:01:44 host kernel: XNFT-DROP: IN=eth0 OUT= MAC=... SRC=185.220.101.5
#   DST=10.0.0.1 LEN=44 TOS=0x00 PREC=0x00 TTL=235 ID=54321 PROTO=TCP
#   SPT=54321 DPT=22 WINDOW=1024 RES=0x00 SYN URGP=0
#
# SRC   = source IP (the scanner/attacker)
# DST   = your server IP
# DPT   = destination port they tried to reach
# PROTO = TCP/UDP/ICMP
```

### Structured logging with rsyslog

To ship `XNFT-*` events to a remote SIEM or Loki instance, add to `/etc/rsyslog.conf`:

```
# Forward all kernel netfilter logs matching XNFT- to a remote host
:msg, contains, "XNFT-" @your-siem-host:514
```

Or to a local file for analysis:

```
:msg, contains, "XNFT-" /var/log/xnftables.log
& stop
```

---

## Auditing the ruleset

### Dump the live ruleset

```bash
sudo nft list ruleset
```

### List only named sets (peer CIDRs)

```bash
sudo nft list sets
```

### List a specific chain

```bash
sudo nft list chain inet filter services
sudo nft list chain inet filter mesh_input
```

### Validate config before applying

```bash
sudo nft -c -f /etc/nftables/nftables.conf
```

### Add rule counters for live hit tracking

```nft
tcp dport 22 counter accept comment "service: SSH (mesh-only)"
```

Then watch them:

```bash
watch -n 1 'sudo nft list chain inet filter services'
```

### Trace a specific packet (debug mode)

nftables has a built-in packet tracer.  Use it to debug why a packet is or isn't matching:

```bash
# Enable tracing for all input packets (temporary)
sudo nft 'add rule inet filter input meta nftrace set 1'

# Monitor the trace output
sudo nft monitor trace

# Remove the trace rule (get the handle first)
sudo nft list chain inet filter input -a
sudo nft delete rule inet filter input handle <HANDLE>
```

Sample trace output:

```
trace id 1234abcd inet filter input packet: iif "eth0" ip saddr 203.0.113.5 …
trace id 1234abcd inet filter input rule iifname "lo" accept (verdict accept)
trace id 1234abcd inet filter input verdict drop
```

---

## Security model

### What this policy protects against

| Threat | Mitigation |
|---|---|
| Port scanning from the internet | Default drop; only UDP/51820 responds, and only to valid WireGuard datagrams |
| Brute-force SSH | SSH is invisible to non-mesh traffic |
| Service enumeration | No ports respond to unauthenticated connections |
| Spoofed source IPs inside the tunnel | WireGuard `AllowedIPs` + nftables `@MESH_PEERS` dual check |
| WireGuard handshake flood | Rate-limited to 20/min per source IP |
| Invalid/broken TCP state | `ct state invalid` drop before any rule evaluation |
| ICMP-based reconnaissance | Only essential ICMP types allowed; ping restricted to mesh peers |
| Accidental rule sprawl | Every rule is explicit, commented, and version-controlled |

### What this policy does NOT protect against

| Threat | Notes |
|---|---|
| Compromised mesh peer | A peer with a valid key can reach all open services. Use per-peer rules for finer isolation. |
| Vulnerabilities in exposed services | nftables controls access, not application security. Patch your services. |
| Egress data exfiltration | Output policy is ACCEPT by default. Add egress rules if needed. |
| Layer 7 attacks | This is L3/L4 only. Deploy a WAF for HTTP-level protection. |
| Physical / hypervisor compromise | Out of scope for a network firewall. |

---

## nftables primer

If you are coming from `iptables`, here is the mental model shift.

### Tables and chains

In `iptables` the tables (`filter`, `nat`, `mangle`) are fixed.  In nftables you create your own tables with any name, and define which hooks (input, forward, output, prerouting, postrouting) they attach to, and at what priority.

```nft
table inet filter {        # "inet" = covers IPv4 + IPv6 simultaneously
    chain input {
        type filter        # hook type: filter, nat, or route
        hook input         # netfilter hook: input, forward, output, prerouting, postrouting
        priority filter;   # numeric priority or named alias (filter = 0)
        policy drop;       # default verdict if no rule matches
    }
}
```

### Rule anatomy

```nft
[match expressions]  [statement]  [comment]
```

Examples:

```nft
# Match on interface + protocol + port, then accept
iifname "wg0"  ip protocol tcp  tcp dport 22  accept  comment "SSH from mesh"

# Match on conntrack state
ct state { established, related }  accept  comment "conntrack fast-path"

# Match on IP set membership
ip saddr @MESH_PEERS  jump services  comment "known peer"

# Rate-limit + log + drop
limit rate 5/second  log prefix "DROP: " drop  comment "rate-limited drop"
```

### Sets and maps

Sets are one of nftables' most powerful features — you can match against lists or ranges of IPs, ports, or any data type in a single rule:

```nft
# Named set — static list
set BLOCKED_COUNTRIES {
    type ipv4_addr
    flags interval
    elements = { 1.0.0.0/8, 2.0.0.0/8 }
}

# Match against the set
ip saddr @BLOCKED_COUNTRIES drop comment "geo-block"
```

Verdict maps (`vmap`) let you jump to different chains based on a key:

```nft
# Route traffic to different chains based on destination port
tcp dport vmap {
    22   : jump ssh_chain,
    80   : jump http_chain,
    443  : jump https_chain
}
```

### Priorities

Chains at lower numeric priority run first.  Named aliases:

| Alias | Value | Use case |
|---|---|---|
| `raw` | -300 | Before conntrack — use for performance-critical drops |
| `mangle` | -150 | Packet modification |
| `filter` | 0 | Standard filtering (this ruleset) |
| `security` | 50 | SELinux / AppArmor hooks |

For most firewall use cases, `priority filter` (0) is correct.

### Atomic ruleset reload

Unlike iptables, nftables applies a ruleset atomically.  The `flush ruleset` + `include` pattern in `nftables.conf` means:

1. New rules are compiled into a transaction
2. Old rules are replaced atomically — there is no window where no rules are loaded
3. If the new config has a syntax error, the old rules remain active

This makes safe reloads trivial:

```bash
sudo nft -c -f /etc/nftables/nftables.conf && sudo nft -f /etc/nftables/nftables.conf
```

---

## Why nftables over iptables

| | iptables | nftables |
|---|---|---|
| IPv4 + IPv6 | Separate `iptables` / `ip6tables` commands | Single `inet` table covers both |
| Rule evaluation | Linear scan of every rule | JIT-compiled bytecode, set-based O(1) lookups |
| Atomic reload | Not atomic — race window during reload | Fully atomic transactions |
| Named sets | Requires `ipset` as a separate tool | Built-in, first-class feature |
| Rule comments | Not supported natively | `comment` field on every rule |
| Scripting | Fragile shell string concatenation | Proper include system, variables, maps |
| Maintenance status | Legacy — no new features | Actively maintained, in-kernel since 3.13 |

`iptables` still works (it's now a compatibility shim over nftables on modern distros), but there is no reason to use it for new deployments.

---

## Why WireGuard over OpenVPN / IPsec

| | OpenVPN | IPsec (strongSwan/Libreswan) | WireGuard |
|---|---|---|---|
| Codebase size | ~70,000 lines | ~400,000 lines | ~4,000 lines |
| Attack surface | Large (userspace TLS stack) | Very large | Minimal |
| Performance | ~200–400 Mbps | ~400–600 Mbps | Line-rate on modern hardware |
| Key exchange | TLS certificates or PSK | IKEv1/IKEv2 (complex) | Noise protocol (modern, simple) |
| Configuration | Complex (many options) | Very complex | Simple (5–10 lines per peer) |
| Kernel integration | Userspace daemon | Partial kernel support | Native in-kernel since 5.6 |
| Roaming support | Limited | Limited | Automatic (peers reconnect seamlessly) |
| Audit friendliness | Hard (large codebase) | Very hard | Straightforward |

WireGuard's cryptographic foundation is the [Noise Protocol Framework](https://noiseprotocol.org/) with:
- **Curve25519** for Diffie-Hellman key exchange
- **ChaCha20-Poly1305** for authenticated encryption
- **BLAKE2s** for hashing
- **SipHash24** for hashtable keys

These are modern, well-audited primitives.  There are no negotiable cipher suites — no downgrade attacks, no BEAST/POODLE-class vulnerabilities.

---

## Threat modelling

### The attacker from the internet

They find your server IP (trivial — it's in DNS, BGP, certificate transparency logs).  They run:

```
nmap -sS -sV -O -p 1-65535 your.server.ip
```

What they see with `xnftables` active:

```
Host is up (0.0034s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT      STATE         SERVICE
51820/udp open|filtered unknown
```

One port.  No banner.  No service version.  No OS fingerprint.  No attack surface.

Without `xnftables` (default Ubuntu install):

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu
80/tcp open  http    nginx 1.26.0
443/tcp open  https   nginx 1.26.0
```

Three services, exact versions, ready to be matched against CVE databases.

### The compromised mesh peer

WireGuard guarantees authentication, not authorisation.  A peer with a valid key pair can reach all services that `rules/40-services.nft` opens.  Mitigations:

1. **Per-peer sub-chains** — route each peer's traffic to a dedicated chain with only the services they need
2. **Revoke immediately** — remove the peer's `[Peer]` block from `wg0.conf` and run `wg syncconf wg0 <(wg-quick strip wg0)` to revoke without restarting the interface
3. **Principle of least privilege** — don't expose services a peer doesn't need
4. **mTLS at the application layer** — add client certificate auth to sensitive services so a network-level compromise isn't sufficient

### The insider / supply chain attack

If you run software that has a network listener (a web app, a database, an agent), and that software is compromised, it may try to exfiltrate data or phone home.  The default `output: accept` policy doesn't prevent this.

To mitigate: enable egress control (see [Advanced patterns](#advanced-patterns)) and restrict outbound connections to known-good destinations.

---

## Advanced patterns

### Per-peer isolation

If you want peer `10.10.0.2` (Alice's workstation) to reach SSH but NOT the database, and `10.10.0.3` (a CI server) to reach the database but NOT SSH:

```nft
chain services {
    # Alice: SSH only
    ip saddr 10.10.0.2 tcp dport 22    accept comment "peer alice: SSH"
    ip saddr 10.10.0.2                 drop   comment "peer alice: deny all else"

    # CI server: PostgreSQL only
    ip saddr 10.10.0.3 tcp dport 5432  accept comment "peer ci: PostgreSQL"
    ip saddr 10.10.0.3                 drop   comment "peer ci: deny all else"

    # Default: log+drop (falls through to 70-logging.nft)
}
```

### Output egress control

Change the output policy to drop and add explicit egress rules:

```nft
chain output {
    type filter hook output priority filter; policy drop;

    oifname "lo"                      accept comment "egress: loopback"
    ct state { established, related } accept comment "egress: established"
    udp dport 53                      accept comment "egress: DNS"
    tcp dport 53                      accept comment "egress: DNS/TCP"
    udp dport 123                     accept comment "egress: NTP"
    tcp dport { 80, 443 }             accept comment "egress: HTTP/HTTPS (updates, APIs)"
    udp dport 51820                   accept comment "egress: WireGuard (if this host is also a peer)"
    log prefix "XNFT-EGRESS-DROP: "   drop   comment "egress: catch-all"
}
```

### Mesh peer routing (WireGuard server as hub)

If this host is the WireGuard server and peers need to reach each other (hub-and-spoke):

```nft
chain forward {
    type filter hook forward priority filter; policy drop;

    # Mesh-to-mesh forwarding through this hub
    iifname "wg0" oifname "wg0"
        ip saddr @MESH_PEERS ip daddr @MESH_PEERS
        accept comment "forward: mesh-to-mesh via hub"

    log prefix "XNFT-FWD-DROP: " drop comment "forward: catch-all"
}
```

### Dynamic peer sets

For environments with many peers or dynamic membership, populate `@MESH_PEERS` from a script:

```bash
#!/bin/bash
# sync-mesh-peers.sh — rebuild the MESH_PEERS set from active WireGuard peers
nft flush set inet filter MESH_PEERS
wg show wg0 allowed-ips | awk '{print $2}' | while read cidr; do
    nft add element inet filter MESH_PEERS "{ $cidr }"
done
```

Run via a `PostUp` hook in `wg0.conf` or a systemd timer.

### Connection rate limiting per service

Protect services from connection floods even from inside the mesh:

```nft
# Limit SSH to 3 new connections per minute per source IP
tcp dport 22 ct state new \
    limit rate 3/minute \
    accept comment "service: SSH rate-limited (mesh-only)"

tcp dport 22 ct state new \
    log prefix "XNFT-SSH-RATELIMIT: " \
    drop comment "service: SSH rate-limit exceeded"
```

### Port knocking (software-defined firewall)

Open a port only after receiving a specific sequence of connection attempts.  Pure nftables implementation:

```nft
table inet portknock {
    set knocked {
        type ipv4_addr
        flags dynamic, timeout
        timeout 10s          # IP removed from set after 10s of no activity
    }

    chain input {
        type filter hook input priority filter - 1; policy accept;

        # Step 1: knock on 7000 → add to "knocked" set
        tcp dport 7000 ct state new add @knocked { ip saddr timeout 5s } drop

        # Step 2: if in "knocked" and knocks 8000 → open SSH for 30s
        tcp dport 8000 ip saddr @knocked ct state new \
            add @open { ip saddr timeout 30s } drop

        # Block SSH unless in the "open" set
        tcp dport 22 ip saddr != @open drop
    }

    set open {
        type ipv4_addr
        flags dynamic, timeout
        timeout 30s
    }
}
```

### Geo-blocking with named sets

Block entire country CIDRs (e.g. using [ipverse.net](https://ipverse.net/ipblocks/data/countries/) country IP blocks):

```nft
set BLOCKED_PREFIXES {
    type ipv4_addr
    flags interval
    elements = {
        # Add country CIDR blocks here
        # e.g. 1.0.0.0/8,
    }
}

chain input {
    ip saddr @BLOCKED_PREFIXES \
        log prefix "XNFT-GEOBLOCK: " \
        drop comment "geo-block: blocked prefix"
}
```

Note: geo-blocking is a speed bump, not a wall — determined attackers use exit nodes in unblocked countries.  Useful for noise reduction, not for security guarantees.

---

## Hardening checklist

Use this as a pre-deploy review before putting a server into production.

```
[ ] MESH_PEERS set contains only your mesh CIDR — no 0.0.0.0/0
[ ] WireGuard interface name matches your actual wg interface (wg0 / wg1 / etc.)
[ ] ListenPort in wg0.conf matches udp dport in 50-vpn-endpoint.nft
[ ] Only services this host actually runs are uncommented in 40-services.nft
[ ] Every uncommented rule has a comment field
[ ] nft -c validates without errors
[ ] nftables.service is enabled for boot persistence
[ ] WireGuard private keys are chmod 600, not committed to git
[ ] Peers use AllowedIPs = <their IP>/32 (not 0.0.0.0/0 unless intentional)
[ ] PersistentKeepalive set on mobile/roaming peers
[ ] Log shipping configured (rsyslog / journald remote)
[ ] Tested: SSH from mesh peer works
[ ] Tested: SSH from public internet does NOT work
[ ] Tested: WireGuard handshake from new peer works
[ ] Tested: nmap from public internet shows only UDP/51820
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

- [nftables wiki](https://wiki.nftables.org/) — canonical reference for syntax and concepts
- [nftables Quick Reference](https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes) — 10-minute overview
- [WireGuard documentation](https://www.wireguard.com/) — protocol design and configuration
- [WireGuard whitepaper](https://www.wireguard.com/papers/wireguard.pdf) — academic paper with cryptographic protocol details
- [Noise Protocol Framework](https://noiseprotocol.org/) — cryptographic foundation of WireGuard
- [Netfilter conntrack](https://conntrack-tools.netfilter.org/) — connection tracking subsystem
- [Linux Kernel WireGuard docs](https://www.kernel.org/doc/html/latest/networking/wireguard.html)
- [nft(8) man page](https://www.netfilter.org/projects/nftables/manpage.html)
- [ipverse country IP blocks](https://ipverse.net/ipblocks/data/countries/) — CIDR lists for geo-blocking

---

## License

MIT — use it, adapt it, share it.  
If you improve it, send a PR.
