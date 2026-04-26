# xnftables

> **If you are not inside the mesh, you see nothing.**
>
> Deny-all defaults. Every exception is explicit, documented and auditable.  
> Least privilege at the network layer.

---

## The idea

Most firewall configs are written backwards: start open, punch holes as problems appear, never clean them up.  After a year you have a ruleset nobody fully understands, with ports open "just in case" and rules that reference services decommissioned in 2021.

`xnftables` inverts that.  The only way traffic reaches this host is through a **WireGuard mesh**.  The public internet sees exactly one thing: a UDP port for WireGuard handshakes.  Everything else — SSH, HTTP, databases, monitoring — is invisible and unreachable unless you are an authenticated mesh peer.

This is a template policy, not a turnkey product.  It is meant to be read, understood, and adapted.  Every rule has a comment explaining *why* it exists, not just what it does.

---

## Concepts

### Deny-all default

```
chain input {
    type filter hook input priority filter; policy drop;
}
```

The kernel drops any packet that doesn't match a rule.  There is no "allow established" by default, no implicit loopback accept, nothing.  Every accept is deliberate.

### Mesh or nothing

[WireGuard](https://www.wireguard.com/) is a modern VPN protocol built into the Linux kernel since 5.6.  Its key properties for this use case:

| Property | Implication |
|---|---|
| Cryptographic peer identity | A packet exiting `wg0` was decrypted with a session key derived from a pre-authorised peer keypair — it cannot be forged |
| Stealth on non-WireGuard traffic | Any datagram that doesn't decrypt correctly is silently dropped — the port appears closed to scanners |
| In-kernel performance | No userspace daemon overhead; same throughput as unencrypted kernel networking |

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
[iifname == "lo"] ──────────────────────────────────────► ACCEPT (loopback)
      │
      ▼
[ct state invalid] ────────────────────────────────────► LOG + DROP
      │
      ▼
[ct state established/related] ────────────────────────► ACCEPT (conntrack)
      │
      ▼
[iifname == "wg0"] ──────► [ip saddr in @MESH_PEERS] ──► jump services
      │                              │
      │                         else └──────────────────► LOG + DROP (spoof)
      │
      ▼
[udp dport 51820] ──────────────────────────────────────► ACCEPT (WireGuard)
      │                     (rate-limited, public internet)
      │
      ▼
[ICMP essential types] ─────────────────────────────────► ACCEPT
      │
      ▼
[everything else] ──────────────────────────────────────► LOG + DROP
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
# Dry-run first — this validates syntax without loading
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

---

## Adding a service

1. Uncomment or add a rule in `rules/40-services.nft`
2. Use the template:
   ```nft
   tcp dport <PORT> accept comment "service: <NAME> — <PURPOSE> (mesh-only)"
   ```
3. Reload: `sudo nft -f /etc/nftables/nftables.conf`
4. Test: `sudo nft list chain inet filter services`
5. Commit with a message like: `feat: open TCP/3000 for Grafana on prod-01`

Never add a rule without a comment.  The comment is the documentation.

---

## Removing a service

1. Comment out the rule in `rules/40-services.nft`
2. Reload
3. Commit: `feat: close TCP/3000 Grafana — moved behind nginx proxy on mesh`

Prefer commenting out over deleting — the git diff becomes the audit log.

---

## Reading the logs

Log lines are prefixed with `XNFT-<CATEGORY>:` for easy filtering.

```
XNFT-DROP        — packet dropped by catch-all (anything not explicitly allowed)
XNFT-INVALID     — conntrack invalid state (broken TCP, out-of-state RST…)
XNFT-MESH-SPOOF  — packet inside wg0 with a source IP outside @MESH_PEERS
XNFT-MESH-UNKNOWN — packet inside wg0 from an unrecognised peer
XNFT-WG-RATELIMIT — WireGuard handshake rate limit exceeded
XNFT-ICMP4-DROP  — unmatched IPv4 ICMP
XNFT-ICMP6-DROP  — unmatched ICMPv6
XNFT-FWD-DROP    — packet dropped in the forward chain
```

### Live monitoring

```bash
# All xnftables log lines
journalctl -k -f | grep "XNFT-"

# Only drop events (not WireGuard rate-limit noise)
journalctl -k -f | grep "XNFT-DROP"

# Top source IPs hitting the catch-all (last 1000 lines)
journalctl -k -n 1000 | grep "XNFT-DROP" | grep -oP 'SRC=\S+' | sort | uniq -c | sort -rn | head
```

### nftables counters

If you add `counter` to any rule, you can watch hit counts in real time:

```bash
sudo nft list ruleset   # shows packet/byte counters per rule if added
```

Example with counter:

```nft
tcp dport 22 counter accept comment "service: SSH (mesh-only)"
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

### Trace a packet (debug mode)

nftables has a built-in packet tracer.  This shows which rules a packet matches without dropping it:

```bash
# Add a trace rule (temporary — remove after debugging)
sudo nft 'add rule inet filter input meta nftrace set 1'

# Monitor the trace
sudo nft monitor trace

# Remove the trace rule when done
sudo nft delete rule inet filter input handle <HANDLE>
```

---

## Security model

### What this policy protects against

| Threat | Mitigation |
|---|---|
| Port scanning from the internet | Default drop; only UDP/51820 responds, and only to valid WireGuard datagrams |
| Brute-force SSH | SSH is invisible to non-mesh traffic |
| Service enumeration | No ports respond to unauthenticated connections |
| Spoofed source IPs inside the tunnel | Dual check: WireGuard `AllowedIPs` + nftables `@MESH_PEERS` set |
| WireGuard handshake flood | Rate-limited to 20/min per source IP |
| Invalid/broken TCP state | `ct state invalid` drop before any rule evaluation |
| ICMP-based reconnaissance | Only essential ICMP types allowed; ping restricted to mesh peers |

### What this policy does NOT protect against

| Threat | Notes |
|---|---|
| Compromised mesh peer | A peer with a valid key can reach all open services. Use per-peer rules in `@MESH_PEERS` for finer isolation. |
| Vulnerabilities in exposed services | nftables controls access, not application security. Patch your services. |
| Egress data exfiltration | Output policy is ACCEPT. Add egress rules if needed. |
| Layer 7 attacks | This is L3/L4 only. Deploy a WAF or application firewall for HTTP-level protection. |
| Physical access / hypervisor compromise | Out of scope for a network firewall. |

### Least privilege at the network layer

The principle of least privilege applied to networking means:

- A service that only needs to serve mesh peers has **no public port**.
- A service that only needs TCP/443 has **no rule for TCP/22**.
- A peer that only needs to reach one service has **no path to others** (achievable with per-peer sub-chains — see *Advanced* below).

---

## Advanced patterns

### Per-peer isolation

If you want peer `10.10.0.2` (Alice's workstation) to reach SSH but NOT the database, and `10.10.0.3` (a CI server) to reach the database but NOT SSH:

```nft
chain services {
    # Alice: SSH only
    ip saddr 10.10.0.2 tcp dport 22 accept comment "peer alice: SSH"

    # CI server: PostgreSQL only
    ip saddr 10.10.0.3 tcp dport 5432 accept comment "peer ci: PostgreSQL"

    # Catch-all: log+drop (falls through to 70-logging.nft)
}
```

### Output egress control

Change the output policy to drop and add explicit egress rules:

```nft
chain output {
    type filter hook output priority filter; policy drop;

    oifname "lo" accept comment "egress: loopback"
    ct state { established, related } accept comment "egress: established"
    udp dport 53  accept comment "egress: DNS"
    tcp dport 53  accept comment "egress: DNS/TCP"
    udp dport 123 accept comment "egress: NTP"
    tcp dport { 80, 443 } accept comment "egress: HTTP/HTTPS (package updates, APIs)"
    udp dport 51820 accept comment "egress: WireGuard (if this host is also a peer)"
    log prefix "XNFT-EGRESS-DROP: " drop comment "egress: catch-all"
}
```

### Mesh peer routing (WireGuard server as hub)

If this host is the WireGuard server and peers need to reach each other (hub-and-spoke mesh):

```nft
chain forward {
    type filter hook forward priority filter; policy drop;

    # Permit mesh-to-mesh forwarding through this hub
    iifname "wg0" oifname "wg0" \
        ip saddr @MESH_PEERS ip daddr @MESH_PEERS \
        accept comment "forward: mesh-to-mesh via hub"

    # Log and drop everything else
    log prefix "XNFT-FWD-DROP: " drop comment "forward: catch-all"
}
```

### Dynamic peer sets (with ipset compatibility)

For environments with many peers or dynamic membership, populate `@MESH_PEERS` from a script:

```bash
#!/bin/bash
# sync-mesh-peers.sh — rebuild the MESH_PEERS set from WireGuard peer list
nft flush set inet filter MESH_PEERS
wg show wg0 allowed-ips | awk '{print $2}' | while read cidr; do
    nft add element inet filter MESH_PEERS "{ $cidr }"
done
```

Run via cron or a WireGuard `PostUp` hook to keep the set in sync.

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
- [WireGuard docs](https://www.wireguard.com/) — protocol and configuration
- [nftables Quick Reference](https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes)
- [Netfilter conntrack](https://conntrack-tools.netfilter.org/) — connection tracking
- [Linux Kernel WireGuard](https://www.kernel.org/doc/html/latest/networking/wireguard.html)

---

## License

MIT — use it, adapt it, share it.  
If you improve it, send a PR.
