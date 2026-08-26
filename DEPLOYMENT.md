# Production deployment checklist

> Moving xnftables to a remote host is the one moment where a firewall mistake
> locks you out. This checklist exists so that never happens.

The single most dangerous property of a deny-all firewall is that it works.
Apply it half-configured and it will happily drop your own SSH session, your
WireGuard handshake, and every path back in. Follow this checklist top to
bottom — every step is ordered so that you always have at least one working
path into the machine.

---

## Table of contents

- [Phase 0 — Before you touch the server](#phase-0--before-you-touch-the-server)
- [Phase 1 — Prepare the mesh first](#phase-1--prepare-the-mesh-first)
- [Phase 2 — Stage the ruleset](#phase-2--stage-the-ruleset)
- [Phase 3 — Dry-run and review](#phase-3--dry-run-and-review)
- [Phase 4 — Apply with a safety net](#phase-4--apply-with-a-safety-net)
- [Phase 5 — Verify enforcement](#phase-5--verify-enforcement)
- [Phase 6 — Make it survive a reboot](#phase-6--make-it-survive-a-reboot)
- [Phase 7 — Operational follow-through](#phase-7--operational-follow-through)
- [Emergency: locked out anyway](#emergency-locked-out-anyway)
- [Printable checklist](#printable-checklist)

---

## Phase 0 — Before you touch the server

- [ ] **Console access confirmed.** You have out-of-band access that does not
      depend on the network stack: provider web console (Hetzner/OVH/AWS EC2
      serial console, Proxmox VNC, IPMI/iDRAC). Log in through it once NOW to
      verify credentials work. This is your parachute — pack it before jumping.
- [ ] **Provider firewall reviewed.** Cloud-level security groups / provider
      firewalls sit in front of nftables. Confirm UDP 51820 is allowed there,
      or the WireGuard handshake will never reach the kernel.
- [ ] **Kernel ≥ 5.6** (`uname -r`) — in-tree WireGuard. Older kernels need
      `wireguard-dkms`.
- [ ] **nftables ≥ 0.9.3** (`nft --version`).
- [ ] **No competing firewall managers.** Disable anything that also writes
      netfilter rules, or they will fight over the ruleset:

      ```bash
      systemctl disable --now ufw firewalld iptables netfilter-persistent 2>/dev/null
      ```

- [ ] **Docker awareness.** If Docker/Podman runs here, read
      [Docker interaction](./README.md#docker--podman--lxc-interaction) first.
      Published container ports bypass the input chain via DNAT.
- [ ] **Local rehearsal passed.** Run the test suite on your workstation:

      ```bash
      sudo ./tests/run-tests.sh
      ```

## Phase 1 — Prepare the mesh first

**The mesh must work BEFORE the firewall depends on it.**

- [ ] Install WireGuard, generate server keys, write `/etc/wireguard/wg0.conf`
      (template in [README → WireGuard configs](./README.md#wireguard-configuration)).
- [ ] `chmod 600 /etc/wireguard/wg0.conf` — it contains the private key.
- [ ] Add your workstation as a peer; add the server to your workstation config.
- [ ] Start the mesh and confirm the handshake **while the old firewall is
      still permissive**:

      ```bash
      systemctl enable --now wg-quick@wg0
      wg show wg0 latest-handshakes    # must show a recent timestamp
      ping 10.10.0.1                   # from your workstation, over the mesh
      ```

- [ ] **SSH over the mesh works:** `ssh user@10.10.0.1`. Keep this session
      open for the rest of the deployment. Open a second one as a spare.

## Phase 2 — Stage the ruleset

- [ ] Clone to `/opt/xnftables` (or copy the [release tarball](https://github.com/paulfxyz/xnftables/releases)):

      ```bash
      git clone https://github.com/paulfxyz/xnftables.git /opt/xnftables
      ```

- [ ] **Edit `rules/00-tables.nft` — the three sets that make it yours:**
  - [ ] `MESH_PEERS` matches your actual mesh CIDR (default `10.10.0.0/24`)
  - [ ] `MESH_PEERS6` if you run IPv6 inside the mesh
  - [ ] `ADMIN_ALLOWLIST` — your real, static public IP if you want break-glass
        SSH. Never an RFC 5737 documentation address. Leave empty if your IP
        is dynamic (use the console as break-glass instead).
- [ ] `rules/50-vpn-endpoint.nft`: ListenPort matches `wg0.conf` (default 51820).
- [ ] `rules/40-services.nft`: uncomment only the services this host actually
      runs. Every uncommented line is an explicit, documented exception.
- [ ] Interface names match reality (`ip -br link`): rules assume `wg0` and
      detect the public interface dynamically — verify on unusual setups
      (bonding, VLANs, multiple NICs).

## Phase 3 — Dry-run and review

- [ ] Syntax gate: `sudo ./scripts/check.sh` — must pass.
- [ ] Kernel dry-run: `sudo nft -c -f nftables.conf` — must be silent.
- [ ] Read the full diff against what is currently loaded:

      ```bash
      sudo nft list ruleset > /tmp/before.nft
      diff /tmp/before.nft <(sudo nft -c -f nftables.conf 2>&1) || true
      ```

- [ ] Ask yourself the lockout question: *"If this ruleset is perfect and I am
      NOT inside the mesh, how do I get in?"* Acceptable answers: mesh SSH,
      break-glass from `ADMIN_ALLOWLIST`, provider console. "It won't happen
      to me" is not an answer.

## Phase 4 — Apply with a safety net

- [ ] **Apply with auto-rollback armed** — from the MESH session, not the
      public one:

      ```bash
      sudo ./scripts/reload.sh --confirm-timeout 60
      ```

      The script snapshots the running ruleset, applies the new one, and then
      blocks on a prompt: type `keep` + Enter within 60 seconds or it reverts
      to the snapshot. If your SSH session freezes, do nothing — the prompt
      never receives input and you'll be back in a minute.

- [ ] Your mesh SSH session survived. Type `keep` at the prompt to confirm.
- [ ] `sudo nft list ruleset | head -50` — the `inet filter` table is loaded,
      input policy is `drop`.

## Phase 5 — Verify enforcement

From an **outside** machine (not in the mesh, not in `ADMIN_ALLOWLIST`):

- [ ] `nmap -Pn -p 22,80,443,8080 <public-ip>` → all `filtered` (dropped, not
      `closed` — closed means a REJECT leaked, filtered means deny-all works).
- [ ] `nmap -sU -Pn -p 51820 <public-ip>` → `open|filtered` (UDP; WireGuard
      doesn't answer strangers, and that is correct).
- [ ] `ping <public-ip>` → silence (ICMP echo is mesh-only by policy).

From a **mesh** machine:

- [ ] `ssh user@10.10.0.1` works.
- [ ] Each service you uncommented in `40-services.nft` answers on its mesh IP.
- [ ] `ping 10.10.0.1` works.

On the server:

- [ ] Watch the drops roll in: `journalctl -k -f | grep XNFT-` — you should see
      `XNFT-INPUT-DROP` entries for internet background noise within minutes.
      That noise is the reason this repo exists.
- [ ] Counters moving: `sudo nft list chain inet filter input`.

## Phase 6 — Make it survive a reboot

- [ ] Enable nftables at boot and point it at the repo:

      ```bash
      sudo ln -sf /opt/xnftables/nftables.conf /etc/nftables.conf
      sudo systemctl enable nftables
      ```

- [ ] WireGuard at boot: `systemctl is-enabled wg-quick@wg0` → `enabled`.
- [ ] **Ordering check:** nftables references `wg0` only by name, so rule load
      order vs. interface creation doesn't matter — but verify after reboot
      anyway.
- [ ] **The reboot test.** Do it now, during the deployment window, not at
      3 a.m. three months from now:

      ```bash
      sudo reboot
      # wait, then from your workstation:
      ping 10.10.0.1 && ssh user@10.10.0.1
      # and from outside: nmap still shows everything filtered
      ```

## Phase 7 — Operational follow-through

- [ ] Kernel hardening sysctls applied ([README → Hardening checklist](./README.md#hardening-checklist)).
- [ ] Security monitor deployed ([MONITOR.md](./MONITOR.md)) — cron or systemd
      timer, weekdays 08:00.
- [ ] Log rotation configured for `/var/log/xnft-monitor.log`.
- [ ] The repo on the server is a git clone, not a copy — future changes flow
      through `git pull` + `./scripts/reload.sh --confirm-timeout 60`, and
      `git log` stays your audit trail.
- [ ] Server-local changes are committed back (or configuration-drift is a
      conscious, documented decision).
- [ ] Calendar reminder: re-run the outside `nmap` scan monthly. Enforcement
      you don't verify is enforcement you assume.

---

## Emergency: locked out anyway

1. **Don't panic, don't reboot first.** A reboot with a broken persistent
   ruleset boots locked.
2. Open the provider console (the one you verified in Phase 0).
3. Flush the filter table only (keeps Docker/NAT intact):

   ```bash
   nft delete table inet filter
   ```

4. You now have no firewall — fix the ruleset immediately, re-apply with
   `./scripts/reload.sh --confirm-timeout 60`, and figure out which phase you
   skipped.

---

## Printable checklist

```
PHASE 0  [ ] console access tested   [ ] provider fw allows 51820
         [ ] kernel>=5.6 nft>=0.9.3  [ ] ufw/firewalld disabled
         [ ] docker plan             [ ] local tests pass
PHASE 1  [ ] wg0 up                  [ ] handshake confirmed
         [ ] mesh ssh works          [ ] spare session open
PHASE 2  [ ] MESH_PEERS set          [ ] ADMIN_ALLOWLIST real or empty
         [ ] services uncommented    [ ] ports match wg0.conf
PHASE 3  [ ] check.sh pass           [ ] nft -c pass
         [ ] diff reviewed           [ ] lockout question answered
PHASE 4  [ ] reload --confirm-timeout 60   [ ] confirmed from mesh
PHASE 5  [ ] outside: all filtered   [ ] mesh: ssh+services ok
         [ ] XNFT- logs flowing
PHASE 6  [ ] nftables enabled        [ ] wg-quick enabled
         [ ] reboot test passed
PHASE 7  [ ] sysctls                 [ ] monitor deployed
         [ ] logrotate               [ ] monthly nmap reminder
```
