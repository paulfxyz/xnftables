# xnftables enforcement test suite

`nft -c -f nftables.conf` tells you the ruleset **parses**. It tells you nothing
about whether the policy is **enforced**. This suite answers the questions that
actually matter:

- Is TCP/22 really invisible from the public interface — dropped, not rejected?
- Is UDP/51820 really reachable so WireGuard can hand-shake?
- Does a mesh peer in `10.10.0.0/24` on `wg0` really reach SSH?
- Does a **non-mesh** source inside `wg0` really get killed by the anti-spoof rule?
- Are NULL/XMAS/SYN+FIN scans and bogon sources really dropped, and logged?
- Is loopback really untouched, and does return traffic for outbound
  connections really come back?

It does this by loading the **real, unmodified ruleset** into a throw-away
network namespace and firing real packets at it from a second namespace.

```
1..29
ok 1 - syntax: full ruleset passes nft -c dry-run
ok 2 - load: ruleset commits into the test namespace
...
not ok 9 - public: random TCP port (33333) is dropped
#   expected: filtered
#   actual:   refused
# ------------------------------------------------------------
# tests 29 | passed 28 | failed 1 | skipped 0
# RESULT: FAIL
```

Output is [TAP](https://testanything.org/) — pipe it into `tap-consumer`,
`prove`, or read it as-is. Exit status is `0` when nothing failed (skips do not
count as failures), `1` on any failure, `2` on a usage error.

---

## How to run

### 1. Container mode (recommended, the default when Docker/Podman is present)

```bash
./tests/run-tests.sh --docker
```

This builds `tests/Dockerfile.test` and re-runs the suite inside a
`--privileged` container with the repo mounted read-only at `/repo`. Nothing is
installed on your host and your host firewall is never touched.

### 2. Local namespace mode (no container runtime)

```bash
sudo ./tests/run-tests.sh --netns
# or, if your user has passwordless sudo:
./tests/run-tests.sh --netns
```

Requirements on the host: `nft`, `ip` (iproute2), `python3`, and ideally
`ping`. All firewall rules are loaded **inside a namespace** — your host
ruleset is not modified, and `/etc/nftables/` is never written to (the harness
copies `rules/` to a temp dir and rewrites the include paths).

### 3. Auto mode

```bash
./tests/run-tests.sh
```

Uses Docker, then Podman, then plain namespaces — whatever works first.

### 4. CI mode

The suite is CI-friendly: TAP on stdout, non-zero exit on failure. On GitHub
Actions, `ubuntu-24.04` runners have a full nf_tables kernel and passwordless
sudo, so namespace mode works directly:

```yaml
  enforcement:
    name: nftables enforcement tests
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - name: Install test dependencies
        run: |
          sudo apt-get update -qq
          sudo apt-get install -y nftables iproute2 iputils-ping python3
      - name: Run enforcement suite
        run: sudo ./tests/run-tests.sh --netns
```

Add `| tee tap.txt` if you want to upload the TAP output as an artifact.
Container-based CI (GitLab, Drone, Woodpecker) needs a privileged job:
`privileged: true` plus `./tests/run-tests.sh --netns` inside the job image.

---

## What the topology looks like

```
  CLI_NS  (probe generator)                 SUT_NS  (the protected host)
  ┌────────────────────────────┐            ┌────────────────────────────┐
  │ pub0   45.33.0.2/24        │◄── veth ──►│ eth0   45.33.0.1/24        │  public
  │        192.0.2.5/24        │            │        192.0.2.1/24        │  bogon source
  │ mesh0  10.10.0.2/24        │◄── veth ──►│ wg0    10.10.0.1/24        │  mesh peer
  │        192.168.77.5/24     │            │        192.168.77.1/24     │  spoofed source
  └────────────────────────────┘            └────────────────────────────┘
```

- The SUT-side mesh interface is literally named `wg0`, so every
  `iifname "wg0"` match in `rules/20-mesh.nft` and `rules/10-antiscan.nft`
  behaves exactly as it does with a real WireGuard device. A veth is a valid
  stand-in: nftables matches the interface *name*, and WireGuard's crypto is
  out of scope for a firewall test.
- `45.33.0.0/24` was chosen because it is **not** in `@BOGON_V4`, so the
  "public traffic is dropped" tests cannot accidentally pass because of the
  bogon filter.
- `192.0.2.0/24` (TEST-NET-1) **is** in `@BOGON_V4` — that is the bogon probe.
- `192.168.77.0/24` presented on `wg0` is outside `@MESH_PEERS` — that is the
  anti-spoof probe (regression test for BUG 1A).

## How "was it really dropped?" is proven

nftables runs every base chain registered on a hook in priority order, and an
`accept` only ends the *current* chain — the packet still visits later chains.
A `drop` ends the journey. So the harness registers a second, **counter-only**
table around the table under test:

```
priority -300   table inet xnft_probe, chain pre    ← sees every arriving packet
priority    0   table inet filter                   ← the ruleset under test
priority   10   table inet xnft_probe, chain post   ← sees only survivors
```

| `pre` | `post` | verdict |
|-------|--------|---------|
| > 0   | 0      | packet arrived and the ruleset **dropped** it |
| > 0   | > 0    | packet arrived and the ruleset **accepted** it |
| 0     | 0      | the probe never arrived → reported as a **broken test**, not a pass |

The observation table contains no verdicts, so it cannot change any outcome, and
`rules/*.nft` and `nftables.conf` are never modified.

Client-side classification is equally explicit: `helpers/tcpconnect.py`
distinguishes `open` (SYN/ACK), `refused` (RST — a policy failure for this
ruleset, it confirms the host exists) and `filtered` (silence — the intended
behaviour). Listeners are bound on 22, 80, 2323 and 51820 inside the SUT
namespace *on purpose*: without a listener the kernel would answer RST and
every test would say "refused", hiding the difference between drop and reject.

---

## Files

| File | Purpose |
|------|---------|
| `run-tests.sh` | Orchestrator: mode detection, TAP plan/summary, test ordering |
| `lib.sh` | Helpers: TAP output, staging, namespace setup, counters, probes |
| `cases/00-static.sh` | Syntax, load, chains, sets, policies, `XNFT-*` log prefixes |
| `cases/10-public.sh` | Public interface: SSH/HTTP/random dropped, UDP/51820 open |
| `cases/20-mesh.sh` | Mesh peer reaches SSH; anti-spoof; established echo |
| `cases/30-antiscan.sh` | NULL/XMAS/SYN+FIN/FIN scans, bogon source, log check |
| `cases/40-icmp.sh` | ICMP echo dropped from public, allowed from mesh |
| `cases/50-loopback.sh` | Loopback TCP + ping unaffected |
| `cases/60-conntrack.sh` | Established/related return path on the public iface |
| `helpers/tcpconnect.py` | Connection classifier: open / refused / filtered / echo |
| `helpers/tcpflags.py` | Raw-socket crafter for illegal TCP flag combinations |
| `helpers/icmpecho.py` | Raw-socket ICMP echo probe (fall-back when `ping` is absent) |
| `helpers/listener.py` | Minimal TCP echo / UDP recording listener |
| `Dockerfile.test` | Debian image with nftables + probe tools |

## Test inventory (29 tests)

| # | Test | Covers |
|---|------|--------|
| 1 | `t_syntax_dryrun` | (a) ruleset parses via `nft -c` |
| 2 | `t_ruleset_loads` | (a) ruleset commits into the kernel |
| 3 | `t_chains_present` | `input`, `forward`, `output`, `mesh_input`, `services` |
| 4 | `t_sets_present` | `MESH_PEERS`, `ADMIN_ALLOWLIST`, `BOGON_V4` content |
| 5 | `t_base_policies` | deny-all: input/forward `drop`, output `accept` |
| 6 | `t_log_prefixes` | all monitored `XNFT-*` prefixes still exist |
| 7 | `t_public_ssh_dropped` | (b) SSH unreachable from public |
| 8 | `t_public_http_dropped` | (b) HTTP unreachable from public |
| 9 | `t_public_random_port_dropped` | (b) random port unreachable |
| 10 | `t_public_no_rst_leak` | (b) dropped, **not** rejected (no RST) |
| 11 | `t_public_counters_prove_drop` | (b) counter proof of the drop |
| 12 | `t_public_wireguard_udp_reachable` | (c) UDP/51820 accepted |
| 13 | `t_mesh_ssh_reachable` | (d) mesh source on `wg0` reaches SSH |
| 14 | `t_mesh_spoof_blocked` | (e) non-mesh source on `wg0` blocked |
| 15 | `t_mesh_spoof_counter` | (e) counter proof of the spoof drop |
| 16 | `t_mesh_established_echo` | (j) established/related inside the mesh |
| 17 | `t_scan_null_dropped` | (f) NULL scan dropped |
| 18 | `t_scan_xmas_dropped` | (f) XMAS scan dropped |
| 19 | `t_scan_synfin_dropped` | (f) SYN+FIN dropped |
| 20 | `t_scan_fin_dropped` | (f) bare FIN dropped |
| 21 | `t_bogon_status_filtered` | (g) bogon source gets silence |
| 22 | `t_bogon_counter_drop` | (g) counter proof of the bogon drop |
| 23 | `t_scan_logs_present` | (f) `XNFT-TCPFL-*` reaches the kernel log |
| 24 | `t_icmp_public_no_reply` | (i) no ping reply from public |
| 25 | `t_icmp_public_counter_drop` | (i) counter proof of the ICMP drop |
| 26 | `t_icmp_mesh_allowed` | (i) ping from mesh peer answered |
| 27 | `t_loopback_tcp_open` | (h) loopback TCP unaffected |
| 28 | `t_loopback_ping_ok` | (h) loopback ICMP unaffected |
| 29 | `t_public_established_return` | (j) return traffic on the public iface |

List them any time with `./tests/run-tests.sh --list`.

---

## How to add a test

1. Pick the `cases/*.sh` file that matches the policy area (or add a new one —
   `run-tests.sh` sources `cases/*.sh` in glob order).
2. Write a function named `t_<something>`:

```bash
t_public_dns_dropped() {
    local desc="public: UDP/53 (DNS) is dropped"
    enforcement_guard "$desc" || return 0   # → SKIP when there is no netns/nft
    probes_reset                            # zero the observation counters
    udp_send "$CLI_NS" "$PUB_CLI_IP" "$PUB_SUT_IP" 53 >/dev/null
    sleep 0.3
    assert_dropped "$desc" "dns"            # needs a probe rule named "dns"
}
```

3. If the test needs a new observation counter, add one line to `probe_rules()`
   in `lib.sh` with the comment `probe:$phase:<name>` — it is emitted into both
   the `pre` and `post` chains automatically.
4. Register the function name in the `TESTS=( ... )` array in `run-tests.sh`.
   The TAP plan count is derived from that array, so there is nothing else to
   update.
5. Rules of the house: emit **exactly one** TAP line per test (use `tap_ok`,
   `tap_not_ok`, `tap_skip`, `tap_assert`, `assert_dropped`, `assert_accepted`),
   never `exit`, and always `return 0`.

Useful helpers (all documented in `lib.sh`): `tcp_status`, `tcp_echo`,
`udp_send`, `scan_send`, `icmp_ping`, `probe_count`, `kernel_log_has`,
`nft_sut`, `ns_exec`.

---

## Requirements

| Mode | Needs |
|------|-------|
| Container | Docker or Podman, ability to run `--privileged`, host kernel with nf_tables |
| Namespace | root/sudo, `nft`, `ip` (iproute2), `python3` |
| Optional | `ping` (iputils) — `helpers/icmpecho.py` covers the ICMP tests without it |
| Optional | `nmap` or `hping3` — fall-backs for the malformed-flag scans if `python3` is absent |

Kernel modules used by the ruleset and the probes: `nf_tables`, `nft_ct`,
`nf_conntrack`, `nft_log`, `nft_limit`, `nft_counter`, `nft_meta`, plus `veth`.

---

## Caveats

- **Kernel modules cannot be faked.** Containers share the host kernel. On a
  host without nf_tables `inet` support (gVisor, some managed CI sandboxes,
  hardened kernels), `nft` fails with `Operation not supported`. The suite
  detects that error text and reports the enforcement tests as
  `# SKIP kernel has no nf_tables inet support` instead of failing — read the
  summary line, a run that is mostly skips has verified nothing.
- **Privileged containers.** Namespaces, veth pairs, nftables and raw sockets
  need `CAP_NET_ADMIN` + `CAP_NET_RAW`. `--privileged` is used because the
  narrower `--cap-add` combination behaves inconsistently across runtimes. Do
  not run the suite on a host where a privileged container is unacceptable —
  use a disposable VM.
- **SSH rate limit is a shared bucket.** `rules/40-services.nft` allows
  `6/minute` new SSH connections (burst 5) for *all* mesh peers combined. The
  suite deliberately opens only two new port-22 connections per run. If you add
  more, later tests will start failing with `filtered` because the rate limit —
  not the mesh policy — dropped them. Wait a minute between runs when
  iterating, or add your new probes on a different port.
- **WireGuard handshake meter.** `rules/50-vpn-endpoint.nft` allows `5/minute`
  per source IP on UDP/51820. Repeated rapid runs can exhaust that budget and
  make test 12 fail spuriously.
- **`wg0` is a veth, not WireGuard.** The tests verify the *firewall's* trust
  model (interface + source-address validation). They do not verify WireGuard's
  cryptography, key handling, or `AllowedIPs` configuration.
- **Log assertions depend on `dmesg`.** netfilter's `log` statement writes via
  `printk`, and kernel log messages are not namespaced. With
  `kernel.dmesg_restrict=1` or without privileges the log test SKIPs; the
  counter-based tests still prove enforcement.
- **rp_filter is disabled in the test namespace** so that nftables is the only
  component making decisions. On a real host, reverse-path filtering is a
  useful extra layer — keep it on there.
- **IPv6 is only checked structurally.** `MESH_PEERS6` is empty in the shipped
  ruleset (deliberately — see the warning in `rules/00-tables.nft`), so there is
  no meaningful v6 enforcement to exercise until you populate it. Once you do,
  add v6 probes following "How to add a test".
- **Interval sets are strict.** nftables rejects a whole `flags interval` set
  when two elements overlap (`Error: conflicting intervals specified`) — e.g.
  adding `255.255.255.255/32` to `BOGON_V4` while `240.0.0.0/4` is already
  there. Test 1 catches this class of error and reports it as a **failure**
  (with the offending line), while genuine "this kernel cannot do nf_tables"
  errors are reported as a skip. Keep the two apart when reading the output.
