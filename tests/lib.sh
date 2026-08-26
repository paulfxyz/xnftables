#!/usr/bin/env bash
# =============================================================================
# lib.sh — shared helpers for the xnftables enforcement test suite
# =============================================================================
# This file is *sourced*, never executed directly.  It provides:
#
#   1. TAP output helpers            tap_ok / tap_not_ok / tap_skip / tap_summary
#   2. Ruleset staging               stage_ruleset (rewrites the /etc/nftables
#                                    include paths into a temp dir so the repo
#                                    is never modified and root is not needed
#                                    to install files)
#   3. Namespace topology            env_up / env_down — two network namespaces
#                                    joined by two veth pairs that model the two
#                                    worlds of the policy: the public interface
#                                    and the WireGuard mesh (wg0)
#   4. Enforcement observation       probes_install / probe_count — a SEPARATE
#                                    nft table with counter-only rules placed
#                                    before and after the table under test, so
#                                    we can prove whether a packet survived the
#                                    filter without touching the real ruleset
#   5. Packet probes                 tcp_status / tcp_echo / udp_send /
#                                    icmp_ping / scan_send
#
# =============================================================================
# HOW THE "DID IT REALLY GET DROPPED?" CHECK WORKS
# -----------------------------------------------------------------------------
# nftables evaluates every base chain registered on a hook in priority order,
# and an `accept` verdict only ends the *current* chain — the packet still
# visits base chains with a higher (later) priority.  A `drop`, in contrast,
# ends the journey immediately.
#
# So we register two counter-only base chains in our own table:
#
#      priority -300   table inet xnft_probe, chain pre    ← sees EVERYTHING
#      priority    0   table inet filter                   ← the ruleset (SUT)
#      priority   10   table inet xnft_probe, chain post   ← sees SURVIVORS
#
#   pre  counter > 0 and post counter == 0  → packet arrived and was DROPPED
#   pre  counter > 0 and post counter  > 0  → packet arrived and was ACCEPTED
#   pre  counter == 0                       → the probe never arrived; the test
#                                             itself is broken (reported as such
#                                             rather than as a policy pass)
#
# This is strictly non-invasive: rules/*.nft and nftables.conf are untouched.
# =============================================================================
# SPDX-License-Identifier: MIT
# =============================================================================

# ---------------------------------------------------------------------------
# Topology constants — change here if they ever clash with your environment.
# ---------------------------------------------------------------------------
SUT_NS="${SUT_NS:-xnftsut}" # "server": the host the ruleset protects
CLI_NS="${CLI_NS:-xnftcli}" # "attacker/peer": generates all the probe traffic

PUB_IF_SUT="eth0"   # public-facing interface name inside SUT_NS
PUB_IF_CLI="pub0"   # its veth peer inside CLI_NS
MESH_IF_SUT="wg0"   # MUST be wg0: the ruleset matches on iifname
MESH_IF_CLI="mesh0" # its veth peer inside CLI_NS

# Public world: a routable-looking /24 deliberately NOT inside BOGON_V4, so the
# generic "public traffic is dropped" tests are not confounded by the bogon rule.
PUB_SUT_IP="45.33.0.1"
PUB_CLI_IP="45.33.0.2"
PUB_CIDR="24"

# Bogon world: TEST-NET-1 (192.0.2.0/24) is an element of @BOGON_V4.
BOGON_SUT_IP="192.0.2.1"
BOGON_CLI_IP="192.0.2.5"

# Mesh world: matches @MESH_PEERS (10.10.0.0/24) from rules/00-tables.nft.
MESH_SUT_IP="10.10.0.1"
MESH_CLI_IP="10.10.0.2"

# Non-mesh source presented *inside* wg0 — the anti-spoof case of 20-mesh.nft.
SPOOF_SUT_IP="192.168.77.1"
SPOOF_CLI_IP="192.168.77.5"

# Ports used by the probes.
PORT_SSH=22       # allowed from the mesh only (40-services.nft)
PORT_HTTP=80      # commented out in 40-services.nft → must be dropped
PORT_RANDOM=33333 # never allowed anywhere
PORT_WG=51820     # public UDP handshake port (50-vpn-endpoint.nft)
# shellcheck disable=SC2034  # consumed by tests/cases/*.sh (sourced at runtime)
PORT_SCAN=44444    # target for malformed-flag scans
PORT_LOOPBACK=2323 # loopback-only service inside SUT_NS
# shellcheck disable=SC2034  # consumed by tests/cases/60-conntrack.sh
PORT_CLI_ECHO=9999 # listener in CLI_NS for the outbound/return test

# Where the UDP listener records handshake datagrams it received.
WG_HIT_FILE="/tmp/xnft-test-wg-hits.$$"

# ---------------------------------------------------------------------------
# Runtime state
# ---------------------------------------------------------------------------
REPO_ROOT="${REPO_ROOT:-}" # set by run-tests.sh
STAGE_DIR=""               # temp copy of the ruleset (see stage_ruleset)
SUDO=""                    # "" when already root, otherwise "sudo"
PY=""                      # python3 path, "" if unavailable
ENV_READY=0                # 1 once env_up() succeeded
LISTENER_PIDS=()           # background listeners to reap in teardown

TAP_COUNT=0
TAP_FAILED=0
TAP_SKIPPED=0
VERBOSE="${VERBOSE:-0}"

# ---------------------------------------------------------------------------
# Logging helpers.  Diagnostics go to stdout as TAP comments ("# ...") so the
# output stays valid TAP and can be piped into any TAP consumer.
# ---------------------------------------------------------------------------
diag() { printf '# %s\n' "$*"; }
vdiag() {
  [[ "$VERBOSE" == "1" ]] && printf '# %s\n' "$*"
  return 0
}
die() {
  printf 'Bail out! %s\n' "$*"
  exit 1
}

have() { command -v "$1" > /dev/null 2>&1; }

# ---------------------------------------------------------------------------
# TAP output
# ---------------------------------------------------------------------------
tap_plan() { printf '1..%d\n' "$1"; }

tap_ok() {
  TAP_COUNT=$((TAP_COUNT + 1))
  printf 'ok %d - %s\n' "$TAP_COUNT" "$1"
}

tap_not_ok() {
  TAP_COUNT=$((TAP_COUNT + 1))
  TAP_FAILED=$((TAP_FAILED + 1))
  printf 'not ok %d - %s\n' "$TAP_COUNT" "$1"
  shift || true
  local line
  for line in "$@"; do
    [[ -n "$line" ]] && diag "  $line"
  done
  return 0
}

tap_skip() {
  TAP_COUNT=$((TAP_COUNT + 1))
  TAP_SKIPPED=$((TAP_SKIPPED + 1))
  printf 'ok %d - %s # SKIP %s\n' "$TAP_COUNT" "$1" "${2:-not applicable here}"
}

# Convenience: assert a shell-visible condition.
#   tap_assert "description" "expected" "actual" ["extra diagnostic"]
tap_assert() {
  local desc="$1" expected="$2" actual="$3" extra="${4:-}"
  if [[ "$expected" == "$actual" ]]; then
    tap_ok "$desc"
  else
    tap_not_ok "$desc" "expected: $expected" "actual:   $actual" "$extra"
  fi
}

tap_summary() {
  local passed=$((TAP_COUNT - TAP_FAILED - TAP_SKIPPED))
  printf '# ------------------------------------------------------------\n'
  printf '# tests %d | passed %d | failed %d | skipped %d\n' \
    "$TAP_COUNT" "$passed" "$TAP_FAILED" "$TAP_SKIPPED"
  if ((TAP_FAILED > 0)); then
    printf '# RESULT: FAIL\n'
    return 1
  fi
  printf '# RESULT: PASS\n'
  return 0
}

# ---------------------------------------------------------------------------
# Privilege handling: netns + nft both need CAP_NET_ADMIN.
# ---------------------------------------------------------------------------
detect_privileges() {
  if [[ "$(id -u)" -eq 0 ]]; then
    SUDO=""
  elif have sudo; then
    SUDO="sudo"
  else
    SUDO=""
    return 1
  fi
  return 0
}

# Root-privileged command wrapper (a no-op prefix when already root).
priv() {
  if [[ -n "$SUDO" ]]; then
    $SUDO "$@"
  else
    "$@"
  fi
}

# Run a command inside a namespace.  ns_exec <ns> <cmd...>
ns_exec() {
  local ns="$1"
  shift
  priv ip netns exec "$ns" "$@"
}

# nft inside the system-under-test namespace.
nft_sut() { ns_exec "$SUT_NS" nft "$@"; }

detect_python() {
  if have python3; then
    PY="$(command -v python3)"
    return 0
  fi
  PY=""
  return 1
}

# ---------------------------------------------------------------------------
# stage_ruleset — copy the ruleset to a temp dir with rewritten include paths
# ---------------------------------------------------------------------------
# nftables.conf includes absolute paths under /etc/nftables/.  Rather than
# installing into /etc (which would mutate the host) we copy rules/ into a temp
# directory and rewrite the include prefix.  Nothing in the repo is modified.
# Sets STAGE_DIR.  Idempotent.
# ---------------------------------------------------------------------------
stage_ruleset() {
  [[ -n "$STAGE_DIR" ]] && return 0
  [[ -n "$REPO_ROOT" ]] || die "REPO_ROOT is not set"
  [[ -f "$REPO_ROOT/nftables.conf" ]] || die "nftables.conf not found in $REPO_ROOT"

  STAGE_DIR="$(mktemp -d -t xnft-stage-XXXXXX)"
  cp -r "$REPO_ROOT/rules" "$STAGE_DIR/rules"
  # Rewrite include prefix "/etc/nftables/" → "$STAGE_DIR/".
  sed "s#/etc/nftables/#${STAGE_DIR}/#g" \
    "$REPO_ROOT/nftables.conf" > "$STAGE_DIR/nftables.conf"
  # World-readable: the ruleset is read back by nft running as root.
  chmod -R a+rX "$STAGE_DIR"
  vdiag "staged ruleset at $STAGE_DIR"
  return 0
}

# Path to the staged entry point.
staged_conf() { printf '%s/nftables.conf\n' "$STAGE_DIR"; }

# ---------------------------------------------------------------------------
# NOTE on kernel capability: some environments (gVisor, minimal CI kernels,
# unprivileged containers) ship the nft binary but cannot create an `inet`
# table at all.  Rather than probing the host firewall for that, run-tests.sh
# inspects the error text of the first in-namespace load ("Operation not
# supported") and turns the enforcement tests into SKIPs.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# env_up — build the two-namespace, two-world topology
# ---------------------------------------------------------------------------
#   CLI_NS (probe generator)                SUT_NS (protected host)
#   ┌──────────────────────────┐            ┌───────────────────────────┐
#   │ pub0  45.33.0.2/24       │◄── veth ──►│ eth0  45.33.0.1/24        │
#   │       192.0.2.5/24       │            │       192.0.2.1/24        │
#   │ mesh0 10.10.0.2/24       │◄── veth ──►│ wg0   10.10.0.1/24        │
#   │       192.168.77.5/24    │            │       192.168.77.1/24     │
#   └──────────────────────────┘            └───────────────────────────┘
#
# The SUT-side mesh interface is literally named wg0 so that the
# `iifname "wg0"` matches in 20-mesh.nft / 10-antiscan.nft behave exactly as
# they do with a real WireGuard device.  A veth is a fine stand-in: nftables
# matches the interface *name*, and the cryptographic part of WireGuard is out
# of scope for a firewall test.
# ---------------------------------------------------------------------------
env_up() {
  env_down_quiet # make repeated runs idempotent

  priv ip netns add "$SUT_NS"
  priv ip netns add "$CLI_NS"

  # --- public link ---
  priv ip link add "xnftpub0" type veth peer name "xnftpub1"
  priv ip link set "xnftpub0" netns "$SUT_NS" name "$PUB_IF_SUT"
  priv ip link set "xnftpub1" netns "$CLI_NS" name "$PUB_IF_CLI"

  # --- mesh link (SUT side named wg0) ---
  priv ip link add "xnftwg0" type veth peer name "xnftwg1"
  priv ip link set "xnftwg0" netns "$SUT_NS" name "$MESH_IF_SUT"
  priv ip link set "xnftwg1" netns "$CLI_NS" name "$MESH_IF_CLI"

  # --- addresses + link state, SUT side ---
  ns_exec "$SUT_NS" ip link set lo up
  ns_exec "$SUT_NS" ip addr add "$PUB_SUT_IP/$PUB_CIDR" dev "$PUB_IF_SUT"
  ns_exec "$SUT_NS" ip addr add "$BOGON_SUT_IP/$PUB_CIDR" dev "$PUB_IF_SUT"
  ns_exec "$SUT_NS" ip link set "$PUB_IF_SUT" up
  ns_exec "$SUT_NS" ip addr add "$MESH_SUT_IP/$PUB_CIDR" dev "$MESH_IF_SUT"
  ns_exec "$SUT_NS" ip addr add "$SPOOF_SUT_IP/$PUB_CIDR" dev "$MESH_IF_SUT"
  ns_exec "$SUT_NS" ip link set "$MESH_IF_SUT" up

  # --- addresses + link state, client side ---
  ns_exec "$CLI_NS" ip link set lo up
  ns_exec "$CLI_NS" ip addr add "$PUB_CLI_IP/$PUB_CIDR" dev "$PUB_IF_CLI"
  ns_exec "$CLI_NS" ip addr add "$BOGON_CLI_IP/$PUB_CIDR" dev "$PUB_IF_CLI"
  ns_exec "$CLI_NS" ip link set "$PUB_IF_CLI" up
  ns_exec "$CLI_NS" ip addr add "$MESH_CLI_IP/$PUB_CIDR" dev "$MESH_IF_CLI"
  ns_exec "$CLI_NS" ip addr add "$SPOOF_CLI_IP/$PUB_CIDR" dev "$MESH_IF_CLI"
  ns_exec "$CLI_NS" ip link set "$MESH_IF_CLI" up

  # Reverse-path filtering would silently drop some probes *before* nftables
  # ever sees them, which would make the firewall look stricter than it is.
  # Disable it so nftables is the only thing making decisions.
  ns_exec "$SUT_NS" sysctl -qw net.ipv4.conf.all.rp_filter=0 || true
  ns_exec "$SUT_NS" sysctl -qw net.ipv4.conf.default.rp_filter=0 || true
  ns_exec "$SUT_NS" sysctl -qw net.ipv4.icmp_echo_ignore_all=0 || true

  ENV_READY=1
  return 0
}

# Kill listeners and remove namespaces.  Safe to call at any time.
env_down() {
  local pid
  for pid in "${LISTENER_PIDS[@]:-}"; do
    if [[ -n "$pid" ]]; then
      priv kill "$pid" > /dev/null 2>&1 || true
    fi
  done
  LISTENER_PIDS=()
  priv ip netns del "$SUT_NS" > /dev/null 2>&1 || true
  priv ip netns del "$CLI_NS" > /dev/null 2>&1 || true
  priv rm -f "$WG_HIT_FILE" > /dev/null 2>&1 || true
  if [[ -n "$STAGE_DIR" && -d "$STAGE_DIR" ]]; then
    rm -rf "$STAGE_DIR"
  fi
  STAGE_DIR=""
  # shellcheck disable=SC2034  # read by run-tests.sh / cases/*.sh guards
  ENV_READY=0
  return 0
}

env_down_quiet() { env_down > /dev/null 2>&1 || true; }

# ---------------------------------------------------------------------------
# load_ruleset — load the staged ruleset inside SUT_NS
# ---------------------------------------------------------------------------
# Prints nft's error output on failure so the harness can show it as a TAP
# diagnostic.  Returns nft's exit status.
# ---------------------------------------------------------------------------
load_ruleset() {
  stage_ruleset
  ns_exec "$SUT_NS" nft -f "$(staged_conf)" 2>&1
}

# Dry-run only (no kernel commit beyond validation): the syntax test.
dryrun_ruleset() {
  stage_ruleset
  priv nft -c -f "$(staged_conf)" 2>&1
}

# ---------------------------------------------------------------------------
# probes_install — counter-only observation table (see header comment)
# ---------------------------------------------------------------------------
# Every rule carries a comment "probe:<pre|post>:<name>"; probe_count() reads
# the packet counter back by matching that comment.  No verdicts are used, so
# the observation table cannot change the outcome of any test.
# ---------------------------------------------------------------------------
probes_install() {
  stage_ruleset
  local file
  file="$STAGE_DIR/probe.nft"
  # shellcheck disable=SC2016  # the $-less nft syntax below is intentional
  cat > "$file" << PROBES
# Observation table — NOT part of the ruleset under test.
table inet xnft_probe {
    chain pre {
        # priority -300 (raw): earlier than table inet filter (priority 0),
        # so this chain sees every packet that reaches the host.
        type filter hook input priority -300; policy accept;
$(probe_rules pre)
    }

    chain post {
        # priority 10: later than table inet filter, so this chain only sees
        # packets the ruleset under test ACCEPTED.
        type filter hook input priority 10; policy accept;
$(probe_rules post)
    }
}
PROBES
  chmod a+r "$file"
  ns_exec "$SUT_NS" nft -f "$file" 2>&1
}

# The identical rule body is used in both chains so pre/post are comparable.
# $1 = "pre" or "post"
probe_rules() {
  local phase="$1"
  cat << RULES
        tcp dport $PORT_SSH counter comment "probe:$phase:ssh"
        tcp dport $PORT_HTTP counter comment "probe:$phase:http"
        tcp dport $PORT_RANDOM counter comment "probe:$phase:random"
        tcp dport $PORT_LOOPBACK counter comment "probe:$phase:loopback"
        udp dport $PORT_WG counter comment "probe:$phase:wg"
        tcp flags == 0x0 counter comment "probe:$phase:null"
        tcp flags & (fin|psh|urg) == fin|psh|urg counter comment "probe:$phase:xmas"
        tcp flags & (syn|fin) == syn|fin counter comment "probe:$phase:synfin"
        tcp flags & (fin|ack) == fin counter comment "probe:$phase:finscan"
        ip saddr $BOGON_CLI_IP counter comment "probe:$phase:bogon"
        iifname "$MESH_IF_SUT" ip saddr $SPOOF_CLI_IP counter comment "probe:$phase:meshspoof"
        iifname "lo" counter comment "probe:$phase:lo"
        ip protocol icmp icmp type echo-request ip saddr $PUB_CLI_IP counter comment "probe:$phase:icmp_pub"
        ip protocol icmp icmp type echo-request ip saddr $MESH_CLI_IP counter comment "probe:$phase:icmp_mesh"
RULES
}

# probe_count <pre|post> <name> → packet count (0 when the rule/table is absent)
probe_count() {
  local phase="$1" name="$2" out
  out="$(nft_sut list table inet xnft_probe 2> /dev/null || true)"
  printf '%s\n' "$out" | awk -v key="probe:${phase}:${name}\"" '
        index($0, key) > 0 {
            for (i = 1; i <= NF; i++) {
                if ($i == "packets") { print $(i+1); found = 1; exit }
            }
        }
        END { if (!found) print 0 }
    '
}

# Zero all observation counters so each test starts from a clean slate.
probes_reset() {
  if nft_sut reset rules table inet xnft_probe > /dev/null 2>&1; then
    return 0
  fi
  # Older nft without "reset rules": rebuild the table instead.
  nft_sut delete table inet xnft_probe > /dev/null 2>&1 || true
  probes_install > /dev/null 2>&1 || true
  return 0
}

# ---------------------------------------------------------------------------
# Listeners — something must answer, otherwise every probe looks "refused"
# ---------------------------------------------------------------------------
# start_listener <ns> <tcp|udp> <port> [bind] [extra args...]
start_listener() {
  local ns="$1" proto="$2" port="$3" bind="${4:-0.0.0.0}"
  shift 4 || shift $#
  [[ -n "$PY" ]] || return 1
  ns_exec "$ns" "$PY" "$TESTS_DIR/helpers/listener.py" \
    --proto "$proto" --port "$port" --bind "$bind" "$@" \
    > /dev/null 2>&1 &
  LISTENER_PIDS+=("$!")
  return 0
}

# Give listeners a moment to bind before probing them.
listeners_settle() { sleep 0.5; }

# ---------------------------------------------------------------------------
# Packet probes (all executed from CLI_NS unless stated otherwise)
# ---------------------------------------------------------------------------
# tcp_status <ns> <src-ip|-> <dst-ip> <port> [timeout]
# Prints one of: open | refused | filtered | unreachable | error
# "filtered" is what a *dropping* firewall produces; "refused" means a RST came
# back, which for this ruleset would be a policy failure (information leak).
tcp_status() {
  local ns="$1" src="$2" dst="$3" port="$4" timeout="${5:-3}"
  local -a args=(--dst "$dst" --port "$port" --timeout "$timeout")
  [[ "$src" != "-" ]] && args+=(--src "$src")
  ns_exec "$ns" "$PY" "$TESTS_DIR/helpers/tcpconnect.py" "${args[@]}" 2> /dev/null || true
}

# tcp_echo <ns> <src|-> <dst> <port> <payload>
# Connects, sends the payload and requires it back — this exercises the
# established/related return path end to end.
# Prints: echo-ok | echo-fail | filtered | refused | ...
tcp_echo() {
  local ns="$1" src="$2" dst="$3" port="$4" payload="$5"
  local -a args=(--dst "$dst" --port "$port" --timeout 4 --send "$payload" --expect-echo)
  [[ "$src" != "-" ]] && args+=(--src "$src")
  ns_exec "$ns" "$PY" "$TESTS_DIR/helpers/tcpconnect.py" "${args[@]}" 2> /dev/null || true
}

# udp_send <ns> <src|-> <dst> <port> [payload-size]
# WireGuard's initiation datagram is 148 bytes; we mimic that size.
udp_send() {
  local ns="$1" src="$2" dst="$3" port="$4" size="${5:-148}"
  local -a args=(--proto udp --dst "$dst" --port "$port" --payload-size "$size" --timeout 2)
  [[ "$src" != "-" ]] && args+=(--src "$src")
  ns_exec "$ns" "$PY" "$TESTS_DIR/helpers/tcpconnect.py" "${args[@]}" 2> /dev/null || true
}

# scan_send <ns> <src> <dst> <dport> <null|xmas|synfin|synrst|fin|syn> [count]
# Uses the raw-socket crafter; falls back to hping3 / nmap when python3 is
# unavailable.  Returns non-zero if no crafting tool exists.
scan_send() {
  local ns="$1" src="$2" dst="$3" dport="$4" kind="$5" count="${6:-3}"
  if [[ -n "$PY" ]]; then
    ns_exec "$ns" "$PY" "$TESTS_DIR/helpers/tcpflags.py" \
      --src "$src" --dst "$dst" --dport "$dport" --flags "$kind" \
      --count "$count" > /dev/null 2>&1
    return $?
  fi
  if have hping3; then
    local flag_args
    case "$kind" in
      null) flag_args="" ;;
      xmas) flag_args="-F -P -U" ;;
      synfin) flag_args="-S -F" ;;
      synrst) flag_args="-S -R" ;;
      fin) flag_args="-F" ;;
      syn) flag_args="-S" ;;
      *) return 2 ;;
    esac
    # shellcheck disable=SC2086  # word splitting of flag_args is intended
    ns_exec "$ns" hping3 -c "$count" -a "$src" -p "$dport" $flag_args "$dst" \
      > /dev/null 2>&1
    return $?
  fi
  if have nmap; then
    local scan
    case "$kind" in
      null) scan="-sN" ;;
      xmas) scan="-sX" ;;
      fin) scan="-sF" ;;
      *) return 2 ;;
    esac
    ns_exec "$ns" nmap "$scan" -p "$dport" -Pn --max-retries 1 "$dst" \
      > /dev/null 2>&1
    return $?
  fi
  return 2
}

# icmp_ping <ns> <src|-> <dst> [count]
#   0 = at least one echo-reply arrived
#   1 = silence (what the policy should produce for a non-mesh source)
#   2 = no usable ICMP tool here → the caller should SKIP
# Prefers ping(8); falls back to helpers/icmpecho.py (raw socket) because slim
# container images often ship without iputils-ping.
icmp_ping() {
  local ns="$1" src="$2" dst="$3" count="${4:-2}"
  if have ping; then
    if [[ "$src" == "-" ]]; then
      ns_exec "$ns" ping -c "$count" -W 2 -q "$dst" > /dev/null 2>&1
    else
      ns_exec "$ns" ping -c "$count" -W 2 -q -I "$src" "$dst" > /dev/null 2>&1
    fi
    return $?
  fi
  [[ -n "$PY" ]] || return 2
  local -a args=(--dst "$dst" --count "$count" --timeout 2)
  [[ "$src" != "-" ]] && args+=(--src "$src")
  local out rc
  out="$(ns_exec "$ns" "$PY" "$TESTS_DIR/helpers/icmpecho.py" "${args[@]}" 2> /dev/null)" &&
    rc=0 || rc=$?
  vdiag "icmpecho: $out (rc=$rc)"
  return "$rc"
}

# True when some ICMP echo tool is usable at all (used by the ICMP tests to
# decide between a real assertion and a SKIP).
icmp_tool_available() {
  have ping && return 0
  [[ -n "$PY" ]] && return 0
  return 1
}

# ---------------------------------------------------------------------------
# Kernel log inspection — the ruleset logs with "XNFT-*" prefixes before every
# drop.  netfilter's log target writes via printk, so entries land in dmesg /
# journalctl -k on the HOST (log messages are not namespaced).
# kernel_log_has <prefix> → 0 if seen, 1 if not seen, 2 if the log is unreadable
# ---------------------------------------------------------------------------
kernel_log_has() {
  local prefix="$1" out
  if ! out="$(priv dmesg 2> /dev/null | tail -n 2000)"; then
    return 2
  fi
  [[ -z "$out" ]] && return 2
  printf '%s\n' "$out" | grep -q -- "$prefix"
}

# Clear the kernel ring buffer if we are allowed to; best-effort only.
kernel_log_clear() { priv dmesg -C > /dev/null 2>&1 || true; }

# ---------------------------------------------------------------------------
# Helper used by many tests: "the packet arrived and the ruleset dropped it"
# assert_dropped <desc> <probe-name>
# ---------------------------------------------------------------------------
assert_dropped() {
  local desc="$1" name="$2"
  local pre post
  pre="$(probe_count pre "$name")"
  post="$(probe_count post "$name")"
  if ((pre == 0)); then
    tap_not_ok "$desc" \
      "probe never reached the host (pre counter is 0) — test setup problem"
    return 0
  fi
  if ((post == 0)); then
    tap_ok "$desc"
    return 0
  fi
  tap_not_ok "$desc" "pre=$pre post=$post — packet survived the ruleset"
  return 0
}

# assert_accepted <desc> <probe-name>
assert_accepted() {
  local desc="$1" name="$2"
  local pre post
  pre="$(probe_count pre "$name")"
  post="$(probe_count post "$name")"
  if ((pre == 0)); then
    tap_not_ok "$desc" \
      "probe never reached the host (pre counter is 0) — test setup problem"
    return 0
  fi
  if ((post > 0)); then
    tap_ok "$desc"
    return 0
  fi
  tap_not_ok "$desc" "pre=$pre post=$post — packet was dropped but should pass"
  return 0
}
