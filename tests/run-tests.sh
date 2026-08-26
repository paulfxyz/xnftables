#!/usr/bin/env bash
# =============================================================================
# run-tests.sh — xnftables ENFORCEMENT test suite (orchestrator)
# =============================================================================
# `nft -c` proves the ruleset parses.  It proves nothing about behaviour.
# This suite loads the real ruleset into a throw-away network namespace, fires
# real packets at it from a second namespace, and checks what actually happens:
# what is dropped, what is accepted, what is logged and counted.
#
#   ./tests/run-tests.sh              # auto-detect: docker/podman, else netns
#   ./tests/run-tests.sh --netns      # force plain network namespaces (sudo)
#   ./tests/run-tests.sh --docker     # force container mode (--privileged)
#   ./tests/run-tests.sh --list       # list test names and exit
#   ./tests/run-tests.sh --verbose    # extra TAP comments
#
# Output is TAP (Test Anything Protocol):
#   1..29
#   ok 1 - syntax: full ruleset passes nft -c dry-run
#   not ok 2 - public: TCP/22 (SSH) is dropped, not reachable
#   ok 3 - ... # SKIP ping not installed
#   # tests 29 | passed 28 | failed 1 | skipped 0
#   # RESULT: FAIL
#
# Exit status: 0 = no failures (skips are not failures), 1 = at least one
# failure, 2 = usage error, 1 with "Bail out!" = the harness could not run.
#
# NOTHING OUTSIDE tests/ IS TOUCHED.  The ruleset is copied to a temp directory
# with its include paths rewritten, so /etc/nftables is never written to and the
# host firewall is never modified — all rules are loaded inside a namespace.
#
# SPDX-License-Identifier: MIT
# https://github.com/paulfxyz/xnftables
# =============================================================================

set -euo pipefail

TESTS_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$TESTS_DIR/.." && pwd)"
export TESTS_DIR REPO_ROOT

# shellcheck source=lib.sh disable=SC1091
source "$TESTS_DIR/lib.sh"

# ---------------------------------------------------------------------------
# The ordered list of test functions.  ADD NEW TESTS HERE (and to a cases/ file)
# — the TAP plan count is derived from this array, so nothing else to update.
# ---------------------------------------------------------------------------
TESTS=(
  # cases/00-static.sh — does it parse, load and say what we expect?
  t_syntax_dryrun
  t_ruleset_loads
  t_chains_present
  t_sets_present
  t_base_policies
  t_log_prefixes
  # cases/10-public.sh — the public interface is a black hole (except WG)
  t_public_ssh_dropped
  t_public_http_dropped
  t_public_random_port_dropped
  t_public_no_rst_leak
  t_public_counters_prove_drop
  t_public_wireguard_udp_reachable
  # cases/20-mesh.sh — mesh trust boundary and anti-spoofing
  t_mesh_ssh_reachable
  t_mesh_spoof_blocked
  t_mesh_spoof_counter
  t_mesh_established_echo
  # cases/30-antiscan.sh — stealth scans and bogons
  t_scan_null_dropped
  t_scan_xmas_dropped
  t_scan_synfin_dropped
  t_scan_fin_dropped
  t_bogon_status_filtered
  t_bogon_counter_drop
  t_scan_logs_present
  # cases/40-icmp.sh — controlled ICMP
  t_icmp_public_no_reply
  t_icmp_public_counter_drop
  t_icmp_mesh_allowed
  # cases/50-loopback.sh — local traffic unaffected
  t_loopback_tcp_open
  t_loopback_ping_ok
  # cases/60-conntrack.sh — established/related return path
  t_public_established_return
)

MODE="auto"
IMAGE_NAME="${XNFT_TEST_IMAGE:-xnftables-tests:local}"

usage() {
  sed -n '3,32p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

parse_args() {
  while (($# > 0)); do
    case "$1" in
      --netns) MODE="netns" ;;
      --docker) MODE="docker" ;;
      --verbose | -v) VERBOSE=1 ;;
      --list)
        printf '%s\n' "${TESTS[@]}"
        exit 0
        ;;
      --help | -h)
        usage
        exit 0
        ;;
      *)
        printf 'unknown option: %s\n' "$1" >&2
        usage >&2
        exit 2
        ;;
    esac
    shift
  done
}

# ---------------------------------------------------------------------------
# Container runtime detection.  Docker/podman is the friendlier default because
# the image ships every probe tool; plain namespaces are the fallback and need
# nft + python3 on the host.
# ---------------------------------------------------------------------------
detect_runtime() {
  if have docker && docker info > /dev/null 2>&1; then
    printf 'docker\n'
    return 0
  fi
  if have podman && podman info > /dev/null 2>&1; then
    printf 'podman\n'
    return 0
  fi
  printf 'none\n'
}

# ---------------------------------------------------------------------------
# Container mode: build the image, then re-run THIS script inside it with
# --netns.  The container needs --privileged (nftables + netns + raw sockets).
# ---------------------------------------------------------------------------
run_in_container() {
  local runtime="$1"
  shift
  diag "container mode via $runtime (image $IMAGE_NAME)"
  if ! "$runtime" build -q -f "$TESTS_DIR/Dockerfile.test" -t "$IMAGE_NAME" "$TESTS_DIR" > /dev/null; then
    die "failed to build $IMAGE_NAME from tests/Dockerfile.test"
  fi
  # --privileged: loading an nftables ruleset and creating veth pairs both
  # require CAP_NET_ADMIN in a namespace the kernel trusts; raw sockets for
  # the scan probes require CAP_NET_RAW.
  exec "$runtime" run --rm --privileged \
    -v "$REPO_ROOT:/repo:ro" \
    -e "VERBOSE=$VERBOSE" \
    -e "XNFT_IN_CONTAINER=1" \
    "$IMAGE_NAME" /repo/tests/run-tests.sh --netns "$@"
}

# ---------------------------------------------------------------------------
# Bring up the enforcement environment.  On any problem we set SKIP_REASON and
# leave ENV_READY=0: the enforcement tests then report SKIP instead of bogus
# failures, and the exit status stays clean.
# ---------------------------------------------------------------------------
SKIP_REASON=""
RULESET_LOADED=0
RULESET_LOAD_OUTPUT=""

setup_environment() {
  if ! detect_privileges; then
    SKIP_REASON="needs root or sudo"
    return 1
  fi
  if ! have ip; then
    SKIP_REASON="iproute2 (ip) not installed"
    return 1
  fi
  if ! have nft; then
    SKIP_REASON="nft not installed"
    return 1
  fi
  if ! detect_python; then
    SKIP_REASON="python3 not installed (needed by the packet probes)"
    return 1
  fi
  if ! priv ip netns list > /dev/null 2>&1; then
    SKIP_REASON="cannot manage network namespaces here"
    return 1
  fi

  if ! env_up 2> /tmp/xnft-envup.$$; then
    SKIP_REASON="namespace setup failed: $(tr '\n' ' ' < /tmp/xnft-envup.$$ | cut -c1-160)"
    rm -f /tmp/xnft-envup.$$
    return 1
  fi
  rm -f /tmp/xnft-envup.$$

  # Load the ruleset under test inside the SUT namespace.
  RULESET_LOAD_OUTPUT="$(load_ruleset)" && RULESET_LOADED=1 || RULESET_LOADED=0
  if ((RULESET_LOADED == 0)); then
    if printf '%s' "$RULESET_LOAD_OUTPUT" | grep -q "Operation not supported"; then
      SKIP_REASON="kernel lacks nf_tables inet support (see README caveats)"
      ENV_READY=0
      return 1
    fi
    # A genuine ruleset error: keep ENV_READY=1 so t_ruleset_loads FAILS
    # loudly, but the packet tests have nothing to test against.
    SKIP_REASON="ruleset failed to load — see the t_ruleset_loads diagnostic"
    return 0
  fi

  # Observation counters (separate table, no verdicts — see lib.sh header).
  local probe_out
  if ! probe_out="$(probes_install)"; then
    SKIP_REASON="could not install observation counters: $(printf '%s' "$probe_out" | head -n 3)"
    return 1
  fi

  start_all_listeners
  listeners_settle
  return 0
}

# The "services" the firewall is supposed to be protecting (or hiding).
# PORT_RANDOM and 33334 intentionally have NO listener: they prove that even a
# closed port answers with silence rather than a RST.
start_all_listeners() {
  start_listener "$SUT_NS" tcp "$PORT_SSH" 0.0.0.0
  start_listener "$SUT_NS" tcp "$PORT_HTTP" 0.0.0.0
  start_listener "$SUT_NS" tcp "$PORT_LOOPBACK" 127.0.0.1
  start_listener "$SUT_NS" udp "$PORT_WG" 0.0.0.0 --record "$WG_HIT_FILE"
  start_listener "$CLI_NS" tcp "$PORT_CLI_ECHO" 0.0.0.0
}

# ---------------------------------------------------------------------------
# Guards used by the test cases to degrade gracefully.
# ---------------------------------------------------------------------------
enforcement_guard() {
  local desc="$1"
  if ((ENV_READY != 1)) || ((RULESET_LOADED != 1)); then
    tap_skip "$desc" "${SKIP_REASON:-no enforcement environment}"
    return 1
  fi
  return 0
}

# Same, but only needs the ruleset loaded (no packet probing).
ruleset_guard() { enforcement_guard "$1"; }

cleanup() {
  local rc=$?
  env_down_quiet
  # Listeners are children of `ip netns exec`; make sure none survive.
  priv pkill -f "helpers/listener.py" > /dev/null 2>&1 || true
  exit "$rc"
}

main() {
  parse_args "$@"

  if [[ "$MODE" == "auto" ]]; then
    local runtime
    runtime="$(detect_runtime)"
    if [[ "$runtime" != "none" && -z "${XNFT_IN_CONTAINER:-}" ]]; then
      MODE="docker"
    else
      MODE="netns"
    fi
  fi

  if [[ "$MODE" == "docker" ]]; then
    local runtime
    runtime="$(detect_runtime)"
    [[ "$runtime" == "none" ]] && die "no working docker/podman found (try --netns)"
    run_in_container "$runtime"
    # run_in_container execs; we never get here.
  fi

  trap cleanup EXIT INT TERM

  diag "xnftables enforcement suite — netns mode"
  diag "repo:  $REPO_ROOT"
  diag "kernel: $(uname -r)   nft: $(nft --version 2> /dev/null || echo 'missing')"

  # Load the test cases.
  local case_file
  for case_file in "$TESTS_DIR"/cases/*.sh; do
    # shellcheck source=/dev/null
    source "$case_file"
  done

  tap_plan "${#TESTS[@]}"

  # Best-effort: start from a quiet kernel log so log assertions are precise.
  kernel_log_clear

  if ! setup_environment; then
    diag "enforcement environment unavailable: ${SKIP_REASON:-unknown reason}"
    diag "syntax tests still run; packet tests will be reported as SKIP"
  fi

  local test_fn
  for test_fn in "${TESTS[@]}"; do
    if ! declare -F "$test_fn" > /dev/null; then
      tap_not_ok "$test_fn" "test function not defined in tests/cases/*.sh"
      continue
    fi
    vdiag "running $test_fn"
    # A crashing test must not abort the whole run.
    "$test_fn" || tap_not_ok "$test_fn" "test function returned non-zero unexpectedly"
  done

  tap_summary
}

main "$@"
