#!/bin/bash
# helpers.sh — Shared test utilities for agent-sandbox tests.
#
# Source this from test scripts:
#   source "$(dirname "$0")/helpers.sh"

set -euo pipefail

IMAGE="${IMAGE:-agent-sandbox:latest}"
USERNS_ARGS=(--userns=keep-id:uid=1000,gid=1000)

# ── Test bookkeeping ────────────────────────────────────────────────

_PASS=0
_FAIL=0
_TOTAL=0
_SCRIPT="${0##*/}"

# Run a named test.  Passes if the command exits 0.
#   run_test "description" command [args...]
#   run_test "description" test_function_name
run_test() {
    local name="$1"; shift
    _TOTAL=$((_TOTAL + 1))
    echo "--- $name ---"
    local rc=0
    # Run in a subshell so set -e is active inside the test body,
    # but a failure doesn't abort the entire test suite.
    (set -e; "$@") || rc=$?
    if [ "$rc" -eq 0 ]; then
        _PASS=$((_PASS + 1))
        echo "PASS"
    else
        _FAIL=$((_FAIL + 1))
        echo "FAIL (exit $rc)" >&2
    fi
    echo ""
}

# Print summary and exit with 0 (all passed) or 1 (some failed).
test_summary() {
    echo "==========================================="
    echo "$_SCRIPT: $_PASS passed, $_FAIL failed ($_TOTAL total)"
    echo "==========================================="
    [ "$_FAIL" -eq 0 ]
}

# ── Container helpers ───────────────────────────────────────────────

# Run a command in a fresh ephemeral container (no persistent volume).
run_in_image() {
    podman run --rm "$IMAGE" "$@"
}

# Run a command with a persistent home volume.
# Caller must set PERSISTENT_HOME before using this.
run_with_home() {
    podman run --rm \
        "${USERNS_ARGS[@]}" \
        -v "$PERSISTENT_HOME:/home/agent" \
        "$IMAGE" "$@"
}

# ── Assertion helpers ───────────────────────────────────────────────

# assert_eq expected actual [label]
assert_eq() {
    local expected="$1" actual="$2" label="${3:-}"
    if [ "$expected" != "$actual" ]; then
        echo "  assert_eq${label:+ ($label)}: expected '$expected', got '$actual'" >&2
        return 1
    fi
}

# assert_contains haystack needle [label]
assert_contains() {
    local haystack="$1" needle="$2" label="${3:-}"
    if ! echo "$haystack" | grep -q "$needle"; then
        echo "  assert_contains${label:+ ($label)}: '$needle' not found" >&2
        return 1
    fi
}
