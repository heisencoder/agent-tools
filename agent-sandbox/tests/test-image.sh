#!/bin/bash
# test-image.sh — Verify the agent-sandbox image contents and environment.
#
# Run locally:  podman build -t agent-sandbox agent-sandbox/ && agent-sandbox/tests/test-image.sh
# Or via CI:    Same (the image must already be built).

source "$(dirname "$0")/helpers.sh"

TEST_TMPDIR=$(mktemp -d "${TMPDIR:-/tmp}/agent-sandbox-test.XXXXXX")
trap 'rm -rf "$TEST_TMPDIR"' EXIT

# ── System tools ────────────────────────────────────────────────────

for tool in node npm python3 git curl jq gh clang; do
    run_test "$tool is available" run_in_image "$tool" --version
done
run_test "lld is available" run_in_image ld.lld --version

# ── Coding agents ───────────────────────────────────────────────────

run_test "Claude Code is installed" run_in_image claude --version
run_test "OpenAI Codex is installed" run_in_image codex --version

# ── Container environment ──────────────────────────────────────────

test_user() {
    local actual
    actual=$(run_in_image whoami)
    assert_eq "agent" "$actual" "whoami"
}
run_test "runs as non-root 'agent' user" test_user

test_workdir() {
    local actual
    actual=$(run_in_image pwd)
    assert_eq "/workspace" "$actual" "pwd"
}
run_test "working directory is /workspace" test_workdir

test_shell() {
    local actual
    actual=$(run_in_image sh -c 'echo $SHELL')
    assert_eq "/bin/bash" "$actual" "SHELL"
}
run_test "default shell is /bin/bash" test_shell

test_cargo_on_path() {
    local path_val
    path_val=$(run_in_image sh -c 'echo $PATH')
    assert_contains "$path_val" "/home/agent/.cargo/bin" "PATH"
}
run_test "~/.cargo/bin is on PATH" test_cargo_on_path

run_test "home skel template exists" run_in_image test -d /home/agent.skel/.npm-global

# ── Bind mounts ─────────────────────────────────────────────────────

test_bind_mount() {
    echo "hello from host" > "$TEST_TMPDIR/test.txt"
    local actual
    actual=$(podman run --rm -v "$TEST_TMPDIR:/workspace" "$IMAGE" cat /workspace/test.txt)
    assert_eq "hello from host" "$actual" "bind mount content"
}
run_test "bind mount works" test_bind_mount

# ── Python venv ─────────────────────────────────────────────────────

run_test "python3 venv creation" run_in_image python3 -m venv /tmp/testvenv

# ── Summary ─────────────────────────────────────────────────────────

test_summary
