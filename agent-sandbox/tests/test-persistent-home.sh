#!/bin/bash
# test-persistent-home.sh — Verify persistent home directory behavior.
#
# Tests the entrypoint's first-run initialization, skip-on-rerun logic,
# agent availability with a mounted home, runtime install persistence,
# and config overlay mounts on top of the persistent home.
#
# Run locally:  podman build -t agent-sandbox agent-sandbox/ && agent-sandbox/tests/test-persistent-home.sh
# Or via CI:    Same (the image must already be built).

source "$(dirname "$0")/helpers.sh"

TEST_TMPDIR=$(mktemp -d "${TMPDIR:-/tmp}/agent-sandbox-test.XXXXXX")
trap 'podman unshare rm -rf "$TEST_TMPDIR"' EXIT

export PERSISTENT_HOME="$TEST_TMPDIR/home"
TEST_PROJECT="$TEST_TMPDIR/project"
mkdir -p "$PERSISTENT_HOME" "$TEST_PROJECT"

# ── Entrypoint initialization ──────────────────────────────────────

test_entrypoint_first_run() {
    run_with_home test -f /home/agent/.home-initialized

    # Verify key directories were copied from the skel
    for d in .npm-global .claude; do
        if [ ! -d "$PERSISTENT_HOME/$d" ]; then
            echo "  $d was not copied into persistent home" >&2
            return 1
        fi
    done
}
run_test "entrypoint populates persistent home on first run" test_entrypoint_first_run

test_entrypoint_skip() {
    # Drop a canary file and verify the entrypoint does NOT re-copy
    # (i.e. it skips because .home-initialized already exists).
    echo "canary" > "$PERSISTENT_HOME/.canary"
    run_with_home cat /home/agent/.canary | grep -q canary
}
run_test "entrypoint skips initialization on subsequent runs" test_entrypoint_skip

# ── Agents with persistent home ────────────────────────────────────

test_agents_with_home() {
    podman run --rm \
        "${USERNS_ARGS[@]}" \
        -v "$PERSISTENT_HOME:/home/agent" \
        -v "$TEST_PROJECT:/workspace" \
        "$IMAGE" claude --version

    podman run --rm \
        "${USERNS_ARGS[@]}" \
        -v "$PERSISTENT_HOME:/home/agent" \
        -v "$TEST_PROJECT:/workspace" \
        "$IMAGE" codex --version
}
run_test "agents work with persistent home mount" test_agents_with_home

# ── Runtime persistence ────────────────────────────────────────────

test_runtime_persistence() {
    # Container 1: install a tool
    run_with_home sh -c \
        'mkdir -p ~/.local/bin && echo "#!/bin/sh" > ~/.local/bin/my-tool && chmod +x ~/.local/bin/my-tool'

    # Container 2: verify it survived
    run_with_home test -x /home/agent/.local/bin/my-tool
}
run_test "runtime installs persist across container restarts" test_runtime_persistence

# ── Config overlays ────────────────────────────────────────────────

test_gh_config_overlay() {
    local gh_config="$TEST_TMPDIR/gh-config"
    mkdir -p "$gh_config"
    echo "github.com:" > "$gh_config/hosts.yml"

    local actual
    actual=$(podman run --rm \
        "${USERNS_ARGS[@]}" \
        -v "$PERSISTENT_HOME:/home/agent" \
        -v "$gh_config:/home/agent/.config/gh:ro" \
        "$IMAGE" cat /home/agent/.config/gh/hosts.yml)
    assert_eq "github.com:" "$actual" "hosts.yml"
}
run_test "gh config overlay on persistent home" test_gh_config_overlay

test_gitconfig_overlay() {
    local gitconfig="$TEST_TMPDIR/gitconfig"
    printf '[user]\n\tname = Test Agent\n' > "$gitconfig"

    local actual
    actual=$(podman run --rm \
        "${USERNS_ARGS[@]}" \
        -v "$PERSISTENT_HOME:/home/agent" \
        -v "$gitconfig:/home/agent/.gitconfig:ro" \
        "$IMAGE" git config user.name)
    assert_eq "Test Agent" "$actual" "git user.name"
}
run_test "gitconfig overlay on persistent home" test_gitconfig_overlay

# ── Summary ─────────────────────────────────────────────────────────

test_summary
