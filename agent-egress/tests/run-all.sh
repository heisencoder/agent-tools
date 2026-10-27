#!/bin/bash
# run-all.sh — Run every agent-egress test that this machine can run.
#
#   - Python unit/integration tests (no root, no internet)
#   - shellcheck on the shell scripts, if shellcheck is installed
#   - nft syntax check, if root or passwordless sudo is available
#
# Usage:
#   agent-egress/tests/run-all.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EGRESS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
rc=0

echo "=== Python tests ==="
python3 -m unittest discover -s "$SCRIPT_DIR" || rc=1
echo ""

echo "=== shellcheck ==="
if command -v shellcheck >/dev/null; then
    shellcheck "$EGRESS_DIR"/install-host.sh "$EGRESS_DIR"/vm/install-vm.sh \
        "$SCRIPT_DIR"/*.sh && echo "ok" || rc=1
else
    echo "skipped (shellcheck not installed)"
fi
echo ""

echo "=== nft -c ==="
if [ "$(id -u)" -eq 0 ] || sudo -n true 2>/dev/null; then
    "$SCRIPT_DIR/check-nft.sh" || rc=1
else
    echo "skipped (needs root or passwordless sudo)"
fi

if [ "$rc" -ne 0 ]; then
    echo "Some agent-egress tests FAILED." >&2
fi
exit "$rc"
