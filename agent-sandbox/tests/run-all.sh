#!/bin/bash
# run-all.sh — Build the agent-sandbox image and run all tests.
#
# Usage:
#   agent-sandbox/tests/run-all.sh              # build + test
#   IMAGE=my-image:v2 agent-sandbox/tests/run-all.sh  # test a custom image

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export IMAGE="${IMAGE:-agent-sandbox:latest}"

echo "=== Building container image ($IMAGE) ==="
podman build --layers -t "$IMAGE" "$SCRIPT_DIR/.."
echo ""

rc=0

echo "=== Image tests ==="
"$SCRIPT_DIR/test-image.sh" || rc=1
echo ""

echo "=== Persistent home tests ==="
"$SCRIPT_DIR/test-persistent-home.sh" || rc=1
echo ""

if [ "$rc" -ne 0 ]; then
    echo "Some test suites FAILED." >&2
fi
exit "$rc"
