#!/bin/bash
# check-nft.sh — Syntax-check the nftables files exactly as installed.
#
# Stages an install with install-host.sh --root (which substitutes the agent
# UID and dev ports), then runs `nft -c -f` on each staged file.  `nft -c`
# needs CAP_NET_ADMIN even for a check, so this uses sudo when not root
# (CI: ubuntu-latest has passwordless sudo).  Nothing is loaded.
#
# Usage:
#   agent-egress/tests/check-nft.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NFT=(nft)
if [ "$(id -u)" -ne 0 ]; then NFT=(sudo -n nft); fi

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
"$SCRIPT_DIR/../install-host.sh" --root "$STAGE" --agent-uid 2000 --no-libvirt >/dev/null

rc=0
for f in "$STAGE"/etc/agent-egress/*.nft; do
    if "${NFT[@]}" -c -f "$f"; then
        echo "ok      $(basename "$f")"
    else
        echo "FAILED  $(basename "$f")" >&2
        rc=1
    fi
done
exit "$rc"
