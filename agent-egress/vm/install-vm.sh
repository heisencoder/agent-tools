#!/bin/bash
# install-vm.sh — Point an agent VM at the host's egress proxy.
#
# Run as root inside each agent VM (docs/design/implementation.md,
# "Isolated VM network").
# The VM sits on the isolated agent-net network with no DNS and no route out;
# the only way out is the host proxy at 192.168.123.1:3128.  This installs:
#   - /etc/environment: http_proxy, https_proxy, no_proxy (both cases)
#   - /etc/apt/apt.conf.d/90agent-proxy: apt through the proxy
#   - /etc/gitconfig: url."https://github.com/".insteadOf git@github.com:
#     (SSH is blocked; GitHub SSH remotes are rewritten to HTTPS)
#   - /etc/claude-code/managed-settings.d/40-agent-egress.json
#
# Safe to re-run.
#
# Usage:
#   sudo ./install-vm.sh [OPTIONS]
#
# Examples:
#   sudo ./install-vm.sh
#   ./install-vm.sh --root "$(mktemp -d)"     # staging, no root
#   ./install-vm.sh --dry-run

set -euo pipefail
umask 022

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EGRESS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# -----------------------------------------------------------------
# Defaults
# -----------------------------------------------------------------
ROOT=""
DRY_RUN=false
PROXY_ADDR="192.168.123.1"

usage() {
    cat <<'EOF'
Usage: install-vm.sh [OPTIONS]

Configure this VM to reach the internet through the host egress proxy.
Must be run as root, except with --root or --dry-run.

Options:
  --root <dir>      Install under <dir> instead of / (no root needed)
  --dry-run         Print what would be done; change nothing
  --proxy <ipv4>    Proxy address (default: 192.168.123.1)
  --help            Show this help message
EOF
}

die() { echo "install-vm.sh: ERROR: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --root)    [ $# -ge 2 ] || die "--root needs a directory"; ROOT="$2"; shift 2 ;;
        --dry-run) DRY_RUN=true; shift ;;
        --proxy)   [ $# -ge 2 ] || die "--proxy needs an address"; PROXY_ADDR="$2"; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *)         usage >&2; die "unknown option: $1" ;;
    esac
done

if [ -n "$ROOT" ]; then
    [ -d "$ROOT" ] || die "--root $ROOT is not a directory"
    ROOT="$(cd "$ROOT" && pwd)"
    [ "$ROOT" != "/" ] || ROOT=""
fi
if [ -z "$ROOT" ] && ! $DRY_RUN && [ "$(id -u)" -ne 0 ]; then
    die "must be run as root (or use --root DIR or --dry-run)"
fi
[[ "$PROXY_ADDR" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || die "--proxy must be an IPv4 address"
command -v git >/dev/null || die "git not found"
PROXY_URL="http://$PROXY_ADDR:3128"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

OWNER_ARGS=()
if [ "$(id -u)" -eq 0 ]; then OWNER_ARGS=(-o root -g root); fi

# install_file SRC DEST MODE: install SRC as $ROOT/DEST if it differs.
install_file() {
    local src="$1" dest="$2" mode="$3"
    if [ -f "$ROOT$dest" ] && cmp -s "$src" "$ROOT$dest"; then
        echo "  unchanged  $dest"
    elif $DRY_RUN; then
        echo "  would install $dest"
    else
        install -D -m "$mode" "${OWNER_ARGS[@]}" "$src" "$ROOT$dest"
        echo "  installed  $dest"
    fi
}

# -----------------------------------------------------------------
# /etc/environment (read by pam_env at login)
# -----------------------------------------------------------------
echo "== /etc/environment"
MARK="# agent-egress: route through the host egress proxy (agent-egress/vm/install-vm.sh)"
: > "$TMP/environment"
if [ -f "$ROOT/etc/environment" ]; then
    # Keep everything except earlier proxy settings, ours included.
    grep -v -i -E "^[[:space:]]*(export[[:space:]]+)?(https?|no)_proxy=" "$ROOT/etc/environment" |
        grep -v -F -x "$MARK" > "$TMP/environment" || true
fi
cat >> "$TMP/environment" <<EOF
$MARK
http_proxy=$PROXY_URL
https_proxy=$PROXY_URL
no_proxy=localhost,127.0.0.1,::1,$PROXY_ADDR
HTTP_PROXY=$PROXY_URL
HTTPS_PROXY=$PROXY_URL
NO_PROXY=localhost,127.0.0.1,::1,$PROXY_ADDR
EOF
install_file "$TMP/environment" /etc/environment 0644

# -----------------------------------------------------------------
# apt
# -----------------------------------------------------------------
echo "== apt"
cat > "$TMP/90agent-proxy" <<EOF
// Installed by agent-egress/vm/install-vm.sh: apt goes through the host
// egress proxy.  Enable the ubuntu allowlist profile on the host first.
Acquire::http::Proxy "$PROXY_URL/";
Acquire::https::Proxy "$PROXY_URL/";
EOF
install_file "$TMP/90agent-proxy" /etc/apt/apt.conf.d/90agent-proxy 0644

# -----------------------------------------------------------------
# git: rewrite GitHub SSH remotes to HTTPS, system-wide
# -----------------------------------------------------------------
echo "== /etc/gitconfig"
GITCONFIG="$ROOT/etc/gitconfig"
KEY='url.https://github.com/.insteadOf'
if [ -f "$GITCONFIG" ] && git config --file "$GITCONFIG" --get-all "$KEY" | grep -qxF 'git@github.com:'; then
    echo "  unchanged  /etc/gitconfig"
elif $DRY_RUN; then
    echo "  would set $KEY git@github.com: in /etc/gitconfig"
else
    mkdir -p "$ROOT/etc"
    git config --file "$GITCONFIG" --add "$KEY" 'git@github.com:'
    chmod 0644 "$GITCONFIG"
    echo "  updated    /etc/gitconfig"
fi

# -----------------------------------------------------------------
# Claude Code managed settings
# -----------------------------------------------------------------
echo "== managed settings"
sed "s|@PROXY@|$PROXY_ADDR|g" "$EGRESS_DIR/managed-settings.d/40-agent-egress.json.in" \
    > "$TMP/40-agent-egress.json"
if grep -qE '@[A-Z_]+@' "$TMP/40-agent-egress.json"; then
    die "unsubstituted placeholder in 40-agent-egress.json"
fi
python3 -m json.tool "$TMP/40-agent-egress.json" >/dev/null || die "40-agent-egress.json is not valid JSON"
if ! $DRY_RUN; then
    install -d -m 0755 "${OWNER_ARGS[@]}" "$ROOT/etc/claude-code" "$ROOT/etc/claude-code/managed-settings.d"
fi
install_file "$TMP/40-agent-egress.json" /etc/claude-code/managed-settings.d/40-agent-egress.json 0644

echo "Done.  Log in again (or reboot) so /etc/environment takes effect, then check:"
echo "  curl -sS https://api.github.com/zen"
