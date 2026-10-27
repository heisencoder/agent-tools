#!/bin/bash
# install-claude.sh — Install a root-owned copy of the Claude Code binary.
#
# The agent user must not be able to replace the claude it runs (a patched
# binary could ignore managed settings), so sessions run a copy owned by
# root:
#   /opt/claude-code/<version>/claude        root:root 0755
#   /usr/local/bin/claude -> /opt/claude-code/<version>/claude
# The symlink is repointed atomically (temporary symlink, then rename), so a
# claude starting during an upgrade sees either the old or the new version.
# Auto-update is turned off by DISABLE_AUTOUPDATER=1 in the managed settings
# (50-agent-audit.json).  See docs/design/implementation.md, "Root-owned
# Claude Code".
#
# Usage (from the administrator's account):
#   sudo ./install-claude.sh --binary PATH [--sha256 HASH]
#
# Options:
#   --binary PATH   An existing Claude Code binary (a downloaded release, or
#                   the file under ~/.local/share/claude/versions/)
#   --sha256 HASH   Expected SHA-256 of the binary; verified when given
#   --root DIR      Install into a staging tree under DIR instead of /
#                   (for tests; no root needed)
#
# The binary is copied into the root-owned store *before* it is executed
# for `--version`, and that run happens as the unprivileged user nobody, so
# an agent-modified binary never runs as root here.  (It will still run as
# the agent later, so prefer a freshly downloaded, hash-checked release.)

set -euo pipefail

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
umask 022

# -----------------------------------------------------------------
# Defaults
# -----------------------------------------------------------------
BINARY=""
SHA256=""
ROOT=""
STORE_REL="/opt/claude-code"
LINK_REL="/usr/local/bin/claude"

usage() {
    sed -n '2,/^$/{s/^# \{0,1\}//;p}' "$0"
}

die() {
    echo "install-claude.sh: $*" >&2
    exit 1
}

# -----------------------------------------------------------------
# Parse arguments
# -----------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --binary)   [ $# -ge 2 ] || die "--binary needs a value"; BINARY="$2"; shift 2 ;;
        --binary=*) BINARY="${1#*=}"; shift ;;
        --sha256)   [ $# -ge 2 ] || die "--sha256 needs a value"; SHA256="$2"; shift 2 ;;
        --sha256=*) SHA256="${1#*=}"; shift ;;
        --root)     [ $# -ge 2 ] || die "--root needs a value"; ROOT="$2"; shift 2 ;;
        --root=*)   ROOT="${1#*=}"; shift ;;
        --help|-h)  usage; exit 0 ;;
        *)          die "unknown argument: $1 (see --help)" ;;
    esac
done

[ -n "$BINARY" ] || die "--binary PATH is required"
[ -f "$BINARY" ] || die "not a regular file: $BINARY"
if [ -n "$SHA256" ]; then
    SHA256="${SHA256,,}"
    [[ "$SHA256" =~ ^[0-9a-f]{64}$ ]] || die "--sha256 must be 64 hex digits"
fi
if [ -z "$ROOT" ] && [ "$(id -u)" -ne 0 ]; then
    die "must be run as root (or with --root DIR for a staging install)"
fi
if [ -n "$ROOT" ]; then
    ROOT="$(mkdir -p "$ROOT" && cd "$ROOT" && pwd -P)"
fi

STORE="$ROOT$STORE_REL"
LINK="$ROOT$LINK_REL"

# Owner flags for install(1): root:root for a real install; the current
# user in a staging tree (chown would fail without root).
OWNER=()
[ -z "$ROOT" ] && OWNER=(-o root -g root)

# -----------------------------------------------------------------
# Stage a private copy inside the store (same filesystem, so the final
# move is an atomic rename), then verify and inspect only that copy.
# -----------------------------------------------------------------
install -d -m 0755 "${OWNER[@]}" "$STORE" "$(dirname "$LINK")"
STAGED="$(mktemp "$STORE/.staging.XXXXXX")"
trap 'rm -f "$STAGED"' EXIT
cat -- "$BINARY" > "$STAGED"
chmod 0755 "$STAGED"
[ -z "$ROOT" ] && chown root:root "$STAGED"

actual="$(sha256sum "$STAGED" | cut -d' ' -f1)"
if [ -n "$SHA256" ] && [ "$actual" != "$SHA256" ]; then
    die "SHA-256 mismatch: expected $SHA256, got $actual"
fi

# Ask the binary for its version without giving it root.
if [ -z "$ROOT" ]; then
    version_out="$(cd / && setpriv --reuid=nobody --regid=nogroup --clear-groups \
        --no-new-privs -- env -i HOME=/nonexistent PATH=/usr/bin:/bin \
        DISABLE_AUTOUPDATER=1 "$STAGED" --version)" \
        || die "'$BINARY --version' failed"
else
    version_out="$(env -i HOME=/nonexistent PATH=/usr/bin:/bin \
        DISABLE_AUTOUPDATER=1 "$STAGED" --version)" \
        || die "'$BINARY --version' failed"
fi
# "2.1.312 (Claude Code)" -> "2.1.312".  The version becomes a directory
# name, so accept only a plain version string.
VERSION="${version_out%% *}"
[[ "$VERSION" =~ ^[0-9]+(\.[0-9]+)+([-+][0-9A-Za-z.]+)?$ ]] \
    || die "unexpected --version output: $version_out"

# -----------------------------------------------------------------
# Install /opt/claude-code/<version>/claude
# -----------------------------------------------------------------
DEST_DIR="$STORE/$VERSION"
DEST="$DEST_DIR/claude"
install -d -m 0755 "${OWNER[@]}" "$DEST_DIR"
if [ -e "$DEST" ]; then
    existing="$(sha256sum "$DEST" | cut -d' ' -f1)"
    if [ "$existing" != "$actual" ]; then
        die "$DEST already exists with different contents (sha256 $existing); remove it first"
    fi
    echo "Version $VERSION already installed at $STORE_REL/$VERSION/claude (identical)."
else
    mv -f -- "$STAGED" "$DEST"
    echo "Installed $STORE_REL/$VERSION/claude (sha256 $actual)."
fi

# -----------------------------------------------------------------
# Atomically repoint /usr/local/bin/claude.  The link target is the real
# path (without the staging root).
# -----------------------------------------------------------------
TMP_LINK="$(dirname "$LINK")/.claude.tmp.$$"
ln -sfn -- "$STORE_REL/$VERSION/claude" "$TMP_LINK"
mv -Tf -- "$TMP_LINK" "$LINK"
echo "$LINK_REL -> $STORE_REL/$VERSION/claude"
