#!/bin/bash
# install-env.sh — Install agent-log-shipper (hook collector + log shipper)
# in one agent environment: the host, or inside an agent VM.
#
# Installs:
#   /usr/local/lib/agent-logs/agent-log-shipper
#   /etc/systemd/system/agent-log-shipper.service
#   /etc/agent-tools/agent-log-shipper.env        (SHIPPER_MODE, AGENT_USER)
#   /etc/claude-code/managed-settings.d/45-agent-otel.json   (only with --otel)
# then enables and (re)starts agent-log-shipper.service.
#
# Modes (docs/design/implementation.md, "Log shipper"; overview.md, "Rollout"):
#   host   ship to agent-logd over /run/agent-logd/ingest.sock
#   vm     ship to agent-logd over vsock (host CID 2, port 700)
#   local  phase 1: hook collector and spool only, nothing leaves the machine
#
# Usage:
#   sudo ./install-env.sh --mode host|vm|local [--otel] [--root DIR] [--dry-run]
#
# Examples:
#   sudo ./install-env.sh --mode local          # phase 1, before agent-logd exists
#   sudo ./install-env.sh --mode host --otel    # host environment with OTel export
#   ./install-env.sh --mode vm --root /tmp/stage   # stage files, touch nothing else

set -euo pipefail

# -----------------------------------------------------------------
# Defaults
# -----------------------------------------------------------------
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE=""
OTEL=false
AGENT_USER=agent
ROOT=""
DRY_RUN=false

LIB_DIR=/usr/local/lib/agent-logs
UNIT_DIR=/etc/systemd/system
CONF_DIR=/etc/agent-tools
MANAGED_DIR=/etc/claude-code/managed-settings.d

usage() {
    cat <<'USAGE'
Usage: install-env.sh --mode host|vm|local [OPTIONS]

Install agent-log-shipper in this agent environment.

Options:
  --mode <mode>   host (ship over the local unix socket), vm (ship over vsock),
                  or local (phase 1: keep hook records in the local spool)
  --agent-user <name>  The agent account whose transcripts are shipped
                  (default: agent)
  --otel          Also install the 45-agent-otel.json managed settings drop-in
                  (OTLP endpoint 127.0.0.1 on the host, 192.168.123.1 in a VM)
  --root <dir>    Stage files under DIR; skip systemctl (no root needed)
  --dry-run       Print the actions without performing them
  --help          Show this help message
USAGE
}

die() { echo "install-env.sh: $*" >&2; exit 1; }
note() { echo "==> $*"; }

# -----------------------------------------------------------------
# Arguments
# -----------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --mode)    [ $# -ge 2 ] || die "--mode needs a value"; MODE="$2"; shift 2 ;;
        --otel)    OTEL=true; shift ;;
        --agent-user) [ $# -ge 2 ] || die "--agent-user needs a value"; AGENT_USER="$2"; shift 2 ;;
        --root)    [ $# -ge 2 ] || die "--root needs a value"; ROOT="${2%/}"; shift 2 ;;
        --dry-run) DRY_RUN=true; shift ;;
        --help|-h) usage; exit 0 ;;
        *)         usage >&2; die "unknown argument: $1" ;;
    esac
done

[[ "$AGENT_USER" =~ ^[a-z_][a-z0-9_-]*$ ]] || die "bad --agent-user '$AGENT_USER'"
case "$MODE" in
    host|vm|local) ;;
    "") usage >&2; die "--mode is required" ;;
    *)  die "bad --mode '$MODE' (host, vm, or local)" ;;
esac
if $OTEL && [ "$MODE" = local ]; then
    die "--otel needs agent-logd's OTLP receiver; not available in local mode"
fi
if [ -z "$ROOT" ] && ! $DRY_RUN && [ "$(id -u)" -ne 0 ]; then
    die "must run as root (or use --root DIR / --dry-run)"
fi
if [ -n "$ROOT" ]; then
    mkdir -p "$ROOT" || die "cannot create $ROOT"
    ROOT="$(cd "$ROOT" && pwd)"
fi

# -----------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------

# Run a command, or print it under --dry-run.
run() {
    if $DRY_RUN; then
        echo "+ $*"
    else
        "$@"
    fi
}

# Run a system-management command only on a real install (not --root).
run_system() {
    if [ -n "$ROOT" ]; then
        echo "(--root: skipping: $*)"
    else
        run "$@"
    fi
}

# install_file MODE SRC DEST — copy with mode; root-owned on a real install.
install_file() {
    local mode="$1" src="$2" dest="$ROOT$3"
    local owner=()
    [ -z "$ROOT" ] && owner=(-o root -g root)
    run install -D -m "$mode" "${owner[@]}" "$src" "$dest"
}

# install_content MODE DEST — write stdin to DEST (atomically via install).
install_content() {
    local mode="$1" dest="$2" tmp
    tmp="$(mktemp)"
    cat >"$tmp"
    install_file "$mode" "$tmp" "$dest"
    rm -f "$tmp"
}

# -----------------------------------------------------------------
# Checks
# -----------------------------------------------------------------
python3 -c 'import sys; sys.exit(sys.version_info < (3, 12))' \
    || die "python3 >= 3.12 is required"
for f in agent-log-shipper systemd/agent-log-shipper.service managed-settings.d/45-agent-otel.json.in; do
    [ -f "$HERE/$f" ] || die "missing $HERE/$f"
done
if [ "$MODE" = vm ] && [ -z "$ROOT" ] && [ ! -e /dev/vsock ]; then
    echo "WARNING: /dev/vsock not found; add a <vsock> device to this VM (see README)" >&2
fi

# -----------------------------------------------------------------
# Install
# -----------------------------------------------------------------
note "installing agent-log-shipper ($MODE mode)"
install_file 0755 "$HERE/agent-log-shipper" "$LIB_DIR/agent-log-shipper"
install_file 0644 "$HERE/systemd/agent-log-shipper.service" "$UNIT_DIR/agent-log-shipper.service"
install_content 0644 "$CONF_DIR/agent-log-shipper.env" <<CONF
# Written by agent-logs/install-env.sh; read by agent-log-shipper.service.
SHIPPER_MODE=$MODE
AGENT_USER=$AGENT_USER
CONF

if $OTEL; then
    if [ "$MODE" = host ]; then OTLP=127.0.0.1; else OTLP=192.168.123.1; fi
    note "installing OTel managed settings (endpoint $OTLP:4318)"
    sed "s/@OTLP@/$OTLP/g" "$HERE/managed-settings.d/45-agent-otel.json.in" \
        | install_content 0644 "$MANAGED_DIR/45-agent-otel.json"
fi

note "enabling agent-log-shipper.service"
run_system systemctl daemon-reload
run_system systemctl enable agent-log-shipper.service
# restart (not start) so a re-run picks up new code and a new mode.
run_system systemctl restart agent-log-shipper.service

note "done"
if [ "$MODE" = local ]; then
    echo "Hook records stay in /var/lib/agent-log-shipper/spool (local-only mode)."
fi
