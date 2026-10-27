#!/bin/bash
# install-host.sh — Install agent-logd (receiver + store) and the agent-log
# query CLI on the host.
#
# Installs:
#   /etc/sysusers.d/agent-logs.conf     users agent-logd, group agent-audit
#   /etc/tmpfiles.d/agent-logs.conf     /var/log/agent-audit (2750 agent-logd:agent-audit)
#   /etc/modules-load.d/agent-logs.conf vhost_vsock, so vsock::700 binds at boot
#   /usr/local/lib/agent-logs/{agent-logd,agent-log}, /usr/local/bin/agent-log
#   /etc/systemd/system/agent-logd.service and agent-logd-{vsock,unix,otlp}.socket
#   /etc/agent-tools/envs.conf          from envs.conf.example, only if missing
# then enables the sockets (OTLP only with --otlp) and adds the reader user
# to group agent-audit.  The host's own shipper is installed separately
# with: sudo ./install-env.sh --mode host
#
# See docs/design/implementation.md, "agent-logd".
#
# Usage:
#   sudo ./install-host.sh [--reader USER] [--otlp] [--root DIR] [--dry-run]
#
# Examples:
#   sudo ./install-host.sh                    # store + vsock and unix ingest
#   sudo ./install-host.sh --otlp             # also the OTLP receiver on :4318
#   ./install-host.sh --root /tmp/stage       # stage files only

set -euo pipefail

# -----------------------------------------------------------------
# Defaults
# -----------------------------------------------------------------
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
READER="${SUDO_USER:-}"
OTLP=false
ROOT=""
DRY_RUN=false

LIB_DIR=/usr/local/lib/agent-logs
UNIT_DIR=/etc/systemd/system
STORE=/var/log/agent-audit
ENVS_CONF=/etc/agent-tools/envs.conf

usage() {
    cat <<'USAGE'
Usage: install-host.sh [OPTIONS]

Install agent-logd, the agent audit store, and agent-log on the host.

Options:
  --reader <user>  User allowed to read the store via group agent-audit
                   (default: the account that ran sudo, $SUDO_USER;
                   skipped if unset, root, or the user does not exist)
  --otlp           Enable the optional OTLP/HTTP receiver socket (port 4318)
  --root <dir>     Stage files under DIR; skip systemctl, systemd-sysusers,
                   systemd-tmpfiles, modprobe and usermod (no root needed)
  --dry-run        Print the actions without performing them
  --help           Show this help message
USAGE
}

die() { echo "install-host.sh: $*" >&2; exit 1; }
note() { echo "==> $*"; }

# -----------------------------------------------------------------
# Arguments
# -----------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --reader)  [ $# -ge 2 ] || die "--reader needs a value"; READER="$2"; shift 2 ;;
        --otlp)    OTLP=true; shift ;;
        --root)    [ $# -ge 2 ] || die "--root needs a value"; ROOT="${2%/}"; shift 2 ;;
        --dry-run) DRY_RUN=true; shift ;;
        --help|-h) usage; exit 0 ;;
        *)         usage >&2; die "unknown argument: $1" ;;
    esac
done

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

run() {
    if $DRY_RUN; then
        echo "+ $*"
    else
        "$@"
    fi
}

run_system() {
    if [ -n "$ROOT" ]; then
        echo "(--root: skipping: $*)"
    else
        run "$@"
    fi
}

install_file() {
    local mode="$1" src="$2" dest="$ROOT$3"
    local owner=()
    [ -z "$ROOT" ] && owner=(-o root -g root)
    run install -D -m "$mode" "${owner[@]}" "$src" "$dest"
}

# -----------------------------------------------------------------
# Checks
# -----------------------------------------------------------------
python3 -c 'import sys; sys.exit(sys.version_info < (3, 12))' \
    || die "python3 >= 3.12 is required"
for f in agent-logd agent-log sysusers.d/agent-logs.conf tmpfiles.d/agent-logs.conf \
         systemd/agent-logd.service systemd/agent-logd-vsock.socket \
         systemd/agent-logd-unix.socket systemd/agent-logd-otlp.socket; do
    [ -f "$HERE/$f" ] || die "missing $HERE/$f"
done

# -----------------------------------------------------------------
# Users, store directory, kernel module
# -----------------------------------------------------------------
note "creating users and the store directory"
install_file 0644 "$HERE/sysusers.d/agent-logs.conf" /etc/sysusers.d/agent-logs.conf
install_file 0644 "$HERE/tmpfiles.d/agent-logs.conf" /etc/tmpfiles.d/agent-logs.conf
run_system systemd-sysusers /etc/sysusers.d/agent-logs.conf
run_system systemd-tmpfiles --create /etc/tmpfiles.d/agent-logs.conf
if [ -n "$ROOT" ]; then
    run mkdir -p "$ROOT$STORE"
    run chmod 2750 "$ROOT$STORE"
fi
if [ "$READER" = root ]; then READER=""; fi
if [ -z "$ROOT" ] && [ -n "$READER" ] && getent passwd "$READER" >/dev/null; then
    run usermod -aG agent-audit "$READER"
    echo "$READER can read $STORE after logging in again"
elif [ -z "$ROOT" ]; then
    echo "WARNING: no reader ('${READER:-none}' unset or unknown); nobody was added to" \
         "group agent-audit (use --reader USER)" >&2
fi

modules="$(mktemp)"
printf '# agent-logd listens on vsock::700 (agent-logs/install-host.sh)\nvhost_vsock\n' >"$modules"
install_file 0644 "$modules" /etc/modules-load.d/agent-logs.conf
rm -f "$modules"
run_system modprobe vhost_vsock

# -----------------------------------------------------------------
# Programs, configuration, units
# -----------------------------------------------------------------
note "installing agent-logd and agent-log"
install_file 0755 "$HERE/agent-logd" "$LIB_DIR/agent-logd"
install_file 0755 "$HERE/agent-log" "$LIB_DIR/agent-log"
run mkdir -p "$ROOT/usr/local/bin"
run ln -sfn "$LIB_DIR/agent-log" "$ROOT/usr/local/bin/agent-log"

if [ ! -e "$ROOT$ENVS_CONF" ]; then
    install_file 0644 "$REPO/envs.conf.example" "$ENVS_CONF"
    echo "Installed $ENVS_CONF from envs.conf.example; edit it to list your VMs."
fi

for unit in agent-logd.service agent-logd-vsock.socket agent-logd-unix.socket \
            agent-logd-otlp.socket; do
    install_file 0644 "$HERE/systemd/$unit" "$UNIT_DIR/$unit"
done

note "enabling sockets"
run_system systemctl daemon-reload
run_system systemctl enable --now agent-logd-unix.socket agent-logd-vsock.socket
if $OTLP; then
    run_system systemctl enable --now agent-logd-otlp.socket
else
    run_system systemctl disable --now agent-logd-otlp.socket
fi
# Pick up new code (and a changed socket set) if it is already running.
run_system systemctl try-restart agent-logd.service

note "done"
echo "Next: sudo $HERE/install-env.sh --mode host   (the host's own shipper)"
