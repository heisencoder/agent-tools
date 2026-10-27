#!/bin/bash
# install-host.sh — Install agent egress control on the host.
#
# Installs (docs/design/implementation.md):
#   - the agent-egress system user (sysusers.d)
#   - agent-egress-proxy → /usr/local/lib/agent-egress/
#   - allowlist profiles → /etc/agent-egress/profiles/, with anthropic and
#     github (plus any --enable'd ones) enabled by symlink in
#     /etc/agent-egress/allowlist.d/
#   - /etc/agent-tools/envs.conf from envs.conf.example, if missing
#   - nftables tables (agent_egress, agent_vmnet) and agent-egress-nft.service
#   - agent-egress-proxy.socket / .service (127.0.0.1:3128, 192.168.123.1:3128)
#   - the isolated libvirt network agent-net, with static DHCP leases from
#     envs.conf, autostarted
#   - Claude Code managed settings 40-agent-egress.json (proxy 127.0.0.1)
#
# Safe to re-run: files are replaced only when they differ, and running
# services are reloaded rather than restarted where possible.
#
# Usage:
#   sudo ./install-host.sh [OPTIONS]
#
# Examples:
#   sudo ./install-host.sh
#   sudo ./install-host.sh --enable npm --enable pypi --mask-snapd
#   ./install-host.sh --root "$(mktemp -d)" --agent-uid 2000   # staging, no root
#   ./install-host.sh --dry-run                                # show actions only

set -euo pipefail
umask 022

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# -----------------------------------------------------------------
# Defaults
# -----------------------------------------------------------------
ROOT=""
DRY_RUN=false
AGENT_USER="agent"
AGENT_UID=""
DEV_PORTS="8000-8999"
ENABLE=(anthropic github)
MASK_SNAPD=false
LIBVIRT=true
PROXY_ADDR="127.0.0.1"
LIBVIRT_URI="qemu:///system"

# -----------------------------------------------------------------
# Usage
# -----------------------------------------------------------------
usage() {
    cat <<'EOF'
Usage: install-host.sh [OPTIONS]

Install the agent egress proxy, nftables rules, isolated libvirt network, and
Claude Code proxy settings on the host.  Must be run as root, except with
--root or --dry-run.

Options:
  --root <dir>        Install under <dir> instead of /, and skip every
                      systemctl, systemd-sysusers, nft, and virsh call
                      (for packaging and tests; no root needed)
  --dry-run           Print what would be done; change nothing
  --agent-user <name> Agent user whose traffic is restricted (default: agent)
  --agent-uid <uid>   Numeric UID to use instead of looking up --agent-user
  --dev-ports <range> Loopback TCP ports the host agent may use for local
                      servers (default: 8000-8999)
  --enable <profile>  Also enable allowlist profile <profile> (repeatable),
                      e.g. npm, pypi, ubuntu.  anthropic and github are
                      always enabled.
  --mask-snapd        Mask snapd.socket and snapd.service (otherwise asked
                      interactively when stdin is a terminal)
  --no-libvirt        Do not define the agent-net libvirt network
  --help              Show this help message
EOF
}

die() { echo "install-host.sh: ERROR: $*" >&2; exit 1; }
note() { echo "install-host.sh: $*"; }

# -----------------------------------------------------------------
# Argument parsing
# -----------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --root)       [ $# -ge 2 ] || die "--root needs a directory"; ROOT="$2"; shift 2 ;;
        --dry-run)    DRY_RUN=true; shift ;;
        --agent-user) [ $# -ge 2 ] || die "--agent-user needs a name"; AGENT_USER="$2"; shift 2 ;;
        --agent-uid)  [ $# -ge 2 ] || die "--agent-uid needs a number"; AGENT_UID="$2"; shift 2 ;;
        --dev-ports)  [ $# -ge 2 ] || die "--dev-ports needs a range"; DEV_PORTS="$2"; shift 2 ;;
        --enable)     [ $# -ge 2 ] || die "--enable needs a profile"; ENABLE+=("$2"); shift 2 ;;
        --mask-snapd) MASK_SNAPD=true; shift ;;
        --no-libvirt) LIBVIRT=false; shift ;;
        --help|-h)    usage; exit 0 ;;
        *)            usage >&2; die "unknown option: $1" ;;
    esac
done

if [ -n "$ROOT" ]; then
    [ -d "$ROOT" ] || die "--root $ROOT is not a directory"
    ROOT="$(cd "$ROOT" && pwd)"
    [ "$ROOT" != "/" ] || ROOT=""
fi
# LIVE: we are changing the running system (not staging, not dry run).
LIVE=true
if [ -n "$ROOT" ] || $DRY_RUN; then LIVE=false; fi
if $LIVE && [ "$(id -u)" -ne 0 ]; then
    die "must be run as root (or use --root DIR or --dry-run)"
fi

if [ -z "$AGENT_UID" ]; then
    AGENT_UID="$(id -u "$AGENT_USER" 2>/dev/null)" ||
        die "no user '$AGENT_USER'; create it or pass --agent-uid"
fi
[[ "$AGENT_UID" =~ ^[0-9]+$ ]] || die "--agent-uid must be numeric"
[ "$AGENT_UID" -ne 0 ] || die "refusing to restrict uid 0"
[[ "$DEV_PORTS" =~ ^[0-9]{1,5}(-[0-9]{1,5})?$ ]] || die "--dev-ports must look like 8000-8999"
for p in "${ENABLE[@]}"; do
    [ -f "$SCRIPT_DIR/allowlist.d/$p.list" ] || die "no allowlist profile '$p'"
done

if $LIVE; then
    for cmd in nft python3 systemctl systemd-sysusers; do
        command -v "$cmd" >/dev/null || die "$cmd not found"
    done
    python3 -c 'import sys; sys.exit(sys.version_info < (3, 12))' ||
        die "python3 >= 3.12 required"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# -----------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------
OWNER_ARGS=()
if [ "$(id -u)" -eq 0 ]; then OWNER_ARGS=(-o root -g root); fi

# run CMD...: a system command; only printed when staging or dry-running.
run() {
    if $LIVE; then "$@"; else echo "  skip       $*"; fi
}

# install_file SRC DEST MODE: install SRC as $ROOT/DEST.  Sets CHANGED=true
# if the destination's content differed.
CHANGED=false
install_file() {
    local src="$1" dest="$2" mode="$3"
    if [ -f "$ROOT$dest" ] && [ ! -L "$ROOT$dest" ] && cmp -s "$src" "$ROOT$dest"; then
        CHANGED=false
    else
        CHANGED=true
    fi
    if $DRY_RUN; then
        if $CHANGED; then echo "  would install $dest"; fi
        return 0
    fi
    install -D -m "$mode" "${OWNER_ARGS[@]}" "$src" "$ROOT$dest"
    if $CHANGED; then echo "  installed  $dest"; else echo "  unchanged  $dest"; fi
}

# make_dir DIR MODE
make_dir() {
    if $DRY_RUN; then
        [ -d "$ROOT$1" ] || echo "  would create $1/"
        return 0
    fi
    install -d -m "$2" "${OWNER_ARGS[@]}" "$ROOT$1"
}

# render SRC KEY=VALUE...: print SRC with each @KEY@ replaced by VALUE, and
# fail if any @PLACEHOLDER@ is left.  Values are validated by the caller and
# never contain '|', '&', '\', or newlines.
render() {
    local src="$1" kv out
    shift
    local args=()
    for kv in "$@"; do args+=(-e "s|@${kv%%=*}@|${kv#*=}|g"); done
    out="$(sed "${args[@]}" "$src")"
    if grep -qE '@[A-Z_]+@' <<<"$out"; then
        die "unsubstituted placeholder in $src: $(grep -oE '@[A-Z_]+@' <<<"$out" | head -1)"
    fi
    printf '%s\n' "$out"
}

# -----------------------------------------------------------------
# envs.conf: the registry of VM environments
# -----------------------------------------------------------------
ENVS_CONF="/etc/agent-tools/envs.conf"
echo "== envs.conf"
make_dir /etc/agent-tools 0755
if [ -e "$ROOT$ENVS_CONF" ]; then
    echo "  keeping    $ENVS_CONF"
    ENVS_SRC="$ROOT$ENVS_CONF"
else
    install_file "$REPO_DIR/envs.conf.example" "$ENVS_CONF" 0644
    ENVS_SRC="$REPO_DIR/envs.conf.example"
fi

# Parse envs.conf (same format as agent-egress-proxy reads): fill ENV_LINES
# with "name mac ip cid" for each environment that has mac= and ip=.
ENV_LINES=()
while read -r -a fields; do
    [ "${#fields[@]}" -gt 0 ] || continue
    name="${fields[0]}"
    [[ "$name" =~ ^[a-z0-9][a-z0-9-]*$ ]] || die "envs.conf: bad name '$name'"
    mac="" ip="" cid=""
    for field in "${fields[@]:1}"; do
        case "$field" in
            mac=*) mac="${field#mac=}" ;;
            ip=*)  ip="${field#ip=}" ;;
            cid=*) cid="${field#cid=}" ;;
        esac
    done
    if [ -z "$mac" ] || [ -z "$ip" ]; then
        note "envs.conf: $name has no mac= or ip=; no DHCP lease"
        continue
    fi
    [[ "$mac" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]] || die "envs.conf: $name: bad mac '$mac'"
    if ! [[ "$ip" =~ ^192\.168\.123\.([0-9]{1,3})$ ]] ||
        [ "${BASH_REMATCH[1]}" -lt 2 ] || [ "${BASH_REMATCH[1]}" -gt 254 ]; then
        die "envs.conf: $name: ip '$ip' not in 192.168.123.2-254"
    fi
    [[ "$cid" =~ ^[0-9]*$ ]] || die "envs.conf: $name: bad cid '$cid'"
    ENV_LINES+=("$name ${mac,,} $ip ${cid:-}")
done < <(sed 's/#.*//' "$ENVS_SRC")

# -----------------------------------------------------------------
# System user, proxy, allowlist
# -----------------------------------------------------------------
echo "== proxy"
install_file "$SCRIPT_DIR/sysusers.d/agent-egress.conf" /etc/sysusers.d/agent-egress.conf 0644
run systemd-sysusers /etc/sysusers.d/agent-egress.conf
install_file "$SCRIPT_DIR/agent-egress-proxy" /usr/local/lib/agent-egress/agent-egress-proxy 0755
PROXY_CHANGED=$CHANGED

echo "== allowlist"
make_dir /etc/agent-egress 0755
make_dir /etc/agent-egress/allowlist.d 0755
for f in "$SCRIPT_DIR"/allowlist.d/*.list; do
    install_file "$f" "/etc/agent-egress/profiles/$(basename "$f")" 0644
done
for p in "${ENABLE[@]}"; do
    link="/etc/agent-egress/allowlist.d/$p.list"
    target="../profiles/$p.list"
    if [ -L "$ROOT$link" ] && [ "$(readlink "$ROOT$link")" = "$target" ]; then
        echo "  enabled    $p"
    elif [ -e "$ROOT$link" ] || [ -L "$ROOT$link" ]; then
        note "leaving $link alone (not a link to $target)"
    elif $DRY_RUN; then
        echo "  would enable $p"
    else
        ln -s "$target" "$ROOT$link"
        echo "  enabled    $p (new)"
    fi
done

# -----------------------------------------------------------------
# nftables
# -----------------------------------------------------------------
echo "== nftables"
render "$SCRIPT_DIR/nftables/agent-host.nft" AGENT_UID="$AGENT_UID" DEV_PORTS="$DEV_PORTS" \
    > "$TMP/agent-host.nft"
cp "$SCRIPT_DIR/nftables/agent-vmnet.nft" "$TMP/agent-vmnet.nft"
for f in agent-host.nft agent-vmnet.nft; do
    run nft -c -f "$TMP/$f"     # syntax check before it can break boot
    install_file "$TMP/$f" "/etc/agent-egress/$f" 0644
done

# -----------------------------------------------------------------
# systemd units
# -----------------------------------------------------------------
echo "== systemd"
install_file "$SCRIPT_DIR/systemd/agent-egress-nft.service" /etc/systemd/system/agent-egress-nft.service 0644
install_file "$SCRIPT_DIR/systemd/agent-egress-proxy.service" /etc/systemd/system/agent-egress-proxy.service 0644
if $CHANGED; then PROXY_CHANGED=true; fi
install_file "$SCRIPT_DIR/systemd/agent-egress-proxy.socket" /etc/systemd/system/agent-egress-proxy.socket 0644
SOCKET_CHANGED=$CHANGED
run systemctl daemon-reload
run systemctl enable agent-egress-nft.service agent-egress-proxy.socket
run systemctl reload-or-restart agent-egress-nft.service
if $SOCKET_CHANGED; then
    run systemctl stop agent-egress-proxy.service
    run systemctl restart agent-egress-proxy.socket
else
    run systemctl start agent-egress-proxy.socket
fi
if $PROXY_CHANGED; then
    # Restarting drops open tunnels; the socket keeps the port meanwhile.
    run systemctl try-restart agent-egress-proxy.service
else
    run systemctl try-reload-or-restart agent-egress-proxy.service
fi

# -----------------------------------------------------------------
# Claude Code managed settings
# -----------------------------------------------------------------
echo "== managed settings"
make_dir /etc/claude-code 0755
make_dir /etc/claude-code/managed-settings.d 0755
render "$SCRIPT_DIR/managed-settings.d/40-agent-egress.json.in" PROXY="$PROXY_ADDR" \
    > "$TMP/40-agent-egress.json"
python3 -m json.tool "$TMP/40-agent-egress.json" >/dev/null || die "40-agent-egress.json is not valid JSON"
install_file "$TMP/40-agent-egress.json" /etc/claude-code/managed-settings.d/40-agent-egress.json 0644

# -----------------------------------------------------------------
# libvirt: isolated agent-net network
# -----------------------------------------------------------------
if $LIBVIRT; then
    echo "== libvirt"
    {
        while IFS= read -r line; do
            if [[ "$line" == *@DHCP_HOSTS@* ]]; then
                indent="${line%%@DHCP_HOSTS@*}"
                for e in "${ENV_LINES[@]}"; do
                    read -r name mac ip _ <<<"$e"
                    echo "$indent<host mac='$mac' name='$name' ip='$ip'/>"
                done
            else
                printf '%s\n' "$line"
            fi
        done < "$SCRIPT_DIR/libvirt/agent-net.xml"
    } > "$TMP/agent-net.xml"
    make_dir /etc/agent-egress/libvirt 0755
    install_file "$TMP/agent-net.xml" /etc/agent-egress/libvirt/agent-net.xml 0644
    NET_CHANGED=$CHANGED
    for e in "${ENV_LINES[@]}"; do
        read -r name mac ip cid <<<"$e"
        if [ -z "$cid" ]; then
            note "envs.conf: $name has no cid=; skipping its interface snippet"
            continue
        fi
        render "$SCRIPT_DIR/libvirt/vm-interface.xml" MAC="$mac" IP="$ip" CID="$cid" \
            > "$TMP/$name-interface.xml"
        install_file "$TMP/$name-interface.xml" "/etc/agent-egress/libvirt/$name-interface.xml" 0644
    done

    if $LIVE && ! command -v virsh >/dev/null; then
        note "virsh not found; skipping network definition (re-run after installing libvirt)"
    elif $LIVE; then
        virsh -c "$LIBVIRT_URI" net-define /etc/agent-egress/libvirt/agent-net.xml
        virsh -c "$LIBVIRT_URI" net-autostart agent-net
        if virsh -c "$LIBVIRT_URI" net-info agent-net | grep -Eq '^Active:[[:space:]]+yes'; then
            if $NET_CHANGED; then
                note "agent-net is running with the old definition. To apply it:"
                note "  virsh net-destroy agent-net && virsh net-start agent-net"
                note "  (running VMs then need their agent-net interface re-attached or a reboot)"
            fi
        else
            virsh -c "$LIBVIRT_URI" net-start agent-net
        fi
    else
        run virsh -c "$LIBVIRT_URI" net-define /etc/agent-egress/libvirt/agent-net.xml
        run virsh -c "$LIBVIRT_URI" net-autostart agent-net
        run virsh -c "$LIBVIRT_URI" net-start agent-net
    fi
fi

# -----------------------------------------------------------------
# snapd (implementation.md, "agent-run"): its sockets sit directly in /run
# and cannot be hidden from agent-run sessions, and snapd queries the store
# as root.
# -----------------------------------------------------------------
echo "== snapd"
if $MASK_SNAPD; then
    run systemctl mask --now snapd.socket snapd.service
elif $LIVE && [ "$(systemctl is-enabled snapd.socket 2>/dev/null || true)" != "masked" ] &&
        systemctl cat snapd.socket >/dev/null 2>&1; then
    if [ -t 0 ]; then
        read -r -p "Mask snapd (only if you do not use snaps on this host)? [y/N] " answer || answer=""
        if [[ "$answer" =~ ^[Yy] ]]; then
            systemctl mask --now snapd.socket snapd.service
        fi
    else
        note "snapd is not masked; consider re-running with --mask-snapd if snaps are unused"
    fi
else
    echo "  nothing to do"
fi

# -----------------------------------------------------------------
# Checks
# -----------------------------------------------------------------
if $LIVE; then
    echo "== checks"
    nft list table inet agent_egress >/dev/null || die "nft table inet agent_egress not loaded"
    nft list table inet agent_vmnet >/dev/null || die "nft table inet agent_vmnet not loaded"
    systemctl is-active --quiet agent-egress-proxy.socket || die "agent-egress-proxy.socket not active"
    echo "  ok         nft tables loaded, proxy socket listening"
    if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
        note "ufw is active; allow VMs to reach the proxy with:"
        note "  ufw allow in on virbr-agent to 192.168.123.1 port 3128,4318 proto tcp"
    fi
    if systemctl is-active --quiet firewalld 2>/dev/null; then
        note "firewalld is active; allow tcp 3128 and 4318 on virbr-agent"
    fi
fi
echo "Done."
