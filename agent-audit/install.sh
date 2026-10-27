#!/bin/bash
# install.sh — Install the agent-audit policy into one agent environment
# (the host, or a VM; run it once in each).
#
# Installs:
#   claude-audit-hook             -> /usr/local/lib/agent-audit/claude-audit-hook
#   agent-run                     -> /usr/local/sbin/agent-run
#   managed-settings.d/50-agent-audit.json
#                                 -> /etc/claude-code/managed-settings.d/
#   pam.d/agent-run               -> /etc/pam.d/agent-run
#   audit.rules (@AGENT_UID@ substituted)
#                                 -> /etc/audit/rules.d/50-agent.rules
#   sysctl.d/60-agent-ptrace.conf -> /etc/sysctl.d/
#   /etc/audit/auditd.conf        edited in place (backup kept once, as
#                                 auditd.conf.agent-audit.bak)
#   /etc/cron.allow, /etc/at.allow  root + the admin user, never the agent
# and, on a real install: `apt-get install auditd` if missing, loads the
# audit rules, applies the sysctl, reloads auditd, and turns off lingering
# for the agent user.  Re-running it is safe (idempotent).
#
# Install the root-owned Claude Code first (install-claude.sh) and the hook
# collector (agent-logs/install-env.sh) before using agent-run.
# See docs/design/implementation.md and agent-audit/README.md.
#
# Usage (from the administrator's account):
#   sudo ./install.sh [--agent-user agent] [--admin-user NAME]
#   ./install.sh --root /tmp/stage --agent-user "$(id -un)" --admin-user ADMIN  # staging tree
#   ./install.sh --dry-run --admin-user ADMIN                   # show actions
#
# Options:
#   --agent-user NAME  The agent's account; its numeric UID goes into the
#                      audit rules (default: agent)
#   --admin-user NAME  Account kept in cron.allow/at.allow (default: the
#                      account that ran sudo, i.e. $SUDO_USER; required when
#                      that is unset or root)
#   --root DIR         Write files under DIR instead of /; skip apt,
#                      systemctl, augenrules, sysctl and loginctl (no root
#                      needed)
#   --dry-run          Print what would be done; change nothing

set -euo pipefail

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
umask 022

SRC="$(cd "$(dirname "$0")" && pwd -P)"

# -----------------------------------------------------------------
# Defaults
# -----------------------------------------------------------------
AGENT_USER="agent"
ADMIN_USER="${SUDO_USER:-}"
ROOT=""
DRY_RUN=false

# auditd.conf settings we enforce (docs/design/implementation.md, "Kernel
# audit rules").  A full disk must not halt a workstation, so auditd
# suspends instead; agent-log-shipper detects that by watching free space
# and raises audit-degraded, and agent-run refuses new sessions.
AUDITD_SETTINGS=(
    "admin_space_left_action = SUSPEND"
    "disk_full_action = SUSPEND"
    "disk_error_action = SUSPEND"
    "max_log_file_action = ROTATE"
)

usage() {
    sed -n '2,/^$/{s/^# \{0,1\}//;p}' "$0"
}

die() {
    echo "install.sh: $*" >&2
    exit 1
}

# -----------------------------------------------------------------
# Parse arguments
# -----------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --agent-user)   [ $# -ge 2 ] || die "--agent-user needs a value"; AGENT_USER="$2"; shift 2 ;;
        --agent-user=*) AGENT_USER="${1#*=}"; shift ;;
        --admin-user)   [ $# -ge 2 ] || die "--admin-user needs a value"; ADMIN_USER="$2"; shift 2 ;;
        --admin-user=*) ADMIN_USER="${1#*=}"; shift ;;
        --root)         [ $# -ge 2 ] || die "--root needs a value"; ROOT="$2"; shift 2 ;;
        --root=*)       ROOT="${1#*=}"; shift ;;
        --dry-run)      DRY_RUN=true; shift ;;
        --help|-h)      usage; exit 0 ;;
        *)              die "unknown argument: $1 (see --help)" ;;
    esac
done

if [ -z "$ROOT" ] && ! $DRY_RUN && [ "$(id -u)" -ne 0 ]; then
    die "must be run as root (or with --root DIR / --dry-run)"
fi
if [ -n "$ROOT" ] && ! $DRY_RUN; then
    ROOT="$(mkdir -p "$ROOT" && cd "$ROOT" && pwd -P)"
fi

AGENT_UID="$(id -u "$AGENT_USER" 2>/dev/null)" || die "no such user: $AGENT_USER"
[ "$AGENT_UID" -ne 0 ] || die "--agent-user must not be root"
AGENT_HOME="$(getent passwd "$AGENT_USER" | cut -d: -f6)"
[ -n "$AGENT_HOME" ] || die "no home directory for $AGENT_USER"
if [ -z "$ADMIN_USER" ] || [ "$ADMIN_USER" = root ]; then
    die "no admin account: run via sudo from your admin account, or pass --admin-user NAME"
fi
[ "$AGENT_USER" != "$ADMIN_USER" ] || die "--agent-user and --admin-user must differ"

# A real install sets root ownership; a staging tree keeps the caller's.
OWNER=()
[ -z "$ROOT" ] && OWNER=(-o root -g root)

# -----------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------

# Run a system-changing command, unless staging or dry-running.
sys() {
    if $DRY_RUN; then
        echo "would run: $*"
    elif [ -n "$ROOT" ]; then
        echo "skipped (--root): $*"
    else
        echo "+ $*"
        "$@"
    fi
}

# put MODE SRC DEST: install a file under $ROOT if its contents or mode differ.
put() {
    local mode="$1" src="$2" dest="$ROOT$3"
    # Also require root ownership on a real install, so a file someone
    # else managed to create there is replaced, not trusted.
    if [ -f "$dest" ] && cmp -s "$src" "$dest" \
       && [ "$(stat -c %a "$dest")" = "${mode#0}" ] \
       && { [ -n "$ROOT" ] || [ "$(stat -c %u:%g "$dest")" = 0:0 ]; }; then
        echo "unchanged: $3"
        return
    fi
    if $DRY_RUN; then
        echo "would install: $3 (mode $mode)"
        return
    fi
    install -d -m 0755 "${OWNER[@]}" "$(dirname "$dest")"
    install -m "$mode" "${OWNER[@]}" "$src" "$dest"
    echo "installed: $3"
}

TMPDIR_INSTALL="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_INSTALL"' EXIT

# -----------------------------------------------------------------
# 1. auditd package
# -----------------------------------------------------------------
if [ -z "$ROOT" ] && ! dpkg-query -W -f='${Status}' auditd 2>/dev/null | grep -q 'ok installed'; then
    sys apt-get install -y auditd
fi

# -----------------------------------------------------------------
# 2. Hook, launcher, managed settings, PAM, sysctl
# -----------------------------------------------------------------
put 0755 "$SRC/claude-audit-hook" /usr/local/lib/agent-audit/claude-audit-hook
# agent-run hard-codes the account it launches as; rewrite it for --agent-user.
sed "s|^AGENT_USER=\"agent\" |AGENT_USER=\"$AGENT_USER\" |" "$SRC/agent-run" > "$TMPDIR_INSTALL/agent-run"
grep -q "^AGENT_USER=\"$AGENT_USER\" " "$TMPDIR_INSTALL/agent-run" || die "could not set AGENT_USER in agent-run"
put 0755 "$TMPDIR_INSTALL/agent-run" /usr/local/sbin/agent-run
put 0644 "$SRC/managed-settings.d/50-agent-audit.json" \
         /etc/claude-code/managed-settings.d/50-agent-audit.json
put 0644 "$SRC/pam.d/agent-run"   /etc/pam.d/agent-run
put 0644 "$SRC/sysctl.d/60-agent-ptrace.conf" /etc/sysctl.d/60-agent-ptrace.conf

# Apply the sysctl now only if the live value is too low; never lower a
# stricter setting (2 or 3) at runtime.
scope="$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo 0)"
if [ "$scope" -lt 1 ]; then
    sys sysctl -p /etc/sysctl.d/60-agent-ptrace.conf
fi

# -----------------------------------------------------------------
# 3. Audit rules.  A watch (-w) whose parent directory is missing on this
#    machine is rejected by the kernel and would stop auditctl from loading
#    the remaining rules, so such lines are installed commented out.
# -----------------------------------------------------------------
RULES="$TMPDIR_INSTALL/50-agent.rules"
while IFS= read -r line || [ -n "$line" ]; do
    line="${line//@AGENT_UID@/$AGENT_UID}"
    line="${line//@AGENT_HOME@/$AGENT_HOME}"
    if [[ "$line" =~ ^-w[[:space:]]+([^[:space:]]+) ]]; then
        path="${BASH_REMATCH[1]%/}"
        parent="$(dirname "$path")"
        if [ ! -d "$ROOT$parent" ]; then
            echo "note: $parent does not exist; disabling watch on $path" >&2
            line="# disabled by install.sh (missing $parent): $line"
        fi
    fi
    printf '%s\n' "$line"
done < "$SRC/audit.rules" > "$RULES"
put 0640 "$RULES" /etc/audit/rules.d/50-agent.rules

# -----------------------------------------------------------------
# 4. auditd.conf: edit in place, keep the original once as a backup.
# -----------------------------------------------------------------
CONF="$ROOT/etc/audit/auditd.conf"
if [ -f "$CONF" ]; then
    NEW_CONF="$TMPDIR_INSTALL/auditd.conf"
    cp -- "$CONF" "$NEW_CONF"
    for setting in "${AUDITD_SETTINGS[@]}"; do
        key="${setting%% *}"
        if grep -Eq "^[[:space:]]*${key}[[:space:]]*=" "$NEW_CONF"; then
            sed -Ei "s|^[[:space:]]*${key}[[:space:]]*=.*|$setting|" "$NEW_CONF"
        else
            printf '%s\n' "$setting" >> "$NEW_CONF"
        fi
    done
    if cmp -s "$CONF" "$NEW_CONF"; then
        echo "unchanged: /etc/audit/auditd.conf"
    elif $DRY_RUN; then
        echo "would edit: /etc/audit/auditd.conf:"
        diff -u "$CONF" "$NEW_CONF" || true
    else
        [ -e "$CONF.agent-audit.bak" ] || cp -p -- "$CONF" "$CONF.agent-audit.bak"
        # Overwrite in place to keep the file's owner and mode.
        cat -- "$NEW_CONF" > "$CONF"
        echo "edited: /etc/audit/auditd.conf (original in auditd.conf.agent-audit.bak)"
    fi
elif $DRY_RUN || [ -n "$ROOT" ]; then
    echo "note: /etc/audit/auditd.conf not present; skipping its edit" >&2
else
    die "/etc/audit/auditd.conf missing after installing auditd"
fi

# -----------------------------------------------------------------
# 5. cron.allow / at.allow: only listed users may schedule jobs, so the
#    agent cannot start work that runs outside its session.  Existing
#    entries are kept, except the agent user, which is removed.
# -----------------------------------------------------------------
for f in /etc/cron.allow /etc/at.allow; do
    NEW_ALLOW="$TMPDIR_INSTALL/$(basename "$f")"
    { [ -f "$ROOT$f" ] && grep -vxF -- "$AGENT_USER" "$ROOT$f"; true; } > "$NEW_ALLOW"
    for u in root "$ADMIN_USER"; do
        grep -qxF -- "$u" "$NEW_ALLOW" || printf '%s\n' "$u" >> "$NEW_ALLOW"
    done
    put 0644 "$NEW_ALLOW" "$f"
done

# -----------------------------------------------------------------
# 6. Activate: auditd running, rules loaded, config reloaded, no lingering.
# -----------------------------------------------------------------
sys systemctl enable --now auditd.service
sys augenrules --load
# auditd re-reads auditd.conf on SIGHUP (systemctl restart is refused).
sys systemctl kill --kill-whom=main --signal=HUP auditd.service
sys loginctl disable-linger "$AGENT_USER"

# -----------------------------------------------------------------
# 7. Sanity hints
# -----------------------------------------------------------------
if [[ "$(readlink "$ROOT/usr/local/bin/claude" 2>/dev/null || true)" != /opt/claude-code/* ]]; then
    echo "note: /usr/local/bin/claude is not a root-owned install yet; run install-claude.sh" >&2
fi
if $DRY_RUN; then
    echo "dry run: nothing was changed (agent uid $AGENT_UID)."
else
    echo "agent-audit installed (agent uid $AGENT_UID)."
fi
