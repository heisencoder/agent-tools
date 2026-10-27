# agent-audit

This directory holds the Claude Code policy, the hook, the session launcher,
and the kernel audit rules for running coding agents under
`--dangerously-skip-permissions`. The rationale is in the
[design overview](../docs/design/overview.md#key-design-decisions); formats
and exact behavior are in [implementation.md](../docs/design/implementation.md)
(managed settings, hook protocol, agent-run, kernel audit rules). In one environment (the host, or a VM) it sets up:

- **A Claude Code binary owned by root** at `/opt/claude-code/<version>/claude`,
  linked from `/usr/local/bin/claude`, with auto-update turned off. The
  `agent` user can no longer swap in a patched binary.
- **Managed settings** (`/etc/claude-code/managed-settings.d/50-agent-audit.json`).
  These are root-owned hooks for every tool call, prompt, subagent, and
  session event. User and project settings cannot remove or wrap them, and
  they pin to empty the environment variables that could inject code.
- **`claude-audit-hook`**, which hands each event to the root-owned
  collector in `agent-log-shipper` (from `agent-logs/`) and waits for an
  `ok` that the record was `fsync`ed. `PreToolUse` fails closed, so a tool
  call cannot run unless its record was stored.
- **`agent-run`**, which starts each session as a hardened transient system
  unit with its own audit session ID (`ses`) and cgroup.
- **auditd rules** for every `execve` by the agent, unusual socket
  families, reads of secrets, and writes to policy files.
- **Escape-hatch closing**: `cron.allow`/`at.allow` without the agent,
  lingering off, and Yama `ptrace_scope` ≥ 1.

| File | Installed as |
|---|---|
| `claude-audit-hook` | `/usr/local/lib/agent-audit/claude-audit-hook` (0755) |
| `agent-run` | `/usr/local/sbin/agent-run` (0755) |
| `managed-settings.d/50-agent-audit.json` | `/etc/claude-code/managed-settings.d/` (0644) |
| `pam.d/agent-run` | `/etc/pam.d/agent-run` (0644) |
| `audit.rules` (template, `@AGENT_UID@`) | `/etc/audit/rules.d/50-agent.rules` (0640) |
| `sysctl.d/60-agent-ptrace.conf` | `/etc/sysctl.d/` (0644) |
| `install-claude.sh` | run from the checkout |
| `install.sh` | run from the checkout |

## Install

Run these from the administrator's account with `sudo`, **once in each environment**: on the host
for host agents, and inside each VM for VM agents.

```bash
cd agent-tools

# 1. Install Claude Code as root. Use a binary you trust (see "Upgrading
#    Claude Code" below); --sha256 is checked when given.
sudo agent-audit/install-claude.sh --binary /path/to/claude [--sha256 HASH]

# 2. Install the policy, hook, launcher, audit rules, and sysctl. This
#    also installs auditd if it is missing.
sudo agent-audit/install.sh            # defaults: --agent-user agent --admin-user "$SUDO_USER"

# 3. Install the shipper with the hook collector right away (see agent-logs/README.md).
#    Use --mode local until agent-logd exists; later re-run with host or vm.
sudo agent-logs/install-env.sh --mode local

# 4. Check: the collector socket exists and agent-run's checks pass.
ls -l /run/agent-log-shipper/hook.sock
sudo agent-run --print --dir /home/agent

# 5. Check that the managed hooks really fire: start a session, ask it to
#    run `true`, exit, and look for the PreToolUse record in the spool.
sudo agent-run --dir /home/agent -- -p 'Run the shell command: true'
sudo tail -n 3 /var/lib/agent-log-shipper/spool/hook-*.jsonl | grep -c PreToolUse
```

**Do step 3 right after step 2.** The managed settings apply to *every*
Claude Code session on the machine, including the administrator's own sessions and
sessions not started by `agent-run`. Until the collector socket
`/run/agent-log-shipper/hook.sock` exists, every tool call in every session
is blocked with `PreToolUse:… hook error … blocking because onFailure is
"block"`. Other events fail open and are not logged. `agent-run` refuses to
start until the socket exists.

`install.sh` is idempotent. Re-run it after pulling changes. It:

- installs `auditd` with `apt-get` if it is missing, then `systemctl enable --now auditd`
- installs the files in the table above, owned by `root:root`. Files are
  replaced when their contents, mode, or owner differ.
- substitutes `id -u <agent-user>` for `@AGENT_UID@` in the audit rules,
  then runs `augenrules --load`. A `-w` watch whose parent directory does
  not exist (e.g. `/etc/libvirt/qemu/networks/` in a VM without libvirt) is
  installed commented out. The kernel rejects such a watch, and auditctl
  would then stop loading the rest. Re-run `install.sh` if that directory
  appears later.
- edits `/etc/audit/auditd.conf` in place and keeps the original once as
  `auditd.conf.agent-audit.bak`. It sets `admin_space_left_action`,
  `disk_full_action`, and `disk_error_action` to `SUSPEND`, and
  `max_log_file_action` to `ROTATE`. Then it sends auditd `SIGHUP`.
- writes `/etc/cron.allow` and `/etc/at.allow`. It keeps existing entries,
  adds `root` and the admin user, and removes the agent user. The admin user
  defaults to `$SUDO_USER` (the account that ran `sudo`); pass
  `--admin-user NAME` when that is unset or root.
- applies the ptrace sysctl now only if the live value is below 1. It never
  lowers 2 or 3.
- runs `loginctl disable-linger <agent-user>`.

Options: `--dry-run` prints what would change. `--root DIR` writes into a
staging tree and skips apt, systemctl, augenrules, sysctl, and loginctl. Both
work without root.

## Using `agent-run`

```bash
sudo agent-run [--env host|vm] [--dir PROJECT] [-- CLAUDE_ARGS...]

sudo agent-run --dir /home/agent/work/webapp
sudo agent-run --dir /home/agent/work/webapp -- --resume
sudo agent-run --print --dir /home/agent/work/webapp   # show the systemd-run command
```

- `--env` defaults to `vm` when `systemd-detect-virt --vm` succeeds, and to
  `host` otherwise.
- `--dir` defaults to the current directory. The `agent` user must be able
  to enter it.
- The session runs `/usr/local/bin/claude --dangerously-skip-permissions
  CLAUDE_ARGS…` as `agent` in the unit `agent-run-<RUN_ID>`. `RUN_ID` is
  `YYYYmmddTHHMMSS-<8 hex>` in UTC and is exported as `AGENT_RUN_ID`. When
  claude exits, systemd kills everything left in the unit.
- Unit properties: `PAMName=agent-run` (a new `ses` from `pam_loginuid`),
  `NoNewPrivileges=yes`, and `RestrictAddressFamilies=AF_UNIX AF_INET
  AF_INET6 AF_NETLINK`. The host also gets `InaccessiblePaths=` for the
  resolver, D-Bus, avahi, and cups socket directories.
- Network properties (`IPAddressDeny=any`, `IPAddressAllow=localhost`, plus
  `192.168.123.1` in VMs) are added only when
  `/etc/claude-code/managed-settings.d/40-agent-egress.json` exists. On the
  host they also require `nft list table inet agent_egress` to succeed.
  Without that file, agent-run prints `WARNING: egress control not
  installed` and launches anyway (phase 1).

**Pre-launch checks.** agent-run lists every failed check and exits 1
when any of these is missing:

- the managed settings
- the executable hook
- the collector socket
- `/usr/local/bin/claude` as a symlink directly to a root-owned
  `/opt/claude-code/<version>/claude`
- `ptrace_scope` ≥ 1
- no `audit-degraded` flag
- on the host with egress installed, the nft table

**The `audit-degraded` contract with agent-logs.** `agent-log-shipper`
creates the file `/run/agent-log-shipper/audit-degraded` when free space on
the `/var/log/audit` filesystem drops below auditd's `admin_space_left`. At
that point auditd may already be suspended. The shipper removes the file
when space recovers, and it emits `meta audit-degraded` records as usual.
`agent-run` refuses to start while the file exists. The content of the file
is not read.

`--print` runs every check, then prints the command instead of executing
it, so it works without root. `--root DIR` (test-only, accepted only with
`--print`) looks for every checked path and helper program (`nft`,
`systemd-detect-virt`) under `DIR`.

## Hook protocol (contract with agent-logs)

`claude-audit-hook [--socket PATH]`. The default socket is
`/run/agent-log-shipper/hook.sock`. `--socket` exists for tests only. The
managed settings never pass it, and the path is never read from the
environment.

1. Read the event JSON from stdin, up to 64 MiB. A larger event is an error.
2. Cut every string at any depth to 16 KiB of UTF-8, without splitting a
   character. Each cut is recorded as
   `audit.truncated["<JSON pointer>"] = {"length": <original UTF-8 bytes>, "sha256": "<hex>"}`,
   for example `/tool_input/content` or `/tool_response/stdout`.
3. If header plus body would still exceed 1 MiB, replace **both**
   `tool_input` and `tool_response` with `{"length", "sha256"}` stubs. The
   stub hashes the original value's compact JSON
   (`separators=(",", ":")`, `ensure_ascii=False`, UTF-8). The stub is also
   recorded at `/tool_input` and `/tool_response`, and entries for strings
   inside a stubbed value are dropped.
4. Add `"audit": {"truncated": {...}, "hook_ts": "<RFC 3339 UTC, ms>"}`.
   `truncated` is omitted when it is empty.
5. Send one frame: a 4-byte big-endian length, then the UTF-8 JSON. The
   header plus body is at most 1 MiB.
6. Wait for exactly `ok`. Any other reply, EOF, or the 5-second deadline
   means one line on stderr and exit 1.

The hook exits only with 0 or 1. It never writes to stdout: fd 1 is
pointed at `/dev/null` at start-up. Argument parsing is hand-written
because argparse exits with 2.

One 5-second deadline covers connect, send, and reply. Further edge cases
(long dict keys, last-resort stubbing, lone surrogates, an incoming `audit`
key) are specified in
[implementation.md](../docs/design/implementation.md#hook-protocol).

## Upgrading Claude Code

`DISABLE_AUTOUPDATER=1` keeps Claude Code from updating itself. Upgrades are
done by the administrator:

1. Get the new binary from a source you trust. The safest choice is
   Claude Code's native installer run **as the administrator**, or a release download
   whose SHA-256 you check against the published release manifest. Copying
   `~agent/.local/share/claude/versions/<v>` also works, but `agent` owned
   that file and could have modified it.
2. Install it, then check the link:
   ```bash
   sudo agent-audit/install-claude.sh --binary ~/.local/share/claude/versions/X.Y.Z --sha256 HASH
   ls -l /usr/local/bin/claude      # -> /opt/claude-code/X.Y.Z/claude
   ```
   The binary is copied into `/opt/claude-code` before it is run, and
   `--version` runs as `nobody`. So an untrusted binary never runs as root
   during install. Re-installing the same version is a no-op. The installer
   refuses the same version with different contents.
3. **Re-run the hook verification** (next section) against the new
   version. Hook spawning and settings precedence are not stable APIs.
4. New `agent-run` sessions use the new version, and running sessions keep
   the old one. To roll back, re-run the installer with the old binary.
   Delete old `/opt/claude-code/<version>/` directories once no session
   uses them.

## Verification results, Claude Code 2.1.312

Method: `claude -p … --model haiku --dangerously-skip-permissions --settings
FILE`, run from a temporary project directory. `FILE` carried the same hooks
block as `50-agent-audit.json`, with the command changed to `<repo hook>
--socket <temp socket>`. A small local test collector recorded `SO_PEERCRED`
and walked `/proc/<pid>` up the `PPid` chain. Managed settings need root, so
`--settings` stood in for them. A project-level `.claude/settings.json`
stood in for the agent-writable sources (user, project, local).

1. **Hooks under `--dangerously-skip-permissions`: yes.** `PreToolUse`
   fired with `permission_mode: "bypassPermissions"`. So did `SessionStart`,
   `UserPromptSubmit`, `PostToolUse`/`PostToolUseFailure`, `Stop`, and
   `SessionEnd`. **`"onFailure": "block"` works.** With no collector
   running, the hook exited 1, the `touch` never ran, and the model saw
   `PreToolUse:Bash hook error: [...]: failed; blocking because onFailure is
   "block"` followed by the hook's stderr line. Failing non-tool hooks
   (e.g. `SessionEnd`) were only reported, as designed.
2. **`env` set to `""` at higher precedence: overrides, as the empty
   string.** With `AGENT_TEST_VAR="from-project"` in project settings and
   `""` in `--settings`, hooks and Bash-tool children both saw
   `AGENT_TEST_VAR=` (set and empty). A `""` in settings also overrode the
   same variable in claude's own process environment. `LD_PRELOAD=""` and
   the others arrive set and empty, which the dynamic loader treats as
   unset. Variables only in project settings still pass through, so pins
   must be listed explicitly.
3. **Hook ancestry: claude runs `/bin/sh -c '<command>'`.** Observed chain,
   from the hook upwards:

   ```
   /usr/bin/python3.14   argv: /usr/bin/python3 -I <hook path>      (the hook; shebang exec)
   /usr/bin/dash         argv: /bin/sh -c <hook command string>     (spawned by claude)
   <claude exe>          argv: claude …                             (here ~/.local/share/claude/versions/2.1.312;
                                                                     /opt/claude-code/<v>/claude under agent-run)
   ```

   A process run by the **Bash tool** has a different shape. Claude runs
   `/usr/bin/bash` as `/bin/bash -c 'source ~/.claude/shell-snapshots/snapshot-bash-….sh … && eval '<cmd>' && pwd -P >| /tmp/claude-XXXX-cwd'`,
   and the command is a child of that bash. **But this does not
   authenticate a hook record.** A Bash tool command `exec /bin/sh -c
   '<hook>'` replaces the tool's bash. The forged hook then has *exactly*
   the real ancestry, python3 ← dash `/bin/sh -c …` ← claude. This was
   observed with a real claude. `agent-log verify` must therefore also use
   auditd. In the forged case, the `sh` PID was first `execve`d as
   `/usr/bin/bash` (the tool shell) and only then as `/bin/sh`. A genuine
   hook's `sh` PID has a single `execve` of `/bin/sh` with `ppid` = claude.
   The forging command is also visible in the enclosing Bash
   `PreToolUse` record.

**Additional finding: `CLAUDE_CODE_SHELL_PREFIX` bypassed every hook.**
Claude Code wraps hook commands, not only Bash tool commands, with
`CLAUDE_CODE_SHELL_PREFIX`. That variable could be set from
**project-level** settings, which the agent can write. A prefix script that
just `exit 0`s made every hook "succeed" without running: `PreToolUse`
passed and the collector received **zero records**. Pinning
`"CLAUDE_CODE_SHELL_PREFIX": ""` at higher precedence closed it: no prefix
runs, and all records arrived. `50-agent-audit.json` therefore pins it,
in addition to the loader variables. In the same run, `SHELL` and
`CLAUDE_CODE_SHELL` from project settings did *not* change how hooks are
spawned.

**Additional finding: `disableAllHooks`.** A project-level
`"disableAllHooks": true` switched off the `--settings` hooks. A
higher-precedence `"disableAllHooks": false` restored them. The managed
file therefore sets `"disableAllHooks": false` explicitly. Without root it
could not be tested whether a user-level `true` would also disable
*managed* hooks; the explicit `false` makes that question moot.

To repeat these checks after an upgrade, use the same recipe:

1. Write a settings file with the hooks block, pointing at
   `claude-audit-hook --socket /run/user/$UID/x/h.sock`.
2. Run a tiny collector that replies `ok` and dumps `/proc` ancestry.
3. Run `claude -p "run: touch marker" --model haiku
   --dangerously-skip-permissions --settings FILE`. Run it with the
   collector up and with it down, and with a hostile
   `.claude/settings.json` in the project. Use
   `--output-format stream-json --verbose` to see the hook outcomes.

## Known gaps

- **Not verified with real managed settings.** That needs root. In
  particular, `allowManagedHooksOnly` and the `""` env pins were verified
  only with `--settings` as the higher-precedence source. After installing,
  check once from the admin account that a hostile `~agent/.claude/settings.json` (e.g.
  `CLAUDE_CODE_SHELL_PREFIX`, extra hooks, `disableAllHooks`) changes
  nothing.
- **Hook origin is forgeable by ancestry alone.** See check 3 above. auditd
  exec records are required to tell a forged record from a real one.
- **Other environment variables may affect hook spawning** in future Claude
  Code versions, as `CLAUDE_CODE_SHELL_PREFIX` does today. Re-run the
  verification after every upgrade.
- **Managed settings affect the administrator too.** The administrator's own Claude Code sessions
  on the machine are logged, block when the collector is down, and do not
  auto-update.
- **Hook stderr reaches the model.** The block message includes the hook's
  one-line error, e.g. the socket path. It holds nothing secret.
- **`cron.allow`/`at.allow`** take effect only for cron/at implementations
  that honor them (Debian/Ubuntu `cron` and `at` do).

## Tests

Run from the repository root. No root is needed:

```bash
python3 -m unittest discover -s agent-audit/tests
```

The tests cover:

- **Hook:** truncation at depth (pointers, multibyte cuts, long keys, a
  1 MiB `Write`), the stub fallback, framing, and exit codes (ok, bad
  reply, EOF, no socket, timeout, bad JSON, over 64 MiB, bad argument). They
  also check that nothing reaches stdout.
- **agent-run:** `--print` output for host and VM, with and without the
  egress drop-in, and every refusal path.
- **Installers:** `install.sh` and `install-claude.sh` in `--root` staging
  mode, covering layout, modes, substitution, the `auditd.conf` edit,
  backup and idempotence, and the allow files.
- **Config:** JSON shape of the managed settings, PAM and sysctl contents,
  and an `audit.rules` grammar lint that also matches the rules against
  the "Kernel audit rules" block in `docs/design/implementation.md`.
- **Scripts:** `bash -n` on every script, plus shellcheck and jq when
  available.

Unix socket paths are limited to 107 bytes. If `$TMPDIR` is long, the
tests fall back to `/tmp` for their temporary directories.
