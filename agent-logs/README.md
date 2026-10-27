# agent-logs

Log transport, storage, and queries for coding-agent sessions. The rationale
is in the [design overview](../docs/design/overview.md#key-design-decisions);
the exact behavior is specified in
[implementation.md](../docs/design/implementation.md) (hook collector, log
shipper, agent-logd, OpenTelemetry, envelope schema, correlation, and
`agent-log`).

Every Claude Code session, on the host or in a VM, produces records of
prompts, tool calls, process executions, network decisions and transcripts.
A root-owned shipper takes them off the agent's machine as they are produced,
and they land in one store on the host that the `agent` user cannot read.
`agent-log` rebuilds per-session timelines from that store.

| Program | Runs on | As | Installed to |
|---|---|---|---|
| `agent-log-shipper` | every agent environment | root | `/usr/local/lib/agent-logs/` |
| `agent-logd` | host | `agent-logd` | `/usr/local/lib/agent-logs/` |
| `agent-log` | host | the administrator (group `agent-audit`) | `/usr/local/lib/agent-logs/`, linked from `/usr/local/bin/` |

All three are single-file Python programs (standard library only, Python ≥ 3.12)
started with `python3 -I`.

## Data flow

```
 claude-audit-hook ──hook.sock (frame, waits for "ok")──┐
 journald (proxy decisions, nft drops, suppression,     │   agent-log-shipper (root)
           pipeline errors) ── journalctl -o json ──────┤   collector → spool (fsync, then "ok")
 /var/log/audit/audit.log ── tail + group events ───────┤   readers, one thread + cursor each
 ~agent/.claude/projects/**/*.jsonl ── 2 s poll ────────┘   sender: NDJSON batches, wait for ack
                                                                     │
          VM:   AF_VSOCK → host CID 2 port 700, source port 600–1023 │
          host: /run/agent-logd/ingest.sock (root only)              ▼
                                         agent-logd (agent-logd) → /var/log/agent-audit/<env>/<date>.jsonl
 Claude Code OTLP/HTTP JSON → :4318 (optional) ──────────┘
```

### agent-log-shipper

* **Hook collector.** Listens on `/run/agent-log-shipper/hook.sock` (mode 0666).
  A hook sends one frame: a 4-byte big-endian length, then UTF-8 JSON
  (at most 1 MiB): the Claude Code hook event plus a top-level `audit` object.
  While the hook waits, the collector reads `SO_PEERCRED` and `/proc/<pid>/`
  and builds `observed` (pid, uid, gid, exe, cmdline, auid, ses, cgroup,
  ancestry, claude_pid, claude_exe, run_id, loader_env). It appends
  `{ts, boot_id, observed, event}` to the spool, calls `fsync`, and only then
  replies `ok`. Any failure (bad frame, spool full, disk error) closes the
  connection without `ok`, so `PreToolUse` blocks. One writer thread appends
  everything, with one `fsync` per burst of concurrent hooks.
  `claude_pid` is the nearest ancestor whose exe basename is not in `SHELLS`
  (`sh`, `dash`, `bash`, `zsh`; a constant at the top of the program).
* **Spool.** `/var/lib/agent-log-shipper/spool/hook-<seq>.jsonl`, 64 MiB
  segments, 1 GiB cap. `seq` lives in `state.json` and never resets, so
  `source_id = <seq>:<offset>` is unique for the life of the environment.
  The sender deletes a segment once all of it is acked. In local mode the
  oldest segment is deleted above 90% of the cap and a `meta spool-pruned`
  record is written into the spool.
* **journald:** `journalctl --all -o json --follow --after-cursor=…` with
  OR-ed match groups for the proxy (`_SYSTEMD_UNIT=agent-egress-proxy.service`
  and `_UID` of `agent-egress`), `_TRANSPORT=kernel` (the `agent-*-drop`
  prefix is checked after reading), journald's "Suppressed N messages"
  (`MESSAGE_ID=a596d6fe…`), and the shipper's and agent-logd's own logs.
* **auditd:** tails `audit.log` by inode and offset, finishing rotated files
  first. Lines are grouped by `msg=audit(<time>:<serial>)`; a group is done at
  `EOE`, after 2 s idle, or at the end of a rotated file. Keeps keys
  `agent-exec`, `agent-socket`, `agent-secret-read`, `agent-policy` and every
  `NETFILTER_CFG`/`CONFIG_CHANGE`. Hex-encoded fields and split arguments
  (`a1[0]`, `a1[1]`) are decoded; arguments are capped at 16 KiB each and
  512 KiB in total with original length and SHA-256 recorded.
  `source_id = <boot_id>:<time>:<serial>`.
* **Transcripts:** every 2 s, `os.walk(followlinks=False)` over
  `~agent/.claude/projects` plus every `transcript_path` / `agent_transcript_path`
  seen in hook records. Files are opened `O_NOFOLLOW|O_NONBLOCK` and must be
  regular files owned by the agent; only complete lines are shipped, lines
  over 1 MiB become a `transcript-oversize` stub (length + SHA-256), and a
  shrink or inode change produces `meta transcript-rewritten`. Transcript
  records are *claims* (`data.claim = true`).
* **Sender:** round-robin over the sources, batches of ≤ 500 records / 4 MiB,
  `{"batch": n}` → `{"ack": n}`, exponential backoff up to 60 s. Cursors are
  written to `state.json` (0600) only after the ack: delivery is
  at-least-once and `agent-log` removes duplicates.
* **audit-degraded** (see below).

### agent-logd

* Sockets come from systemd (`LISTEN_FDS`, told apart by
  `FileDescriptorName=vsock|unix|otlp`):
  * `agent-logd-vsock.socket` — `vsock::700`. A peer is accepted only if its
    CID is in `envs.conf` and its source port is ≤ 1023; CID 1, CID 2 and
    unknown CIDs are rejected. The environment name comes from `envs.conf`.
  * `agent-logd-unix.socket` — `/run/agent-logd/ingest.sock`, 0600 root;
    `SO_PEERCRED` uid must be 0. Environment `host`.
  * `agent-logd-otlp.socket` (optional) — `127.0.0.1:4318` and
    `192.168.123.1:4318`, OTLP/HTTP JSON `POST /v1/logs` and `/v1/metrics`.
* The stored `env` and `recv_ts` are always agent-logd's own; a VM can only
  write records labelled as itself.
* Lines over 2 MiB become `meta oversize` (source, source_id, length,
  SHA-256); unparseable lines become `meta invalid-record`. Both are acked.
* 2 GiB per environment per day; then one `meta quota-exceeded` record and
  the rest are dropped (still acked).
* `envs.conf` is re-read when it changes (and on `SIGHUP`). A malformed file
  rejects every VM until fixed.

## Install

Run from the administrator's account with `sudo`, from a checkout of this repository.

### Phase 1: local only (any environment, before agent-logd exists)

```bash
sudo agent-logs/install-env.sh --mode local
```

Runs only the hook collector and the audit-space check. Hook records stay in
`/var/lib/agent-log-shipper/spool/`; auditd keeps its own log. Re-run with
`--mode host` or `--mode vm` later; the spool is then shipped from the start.

### Host

```bash
sudo agent-logs/install-host.sh            # agent-logd, store, agent-log; add --otlp for OTel
sudo $EDITOR /etc/agent-tools/envs.conf    # list each VM: name cid=… ip=… mac=…
sudo agent-logs/install-env.sh --mode host # the host's own shipper (add --otel for OTel export)
```

`install-host.sh` creates user `agent-logd` and group `agent-audit`, adds
the account that ran `sudo` (`$SUDO_USER`) to `agent-audit` (`--reader USER`
to choose another; log in again afterwards),
creates `/var/log/agent-audit` (2750 `agent-logd:agent-audit`), loads
`vhost_vsock` now and at boot, installs `envs.conf` from
`envs.conf.example` if missing, and enables the vsock and unix sockets
(`--otlp` also enables the OTLP socket). Recommended: put
`/var/log/agent-audit` on its own filesystem.

### Each VM

1. Give the VM a pinned vsock CID (and the `agent-net` interface) in its
   libvirt XML — see [`agent-egress/libvirt/vm-interface.xml`](../agent-egress/libvirt/vm-interface.xml):
   `<vsock model='virtio'><cid auto='no' address='10'/></vsock>`.
2. List the VM in the host's `/etc/agent-tools/envs.conf` with that `cid=`.
3. Inside the VM: `sudo agent-logs/install-env.sh --mode vm` (add `--otel` to
   export OTel to the host's `192.168.123.1:4318`).

All installers are idempotent, accept `--dry-run`, and accept `--root DIR`
to stage files without touching the system (no root needed).

## Store layout

```
/var/log/agent-audit/                  2750 agent-logd:agent-audit
  host/2026-10-27.jsonl                0640, one envelope per line
  host/otel-2026-10-27.jsonl           OTel records (separate quota)
  agent-vm1/2026-10-27.jsonl
```

Dates are the UTC date of `recv_ts`. Every line is the common envelope ([schema](../docs/design/implementation.md#envelope-schema)):

```json
{"ts": "…", "recv_ts": "…", "env": "agent-vm1", "client_env": null,
 "boot_id": "…", "source": "hook|audit|egress|netfilter|transcript|otel|meta",
 "source_id": "…", "run_id": "…", "session_id": "…", "agent_id": null,
 "uid": 2000, "auid": 2000, "ses": 17, "pid": 41733, "event": "PreToolUse", "data": {…}}
```

| source | event | source_id | data |
|---|---|---|---|
| hook | hook_event_name | `<seq>:<offset>` | `{observed, event}` |
| audit | exec, socket, secret-read, policy, netfilter-cfg, config-change | `<boot_id>:<time>:<serial>` | pid, ppid, auid, ses, uid, exe, argv, cwd, success, key, paths, records |
| egress | connect | journal cursor | the proxy's JSON decision (`ts` = its start time) |
| netfilter | drop | journal cursor | prefix, parsed nft fields |
| transcript | transcript, transcript-oversize | `<path>:<inode>:<offset>` | path, claim, line |
| otel | e.g. api_request, tool_result, token.usage | content hash | attributes, body, resource |
| meta | spool-pruned, audit-degraded, audit-recovered, transcript-rewritten, journal-suppressed, pipeline-log, proxy-log, quota-exceeded, oversize, invalid-record, audit-cursor-lost | various | details |

For heavy analysis: `duckdb -c "select … from read_json_auto('/var/log/agent-audit/*/*.jsonl')"`.

## agent-log

```bash
agent-log sessions --since 2h                 # START ENV SESSION SES TOOLS EXECS DENY STATE CWD
agent-log timeline 4b1f --exec --net          # merged view; SESSION = session_id prefix or run ID
agent-log timeline 4b1f --all --json | jq .   # plus transcripts, OTel, meta
agent-log net --denied --since 1d             # build an allowlist from what was denied
agent-log net --env agent-vm1              # traffic from one environment (client_env)
agent-log exec 4b1f                           # process tree from auditd
agent-log tail --env agent-vm1             # follow live
agent-log verify                              # all sessions + store-wide checks; exit 1 on FAIL
agent-log verify 4b1f --json
```

Every command takes `--store DIR` (default `/var/log/agent-audit`), `--since`
(`30m`, `2h`, `1d`, `1w`, or an ISO date) and `--json`.

Correlation ([details](../docs/design/implementation.md#correlation)):

* **Session** = hook records with the same `(env, session_id)`. Its window runs
  from 2 s before the first hook record to 5 s after `SessionEnd`, or to 5
  minutes after the last hook record if it has not ended.
* **exec → session:** same `(env, boot_id, ses)` within the window. If several
  sessions share the `ses` and overlap, `ppid` is walked (exec records plus
  hook ancestry) to a session's `claude_pid`; unresolved execs are shown in
  every candidate as `ambiguous`.
* **network → session:** only records shipped by `host` (the proxy and
  nftables live there); `client_env` = session env within the window.
  `exact` with one candidate session, `probable` with several.

`verify` checks (FAIL = tamper/policy signal, WARN = incomplete or pipeline):

| check | level | condition |
|---|---|---|
| binary | FAIL | a hook's `claude_exe` is outside `/opt/claude-code/` |
| completeness | WARN | `PreToolUse` without `PostToolUse(Failure)` by `tool_use_id`; no `SessionEnd` |
| origin | FAIL | hook ancestry is not `claude-audit-hook (python3) ← sh/dash ← claude` (`HOOK_ANCESTRY_SHAPES`) |
| forged-hook / hook-parent | FAIL / WARN | auditd history of the hook's parent PID: genuine = one exec of `/bin/sh` with ppid = claude_pid; a prior `/usr/bin/bash` exec (Bash tool shell, argv with `shell-snapshots`) = `forged-hook-suspect`; no audit data = `unverifiable` (WARN, never a pass) |
| injection | FAIL / WARN | `observed.loader_env` not empty / unreadable |
| policy | FAIL / WARN | `agent-policy` audit events, or `NETFILTER_CFG` unregistering `agent_egress`/`agent_vmnet` objects, in the window (env and host). FAIL if a change's `auid`/`uid` is the agent's or its audit session is the agent's; otherwise WARN (administrator maintenance, e.g. a rules reload). Audit rule removals warn. |
| unhooked-claude | FAIL | an exec of something named `claude` outside `/opt/claude-code/` |
| pipeline | WARN | meta records reporting loss or rewrite (quota, suppression, rewritten transcripts, spool pruning, audit-degraded, oversize, …) or pipeline errors |

## The audit-degraded contract

Every 60 s the shipper compares free space on the filesystem holding
`/var/log/audit` with `admin_space_left` from `/etc/audit/auditd.conf`
(megabytes, or `N%` of the filesystem; default 50). While below it — or while
either cannot be read (fail closed) — the file
**`/run/agent-log-shipper/audit-degraded`** exists (JSON with the reason) and
`agent-run` refuses to start sessions. Each transition writes a
`meta audit-degraded` or `meta audit-recovered` record. The file is removed as
soon as space recovers. `/run/agent-log-shipper` is preserved across shipper
restarts.

## Interfaces with the other components

* **Hook → collector:** frame and `ok` as above (`agent-audit/claude-audit-hook`).
* **Proxy → journald:** one JSON object per `MESSAGE` from
  `agent-egress-proxy.service` running as `agent-egress`; plain-text lines
  from that unit are kept as `meta proxy-log`. No reason values are assumed.
* **nftables → kernel log:** prefixes `agent-egress-drop ` (host; `client_env`
  `host`), `agent-vmnet-drop ` and `agent-vmnet-fwd-drop ` (`client_env` from
  `SRC=` via `envs.conf`).
* **Shipper → agent-logd:** NDJSON envelopes, each batch ending
  `{"batch": n}`, answered `{"ack": n}` after `fsync`.

## Implementation notes

Behavior not obvious from the overview (local mode, first-start positions,
hook `ts`, non-empty `loader_env`, boot IDs for pre-boot audit lines, the
separate OTel files and quota, dropped unknown envelope keys) is specified in
[implementation.md](../docs/design/implementation.md#log-shipper).

## Known gaps

* PID reuse between `SO_PEERCRED` and reading `/proc` (accepted; see [hook collector](../docs/design/implementation.md#hook-collector)).
* The ancestry shape alone is forgeable (`exec /bin/sh -c hook` from a Bash
  tool call); `verify` relies on auditd to detect that and says
  `unverifiable` without it.
* Transcripts and OTel records are claims: the agent can edit transcripts
  before they are read, and anyone can post to the OTLP port.
* If the shipper is down for an entire boot, audit lines from that boot are
  attributed to the previous boot ID.
* A process whose parent never exec'd breaks the `ppid` walk; with overlapping
  sessions in one `ses` such execs are labelled `ambiguous`.
* Egress attribution between concurrent sessions of one environment is only
  `probable` (exact attribution is future work; see [rollout](../docs/design/overview.md#rollout)).
* `agent-log` reads the selected days into memory; use `--since` or DuckDB for
  large stores. No retention or rotation of the store yet ([open question 2](../docs/design/overview.md#open-questions)).
* Not exercised by the tests: real systemd socket activation and unit
  sandboxing, real auditd and journald.

## Tests

From the repository root, no root needed:

```bash
python3 -m unittest discover -s agent-logs/tests            # add -v for names
AGENT_LOGS_TEST_TMP=/some/dir python3 -m unittest discover -s agent-logs/tests
```

(`-t .` does not work: the directory name `agent-logs` is not importable.)
Temporary files go under `$AGENT_LOGS_TEST_TMP` if set; Unix sockets always
use a short directory under the system temp dir. `AGENT_LOGS_TEST_VERBOSE=1`
shows the programs' own log lines.

| File | Covers |
|---|---|
| `test_collector.py` | `/proc` observation (fixture `/proc` and the live test process), spool segments/seq/torn tail/cap/local pruning, no `ok` before `fsync`, no `ok` on fsync failure, cap or bad frames, concurrency |
| `test_shipper_audit.py` | grouping (EOE, interleave, idle, rotated EOF), hex/enriched/split args, keys, truncation, `source_id` with boot ID, rotation following and resume |
| `test_shipper_sources.py` | safe transcript reads (symlink, FIFO, wrong owner, symlinked dir, oversize line, shrink/inode change, hook paths), journald classification and resume from cursor, spool reader, sender acks and cursor commit, audit-degraded, `envs.conf` |
| `test_logd.py` | vsock/unix peer checks, socket activation parsing, store layout and modes, quota, framing/acks/oversize/invalid, OTLP flattening and HTTP, vsock end to end over `vsock_loopback` (skipped without `AF_VSOCK`) |
| `test_agent_log.py` | dedup, exec/net correlation, `verify` (clean, tampered, forged hook, unverifiable), every CLI command |
| `test_e2e.py` | hook client → shipper → agent-logd (unix socket, test mode) → store → `agent-log`, including an agent-logd outage and a shipper restart |
| `test_install.py` | both installers with `--root` (modes, idempotency, dry run, errors), unit files, sysusers/tmpfiles, OTel template |
