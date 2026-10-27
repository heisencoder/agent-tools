# Background: concepts behind the agent containment design

Status: Implemented (initial version)

This is a tutorial for experienced software engineers who are not Linux
systems specialists. Each section explains one technology, the one or two
facts the design relies on, and where it is used in
[overview.md](overview.md). Mechanics and exact configuration are in
[implementation.md](implementation.md). A [glossary](#glossary) is at the
end.

## Users, UIDs, capabilities, and Yama

Linux checks permissions against a numeric **user ID (UID)**. A process
running as the agent's UID can modify only files that UID owns (or that are
group- or world-writable) and can signal only that UID's processes. Root
(UID 0) bypasses these checks.

Root's power is split into **capabilities**, for example
`CAP_NET_BIND_SERVICE` (bind ports below 1024), `CAP_SYS_PTRACE` (inspect
other users' processes), and `CAP_DAC_READ_SEARCH` (read any file). A
service can be limited to a subset.

**Yama** is a kernel security module. With `kernel.yama.ptrace_scope` ≥ 1, a
process without `CAP_SYS_PTRACE` may debug (ptrace) or patch the memory of
only its own descendants.

**Relied on:** every boundary in the design reduces to "is this file,
socket, rule, or binary controlled by someone other than the agent's UID?"
Yama stops a tool process from patching its *parent*, the running `claude`,
to switch off hooks. **Used in:**
[threat model](overview.md#threat-model),
[root-owned Claude Code](overview.md#root-owned-claude-code-pinned-by-managed-settings).

## Unix sockets, peer credentials, and daemons acting for callers

A **Unix-domain socket** has a filesystem path (e.g. `/run/foo.sock`);
connecting requires write permission on it, so file permissions decide who
can connect. The server can ask the kernel who the client is:
**`SO_PEERCRED`** returns the client's PID, UID, and GID, and the client
cannot lie about them. A root server can then read `/proc/<pid>/` to learn
the client's executable, command line, parent process, environment, and
audit session.

Many system daemons (the DNS resolver, D-Bus, avahi for mDNS, cups, snapd)
listen on world-connectable sockets and then act *as themselves*. Traffic
they generate on a caller's behalf is not attributed to the caller's UID, so
per-UID firewall rules never see it. **Abstract** Unix sockets have no path
and no permissions: any process in the same network namespace can reach
them.

**Relied on:** kernel-attested peer identity lets the hook collector record
who really sent a hook record; hiding daemon socket directories closes
"ask a daemon to do it" channels for host agents. **Used in:**
[hooks to a root collector](overview.md#hooks-to-a-root-collector-with-fail-closed-pretooluse),
[host agents and VM agents](overview.md#host-agents-and-vm-agents).

## systemd units, socket units, cgroups, and sandboxing

**systemd** is the init system and service manager. A **service unit** is a
managed process; `systemd-run` creates a transient unit on the fly. A
**socket unit** makes systemd own a listening socket from boot and hand it
to the service (socket activation), so the port stays held while the service
restarts.

Each unit gets a **cgroup**, a kernel-tracked group of processes that
children inherit. A cgroup created by the system manager (PID 1) is owned by
root and its processes cannot leave it. A user's own `systemd --user`
manager delegates a subtree to that user, whose processes *can* move around
in it.

Units accept kernel-enforced **sandboxing properties**, among them:

| Property | Effect |
|---|---|
| `IPAddressDeny=` / `IPAddressAllow=` | eBPF packet filter on the cgroup, independent of UID |
| `RestrictAddressFamilies=` | allow-list of address families for `socket(2)` (seccomp; native ABI only), e.g. no `AF_VSOCK` or `AF_PACKET` |
| `InaccessiblePaths=` | hide files or directories from the unit |
| `NoNewPrivileges=` | setuid binaries cannot raise privileges |
| `CapabilityBoundingSet=` | upper bound on capabilities |
| `ProtectSystem=`, `ProtectHome=`, `PrivateTmp=` | read-only or private views of the filesystem |

**Relied on:** a system unit gives each agent session a cgroup it cannot
escape and that systemd kills as a whole; socket units stop an agent from
grabbing a service's port during a restart. **Used in:**
[system-unit launcher](overview.md#system-unit-launcher-with-a-pam-audit-session),
[architecture](overview.md#architecture).

## journald

**journald** is systemd's log daemon. For each entry it adds **trusted
fields** from the kernel's view of the sender (`_PID`, `_UID`, `_GID`,
`_SYSTEMD_UNIT`, `_TRANSPORT`), which the sender cannot forge; fields such as
`_COMM` are process-controlled. Kernel log lines, including nftables
`log` output, arrive with `_TRANSPORT=kernel`. `journalctl -o json
--after-cursor=…` streams entries with a resumable **cursor**.

journald **rate-limits** each unit (by default 10,000 messages per 30 s) and
silently drops the excess, leaving only a "Suppressed N messages" entry.

**Relied on:** the proxy's decision log is trustworthy when matched on unit
*and* UID; journald is *not* suitable for records that must never be lost,
so hook records bypass it. **Used in:**
[hooks to a root collector](overview.md#hooks-to-a-root-collector-with-fail-closed-pretooluse).

## PAM, login UID, and audit sessions

**PAM** (Pluggable Authentication Modules) runs configurable steps when a
session starts, for example at SSH login. The `pam_loginuid` module stamps
the process with a **login UID** (`auid`) and a fresh **audit session ID**
(`ses`). Both are inherited by every descendant, including double-forked
daemons, and once set cannot be changed without `CAP_AUDIT_CONTROL`. Each
SSH login gets a new `ses`.

**Relied on:** `ses` is an unforgeable label for "everything this session
started", so kernel exec records can be tied to a Claude Code session.
**Used in:**
[system-unit launcher](overview.md#system-unit-launcher-with-a-pam-audit-session),
[query-time correlation](overview.md#central-host-store-and-query-time-correlation).

## auditd

The kernel's audit subsystem emits records when processes make selected
**system calls** or touch watched files. The rule `-a always,exit -F
arch=b64 -S execve -F uid=2000 -k agent-exec` means "log every program
execution by UID 2000, tagged `agent-exec`". One event is several lines
(`SYSCALL`, `EXECVE`, `CWD`, `PATH`, …) sharing a timestamp and serial
number, usually ending with `EOE`. Records include `pid`, `ppid`, `auid`,
`ses`, the executable, arguments, and working directory. **auditd** is the
root daemon that writes them to `/var/log/audit/audit.log`. Changes to
firewall or audit rules produce `NETFILTER_CFG` and `CONFIG_CHANGE` records
without any rule.

Serial numbers restart at boot; the kernel drops records if its queue (the
**backlog**) overflows; and auditd can be told to *suspend* rather than halt
the machine when its disk fills.

**Relied on:** every program the agent runs is recorded with its `ses`, even
if it never went through a Claude Code tool call. **Used in:**
[threat model](overview.md#threat-model),
[tamper and failure analysis](overview.md#tamper-and-failure-analysis).

## nftables

**nftables** (`nft`) is the Linux packet filter. Rules live in **tables**
containing **chains** attached to **hooks** on the packet path: `output`
(packets from local processes), `input` (packets to this machine), and
`forward` (packets routed through it, e.g. from a VM). The `inet` family
covers IPv4 and IPv6 in one table; a rule set that forgets IPv6 can be
bypassed over IPv6.

Several tables can hook the same point, and each sees every packet:
**`accept` ends only that chain**, while **`drop` is final everywhere**. So
a table can always add restrictions but never override another firewall's
drop (ufw, firewalld, libvirt). `meta skuid <uid>` matches packets sent from
a socket owned by that UID, so it applies to locally generated traffic
(`output`); forwarded packets have no local socket. Only root can change
rules.

**Relied on:** the agent's own traffic can be restricted by UID without
affecting other users, and adding our tables cannot weaken an existing
firewall. **Used in:**
[isolated network and host nftables](overview.md#isolated-libvirt-network-nwfilter-and-host-nftables).

## libvirt networks and nwfilter

**libvirt** (`virsh`) manages KVM virtual machines. A libvirt **network** is
a virtual switch: a Linux **bridge** (e.g. `virbr0`) to which each VM's NIC
connects through its own **tap** device (`vnetN`). libvirt's `default`
network is NAT on `192.168.122.0/24`. A network without a `<forward>`
element is **isolated**: no route or NAT to the outside, although VMs can
still reach the host's address on the bridge. libvirt runs a dnsmasq per
network for DHCP and, optionally, DNS. `<port isolated='yes'/>` stops VMs on
the same bridge from talking to each other.

**nwfilter** attaches per-VM packet filters to tap devices. The stock
`clean-traffic` filter stops a VM from spoofing its MAC or IP address.

**Relied on:** a VM on an isolated, DNS-less network has exactly the paths
the host allows; anti-spoofing lets the host identify a VM by its source IP.
**Used in:**
[isolated network](overview.md#isolated-libvirt-network-nwfilter-and-host-nftables).

## Forward proxies, CONNECT, TLS SNI, and domain fronting

A **forward proxy** makes outbound connections for a client. For HTTPS the
client sends `CONNECT api.anthropic.com:443`; the proxy answers `200` and
from then on copies encrypted bytes both ways. For plain HTTP the client
sends the full URL (`GET http://host/path`). Most CLI tools and Claude Code
honor `HTTPS_PROXY`, `HTTP_PROXY`, and `NO_PROXY` (some only lowercase);
Claude Code does not support SOCKS. An **explicit** proxy relies on these
variables; tools that ignore them simply fail when direct traffic is
dropped.

The first TLS message, the **ClientHello**, is unencrypted and normally
carries **SNI** (Server Name Indication), the hostname the client wants.
CDNs pick the site to serve by SNI. A proxy that checks only the `CONNECT`
line can be fooled by **domain fronting**: `CONNECT allowed.example`, then
SNI `evil.example`, and a CDN that hosts both serves `evil.example`. A
variant puts the real name only in the HTTP `Host` header *inside* TLS,
which a non-decrypting proxy cannot see. **ECH** (Encrypted Client Hello)
hides the real SNI; some clients send a decoy ("GREASE") ECH extension.
**QUIC** (HTTP/3) runs over UDP; when UDP is dropped, clients fall back to
TCP.

**Relied on:** requiring SNI to equal the `CONNECT` host, and refusing ECH,
closes TLS-level fronting without decrypting anything. **Used in:**
[explicit proxy](overview.md#explicit-proxy-with-allowlist-sni-check-pinned-address-no-dns).

## DNS as a side channel

A query for `<data>.evil.example` reaches the attacker's nameserver through
any chain of recursive resolvers, so an environment that can resolve
arbitrary names can leak data with no other internet access. With
`CONNECT`, clients hand hostnames to the proxy and need no DNS of their own.
A related trick, **DNS rebinding**, makes a public name resolve to an
internal address such as `127.0.0.1`.

**Relied on:** removing DNS entirely is stronger than filtering it, and the
proxy must check the addresses it resolves. **Used in:**
[explicit proxy](overview.md#explicit-proxy-with-allowlist-sni-check-pinned-address-no-dns),
[host agents and VM agents](overview.md#host-agents-and-vm-agents).

## vsock

**vsock** (`AF_VSOCK`, virtio-vsock) is a socket family for VM↔host
communication outside the network stack. Addresses are a **CID** (context
ID) and a port. The host is CID 2; each VM gets a CID from its libvirt XML
(pin it, since automatic assignment can change); CID 1 is local loopback, so
host processes can reach host vsock listeners too. vsock traffic passes no
nftables rule or bridge and cannot reach the internet. On the host it needs
the `vhost_vsock` module.

Binding a vsock port below 1024 requires `CAP_NET_BIND_SERVICE`, which an
unprivileged user lacks.

**Relied on:** the receiver can tell from the sender's *source port* that
the sender is privileged inside its VM, and from the CID which VM it is.
**Used in:**
[vsock transport](overview.md#vsock-transport-authenticated-by-privileged-source-port).

## OpenTelemetry

**OpenTelemetry** (OTel) is a vendor-neutral standard for metrics, logs, and
traces, exported over **OTLP** (gRPC or HTTP; protobuf or JSON) to a
collector. Claude Code can export metrics and log events (API requests,
tokens, cost, tool results) when configured through environment variables.

**Relied on:** OTel adds model-level data the hooks do not see; because any
local process can post to an OTLP endpoint, these records are only
supplementary claims. **Used in:** [rollout](overview.md#rollout) (phase 4).

## Claude Code settings, managed settings, and hooks

Claude Code merges settings from several sources: user
(`~/.claude/settings.json`), project (`.claude/settings.json`), local, the
`--settings` flag, and **managed settings**, which have the highest
precedence; no other source overrides a managed key. On Linux, managed
settings come from `/etc/claude-code/managed-settings.json` and every
`*.json` in `/etc/claude-code/managed-settings.d/`, merged in name order
(later files win for scalars; lists such as `permissions.deny` are
concatenated). Claude Code does not protect these files itself; their
strength comes from being owned by root. A settings `env` block sets
environment variables for Claude Code and everything it runs.

**Hooks** are commands Claude Code runs at lifecycle events, each receiving
a JSON description of the event on stdin (`session_id`, `transcript_path`,
`cwd`, `hook_event_name`, and event-specific fields such as `tool_name`,
`tool_input`, `tool_use_id`, `tool_response`, or `prompt`). The events used
here are `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`,
`PostToolUseFailure`, `SubagentStart`, `SubagentStop`, `Stop`,
`ConfigChange`, and `SessionEnd`.

Exit code 0 is success; 2 is a "blocking error" whose stderr is shown to
Claude; any other code, or a timeout, is a non-blocking failure, and **by
default Claude Code proceeds when a hook fails**. A command hook can opt into
fail-closed behavior with `"onFailure": "block"`. A hook's stdout is parsed
as control JSON (and for some events added to the model's context), so an
audit hook must not write to it. The managed key
`allowManagedHooksOnly` ignores hooks from every non-managed source;
`permissions.disableBypassPermissionsMode` would reject
`--dangerously-skip-permissions` and must stay unset.
`CLAUDE_CODE_PROXY_RESOLVES_HOSTS=1` leaves DNS to the proxy, and
`CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` turns off auto-update,
telemetry, error reporting, feature-flag fetches, and other nonessential
requests.

**Relied on:** root-owned managed settings are the one policy source the
agent cannot override; `onFailure: block` turns a logging failure into a
refused tool call. **Used in:**
[root-owned Claude Code](overview.md#root-owned-claude-code-pinned-by-managed-settings),
[hooks to a root collector](overview.md#hooks-to-a-root-collector-with-fail-closed-pretooluse).

## bubblewrap and Claude Code's sandbox

**bubblewrap** (`bwrap`) is an unprivileged sandboxing tool built on Linux
**namespaces**, which give a process its own view of a global resource such
as the mount table or the network stack. Claude Code can optionally run its
Bash tool's commands inside bubblewrap (`sandbox.enabled`), with
filesystem write limits and a domain allowlist enforced by its own proxy.
Under `--dangerously-skip-permissions`, unlisted hosts are *allowed* unless
`sandbox.network.strictAllowlist` or the managed-only
`sandbox.network.allowManagedDomainsOnly` is set; it wraps Bash commands
only; and it is configured and run by the very process being contained.

**Relied on:** nothing. It is an optional inner layer against accidents.
**Used in:**
[credentials and optional layers](overview.md#credentials-and-optional-layers).

## Glossary

| Term | Meaning |
|---|---|
| `auid` | Login UID set by `pam_loginuid`; survives `su`/`sudo` |
| backlog | The kernel's queue of pending audit records |
| CID | vsock context ID; 2 = host, 1 = local loopback |
| ClientHello | First, unencrypted message of a TLS handshake |
| `CONNECT` | HTTP method asking a proxy to open a raw tunnel |
| cgroup | Kernel-tracked group of processes, inherited by children |
| ECH | Encrypted Client Hello; hides the SNI |
| environment | The host, or one agent VM; each has its own shipper |
| fronting | Reaching one site through another site's allowed name on a shared CDN |
| managed settings | Highest-precedence Claude Code settings under `/etc/claude-code/` |
| nwfilter | libvirt's per-VM packet filters |
| OTLP | OpenTelemetry's export protocol |
| `ses` | Audit session ID; inherited, unforgeable |
| SNI | Server Name Indication: hostname in the ClientHello |
| skuid | nftables match on the UID owning a packet's socket |
| socket activation | systemd holds a listening socket and passes it to the service |
| `SO_PEERCRED` | Socket option returning a Unix-socket peer's PID, UID, GID |
| tap | Host-side end of a VM's virtual NIC |
| Yama | Kernel module restricting ptrace to descendants |
