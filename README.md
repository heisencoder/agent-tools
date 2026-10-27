# agent-tools

Tools for securely running AI coding agents in isolated environments.

The recommended setup runs Claude Code with `--dangerously-skip-permissions`
inside libvirt VMs (or, for low-risk work, directly on the host), with
network egress restricted by `agent-egress` and every session recorded by
`agent-audit` and `agent-logs`. These three packages target **Ubuntu 26.04 or
later, or the Debian equivalent**, and need `nftables`, `auditd`, systemd,
`python3` ≥ 3.12, and for VMs `libvirt-daemon-system` and `qemu-kvm`; see
the [prerequisites](docs/design/overview.md#prerequisites).

## Design docs

- [Design overview](docs/design/overview.md): goals, threat model, trust
  boundaries, architecture, and the key design decisions.
- [Implementation details](docs/design/implementation.md): proxy algorithm,
  nftables and libvirt configuration, managed settings, hook protocol, log
  transport and storage, query CLI, and tests.
- [Background](docs/design/background.md): the Linux and Claude Code concepts
  the design relies on, for readers who are not systems specialists.

## Packages

### [agent-egress](agent-egress/)

Restricted network egress. Agents reach the internet only through an
allowlisting HTTPS proxy on the host that checks TLS SNI against the
`CONNECT` host and refuses internal addresses; nftables rules and an
isolated libvirt network drop everything else, including DNS. Every decision
is logged as JSON.

### [agent-audit](agent-audit/)

Claude Code policy for one environment: a root-owned Claude Code install,
managed-settings hooks that fail closed for tool calls, the `agent-run`
launcher (each session in a hardened systemd unit with its own audit
session), and auditd rules for every program the agent runs.

### [agent-logs](agent-logs/)

Tamper-resistant log pipeline: a root hook collector and shipper in each
environment, `agent-logd` on the host (vsock and Unix-socket ingest,
per-environment store with quotas, optional OpenTelemetry receiver), and the
`agent-log` CLI for sessions, timelines, network decisions, and `verify`.

### [agent-sandbox](agent-sandbox/)

A Podman container and launcher script for running coding agents (Claude Code,
OpenAI Codex) in rootless containers on Linux. It predates the VM-based
egress and audit setup above, which is now the recommended path.

**Key features:**

- **Rootless Podman containers** with user-namespace isolation
- **Claude Code support** via API key or OAuth login (mount your host
  `~/.claude` into the container)
- **OpenAI Codex support** via API key
- **Security hardened** — capabilities dropped, no-new-privileges, optional
  full network isolation
- **OCI-compliant Dockerfile** — builds with both Podman and Docker

**Quick start:**

```bash
# Build the container image
podman build -t agent-sandbox agent-sandbox/

# Run Claude Code with an API key
export ANTHROPIC_API_KEY="sk-ant-..."
./agent-sandbox/run-agent.sh ./projects/webapp

# Run Claude Code using your existing OAuth login
./agent-sandbox/run-agent.sh --claude-config ~/.claude ./projects/webapp
```

See the [agent-sandbox README](agent-sandbox/README.md) for full documentation.

## License

MIT — see [LICENSE](LICENSE).
