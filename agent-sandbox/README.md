# agent-sandbox

Secure Podman container for running coding agents (Claude Code, OpenAI Codex)
with per-client data compartmentalization on Ubuntu.

## Overview

When working with AI coding agents across multiple client projects, you need
strong isolation guarantees — one client's code and credentials must never leak
to another. This package provides:

- **Rootless Podman containers** — no daemon, no root, user-namespace isolation
- **Per-client data directories** — each client gets its own agent config,
  conversation history, and workspace
- **Minimal attack surface** — capabilities dropped, `no-new-privileges` enforced
- **Optional network firewall** — allowlist-only outbound access to APIs and
  package registries
- **Multi-agent support** — run Claude Code, OpenAI Codex, or a plain shell

## Quick Start

### Prerequisites

- Ubuntu 22.04+ (or any Linux with Podman)
- [Podman](https://podman.io/getting-started/installation) (rootless mode)
- An Anthropic API key **or** an existing Claude Code OAuth login

### Build the image

```bash
podman build -t agent-sandbox agent-sandbox/
```

### Run an agent

```bash
# Claude Code for client "acme" (API key)
export ANTHROPIC_API_KEY="sk-ant-..."
./agent-sandbox/run-agent.sh --client acme --agent claude ./projects/acme-webapp

# Claude Code for client "acme" (OAuth — share your host login)
./agent-sandbox/run-agent.sh --client acme --agent claude --claude-config ~/.claude ./projects/acme-webapp

# OpenAI Codex for client "globex"
export OPENAI_API_KEY="sk-..."
./agent-sandbox/run-agent.sh --client globex --agent codex ./projects/globex-api

# Just a shell for exploration
./agent-sandbox/run-agent.sh --client personal --agent shell
```

### Resume a session

```bash
./agent-sandbox/run-agent.sh --client acme --resume
```

## Authentication

Claude Code supports two authentication modes inside the container.

### Option 1: API Key

Set `ANTHROPIC_API_KEY` in your environment before launching. The key is
passed into the container automatically:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
./agent-sandbox/run-agent.sh --client acme --agent claude ./project
```

Each client gets an isolated `~/.claude` directory inside the container, so
conversation history and settings are fully compartmentalized.

### Option 2: OAuth Login (no API key)

If you have logged into Claude Code on your host machine (`claude login`),
you can share that session with the container using `--claude-config`:

```bash
./agent-sandbox/run-agent.sh --client acme --agent claude \
    --claude-config ~/.claude ./project
```

This bind-mounts your host `~/.claude` directory (which contains
`.credentials.json` and related files) into the container. The host's
`~/.claude.json` is also mounted automatically if present (required for
OAuth session state).

**Auto-detection:** If neither `ANTHROPIC_API_KEY` nor `--claude-config`
is set, and `~/.claude/.credentials.json` exists on the host, the script
automatically mounts `~/.claude` **read-only** so your OAuth tokens are
available without any extra flags.

## Data Compartmentalization

Each client's data is stored separately under `~/.local/share/agent-sandbox/`:

```
~/.local/share/agent-sandbox/
└── clients/
    ├── acme/
    │   ├── claude/      # Claude config and conversation history
    │   ├── codex/       # Codex session data
    │   ├── config/      # Agent configuration
    │   └── history/     # Shell and command history
    └── globex/
        ├── claude/
        ├── codex/
        ├── config/
        └── history/
```

Only the designated project directory is mounted read-write in the container.
Client A's container has zero access to Client B's data or project files.

> **Note:** When using `--claude-config`, the host's `~/.claude` replaces the
> per-client `claude/` directory. This shares your OAuth session across clients
> but also means conversation history is shared. If you need fully isolated
> history per client, use API key authentication instead.

## Security Features

### Container isolation

| Layer | Protection |
|-------|-----------|
| User namespaces | Container `root` maps to your unprivileged UID |
| Capability drop | `--cap-drop=ALL` with minimal re-adds |
| No new privileges | Prevents privilege escalation inside the container |
| Bind mounts | Only project dir (rw) and client config (rw) are mounted |
| SELinux labels | `:Z` relabeling for proper MAC enforcement |

### Optional network firewall

Use `--firewall` to restrict outbound traffic to an allowlist:

```bash
./agent-sandbox/run-agent.sh --client acme --agent claude --firewall ./project
```

Allowed destinations:
- `api.anthropic.com` (Claude)
- `api.openai.com` (Codex)
- `github.com`, `api.github.com` (Git operations)
- `registry.npmjs.org`, `pypi.org` (Package installs)
- DNS (port 53) and SSH (port 22)

Everything else is blocked.

### Full network isolation

For maximum security, disable networking entirely:

```bash
./agent-sandbox/run-agent.sh --client acme --agent claude --no-network ./project
```

## run-agent.sh Reference

```
Usage: run-agent.sh --client <name> [OPTIONS] [project-dir]

Required:
  --client <name>        Client/project identifier for data compartmentalization

Options:
  --agent <name>         Agent to run: claude (default), codex, or shell
  --claude-config <dir>  Mount a Claude config directory into the container
                         (use to share OAuth login from the host)
  --image <image>        Container image (default: agent-sandbox:latest)
  --resume               Reattach to an existing container for this client
  --no-network           Disable all container networking
  --firewall             Enable the allowlist-based firewall inside the container
  --mount <host:cont>    Additional bind mount (read-only)
  --mount-rw <host:cont> Additional bind mount (read-write)
  --podman-arg <arg>     Pass additional argument to podman run
  --help                 Show this help message

Environment variables:
  AGENT_SANDBOX_DATA     Base dir for per-client state
                         (default: ~/.local/share/agent-sandbox)
  ANTHROPIC_API_KEY      API key for Claude Code
  OPENAI_API_KEY         API key for OpenAI Codex
```

## Development

### Building locally

```bash
podman build -t agent-sandbox agent-sandbox/
```

### Running tests

The GitHub Actions workflow builds the image and verifies that the installed
tools work correctly. To run the same checks locally:

```bash
podman build -t agent-sandbox agent-sandbox/
podman run --rm agent-sandbox node --version
podman run --rm agent-sandbox python3 --version
podman run --rm agent-sandbox git --version
podman run --rm agent-sandbox claude --version
podman run --rm agent-sandbox codex --version
```

## License

MIT — see [LICENSE](../LICENSE).
