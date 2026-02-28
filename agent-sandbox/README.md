# agent-sandbox

Secure Podman container for running coding agents (Claude Code, OpenAI Codex)
with rootless isolation on Linux.

## Overview

- **Rootless Podman containers** — no daemon, no root, user-namespace isolation
- **Persistent agent state** — config and conversation history survive across
  sessions
- **Minimal attack surface** — capabilities dropped, `no-new-privileges` enforced
- **Network isolation** — full network disable via `--no-network`
- **Multi-agent support** — run Claude Code, OpenAI Codex, or a plain shell

For multi-client isolation, create separate Linux users and run the script as
each user — each gets their own home directory and container state automatically.

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
# Claude Code with an API key
export ANTHROPIC_API_KEY="sk-ant-..."
./agent-sandbox/run-agent.sh --agent claude ./projects/webapp

# Claude Code with OAuth (share your host login)
./agent-sandbox/run-agent.sh --claude-config ~/.claude ./projects/webapp

# OpenAI Codex
export OPENAI_API_KEY="sk-..."
./agent-sandbox/run-agent.sh --agent codex ./projects/api

# Just a shell for exploration
./agent-sandbox/run-agent.sh --agent shell
```

### Resume a session

```bash
./agent-sandbox/run-agent.sh --resume
```

## Authentication

Claude Code supports two authentication modes inside the container.

### Option 1: API Key

Set `ANTHROPIC_API_KEY` in your environment before launching. The key is
passed into the container automatically:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
./agent-sandbox/run-agent.sh ./project
```

### Option 2: OAuth Login (no API key)

If you have logged into Claude Code on your host machine (`claude login`),
you can share that session with the container using `--claude-config`:

```bash
./agent-sandbox/run-agent.sh --claude-config ~/.claude ./project
```

This bind-mounts your host `~/.claude` directory (which contains
`.credentials.json` and related files) into the container. The host's
`~/.claude.json` is also mounted automatically if present (required for
OAuth session state).

**Auto-detection:** If neither `ANTHROPIC_API_KEY` nor `--claude-config`
is set, and `~/.claude/.credentials.json` exists on the host, the script
automatically mounts `~/.claude` **read-only** so your OAuth tokens are
available without any extra flags.

## Persistent Data

Agent state is stored under `~/.local/share/agent-sandbox/`:

```
~/.local/share/agent-sandbox/
├── claude/      # Claude Code config and conversation history
├── config/      # Agent configuration
└── history/     # Shell and command history
```

Only the designated project directory is mounted read-write in the container.

## Security Features

### Container isolation

| Layer | Protection |
|-------|-----------|
| User namespaces | Container `root` maps to your unprivileged UID |
| Capability drop | `--cap-drop=ALL` with minimal re-adds |
| No new privileges | Prevents privilege escalation inside the container |
| Bind mounts | Only project dir (rw) and agent state (rw) are mounted |
| SELinux labels | `:Z` relabeling for proper MAC enforcement |

### Network isolation

Disable networking entirely with `--no-network`:

```bash
./agent-sandbox/run-agent.sh --no-network ./project
```

This passes `--network=none` to Podman, completely preventing the container
from making any network connections.

## run-agent.sh Reference

```
Usage: run-agent.sh [OPTIONS] [project-dir]

Options:
  --agent <name>         Agent to run: claude (default), codex, or shell
  --claude-config <dir>  Mount a Claude config directory into the container
                         (use to share OAuth login from the host)
  --image <image>        Container image (default: agent-sandbox:latest)
  --resume               Reattach to an existing container
  --no-network           Disable all container networking
  --mount <host:cont>    Additional bind mount (read-only)
  --mount-rw <host:cont> Additional bind mount (read-write)
  --podman-arg <arg>     Pass additional argument to podman run
  --help                 Show this help message

Environment variables:
  AGENT_SANDBOX_DATA     Base dir for persistent agent state
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
