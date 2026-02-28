# agent-tools

Tools for securely running AI coding agents in isolated environments.

## Packages

### [agent-sandbox](agent-sandbox/)

A Podman container and launcher script for running coding agents (Claude Code,
OpenAI Codex) in rootless containers on Linux.

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
