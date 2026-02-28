# agent-tools

Tools for securely running AI coding agents in isolated environments.

## Packages

### [agent-sandbox](agent-sandbox/)

A Podman container and launcher script for running coding agents (Claude Code,
OpenAI Codex) with per-client data compartmentalization. Designed for
consultants and developers who work across multiple client projects and need
strong isolation guarantees.

**Key features:**

- **Rootless Podman containers** with user-namespace isolation
- **Per-client data directories** — each client gets isolated agent config,
  conversation history, and workspace
- **Claude Code support** via API key or OAuth login (mount your host
  `~/.claude` into the container)
- **OpenAI Codex support** via API key
- **Security hardened** — capabilities dropped, no-new-privileges, optional
  network firewall with domain allowlist
- **OCI-compliant Dockerfile** — builds with both Podman and Docker

**Quick start:**

```bash
# Build the container image
podman build -t agent-sandbox agent-sandbox/

# Run Claude Code for a client project (API key)
export ANTHROPIC_API_KEY="sk-ant-..."
./agent-sandbox/run-agent.sh --client acme --agent claude ./projects/acme-webapp

# Run Claude Code using your existing OAuth login
./agent-sandbox/run-agent.sh --client acme --agent claude \
    --claude-config ~/.claude ./projects/acme-webapp
```

See the [agent-sandbox README](agent-sandbox/README.md) for full documentation.

## License

MIT — see [LICENSE](LICENSE).
