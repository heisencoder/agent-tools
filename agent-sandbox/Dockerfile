# Secure Coding Agent Container
#
# A hardened container image for running coding agents (Claude Code, OpenAI Codex,
# etc.) in rootless Podman on Ubuntu.
#
# Build:
#   podman build -t agent-sandbox agent-sandbox/
#
# Run via helper script:
#   ./agent-sandbox/run-agent.sh --agent claude /path/to/project

FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
ARG TZ=UTC
ENV TZ="$TZ"

# -------------------------------------------------------------------
# 1. Install system packages: dev tools, networking, security
# -------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl wget ca-certificates gnupg \
    less vim jq fzf unzip man-db procps \
    build-essential pkg-config libssl-dev \
    iproute2 \
    python3 python3-pip python3-venv \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# -------------------------------------------------------------------
# 2. Install Node.js 24 LTS (for Claude Code)
# -------------------------------------------------------------------
ARG NODE_MAJOR=24
RUN mkdir -p /etc/apt/keyrings \
    && curl -fsSL -o /tmp/nodesource.gpg.key https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
    && gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg /tmp/nodesource.gpg.key \
    && rm /tmp/nodesource.gpg.key \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main" \
       > /etc/apt/sources.list.d/nodesource.list \
    && apt-get update && apt-get install -y --no-install-recommends nodejs \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# -------------------------------------------------------------------
# 3. Install GitHub CLI
# -------------------------------------------------------------------
RUN mkdir -p /etc/apt/keyrings \
    && curl -fsSL -o /etc/apt/keyrings/githubcli-archive-keyring.gpg https://cli.github.com/packages/githubcli-archive-keyring.gpg \
    && chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
       > /etc/apt/sources.list.d/github-cli.list \
    && apt-get update && apt-get install -y --no-install-recommends gh \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# -------------------------------------------------------------------
# 4. Create non-root 'agent' user for rootless Podman compatibility
# -------------------------------------------------------------------
RUN userdel -r ubuntu 2>/dev/null || true \
    && groupdel ubuntu 2>/dev/null || true \
    && groupadd --gid 1000 agent \
    && useradd --uid 1000 --gid 1000 -m -s /bin/bash agent \
    && mkdir -p /home/agent/.claude /home/agent/.npm-global \
    && chown -R agent:agent /home/agent

# -------------------------------------------------------------------
# 5. Switch to non-root user and configure environment
# -------------------------------------------------------------------
USER agent
WORKDIR /workspace

ENV HOME=/home/agent
ENV NPM_CONFIG_PREFIX=/home/agent/.npm-global
ENV PATH="$PATH:/home/agent/.npm-global/bin:/home/agent/.local/bin"
ENV SHELL=/bin/bash
ENV EDITOR=vim
ENV VISUAL=vim

# -------------------------------------------------------------------
# 6. Install coding agents
# -------------------------------------------------------------------
# Claude Code
RUN npm install -g @anthropic-ai/claude-code@latest

# OpenAI Codex CLI
RUN npm install -g @openai/codex@latest

# -------------------------------------------------------------------
# 7. Container metadata
# -------------------------------------------------------------------
LABEL org.opencontainers.image.title="agent-sandbox" \
      org.opencontainers.image.description="Secure container for running coding agents with rootless isolation" \
      org.opencontainers.image.source="https://github.com/heisencoder/agent-tools"

CMD ["/bin/bash"]
