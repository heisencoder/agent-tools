# Secure Coding Agent Container
#
# A hardened container image for running coding agents (Claude Code, OpenAI Codex,
# etc.) with multi-client data compartmentalization. Designed for rootless Podman
# on Ubuntu, providing strong isolation between client projects.
#
# Build:
#   podman build -t agent-sandbox agent-sandbox/
#
# Run via helper script:
#   ./agent-sandbox/run-agent.sh --client acme --agent claude /path/to/project

FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
ARG TZ=UTC
ENV TZ="$TZ"

# -------------------------------------------------------------------
# 1. Install system packages: dev tools, networking, security
# -------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl wget ca-certificates gnupg2 sudo \
    zsh less vim nano jq fzf unzip man-db procps \
    build-essential pkg-config libssl-dev \
    iptables ipset iproute2 dnsutils \
    python3 python3-pip python3-venv \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# -------------------------------------------------------------------
# 2. Install Node.js 20 LTS (for Claude Code)
# -------------------------------------------------------------------
ARG NODE_MAJOR=20
RUN mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
       | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main" \
       > /etc/apt/sources.list.d/nodesource.list \
    && apt-get update && apt-get install -y --no-install-recommends nodejs \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# -------------------------------------------------------------------
# 3. Install GitHub CLI
# -------------------------------------------------------------------
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
    | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg \
    && chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
    > /etc/apt/sources.list.d/github-cli.list \
    && apt-get update && apt-get install -y --no-install-recommends gh \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# -------------------------------------------------------------------
# 4. Create non-root 'agent' user for rootless Podman compatibility
# -------------------------------------------------------------------
RUN groupadd --gid 1000 agent \
    && useradd --uid 1000 --gid 1000 -m -s /bin/zsh agent \
    && mkdir -p /home/agent/.claude /home/agent/.local/share/npm-global \
    && chown -R agent:agent /home/agent

# Allow agent to run firewall script as root (for optional network restriction)
COPY init-firewall.sh /usr/local/bin/init-firewall.sh
RUN chmod +x /usr/local/bin/init-firewall.sh \
    && echo "agent ALL=(root) NOPASSWD: /usr/local/bin/init-firewall.sh" \
    > /etc/sudoers.d/agent-firewall \
    && chmod 0440 /etc/sudoers.d/agent-firewall

# -------------------------------------------------------------------
# 5. Switch to non-root user and configure environment
# -------------------------------------------------------------------
USER agent
WORKDIR /workspace

ENV HOME=/home/agent
ENV NPM_CONFIG_PREFIX=/home/agent/.local/share/npm-global
ENV PATH="$PATH:/home/agent/.local/share/npm-global/bin:/home/agent/.local/bin"
ENV SHELL=/bin/zsh
ENV EDITOR=nano
ENV VISUAL=nano

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
      org.opencontainers.image.description="Secure container for running coding agents with client data isolation" \
      org.opencontainers.image.source="https://github.com/heisencoder/agent-tools"

CMD ["/bin/zsh"]
