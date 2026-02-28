#!/bin/bash
# run-agent.sh — Launch a coding agent inside a secure Podman container.
#
# The container gets:
#   - Read-write access to the project directory
#   - Persistent agent config and history across sessions
#   - Rootless Podman user-namespace isolation
#
# Usage:
#   ./run-agent.sh [--agent claude|codex] [OPTIONS] [project-dir]
#
# Examples:
#   ./run-agent.sh --agent claude ./projects/webapp
#   ./run-agent.sh --claude-config ~/.claude ./projects/webapp
#   ./run-agent.sh --agent codex --no-network ./projects/api
#   ./run-agent.sh --resume

set -euo pipefail

# -----------------------------------------------------------------
# Defaults
# -----------------------------------------------------------------
IMAGE="agent-sandbox:latest"
AGENT="claude"
PROJECT_DIR=""
RESUME=false
NO_NETWORK=false
CLAUDE_CONFIG=""
EXTRA_MOUNTS=()
EXTRA_PODMAN_ARGS=()
CONTAINER_NAME=""

DATA_HOME="${AGENT_SANDBOX_DATA:-$HOME/.local/share/agent-sandbox}"

# -----------------------------------------------------------------
# Usage
# -----------------------------------------------------------------
usage() {
    cat <<'EOF'
Usage: run-agent.sh [OPTIONS] [project-dir]

Launch a coding agent inside a secure Podman container.

Options:
  --agent <name>        Agent to run: claude (default), codex, or shell
  --claude-config <dir> Mount a Claude Code config directory (~/.claude) into
                        the container. Use this to share your OAuth login session
                        with the container. (default: auto-detected, see below)
  --image <image>       Container image (default: agent-sandbox:latest)
  --resume              Reattach to an existing container
  --no-network          Disable all container networking
  --mount <host:cont>   Additional bind mount (read-only by default)
  --mount-rw <host:cont> Additional bind mount (read-write)
  --podman-arg <arg>    Pass additional argument to podman run
  --help                Show this help message

Authentication:
  Claude Code supports two authentication modes inside the container:

  1. API Key (simplest):
     Set ANTHROPIC_API_KEY in your environment before running this script.
     The key is passed into the container automatically.

  2. OAuth Login (no API key needed):
     If you have logged in to Claude Code on the host (via 'claude login'),
     use --claude-config to share your credentials with the container:

       ./run-agent.sh --claude-config ~/.claude ./project

     When --claude-config is used, the specified directory is bind-mounted
     into the container, giving Claude Code access to your OAuth tokens.
     The host's ~/.claude.json is also mounted if it exists (required for
     OAuth session state).

  Auto-detection: If neither ANTHROPIC_API_KEY nor --claude-config is set,
  and ~/.claude/.credentials.json exists, the script will automatically
  mount ~/.claude read-only for OAuth support.

Environment variables:
  AGENT_SANDBOX_DATA    Base directory for persistent agent state
                        (default: ~/.local/share/agent-sandbox)
  ANTHROPIC_API_KEY     API key for Claude Code
  OPENAI_API_KEY        API key for OpenAI Codex
EOF
    exit 0
}

# -----------------------------------------------------------------
# Parse arguments
# -----------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --help)          usage ;;
        --agent)         AGENT="$2"; shift 2 ;;
        --claude-config) CLAUDE_CONFIG="$2"; shift 2 ;;
        --image)         IMAGE="$2"; shift 2 ;;
        --resume)        RESUME=true; shift ;;
        --no-network)    NO_NETWORK=true; shift ;;
        --mount)         EXTRA_MOUNTS+=("-v" "$2:ro"); shift 2 ;;
        --mount-rw)      EXTRA_MOUNTS+=("-v" "$2"); shift 2 ;;
        --podman-arg)    EXTRA_PODMAN_ARGS+=("$2"); shift 2 ;;
        -*)              echo "Unknown option: $1" >&2; exit 1 ;;
        *)               PROJECT_DIR="$1"; shift ;;
    esac
done

# Default project dir to current directory
PROJECT_DIR="${PROJECT_DIR:-$(pwd)}"
PROJECT_DIR="$(cd "$PROJECT_DIR" && pwd)"  # Resolve to absolute path

CONTAINER_NAME="agent-sandbox-$(basename "$PROJECT_DIR")"

# -----------------------------------------------------------------
# Resume existing container
# -----------------------------------------------------------------
if [ "$RESUME" = true ]; then
    if podman container exists "$CONTAINER_NAME" 2>/dev/null; then
        echo "Reattaching to container: $CONTAINER_NAME"
        exec podman attach "$CONTAINER_NAME"
    else
        echo "No existing container found. Starting a new one."
    fi
fi

# -----------------------------------------------------------------
# Set up persistent data directories
# -----------------------------------------------------------------
mkdir -p "$DATA_HOME"/{claude,config,history}

echo "Data directory:  $DATA_HOME"
echo "Project:         $PROJECT_DIR"
echo "Agent:           $AGENT"
echo "Container:       $CONTAINER_NAME"

# -----------------------------------------------------------------
# Remove stale container with the same name
# -----------------------------------------------------------------
podman rm -f "$CONTAINER_NAME" 2>/dev/null || true

# -----------------------------------------------------------------
# Build podman run arguments
# -----------------------------------------------------------------
PODMAN_ARGS=(
    --name "$CONTAINER_NAME"
    --rm
    -it
    --userns=keep-id
    # Mount the project directory (read-write)
    -v "$PROJECT_DIR:/workspace:Z"
    # Mount persistent config and history
    -v "$DATA_HOME/config:/home/agent/.config:Z"
    -v "$DATA_HOME/history:/home/agent/.local/share:Z"
    # Working directory
    -w /workspace
    # Security: drop all capabilities, re-add only what's needed
    --cap-drop=ALL
    --cap-add=DAC_OVERRIDE
    --cap-add=FOWNER
    --cap-add=SETUID
    --cap-add=SETGID
    # Security: no new privileges
    --security-opt=no-new-privileges
)

# -----------------------------------------------------------------
# Claude Code config / auth mounts
# -----------------------------------------------------------------
# Determine how to mount ~/.claude:
#   1. Explicit --claude-config: mount that directory (read-write)
#   2. No --claude-config, no ANTHROPIC_API_KEY, but ~/.claude/.credentials.json
#      exists: auto-mount ~/.claude read-only for OAuth
#   3. Otherwise: mount the data dir's claude/ subdir

if [ -n "$CLAUDE_CONFIG" ]; then
    CLAUDE_CONFIG="$(cd "$CLAUDE_CONFIG" && pwd)"
    echo "Claude config:   $CLAUDE_CONFIG (shared)"
    PODMAN_ARGS+=(-v "$CLAUDE_CONFIG:/home/agent/.claude:Z")
    # Also mount ~/.claude.json if it exists (required for OAuth session state)
    CLAUDE_JSON="${CLAUDE_CONFIG%/.claude}/.claude.json"
    if [ -f "$CLAUDE_JSON" ]; then
        PODMAN_ARGS+=(-v "$CLAUDE_JSON:/home/agent/.claude.json:Z")
    fi
elif [ -z "${ANTHROPIC_API_KEY:-}" ] && [ -f "$HOME/.claude/.credentials.json" ]; then
    echo "Claude config:   $HOME/.claude (auto-detected OAuth, read-only)"
    PODMAN_ARGS+=(-v "$HOME/.claude:/home/agent/.claude:ro")
    if [ -f "$HOME/.claude.json" ]; then
        PODMAN_ARGS+=(-v "$HOME/.claude.json:/home/agent/.claude.json:ro")
    fi
else
    PODMAN_ARGS+=(-v "$DATA_HOME/claude:/home/agent/.claude:Z")
fi

# Network isolation
if [ "$NO_NETWORK" = true ]; then
    PODMAN_ARGS+=(--network=none)
fi

# Pass API keys via environment (if set on the host)
if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
    PODMAN_ARGS+=(-e "ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY")
fi
if [ -n "${OPENAI_API_KEY:-}" ]; then
    PODMAN_ARGS+=(-e "OPENAI_API_KEY=$OPENAI_API_KEY")
fi

# Extra mounts
PODMAN_ARGS+=("${EXTRA_MOUNTS[@]+"${EXTRA_MOUNTS[@]}"}")

# Extra podman args
PODMAN_ARGS+=("${EXTRA_PODMAN_ARGS[@]+"${EXTRA_PODMAN_ARGS[@]}"}")

# -----------------------------------------------------------------
# Determine the container command
# -----------------------------------------------------------------
case "$AGENT" in
    claude)
        CONTAINER_CMD=("claude" "--dangerously-skip-permissions")
        ;;
    codex)
        CONTAINER_CMD=("codex" "--full-auto")
        ;;
    shell)
        CONTAINER_CMD=("/bin/zsh")
        ;;
    *)
        echo "Unknown agent: $AGENT (expected: claude, codex, or shell)" >&2
        exit 1
        ;;
esac

# -----------------------------------------------------------------
# Launch
# -----------------------------------------------------------------
echo "Starting container..."
exec podman run "${PODMAN_ARGS[@]}" "$IMAGE" "${CONTAINER_CMD[@]}"
