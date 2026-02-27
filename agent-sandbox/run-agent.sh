#!/bin/bash
# run-agent.sh — Launch a coding agent inside a secure Podman container
# with per-client data compartmentalization.
#
# Each client gets an isolated container with:
#   - Its own Claude/Codex config and conversation history
#   - Read-write access to the project directory only
#   - No access to other clients' data or the host filesystem
#   - Rootless Podman user-namespace isolation
#
# Usage:
#   ./run-agent.sh --client <name> [--agent claude|codex] [OPTIONS] [project-dir]
#
# Examples:
#   ./run-agent.sh --client acme --agent claude ./projects/acme-webapp
#   ./run-agent.sh --client globex --agent codex --no-network ./projects/globex-api
#   ./run-agent.sh --client personal --resume

set -euo pipefail

# -----------------------------------------------------------------
# Defaults
# -----------------------------------------------------------------
IMAGE="agent-sandbox:latest"
CLIENT=""
AGENT="claude"
PROJECT_DIR=""
RESUME=false
NO_NETWORK=false
FIREWALL=false
EXTRA_MOUNTS=()
EXTRA_PODMAN_ARGS=()
CONTAINER_NAME=""

DATA_HOME="${AGENT_SANDBOX_DATA:-$HOME/.local/share/agent-sandbox}"

# -----------------------------------------------------------------
# Usage
# -----------------------------------------------------------------
usage() {
    cat <<'EOF'
Usage: run-agent.sh --client <name> [OPTIONS] [project-dir]

Launch a coding agent inside a secure Podman container with per-client isolation.

Required:
  --client <name>       Client/project identifier for data compartmentalization

Options:
  --agent <name>        Agent to run: claude (default), codex, or shell
  --image <image>       Container image (default: agent-sandbox:latest)
  --resume              Reattach to an existing container for this client
  --no-network          Disable all container networking
  --firewall            Enable the allowlist-based firewall inside the container
  --mount <host:cont>   Additional bind mount (read-only by default)
  --mount-rw <host:cont> Additional bind mount (read-write)
  --podman-arg <arg>    Pass additional argument to podman run
  --help                Show this help message

Environment variables:
  AGENT_SANDBOX_DATA    Base directory for per-client state
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
        --help)        usage ;;
        --client)      CLIENT="$2"; shift 2 ;;
        --agent)       AGENT="$2"; shift 2 ;;
        --image)       IMAGE="$2"; shift 2 ;;
        --resume)      RESUME=true; shift ;;
        --no-network)  NO_NETWORK=true; shift ;;
        --firewall)    FIREWALL=true; shift ;;
        --mount)       EXTRA_MOUNTS+=("-v" "$2:ro"); shift 2 ;;
        --mount-rw)    EXTRA_MOUNTS+=("-v" "$2"); shift 2 ;;
        --podman-arg)  EXTRA_PODMAN_ARGS+=("$2"); shift 2 ;;
        -*)            echo "Unknown option: $1" >&2; exit 1 ;;
        *)             PROJECT_DIR="$1"; shift ;;
    esac
done

if [ -z "$CLIENT" ]; then
    echo "Error: --client is required" >&2
    echo "Run with --help for usage information" >&2
    exit 1
fi

# Default project dir to current directory
PROJECT_DIR="${PROJECT_DIR:-$(pwd)}"
PROJECT_DIR="$(cd "$PROJECT_DIR" && pwd)"  # Resolve to absolute path

CONTAINER_NAME="agent-${CLIENT}-$(basename "$PROJECT_DIR")"

# -----------------------------------------------------------------
# Resume existing container
# -----------------------------------------------------------------
if [ "$RESUME" = true ]; then
    if podman container exists "$CONTAINER_NAME" 2>/dev/null; then
        echo "Reattaching to container: $CONTAINER_NAME"
        exec podman attach "$CONTAINER_NAME"
    else
        echo "No existing container found for client '$CLIENT'. Starting a new one."
    fi
fi

# -----------------------------------------------------------------
# Set up per-client data directories
# -----------------------------------------------------------------
CLIENT_DATA="${DATA_HOME}/clients/${CLIENT}"
mkdir -p "$CLIENT_DATA"/{claude,codex,config,history}

echo "Client data directory: $CLIENT_DATA"
echo "Project directory:     $PROJECT_DIR"
echo "Agent:                 $AGENT"
echo "Container:             $CONTAINER_NAME"

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
    # Mount per-client agent config and history (isolated from other clients)
    -v "$CLIENT_DATA/claude:/home/agent/.claude:Z"
    -v "$CLIENT_DATA/config:/home/agent/.config:Z"
    -v "$CLIENT_DATA/history:/home/agent/.local/share:Z"
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

if [ "$FIREWALL" = true ]; then
    # Start detached, apply firewall, then attach
    podman run -d "${PODMAN_ARGS[@]}" "$IMAGE" sleep infinity
    echo "Applying network firewall..."
    podman exec --user root "$CONTAINER_NAME" sudo /usr/local/bin/init-firewall.sh
    podman exec -it "$CONTAINER_NAME" "${CONTAINER_CMD[@]}"
else
    exec podman run "${PODMAN_ARGS[@]}" "$IMAGE" "${CONTAINER_CMD[@]}"
fi
