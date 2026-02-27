#!/bin/bash
# init-firewall.sh — Restrict container network access to essential services only.
#
# This script is intended to be run as root inside the container via:
#   sudo /usr/local/bin/init-firewall.sh
#
# It implements a default-deny outbound firewall, whitelisting only the services
# required by coding agents (Anthropic API, OpenAI API, GitHub, npm registry, PyPI).
#
# When running under rootless Podman, iptables may not be available (depending on
# network mode). In that case the script exits gracefully — rootless Podman already
# provides user-namespace isolation.

set -euo pipefail
IFS=$'\n\t'

# Check if iptables is functional (may not be under rootless Podman slirp4netns)
if ! iptables -L -n &>/dev/null; then
    echo "INFO: iptables not available (expected under rootless Podman). Skipping firewall setup."
    echo "INFO: Container network isolation is provided by Podman user namespaces."
    exit 0
fi

echo "Configuring container firewall..."

# ---------------------------------------------------------------
# Flush existing rules
# ---------------------------------------------------------------
iptables -F
iptables -X
iptables -t nat -F 2>/dev/null || true
iptables -t nat -X 2>/dev/null || true
ipset destroy allowed-domains 2>/dev/null || true

# ---------------------------------------------------------------
# Allow essential traffic first
# ---------------------------------------------------------------
# Localhost
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# DNS (required for domain resolution)
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p udp --sport 53 -j ACCEPT

# SSH (for git operations)
iptables -A OUTPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

# ---------------------------------------------------------------
# Build whitelist of allowed destination IPs
# ---------------------------------------------------------------
ipset create allowed-domains hash:net

# Resolve and add allowed domains
ALLOWED_DOMAINS=(
    # Anthropic (Claude Code)
    "api.anthropic.com"
    "statsig.anthropic.com"
    # OpenAI (Codex)
    "api.openai.com"
    # GitHub
    "github.com"
    "api.github.com"
    "objects.githubusercontent.com"
    # Package registries
    "registry.npmjs.org"
    "pypi.org"
    "files.pythonhosted.org"
    # Sentry (telemetry)
    "sentry.io"
    "statsig.com"
)

for domain in "${ALLOWED_DOMAINS[@]}"; do
    echo "Resolving $domain..."
    ips=$(dig +noall +answer A "$domain" 2>/dev/null | awk '$4 == "A" {print $5}')
    if [ -z "$ips" ]; then
        echo "WARNING: Could not resolve $domain — skipping"
        continue
    fi
    while read -r ip; do
        if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            ipset add allowed-domains "$ip" 2>/dev/null || true
            echo "  Added $ip ($domain)"
        fi
    done <<< "$ips"
done

# If GitHub CLI is available, also add GitHub's published IP ranges
if command -v curl &>/dev/null; then
    echo "Fetching GitHub IP ranges..."
    gh_ranges=$(curl -sf https://api.github.com/meta 2>/dev/null || true)
    if [ -n "$gh_ranges" ] && echo "$gh_ranges" | jq -e '.git' &>/dev/null; then
        for cidr in $(echo "$gh_ranges" | jq -r '(.web + .api + .git)[]' 2>/dev/null | grep -E '^[0-9]'); do
            ipset add allowed-domains "$cidr" 2>/dev/null || true
        done
        echo "  Added GitHub IP ranges"
    fi
fi

# ---------------------------------------------------------------
# Allow host network (for Podman port forwarding)
# ---------------------------------------------------------------
HOST_IP=$(ip route 2>/dev/null | grep default | head -1 | cut -d" " -f3 || true)
if [ -n "$HOST_IP" ]; then
    HOST_NETWORK=$(echo "$HOST_IP" | sed "s/\.[0-9]*$/.0\/24/")
    iptables -A INPUT -s "$HOST_NETWORK" -j ACCEPT
    iptables -A OUTPUT -d "$HOST_NETWORK" -j ACCEPT
    echo "Allowed host network: $HOST_NETWORK"
fi

# ---------------------------------------------------------------
# Set default-deny policy
# ---------------------------------------------------------------
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow traffic to whitelisted IPs
iptables -A OUTPUT -m set --match-set allowed-domains dst -j ACCEPT

# Reject everything else with immediate feedback
iptables -A OUTPUT -j REJECT --reject-with icmp-admin-prohibited

echo "Firewall configuration complete."
