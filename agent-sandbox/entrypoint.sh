#!/bin/bash
# entrypoint.sh — Initialize a persistent home volume on first run.
#
# When run-agent.sh mounts a persistent volume over /home/agent, the
# image's home directory contents (Rust toolchain, npm packages, shell
# config, etc.) are hidden.  On first run we copy them from the saved
# template at /home/agent.skel into the persistent volume so that
# image-provided tools are available immediately and any runtime
# installs (extra crates, pip packages, etc.) survive container
# restarts.

if [ ! -f "$HOME/.home-initialized" ] && [ -d /home/agent.skel ]; then
    echo "First run: populating persistent home from image template..." >&2
    cp -a /home/agent.skel/. "$HOME/"
    touch "$HOME/.home-initialized"
fi

exec "$@"
