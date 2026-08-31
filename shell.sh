#!/usr/bin/env bash
# shell.sh — open a root shell INSIDE the running container (the tool's
# environment, with all its deps preinstalled). No sudo needed: in a
# rootless podman container, "root" maps to your normal WSL user on the host.
set -euo pipefail
NAME="${NAME:-ip-rotator}"

command -v podman >/dev/null 2>&1 || { echo "podman not found" >&2; exit 1; }
podman container exists "$NAME" || { echo "container '$NAME' not found — start it with ./run.sh first" >&2; exit 1; }

exec podman exec -it "$NAME" bash -c "cd /app && bash"
