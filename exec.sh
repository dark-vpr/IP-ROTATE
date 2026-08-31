#!/usr/bin/env bash
# exec.sh — run any ip-rotator subcommand INSIDE the running container.
# Examples:
#   ./exec.sh doctor
#   ./exec.sh test
#   ./exec.sh warp --register 4
#   ./exec.sh warp --probe
#   ./exec.sh api-status
#   ./exec.sh harvest
set -euo pipefail
NAME="${NAME:-ip-rotator}"

command -v podman >/dev/null 2>&1 || { echo "podman not found" >&2; exit 1; }
podman container exists "$NAME" || { echo "container '$NAME' not found — start it with ./run.sh first" >&2; exit 1; }

exec podman exec -it "$NAME" /app/.venv/bin/ip-rotator "$@"
