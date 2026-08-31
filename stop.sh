#!/usr/bin/env bash
# stop.sh — cleanly stop and remove the ip-rotator container.
# State is NOT lost: everything persistent lives in ./data on the host.
set -euo pipefail
NAME="${NAME:-ip-rotator}"

if podman container exists "$NAME"; then
    podman stop -t 20 "$NAME" >/dev/null 2>&1 || true
    podman rm "$NAME" >/dev/null 2>&1 || true
    echo "[+] stopped and removed '$NAME' (state kept in ./data)"
else
    echo "(-) no container named '$NAME' is defined"
fi
