#!/usr/bin/env bash
# =============================================================================
# build.sh — build the ip-rotator container image (rootless podman, in WSL).
# Run this INSIDE WSL (Kali/whatever) after installing podman there:
#   sudo apt-get update && sudo apt-get install -y podman
# =============================================================================
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

IMAGE="${IMAGE:-localhost/ip-rotator:3.1.0}"

fail() { echo "ERROR: $*" >&2; exit 1; }

command -v podman >/dev/null 2>&1 || fail "podman not found in PATH.
  Install it INSIDE WSL first:  sudo apt-get update && sudo apt-get install -y podman
  (On Kali rolling this is all it takes; the container then removes the need
   to install ANY other dependency on the host.)"

[[ -f Containerfile ]] || fail "Containerfile missing — run this from the package root"
[[ -f app/pyproject.toml ]] || fail "app/ source tree missing — re-unzip the package"

echo "[*] building image $IMAGE (needs internet: apt + PyPI + 3 GitHub releases)"
echo "    first build: ~2-5 min"
podman build -t "$IMAGE" -f Containerfile .

echo
echo "[+] image built: $IMAGE"
echo "[+] next:  ./run.sh"
