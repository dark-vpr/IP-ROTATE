#!/usr/bin/env bash
# =============================================================================
# run.sh — start the ip-rotator gateway container (rootless podman, in WSL).
#
# Usage:
#   ./run.sh                              # default: serve with config.container.json
#   ./run.sh serve --warp-accounts 4      # any serve flags are passed through
#   ./run.sh serve --v2ray --warpplus 2 --no-reuse-minutes 60
#
# Environment overrides:
#   IMAGE=localhost/ip-rotator:3.1.0      # image tag to run
#   NAME=ip-rotator                       # container name
#   HTTP_PORT=8000  SOCKS_PORT=1080       # host-side published ports (loopback only)
#
# Mounts (host -> container):
#   ./config.container.json -> /app/config.json (ro)   edit config on host, restart to apply
#   ./data                  -> /root/.ip_rotator (rw)  state.db, warp accounts, wg-configs/,
#                                                        wireproxy/warpplus/v2ray runtimes
#   ./data/wg-configs/      your Proton .conf files (5 dummy-account configs preloaded)
#
# Rootless by design: no capabilities, no devices, no host root. Outbound UDP
# (WireGuard/WARP handshakes) flows through the default rootless network
# (pasta/slirp4netns) without any extra flags; only the two TCP frontends are
# published, and to 127.0.0.1 only.
# =============================================================================
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

IMAGE="${IMAGE:-localhost/ip-rotator:3.1.0}"
NAME="${NAME:-ip-rotator}"
HTTP_PORT="${HTTP_PORT:-8000}"
SOCKS_PORT="${SOCKS_PORT:-1080}"

fail() { echo "ERROR: $*" >&2; exit 1; }

command -v podman >/dev/null 2>&1 || fail "podman not found in PATH — see ./build.sh header for the one-liner install"
podman image exists "$IMAGE" || fail "image $IMAGE not built — run ./build.sh first"
[[ -f config.container.json ]] || fail "config.container.json missing"
mkdir -p data/wg-configs

# fresh start if a stale container is in the way
if podman container exists "$NAME"; then
    if podman ps --format '{{.Names}}' | grep -qx "$NAME"; then
        echo "[*] container '$NAME' is already running:"
        echo "      logs:   podman logs -f $NAME      (or ./status.sh)"
        echo "      stop:   ./stop.sh                  restart: ./stop.sh && ./run.sh"
        echo "      shell:  ./shell.sh                 commands: ./exec.sh doctor"
        exit 0
    fi
    podman rm -f "$NAME" >/dev/null 2>&1 || true
fi

echo "[*] starting '$NAME' (rootless, no caps, ports on 127.0.0.1 only)"
podman run -d \
    --name "$NAME" \
    --init \
    --publish "127.0.0.1:${HTTP_PORT}:8000/tcp" \
    --publish "127.0.0.1:${SOCKS_PORT}:1080/tcp" \
    --volume "$(pwd)/config.container.json:/app/config.json:ro" \
    --volume "$(pwd)/data:/root/.ip_rotator:rw" \
    --env TZ="${TZ:-UTC}" \
    "$IMAGE" "$@" || fail "podman run failed — read the output above and see README.md troubleshooting"

sleep 5
echo "[*] log tail:"
podman logs --tail=25 "$NAME" 2>&1 || true
echo
echo "[+] gateway should be up.  From WSL or Windows (localhost is shared):"
echo "      curl -x http://127.0.0.1:${HTTP_PORT} https://api.ipify.org            # HTTP CONNECT frontend"
echo "      curl --socks5-hostname 127.0.0.1:${SOCKS_PORT} https://api.ipify.org   # SOCKS5 (Burp)"
echo "[+] next: ./status.sh | ./exec.sh doctor | ./shell.sh"
