#!/usr/bin/env bash
# status.sh — one-shot health view of the running gateway.
# Shows: container state, log tail, and live egress checks through BOTH
# frontends (HTTP CONNECT :8000 and SOCKS5 :1080) with rotation evidence.
set -uo pipefail
NAME="${NAME:-ip-rotator}"
HTTP_PORT="${HTTP_PORT:-8000}"
SOCKS_PORT="${SOCKS_PORT:-1080}"

say() { echo; echo "=== $* ==="; }

say "container"
podman ps -a --filter "name=${NAME}" --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}' 2>/dev/null || echo "(podman error)"

say "log tail (last 20 lines)"
podman logs --tail=20 "$NAME" 2>&1 || echo "(container not running?)"

say "state (accounts / wg configs / db)"
echo "warp accounts : $(ls -1 data/warp_accounts.json 2>/dev/null | wc -l | tr -d ' ') file(s)"
echo "wg configs    : $(ls -1 data/wg-configs/*.conf 2>/dev/null | wc -l | tr -d ' ') .conf file(s)"
ls -1 data/wg-configs/*.conf 2>/dev/null | sed 's/^/                /'
echo "state db      : $(du -h data/state.db 2>/dev/null | cut -f1 || echo 'not created yet')"

say "egress via HTTP CONNECT frontend (127.0.0.1:${HTTP_PORT})"
for i in 1 2 3; do
    ip="$(curl -fsS --max-time 20 -x "http://127.0.0.1:${HTTP_PORT}" https://api.ipify.org 2>/dev/null || echo 'fail')"
    echo "  request $i -> $ip"
done

say "egress via SOCKS5 frontend (127.0.0.1:${SOCKS_PORT})"
for i in 1 2 3; do
    ip="$(curl -fsS --max-time 20 --socks5-hostname "127.0.0.1:${SOCKS_PORT}" https://api.ipify.org 2>/dev/null || echo 'fail')"
    echo "  request $i -> $ip"
done

say "hint"
echo "  distinct IPs across requests = rotation working. Same IP 3x = see README 'Troubleshooting'."
echo "  deep check inside:  ./exec.sh doctor      interactive:  ./shell.sh"
