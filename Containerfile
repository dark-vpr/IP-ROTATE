# =============================================================================
#  ip-rotator v3.1.0 — rootless Podman container for WSL (Kali or any distro)
#
#  WHY THIS DESIGN (full research verdicts in RESEARCH.md):
#   * The tool's VPN lanes are USERSPACE (wireproxy / warp-plus / sing-box):
#     no TUN device, no NET_ADMIN, no systemd, no root. A rootless Podman
#     container is therefore enough — this is what makes it work in WSL
#     where host-side packages kept failing ("not found / not configured").
#   * Base image: python:3.12-slim (Debian bookworm + official Python).
#     - glibc, same ABI as Kali: everything the tool needs just works.
#     - Python is in the image already (the tool requires >= 3.9).
#     - ~130 MB, official library image, security-patched, reproducible.
#     - Alpine was rejected (musl edge cases), Kali base rejected (rolling,
#       huge, moving target — the exact opposite of a stable appliance).
#   * uv + uv.lock: the Python dependency set is pinned and reproducible.
#   * Lane binaries are baked in at /usr/local/bin BEFORE the app layer, so
#     editing app/ source and rebuilding does NOT re-download them.
#     (The tool also still auto-downloads into the mounted data dir if you
#     ever enable a lane whose binary is missing.)
#
#  BUILD:   ./build.sh
#           (equivalent: podman build -t localhost/ip-rotator:3.1.0 -f Containerfile .)
#  RUN:     ./run.sh
# =============================================================================

FROM docker.io/library/python:3.12-slim

ARG DEBIAN_FRONTEND=noninteractive

# --- system tools the tool actually shells out to (audited: no ps/ip/dig) ---
#   ca-certificates : TLS everywhere
#   curl            : image healthcheck
#   openssl         : WARP account registration (X25519 keygen)
#   tar, unzip      : runtime auto-download of lane binaries
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        openssl \
        tar \
        unzip \
    && rm -rf /var/lib/apt/lists/*

# --- uv, pinned (the app's Python deps are pinned by uv.lock regardless) ----
COPY --from=ghcr.io/astral-sh/uv:0.12.5 /uv /usr/local/bin/uv

# --- lane binaries (userspace, no root) — layer ordered before app/ on
#     purpose: app edits don't invalidate the binary downloads ---------------
ARG WIREPROXY_URL=https://github.com/pufferffish/wireproxy/releases/latest/download/wireproxy_linux_amd64.tar.gz
ARG WARPPLUS_URL=https://github.com/bepass-org/warp-plus/releases/latest/download/warp-plus_linux-amd64.zip
ARG SINGBOX_URL=https://github.com/SagerNet/sing-box/releases/download/v1.14.0/sing-box-1.14.0-linux-amd64.tar.gz
RUN set -eux; \
    mkdir -p /tmp/bin && cd /tmp/bin; \
    curl -fsSL "$WIREPROXY_URL" | tar xz; \
    curl -fsSL -o warp-plus.zip "$WARPPLUS_URL"; \
    unzip -oq warp-plus.zip; \
    curl -fsSL "$SINGBOX_URL" | tar xz; \
    mv -f sing-box-*/sing-box ./sing-box; \
    install -m 0755 wireproxy warp-plus sing-box /usr/local/bin/; \
    cd / && rm -rf /tmp/bin

# --- the tool itself ----------------------------------------------------------
WORKDIR /app
COPY app/ /app/
# uv sync reads app/uv.lock -> exact httpx/python-socks/rich versions,
# creates /app/.venv and the `ip-rotator` console script.
# dev group kept so the 116-test suite can run inside the container.
RUN uv sync --frozen && uv cache clean

# --- default config (run.sh bind-mounts the host-editable one over it) -------
# Container-tuned: frontends bind 0.0.0.0 so rootless podman can publish them
# (works since the B37 fix: file listen_host is no longer stomped by CLI
# defaults); wg-configs dir points at the mounted data dir; the user's
# Webshare static proxies + Proton wg confs ship in data/.
COPY config.container.json /app/config.json

# fail fast at build time if the CLI broke
RUN /app/.venv/bin/ip-rotator --help > /dev/null

ENV IP_ROTATOR_CONTAINER=1 \
    HOME=/root

HEALTHCHECK --interval=60s --timeout=15s --start-period=30s --retries=3 \
    CMD curl -fsS --max-time 10 -x http://127.0.0.1:8000 https://api.ipify.org >/dev/null 2>&1 || exit 1

ENTRYPOINT ["/app/.venv/bin/ip-rotator"]
CMD ["serve", "--config", "/app/config.json"]
