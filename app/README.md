# ip-rotator v3.1.0 — Free & Freemium (no card) Self-Healing IP-Rotation Gateway

One local gateway. Two front-ends. A **no-reuse window** (an IP stays burned
for 30-60 min, your choice). A **10-second rotation clock**. **Multiple
independent fallback lanes** — including two v3 elastic IP factories
(warp-plus country rotation + the community free-node lane) — so supply
never runs dry and no request is lost.

| Front-end | Default address | Use it from |
|---|---|---|
| HTTP proxy | `http://127.0.0.1:8000` | `curl -x`, Python requests, scrapy, most tools |
| SOCKS5 proxy | `127.0.0.1:1080` (no-auth) | **Burp Suite**, `curl --socks5-hostname` |

The full documentation lives in **[`docs/`](docs/)** — short chapters instead
of one giant wall of text:

| # | Chapter | What's inside |
|---|---|---|
| 1 | [Install (uv + fish)](docs/01-install.md) | `uv sync`, binaries, doctor |
| 2 | [Verify with curl](docs/02-verify.md) | 4 curl commands that PROVE rotation works |
| 3 | [Burp Suite setup](docs/03-burp-suite.md) | SOCKS upstream, DNS-through-proxy, Burp quirks |
| 4 | [Reliability design](docs/04-reliability.md) | zero-gap rotation, fallback chains, survival window, **no-reuse window, IP economics (will it exhaust?)** |
| 5 | [Lanes & providers](docs/05-providers.md) | every free/freemium (no-CC) lane, limits, tiers, what's rejected and why |
| 6 | [Auth & login guides](docs/06-auth-guides.md) | per-service: protonvpn login, windscribe login, webshare key, WARP accounts, WireGuard configs |
| 7 | [Config reference](docs/07-config.md) | every field in `config.json` |
| 8 | [Issues & bug log](docs/08-issues.md) | every known failure mode + every bug found & fixed |
| 9 | [warp-plus lane](docs/09-warp-plus.md) | multi-country WARP egress, **automatic country rotation** = never-seen IPs on demand |
| 10 | [Free-node v2ray lane](docs/10-free-node-lane.md) | thousands of community nodes via sing-box; works where UDP is blocked |

---

## Usage guide

Everything you need to run it lives here. All commands are **fish shell**;
all package commands go through **uv**. Working directory: the project root
(where `pyproject.toml` is).

### 1. One-time install

```fish
cd ~/tools/ip-rotator
uv sync                                # deps (httpx[socks], python-socks, rich) + CLI
uv run ip-rotator doctor               # sanity-check: internet, sources, lanes, UDP
```

`doctor` is safe to run any time — it prints a health report and exits.
Binaries (`wireproxy`, `warp-plus`, `sing-box`) are **auto-downloaded on
first use**; see [docs/01](docs/01-install.md) if you prefer manual install.

### 2. RUN ALL — every lane, full firepower

The one command you asked for. Four free WARP tunnels + four country-rotating
warp-plus instances + the community free-node lane, 45-minute no-reuse
window, new IP every 10 seconds:

```fish
uv run ip-rotator serve --warp-accounts 4 --warpplus 4 --v2ray --no-reuse-minutes 45
```

First run is slower (binary downloads + node probing). It prints one line
per rotation: window #, egress IP, lane used, pool depth. Leave it running
in a terminal — or start it detached:

```fish
# detached: survives terminal close, logs to file
nohup uv run ip-rotator serve --warp-accounts 4 --warpplus 4 --v2ray \
    --no-reuse-minutes 45 --stats-file ~/ip-rotator-stats.json \
    > ~/ip-rotator.log 2>&1 &

# stop it later
pkill -f "ip-rotator serve"    # also stops child tunnels (parent-death signal)
```

Prefer minimal first? This works with zero setup — no accounts, no binaries
(public SOCKS/HTTP pool + scraping-API free tiers):

```fish
uv run ip-rotator serve
```

### 3. Prove it works (second terminal)

```fish
# a different IP every 10 seconds, through the HTTP front-end:
for i in 1 2 3 4
    curl -s --max-time 25 -x http://127.0.0.1:8000 https://checkip.amazonaws.com
    sleep 10
end

# same through the SOCKS5 front-end (what Burp uses):
curl -s --max-time 25 --socks5-hostname 127.0.0.1:1080 https://checkip.amazonaws.com

# or let the tool test BOTH front-ends end-to-end for you:
uv run ip-rotator test
```

Point **Burp Suite** at SOCKS `127.0.0.1:1080` — 3-minute walkthrough in
[docs/03-burp-suite.md](docs/03-burp-suite.md).

### 4. Lane setup commands (one-time per lane)

```fish
# WARP/WireGuard lane — register free accounts (no card, no email, ~1s each)
uv run ip-rotator warp --register 4     # 4 accounts = 4 warm tunnels
uv run ip-rotator warp --probe          # prove tunnels work on YOUR network

# warp-plus lane — multi-country WARP egress (needs UDP; auto country rotation)
uv run ip-rotator warpplus --probe --instances 2

# free-node v2ray lane — community nodes via sing-box (TCP; works if UDP blocked)
uv run ip-rotator v2ray --probe --nodes 60

# check free-tier usage (Webshare + scraping-API lanes)
uv run ip-rotator api-status
```

Every probe command verifies **real egress IPs** and exits — run them before
relying on a lane.

### 5. Serve — the flags that matter

| Flag | Default | Meaning |
|---|---|---|
| `--interval N` | 10 | seconds per fresh IP |
| `--no-reuse-minutes N` | 45 | an IP stays burned for N min after use (0 = old behavior) |
| `--warp-accounts N` | 0 | N warm WARP tunnels (clean Cloudflare egress; recommend 3-6) |
| `--warpplus N` | 0 | warp-plus instances (multi-country, auto-rotation, needs UDP) |
| `--v2ray` | off | free-node lane via sing-box (TCP; biggest IP supply) |
| `--v2ray-nodes N` | 240 | max warm nodes in the lane |
| `--wg-dir DIR` | — | your own WireGuard configs (Proton/Windscribe/Privado free) |
| `--rotate-every-request` | off | fresh upstream per **connection**, not per window |
| `--sticky` | off | same host keeps its IP 60s (helps session-heavy sites) |
| `--listen H:P` | 127.0.0.1:8000 | HTTP front-end address |
| `--socks-listen H:P` | 127.0.0.1:1080 | SOCKS5 front-end (Burp) |
| `--socks-auth USER:PASS` | off | RFC 1929 auth on SOCKS5 (curl-compatible) |
| `--retries N` | 2 | extra failover attempts per request |
| `--policy {recycle,strict,backbone}` | recycle | what to do when no unseen IPs remain |
| `--allow-direct` | off | last-resort fallback to your REAL IP (flagged loudly) |

### 6. Recipes

```fish
# faster clock — new IP every 5 seconds
uv run ip-rotator serve --interval 5

# your 30-60 min ask, pinned to 60
uv run ip-rotator serve --no-reuse-minutes 60 --warpplus 4 --v2ray

# one-shot: harvest + validate the public pool, print results
uv run ip-rotator harvest --limit 20

# metered last-resort fetch through scraping-API free tiers (Firecrawl etc.)
uv run ip-rotator fetch https://example.com --provider firecrawl

# low-frequency full-tunnel mode via free VPN CLIs (Proton/Windscribe/Hide.me)
uv run ip-rotator vpn --provider auto --interval 60
```

### 7. Run the test suite (116 tests, offline)

```fish
uv run pytest tests/ -q        # pytest ships via `uv sync` (dev group) — nothing extra to install
```

Full flag list: `uv run ip-rotator serve --help` · every config-file field:
[docs/07](docs/07-config.md).

---

## What's new in v3.0

* **No-reuse window (`--no-reuse-minutes`, default 45)** — an egress IP is
  burned for 30-60 min (your call) after use, enforced in every selection
  path, persisted across restarts. After expiry it's honestly fresh again.
* **warp-plus lane** — multi-country WARP egress (bepass-org/warp-plus,
  31 countries + warp-in-warp). When supply runs low the lane **wipes an
  identity and respawns it in the next country automatically** — the
  elastic mint that keeps the 10s clock fed forever. See
  [docs/09](docs/09-warp-plus.md).
* **Free-node v2ray lane** — ~7,250 community nodes (vless/reality, vmess,
  trojan, ss) refreshed every few minutes, mapped to warm local SOCKS ports
  by ONE sing-box process (A/B port-set swaps, zero dark time). The biggest
  free IP supply that exists, and it rides TCP so it works where WireGuard
  can't. See [docs/10](docs/10-free-node-lane.md).
* **IP-factory telemetry** — `ip_factory` in stats/doctor computes burn rate
  vs mint capacity live and answers "will it exhaust?" with numbers:
  `factory-outpaces-demand` / `healthy` / `tight`. See
  [docs/04 §4.8](docs/04-reliability.md).
* **Landscape re-researched (Aug 2026, multiple rounds)** — nothing reliable
  was missed: hide.me already in (vpn mode), Mullvad has no free tier,
  Atlas VPN is dead; new supply is all in the node/VPN-over-TCP ecosystem.

Verified: **116/116 offline tests** + live evidence (`LIVE_DEMO_v3.log`):
8/8 windows served distinct never-used IPs through both front-ends,
no-reuse window actively blocking (17 refusals counted), v2ray lane UP with
real egress IPs, warp-plus lane correctly diagnosing a UDP-blocked network.

### v3.0.1 — shutdown & lane-hardening fixes (found live, fixed live)

* **B34 — serve could hang forever after Ctrl-C/SIGTERM** (py-spy proof in
  the bug log): a validator thread wedged in an un-timeout-able SOCKS5
  greeting read blocked interpreter shutdown AFTER "bye" — zombie held the
  ports, next serve hit "Address already in use". Fix: front-ends stop
  accepting first, lane teardown is parallel, and a hard-exit watchdog
  guarantees the process ALWAYS dies within ~25s. Verified: exit at exactly
  the budget with zero orphans and zero ports held.
* **B35 — one bad node killed the whole v2ray lane**: nodes advertising
  `fp=unsafe` (uTLS) aborted ALL 240 inbounds with one FATAL, and a shared
  `check.json` race let bad nodes pass validation on a neighbour's PASS.
  Fix: fingerprint whitelist (live-verified against sing-box v1.13.19) +
  per-worker tempfiles. Verified: lane UP 53/240 nodes / 50 distinct IPs
  where it previously came up with zero.
* **B36 — dead/MITM upstreams stayed in rotation after client-side TLS
  failures**: the CONNECT tunnel "succeeded" so no failover fired; only the
  client saw the junk. Fix: zombie-tunnel feedback — a tunnel that returns
  <512B in <10s now strikes the upstream (3 strikes → blacklist, same as
  any other failure).

### Still here from v2.1

* **WireGuard lane** — N warm userspace tunnels (wireproxy, **no root**),
  each = one local SOCKS port = one **distinct clean Cloudflare-edge egress
  IP**. Fuel: free WARP accounts (one HTTPS POST each) and/or your own
  WireGuard configs (Proton/Windscribe/PrivadoVPN Free — `--wg-dir`).
* **Request survival window** — when an entire fallback chain fails, the
  gateway *holds the request* (default 5s) retrying all lanes instead of
  instantly returning 502. "Multiple fallbacks so no request is lost."
* **Sticky sessions (opt-in)** — `--sticky` keeps each target host on its
  lane for 60s while everything else rotates.
* **VPN Gate + Psiphon (opt-in dirty tier)**, **Windscribe proxy-mode lane**,
  **bind-retry + parent-death signal** (no orphaned `uv run` children).

## Hard rules this tool obeys

* **Never Tor, never heavily-blacklisted pools by default** — Tor is
  removed entirely; VPN Gate / Psiphon are opt-in with loud warnings.
* **Free and freemium only; freemium never requires a credit card** — every
  lane's signup requirements are documented in
  [docs/05-providers.md](docs/05-providers.md).
* **No IP reuse inside the window** — persistent SQLite ledger across
  restarts; default 45 min (`--no-reuse-minutes`).
* **A new IP every N seconds (default 10)** — zero-drift monotonic clock;
  in-flight tunnels drain gracefully instead of being killed.

Python ≥ 3.9 · deps: `httpx[socks]`, `python-socks`, `rich` (uv-managed) ·
external best-in-class: `wireproxy` (userspace WireGuard), `warp-plus`
(multi-country WARP), `sing-box` (universal proxy client), `openssl`
(X25519 keygen). MIT license.
