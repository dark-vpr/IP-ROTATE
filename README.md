# ip-rotator — Podman container edition (rootless, inside WSL)

This package wraps the **ip-rotator v3.1.0** free-IP-rotation gateway in a
rootless Podman container that runs **entirely inside WSL**. It exists to fix
the exact problem you hit on WSL Kali — *"some packages are not found, some
were not configured"* — by baking **every** dependency (Python 3.12, uv,
httpx/python-socks/rich, wireproxy, warp-plus, sing-box, openssl, curl) into
one image. After one `apt install podman`, nothing else ever needs to be
installed or configured on the host.

Your own assets are preloaded and verified: **5 Proton WireGuard configs**
(dummy accounts, 4–5 live tunnels with distinct exit IPs observed in testing)
and **10 Webshare static proxies** (all verified working with credentials).
Nothing about the tool changes: same CLI, same lanes, same tests. The
container is just the environment. You get the gateway's two frontends on
your localhost as usual:

| Frontend | Address | Use |
|---|---|---|
| HTTP CONNECT proxy | `http://127.0.0.1:8000` | curl, browsers, scrapers |
| SOCKS5 (no-auth) | `127.0.0.1:1080` | Burp Suite |

Both are published **to loopback only** — nothing is reachable from other
machines.

---

## 0. What you need to get, from where (configs / usernames / passwords)

**Short version: your package already contains everything needed — the core
tool needs no accounts, and your 5 Proton configs + 10 Webshare proxies are
preloaded and verified.** The proxy-pool lane, the WARP lane (accounts
auto-registered, no email, no card), the v2ray free-node lane and the keyless
Firecrawl fetch lane all work with no login of any kind.

Status of every optional lane (provider facts **verified Aug 2026**):

| Lane | What it needs | Where to get it — login / download | Status in your package |
|---|---|---|---|
| Proxy pool + WARP + v2ray + Firecrawl | **nothing** | — | works out of the box |
| **Webshare static proxies** | `ip:port:user:pass` lines | dashboard.webshare.io → free signup (email, no card) → **Proxy → List** — select the 10, copy as `ip:port:user:pass` | **preloaded in `config.container.json` → `static_proxies` (all 10 verified live)** — no API key needed |
| Webshare API lane (alternative) | API key | same dashboard → **Account → API Key** | optional; static list covers the same proxies |
| **Proton VPN WireGuard** | `.conf` files, **no VPN username/password** | see §1 below | **5 configs preloaded in `data/wg-configs/`** (dummy accounts) |
| PrivadoVPN WireGuard (10 GB/mo) | `.conf` files | signup at **privadovpn.com** (email, no card) → log in to the **web dashboard** → **Dashboard tab → scroll down → Manual Configuration → WireGuard** → generate per server | verified available on free plan (Aug 2026); you just hadn't found the menu — it is NOT under Firewall |
| Windscribe WireGuard | — | — | **REMOVED — Pro/Build-A-Plan only** (verified Aug 2026: free accounts cannot generate WireGuard/OpenVPN configs; their SOCKS5 is Pro-only too). Your no-upgrade condition rules it out |
| ZenRows / ScrapingBee / Crawlbase / ScraperAPI | API keys | their dashboards (exact click paths in `app/docs/06-auth-guides.md` §6.8) | optional fetch lane |
| Proton VPN CLI (vpn mode) | Proton account, browser login | **NOT in the container by design** — see §6 | out of scope |

### 1. Proton VPN WireGuard configs — the exact click path (for more configs)

WireGuard configs are **key-based**: the `.conf` file contains an
auto-generated private/public key pair. There is **no VPN username or
password for WireGuard**. The only username/password in play is your
**Proton account login** (the email + password you signed up with), and you
only use it to log in to the website dashboard.

1. **Sign up / log in**: **https://account.protonvpn.com** (free plan is
   enough; email + password only, no card).
2. Left sidebar → **Downloads**.
3. Click **WireGuard configuration**.
4. Fill the form: name anything, platform **Linux**, pick **one** free
   server.
5. Click **Create** → the `.conf` downloads.
6. **Repeat steps 3–5 for every server** you want — one server = one
   `.conf` = one dedicated egress IP.

Drop extra `.conf` files into **`data/wg-configs/`** and restart:
`./stop.sh && ./run.sh`. Free-plan reality check: unlimited data, ~5
countries, **1 active VPN connection per account** — the tool re-probes and
self-disables dead tunnels (observed live: one Proton server occasionally
refuses a handshake, the lane recovers it on the next probe cycle).

> ⚠️ **Do NOT confuse with OpenVPN credentials.** The same Downloads page
> also shows an OpenVPN/IKEv2 **username** (like `vpnabc123`) + password.
> Those are only for OpenVPN/IKEv2 configs. This package never uses them.

---

## 2. Quick start (inside WSL)

```bash
# 0) one-time: install podman INSIDE WSL (the only host package you need)
sudo apt-get update && sudo apt-get install -y podman

# 1) build the image (~2-5 min, needs internet)
./build.sh

# 2) start the gateway
./run.sh

# 3) verify — three requests, expect (mostly) distinct IPs
./status.sh
```

From WSL **or Windows** (localhost is shared by WSL2):

```bash
curl -x http://127.0.0.1:8000 https://api.ipify.org
curl --socks5-hostname 127.0.0.1:1080 https://api.ipify.org
```

Burp Suite: *User options → Connections → Upstream Proxy Servers → add*
SOCKS proxy `127.0.0.1:1080` (full walkthrough in `app/docs/03-burp-suite.md`).

## 3. Everyday commands

| Command | What it does |
|---|---|
| `./build.sh` | build the image (re-run after editing `app/` source) |
| `./run.sh [serve flags…]` | start; extra args pass through, e.g. `./run.sh serve --warpplus 2 --v2ray --no-reuse-minutes 60` |
| `./stop.sh` | clean stop (state kept in `./data`) |
| `./status.sh` | container state + log tail + live IP checks through both frontends |
| `./exec.sh doctor` | the tool's own doctor, inside the container |
| `./exec.sh test` | the tool's built-in self-test (HTTP + SOCKS lanes) |
| `./exec.sh warp --register 4` | register 4 more free WARP accounts |
| `./exec.sh warp --probe` | spawn WARP tunnels, verify egress IPs |
| `./exec.sh api-status` | API-lane quota usage |
| `./shell.sh` | root shell inside the container (the full environment) |
| `podman logs -f ip-rotator` | follow the gateway log |

**Config**: edit `config.container.json` (mounted into the container), then
`./stop.sh && ./run.sh`. All fields documented in `app/docs/07-config.md`.

**Data that survives restarts** (host-side, in `./data`):
`state.db` (never-reuse ledger), `warp_accounts.json`,
`wg-configs/` (your `.conf` files), `wireproxy/`, `warpplus/`, `v2ray/`
runtime dirs.

## 4. How the container is wired

- **Rootless, zero capabilities**: the tool's VPN lanes are userspace
  (wireproxy = WireGuard-in-userspace exposing SOCKS5; warp-plus and
  sing-box likewise). No `/dev/net/tun`, no `NET_ADMIN`, no systemd, no
  root — that is exactly why it runs reliably in rootless Podman on WSL
  where host installs kept breaking.
- **Ports**: `run.sh` publishes `127.0.0.1:8000→8000` and
  `127.0.0.1:1080→1080`; the in-container config binds the frontends to
  `0.0.0.0` so rootless networking can forward them.
- **UDP**: WARP/WireGuard handshakes need UDP egress; rootless podman's
  slirp/pasta networking provides it on real machines (WSL included).
- **Image**: `python:3.12-slim` + uv-locked Python deps + wireproxy /
  warp-plus / sing-box baked at `/usr/local/bin`. Full rationale in
  `RESEARCH.md`.

## 5. VPN full-tunnel mode (protonvpn-cli) — deliberately NOT in the container

`vpn` mode routes the *whole machine* through a VPN. It needs TUN, NET_ADMIN,
and a working systemd/polkit stack — all hostile to rootless containers.
Inside this package the WireGuard lane (`.conf` + wireproxy) covers the
"clean Proton egress IP" need in userspace, per-tunnel, without hijacking
your routes. If you ever want machine-wide tunneling, run it on the host
directly — it is the one mode that belongs there.

## 6. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `podman: command not found` | podman not installed in WSL | `sudo apt-get install -y podman` (run inside WSL, not Windows) |
| build fails at `apt-get` | no DNS / offline | check WSL internet; `ping 1.1.1.1` |
| build fails at a GitHub URL | release URL changed | `podman build --build-arg WIREPROXY_URL=... -t localhost/ip-rotator:3.1.0 .` with a pinned URL |
| `status.sh` shows `fail` for all requests | gateway not up yet / died | `podman logs ip-rotator`; wait 30 s (harvest needs a moment); re-run `./status.sh` |
| same IP 3× in status | free pool exhausted this window | enable more lanes: WARP accounts (`./exec.sh warp --register 4`), warp-plus/v2ray in `config.container.json`, or drop `.conf` files in `data/wg-configs/` |
| `WG TUNNEL UP` never appears | UDP blocked on your network | `./exec.sh warp --probe` to diagnose; on blocked networks use the proxy/v2ray lanes |
| port 8000/1080 already in use | something on the host occupies it | `HTTP_PORT=18000 SOCKS_PORT=11080 ./run.sh` |
| `pasta`/`slirp` errors on very old podman | old rootless network stack | run.sh auto-retries with defaults; or upgrade podman |
| config edits don't apply | config is read at start | `./stop.sh && ./run.sh` |
| WARP lane disabled with UDP diagnosis | network blocks UDP | expected on hostile networks — lane self-disables, others keep working |

## 7. File map

```
ip-rotator-podman/
├── README.md                 ← you are here
├── RESEARCH.md               ← all research verdicts (pros/cons, image, wg-vs-CLI, Termux, IP math)
├── AI_CONTEXT.md             ← hand-off file: upload the zip to another AI, it reads this first
├── Containerfile             ← image recipe (rootless, userspace lanes)
├── .containerignore          ← build-context exclusions
├── build.sh  run.sh  stop.sh  status.sh  exec.sh  shell.sh   ← host-side lifecycle (run in WSL)
├── config.container.json     ← container-tuned config (edit me, no rebuild)
├── data/                     ← persistent state, mounted into the container
│   └── wg-configs/           ← drop Proton/Windscribe/PrivadoVPN .conf files here
└── app/                      ← ip-rotator v3.1.0 source (docs/ = full manual)
```

The tool's own documentation is inside `app/docs/` (01-install …
10-free-node-lane). Chapters 01/03/06/07 are the most useful ones; note that
host-install instructions in `app/docs/01-install.md` are superseded by this
container — you never install uv/wireproxy/etc. on the host anymore.
