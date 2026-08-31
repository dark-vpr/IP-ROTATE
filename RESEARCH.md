# Research verdicts — containerization, images, tools, configs, Termux

This file records the conclusions behind every design decision in this
package. Written for the user (and for any future AI handed the zip — see
`AI_CONTEXT.md`).

---

## 1. Containerizing in rootless Podman INSIDE WSL — verdict: DO IT

The user's environment: WSL (Kali), where host-side installs of the tool's
dependencies kept failing ("packages not found / not configured"). Hard
constraint: **Podman runs inside WSL only** — never on the Windows host.

### Positives (why containerizing wins here)

1. **The failure class disappears.** Every dependency (python 3.12, uv,
   httpx/python-socks/rich, wireproxy, warp-plus, sing-box, openssl) is baked
   into the image at build time. The host needs exactly one package
   (`podman`) — and that one is a standard distro package that installs
   cleanly on Kali/Debian/Ubuntu WSL.
2. **Reproducibility.** `uv.lock` pins Python deps to exact versions; the
   `Containerfile` pins system packages and binaries. The same image builds
   and behaves identically today and in a year. "It worked yesterday" drift
   ends.
3. **No root, ever.** Rootless podman maps container-root to the normal WSL
   user. Nothing installs with sudo, no root-owned config files scattered in
   `~` — the exact source of the user's "I don't know which to configure"
   pain.
4. **No systemd dependency.** WSL often has systemd disabled or awkwardly
   enabled; podman is daemonless and the tool is a plain foreground process.
   wg-quick/systemd-unit confusion does not exist inside the container.
5. **Isolation of blast radius.** The tool's fail-closed drop-guard,
   blacklists, wireproxy children, sing-box processes — all live in the
   container's PID/net namespaces. A runaway lane cannot wedge the host
   network stack. Uninstall = `podman rmi` + delete one folder.
6. **State is explicit and host-owned.** `./data` (ledger, WARP accounts, WG
   configs, runtimes) is a bind-mount: inspect, back up, or reset the tool
   by touching files you can see.
7. **Lane architecture is natively container-friendly.** The tool's VPN
   lanes are *userspace* (wireproxy / warp-plus / sing-box → local SOCKS
   ports). They need no TUN, no NET_ADMIN, no root — a rootless container
   with default capabilities is fully sufficient.
8. **Snapshot/rollback.** `podman tag` before an experiment; `podman rmi`
   to revert. Host-level experiments have no such undo.
9. **Portability.** The same image runs on a future VPS, laptop, or any
   Linux box with podman — the WSL-specific pain never follows.
10. **Hygiene for credentials.** `.conf` private keys and API keys live in
    two host files (`data/`, `config.container.json`), not spread across
    `/etc`, `~/.config`, and package dirs.

### Negatives (honest costs)

1. **Rootless networking overhead.** slirp4netns/pasta add a userspace hop:
   typically ~10–30% throughput and a few ms latency vs native. For a
   rotation gateway this is negligible; for bulk downloads it is real.
2. **Extra ~400 MB disk.** Image + venv + binaries. Host install would be
   similar once you count uv + binaries; but it is *new* disk the user must
   accept.
3. **One more layer to debug.** When something fails, you now ask: host?
   podman? container? Mitigated: `status.sh`/`exec.sh doctor`/`shell.sh`
   give direct visibility, and logs are one command.
4. **No systemd = no boot autostart.** The container does not auto-start
   with WSL. Rootless restart-on-boot would need `podman generate systemd`
   + `loginctl enable-linger` — deliberately not shipped (documented trade
   off; start with `./run.sh`).
5. **Port publishing via userspace NAT.** Loopback publishing works well,
   but binding frontends on other interfaces or very high throughput
   scenarios are weaker than native.
6. **Build-time internet required.** First build pulls apt packages, PyPI
   wheels, and three GitHub release binaries. On air-gapped networks this
   needs a mirrored build (documented via `--build-arg` overrides).
7. **Windows-side tools can't use unix-socket features** — irrelevant for
   TCP frontends, listed only for completeness.
8. **vpn full-tunnel mode stays out** (see §5) — the one feature a
   container genuinely cannot own without TUN/caps/systemd.

**Verdict:** the pros map 1:1 to the user's reported failures; the cons are
all bounded, documented, or optional. Containerize — decisively.

---

## 2. Base image — verdict: `python:3.12-slim` (Debian bookworm)

| Candidate | Size | Verdict | Why |
|---|---|---|---|
| **python:3.12-slim** | ~130 MB | **chosen** | official Python on Debian bookworm (glibc). Python ≥3.9 required by the tool; 3.12 = the version the tool was developed and 105-test-verified on. glibc = same ABI as Kali, so every binary/wheel works. Docker-library maintained, security patches, tiny surface. |
| debian:12-slim + apt python3 | ~90 MB | fine, more steps | same foundation, but you hand-manage Python; python image is the same thing done officially |
| alpine:3.x + python3 | ~55 MB | rejected | musl: subtle DNS/resolver/wheel incompatibilities; PyPI wheels are glibc-first; saving 75 MB is not worth a class of edge cases in a network tool |
| kalilinux/kali-rolling | 400 MB+ | rejected | rolling = the build breaks whenever Kali shifts; mirrors are slow; a moving target is the opposite of an appliance |
| ubuntu:24.04 | ~80 MB | rejected | no advantage over Debian here; larger support surface |

**Binaries** baked in: `wireproxy` (userspace WireGuard→SOCKS), `warp-plus`
1.2.x (multi-country WARP), `sing-box` v1.13.19 (v2ray lane). All are
static Go binaries — they work on any base, which makes the base choice
purely about Python/ABI comfort.

**Python deps** via `uv sync --frozen` (uv.lock pins httpx, python-socks,
rich exactly; dev group kept so the test suite runs inside the container).

---

## 3. "Best of the best" tooling audit (does anything beat what we use?)

| Component | Current | Challenged by | Verdict |
|---|---|---|---|
| Container engine in WSL | podman (rootless) | docker Desktop on Windows | docker Desktop violates the constraint (installs outside WSL) and runs a VM + daemon. Rootless podman inside WSL is daemonless, root-free, distro-packaged. Podman stays. |
| WireGuard userspace | wireproxy | boringtun, wireguard-go + tun2socks | wireproxy already exposes SOCKS5 per tunnel with **zero** TUN/root/caps — purpose-built for exactly this lane shape. boringtun+userspace stack would need TUN (`/dev/net/tun`, NET_ADMIN) — strictly worse in rootless. wireproxy stays. |
| HTTP client (Python) | httpx[socks] | requests+PySocks, aiohttp | httpx: verified TLS by default, native SOCKS support, HTTP/2, sync+async — already the field's best practice. stays. |
| SOCKS client | python-socks | hand-rolled (was v1) | python-socks is the maintained, audited implementation; the hand-rolled client was replaced in v2 precisely for that reason. stays. |
| v2ray engine | sing-box | Xray-core | sing-box: single binary, sane config, outbound routing per lane, actively maintained. Xray has more transports but the tool only uses mainstream ones (tcp/ws/grpc/h2). sing-box stays. |
| WARP client | warp-plus | official cloudflare-warp (`warp-cli`) | warp-cli needs a system service + root; warp-plus is userspace with country rotation + identity reset (mint new IP). stays. |
| Terminal UX | rich | plain prints | rich already chosen upstream. stays. |

Nothing in the stack is superseded. The one *new* dependency the container
adds is uv itself — which is the current best practice for reproducible
Python projects and removes the "pip vs distro python" confusion entirely.

---

## 4. ProtonVPN: WireGuard `.conf` files vs the official CLI — verdict: `.conf` files

| Criterion | wg `.conf` (via wireproxy) | protonvpn-cli (official) |
|---|---|---|
| Root needed | **no** (userspace) | yes (system service, routes, NetworkManager/systemd hooks) |
| Works in rootless container | **yes** | no (systemd + polkit + TUN) |
| Login/credentials | none — keypair inside the file | browser OAuth login, stored session |
| Server switching | instant (one .conf per server, warm tunnels) | 10–30 s reconnect blip, machine-wide |
| Rotation granularity | per-tunnel / per-lane (fits the tool's design) | whole machine |
| Kill switch | lane-level (tool's fail-closed guard) | app-level (needs the service running) |
| Failure modes in containers | ~none relevant | many (service startup, polkit, TUN, resolvconf) |
| Auto server pick / load balancing | no (you choose servers when downloading) | yes |
| Free plan device limit | same 1-connection-per-account limit applies | same |

**Verdict:** inside a rootless container there is no contest — `.conf`
files. The CLI's advantages (auto server selection, app kill switch) are
desktop conveniences; its architecture (system service, root, TUN) is
incompatible with the container's constraint set. The tool's design already
agrees: the WG lane is built around `.conf` + wireproxy.

---

## 5. Full-tunnel `vpn` mode (and why it is not containerized)

`vpn` mode = route the *entire machine* through a VPN via `protonvpn-cli` /
`windscribe` / `openvpn` (VPN Gate). That requires TUN (`/dev/net/tun`),
`CAP_NET_ADMIN`, and typically a systemd/polkit environment — all things
rootless containers lack, and all things that would reintroduce exactly the
"which package do I configure" pain this package removes. The userspace WG
lane covers the clean-IP need per-tunnel; if machine-wide tunneling is ever
required, run that one mode on the host (or in a separate *rootful* podman
run with `--cap-add NET_ADMIN --device /dev/net/tun` — possible, but
deliberately out of scope here).

---

## 6. Termux compatibility — verdict: a separate Termux *app* is not feasible; a Termux *remote control* is

The question: can a **completely different, Termux-native version** of this
tool exist, and what are the cons?

**Core blocker:** this tool's lanes are all *userspace network clients*
(HTTP/SOCKS proxies, UDP WireGuard handshakes). Those work in Termux.
What does *not* exist in Termux: the ability to become a system VPN
(no TUN device, no `CAP_NET_ADMIN`, no netns) — not needed here — and the
ability to run arbitrary Linux binaries.

Cons list, exhaustively:

1. **Bionic libc, not glibc.** Prebuilt wireproxy/warp-plus/sing-box Linux
   binaries don't run; everything must be recompiled in Termux (Go
   cross-compiles, but you rebuild every release).
2. **No /dev/net/tun, no root.** Any future "real VPN" feature is dead on
   arrival. (The tool as designed doesn't need it — lucky, not portable.)
3. **Python friction.** Termux Python works, but pip wheels are often
   unavailable (compile-from-source for httpx's stack is usually OK, but
   it is a recurring tax).
4. **No namespaces/cgroups → no podman/docker.** No isolation layer, no
   reproducible environment — the whole "fix WSL packaging pain" value is
   unreachable in Termux.
5. **Android background killing.** Doze/OEM task killers murder long-running
   gateways unless the app holds a foreground service (needs a real Android
   app, not Termux) or the user babysits wakelocks/battery settings.
6. **Battery + thermal.** Continuous proxy validation = CPU + radio = heat.
7. **Portability of use.** A Termux gateway serves *the phone*; Burp on your
   laptop can use it only over adb-reverse/wifi with more setup.
8. **Ecosystem churn.** Termux packages break with Android updates; the
   Play-Store variant is abandoned (F-Droid/GitHub only).
9. **Filesystem sandboxing.** No shared `~` with a laptop workflow; state
   must be moved around manually.
10. **No systemd** — same lifecycle problem as containers, but with fewer
    workarounds.
11. **App-level VPN API unusable.** Android's VpnService (the *right* way to
    do a phone VPN) is a Java/Kotlin IPC API — a Termux CLI cannot use it.
    A "Termux version" can never graduate into a real phone-wide VPN.

**What IS sensible on Termux:** a thin **remote control** — SSH into the WSL
box from the phone (`pkg install openssh`) and run `./run.sh`, `./status.sh`
there. Zero porting, full feature set, and the gateway keeps running when
the phone is offline. If a *phone-native* VPN tool is ever wanted, that is a
separate Android-app project (Kotlin + VpnService + a WireGuard library),
not a port of this one.

---

## 7. "With one wg config, how many IPs do I get?"

Exact math for a ProtonVPN WireGuard `.conf`:

- **Inside the tunnel**: exactly **one** static private IPv4
  (`10.2.0.2/32`) + one IPv6 (`fd12:…::2/128`). Every Proton config uses
  the same internal address (it is NAT'd per-tunnel) — which is precisely
  why multiple tunnels must live in *separate* namespaces/containers (or
  run sequentially, like this tool's lane design does).
- **Outside (what websites see)**: exactly **one** public IP — the *shared*
  IP of the chosen server, shared with every other user on that server.
  It is not exclusive to you, and it does not change while you use that
  config.

So: **1 config = 1 egress IP.** Therefore:

| Goal | Configs needed |
|---|---|
| N distinct public IPs available simultaneously | N `.conf` files from N different servers (and, on free Proton, realistically N accounts — 1 active connection per account) |
| N IPs available one-after-another (rotation) | N `.conf` files, one active at a time — no extra accounts needed |

**Workarounds if you want more IPs without more configs:**

1. **Sequential rotation** (built in): the tool re-probes and rotates lanes;
   the never-reuse ledger (`no_reuse_seconds`) schedules when each config's
   IP comes back. One config still only ever offers its one server IP.
2. **Other free lanes = more IPs from zero configs**: WARP accounts
   (unlimited, auto-registered), warp-plus (31-country rotation, "mint"
   produces a never-seen IP), v2ray free nodes (hundreds of community
   egress IPs). The container ships all three; none need any login.
3. **Multiple accounts**: each dummy account adds its own configs (and its
   own 1-connection free limit). Within Proton ToS limits and abuse
   detection — temp-email signups are frequently blocked at registration;
   that is Proton's anti-abuse, not a tooling failure.
4. **Provider mixing**: Windscribe/PrivadoVPN `.conf` files drop into the
   same `wg-configs/` dir — the lane does not care whose config it is.

---

## 8. Provider facts — verified live, Aug 2026 (session 2)

Everything below was checked against the live web AND the user's own
accounts, not from memory:

| Provider | Claim | Verdict | Evidence |
|---|---|---|---|
| Windscribe | "WireGuard config needs an upgrade" (user report) | **TRUE** — config generators (OpenVPN/WireGuard/IKEv2) are Pro/Build-A-Plan only; free accounts cannot generate any manual config; SOCKS5 is Pro-only too | Windscribe support pages + multiple router-setup guides state it explicitly |
| PrivadoVPN | "no WireGuard option; only a SOCKS5 thing under Firewall" (user report) | **FALSE** — free plan supports WireGuard; the option lives at **web dashboard → Dashboard tab → scroll down → Manual Configuration → WireGuard** (the Firewall menu is unrelated) | PrivadoVPN KB article 1130 + their free-plan blog |
| Webshare | static `ip:port:user:pass` proxies work without the API key | **TRUE** — 10/10 verified live via SOCKS5 AND HTTP CONNECT with credentials, ~0.9–1.7 s egress latency | direct curl tests in this session |
| Proton VPN free | dummy-account WireGuard confs work headlessly | **TRUE** — 4–5 of 5 tunnels came up with distinct exit IPs (one server flaked a handshake and recovered on re-probe; expected on free tier) | live wireproxy runs in this session |
| Proton free "1 device" limit | multiple simultaneous tunnels from ONE account may be refused | observed as occasional per-tunnel handshake failures, NOT account bans — the lane's re-probe handles it; more simultaneous IPs still wants more (dummy) accounts | live observation |

**Windscribe "hashed key" note:** the `0x81273395...` string the user
supplied is not a login credential (hashes are one-way) and nothing in this
tool consumes such a token. Windscribe login = account username+password
(CLI `windscribe login`); WG configs are Pro-only anyway, so the provider is
out of scope under the no-payment condition.

**CRLF gotcha (worth remembering):** the user's webshare export had Windows
line endings — a trailing `\r` in the password field causes instant auth
failures that look like "all proxies dead". The new `static_proxies` parser
strips `\r`/whitespace (tested).

## 9. Session-2 additions to the tool (v3.1.0)

* **`static_proxies` config lane** (new): pasted authenticated proxies —
  webshare dashboard format `ip:port:user:pass`, or
  `scheme://user:pass@host:port` — validated with credentials preserved,
  CRLF-tolerant, revalidated every 10 min, doctor-reported. 9 new tests.
* **B37 fix** (see §8 of app/docs/08-issues.md): config-file
  `listen_host`/`listen_port` no longer stomped by CLI defaults — the bug
  that would have broken the container's `0.0.0.0` frontend binding.
* Container build trimmed & reordered: apt set reduced to the 5 packages the
  code actually shells out to (audited: no ps/ip/dig/ss/less usage); lane
  binaries downloaded in a layer BEFORE the app code (app edits no longer
  re-download ~40 MB of binaries); uv pinned to 0.12.5; run.sh simplified
  (default rootless networking — outbound UDP flows fine, only the two TCP
  frontends are published).
