# AI_CONTEXT.md — hand-off file for any AI model receiving this zip

> **Purpose (user's request):** "add an extra file where it says what all was
> done and what all is implemented, such that uploading the whole zip with it
> to another model gives them full idea of the package." If you are an AI
> reading this, you now have the full picture. Start here, then read
> `README.md` (usage) and `RESEARCH.md` (decisions).

**Package:** ip-rotator v3.0.1 — Podman container edition
**Built:** 2026-09-01 · **State:** complete, syntax-checked; not yet built/run
on the user's WSL machine (that is the user's next step — see §7).

---

## 1. The user's situation (context you must keep)

- Environment: **WSL (Kali Linux)** on Windows. Host-side installs of the
  tool's dependencies repeatedly failed: "some packages are not found, some
  were not configured, I don't know which to configure."
- **Hard constraint:** Podman runs **INSIDE WSL only**. The user explicitly
  forbids suggesting podman/docker on the Windows host ("I can't install
  podman outside, for reasons I can't tell here"). Never propose it.
- Deliverable style: **English only.**
- The user may create **dummy ProtonVPN accounts via temp emails** for
  testing and has explicitly said real private keys inside those throwaway
  `.conf` files are fine to share.
- The underlying tool is `ip-rotator` v3.0.1 (history in §2) — the container
  edition wraps it without changing it.

## 2. What ip-rotator is (the tool inside the container)

A free & freemium (no-credit-card) **self-healing IP-rotation gateway**:
an HTTP CONNECT proxy (:8000) and a Burp-compatible SOCKS5 frontend (:1080)
that route each request through rotating egress IPs with a never-reuse
ledger, per-request failover, and multiple lanes: free-proxy pool (14
sources), **WARP** accounts (auto-registered via a keypair — no login),
userspace **WireGuard** tunnels from user-supplied `.conf` files
(Proton/Windscribe/PrivadoVPN via wireproxy → SOCKS), **warp-plus**
(multi-country WARP with IP "minting"), **v2ray free-node lane** (sing-box),
scraping-API fetch lane (ZenRows/Firecrawl/ScrapingBee/Crawlbase/
ScraperAPI), Webshare proxy lane, and opt-in full-tunnel `vpn` mode.
105 offline tests; v3.0.1 shipped after live-verified bug fixes (see
`app/docs/08-issues.md` for the full bug log B1–B36).

Development history (from the shared worklog): v1 free-proxy rotation
engine → v2 SOCKS5 frontend + Burp → v2.1 warm-tunnel WG lane + survival
window → v3.0 no-reuse window, warp-plus, v2ray lane → v3.0.1 shutdown
hardening + 4 live bugs fixed. Full evidence logs: `app/LIVE_DEMO.log`,
`app/LIVE_DEMO_v3.log`.

## 3. What THIS package adds (the containerization layer)

Everything below was implemented in this session:

| File | Role | Key implementation notes |
|---|---|---|
| `Containerfile` | image recipe | `python:3.12-slim`; apt: curl/openssl/unzip/dnsutils/etc.; uv copied from `ghcr.io/astral-sh/uv`; `COPY app/` + `uv sync --frozen` (uv.lock-pinned, dev group kept so the 105-test suite runs in-container); downloads wireproxy + warp-plus + sing-box into `/usr/local/bin` (URLs overridable via `--build-arg`); ships `config.container.json` as `/app/config.json`; healthcheck = curl through the HTTP frontend; `ENTRYPOINT /app/.venv/bin/ip-rotator`, `CMD serve --config /app/config.json` |
| `.containerignore` | build hygiene | excludes `data/`, `**/__pycache__`, logs, zips, `.venv` from the build context |
| `config.container.json` | container-tuned config (host-editable, bind-mounted) | frontends bind `0.0.0.0` (needed for rootless port publish; host side still only exposes 127.0.0.1); `state_path`/`wg_configs_dir`/`wireproxy_bin` pinned to in-container paths; WARP lane on with 3 accounts; warp-plus/v2ray off by default |
| `build.sh` | image build | preflight (podman present, sources present), `podman build -t localhost/ip-rotator:3.0.1 -f Containerfile .` |
| `run.sh` | start gateway | rootless `podman run -d` with `--init`; publishes `127.0.0.1:8000→8000` and `127.0.0.1:1080→1080`; bind-mounts `./config.container.json→/app/config.json:ro` and `./data→/root/.ip_rotator:rw`; extra CLI args pass through to `serve`; graceful retry with default networking if explicit slirp alias rejected; stale-container cleanup; tail logs + first status after start |
| `stop.sh` | clean stop | SIGTERM (t=20), rm container; state survives in `./data` |
| `status.sh` | health view | container state, log tail, counts of wg-configs/accounts, then 3 live egress requests through EACH frontend (HTTP CONNECT + SOCKS5) showing rotation |
| `exec.sh` | run tool subcommands in-container | `./exec.sh doctor` / `test` / `warp --register 4` / `api-status` … |
| `shell.sh` | root shell in-container | lands in `/app` — the full environment for the user's own tools |
| `data/` | persistent state (bind-mounted) | `state.db` (ledger), `warp_accounts.json`, `wg-configs/` (user drops `.conf` here), `wireproxy/`, `warpplus/`, `v2ray/` runtimes |
| `data/wg-configs/README.txt` | pointer | where to get `.conf` files and from where |
| `app/` | ip-rotator v3.0.1 source, unmodified | incl. `docs/01–10`, `tests/` (105), `uv.lock`, evidence logs |
| `README.md` | user manual | quick start, credential matrix (§0/§1: exactly where to login and download — see §5 below), commands, wiring, troubleshooting, file map |
| `RESEARCH.md` | all research verdicts | containerization pros/cons, base-image comparison, best-of-breed audit, wg-conf-vs-CLI, Termux feasibility, WG IP math |
| `AI_CONTEXT.md` | this file | cross-model hand-off |

**Design keystone:** the tool's VPN lanes are *userspace* (wireproxy,
warp-plus, sing-box). No TUN, no NET_ADMIN, no systemd, no root → a plain
**rootless** podman container suffices. This is why the container works
where the user's host installs failed, and why no capabilities/devices are
requested anywhere.

**Deliberately NOT containerized:** full-tunnel `vpn` mode (protonvpn-cli /
windscribe / openvpn machine-wide routing). It needs TUN + NET_ADMIN +
systemd; it belongs on the host if ever used. Documented in README §5 and
RESEARCH §4/§5.

## 4. Answers already given to the user (do not re-derive)

1. **"With one wg config, how many IPs?"** — 1 `.conf` = 1 internal IP
   (10.2.0.2/32 + IPv6, identical across all Proton configs, NAT'd per
   tunnel) + **1 shared public exit IP** (the server's). N distinct public
   IPs = N configs from N different servers. Workarounds: sequential
   rotation (ledger-driven), warp-plus IP minting (31 countries, no
   configs), v2ray community nodes, WARP accounts — all shipped in the
   image with zero logins. Multiple simultaneous Proton tunnels need
   multiple accounts on free (1 active connection per account).
2. **wg `.conf` vs ProtonVPN CLI** — `.conf` wins decisively in a rootless
   container (key-based, no login, userspace, per-lane); CLI needs root +
   systemd + TUN. Verdict + table in RESEARCH §4.
3. **Termux** — a Termux-native port is a dead end for the full feature set
   (bionic libc, no tun, no containers, background kills — full 11-item
   cons list in RESEARCH §6). Sensible Termux role: SSH remote control of
   the WSL box. A phone-native VPN would be a separate Kotlin+VpnService
   app project.
4. **Best-of-breed audit** — every component held up vs alternatives
   (RESEARCH §3); the only new dependency is uv (current best practice).
5. **Base image** — python:3.12-slim over alpine/kali/ubuntu, with reasons
   (RESEARCH §2).

## 5. Credentials: what exists, where it comes from (FAQ the user asked)

- **Core tool needs nothing** (proxy pool, WARP auto-registration, v2ray,
  keyless Firecrawl).
- **ProtonVPN WireGuard**: no username/password at all — the `.conf` carries
  an auto-generated keypair. The only login is the **Proton account**
  (email + signup password) at **https://account.protonvpn.com** →
  **Downloads → WireGuard configuration** → platform Linux → pick ONE free
  server → Create → download `.conf`. Repeat per server. The OpenVPN
  username/password on that same page is **not used** by this package.
- **Windscribe** `.conf`: windscribe.com → My Account → WireGuard Config
  Generator (account username+password or email).
- **PrivadoVPN** `.conf`: privadovpn.com → dashboard → Manual
  setup/WireGuard.
- **Webshare**: dashboard.webshare.io → Account → API Key →
  `config.container.json: webshare_api_key`.
- **Scraping-API keys**: dashboards listed in `app/docs/06-auth-guides.md`
  §6.8 (Firecrawl needs none).
- Dummy accounts via temp email: user pre-authorized sharing those
  `.conf`/keys for testing. Temp-mail domains are often blocked by Proton
  at signup (anti-abuse) — a signup failure there is expected behavior.

## 6. Verification status (what was and wasn't tested)

- Done here: all scripts written and `bash -n` syntax-checked; JSON config
  parsed/validated; package zipped. **Podman does not exist in the build
  sandbox** (`NO_PODMAN_HERE`), so the image was not built and the tool was
  not run in-container during this session.
- The wrapped tool itself is verified on disk: 105/105 tests, live demos
  (logs included in `app/`), v3.0.1 bug-fix ledger.
- Expected on the user's machine: `sudo apt-get install -y podman` →
  `./build.sh` (~2–5 min) → `./run.sh` → `./status.sh` shows 3 requests per
  frontend with rotating egress IPs. UDP-gated lanes (WARP/WG) additionally
  need UDP egress, which real WSL networks have (this sandbox didn't).

## 7. Open items / next steps for the receiving AI

1. User runs `./build.sh` + `./run.sh` on their WSL box; first error message,
   if any, is the next debugging input (`podman logs ip-rotator`).
2. If the user supplies dummy-account Proton `.conf` files (they offered —
   keys pre-authorized as throwaway), validate they parse with the tool's
   `parse_wg_quick` (`app/ip_rotator/warpwire.py`) and drop them into
   `data/wg-configs/`.
3. Optional hardening backlog (not requested yet): rootless systemd unit +
   `loginctl enable-linger` for auto-start; rootful sidecar container for
   full-tunnel vpn mode; pre-mirrored offline build.
4. If the user asks for edits: change `app/` source → re-run `./build.sh`;
   change behavior/config → edit `config.container.json` →
   `./stop.sh && ./run.sh`. No host changes are ever required beyond
   podman itself.

**Rule reminders when advising the user:** English only; never suggest
running podman outside WSL; the tool's lane architecture is userspace by
design — keep it that way.

---

## Session 2 (2026-09-01) — user assets wired in, live verification, B37 fix, optimization

**What the user provided this session** (in `upload/Download.zip`):
5 ProtonVPN WireGuard configs from dummy accounts
(`wg-CA-FREE-25`, `wg-MX-FREE-17`, `wg-NL-FREE-226`, `wg-US-FREE-154`,
`wg-US-FREE-92` — CA/MX/NL/US servers) + a 10-line Webshare static proxy
export (`ip:port:user:pass`, CRLF line endings). User reports: Windscribe
WG requires a paid upgrade ("violates our condition"); PrivadoVPN portal
seemingly had no WG option; a "hashed key" string for windscribe
(`0x81273395...` — NOT usable, hashes are one-way, nothing in the tool
consumes it). PrivadoVPN account credentials were shared but are NOT
embedded anywhere in the package (portal login only; use them at
privadovpn.com → Dashboard → Manual Configuration → WireGuard to generate
more configs).

**Verified live this session (all evidence reproducible):**
1. Webshare statics: **10/10 working** via SOCKS5 *and* HTTP CONNECT with
   user:pass auth (~0.9–1.7 s). First test round failed ONLY because of
   Windows CRLF `\r` in the password field — the new parser strips it.
2. Proton confs: **4–5/5 tunnels UP** with distinct exit IPs
   (195.242.214.68 CA, 205.147.22.37 MX, 190.2.152.224 NL, 138.199.52.196
   US-154, 149.22.80.122 US-92; one server flaked a handshake per run and
   recovered on re-probe — normal on free tier).
3. End-to-end serve demo with the user's assets: HTTP frontend 4 requests →
   4 distinct IPs; SOCKS5 frontend distinct IP; WG lane preferred in
   rotation; NL graceful failure handling.
4. Provider facts (web-verified Aug 2026): Windscribe config generators are
   Pro/Build-A-Plan-only (removed from the package); PrivadoVPN free DOES
   offer WireGuard at web-dashboard → Dashboard tab → scroll down → Manual
   Configuration → WireGuard (user just hadn't found it; Firewall menu is
   unrelated).

**Tool changes (app/ is now v3.1.0, container edition):**
- NEW `static_proxies` config field + lane: `pool.parse_static_proxy()`
  accepts `ip:port:user:pass` / `user:pass@host:port` /
  `scheme://user:pass@host:port` / `host:port`, CRLF-tolerant;
  `PoolManager._static_refresh` feeds entries through `_validate_one` with
  credentials preserved (template mechanism, same as webshare API lane),
  revalidating every 600 s; doctor reports parse status.
- **B37 fixed** (would have broken the container): `_cfg_from_args`
  unconditionally injected hardcoded `127.0.0.1:8000` listen overrides,
  stomping config-file values — container configs bind `0.0.0.0` and would
  have been reset to container-loopback, killing published ports. Now the
  override is None unless `--listen` is passed. Regression tests added.
- Tests: 105 → **116** (9 static-parser/lane + 2 B37 precedence).

**Package changes:**
- `config.container.json`: now includes the user's 10 webshare statics
  (CR-stripped) — package is turnkey without any API key.
- `data/wg-configs/`: the 5 Proton `.conf` files preloaded (renamed from
  `.conf.txt`; parser handles CRLF).
- `Containerfile` optimized: apt trimmed to ca-certificates/curl/openssl/
  tar/unzip (audited: the code shells out to nothing else); uv pinned
  (0.12.5); lane binaries moved to a layer BEFORE `COPY app/` so app edits
  don't re-download binaries; sanity RUN simplified. Image tag
  `localhost/ip-rotator:3.1.0`.
- `run.sh` simplified: dropped the slirp4netns alias + retry block (default
  rootless networking handles published TCP + outbound UDP fine).
- Removed from the package: `app/LIVE_DEMO.log`, `app/LIVE_DEMO_v3.log`
  (old evidence; current evidence lives in this file + chat), `__pycache__`,
  `.venv` before zipping.
- Docs updated: README §0 credential matrix (verified statuses, windscribe
  removed, privado exact path, webshare static lane), `app/docs/06` §6.2/6.3,
  `app/docs/07` static_proxies field, `app/docs/08` B37 entry, RESEARCH.md
  §8/§9, this file.

**Verification status after session 2:** 116/116 tests, doctor PASSED
(14/14 sources), live serve demo with user assets OK, 10/10 webshare
statics verified, 4–5/5 Proton tunnels verified. Still NOT buildable in
this sandbox (no podman) — the image build/run on the user's WSL remains
the user's step: `sudo apt-get install -y podman` → `./build.sh` →
`./run.sh` → `./status.sh`.

**New user assets NOT to leak into public shares:** the zip contains real
(throwaway) private keys and webshare credentials — the user explicitly
authorized this (dummy accounts, temp emails), but keep the zip private.
