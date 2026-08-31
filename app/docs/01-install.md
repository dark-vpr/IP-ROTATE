# Chapter 1 — Install (uv + fish)

Everything runs through [uv](https://docs.astral.sh/uv/) (≥ 0.4) and
[fish](https://fishshell.com/) (≥ 3.0). No system Python packages are
touched — the project owns a private `.venv`.

## 1.1 Get the prerequisites

```fish
# uv (if you don't have it yet)
curl -LsSf https://astral.sh/uv/install.sh | sh
exec fish    # reload PATH

# check
uv --version
```

Optional but recommended system tools (all free, all standard):

```fish
# openssl — needed to register free WARP accounts (usually preinstalled)
openssl version

# wireproxy — userspace WireGuard for the clean-IP WARP lane (no root!)
curl -L https://github.com/pufferffish/wireproxy/releases/latest/download/wireproxy_linux_amd64.tar.gz | tar xz
chmod +x wireproxy
sudo mv wireproxy /usr/local/bin/        # or: mkdir -p ~/.local/bin; mv wireproxy ~/.local/bin/
fish_add_path ~/.local/bin               # if you used ~/.local/bin
```

## 1.2 Install the project

```fish
cd ~/tools/ip-rotator     # wherever you unpacked it
uv sync                   # creates .venv + installs httpx, python-socks, rich, pytest (dev) + the CLI
```

Two ways to run it (both identical in behavior):

```fish
uv run ip-rotator doctor        # through the console script (recommended)
uv run python -m ip_rotator     # module form, same thing
```

Optional sanity check — run the offline test suite (105 tests, ~25 s, no
network needed beyond loopback):

```fish
uv run pytest tests/ -q         # expect: 105 passed
```

Tip — a fish abbreviation saves typing:

```fish
abbr -a ipr uv run ip-rotator
# from now on:  ipr serve   /   ipr doctor   /   ipr warp --register 4
```

## 1.3 The doctor

```fish
uv run ip-rotator doctor
```

Checks, in order: Python version, the three runtime deps, internet egress,
all 14 proxy-list sources, the SOCKS5 frontend config, `warp-cli`,
**wireproxy**, **openssl**, stored WARP accounts, your `wg_configs_dir`,
**UDP egress**, Psiphon, VPN CLI binaries, VPN Gate prerequisites,
Windscribe CLI, Webshare key, scraping-API keys, state DB. Everything
optional reports as "not installed" without failing the doctor — only
hard requirements (Python, deps, internet) can fail it.

Example healthy output:

```
ip-rotator 2.1.0 doctor
  python          : 3.12.14 (OK)
  dependencies    : httpx 0.28.1, python-socks 3.0.0, rich 15.0.0 (OK)
  internet        : OK (direct egress 47.57.242.119, 262ms)
  sources         : 14/14 reachable (OK)
  socks5 frontend : 127.0.0.1:1080 (no-auth, Burp-compatible)
  wireproxy       : /usr/local/bin/wireproxy
  openssl (x25519): present (WARP account registration ready)
  warp accounts   : 3 stored
  udp egress      : OK (DNS-over-UDP works; run `warp --probe` for the definitive test)
  ...
doctor PASSED
```

## 1.4 Upgrading / uninstalling

```fish
git pull            # or re-download + unpack
uv sync             # re-resolve deps (uv.lock pins exact versions)
```

Everything lives in two places: the project dir and `~/.ip_rotator/`
(state DB, WARP accounts, wireproxy runtime configs). Uninstall = delete
both.

## v3 binaries (all optional, all auto-download on first use)

The two v3 lanes download their own binaries into `~/.ip_rotator/*/bin/`
the first time you enable them — no sudo, no package manager:

| binary | lane | manual install (fish) |
|--------|------|----------------------|
| `warp-plus` v1.2.6 | multi-country WARP | `curl -LO https://github.com/bepass-org/warp-plus/releases/latest/download/warp-plus_linux-amd64.zip; and unzip warp-plus_linux-amd64.zip; and chmod +x warp-plus; and mkdir -p ~/.ip_rotator/warpplus/bin; and mv warp-plus ~/.ip_rotator/warpplus/bin/` |
| `sing-box` v1.13.19 | free-node v2ray | `curl -L https://github.com/SagerNet/sing-box/releases/download/v1.13.19/sing-box-1.13.19-linux-amd64.tar.gz | tar xz; and mv sing-box-*/sing-box ~/.ip_rotator/v2ray/bin/ 2>/dev/null; or begin; mkdir -p ~/.ip_rotator/v2ray/bin; and mv sing-box-*/sing-box ~/.ip_rotator/v2ray/bin/; end` |

Both lanes also accept an explicit path (`--warpplus-bin`, `--singbox-bin`)
or a binary already on `PATH`. Verify everything at once:

```fish
uv run ip-rotator doctor      # now checks both binaries + live node supply
```
