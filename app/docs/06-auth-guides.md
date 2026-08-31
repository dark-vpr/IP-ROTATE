# Chapter 6 — Auth & login guides (every service that needs anything)

Most lanes need **nothing**. This chapter covers the ones that do, in
fish-friendly copy-paste form.

## 6.1 WARP accounts — no login at all (verify it)

The WireGuard/WARP lane needs **no account, no email, no card**. One HTTPS
POST registers a fresh account; the tool does it for you:

```fish
uv run ip-rotator warp --register 4     # 4 free accounts, ~1s each
uv run ip-rotator warp --probe          # spawn tunnels, verify egress IPs
uv run ip-rotator warp                  # status: how many accounts stored
```

Accounts live in `~/.ip_rotator/warp_accounts.json` and survive restarts.
The only "authentication" is the X25519 keypair the tool generates per
account via openssl. Delete the file to start fresh.

## 6.2 Your own WireGuard configs (Proton / PrivadoVPN)

Any VPN that lets you download wg-quick `.conf` files works through
`--wg-dir`. Free tiers that do (all no-card, availability **verified
Aug 2026**):

### Proton VPN Free (unlimited data, ~5 countries)

1. Create a free account at **account.protonvpn.com** (email only, no card).
2. Dashboard → **Downloads → WireGuard configuration**.
3. Pick any free server (US/NL/JP/RO/...), click **Create**, save the
   `.conf` (e.g. `proton-us.conf`).
4. Repeat for a few servers = a few distinct egress IPs.

### PrivadoVPN Free (10 GB/month)

1. Sign up at **privadovpn.com** (email, no card).
2. Log in to the **web dashboard** → **Dashboard tab** → scroll down →
   **Manual Configuration** → **WireGuard** → generate a config per
   server. (It is NOT under the Firewall menu — that section is a
   different feature.)

### Windscribe Free — NOT usable for WireGuard

Verified Aug 2026: Windscribe's OpenVPN/WireGuard/IKEv2 **config
generators require a Pro or Build-A-Plan subscription**; free accounts
cannot download configs, and their SOCKS5 is Pro-only too. Under the
no-payment condition this provider is out (the CLI *proxy mode* in §6.4
still works on free, if you ever install the CLI on a host).

### Wire them up

```fish
mkdir -p ~/.ip_rotator/wg-configs
mv ~/Downloads/*.conf ~/.ip_rotator/wg-configs/

uv run ip-rotator serve --warp-accounts 3 --wg-dir ~/.ip_rotator/wg-configs
# log: WG TUNNEL UP: wg-proton-us -> egress 185.x.x.x (socks5 127.0.0.1:42003)
```

Each `.conf` becomes one warm tunnel = one lane with that VPN's egress IP.
Data caps are enforced by the VPN provider on their side; WG tunnels are
not byte-metered by us (Proton is unlimited anyway).

## 6.3 Webshare (10 proxies, 1 GB/mo, forever)

Two ways — either is enough:

**A. Paste the static proxy list (no API key):** in the dashboard
(**dashboard.webshare.io**, free plan, no card) open **Proxy → List**, copy
your 10 proxies as `ip:port:user:pass` lines and drop them straight into
`config.json`:

```json
{
  "static_proxies": [
    "31.59.20.176:6754:user:pass",
    "45.38.107.97:6014:user:pass"
  ]
}
```

Also accepted: `socks5://user:pass@ip:port` / `http://user:pass@ip:port`.
Windows CRLF line endings are handled. Credentials survive validation
(RFC 1929 / Proxy-Authorization); the lane revalidates every 10 min.
NOTE: this lane is not byte-metered by us — webshare counts its own
1 GB/month cap.

**B. API key (auto-refresh, metered):**

```fish
# 1) email signup at dashboard.webshare.io (NO card, plan: Free)
# 2) dashboard -> Proxy -> Endpoint? no:  Account -> API Key  (copy it)
# 3) put it in config.json:
```

```json
{
  "webshare_api_key": "PASTE_TOKEN_HERE"
}
```

```fish
uv run ip-rotator api-status       # shows: webshare ... configured, 0 MB / 1 GB
```

The lane self-refreshes hourly; bytes are counted and the lane disables at
1 GB until the next calendar month. Common API pitfalls handled: both
payload shapes (`port` as int or as `{http, socks5}` dict), token vs
bearer auth, `valid: false` rows skipped.

## 6.4 Windscribe CLI — proxy mode (opt-in lane, 10 GB/mo)

The CLI's proxy mode is a local SOCKS5 (default `:1080`) WITHOUT touching
your routes — perfect as a lane:

```fish
# 1) install the official CLI (repo: windscribe.com/guides/linux-cli)
sudo apt install windscribe-cli        # or your distro's package

# 2) login ONCE (free account from 6.2's Windscribe step)
windscribe login
windscribe account                     # confirm: FREE plan, no card

# 3) enable the lane
# config.json:
{ "enable_windscribe_proxy": true, "windscribe_proxy_socks_port": 1080 }
# (if our SOCKS5 frontend also uses 1080, change one of them!)
```

Location rotation (different IP, seconds not 30s):

```fish
windscribe proxy location US
windscribe proxy location DE
```

## 6.5 Proton VPN CLI (vpn mode, full tunnel)

```fish
sudo apt install protonvpn-cli         # official package
protonvpn-cli login                    # browser flow with your Proton account
protonvpn-cli status                   # verify: Plan: FREE

# rotate the whole machine through Proton free servers every 60s:
uv run ip-rotator vpn --provider proton --interval 60
```

Full-tunnel caveats (why this is a MODE, not a lane): machine-wide route
hijack, 10–30s reconnect blip per rotation, static IP per server.
The fail-closed drop-guard guarantees you NEVER leak your real IP if the
VPN silently drops — requests get 502 instead.

## 6.6 Hide.me CLI (vpn mode)

```fish
sudo apt install hide.me-linux-cli     # or download from hide.me/en/linux
hideme login                           # free account, no card
uv run ip-rotator vpn --provider hideme --interval 60
```

## 6.7 VPN Gate (opt-in dirty tier)

Needs `openvpn` + passwordless sudo. No account, no login, ever:

```fish
sudo apt install openvpn
# allow your user to run openvpn without a password prompt:
sudo visudo   # add:  youruser ALL=(root) NOPASSWD: /usr/sbin/openvpn

# config.json: { "enable_vpngate": true }
uv run ip-rotator vpn --provider vpngate --interval 120
```

The tool fetches the public server CSV, sorts by speed, writes the
server's inline config to a temp file, connects via `sudo -n openvpn
--config`, verifies the egress IP changed, and rotates servers on the
interval. Expect blocks on strict sites — volunteer egress.

## 6.8 Scraping-API keys (fetch lane)

| Provider | Where the key lives |
|---|---|
| ZenRows | dashboard.zenrows.com → API Keys (free plan, no card) |
| ScrapingBee | app.scrapingbee.com → API (1,000 one-time credits) |
| Crawlbase | crawlbase.com → Dashboard → Normal Token |
| ScraperAPI | dashboard.scraperapi.com → API Key (5,000 credits / 7 days) |
| Firecrawl | **nothing** — keyless, works instantly |

```json
{
  "api_keys": {
    "zenrows": "PASTE",
    "scrapingbee": "PASTE",
    "crawlbase": "PASTE",
    "scraperapi": "PASTE"
  }
}
```

```fish
uv run ip-rotator fetch https://example.com            # tries each in order
uv run ip-rotator fetch https://example.com --provider zenrows
uv run ip-rotator api-status                            # usage vs caps
```

## 6.9 Psiphon (opt-in, zero auth)

```fish
# download psiphon-tunnel-core for linux from github.com/Psiphon-Labs/psiphon-tunnel-core
# run it once: it listens on 127.0.0.1:1080 (SOCKS) + 8080 (HTTP)
# config.json: { "enable_psiphon": true }
```

If its 1080 collides with our SOCKS5 frontend, either move ours
(`--socks-listen 127.0.0.1:1081`) or move Psiphon's (`--localProxyPort`).
The gateway auto-detects which Psiphon port is alive.

## 6.10 Security notes on credentials

* `config.json` holds secrets — `chmod 600 config.json`.
* Webshare/WG credentials are injected **by the gateway**; your crawler
  never sees upstream creds (and Burp's SOCKS config needs none).
* The state DB (`~/.ip_rotator/state.db`) contains no credentials, only
  usage meters, the IP ledger, and blacklist rows.
