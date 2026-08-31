# Chapter 5 — Lanes & providers (everything free / freemium, no card)

The gateway is a **lane stack**: every lane below is independent, validated
its own way, and selected by tier. Premium tiers win whenever they have a
fresh IP; the free-proxy pool is the unlimited workhorse; dirty tiers are
strictly opt-in.

## 5.1 Lane tiers

| Tier | Lane | Egress IPs | Data cap | Signup | Root? | Default |
|---|---|---|---|---|---|---|
| ★★★ | **warp-plus lane** (v3, multi-country WARP) | Cloudflare edge across **31 countries** + warp-in-warp | unlimited | **none** | **no** | on with `--warpplus N` |
| ★★★ | **Free-node v2ray lane** (v3, sing-box) | thousands of community nodes (vless/vmess/trojan/ss), datacenter | unlimited | **none** | **no** | on with `--v2ray` |
| ★★★ | **WireGuard / WARP accounts** (wireproxy) | Cloudflare edge, distinct per account | unlimited | **none** (API POST) | **no** | on with `--warp-accounts N` |
| ★★★ | **Your WG configs** (Proton/Windscribe/Privado, wg-quick `.conf`) | that VPN's servers | per VPN plan | VPN account (no card) | **no** | on with `--wg-dir DIR` |
| ★★☆ | **Webshare free** | 10 dedicated datacenter (auth'd) | 1 GB/month, forever | email + API key | no | on with key |
| ★★☆ | **Windscribe proxy mode** (opt-in) | 10 locations | 10 GB/month | account + CLI login | no | off (`enable_windscribe_proxy`) |
| ★☆☆ | **Free-proxy pool** | thousands, volatile | unlimited | none | no | **on** (engine) |
| ★☆☆ | **warp-cli backbone** | Cloudflare (single identity) | unlimited | none | yes (daemon) | auto if installed |
| DIRTY | **Psiphon** (opt-in) | shared, moderately flagged | unlimited | none | no | off (`enable_psiphon`) |
| DIRTY | **VPN Gate** (opt-in) | volunteer PCs, often flagged | unlimited | none | yes (openvpn+sudo) | off (`enable_vpngate`) |
| LAST | **Your real IP** | yours | — | — | — | off (`--allow-direct`, LOUD) |

Full-tunnel VPN CLI mode (`ip-rotator vpn`) is a separate low-frequency
rotation mode, not a lane: Proton Free (unlimited, ~5 countries),
Windscribe Free (10GB/mo), Hide.me Free (10GB/mo) — all no-card.

## 5.2 The WireGuard lane (v2.1 flagship)

**Why it exists:** the free-proxy pool has unlimited fresh IPs but volatile
quality; Webshare is clean but tiny. WARP accounts are the missing piece:
**free, unlimited, no card, no email, no login** — one HTTPS POST to
Cloudflare's client API registers an account and returns a complete
WireGuard identity (private key slot, peer, addresses). Each account = one
distinct egress IP at Cloudflare's edge.

**How it runs:** `wireproxy` (userspace WireGuard, single static binary, no
kernel module, **no root**) turns each account into a local SOCKS port:

```
warp0 -> 127.0.0.1:42000 -> egress 104.28.x.y   (warm, connected)
warp1 -> 127.0.0.1:42001 -> egress 104.28.z.w   (warm, connected)
wg-proton -> 127.0.0.1:42002 -> egress 185.x.x.x (your own .conf)
```

Rotation = pick a different **already-connected** port. No dial delay. No
teardown. No dropped requests. When every account's IP has been used, the
lane registers more (rate-limited, capped at 64).

**Reality checks (all live-verified while building this):**

* wireproxy ≥ 1.0 uses a NEW config format (`[Interface]/[Peer]` sections).
  The old `WGConfig:` style from blog posts makes it crash with
  `open : no such file or directory`. The tool generates the correct format.
* The old `Reserved = [...]` field (WARP client_id) is GONE from wireproxy
  and is not needed — WARP accepts standard WireGuard handshakes (the wgcf
  approach).
* openssl X25519 keys must be converted from PKCS#8 (48-byte DER) to the
  raw 32-byte key or wireproxy rejects them ("key should be 32 bytes").
  Handled automatically.
* WireGuard needs **UDP egress**. Cloud sandboxes / strict corp NATs often
  allow only UDP/53 — handshakes then never complete. The lane detects
  this (6 consecutive handshake failures), disables itself with that exact
  diagnosis, and other lanes carry traffic. Run `ip-rotator warp --probe`
  to check YOUR network in 30 seconds.

## 5.3 Free-proxy pool details

* Sources (14, all verified live Aug-2026): monosans (http/socks5/socks4),
  proxifly, TheSpeedX, roosterkid, hideip.me, clarketm, proxyscrape v2+v4,
  vakhov. Each source cached 240s + independent exponential backoff to 30min.
* Validation is end-to-end and hostile: TLS **certificate-verified** via
  httpx (a proxy that MITMs the check is force-blacklisted), true egress IP
  recorded through the proxy itself, transparent proxies (leak your real
  IP) force-blacklisted, optional country filter via ip-api (cached,
  throttled to free-tier limits).
* Selection prefers never-before-used egress IPs (SQLite ledger, persists
  across restarts); recycling prefers the LRU IP unused ≥600s, and prefers
  premium lanes (Webshare/WG) when recycling.
* Revalidation every 90s; entries older than 5min drop; 3 strikes (config)
  = 15min blacklist.

## 5.4 Webshare free (the authenticated clean lane)

10 datacenter proxies, **1 GB/month, forever, no card** — email signup,
then `dashboard.webshare.io → API → API Key`. Configure:

```json
{ "webshare_api_key": "tk_xxx" }
```

The lane pulls your 10 proxies hourly, validates them like any candidate
(creds preserved through revalidation/failover), authenticates via RFC 1929
(SOCKS) / `Proxy-Authorization` (HTTP CONNECT), counts every relayed byte
(batched), and auto-disables at the 1 GB cap until the calendar month
rolls. `ip-rotator api-status` shows usage.

## 5.5 Scraping-API fetch lane (metered last resort)

Their fleets rotate server-side, so they can't tunnel arbitrary CONNECT
traffic — they're a **fetch** lane (`ip-rotator fetch <url>`) for when
every proxy lane is dead, plus quota meters in `api-status`:

| Provider | Free tier | Refresh | Card? | Key |
|---|---|---|---|---|
| ZenRows | 5,000 credits | **monthly** | no | dashboard.zenrows.com |
| Firecrawl | 1,000 credits | monthly | no | **keyless** (works with no signup) |
| ScrapingBee | 1,000 credits | one-time | no | app.scrapingbee.com |
| Crawlbase | 1,000 requests | one-time | no | crawlbase.com (normal token) |
| ScraperAPI | 5,000 credits | 7-day trial | no | scraperapi.com |

## 5.6 Opt-in dirty lanes (reliable, but flagged egress)

Kept because they're reliable and free — OFF by default because their
shared/volunteer egress IPs get flagged by anti-bot systems. You opt in
consciously:

* **Psiphon** — free, unlimited, no root, no account. Local SOCKS/HTTP
  (`psiphon-tunnel-core`); `enable_psiphon: true`. Ports 1080/8080 collide
  with our frontends — change ours or its.
* **VPN Gate** — University of Tsukuba volunteer OpenVPN servers. Free,
  unlimited, no account; needs `openvpn` + sudo (full tunnel). Runs inside
  `ip-rotator vpn` mode (`enable_vpngate: true`); server list fetched from
  the public API, fastest-first, egress verified per connection.

## 5.7 Rejected on purpose (and why)

| Service | Why not integrated |
|---|---|
| **Tor** | exit nodes are the most mass-blacklisted egress class on the internet — the one hard exclusion that will not change |
| BrightData / Oxylabs / Smartproxy / IPRoyal trials | free *trial* ≠ free tier; all require a credit card |
| PrivadoVPN / TunnelBear / Hotspot Shield / Zoog / UrbanVPN / Riseup | no usable Linux automation path — **but** PrivadoVPN and any WG-config VPN work fine through the generic `--wg-dir` lane (see chapter 6) |
| Mullvad / AzireVPN | paid only (no free tier) |

Free consumer VPNs with Linux CLIs (Proton, Windscribe, Hide.me) are
integrated — as `vpn` mode / proxy lane / WG-config lane depending on what
each offers.

## 5.9 v3 lanes — the elastic IP factories

**warp-plus lane** (`--warpplus N`): N instances of bepass-org/warp-plus,
each = own WARP identity + SOCKS port; `--cfon --country XX` locks egress
to a country, `--gool` runs warp-in-warp. When the pool runs low the lane
wipes an identity and respawns it in the NEXT country — an unbounded mint
of never-seen IPs (~90/h per instance). Needs UDP. Full chapter:
[docs/09-warp-plus.md](09-warp-plus.md).

**Free-node v2ray lane** (`--v2ray`): the Telegram-channel-sourced
community-node ecosystem (~7,250 links at any moment, refreshed every
5-15 min by the aggregators; vless/reality, vmess, trojan, shadowsocks).
One sing-box process maps 240 warm local SOCKS ports to the best nodes.
TCP-based -> works where UDP is blocked. Datacenter egress, opt-in for
trust-sensitive traffic, MITM-blacklist protected by the same HTTPS
validation as everything else. Full chapter:
[docs/10-free-node-lane.md](10-free-node-lane.md).

**2026 landscape re-sweep (multiple research rounds, Aug 2026):** no
reliable no-CC free lane was missed — hide.me free (10GB) is already in
vpn mode recipes; Mullvad has no free tier; Atlas VPN was discontinued;
the genuinely new free supply is the community-node ecosystem (now
integrated) and WARP-over-country tooling (now integrated). PrivadoVPN
free (10GB/mo) rides the existing WG-config lane. Deep/dark-web-sourced
feeds all collapse into the same aggregators the v2ray lane consumes.
