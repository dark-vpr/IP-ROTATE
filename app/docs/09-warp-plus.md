# Chapter 9 — The warp-plus Lane (Multi-Country WARP Egress)

`bepass-org/warp-plus` (v1.2.6) is an open-source Cloudflare WARP client that
fixes the single biggest weakness of plain WARP: **location**. Each instance
can exit in a chosen country (`--cfon --country XX`, 31 countries) or in a
different virtual NAT location (`--gool`, warp-in-warp). The lane runs N
instances, each with its **own WARP identity** and its own local SOCKS5 port,
and rotates countries **automatically** — so fresh IPs keep getting minted
even at a 10-second rotation interval.

Zero accounts, zero cards, zero logins. The only cost is UDP egress.

---

## 9.1 How the anti-exhaustion mechanism works

```
instance wp0  --cfon --country US   -> SOCKS 127.0.0.1:44000 -> egress A (US)
instance wp1  --gool                -> SOCKS 127.0.0.1:44001 -> egress B
instance wp2  --cfon --country DE   -> SOCKS 127.0.0.1:44002 -> egress C (DE)
instance wp3  --cfon --country JP   -> SOCKS 127.0.0.1:44003 -> egress D (JP)
```

When the pool runs low on selectable IPs (inside the no-reuse window):

1. The pool calls `warpplus.mint_new_ip()` (the "elastic mint").
2. The lane picks the instance whose egress IP is burned, **wipes its WARP
   identity** (`--cache-dir` removed -> a brand-new identity is registered
   on next start — one HTTPS call, no card), and respawns it with the
   **next country in the rotation** (US -> GB -> DE -> FR -> ... 31 total).
3. New identity x new country = an egress IP that has never been used.

Four instances cycling 31 countries at ~1 respawn/40s per instance is
roughly **350+ fresh IPs/hour** of mint capacity — comfortably above the
360/hour burn rate of a 10s interval. That is the whole answer to
"will it exhaust?" (see `docs/04-reliability.md`, IP economics).

Modes (`--warpplus-mode`):

| mode    | meaning                                              | egress diversity            |
|---------|------------------------------------------------------|-----------------------------|
| `auto`  | even instances = `cfon` country, odd = `gool` (mix)  | best spread (default)       |
| `cfon`  | every instance locked to a rotating country           | country control             |
| `gool`  | every instance warp-in-warp                           | NAT-location spread         |
| `plain` | raw WARP, no location tricks                          | same range as wireproxy WARP |

---

## 9.2 Quick start (uv + fish)

```fish
# one-time: the lane auto-downloads the binary on first use; to do it manually:
curl -LO https://github.com/bepass-org/warp-plus/releases/latest/download/warp-plus_linux-amd64.zip
and unzip warp-plus_linux-amd64.zip
and chmod +x warp-plus
and mkdir -p ~/.ip_rotator/warpplus/bin
and mv warp-plus ~/.ip_rotator/warpplus/bin/

# prove the lane works on YOUR network (handshake needs UDP):
cd ip-rotator
uv run ip-rotator warpplus --probe --instances 2
```

Expected output on a normal network:

```
warp-plus binary : /home/you/.ip_rotator/warpplus/bin/warp-plus
probing 2 instance(s) — needs UDP egress (WireGuard handshakes)...
  wp0 [cfon:US]: EGRESS 104.28.x.x via socks5://127.0.0.1:44000  OK
  wp1 [gool:]:   EGRESS 104.28.y.y via socks5://127.0.0.1:44001  OK

mint check: respawning wp0 with the next country in the rotation...
  wp0 respawned [cfon:GB]: EGRESS 104.28.z.z (NEW IP minted — country rotation works)

2/2 instances OK, 2 distinct egress IPs — engage the lane with: ip-rotator serve --warpplus 2
```

Then run the gateway with the lane engaged:

```fish
uv run ip-rotator serve --warpplus 4 --no-reuse-minutes 45
```

---

## 9.3 Verification (curl only)

With the gateway running, watch rotation through the lane:

```fish
# 6 requests, 10s apart, all must show DIFFERENT IPs:
for i in (seq 6)
    curl -s --max-time 25 --socks5-hostname 127.0.0.1:1080 https://checkip.amazonaws.com
    sleep 10
end
```

Any 104.28.0.0/16 (or 172.64.x/172.71.x) result is WARP-family egress —
Cloudflare edge IPs, some of the least-blocked shared IPs on the internet.

Mint activity is logged loudly:

```
WARN warp-plus MINT: wp2 [cfon:FR] -> 104.28.43.9 (fresh identity, next country in rotation)
WARN elastic mint via warp-plus country rotation: 104.28.43.9 (reason: no fresh IPs (timer))
```

---

## 9.4 Requirements & limits (honest)

* **UDP egress required.** WARP is WireGuard; handshakes are UDP. The
  binary registers identities over TLS/TCP (works anywhere), but no UDP =
  no tunnel. The lane detects this and **self-disables with a diagnosis**
  ("SOCKS never bound — WireGuard handshake incomplete"); other lanes carry
  traffic. Test with `ip-rotator warpplus --probe`.
* `--scan` (on by default here) probes for reachable WARP endpoints —
  helps on networks where only some CF endpoint IPs are routable.
* WARP egress ranges are shared CGNAT: **most** WAFs allow them (huge
  legitimate user base), a few block WARP specifically. If a target blocks
  WARP, rotate through the v2ray lane / Webshare / free-proxy pool instead —
  that is exactly why the gateway has multiple lanes.
* Identity wipes consume Cloudflare API calls — the lane rate-limits
  respawns (`warpplus_handshake_grace`) so it stays polite.
* No login, no API key, no credit card — nothing to configure.

---

## 9.5 Flags & config

CLI (serve):

| flag | meaning |
|------|---------|
| `--warpplus N` | enable the lane with N instances (recommend 4-6) |
| `--warpplus-mode auto\|cfon\|gool\|plain` | lane mode (default auto) |
| `--warpplus-bin PATH` | binary location override |

Config file (`config.json`) — see `docs/07-config.md` for the full list:
`enable_warpplus`, `warpplus_instances`, `warpplus_mode`,
`warpplus_countries`, `warpplus_socks_base_port` (default 44000),
`warpplus_scan`, `warpplus_handshake_grace`, `warpplus_download`.

Subcommand:

```fish
uv run ip-rotator warpplus --probe --instances 3   # live handshake + mint test
uv run ip-rotator warpplus                         # status summary
```
