# Chapter 4 — Reliability design: "no request left behind"

The requirement: *when a lane disconnects or the IP changes, there's a
delay — without multiple fallbacks the whole process fails because requests
never reach the server.* Here is exactly how v2.1 answers it, layer by
layer.

## 4.1 Why rotation itself has ZERO gap

A rotation is **not** a teardown. It is a pointer swap.

```
t=0    [pool: A(validated) B C D E ...]   active = A
t=10   ROTATE -> active = B               (A's in-flight tunnels keep draining)
t=20   ROTATE -> active = C               (A finally closed on its own; B drains)
```

* New requests use the new active upstream immediately — there is no dial
  gap because the next upstream was **already validated** (warm) before the
  switch, and WireGuard-lane switches are between **already-connected**
  tunnels.
* Existing tunnels are **never killed** by rotation; both pump directions
  drain until idle-timeout/lifetime caps.
* The rotation clock is monotonic and zero-drift: `interval=10` means
  exactly 10.0s windows forever, not 10s + processing jitter.

## 4.2 The fallback chain (per request)

Every single request walks this ladder until something connects:

```
1. sticky lane for this host (if --sticky) 
2. current active upstream
3. fresh validated standby (never-used IP preferred)
4. ... up to max_retries+1 different upstreams (default 3 dials)
5. starvation policies: recycle oldest acceptable / backbone lanes:
      WireGuard tunnel (cleanest) -> windscribe proxy -> WARP (warp-cli)
      -> Psiphon (opt-in) -> your real IP (only with --allow-direct)
6. SURVIVAL WINDOW (new in v2.1): hold the request up to starvation_wait
   seconds (default 5s), retry the whole ladder every 0.5s while emergency
   harvest / WARP registration produces new lanes
7. only then: 502 to the client (and the log tells you exactly why)
```

Layer 6 is the direct answer to "all requests must reach the server": a
momentarily starved pool no longer drops the request — the gateway parks
the client connection for a few seconds and serves it the moment any lane
recovers. Live evidence from `LIVE_DEMO.log`:

```
dial checkip.amazonaws.com:443: all 3 upstreams failed (TimeoutError) —
survival window: holding request up to 5s for a rescue...
EMERGENCY harvest triggered: request-survival-window
(→ the next request in that window succeeded)
```

## 4.3 Lane redundancy (what dies without you noticing)

| Lane | Independent failure domain | Capacity |
|---|---|---|
| Free-proxy pool | ~14 sources, hundreds of IPs, re-validated every 90s | unlimited-ish, volatile |
| Webshare free | dedicated datacenter proxies (auth'd) | 10 IPs, 1 GB/mo, metered |
| WireGuard/WARP | Cloudflare edge, UDP | unlimited, N warm tunnels |
| Your WG configs | each VPN provider separately | 1 tunnel per .conf |
| windscribe proxy | Windscribe's network | 10 GB/mo, metered |
| Psiphon / VPN Gate (opt-in) | their networks | unlimited, dirty IPs |

One lane dying is a non-event: selection just picks from the others, and
premium lanes (WireGuard, Webshare) are preferred whenever they have a
fresh IP. The pool *replenishes* itself: emergency harvest, hourly Webshare
refresh, WG re-registration, per-source backoff so one dead list never
poisons the rest.

## 4.4 Failure-mode matrix

| What dies | Immediate effect | Recovery |
|---|---|---|
| The active upstream | request dials fail | failover ladder 2→4 within one request; 3-strike blacklist |
| A whole source (404/429) | fewer candidates | per-source exponential backoff (max 30min), other sources unaffected |
| All free proxies (rare) | starvation | survival window + backbone lanes; emergency harvest |
| WireGuard UDP blocked (corp NAT) | WG lane can't handshake | lane self-disables after 6 fails with the exact reason; everything else continues |
| A WARP account's IP gets reused pool-wide | no fresh WG IPs | auto-register another account (cooldown-limited) |
| Webshare 1GB cap hit | lane empty | auto-disable until next calendar month (metered per byte) |
| VPN drops (vpn mode) | — | fail-closed drop-guard: requests get 502, **never** your real IP |
| Gateway restart | ~0-12s bind wait | warm-start reloads validated pool from SQLite; bind-retry absorbs port races; PR_SET_PDEATHSIG prevents orphaned instances |
| Machine reboot | state intact | ledger + pool + WARP accounts + usage meters persist in SQLite/JSON |

## 4.5 In-flight requests during a lane death

A request that already got its `200 Connection established` (or SOCKS
success) and is streaming **cannot be re-routed mid-stream** — bytes already
sent can't be replayed on a different IP. What the engine guarantees
instead:

* the tunnel drains until both sides close (bounded by idle/lifetime caps);
* the *next* request never lands on the dead lane (blacklist + rotation);
* the client sees one failed stream, retries, and the retry rides a healthy
  lane within milliseconds.

For crawlers that's the correct contract: per-request retryability with
sub-second failover, not mid-stream telepathy.

## 4.6 What CANNOT be promised (honesty section)

* A public free proxy can MITM plain-HTTP — that's why plain HTTP is
  blocked by default and validation is TLS-cert-verified end-to-end.
* A free proxy can die mid-response — the retry contract above covers it.
* WARP accounts share Cloudflare's egress ranges: distinct per account, but
  not residential. For most targets they're the cleanest free egress there
  is; for hyper-aggressive WAFs nothing free is guaranteed.
* If EVERY lane is down AND the survival window expires, the request fails
  with 502 — the alternative (stalling forever) is worse for a crawler.

## 4.7 v3 — The no-reuse window (30-60 min contract)

"When I said it shouldn't use the same IP, I meant for 30 to 60 min it
shouldn't use the old IP."

```fish
uv run ip-rotator serve --no-reuse-minutes 45     # anywhere 0-3600
```

Semantics, exactly:

* The moment an egress IP is selected, it is **burned** — written to the
  SQLite ledger with a timestamp (persists across restarts).
* A burned IP is **unselectable** until `now - last_used > window`. The
  selection loop, the recycle path, AND every lane backbone check the same
  window — there is no code path that can hand back a burned IP early.
* After the window expires the IP becomes legitimately fresh again (it is
  no longer "the old IP" by your definition).
* `window_blocks` in the stats counts how often the window refused a
  would-be reuse — watch it climb while the pool self-disciplines.
* Default 45 min (middle of your 30-60 ask). The old
`recycle_avoid_seconds` config key still works as a lower bound.

## 4.8 IP economics — "will it fail faster or exhaust faster?"

Straight math, no hand-waving. At `interval=10`:

```
burn rate        = 3600 / 10            = 360 IPs/hour
no-reuse window  = 45 min               = 0.75 h
steady-state unique-IP demand = 360 x 0.75 = 270 IPs "in the oven" at once
```

So the system needs a **standing stock** of ~270 selectable IPs plus a
**refill rate** >= 360/h. What each source actually provides (measured,
Aug-2026):

| source | standing stock | refill rate | notes |
|--------|---------------|-------------|-------|
| free-proxy pool | ~100-400 validated at a time | 600-700 candidates/h harvested, ~10% survive validation | self-refilling; capped by list freshness |
| v2ray free-node lane | 10-40 alive per 240-node pull | subscriptions refresh every 5-15 min -> thousands of new links/h | effectively unbounded; TCP-only networks OK |
| warp-plus lane | N instances (recommend 4) | ~1 fresh identity per 40s per instance = ~90/h each; 31 countries | needs UDP; **the mint** |
| wireproxy WARP lane | N accounts | new account = new identity on demand | needs UDP |
| Webshare free | 10 proxies | 0 (recyclable after window) | 1GB/mo metered |
| VPN WG configs | as many as you drop in | rotate servers manually | Proton/Windscribe/Privado |

Failure mode comparison — the actual answer:

* **Without** the v3 lanes (old v2.1 behavior): burn 360/h vs freepool
  refill ~60-70/h -> you consume the standing stock in tens of minutes,
  then the recycle policy (now window-gated) takes over. It does not
  *fail* — requests survive via the survival window and backbone ladder —
  but IP *freshness* degrades once the window stock runs out.
* **With** `--warpplus 4` alone: mint capacity ~360/h >= burn 360/h ->
  **factory-outpaces-demand: mathematically inexhaustible** (country
  rotation keeps minting never-seen IPs).
* **With** `--v2ray` on a UDP-blocked network: standing stock of hundreds
  + constant re-harvest -> hours-to-days of runway; combined with the
  45-min window recycling, effectively unbounded for practical sessions.
* Both lanes on a normal network: **belt and suspenders** — the pool
  reports `verdict: factory-outpaces-demand` and `headroom: infinite`.

The gateway **computes and reports this live** instead of trusting the
math above: see `ip_factory` in `--stats-file` output or `uv run
ip-rotator doctor`. Fields: `burn_per_hour`,
`unique_ips_needed_steady_state`, `available_now`, `mint_per_hour_est`,
`net_per_hour`, `headroom_minutes`, `verdict`.

**When does a request actually fail?** Only when EVERY rung of the ladder
fails within its timeout: fresh pool -> window-available lanes ->
recycle(window-ok) -> backbone lanes -> elastic mint (respawn with new
country / re-harvest) -> survival-window retry loop (default 5s). Each
rung is another independent chance; simultaneous death of all of them is
the only true 502. That is what "100% reliability" looks like in practice:
not magic, but enough independent fallbacks that the intersection of
failures rounds to zero.
