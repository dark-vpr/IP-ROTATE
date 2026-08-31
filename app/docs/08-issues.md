# Chapter 8 — Known issues & the complete bug log

## 8.1 Runtime issue catalog (what can bite, and the mitigation already in place)

### Authentication / credentials
1. **Burp's SOCKS config has no username/password fields** → gateway is
   no-auth on loopback by default and injects upstream creds itself
   (Webshare RFC 1929 / Proxy-Authorization).
2. **Webshare auth shape drifts** (token header, two port payload shapes) →
   parser handles both; creds survive validation, revalidation, failover
   and warm-start via `template` upstreams.
3. **Wrong SOCKS creds on our own frontend** → RFC 1929 reject + log line;
   curl shows it instantly (`curl --socks5 user:pass@...`).
4. **windscribe CLI not logged in** → `proxy on` fails; lane logs the exact
   fix (`windscribe login`), other lanes unaffected.
5. **sudo prompt for VPN Gate** → uses `sudo -n` (non-interactive); if sudo
   needs a password the provider is skipped with a log line, not a hang.
6. **WARP account registration is unauthenticated by design** → rate-limited
   (cooldown + cap 64) to stay polite; failures are retried on the next
   lane refresh.

### Limits / quotas
7. **Webshare 1 GB/month** → byte-metered through the relay (batched
   SQLite writes), lane auto-disables at cap, resets at calendar month.
8. **Windscribe/Hide.me 10 GB/month** → metered per provider in vpn/proxy
   modes; provider rotated at cap.
9. **Scraping-API credits** → every fetch metered per provider with monthly
   vs one-time periods kept separate; exhausted providers skipped.
10. **ip-api geo lookups 45/min** → 1.5s throttle + SQLite cache.
11. **Proxy-list source 429/5xx** → per-source exponential backoff to 30min,
    never blocking other sources.
12. **WARP account exhaustion (all 64 IPs used)** → ledger-driven; register
    more by clearing `warp_accounts.json` or raising the cap consciously.

### Reliability / fallback
13. **Mid-stream upstream death** → in-flight tunnels can't re-route;
    bounded drain, 3-strike blacklist, next request fails over in ms.
14. **Whole pool momentarily dead** → survival window holds requests up to
    `starvation_wait` (5s) while emergency harvest rescues; RESCUED logged.
15. **UDP blocked (WG lane dead)** → self-disable after 6 handshake fails
    with exact diagnosis; `warp --probe` to verify any network in 30s.
16. **Port collisions** (1080 Psiphon/windscribe vs our SOCKS; 8000 other
    apps) → validated at startup; graceful degradation + clear messages;
    bind-retry (12s) absorbs restart races.
17. **Gateway restart** → warm-start reloads the validated pool (up to 30min
    old), ledger/usage/WARP accounts persist; PR_SET_PDEATHSIG kills
    orphaned `uv run` children when the wrapper dies.
18. **max_tunnels exhaustion (scanner bursts)** → 503 with an actionable
    message instead of FD death; raise `--max-tunnels`.
19. **DNS leak** → hostnames always resolved AT the egress (socks5h /
    ATYP=domain; DoH for the direct lane); never the local resolver.

### Security
20. **MITM proxies** → TLS-verified validation end-to-end; cert failure =
    instant force-blacklist (no 3-strike grace).
21. **Transparent proxies (leak your IP)** → egress==real-IP check at
    validation AND selection; force-blacklist.
22. **Plain-HTTP rewriting** → plain HTTP refused by default (`--allow-http`
    to consciously accept).
23. **SSRF against internal ranges** → CONNECT targets filtered
    (loopback/RFC1918/link-local/metadata) unless `--allow-private`.
24. **Slowloris on the SOCKS frontend** → handshake timeout + strict length
    checks; malformed = drop.
25. **Real-IP exposure** → direct fallback only with `--allow-direct`,
    every use logged CRITICAL; vpn mode is fail-closed (502, never real IP).

## 8.2 Bug log — every bug found while building, and its fix

### v2.1 (this release)
* **B13 wireproxy config format changed** — old `WGConfig:` Go-style section
  makes wireproxy ≥1.0 `open ""` and die. New generator emits
  `[Interface]/[Peer]/[Socks5]` (live-verified with wireproxy 1.1.3).
* **B14 X25519 key format** — openssl emits PKCS#8 DER (48B); WireGuard
  wants the raw last 32 bytes. Unconverted: `key should be 32 bytes`.
* **B15 `Reserved` field removed from wireproxy** — WARP client_id bytes no
  longer supported AND no longer required; standard handshake works (wgcf
  approach), verified against the registration API.
* **B16 tunnel port drift** — sequential tunnel creation handed every
  tunnel the same base port (allocator didn't see siblings). Fixed with a
  per-pass taken-set; ports now deterministic across rebuilds/restarts.
* **B17 VPN Gate CSV column name** — API ships `CountryShort`, not
  `CountryCode`; parser now accepts both (caught by unit test).
* **B18 survival window never fired** — the deadline started at dial begin,
  but a 3×8s timeout chain already exceeded the 5s window, so it always
  expired instantly. Window now starts AFTER the first chain (observed
  live: request held, emergency harvest, RESCUED).
* **B19 sticky sessions silently diluted the 10s contract** — same-host
    crawls saw one IP for 60s. Sticky is now OFF by default (`--sticky` to
    opt in). Default = exactly what the spec says: new IP per window.
* **B20 bind race on restart** — `Address already in use` crash when the
  old process was still draining. Both frontends now retry the bind for
  12s with backoff (observed live).
* **B21 orphaned gateway under `uv run`** — uv doesn't forward SIGTERM to
  children; killing the wrapper left a live gateway holding 8000/1080
  (observed live). Fixed with Linux `PR_SET_PDEATHSIG` (child gets
  SIGTERM the moment uv dies) + graceful shutdown handlers.
* **B22 doctor UDP message over-promised** — DNS-over-UDP success was
  reported as "WG viable"; some networks only allow :53. Message now
  points to the definitive `warp --probe`.

### v2.0
* B1 `fresh_count()` iterated the validated dict without the lock (race).
* B2 `record_fail` ignored `Config.fail_threshold` (hardcoded 3).
* B3 partial HTTP CONNECT response treated as success → tunnel corruption;
  now requires full `\r\n\r\n`.
* B4 `used_ips()` full SQLite scan per request → in-memory cache with
  incremental updates.
* B5 fragile implicit `urllib.error` import chain → httpx.
* B6 hand-rolled SOCKS client edge cases → python-socks (rdns, IPv6,
  split handshakes), OSError contract preserved.
* B7 dropping `blacklist_minutes` silently reverted the default (caught by
  the test suite).
* B8 port-0 ephemeral validation false positive.
* B9 SOCKS5 domain ATYP double-recv.
* B10 frontend logic divergence → extracted shared `relay.py`.
* B11 `ProxyError` type mismatch across the failover path.
* B12 SOCKS/Psiphon port-1080 collision → graceful degradation + message.

### v1.x
* CONNECT early-bytes ordering; tunnel grace-close (thread leak); RLock
  deadlock in `_activate→fresh_count`; `record_fail` insert-or-ignore;
  `real_ip` guard in selection; fake-test-server TCP partial reads.

## 8.3 Test & verification ledger

* **65/65 offline tests** (`uv run python -m unittest discover -s tests`),
  including: RFC 1928/1929 SOCKS5 frontend, auth dialers, ledger
  semantics, sticky sessions, survival-window rescue + give-up, premium-tier
  preference, WG config generation (new format), wg-quick parser,
  X25519 raw-key conversion, account store persistence, deterministic
  tunnel ports, VPN Gate CSV parsing, windscribe lane shape.
* **Live-verified on this machine:** WARP registration API (HTTP 200 ×N,
  real accounts stored), wireproxy configtest PASS, dual front-ends
  serving **distinct never-used IPs every 10s window** (see
  `LIVE_DEMO.log`), survival-window rescue in the logs, WG lane
  self-disabling cleanly on this UDP-blocked sandbox, sticky opt-in
  behavior, bind-retry, doctor 14/14 sources.
* **Live-verified blocked here (by design of the sandbox, not the tool):**
  WireGuard handshakes need non-DNS UDP egress, which this sandbox drops —
  exactly the degradation path chapter 4 describes. On a normal network,
  run `uv run ip-rotator warp --probe` to see real WARP egress IPs.

## v3.0.1 verification ledger

* **105/105 offline tests** (`uv run pytest tests/ -q`), including the five
  new `TestShutdownHardening` cases: closed-DB degradation across every
  StateDB method, idempotent pool stop, frontends-stop-frees-ports,
  watchdog disarm, uTLS fingerprint whitelist coercion.
* **Shutdown repro (the B34 proof):** `serve --v2ray` + warmup + SIGTERM →
  BEFORE the fix: alive after 60s, orphaned children, ports held, log ends
  at "bye". AFTER the fix: exits at exactly the 25s watchdog budget (a
  validator was genuinely wedged — the log records
  "graceful shutdown exceeded 25s budget — forcing exit"), zero orphan
  processes, zero ports held, children reaped via pdeathsig.
* **v2ray lane at default scale (the B35 proof):** `--nodes 240` BEFORE:
  "new sing-box never bound its ports", 0 nodes. AFTER: lane UP in ~6s with
  53/240 nodes alive / 50 distinct egress IPs.
* **Full run-all smoke (`serve --warp-accounts 2 --warpplus 2 --v2ray
  --no-reuse-minutes 45`):** 5/5 windows served across both front-ends,
  4 distinct egress IPs (the one repeat is the same 10s window crossing
  front-ends — correct window semantics), clean SIGTERM shutdown.

## v3.0 bug log (found & fixed this round)

* **B23 — urllib has no SOCKS support.** The lane prototype used
  `urllib.request.ProxyHandler({"http": "socks5h://..."})`, which silently
  does nothing (urllib only speaks HTTP proxies). All 16 node probes
  "failed" with empty errors even though nodes were fine. Fix: probes go
  through the project's own dialer (httpx + python-socks). Caught live.
* **B24 — sing-box requires uTLS on Reality clients.** Nodes with
  `security=reality` but no `fp=` param made sing-box abort the whole
  config with "uTLS is required by reality client". Fix: parser always
  sets `tls.utls = {enabled: true, fingerprint: chrome}` for Reality.
  Caught live (1/9 worked before the fix — the one with fp= set).
* **B25 — one bad outbound kills the whole lane.** A single schema-invalid
  outbound makes `sing-box run` refuse to start, taking down all 240
  nodes. Fix: every outbound is validated with `sing-box check` on a mini
  config (parallel) BEFORE the big config is written; rejects are dropped.
* **B26 — port collision at lane regen.** Regenerating the sing-box config
  reuses the same port range -> bind conflict with the retiring process.
  Fix: A/B port sets (base and base+512) alternate at every regen; the old
  process is retired only after the new one is probed healthy. Verified
  live (ports 43513-43556 -> 43001-43023 swap in LIVE_DEMO_v3.log).
* **B27 — bad regen could kill a healthy lane.** If a fresh harvest
  produced 0 alive nodes (free nodes die in waves), the code committed the
  dead process and retired the proven one. Fix: bad-regen rollback — the
  old process keeps serving, the port set flips back.
* **B28 — misleading warp-plus diagnosis.** "SOCKS port never bound
  (crashed on start)" was wrong: warp-plus registers its identity over
  TLS/TCP fine on UDP-blocked networks and then waits forever for the
  WireGuard handshake, binding SOCKS only after it. Fix: message now says
  what's actually happening, and the bind wait uses
  `warpplus_handshake_grace` (25s) instead of a hardcoded 6s.
* **B29 — protocol-filter precedence bug.** `if ob and ob["type"] in protos
  or (...)` mixed `and`/`or` precedence; shadowsocks could slip through the
  filter un-intended. Fix: explicit normalize-then-check. Caught by self
  review during the build.
* **B30 — `find_binary` called as an unbound method.** WarpPlusInstance
  invoked `WarpPlusLane.find_binary(...)` (an instance method) from
  `build_args` -> TypeError. Fix: module-level `resolve_warpplus_bin()`
  with a process-wide cache; both the lane and instances use it.
* **B31 — window tests blocked by the legacy lower bound.**
  `effective_no_reuse = max(no_reuse, recycle_avoid=600s)` made sub-second
  test windows 10 minutes long, breaking recycle tests. Fix: tests pin both
  fields; semantics documented (max is intentional for old configs).
* **B32 — `pytest` was not a declared dependency (reproducibility bug).**
  The 100-test suite ran only on machines that already had pytest on PATH
  (the dev sandbox had it globally). On a clean machine `uv run pytest`
  resolved a foreign pytest with a different Python, then died with
  `ModuleNotFoundError: No module named 'python_socks'` because it wasn't
  running inside the project venv. Fix: pytest>=8 added to
  `[dependency-groups].dev` in pyproject.toml; `uv sync` now installs it,
  and `uv run pytest tests/ -q` passes 105/105 on a pristine checkout.
  Caught when the sandbox venv was rebuilt from scratch.

## v3.0.1 bug log (found live during final verification, fixed live)

Everything below was caught by the end-to-end smoke tests of the "run all"
command — nothing was assumed, everything was reproduced, py-spy'd, fixed
and re-verified.

* **B33 — closed state DB crashed mid-drain requests.** After SIGTERM the
  shutdown path closed the SQLite handle while the front-ends were still
  listening, so late requests hit
  `sqlite3.ProgrammingError: Cannot operate on a closed database` and the
  client got a traceback instead of a clean close. Fix (two layers):
  front-ends now stop accepting BEFORE the DB closes (see B34), and every
  StateDB method degrades to a safe default on a closed DB (reads return
  empty/false, writes are no-ops) so even a race can never raise.
* **B34 — serve could hang FOREVER after Ctrl-C/SIGTERM (the zombie
  bug).** py-spy proof: `MainThread` stuck in
  `concurrent.futures.thread._python_exit` → join → a `validator_N` worker
  blocked in `httpcore/_backends/sync.py read` inside
  `_init_socks5_connection`. httpx's `timeout=6` does NOT cover the SOCKS5
  greeting read (httpcore reads it on a socket with no timeout), so a
  proxy that accepts TCP but never answers wedges the worker thread
  permanently; interpreter shutdown joins non-daemon executor workers
  AFTER "bye" is printed, so the process never exits → zombie holds the
  ports → the next `serve` spends 12s in "Address already in use" and
  requests land in the half-dead old process. Compound fix:
  (1) front-ends are tracked and `shutdown()+server_close()`d FIRST (ports
  free immediately, nothing accepts into a torn-down process);
  (2) signal handlers only set a flag — all heavy teardown moved to the
  `finally` block; (3) lane teardown (wireproxy/warp-plus tunnels) is
  parallel, keeping worst-case teardown ~5s flat; (4) the feeder's
  ThreadPoolExecutor gets `shutdown(wait=False)`; (5) an exit watchdog
  (`os._exit(0)` after 25s, armed at signal, intentionally NEVER disarmed)
  guarantees the process always dies — verified live: with a genuinely
  wedged validator it exits at exactly the budget with zero orphan
  processes (children die via pdeathsig) and zero ports held. Same fix
  applied to `vpn` mode.
* **B35 — one bad v2ray node killed the ENTIRE lane at the default 240
  nodes.** Live repro: `v2ray --probe --nodes 240` → "new sing-box never
  bound its ports" while `--nodes 40` worked. Running the generated config
  manually gave the smoking gun:
  `FATAL create service: initialize outbound[183]: unknown uTLS
  fingerprint: unsafe`. Two defects: (a) the parser passed the node's
  `fp=` through verbatim — anything outside sing-box's accepted set
  (live-verified: chrome, firefox, edge, safari, 360, qq, ios, android,
  random, randomized) aborts the WHOLE process; (b) the per-outbound
  validation raced: all 16 workers wrote the SAME `check.json`, so a bad
  outbound could be "validated" against a neighbour's valid config.
  Fix: fingerprint whitelist (coerced to chrome) + one tempfile per
  worker. Also: sing-box's stderr is now captured to a file and the last
  line is included in the "never bound" warning (this bug was found
  precisely because the old message hid the real error), and the bind
  wait grew 8s → 12s. Verified: lane UP 53/240 nodes / 50 distinct
  egress IPs in 6s where it previously came up empty.
* **B36 — dead/MITM upstreams stayed in rotation after client-side TLS
  failures.** Smoke evidence: HTTP windows failed with NO gateway-side
  error logged — the CONNECT tunnel opened (so the retry chain never
  fired) but the upstream returned junk/cert-MITM that only the client's
  TLS verification could see. Fix: zombie-tunnel feedback in
  `relay.tunnel()` — when a tunnel relays <512 bytes back in <10s, the
  upstream gets a failure strike (3 strikes → blacklist, instant rotate
  away if it was the active one). Honest limits: a full MITM with a large
  forged cert is still only visible to the client (the gateway never
  breaks your TLS); the whitelist/rotation/mitigation layers make it
  statistically rare, and the clean lanes (WARP/v2ray/scraping-API) don't
  have this failure class at all.

## v3.0 runtime notes

* warp-plus and wireproxy lanes need **UDP egress**; both self-disable with
  a loud diagnosis on UDP-blocked networks, and `--v2ray` is the TCP-native
  alternative. `doctor` prints a UDP hint; `warp --probe` /
  `warpplus --probe` are the definitive tests.
* Free-node mortality is 70-90% per pull BY DESIGN (aggregators refresh
  every few minutes); the lane treats it as a fact of life — bulk validate,
  keep the healthy, re-harvest constantly.
* hysteria2 nodes are UDP/QUIC and are skipped unless `v2ray_udp_ok: true`.

## v3.1 container-edition fixes

* **B37 — config file `listen_host`/`listen_port` silently ignored by serve**
  (found live while container-testing, fixed live). `_cfg_from_args` injected
  hardcoded `127.0.0.1:8000` as overrides UNCONDITIONALLY, so a config
  FILE's `listen_host: "0.0.0.0"` never took effect — fatal in containers,
  where frontends must bind 0.0.0.0 for rootless port publishing (symptom:
  all HTTP frontend requests refused, SOCKS fine, server log showed port
  8000 despite config 18000). Fix: only override when `--listen` is actually
  passed; regression tests added (TestListenConfigPrecedence).
* **v3.1 feature — `static_proxies` config lane**: paste authenticated
  proxies (webshare dashboard `ip:port:user:pass` export, or
  `scheme://user:pass@host:port`) directly into config; validated with
  credentials preserved (RFC 1929 / Proxy-Authorization), CRLF-tolerant,
  revalidated every 10 min. Verified live with a real 10-proxy webshare
  export (10/10 egress-verified).
