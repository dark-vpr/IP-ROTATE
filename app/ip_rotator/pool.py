"""PoolManager — the brain.

Threads:
  * harvester   — fetches candidate proxies from all sources (cache + backoff)
  * feeder      — feeds candidates into a validation ThreadPoolExecutor and
                  revalidates ageing entries so the pool never goes stale
  * rotator     — swaps the active upstream every `interval` seconds
                  (monotonic clock => zero drift), ALWAYS preferring an
                  egress IP that has never been used before (SQLite ledger)

Guarantees:
  * never reuse an egress IP while unseen ones exist (persists across restarts)
  * per-request failover across validated standbys
  * 3-strike (configurable) blacklisting, MITM detection,
    transparent-proxy rejection
  * backbones (WARP, opt-in Psiphon, guarded direct) engaged only when
    starving — loudly flagged

v2 bug fixes over v1 (see README "Bug log"):
  * fresh_count() iterated the validated dict WITHOUT the lock -> occasional
    "dictionary changed size during iteration" crashes under load. Now locked.
  * used_ips() was a full SQLite table scan on EVERY selection; the used-IP
    set is now cached in memory and updated on every mark (invalidated on
    ledger reset). Big win at 100k+ ledger rows.
  * record_fail now honors Config.fail_threshold.
  * Validation MITM detection works through httpx's exception chain.
"""
import concurrent.futures
import random
import threading
import time
from collections import deque
from typing import Dict, List, Optional, Set, Tuple

import httpx

from . import dialer
from .dialer import Upstream, fetch_egress_ip, is_tls_verification_error
from .apiproviders import WebshareClient
from .providers import (PsiphonProvider, WarpProvider, WindscribeProxyProvider,
                        geo_lookup)
from .state import StateDB
from .v2raylane import V2RayLane
from .warpwire import WarpPlusLane, WireGuardLane


def _proto_for_source(url: str) -> str:
    u = url.lower()
    if "socks5" in u:
        return "socks5"
    if "socks4" in u:
        return "socks4"
    return "http"


def parse_static_proxy(entry: str) -> Optional[Tuple[str, str, int, str, str]]:
    """Parse one static-proxy line from config `static_proxies` into
    (kind, host, port, username, password). Accepts, CR/whitespace-tolerant:

      socks5://user:pass@host:port      (scheme http/https/socks4/socks5;
                                        socks5h/socks4a = socks5/socks4)
      user:pass@host:port               (defaults to socks5)
      host:port:user:pass               (Webshare dashboard export format,
                                        defaults to socks5 — webshare proxies
                                        speak both SOCKS5 and HTTP CONNECT)
      host:port                         (no auth, defaults to socks5)

    Returns None for anything unparseable (caller logs/skips). Passwords may
    contain ':' (split on the first colon only). IPv6 hosts are not supported
    (bare colons would be ambiguous; keep the parser predictable)."""
    s = entry.strip()
    if not s or s.startswith("#"):
        return None
    kind = "socks5"
    user = password = ""
    if "://" in s:
        scheme, _, s = s.partition("://")
        scheme = scheme.lower()
        if scheme in ("socks5", "socks5h"):
            kind = "socks5"
        elif scheme in ("socks4", "socks4a"):
            kind = "socks4"
        elif scheme in ("http", "https"):
            kind = "http"
        else:
            return None
        if s.startswith("["):  # bracketed IPv6 in URL form
            return None  # unsupported: keep parser simple + predictable
    if "@" in s:
        creds, _, s = s.rpartition("@")
        user, _, password = creds.partition(":")
    parts = s.split(":")
    if len(parts) == 2:
        host, port = parts[0], parts[1]
    elif len(parts) == 4 and not user:
        host, port, user, password = parts
    else:
        return None
    host = host.strip()
    port = port.strip()
    if not host or not port.isdigit() or not (1 <= int(port) <= 65535):
        return None
    return kind, host, int(port), user.strip(), password.strip()


class PoolManager:
    def __init__(self, cfg, state: StateDB, log):
        self.cfg = cfg
        self.state = state
        self.log = log
        self.real_ip = ""

        self._lock = threading.RLock()  # reentrant: _activate -> fresh_count()
        self._candidates: deque = deque()
        self._candidate_keys: Set[str] = set()
        self._validated: Dict[str, Upstream] = {}
        self._candidate_fails: Dict[str, int] = {}
        self._current: Optional[Upstream] = None
        self._inflight = 0

        # v2: in-memory cache of the never-reuse ledger (fixes per-request
        # full-table scans); None => load from DB on first use
        self._used_cache: Optional[Set[str]] = None
        # v3: in-memory {ip: last_used} map powering the no-reuse window
        # ("don't reuse an IP for 30-60 min"). None => lazy-load from DB.
        self._last_used_cache: Optional[Dict[str, float]] = None

        self._stop = threading.Event()
        self._stopped = False          # B34: makes stop() idempotent
        self._emergency = threading.Event()
        self._last_emergency = 0.0
        self._next_tick = time.monotonic() + cfg.interval
        self._geo_last = 0.0

        self._source_state = {u: {"next_ok": 0.0, "backoff": 0.0,
                                  "fetched": 0.0}
                              for u in cfg.harvest_sources}

        self.warp = WarpProvider(cfg, log)
        self.psiphon = PsiphonProvider(cfg, log)
        self.windscribe = WindscribeProxyProvider(cfg, log)
        self.webshare = WebshareClient(cfg, log, state)
        self.wg = WireGuardLane(cfg, log, state)
        self.warpplus = WarpPlusLane(cfg, log, state)
        self.v2ray = V2RayLane(cfg, log, state)
        self._warp_checked = False
        self._webshare_next_refresh = 0.0
        self._api_bytes_lock = threading.Lock()
        self._api_bytes_pending: Dict[str, int] = {}

        # sticky sessions: target host -> (upstream_label, expires_at)
        self._sticky: Dict[str, Tuple[str, float]] = {}
        self._sticky_lock = threading.Lock()

        self.stats = {
            "harvested": 0, "validated": 0, "validation_fails": 0,
            "mitm_rejected": 0, "transparent_rejected": 0,
            "geo_rejected": 0, "rotations": 0, "recycles": 0,
            "backbone_activations": 0, "blacklisted": 0,
            "requests": 0, "failovers": 0, "sticky_hits": 0,
            "starvation_waits": 0, "starvation_rescues": 0,
            "window_blocks": 0, "mints": 0,
        }

    # ==================================================================
    # startup / lifecycle
    # ==================================================================
    def start(self):
        self._detect_real_ip()
        self._warm_start_from_db()
        threading.Thread(target=self._harvester_loop, name="harvester",
                         daemon=True).start()
        threading.Thread(target=self._feeder_loop, name="feeder",
                         daemon=True).start()
        threading.Thread(target=self._rotator_loop, name="rotator",
                         daemon=True).start()
        if self.cfg.webshare_api_key:
            threading.Thread(target=self._webshare_refresh, name="webshare",
                             daemon=True).start()
        if self.cfg.static_proxies:
            self.log.warning(
                f"static proxies lane: {len(self.cfg.static_proxies)} "
                "pasted entries (credentials preserved, revalidated "
                "every 10 min)")
            threading.Thread(target=self._static_refresh,
                             name="static-proxies", daemon=True).start()
        if self.wg.enabled():
            self.wg.start()
            self.log.warning(
                f"WireGuard lane: {self.cfg.warp_accounts} WARP account(s)"
                + (f" + configs in {self.cfg.wg_configs_dir}"
                   if self.cfg.wg_configs_dir else "")
                + " — warm tunnels, zero-dial-delay IP switches")
        if self.warpplus.enabled():
            self.warpplus.start()
            self.log.warning(
                f"warp-plus lane: {self.cfg.warpplus_instances} instances, "
                f"mode={self.cfg.warpplus_mode}, automatic country rotation "
                f"across {len(self.cfg.warpplus_countries)} countries — "
                "elastic never-seen-IP supply (needs UDP egress)")
        if self.v2ray.enabled():
            self.v2ray.start()
            self.log.warning(
                f"v2ray free-node lane: up to {self.cfg.v2ray_max_nodes} "
                f"warm community nodes via sing-box — TCP protocols work "
                "even where UDP is blocked")
        threading.Thread(target=self._wg_refresh_loop, name="wg-refresh",
                         daemon=True).start()

    def stop(self):
        if self._stopped:
            return                      # idempotent (called from signal + finally)
        self._stopped = True
        self._stop.set()
        self._emergency.set()
        self.wg.stop()
        self.warpplus.stop()
        self.v2ray.stop()
        try:
            self._flush_api_bytes()
        except Exception:
            pass

    def _detect_real_ip(self):
        try:
            ip, _ = fetch_egress_ip(
                Upstream(kind="direct", host="-", port=0), timeout=8)
            self.real_ip = ip
            self.log.info(f"real egress IP (direct): {ip}")
        except Exception:
            try:
                from .httpkit import http_client
                r = http_client().get("https://checkip.amazonaws.com",
                                      timeout=8)
                self.real_ip = r.text.strip()
                self.log.info(f"real egress IP (fallback): {self.real_ip}")
            except Exception:
                self.log.warning("could not detect real egress IP "
                                 "(transparent-proxy rejection disabled)")

    def _warm_start_from_db(self):
        rows = self.state.load_validated(max_age=1800.0)
        added = 0
        for host, port, proto, egress_ip, latency_ms, _last_ok in rows:
            key = f"{proto}://{host}:{port}"
            with self._lock:
                self._validated[key] = Upstream(
                    kind=proto, host=host, port=port, egress_ip=egress_ip,
                    latency_ms=latency_ms or 9999,
                    validated_at=time.time() - 60, source="warm-start")
            added += 1
        if added:
            self.log.info(f"warm start: loaded {added} recently-validated "
                          "upstreams from state DB")

    # ==================================================================
    # WireGuard lane feed (warm tunnels -> premium-tier upstreams)
    # ==================================================================
    def _wg_refresh_loop(self):
        """Every few seconds, pull the warm-tunnel lanes' live upstreams into
        the selection candidate set. Lane upstreams never enter _validated
        (their health is owned by the lane), but selection prefers them."""
        while not self._stop.is_set():
            try:
                ups = self.wg.validated_upstreams()
                with self._lock:
                    self._wg_upstreams = {u.label: u for u in ups}
                # v2ray free-node lane (v3): N warm ports = N egress IPs
                for u in self.v2ray.validated_upstreams():
                    with self._lock:
                        self._wg_upstreams[u.label] = u
                # warp-plus lane (v3): country-rotated WARP egress
                for u in self.warpplus.validated_upstreams():
                    with self._lock:
                        self._wg_upstreams[u.label] = u
                # windscribe proxy mode lane (opt-in): a single local SOCKS
                # upstream whose egress changes when we rotate the location
                if self.cfg.enable_windscribe_proxy and \
                        self.windscribe.available():
                    up = self.windscribe.upstream()
                    try:
                        ip, _ = fetch_egress_ip(up, timeout=12)
                        if ip and ip != self.real_ip:
                            up.egress_ip, up.validated_at = ip, time.time()
                            with self._lock:
                                self._wg_upstreams[up.label] = up
                    except Exception:
                        pass
            except Exception as e:
                self.log.debug(f"wg refresh error: {e}")
            self._stop.wait(5.0)

    def _premium_locked(self, u: Upstream) -> bool:
        """Tier-1 lanes: authenticated / dedicated / Cloudflare-edge egress,
        plus the v3 warm-node lanes (local SOCKS ports = zero dial delay).
        Preferred over anonymous free proxies whenever one is fresh."""
        src = u.source or ""
        return (src.startswith("wg:") or src.startswith("webshare") or
                src.startswith("v2ray:") or src.startswith("warpplus:") or
                src == "windscribe-proxy")

    def _candidates_locked(self) -> List[Upstream]:
        return list(self._validated.values()) + \
            list(getattr(self, "_wg_upstreams", {}).values())

    # ==================================================================
    # used-IP cache + NO-REUSE WINDOW (v3)
    # ==================================================================
    def _used_ips(self) -> Set[str]:
        with self._lock:
            if self._used_cache is None:
                self._used_cache = self.state.used_ips()
            return self._used_cache

    def _last_used_map(self) -> Dict[str, float]:
        with self._lock:
            if self._last_used_cache is None:
                self._last_used_cache = self.state.last_used_map()
            return self._last_used_cache

    def _ip_available_locked(self, ip: str) -> bool:
        """Window semantics: an IP is selectable only if it was NEVER used
        or its last use is older than the no-reuse window (default 45 min).
        This is the user's "30-60 min no old IP" contract."""
        if not ip:
            return False
        lu = self._last_used_map().get(ip)
        if lu is None:
            return True   # never used
        window = self.cfg.effective_no_reuse()
        if window <= 0:
            return True
        return (time.time() - lu) > window

    def _mark_used(self, ip: str, provider: str) -> None:
        self.state.mark_ip_used(ip, provider)
        with self._lock:
            if self._used_cache is not None:
                self._used_cache.add(ip)
            if self._last_used_cache is not None:
                self._last_used_cache[ip] = time.time()

    # ==================================================================
    # harvesting
    # ==================================================================
    def _harvest_pass_needed(self) -> bool:
        return self._emergency.is_set()

    def _harvester_loop(self):
        from .httpkit import http_client
        while not self._stop.is_set():
            now = time.monotonic()
            ran = False
            emergency = self._emergency.is_set()
            for url, st in self._source_state.items():
                if self._stop.is_set():
                    break
                if now < st["next_ok"]:
                    continue
                if not emergency and now - st["fetched"] < \
                        self.cfg.source_cache_ttl:
                    continue
                ran = True
                try:
                    body = http_client().get(url, timeout=20.0).text
                    self._ingest(body, url)
                    st["backoff"] = 0.0
                    st["next_ok"] = 0.0
                except httpx.HTTPStatusError as e:
                    # 429/5xx -> exponential backoff (anti-thundering-herd)
                    code = e.response.status_code if e.response is not None else 0
                    st["backoff"] = min(max(st["backoff"] * 2, 60),
                                        self.cfg.source_backoff_max)
                    st["next_ok"] = time.monotonic() + st["backoff"]
                    self.log.warning(
                        f"source {url.rsplit('/', 2)[-1][:40]} HTTP {code} "
                        f"- backing off {st['backoff']:.0f}s")
                except Exception as e:
                    st["backoff"] = min(max(st["backoff"] * 2, 120),
                                        self.cfg.source_backoff_max)
                    st["next_ok"] = time.monotonic() + st["backoff"]
                    self.log.warning(
                        f"source {url.rsplit('/', 2)[-1][:40]} failed "
                        f"({type(e).__name__}) - backing off {st['backoff']:.0f}s")
                finally:
                    st["fetched"] = time.monotonic()
                    time.sleep(random.uniform(0.2, 0.8))  # politeness jitter
            if emergency:
                self._emergency.clear()
            if ran:
                self.log.info(
                    f"harvest pass done: {self.stats['harvested']} candidates "
                    f"total, queue={self._queue_len()}, "
                    f"validated={self._pool_len()}")
            self._stop.wait(5.0)

    def _ingest(self, body: str, source_url: str) -> None:
        default_proto = _proto_for_source(source_url)
        added = 0
        for line in body.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            proto, hp = default_proto, line
            if "://" in line:
                p, _, rest = line.partition("://")
                if p in ("http", "https", "socks4", "socks5"):
                    proto = "socks4" if p == "socks4" else (
                        "socks5" if p == "socks5" else "http")
                    hp = rest
            host, sep, port = hp.rpartition(":")
            if not sep or not host or not port.isdigit():
                continue
            port_i = int(port)
            if not (1 <= port_i <= 65535):
                continue
            key = f"{proto}://{host}:{port}"
            with self._lock:
                if key in self._candidate_keys or key in self._validated:
                    continue
                if len(self._candidate_keys) > 20000:
                    break
                self._candidate_keys.add(key)
                self._candidates.append((host, port_i, proto, key, source_url))
            added += 1
        if added:
            self.stats["harvested"] += added

    def _queue_len(self) -> int:
        with self._lock:
            return len(self._candidates)

    def _pool_len(self) -> int:
        with self._lock:
            return len(self._validated)

    def trigger_emergency_harvest(self, reason: str):
        now = time.monotonic()
        if now - self._last_emergency < 20.0:
            return
        self._last_emergency = now
        self.log.warning(f"EMERGENCY harvest triggered: {reason}")
        self._emergency.set()

    # ==================================================================
    # Webshare free lane (10 authenticated datacenter proxies, 1GB/month)
    # ==================================================================
    def _webshare_refresh(self):
        """Pull the account's free proxies and validate them like any other
        candidate (MITM check + egress discovery) — but preserving their
        credentials. Re-run hourly; auto-disable at the 1GB monthly cap."""
        while not self._stop.is_set():
            if self.webshare.over_cap():
                self.log.warning(
                    f"webshare lane DISABLED - free 1GB/month cap hit "
                    f"({self.webshare.describe()}); resets next calendar month")
            else:
                try:
                    ups = self.webshare.fetch_proxies()
                    ok = 0
                    for up in ups:
                        key = f"{up.kind}://{up.host}:{up.port}"
                        with self._lock:
                            have = self._validated.get(key)
                        if have is not None and \
                                time.time() - have.validated_at < 600:
                            continue
                        self._validate_one(
                            (up.host, up.port, up.kind, key, up.source),
                            False, template=up)
                        ok += 1
                    if ok:
                        self.log.info(
                            f"webshare free lane refreshed: {ok} proxies "
                            f"queued for validation ({self.webshare.describe()})")
                except Exception as e:
                    self.log.warning(
                        f"webshare lane refresh failed: {e} "
                        f"(check webshare_api_key; lane skipped)")
            self._webshare_next_refresh = time.monotonic() + \
                WebshareClient.REFRESH_SECONDS
            self._stop.wait(WebshareClient.REFRESH_SECONDS)

    # ==================================================================
    # static authenticated proxies pasted straight into config
    # (e.g. the Webshare dashboard 'ip:port:user:pass' export — works
    # WITHOUT the webshare API key; validated like the webshare lane so
    # RFC 1929 / Proxy-Authorization credentials survive)
    # ==================================================================
    def _static_refresh(self):
        while not self._stop.is_set():
            fed = 0
            for entry in self.cfg.static_proxies:
                if self._stop.is_set():
                    return
                parsed = parse_static_proxy(entry)
                if parsed is None:
                    self.log.warning(
                        f"static proxies: skipping unparseable entry "
                        f"{entry[:48]!r}")
                    continue
                kind, host, port, user, password = parsed
                key = f"{kind}://{host}:{port}"
                with self._lock:
                    have = self._validated.get(key)
                if have is not None and time.time() - have.validated_at < 600:
                    continue  # validated recently; skip this pass
                self._validate_one(
                    (host, port, kind, key, "static"), False,
                    template=Upstream(kind=kind, host=host, port=port,
                                      source="static", username=user,
                                      password=password))
                fed += 1
            if fed:
                self.log.info(
                    f"static proxies lane: {fed} entries queued for "
                    "validation")
            self._stop.wait(600.0)

    # ==================================================================
    # validation
    # ==================================================================
    def _feeder_loop(self):
        executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=self.cfg.validation_workers,
            thread_name_prefix="validator")
        try:
            self._feeder_body(executor)
        finally:
            # B34: never leave executor workers behind. wait=False drops
            # queued work; in-flight workers finish (or the exit watchdog in
            # cli.py guarantees the process still terminates).
            executor.shutdown(wait=False)

    def _feeder_body(self, executor):
        last_reval = 0.0
        while not self._stop.is_set():
            # 1) feed new candidates
            with self._lock:
                can_feed = len(self._validated) + self._inflight < \
                    self.cfg.validated_pool_cap
                nxt = self._candidates.popleft() if (
                    can_feed and self._candidates) else None
                if nxt:
                    self._inflight += 1
            if nxt:
                executor.submit(self._validate_one, nxt, False)
            # 2) periodic revalidation of ageing entries
            if time.monotonic() - last_reval > 30.0:
                last_reval = time.monotonic()
                self._submit_revalidations(executor)
            if nxt is None:
                self._stop.wait(0.05)

    def _submit_revalidations(self, executor) -> None:
        now = time.time()
        with self._lock:
            stale = [(k, u) for k, u in self._validated.items()
                     if now - u.validated_at > self.cfg.revalidate_after]
            stale = stale[:60]
            keys_drop = [k for k, u in self._validated.items()
                         if now - u.validated_at > 300.0]
            for k in keys_drop:
                del self._validated[k]
        if stale:
            for k, u in stale:
                with self._lock:
                    self._validated.pop(k, None)
                    self._inflight += 1
                executor.submit(
                    self._validate_one,
                    (u.host, u.port, u.kind, k, "revalidate"), True,
                    template=u)  # keep credentials of metered upstreams

    def _validate_one(self, cand: Tuple, is_reval: bool,
                      template: Optional[Upstream] = None) -> None:
        host, port, proto, key, source = cand
        try:
            if self.state.is_blacklisted(host, port, proto):
                return
            up = template or Upstream(kind=proto, host=host, port=port,
                                      source=source)
            try:
                ip, ms = fetch_egress_ip(up,
                                         timeout=self.cfg.validation_timeout)
            except Exception as e:
                if dialer.is_tls_verification_error(e):
                    # certificate verification failed END-TO-END through the
                    # proxy: MITM signature -> instant blacklist
                    self.stats["mitm_rejected"] += 1
                    self.state.record_fail(host, port, proto, 3600.0,
                                           force=True)
                    self.log.warning(f"BLACKLISTED (MITM cert failure): {key}")
                    return
                self.stats["validation_fails"] += 1
                with self._lock:
                    fails = self._candidate_fails.get(key, 0) + 1
                    self._candidate_fails[key] = fails
                # revalidation failure of an in-use upstream = real failure
                if is_reval and fails >= 2:
                    self.state.record_fail(
                        host, port, proto,
                        self.cfg.blacklist_minutes * 60,
                        threshold=self.cfg.fail_threshold)
                return
            if ms > self.cfg.max_latency_ms:
                return
            if self.real_ip and ip == self.real_ip:
                # "proxy" that reveals OUR ip is transparent -> useless+leaky
                self.stats["transparent_rejected"] += 1
                self.state.record_fail(host, port, proto, 3600.0, force=True)
                return
            if self.cfg.country_filter:
                country = self._geo(ip)
                if country not in {c.upper() for c in self.cfg.country_filter}:
                    self.stats["geo_rejected"] += 1
                    return
            with self._lock:
                self._candidate_fails.pop(key, None)
                self._validated[key] = Upstream(
                    kind=proto, host=host, port=port, egress_ip=ip,
                    latency_ms=ms, validated_at=time.time(), source=source,
                    username=up.username, password=up.password)
            self.state.upsert_upstream(host, port, proto, ip, ms)
            self.stats["validated"] += 1
            # pool running low -> emergency harvest
            if self.fresh_count() < self.cfg.min_pool:
                self.trigger_emergency_harvest("fresh pool below min")
        finally:
            with self._lock:
                self._inflight -= 1

    def _geo(self, ip: str) -> Optional[str]:
        cached = self.state.get_country(ip)
        if cached:
            return cached
        # ip-api free tier: 45 req/min -> throttle hard
        wait = 1.5 - (time.monotonic() - self._geo_last)
        if wait > 0:
            time.sleep(wait)
        self._geo_last = time.monotonic()
        c = geo_lookup(ip)
        if c:
            self.state.set_country(ip, c)
        return c

    # ==================================================================
    # selection / rotation (v3: no-reuse window everywhere)
    # ==================================================================
    def fresh_count(self) -> int:
        """Selectable right now = never-used IPs + window-expired IPs.
        (v2 counted only never-used; the 30-60 min window makes expired IPs
        legitimately fresh again.)"""
        with self._lock:  # v2 fix: was an unlocked dict iteration (race)
            return sum(1 for u in self._candidates_locked()
                       if self._ip_available_locked(u.egress_ip))

    def _pick_fresh_locked(self, exclude_ips: Set[str]) -> Optional[Upstream]:
        best, best_ms = None, 10 ** 9
        best_prem, best_prem_ms = None, 10 ** 9
        for u in self._candidates_locked():
            if not u.egress_ip or u.egress_ip in exclude_ips:
                continue
            if not self._ip_available_locked(u.egress_ip):
                self.stats["window_blocks"] += 1  # inside no-reuse window
                continue
            # defense in depth: never pick an "upstream" that leaks our IP
            if self.real_ip and u.egress_ip == self.real_ip:
                continue
            if self.state.is_blacklisted(u.host, u.port, u.kind):
                continue
            slot, slot_ms = (best, best_ms)
            if self._premium_locked(u):
                slot, slot_ms = (best_prem, best_prem_ms)
            if u.latency_ms < slot_ms:
                if self._premium_locked(u):
                    best_prem, best_prem_ms = u, u.latency_ms
                else:
                    best, best_ms = u, u.latency_ms
        # premium tier (warm lanes / webshare / windscribe) wins ties
        return best_prem if best_prem is not None else best

    def _pick_recycle_locked(self, exclude_ips: Set[str]) -> Optional[Upstream]:
        """Recycle = the no-reuse window already expired for these IPs.
        Prefer the premium lanes (authenticated / warm / CF-edge) on recycle."""
        best, best_lu = None, 0.0
        best_ws, best_ws_lu = None, 0.0
        for u in self._candidates_locked():
            if not u.egress_ip or u.egress_ip in exclude_ips:
                continue
            if self.state.is_blacklisted(u.host, u.port, u.kind):
                continue
            lu = self._last_used_map().get(u.egress_ip, 0.0)
            if lu == 0.0:  # never actually used (ledger miss) -> fresh path
                continue
            if not self._ip_available_locked(u.egress_ip):
                continue  # window still open: not recyclable, period
            is_ws = self._premium_locked(u)
            slot = (best_ws, best_ws_lu) if is_ws else (best, best_lu)
            if slot[0] is None or lu < slot[1]:
                if is_ws:
                    best_ws, best_ws_lu = u, lu
                else:
                    best, best_lu = u, lu
        return best_ws if best_ws is not None else best

    def _activate(self, up: Upstream, how: str) -> None:
        self._current = up
        self._mark_used(up.egress_ip, up.source or up.kind)
        self.stats["rotations"] += 1
        if how == "recycle":
            self.stats["recycles"] += 1
        if up.kind in ("warp", "direct"):
            self.stats["backbone_activations"] += 1
        self.log.warning(
            f"ROTATE #{self.stats['rotations']} -> {up.egress_ip} "
            f"[{how}] via {up.label} ({up.latency_ms}ms) | "
            f"validated={self._pool_len()} fresh={self.fresh_count()}")

    def rotate(self, reason: str = "timer") -> None:
        if self.cfg.rotate_every_request:
            return  # selection happens per request instead
        with self._lock:
            if self._current is not None:
                exclude = {self._current.egress_ip}
            else:
                exclude = set()
            fresh = self._pick_fresh_locked(exclude)
            if fresh:
                self._activate(fresh, "fresh")
                return
        # no fresh freepool IP -> policy
        self._handle_starvation(reason)

    def _handle_starvation(self, reason: str) -> None:
        self.trigger_emergency_harvest(f"no fresh IPs ({reason})")
        self._elastic_mint(reason)
        policy = self.cfg.policy_on_exhaustion

        if policy == "backbone":
            up = self._get_backbone()
            if up is not None:
                with self._lock:
                    self._activate(up, "backbone")
                return

        if policy in ("recycle", "backbone"):
            with self._lock:
                cur_ip = self._current.egress_ip if self._current else ""
                exclude = {cur_ip} if cur_ip else set()
                rec = self._pick_recycle_locked(exclude)
                if rec is not None:
                    self._activate(rec, "recycle")
                    self.log.warning(
                        f"POOL EXHAUSTED - recycling old IP {rec.egress_ip} "
                        f"(unused for {self.cfg.recycle_avoid_seconds:.0f}s+). "
                        f"fresh={self.fresh_count()}")
                    return
            up = self._get_backbone()
            if up is not None:
                with self._lock:
                    self._activate(up, "backbone")
                return
            if self.cfg.allow_direct:
                up = Upstream(kind="direct", host="-", port=0,
                              egress_ip=self.real_ip or "unknown",
                              source="direct")
                with self._lock:
                    self._activate(up, "DIRECT-FALLBACK")
                self.log.critical(
                    "USING YOUR REAL IP (direct fallback enabled) - "
                    "scraping traffic is now EXPOSED")
                return
            self.log.critical(
                f"STARVED (policy={policy}): no fresh/recyclable IPs; "
                f"emergency harvest running. New requests may fail.")
            return

        # strict
        self.log.critical(
            f"STRICT POLICY: no fresh IPs available; refusing to recycle. "
            f"Emergency harvest running; current upstream retained.")

    def _elastic_mint(self, reason: str) -> None:
        """v3 elastic IP factory: when selectable supply runs low, ASK the
        lanes to mint never-seen IPs right now:
          * warp-plus lane: respawn an instance with a FRESH identity in the
            NEXT country (automatic country rotation — the user-requested
            anti-exhaustion mechanism)
          * WireGuard/WARP lane: register another free account if allowed
        Mints are rate-limited inside the lanes; failures are silent (the
        normal recycle/backbone ladder still applies)."""
        try:
            if self.warpplus.enabled() and not self.warpplus.disabled_reason:
                with self._lock:
                    burned = {u.egress_ip for u in
                              self._candidates_locked() if u.egress_ip}
                ip = self.warpplus.mint_new_ip(exclude_ips=burned)
                if ip:
                    self.stats["mints"] += 1
                    self.log.warning(
                        f"elastic mint via warp-plus country rotation: {ip} "
                        f"(reason: {reason})")
        except Exception as e:
            self.log.debug(f"elastic mint error: {e}")

    def _get_backbone(self) -> Optional[Upstream]:
        # 1) warm lanes (WG tunnels / v2ray nodes / warp-plus): a warm local
        # port with a window-available egress IP — the cleanest backbone
        for u in getattr(self, "_wg_upstreams", {}).values():
            if u.egress_ip and self._ip_available_locked(u.egress_ip):
                u.validated_at = time.time()
                self.log.warning(
                    f"backbone -> warm lane {u.source} "
                    f"(egress {u.egress_ip})")
                return u
        # 2) windscribe proxy lane (opt-in)
        if self.cfg.enable_windscribe_proxy and \
                self.windscribe.available():
            up = self.windscribe.upstream()
            try:
                ip, _ = fetch_egress_ip(up, timeout=10)
                if ip and ip != self.real_ip and \
                        self._ip_available_locked(ip):
                    up.egress_ip, up.validated_at = ip, time.time()
                    self.log.warning(
                        f"backbone -> windscribe proxy ({ip})")
                    return up
            except Exception:
                pass
        if self.cfg.enable_warp:
            if not self._warp_checked:
                self._warp_checked = True
                if self.warp.available():
                    self.log.warning(
                        "pool starving -> engaging Cloudflare WARP backbone "
                        "(proxy mode SOCKS 127.0.0.1:%d)" % self.cfg.warp_proxy_port)
            if self.warp.available():
                up = self.warp.upstream()
                if not self.warp.last_egress:
                    self.warp.ensure_ready()
                egress = self.warp.last_egress or ""
                if egress and self._ip_available_locked(egress):
                    up.egress_ip, up.validated_at = egress, time.time()
                    return up
                # WARP IP already used -> try to re-register a new identity
                new_ip = self.warp.refresh_ip()
                if new_ip and self._ip_available_locked(new_ip):
                    up.egress_ip, up.validated_at = new_ip, time.time()
                    return up
                self.log.warning(
                    f"WARP backbone cannot mint an unseen IP "
                    f"(has {egress or 'none'}) - documented limitation")
        if self.cfg.enable_psiphon and self.psiphon.available():
            up = self.psiphon.upstream()
            try:
                ip, _ = fetch_egress_ip(up, timeout=10)
                if ip and ip != self.real_ip and \
                        self._ip_available_locked(ip):
                    up.egress_ip, up.validated_at = ip, time.time()
                    self.log.warning(
                        f"backbone -> Psiphon ({ip}) - free, unlimited, "
                        "shared egress; cannot mint fresh IPs on demand")
                    return up
            except Exception:
                pass
        return None

    def _rotator_loop(self) -> None:
        while not self._stop.is_set():
            now = time.monotonic()
            if now >= self._next_tick:
                # zero-drift: schedule on fixed grid from epoch
                steps = int((now - self._next_tick) / self.cfg.interval) + 1
                self._next_tick += steps * self.cfg.interval
                try:
                    self.rotate("timer")
                except Exception as e:
                    self.log.error(f"rotation error: {e}")
                try:
                    self._flush_api_bytes()
                except Exception:
                    pass
            self._stop.wait(min(1.0, max(0.05, self._next_tick - now)))

    def rotate_now(self, reason: str = "manual") -> None:
        self.log.info(f"manual rotation requested ({reason})")
        self.rotate(reason)

    # ==================================================================
    # request path (server-facing API)
    # ==================================================================
    def _sticky_get(self, host: str, excl_ips: Set[str]) -> Optional[Upstream]:
        """Live sticky binding for this target host, if any."""
        if not self.cfg.sticky_sessions or not host or \
                self.cfg.rotate_every_request:
            return None
        with self._sticky_lock:
            ent = self._sticky.get(host)
            if not ent:
                return None
            label, expires = ent
            if time.time() > expires:
                self._sticky.pop(host, None)
                return None
        with self._lock:
            for u in self._candidates_locked():
                if u.label == label and u.egress_ip not in excl_ips and \
                        not self.state.is_blacklisted(u.host, u.port, u.kind):
                    self.stats["sticky_hits"] += 1
                    return u
        return None

    def _sticky_set(self, host: str, up: Upstream) -> None:
        if not self.cfg.sticky_sessions or not host or \
                self.cfg.rotate_every_request or self.cfg.sticky_ttl <= 0:
            return
        with self._sticky_lock:
            self._sticky[host] = (up.label, time.time() + self.cfg.sticky_ttl)

    def _next_upstream_once(self, exclude: List[Upstream],
                            host: str = "") -> Optional[Upstream]:
        """Current/sticky/fresh upstream, else starvation policy result."""
        excl_ips = {u.egress_ip for u in exclude if u.egress_ip}
        sticky = self._sticky_get(host, excl_ips)
        if sticky is not None:
            return sticky
        with self._lock:
            cur = self._current
            if cur is not None and cur.egress_ip not in excl_ips and \
                    not self.state.is_blacklisted(cur.host, cur.port, cur.kind):
                self._sticky_set(host, cur)
                return cur
            fresh = self._pick_fresh_locked(excl_ips)
            if fresh is not None:
                self._activate(fresh, "failover-fresh")
                self._sticky_set(host, fresh)
                return fresh
        # mid-request failover couldn't find fresh -> starvation policies
        self._handle_starvation("request-failover")
        with self._lock:
            cur = self._current
            if cur is not None and cur.egress_ip not in excl_ips:
                self._sticky_set(host, cur)
                return cur
        return None

    def next_upstream(self, exclude: List[Upstream],
                      host: str = "") -> Optional[Upstream]:
        """Current upstream if usable, else failover to a fresh/standby one.
        Called per connection attempt; `exclude` holds upstreams that just
        failed for THIS request.

        v2.1 survival window: when the whole lane chain fails for a request,
        DON'T 502 instantly — hold the request up to cfg.starvation_wait
        seconds (retrying the chain) so emergency harvest / WG registration
        can rescue it. "Multiple fallbacks so no request is lost."
        """
        self.stats["requests"] += 1
        up = self._next_upstream_once(exclude, host)
        if up is not None:
            return up
        deadline = time.monotonic() + self.cfg.starvation_wait
        self.stats["starvation_waits"] += 1
        while time.monotonic() < deadline and not self._stop.is_set():
            time.sleep(self.cfg.starvation_retry_delay)
            self.trigger_emergency_harvest("request-survival-window")
            up = self._next_upstream_once(exclude, host)
            if up is not None:
                self.stats["starvation_rescues"] += 1
                self.log.warning(
                    f"request rescued inside survival window after "
                    f"{time.monotonic() - (deadline - self.cfg.starvation_wait):.1f}s "
                    f"(pool was momentarily starved)")
                return up
        return None

    def report_success(self, up: Upstream) -> None:
        if up.kind in ("http", "socks4", "socks5"):
            self.state.clear_blacklist(up.host, up.port, up.kind)

    def report_bytes(self, up: Upstream, n: int) -> None:
        """Byte metering for capped free tiers (Webshare 1GB/month, VPNs).
        Called by the relay pump; batches writes to SQLite."""
        if up is None or n <= 0:
            return
        source = up.source or ""
        if up.kind == "direct" and source.startswith("vpn:"):
            provider = source
        elif source.startswith("webshare"):
            provider = "webshare"
        elif source == "windscribe-proxy":
            provider = "vpn:windscribe"  # shares the 10GB/month free cap
        else:
            return
        with self._api_bytes_lock:
            self._api_bytes_pending[provider] = \
                self._api_bytes_pending.get(provider, 0) + n
            if self._api_bytes_pending[provider] < 512 * 1024:
                return  # batch: flush at >=512KB per provider
            n = self._api_bytes_pending.pop(provider)
        self.state.add_api_usage(provider, bytes_=n, monthly=True)

    def _flush_api_bytes(self) -> None:
        with self._api_bytes_lock:
            pending = self._api_bytes_pending
            self._api_bytes_pending = {}
        for provider, n in pending.items():
            if n > 0:
                self.state.add_api_usage(provider, bytes_=n, monthly=True)

    def report_failure(self, up: Upstream, why: str) -> bool:
        """N strikes (configurable) -> blacklist. Returns True if blacklisted.
        Instantly rotates away if the failed upstream was the active one."""
        blacklisted = False
        if up.kind in ("http", "socks4", "socks5"):
            blacklisted = self.state.record_fail(
                up.host, up.port, up.kind,
                self.cfg.blacklist_minutes * 60,
                threshold=self.cfg.fail_threshold)
            if blacklisted:
                self.stats["blacklisted"] += 1
                self.log.warning(f"BLACKLISTED "
                                 f"({self.cfg.fail_threshold} fails): "
                                 f"{up.label} - {why}")
        self.stats["failovers"] += 1
        with self._lock:
            was_current = (self._current is not None and
                           self._current.label == up.label)
        if was_current:
            self.rotate("upstream-death")
        return blacklisted

    def describe_current(self) -> str:
        with self._lock:
            cur = self._current
        if cur is None:
            return "none"
        return f"{cur.egress_ip} via {cur.label}"

    def seconds_to_next_rotation(self) -> float:
        return max(0.0, self._next_tick - time.monotonic())

    # ==================================================================
    # IP-factory economics (v3): burn rate vs mintable supply
    # ==================================================================
    def ip_factory(self) -> dict:
        """The 'will it exhaust?' answer, computed live:
          burn_per_hour   = IPs consumed per hour at the current interval
          (3600 / interval). With the no-reuse window W, an IP stays burned
          for W seconds, so steady-state UNIQUE demand is
          burn_per_hour * W / 3600 IPs.
          available_now   = selectable IPs right now (never-used + expired).
          headroom_min    = minutes until the window-available stock (plus
          factory refill from warp-plus country rotation and the v2ray
          node lane) would run dry at current burn — the pool regenerates
          long before that, which is exactly the design goal.
        """
        window = self.cfg.effective_no_reuse()
        burn_per_hour = 3600.0 / max(1.0, self.cfg.interval)
        unique_needed = burn_per_hour * window / 3600.0
        with self._lock:
            available = sum(1 for u in self._candidates_locked()
                            if self._ip_available_locked(u.egress_ip))
        # mint capacity: warp-plus respawns (one fresh identity each, 31
        # countries) + v2ray node lane re-harvest (subscription refresh)
        mint_per_hour = 0.0
        if self.warpplus.enabled() and not self.warpplus.disabled_reason:
            # each respawn ~ grace+probe; conservative 1 per 40s per instance
            mint_per_hour += (3600.0 / max(30.0,
                              self.cfg.warpplus_handshake_grace + 15)) \
                * self.cfg.warpplus_instances
        if self.v2ray.enabled() and not self.v2ray.disabled_reason:
            # steady-state aliveness of the node lane (observed fill)
            mint_per_hour += len(self.v2ray.validated_upstreams()) * 6.0
        net = mint_per_hour - burn_per_hour
        if net >= 0:
            headroom_min = 10 ** 6   # factory outpaces demand: no exhaustion
        elif available > 0:
            headroom_min = available / (-net) * 60.0
        else:
            headroom_min = 0.0
        verdict = ("factory-outpaces-demand" if net >= 0 else
                   ("healthy" if headroom_min > 60 else
                    "tight — widen window or enable warp-plus/v2ray lanes"))
        return {
            "burn_per_hour": round(burn_per_hour, 1),
            "no_reuse_window_min": round(window / 60.0, 1),
            "unique_ips_needed_steady_state": round(unique_needed, 1),
            "available_now": available,
            "mint_per_hour_est": round(mint_per_hour, 1),
            "net_per_hour": round(net, 1),
            "headroom_minutes": ("infinite" if net >= 0
                                 else round(headroom_min, 1)),
            "verdict": verdict,
        }

    def snapshot(self) -> dict:
        try:
            self._flush_api_bytes()
        except Exception:
            pass
        ws = self.webshare.describe() \
            if self.cfg.webshare_api_key else "disabled (no key)"
        return {
            "current": self.describe_current(),
            "fresh": self.fresh_count(),
            "validated": self._pool_len(),
            "queue": self._queue_len(),
            "ledger": self.state.ledger_size(),
            "real_ip": self.real_ip,
            "ip_factory": self.ip_factory(),
            "webshare": ws,
            "wireguard_lane": self.wg.describe(),
            "warpplus_lane": self.warpplus.describe(),
            "v2ray_lane": self.v2ray.describe(),
            "windscribe_proxy": ("enabled" if self.cfg.enable_windscribe_proxy
                                 else "off"),
            "vpngate": ("opt-in (vpn mode)" if self.cfg.enable_vpngate
                        else "off"),
            "sticky_sessions": (f"on (ttl {self.cfg.sticky_ttl:.0f}s)"
                                if self.cfg.sticky_sessions else "off"),
            "stats": dict(self.stats),
            "next_rotation_in": round(self.seconds_to_next_rotation(), 1),
            "ts": time.time(),
        }
