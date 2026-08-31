"""Freemium API providers: Webshare free proxies + scraping-API fetch lane.

Verified free tiers (Aug 2026 — full landscape table in README). Every
tier below is NO-CREDIT-CARD (hard requirement):

  Provider      | Free tier                                   | Kind
  --------------|---------------------------------------------|------------------
  Webshare      | 10 datacenter proxies, 1 GB/month, forever  | REAL proxies
  ZenRows       | 5,000 credits/MONTH (refreshes!), no card   | scraping API
  Firecrawl     | 1,000 credits/month, KEYLESS (no API key)   | scraping API
  ScrapingBee   | 1,000 credits one-time, no card             | scraping API
  Crawlbase     | 1,000 requests one-time (normal token)      | scraping API
  ScraperAPI    | 5,000 credits 7-DAY TRIAL (not recurring)   | scraping API

Honest limits of this lane:
  * Webshare proxies are REAL upstreams -> they plug straight into the
    rotation pool (authenticated SOCKS5/HTTP, RFC 1929 + Proxy-Authorization).
    Only 10 IPs though: they are a reliability lane, not an IP fountain.
  * Scraping APIs rotate THEIR OWN proxy fleet server-side; they cannot
    tunnel arbitrary CONNECT traffic. They are exposed as a metered FETCH
    lane (`ip-rotator fetch <url>`) — the last resort when every proxy
    lane is dead. 1 request / 10s = 259k req/month, so every free tier
    here burns out in HOURS; that is why quota meters are mandatory.
  * Every credit and byte is metered in the state DB; providers are
    skipped automatically once their free cap is exhausted.

v2: HTTP layer moved from urllib to httpx (keep-alive, strict TLS,
consistent timeouts); helper signatures kept stable for tests.
"""
import dataclasses
import json
from typing import Dict, List, Optional, Tuple

import httpx

from .dialer import Upstream
from .httpkit import http_client

_UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}


def _http_json(url: str, headers: Optional[dict] = None,
               timeout: float = 20.0):
    r = http_client().get(url, headers={**_UA, **(headers or {})},
                          timeout=timeout)
    r.raise_for_status()
    return r.json()


def _http_request(url: str, body: Optional[bytes] = None,
                  headers: Optional[dict] = None,
                  timeout: float = 60.0) -> Tuple[int, str]:
    """GET (body=None) or POST (body=bytes) returning (status, text)."""
    h = {**_UA, **(headers or {})}
    if body is None:
        r = http_client().get(url, headers=h, timeout=timeout)
    else:
        r = http_client().post(url, content=body, headers=h, timeout=timeout)
    return r.status_code, r.text[:8 * 1024 * 1024]


# ===========================================================================
# Webshare — 10 free datacenter proxies, 1 GB/month, forever, no card
# ===========================================================================
class WebshareClient:
    """Fetches the account's free proxies and turns them into authenticated
    Upstreams. The 1 GB/month cap is metered by the pool (byte counting in
    the relay) and enforced: at 100% the lane is disabled until the
    calendar month rolls over."""

    API = "https://proxy.webshare.io/api"
    MONTHLY_BYTES = 1024 ** 3          # 1 GB
    REFRESH_SECONDS = 3600.0           # re-pull proxy list hourly

    def __init__(self, cfg, log, state):
        self.cfg = cfg
        self.log = log
        self.state = state
        self.last_refresh = 0.0
        self.last_error = ""

    # ---------------------------------------------------------------- fetch
    def fetch_proxies(self) -> List[Upstream]:
        """GET /v2/proxy/list/ -> authenticated upstreams (http + socks5)."""
        key = self.cfg.webshare_api_key
        if not key:
            return []
        url = (f"{self.API}/v2/proxy/list/?mode=direct&page=1&page_size=100")
        try:
            data = _http_json(
                url, headers={"Authorization": f"Token {key}"}, timeout=25)
        except Exception as e:
            self.last_error = f"{type(e).__name__}: {e}"
            raise
        out: List[Upstream] = []
        for row in (data.get("results") or [])[:100]:
            if not row.get("valid", True):
                continue
            host = row.get("address") or ""
            user = row.get("username") or ""
            pwd = row.get("password") or ""
            port = row.get("port")
            # API has shipped two shapes: int, or {"http":..,"socks5":..}
            ports: Dict[str, int] = {}
            if isinstance(port, dict):
                for proto in ("http", "socks5"):
                    if port.get(proto):
                        ports[proto] = int(port[proto])
            elif isinstance(port, int):
                protos = row.get("proxy_protocol") or ["http"]
                for proto in protos:
                    ports[proto] = port
            for proto, p in ports.items():
                if not host or not (1 <= p <= 65535):
                    continue
                out.append(Upstream(
                    kind=proto, host=host, port=p,
                    username=user, password=pwd,
                    source="webshare-free"))
        if not out:
            self.last_error = "API returned no valid proxies"
        return out

    # ------------------------------------------------------------- metering
    def bytes_used(self) -> int:
        return self.state.api_usage("webshare", monthly=True)["bytes"]

    def over_cap(self) -> bool:
        return self.bytes_used() >= self.MONTHLY_BYTES

    def describe(self) -> str:
        used = self.bytes_used()
        pct = 100.0 * used / self.MONTHLY_BYTES
        return (f"{used / 1024 ** 2:.0f} MB / 1 GB this month "
                f"({pct:.0f}%){' - CAP HIT, lane disabled' if self.over_cap() else ''}")


# ===========================================================================
# Scraping-API fetch lane (their proxies rotate server-side; metered)
# ===========================================================================
@dataclasses.dataclass
class FetchProvider:
    name: str
    cap: int                      # free credits
    monthly: bool                 # True: cap refreshes monthly; False: one-time
    keyless: bool = False         # works without any API key
    api_key_field: str = ""       # key in Config.api_keys
    endpoint: str = ""
    method: str = "GET"           # GET w/ url param, or POST w/ JSON body
    docs: str = ""

    def build_request(self, target: str, key: str):
        """Returns (url, body_bytes|None, extra_headers)."""
        if self.method == "POST":
            return self.endpoint, \
                json.dumps({"url": target}).encode(), \
                {"Content-Type": "application/json"}
        from urllib.parse import quote
        q = quote(target, safe="")
        return self.endpoint.format(api_key=key, url=q), None, {}

    def extract(self, status: int, body: str) -> str:
        return body  # default: providers return raw HTML


class _Firecrawl(FetchProvider):
    def extract(self, status: int, body: str) -> str:
        try:
            data = json.loads(body)
            d = data.get("data") or {}
            return d.get("markdown") or d.get("html") or body
        except Exception:
            return body


FETCH_PROVIDERS: List[FetchProvider] = [
    FetchProvider(
        name="zenrows", cap=5000, monthly=True, api_key_field="zenrows",
        endpoint="https://api.zenrows.com/v1/?apikey={api_key}&url={url}",
        docs="dashboard.zenrows.com -> API key (free plan needs no card)"),
    _Firecrawl(
        name="firecrawl", cap=1000, monthly=True, keyless=True, method="POST",
        endpoint="https://api.firecrawl.dev/v2/scrape",
        docs="keyless: POST /v2/scrape, no signup; 1k credits/month per IP "
             "(verified live: works with no auth header)"),
    FetchProvider(
        name="scrapingbee", cap=1000, monthly=False, api_key_field="scrapingbee",
        endpoint="https://app.scrapingbee.com/api/v1/?api_key={api_key}&url={url}",
        docs="app.scrapingbee.com -> 1,000 free credits (one-time)"),
    FetchProvider(
        name="crawlbase", cap=1000, monthly=False, api_key_field="crawlbase",
        endpoint="https://api.crawlbase.com/?token={api_key}&url={url}",
        docs="crawlbase.com -> normal token, first 1,000 requests free"),
    FetchProvider(
        name="scraperapi", cap=5000, monthly=False, api_key_field="scraperapi",
        endpoint="https://api.scraperapi.com/?api_key={api_key}&url={url}",
        docs="scraperapi.com -> 5,000 credits, 7-day trial"),
]


class FetchLane:
    """Metered last-resort fetch through scraping APIs.

    Tries providers in priority order (configurable via
    cfg.fetch_priority), skipping any that (a) need a key and don't have
    one, or (b) have exhausted their free cap. Records every used credit.
    """

    def __init__(self, cfg, log, state):
        self.cfg = cfg
        self.log = log
        self.state = state

    def _ordered(self) -> List[FetchProvider]:
        prio = self.cfg.fetch_priority or [p.name for p in FETCH_PROVIDERS]
        by_name = {p.name: p for p in FETCH_PROVIDERS}
        return [by_name[n] for n in prio if n in by_name]

    def provider_ready(self, p: FetchProvider) -> Tuple[bool, str]:
        key = (self.cfg.api_keys or {}).get(p.api_key_field, "")
        if not p.keyless and not key:
            return False, "no API key configured"
        used = self.state.api_usage(p.name, monthly=p.monthly)["credits"]
        if used >= p.cap:
            return False, f"free cap exhausted ({used}/{p.cap})"
        return True, ""

    def fetch(self, url: str, provider: str = "auto") -> Tuple[str, str, str]:
        """Returns (provider_used, content, error)."""
        cand = self._ordered()
        if provider != "auto":
            cand = [p for p in cand if p.name == provider]
            if not cand:
                return "", "", f"unknown provider '{provider}'"
        for p in cand:
            ok, why = self.provider_ready(p)
            if not ok:
                self.log.info(f"fetch lane: skip {p.name} ({why})")
                continue
            key = (self.cfg.api_keys or {}).get(p.api_key_field, "")
            try:
                req_url, body, extra = p.build_request(url, key)
                status, text = _http_request(req_url, body=body,
                                             headers=extra, timeout=90)
                if status != 200 or not text.strip():
                    raise OSError(f"HTTP {status}, {len(text)} bytes")
                content = p.extract(status, text)
                self.state.add_api_usage(p.name, credits=1,
                                         monthly=p.monthly)
                self.log.info(
                    f"fetch lane: {p.name} OK "
                    f"({self.state.api_usage(p.name, monthly=p.monthly)['credits']}"
                    f"/{p.cap} credits)")
                return p.name, content, ""
            except Exception as e:
                self.log.warning(f"fetch lane: {p.name} failed: {e}")
                continue
        return "", "", ("no scraping-API provider available - configure keys "
                        "in config.api_keys or wait for monthly quota reset "
                        "(see `ip-rotator api-status`)")

    def status_table(self) -> List[dict]:
        rows = []
        for p in self._ordered():
            ready, why = self.provider_ready(p)
            usage = self.state.api_usage(p.name, monthly=p.monthly)
            rows.append({
                "provider": p.name,
                "free_cap": p.cap,
                "period": "monthly" if p.monthly else "one-time",
                "credits_used": usage["credits"],
                "key": "keyless" if p.keyless else (
                    "configured" if (self.cfg.api_keys or {}).get(p.api_key_field)
                    else "MISSING"),
                "ready": ready,
                "note": why or "ready",
                "docs": p.docs,
            })
        return rows
