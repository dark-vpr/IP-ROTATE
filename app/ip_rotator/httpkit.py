"""Shared httpx client + tiny helpers.

One process-wide httpx.Client for harvesting / IP echo / API calls.
It is thread-safe (httpx guarantees this) and configured to be
DETERMINISTIC:

  * trust_env=False -> ambient HTTP(S)_PROXY / ALL_PROXY environment
    variables are IGNORED. This is a correctness fix: validation must
    measure the upstream we chose, never an accidental env-proxy chain
    (classic "validator lies about the egress IP" bug).
  * verify=True (default) -> certificate failures = MITM signature.
  * http2="auto" -> enables HTTP/2 negotiation when target supports it
    (modern standard for performance, reduces latency, header compression).
"""
import json
import socket
from typing import Optional

import httpx

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"

_client: Optional[httpx.Client] = None


def http_client() -> httpx.Client:
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.Client(
            headers={"User-Agent": UA},
            timeout=httpx.Timeout(20.0, connect=10.0),
            verify=True,
            follow_redirects=False,
            trust_env=False,
            http2=True,  # Enable HTTP/2 support for modern targets
            limits=httpx.Limits(max_connections=128,
                                max_keepalive_connections=24),
        )
    return _client


def close_client() -> None:
    global _client
    if _client is not None and not _client.is_closed:
        try:
            _client.close()
        except Exception:
            pass
    _client = None


# ---------------------------------------------------------------------------
# DNS-over-HTTPS (used ONLY by the 'direct' backbone so the local resolver
# is never consulted for targets; cached process-wide)
# ---------------------------------------------------------------------------
_DOH_CACHE: dict = {}


def doh_resolve(host: str, timeout: float = 5.0) -> str:
    if host in _DOH_CACHE:
        return _DOH_CACHE[host]
    try:
        r = http_client().get(
            f"https://1.1.1.1/dns-query?name={host}&type=A",
            headers={"accept": "application/dns-json"},
            timeout=timeout)
        data = r.json()
        ip = next(a["data"] for a in data.get("Answer", [])
                  if a.get("type") == 1)
        _DOH_CACHE[host] = ip
        return ip
    except Exception:
        # documented fallback for direct mode only
        return socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]


def get_text(url: str, timeout: float = 20.0, max_bytes: int = 4 * 1024 * 1024,
             headers: Optional[dict] = None) -> str:
    """GET -> text (used by the harvester; raises httpx errors on failure)."""
    r = http_client().get(url, timeout=timeout, headers=headers or {})
    r.raise_for_status()
    return r.text[:max_bytes]


def get_json(url: str, headers: Optional[dict] = None,
             timeout: float = 20.0) -> dict:
    r = http_client().get(url, headers=headers or {}, timeout=timeout)
    r.raise_for_status()
    return json.loads(r.text)
