"""Shared httpx client + curl_cffi for TLS fingerprint spoofing.

Two client strategies:
  1. httpx.Client for harvesting / IP echo / API calls (standard TLS)
  2. curl_cffi.requests for WAF-bypass scenarios (Chrome TLS fingerprint)

DETERMINISTIC behavior:
  * trust_env=False -> ambient HTTP(S)_PROXY / ALL_PROXY environment
    variables are IGNORED. Validation measures the upstream we chose.
  * verify=True (default) -> certificate failures = MITM signature.
  * http2=True -> enables HTTP/2 negotiation for modern targets.
  * curl_cffi impersonates Chrome 131 to bypass TLS fingerprinting WAFs.
"""
import json
import socket
from typing import Optional, Dict, Any

import httpx
from curl_cffi import requests as curl_requests

# Browser-matching User-Agent for Chrome 131 (latest stable as of 2026)
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

_httpx_client: Optional[httpx.Client] = None


def http_client() -> httpx.Client:
    """Get singleton httpx client for harvesting/IP checks/API calls."""
    global _httpx_client
    if _httpx_client is None or _httpx_client.is_closed:
        _httpx_client = httpx.Client(
            headers={"User-Agent": UA},
            timeout=httpx.Timeout(20.0, connect=10.0),
            verify=True,
            follow_redirects=False,
            trust_env=False,
            http2=True,
            limits=httpx.Limits(max_connections=128, max_keepalive_connections=24),
        )
    return _httpx_client


def close_client() -> None:
    """Close the httpx client (for cleanup)."""
    global _httpx_client
    if _httpx_client is not None and not _httpx_client.is_closed:
        try:
            _httpx_client.close()
        except Exception:
            pass
    _httpx_client = None


def curl_chrome_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    data: Optional[Any] = None,
    proxy: Optional[str] = None,
    timeout: int = 30,
    cookies: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    Make a request using curl_cffi with Chrome 131 TLS fingerprint.
    
    This bypasses TLS fingerprinting WAFs (like AppTrana, Cloudflare, Akamai)
    by impersonating a real Chrome browser's TLS handshake.
    
    Args:
        url: Target URL
        method: HTTP method (GET, POST, etc.)
        headers: Custom headers dict
        data: Request body (for POST/PUT)
        proxy: Proxy URL (e.g., "http://user:pass@host:port")
        timeout: Request timeout in seconds
        cookies: Cookie dict
    
    Returns:
        Dict with keys: status_code, headers, text, json (if applicable), success
    """
    try:
        # Build headers with Bruno-like defaults
        req_headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Ch-Ua": '"Chromium";v="131", "Not_A Brand";v="24"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
        }
        if headers:
            req_headers.update(headers)
        
        # Ensure User-Agent matches Chrome 131
        if "User-Agent" not in req_headers:
            req_headers["User-Agent"] = UA
        
        # Prepare request kwargs
        kwargs = {
            "url": url,
            "headers": req_headers,
            "impersonate": "chrome131",
            "verify": False,  # WAF bypass often needs relaxed cert validation
            "timeout": timeout,
        }
        
        if proxy:
            kwargs["proxies"] = {"https": proxy, "http": proxy}
        
        if cookies:
            # Convert dict to cookie header string
            cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
            req_headers["Cookie"] = cookie_str
            kwargs["headers"] = req_headers
        
        if data:
            kwargs["data"] = data
            kwargs["headers"]["Content-Type"] = "application/json"
        
        # Execute request
        if method.upper() == "GET":
            resp = curl_requests.get(**kwargs)
        elif method.upper() == "POST":
            resp = curl_requests.post(**kwargs)
        elif method.upper() == "PUT":
            resp = curl_requests.put(**kwargs)
        elif method.upper() == "DELETE":
            resp = curl_requests.delete(**kwargs)
        else:
            resp = curl_requests.request(method, **kwargs)
        
        result = {
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "text": resp.text,
            "success": resp.status_code < 400,
        }
        
        # Try to parse JSON if response looks like JSON
        if "application/json" in resp.headers.get("Content-Type", ""):
            try:
                result["json"] = resp.json()
            except Exception:
                result["json"] = None
        
        return result
        
    except Exception as e:
        return {
            "status_code": 0,
            "headers": {},
            "text": "",
            "success": False,
            "error": str(e),
        }


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
