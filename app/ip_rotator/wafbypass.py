"""WAF-bypass relay layer using curl_cffi Chrome impersonation.

This module provides an alternative request path for targets with TLS
fingerprinting WAFs (AppTrana, Cloudflare, Akamai, DataDome, etc.).

When the standard HTTP CONNECT/SOCKS5 tunnel fails with 406/403 errors,
the system automatically falls back to this curl_cffi-based approach that
impersonates Chrome 131's exact TLS fingerprint.

Key features:
  - Chrome 131 TLS fingerprint impersonation
  - Bruno-like headers and cookie handling
  - Proxy chain support (route through rotator's upstreams)
  - Automatic fallback from standard tunnel on WAF detection
  - Session cookie persistence for authenticated endpoints
"""
import time
from typing import Optional, Tuple, Dict, Any, List

from .httpkit import curl_chrome_request, UA
from .dialer import Upstream


class WafBypassRelay:
    """
    WAF-bypass aware request handler.
    
    Usage pattern:
      1. Try standard tunnel via relay.dial_with_failover()
      2. If response is 406/403 with WAF signatures, switch to this class
      3. curl_chrome_request() handles the rest with Chrome fingerprint
    """
    
    # WAF detection signatures in responses
    WAF_SIGNATURES = [
        "406 Not Acceptable",
        "403 Forbidden",
        "AppTrana",
        "cloudflare",
        "akamai",
        "datadome",
        "incapsula",
        "sucuri",
        "wordfence",
        "Request was blocked",
        "suspicious behavior",
        "Access denied",
    ]
    
    def __init__(self):
        self.session_cookies: Dict[str, Dict[str, str]] = {}
        self.request_count = 0
        self.successful_requests = 0
    
    def is_waf_response(self, status_code: int, headers: Dict[str, str], text: str) -> bool:
        """Detect if response is from a WAF blocking the request."""
        if status_code in (406, 403, 429):
            return True
        
        header_str = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
        text_lower = text.lower()
        
        for sig in self.WAF_SIGNATURES:
            if sig.lower() in header_str or sig.lower() in text_lower:
                return True
        
        return False
    
    def extract_session_cookie(self, headers: Dict[str, str]) -> Optional[Dict[str, str]]:
        """Extract session cookies from Set-Cookie headers."""
        set_cookie = headers.get("Set-Cookie", "")
        if not set_cookie:
            return None
        
        cookies = {}
        # Parse Set-Cookie header (can be multiple, comma-separated)
        for cookie_part in set_cookie.split(","):
            if "=" in cookie_part:
                key_val = cookie_part.split(";")[0].strip()
                if "=" in key_val:
                    key, val = key_val.split("=", 1)
                    cookies[key.strip()] = val.strip()
        
        return cookies if cookies else None
    
    def make_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Any] = None,
        proxy_url: Optional[str] = None,
        timeout: int = 30,
        use_session_cookies: bool = True,
        domain: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Make a WAF-bypass request with Chrome 131 fingerprint.
        
        Args:
            url: Target URL
            method: HTTP method
            headers: Custom headers (merged with defaults)
            data: Request body for POST/PUT
            proxy_url: Upstream proxy (from rotator pool)
            timeout: Request timeout
            use_session_cookies: Use stored session cookies
            domain: Domain for cookie lookup (extracted from URL if not provided)
        
        Returns:
            Dict with status_code, headers, text, json, success, waf_bypass_used
        """
        self.request_count += 1
        
        # Extract domain for cookie management
        if not domain:
            from urllib.parse import urlparse
            domain = urlparse(url).netloc
        
        # Get stored cookies for this domain
        cookies = None
        if use_session_cookies and domain in self.session_cookies:
            cookies = self.session_cookies[domain]
        
        # Make request via curl_cffi
        result = curl_chrome_request(
            url=url,
            method=method,
            headers=headers,
            data=data,
            proxy=proxy_url,
            timeout=timeout,
            cookies=cookies,
        )
        
        # Store any new session cookies
        if result.get("headers"):
            new_cookies = self.extract_session_cookie(result["headers"])
            if new_cookies:
                if domain not in self.session_cookies:
                    self.session_cookies[domain] = {}
                self.session_cookies[domain].update(new_cookies)
        
        # Track success
        if result.get("success"):
            self.successful_requests += 1
        
        result["waf_bypass_used"] = True
        result["chrome_fingerprint"] = "chrome131"
        result["request_number"] = self.request_count
        
        return result
    
    def test_target(
        self,
        url: str,
        proxy_url: Optional[str] = None,
        expected_status: int = 200,
    ) -> Dict[str, Any]:
        """
        Test if a target is accessible with WAF bypass.
        
        Returns detailed diagnostics about the connection.
        """
        result = self.make_request(url, proxy_url=proxy_url)
        
        diagnostics = {
            "url": url,
            "proxy_used": proxy_url or "direct",
            "status_code": result.get("status_code"),
            "success": result.get("success"),
            "waf_detected": self.is_waf_response(
                result.get("status_code", 0),
                result.get("headers", {}),
                result.get("text", ""),
            ),
            "response_time_ms": result.get("response_time_ms"),
            "has_session_cookie": bool(
                self.session_cookies.get(urlparse(url).netloc)
            ),
        }
        
        from urllib.parse import urlparse
        
        return diagnostics
    
    def get_stats(self) -> Dict[str, Any]:
        """Get usage statistics."""
        return {
            "total_requests": self.request_count,
            "successful_requests": self.successful_requests,
            "success_rate": (
                self.successful_requests / self.request_count * 100
                if self.request_count > 0 else 0
            ),
            "active_sessions": len(self.session_cookies),
            "domains_with_cookies": list(self.session_cookies.keys()),
        }
    
    def clear_session(self, domain: Optional[str] = None):
        """Clear stored cookies for a domain or all domains."""
        if domain:
            self.session_cookies.pop(domain, None)
        else:
            self.session_cookies.clear()


# Singleton instance for process-wide use
_waf_relay: Optional[WafBypassRelay] = None


def get_waf_relay() -> WafBypassRelay:
    """Get or create the singleton WAF bypass relay instance."""
    global _waf_relay
    if _waf_relay is None:
        _waf_relay = WafBypassRelay()
    return _waf_relay


def smart_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    data: Optional[Any] = None,
    proxy_url: Optional[str] = None,
    timeout: int = 30,
    try_standard_first: bool = True,
) -> Dict[str, Any]:
    """
    Smart request handler that tries standard tunnel first, then WAF bypass.
    
    This is the recommended entry point for all requests. It automatically
    detects WAF blocking and switches to Chrome fingerprint mode.
    
    Args:
        url: Target URL
        method: HTTP method
        headers: Custom headers
        data: Request body
        proxy_url: Upstream proxy from rotator pool
        timeout: Request timeout
        try_standard_first: If True, try httpx first (for speed)
    
    Returns:
        Dict with full response details + metadata about which method succeeded
    """
    result = {
        "url": url,
        "method": method,
        "proxy_used": proxy_url,
        "attempts": [],
    }
    
    # Attempt 1: Standard httpx (if enabled)
    if try_standard_first:
        try:
            import httpx
            with httpx.Client(
                proxy=proxy_url,
                timeout=timeout,
                verify=False,
                headers=headers or {},
            ) as client:
                resp = client.request(method, url)
                std_result = {
                    "method": "httpx-standard",
                    "status_code": resp.status_code,
                    "headers": dict(resp.headers),
                    "text": resp.text[:1000],
                    "success": resp.status_code < 400,
                }
                result["attempts"].append(std_result)
                
                # Check if this looks like a WAF block
                waf_relay = get_waf_relay()
                if not waf_relay.is_waf_response(
                    resp.status_code, std_result["headers"], std_result["text"]
                ):
                    # Standard worked, return it
                    result.update(std_result)
                    result["method_used"] = "httpx-standard"
                    result["waf_bypass_needed"] = False
                    return result
                
        except Exception as e:
            result["attempts"].append({
                "method": "httpx-standard",
                "error": str(e),
                "success": False,
            })
    
    # Attempt 2: curl_cffi with Chrome fingerprint
    waf_relay = get_waf_relay()
    chrome_result = waf_relay.make_request(
        url=url,
        method=method,
        headers=headers,
        data=data,
        proxy_url=proxy_url,
        timeout=timeout,
    )
    result["attempts"].append(chrome_result)
    result.update(chrome_result)
    result["method_used"] = "curl_cffi-chrome131"
    result["waf_bypass_needed"] = True
    
    return result
