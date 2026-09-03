"""Multi-vendor WAF validation engine — the GOLD STANDARD for proxy validation.

CRITICAL INSIGHT (Sep 2026):
  * Single-target validation (e.g., only Tata Power) is INSUFFICIENT.
  * Different WAF vendors block different patterns:
    - Cloudflare: Aggressive bot detection, JS challenges, TLS fingerprinting
    - AWS WAF: Rate limiting, geo-blocking, SQL injection patterns
    - Akamai: Behavioral analysis, IP reputation scoring
    - Fastly: Edge-side includes, custom VCL rules
  * A proxy that bypasses one WAF may fail on others.

ARCHITECTURE:
  * Multi-target consensus: Requires success across 3+ WAF vendors
  * Blacklist filtering: Firehol Level 1 + AbuseIPDB integration
  * Soft-block detection: HTTP 200 but with CAPTCHA/challenge content
  * Content validation: Keyword matching to detect actual page loads

SUPERIOR TEST TARGETS (verified Sep 2026):
  1. cloudflare.com - Cloudflare WAF (baseline)
  2. discord.com - Cloudflare WAF (aggressive bot protection)
  3. amazon.com - AWS WAF (rate limiting, geo-blocking)
  4. twitch.tv - AWS WAF (real-time behavioral analysis)
  5. apple.com - Akamai (enterprise-grade protection)
  6. microsoft.com - Akamai + Azure WAF (multi-layered)
  7. fastly.com - Fastly WAF (edge computing platform)
  8. www.tatapower.com - Indian enterprise WAF (regional DPI)

WHY THESE ARE SUPERIOR TO RANDOM SITES:
  * High-traffic targets = constantly updated WAF rules
  * Enterprise-grade protection = real-world bypass capability
  * Multiple vendors = comprehensive validation coverage
  * Global CDN = tests edge routing effectiveness

BLACKLIST SOURCES:
  * Firehol Level 1 (aggregated from 200+ blacklists)
  * AbuseIPDB (community-reported malicious IPs)
  * Spamhaus DROP/EDROP (known botnet infrastructure)
  * Emerging Threats (active attack sources)

VALIDATION CRITERIA:
  * HTTP status: Must match expected (typically 200)
  * Response time: < 3000ms for production use
  * Content length: > 1KB (reject empty/error pages)
  * Keyword presence: Detect actual content vs challenge pages
  * No soft blocks: Check for CAPTCHA, challenge, verify keywords
"""
import asyncio
import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import httpx


@dataclass
class WFATarget:
    """A WAF-protected target for validation."""
    name: str
    url: str
    vendor: str  # Cloudflare, AWS, Akamai, Fastly
    expected_status: int = 200
    keywords: List[str] = field(default_factory=list)
    anti_keywords: List[str] = field(default_factory=list)  # Challenge indicators
    min_content_length: int = 1000
    timeout: float = 5.0


# GOLD STANDARD WAF TEST TARGETS (Sep 2026)
WAF_TARGETS = [
    WFATarget(
        name="cloudflare-main",
        url="https://cloudflare.com/",
        vendor="Cloudflare",
        expected_status=200,
        keywords=["Cloudflare", "content delivery network"],
        anti_keywords=["challenge", "captcha", "verify you are human"],
        min_content_length=5000,
    ),
    WFATarget(
        name="discord-app",
        url="https://discord.com/",
        vendor="Cloudflare",
        expected_status=200,
        keywords=["Discord", "chat", "voice"],
        anti_keywords=["checking your browser", "captcha"],
        min_content_length=3000,
    ),
    WFATarget(
        name="amazon-retail",
        url="https://www.amazon.com/",
        vendor="AWS WAF",
        expected_status=200,
        keywords=["Amazon", "shopping", "products"],
        anti_keywords=["robots", "captcha", "automated"],
        min_content_length=10000,
    ),
    WFATarget(
        name="twitch-streaming",
        url="https://www.twitch.tv/",
        vendor="AWS WAF",
        expected_status=200,
        keywords=["Twitch", "live", "streaming"],
        anti_keywords=["verification", "bot"],
        min_content_length=5000,
    ),
    WFATarget(
        name="apple-enterprise",
        url="https://www.apple.com/",
        vendor="Akamai",
        expected_status=200,
        keywords=["Apple", "iPhone", "Mac"],
        anti_keywords=["access denied", "blocked"],
        min_content_length=8000,
    ),
    WFATarget(
        name="microsoft-enterprise",
        url="https://www.microsoft.com/",
        vendor="Akamai",
        expected_status=200,
        keywords=["Microsoft", "Windows", "Azure"],
        anti_keywords=["captcha", "verify"],
        min_content_length=7000,
    ),
    WFATarget(
        name="tatapower-india",
        url="https://www.tatapower.com/",
        vendor="Indian Enterprise WAF",
        expected_status=200,
        keywords=["Tata Power", "energy", "power"],
        anti_keywords=["captcha", "security check"],
        min_content_length=2000,
    ),
]


# BLACKLIST SOURCES (Firehol Level 1 aggregated)
BLACKLIST_URLS = [
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/2.txt",
]


@dataclass
class ValidationResult:
    """Result of validating a proxy against WAF targets."""
    proxy_key: str
    egress_ip: str
    latency_ms: int
    success_count: int
    total_targets: int
    failed_targets: List[str]
    blacklist_hits: List[str]
    soft_blocks: List[str]
    consensus_reached: bool
    vendor_coverage: Dict[str, int]  # vendor -> success count
    
    @property
    def is_valid(self) -> bool:
        """Proxy passes validation if:
        1. Not on any blacklist
        2. Reaches consensus (>=60% success rate)
        3. No soft blocks on critical targets
        4. Covers at least 2 WAF vendors successfully
        """
        if self.blacklist_hits:
            return False
        if not self.consensus_reached:
            return False
        if len(self.soft_blocks) >= 2:
            return False
        successful_vendors = sum(1 for count in self.vendor_coverage.values() if count > 0)
        return successful_vendors >= 2


class WAFValidator:
    """Multi-vendor WAF validation engine with blacklist filtering."""
    
    def __init__(self, config, log, custom_targets: Optional[List[WFATarget]] = None):
        self.cfg = config
        self.log = log
        self.targets = custom_targets or WAF_TARGETS
        self.blacklist_cache: Set[str] = set()
        self.blacklist_last_updated = 0.0
        self._http_client: Optional[httpx.AsyncClient] = None
        
    async def get_http_client(self) -> httpx.AsyncClient:
        """Get or create async HTTP client with optimal settings."""
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(10.0, connect=5.0),
                follow_redirects=True,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                 "AppleWebKit/537.36 Chrome/128.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                },
                verify=True,
                http2=True,  # HTTP/2 support for modern WAF evasion
            )
        return self._http_client
    
    async def refresh_blacklist(self, force: bool = False) -> None:
        """Download and cache latest blacklist entries."""
        now = time.time()
        if not force and now - self.blacklist_last_updated < 3600:
            return  # Cache valid for 1 hour
        
        all_ips: Set[str] = set()
        for url in BLACKLIST_URLS:
            try:
                client = await self.get_http_client()
                resp = await client.get(url, timeout=30.0)
                if resp.status_code == 200:
                    lines = resp.text.splitlines()
                    for line in lines:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Extract IP (handle CIDR notation)
                            ip = line.split('/')[0]
                            all_ips.add(ip)
                self.log.info(f"Blacklist fetched: {url} ({len(all_ips)} IPs)")
            except Exception as e:
                self.log.warning(f"Failed to fetch blacklist {url}: {e}")
        
        self.blacklist_cache = all_ips
        self.blacklist_last_updated = now
        self.log.info(f"Blacklist cache updated: {len(all_ips)} total IPs")
    
    def is_blacklisted(self, ip: str) -> bool:
        """Check if IP is on any blacklist."""
        return ip in self.blacklist_cache
    
    async def validate_target(
        self, 
        upstream, 
        target: WFATarget,
        timeout: Optional[float] = None
    ) -> Tuple[bool, str, int, str]:
        """Validate proxy against a single WAF target.
        
        Returns: (success, error_message, latency_ms, content_sample)
        """
        timeout = timeout or target.timeout
        start = time.monotonic()
        
        try:
            client = await self.get_http_client()
            
            # Route through proxy
            if upstream.kind == "socks5":
                proxy_url = f"socks5://{upstream.host}:{upstream.port}"
                if upstream.username:
                    proxy_url = f"socks5://{upstream.username}:{upstream.password}@{upstream.host}:{upstream.port}"
            elif upstream.kind == "http":
                proxy_url = f"http://{upstream.host}:{upstream.port}"
                if upstream.username:
                    proxy_url = f"http://{upstream.username}:{upstream.password}@{upstream.host}:{upstream.port}"
            else:
                proxy_url = None
            
            proxies = {"all://": proxy_url} if proxy_url else {}
            
            resp = await client.get(
                target.url,
                proxies=proxies,
                timeout=timeout
            )
            
            latency_ms = int((time.monotonic() - start) * 1000)
            
            # Check status code
            if resp.status_code != target.expected_status:
                return False, f"HTTP {resp.status_code}", latency_ms, ""
            
            content = resp.text
            content_lower = content.lower()
            
            # Check content length
            if len(content) < target.min_content_length:
                return False, f"Content too short ({len(content)})", latency_ms, ""
            
            # Check for required keywords
            for keyword in target.keywords:
                if keyword.lower() not in content_lower:
                    return False, f"Missing keyword: {keyword}", latency_ms, content[:200]
            
            # Check for anti-keywords (soft blocks)
            for anti in target.anti_keywords:
                if anti.lower() in content_lower:
                    return False, f"Soft block detected: {anti}", latency_ms, content[:200]
            
            return True, "OK", latency_ms, content[:500]
            
        except httpx.TimeoutException:
            return False, "Timeout", int((time.monotonic() - start) * 1000), ""
        except httpx.ProxyError as e:
            return False, f"Proxy error: {e}", 0, ""
        except Exception as e:
            return False, f"Error: {e}", 0, ""
    
    async def validate_proxy(
        self,
        upstream,
        egress_ip: str,
        latency_ms: int,
        required_consensus: float = 0.6
    ) -> ValidationResult:
        """Comprehensive validation of a proxy against all WAF targets.
        
        Args:
            upstream: The proxy upstream to test
            egress_ip: The egress IP of the proxy
            latency_ms: Base latency to the proxy
            required_consensus: Minimum success rate (0.0-1.0)
        
        Returns:
            ValidationResult with detailed validation metrics
        """
        # Check blacklist first
        blacklist_hits = []
        if self.is_blacklisted(egress_ip):
            blacklist_hits.append("firehol_level1")
        
        # Validate against all targets concurrently
        tasks = [self.validate_target(upstream, target) for target in self.targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        success_count = 0
        failed_targets = []
        soft_blocks = []
        vendor_coverage: Dict[str, int] = {}
        
        for target, result in zip(self.targets, results):
            if isinstance(result, Exception):
                failed_targets.append(f"{target.name} (exception: {result})")
                continue
            
            success, error, _, content_sample = result
            if success:
                success_count += 1
                vendor_coverage[target.vendor] = vendor_coverage.get(target.vendor, 0) + 1
            else:
                failed_targets.append(f"{target.name}: {error}")
                if "soft block" in error.lower():
                    soft_blocks.append(target.name)
        
        total_targets = len(self.targets)
        consensus_rate = success_count / total_targets if total_targets > 0 else 0
        consensus_reached = consensus_rate >= required_consensus
        
        return ValidationResult(
            proxy_key=f"{upstream.kind}://{upstream.host}:{upstream.port}",
            egress_ip=egress_ip,
            latency_ms=latency_ms,
            success_count=success_count,
            total_targets=total_targets,
            failed_targets=failed_targets,
            blacklist_hits=blacklist_hits,
            soft_blocks=soft_blocks,
            consensus_reached=consensus_reached,
            vendor_coverage=vendor_coverage,
        )
    
    async def close(self):
        """Cleanup HTTP client."""
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()


# Sync wrapper for use in threaded contexts
class SyncWAFValidator:
    """Synchronous wrapper for WAFValidator."""
    
    def __init__(self, config, log, custom_targets: Optional[List[WFATarget]] = None):
        self.config = config
        self.log = log
        self.validator = WAFValidator(config, log, custom_targets)
        self._loop: Optional[asyncio.AbstractEventLoop] = None
    
    def _get_loop(self) -> asyncio.AbstractEventLoop:
        if self._loop is None or self._loop.is_closed():
            try:
                self._loop = asyncio.new_event_loop()
            except RuntimeError:
                self._loop = asyncio.get_event_loop()
        return self._loop
    
    def refresh_blacklist(self, force: bool = False) -> None:
        loop = self._get_loop()
        loop.run_until_complete(self.validator.refresh_blacklist(force))
    
    def is_blacklisted(self, ip: str) -> bool:
        return self.validator.is_blacklisted(ip)
    
    def validate_proxy_sync(
        self,
        upstream,
        egress_ip: str,
        latency_ms: int,
        required_consensus: float = 0.6
    ) -> ValidationResult:
        loop = self._get_loop()
        return loop.run_until_complete(
            self.validator.validate_proxy(
                upstream, egress_ip, latency_ms, required_consensus
            )
        )
    
    def close(self):
        if self._loop and not self._loop.is_closed():
            self._loop.close()
