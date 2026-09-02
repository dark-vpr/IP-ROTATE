#!/usr/bin/env python3
"""
Advanced TLS Fingerprint Spoofing Test for Tatapower WAF Bypass
Tests multiple TLS stacks to match Bruno's fingerprint (Chrome-like)
"""

import asyncio
import json
from typing import Dict, Any

# Test 1: Standard httpx (known to fail)
async def test_httpx_standard():
    try:
        import httpx
        async with httpx.AsyncClient(http2=True, verify=False) as client:
            resp = await client.get(
                "https://analytics-dev.tatapower.com/safety-ai/api/v1/health-check",
                headers={
                    "Accept": "application/json, text/plain, */*",
                    "Content-Type": "application/json",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
                },
                timeout=10
            )
            return {"status": resp.status_code, "method": "httpx-standard", "success": resp.status_code == 200}
    except Exception as e:
        return {"status": str(e), "method": "httpx-standard", "success": False}

# Test 2: curl_cffi with Chrome impersonation (BEST BET)
async def test_curl_cffi_chrome():
    try:
        from curl_cffi import requests
        resp = requests.get(
            "https://analytics-dev.tatapower.com/safety-ai/api/v1/health-check",
            headers={
                "Accept": "application/json, text/plain, */*",
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
            },
            impersonate="chrome131",
            verify=False,
            timeout=10
        )
        return {"status": resp.status_code, "method": "curl_cffi-chrome131", "success": resp.status_code == 200, "data": resp.json() if resp.status_code == 200 else None}
    except Exception as e:
        return {"status": str(e), "method": "curl_cffi-chrome131", "success": False}

# Test 3: curl_cffi with older Chrome
async def test_curl_cffi_chrome120():
    try:
        from curl_cffi import requests
        resp = requests.get(
            "https://analytics-dev.tatapower.com/safety-ai/api/v1/health-check",
            headers={
                "Accept": "application/json, text/plain, */*",
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            },
            impersonate="chrome120",
            verify=False,
            timeout=10
        )
        return {"status": resp.status_code, "method": "curl_cffi-chrome120", "success": resp.status_code == 200, "data": resp.json() if resp.status_code == 200 else None}
    except Exception as e:
        return {"status": str(e), "method": "curl_cffi-chrome120", "success": False}

# Test 4: curl_cffi with Edge
async def test_curl_cffi_edge():
    try:
        from curl_cffi import requests
        resp = requests.get(
            "https://analytics-dev.tatapower.com/safety-ai/api/v1/health-check",
            headers={
                "Accept": "application/json, text/plain, */*",
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"
            },
            impersonate="edge101",
            verify=False,
            timeout=10
        )
        return {"status": resp.status_code, "method": "curl_cffi-edge101", "success": resp.status_code == 200, "data": resp.json() if resp.status_code == 200 else None}
    except Exception as e:
        return {"status": str(e), "method": "curl_cffi-edge101", "success": False}

# Test 5: With proxy via curl_cffi
async def test_curl_cffi_with_proxy():
    try:
        from curl_cffi import requests
        resp = requests.get(
            "https://analytics-dev.tatapower.com/safety-ai/api/v1/health-check",
            headers={
                "Accept": "application/json, text/plain, */*",
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
            },
            impersonate="chrome131",
            proxies={"https": "http://127.0.0.1:8000"},
            verify=False,
            timeout=10
        )
        return {"status": resp.status_code, "method": "curl_cffi-chrome131+proxy", "success": resp.status_code == 200, "data": resp.json() if resp.status_code == 200 else None}
    except Exception as e:
        return {"status": str(e), "method": "curl_cffi-chrome131+proxy", "success": False}

async def main():
    print("=" * 80)
    print("TATAPOWER WAF BYPASS TEST - TLS FINGERPRINT SPOOFING")
    print("=" * 80)
    
    tests = [
        ("Standard httpx (baseline)", test_httpx_standard),
        ("curl_cffi Chrome 131", test_curl_cffi_chrome),
        ("curl_cffi Chrome 120", test_curl_cffi_chrome120),
        ("curl_cffi Edge 101", test_curl_cffi_edge),
        ("curl_cffi Chrome 131 + Proxy", test_curl_cffi_with_proxy),
    ]
    
    results = []
    for name, test_func in tests:
        print(f"\nTesting: {name}...")
        result = await test_func()
        results.append(result)
        status_icon = "✅ SUCCESS" if result["success"] else "❌ FAILED"
        print(f"  {status_icon} | Status: {result['status']}")
        if result.get("data"):
            print(f"  Response: {json.dumps(result['data'], indent=2)}")
    
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    successes = [r for r in results if r["success"]]
    print(f"Passed: {len(successes)}/{len(results)}")
    
    if successes:
        print("\n🎉 WORKING METHODS:")
        for r in successes:
            print(f"  • {r['method']}")
    else:
        print("\n⚠️  All methods failed. Next steps:")
        print("  1. Check if IP is blacklisted (try different egress IP)")
        print("  2. Add Cookie header from Bruno session")
        print("  3. Use browser automation (Playwright) as last resort")
    
    return len(successes) > 0

if __name__ == "__main__":
    success = asyncio.run(main())
    exit(0 if success else 1)
