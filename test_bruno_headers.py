#!/usr/bin/env python3
"""Test exact Bruno headers including the session cookie"""

import asyncio
import httpx

TARGET = "https://analytics-dev.tatapower.com/safety-ai/api/v1/health-check"

# Exact headers from Bruno's successful request
BRUNO_HEADERS = {
    "Accept": "application/json, text/plain, */*",
    "Content-Type": "application/json",
    "User-Agent": "bruno-runtime/4.1.0",
    "Cookie": "sess_map=wqsubytxrcqecarvataewutdyrewddfffcutytddetedvxtuvxewzbtaerfucwedttabffaycrtqwuczqxqcauuawrwvqxwyewzyrxwvrsdtszffxddcudywceecdwtwdvvtdrdavdqysdqsvfazeevayaqbcfyaexsdawdeyeaaybsq",
}

async def test_direct_bruno():
    """Test direct connection with Bruno's exact headers"""
    try:
        async with httpx.AsyncClient(http2=True, verify=False) as client:
            resp = await client.get(TARGET, headers=BRUNO_HEADERS, timeout=10)
            return {
                "success": resp.status_code == 200,
                "status": resp.status_code,
                "method": "direct-bruno-headers",
                "data": resp.json() if resp.status_code == 200 else None
            }
    except Exception as e:
        return {"success": False, "status": str(e), "method": "direct-bruno-headers"}

async def test_chrome_with_cookie():
    """Test Chrome UA with Bruno's cookie"""
    try:
        import httpx
        headers = BRUNO_HEADERS.copy()
        headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        
        async with httpx.AsyncClient(http2=True, verify=False) as client:
            resp = await client.get(TARGET, headers=headers, timeout=10)
            return {
                "success": resp.status_code == 200,
                "status": resp.status_code,
                "method": "chrome-with-bruno-cookie",
                "data": resp.json() if resp.status_code == 200 else None
            }
    except Exception as e:
        return {"success": False, "status": str(e), "method": "chrome-with-bruno-cookie"}

async def test_curl_cffi_with_cookie():
    """Test curl_cffi with Bruno's cookie"""
    try:
        from curl_cffi import requests
        headers = BRUNO_HEADERS.copy()
        headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        
        resp = requests.get(
            TARGET,
            headers=headers,
            impersonate="chrome131",
            verify=False,
            timeout=10
        )
        return {
            "success": resp.status_code == 200,
            "status": resp.status_code,
            "method": "curl_cffi-chrome131-with-bruno-cookie",
            "data": resp.json() if resp.status_code == 200 else None
        }
    except Exception as e:
        return {"success": False, "status": str(e), "method": "curl_cffi-chrome131-with-bruno-cookie"}

async def main():
    print("=" * 80)
    print("TESTING BRUNO'S SUCCESS FACTOR - COOKIE ANALYSIS")
    print("=" * 80)
    
    tests = [
        ("Direct + Bruno Headers", test_direct_bruno),
        ("Chrome UA + Bruno Cookie", test_chrome_with_cookie),
        ("curl_cffi + Bruno Cookie", test_curl_cffi_with_cookie),
    ]
    
    results = []
    for name, test_func in tests:
        print(f"\nTesting: {name}...")
        result = await test_func()
        results.append(result)
        status_icon = "✅ SUCCESS" if result["success"] else "❌ FAILED"
        print(f"  {status_icon} | Status: {result['status']}")
        if result.get("data"):
            print(f"  Response: {result['data']}")
    
    print("\n" + "=" * 80)
    successes = [r for r in results if r["success"]]
    print(f"Passed: {len(successes)}/{len(results)}")
    
    if successes:
        print("\n🎉 KEY INSIGHT: Bruno's session COOKIE is the bypass mechanism!")
        print("   The WAF trusts established sessions, not just TLS fingerprints.")
    
    return len(successes) > 0

if __name__ == "__main__":
    success = asyncio.run(main())
    exit(0 if success else 1)
