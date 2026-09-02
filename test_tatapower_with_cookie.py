#!/usr/bin/env python3
"""
Live test for Tatapower with session cookie from Bruno.

Based on your Bruno request, the key is the sess_map cookie.
This test uses that exact cookie to authenticate the session.
"""

import sys
sys.path.insert(0, '/workspace/app')

from ip_rotator.httpkit import curl_chrome_request

# Your Bruno session cookie (extracted from working Bruno request)
BRUNO_SESSION_COOKIE = "sess_map=wqsubytxrcqecarvataewutdyrewddfffcutytddetedvxtuvxewzbtaerfucwedttabffaycrtqwuczqxqcauuawrwvqxwyewzyrxwvrsdtszffxddcudywceecdwtwdvvtdrdavdqysdqsvfazeevayaqbcfyaexsdawdeyeaaybsq"

# Target URL
URL = "https://analytics-dev.tatapower.com/safety-ai/api/v1/health-check"

# Bruno-like headers
HEADERS = {
    "Accept": "application/json, text/plain, */*",
    "Content-Type": "application/json",
    "User-Agent": "bruno-runtime/4.1.0",
    "request-start-time": "1787635824563",
    "Accept-Encoding": "gzip, deflate, br",
    "Host": "analytics-dev.tatapower.com",
    "Connection": "keep-alive",
}

print("=" * 80)
print("TATAPOWER TEST - Using Bruno Session Cookie + Chrome 131 Fingerprint")
print("=" * 80)
print(f"\nTarget: {URL}")
print(f"Cookie: {BRUNO_SESSION_COOKIE[:50]}...")
print()

# Test 1: Direct with Bruno cookie (no proxy)
print("Test 1: Direct connection with Bruno cookie (baseline)...")
result1 = curl_chrome_request(
    url=URL,
    method="GET",
    headers=HEADERS,
    cookies={"sess_map": BRUNO_SESSION_COOKIE.split("=")[1]},
    timeout=30,
)
print(f"  Status: {result1['status_code']}")
print(f"  Success: {result1['success']}")
if result1.get('json'):
    print(f"  Response: {result1['json']}")
elif result1.get('text'):
    print(f"  Response: {result1['text'][:200]}")
if not result1['success']:
    print(f"  Error: {result1.get('error', 'Unknown')}")
print()

# Test 2: With proxy (if available)
print("Test 2: Via rotator proxy (127.0.0.1:8000) with Bruno cookie...")
try:
    result2 = curl_chrome_request(
        url=URL,
        method="GET",
        headers=HEADERS,
        cookies={"sess_map": BRUNO_SESSION_COOKIE.split("=")[1]},
        proxy="http://127.0.0.1:8000",
        timeout=30,
    )
    print(f"  Status: {result2['status_code']}")
    print(f"  Success: {result2['success']}")
    if result2.get('json'):
        print(f"  Response: {result2['json']}")
    elif result2.get('text'):
        print(f"  Response: {result2['text'][:200]}")
    if not result2['success']:
        print(f"  Error: {result2.get('error', 'Unknown')}")
except Exception as e:
    print(f"  Exception: {e}")
print()

# Test 3: Without cookie (should fail with 406)
print("Test 3: Direct without cookie (control - should fail)...")
result3 = curl_chrome_request(
    url=URL,
    method="GET",
    headers=HEADERS,
    timeout=30,
)
print(f"  Status: {result3['status_code']}")
print(f"  Success: {result3['success']}")
if not result3['success']:
    print(f"  Expected failure (no cookie)")
print()

print("=" * 80)
print("SUMMARY")
print("=" * 80)
if result1['success']:
    print("✅ SUCCESS: Bruno cookie + Chrome fingerprint works!")
    print("   The session cookie is the key to bypassing Tatapower WAF.")
else:
    print("❌ FAILED: Even with Bruno cookie, request blocked.")
    print("   Possible reasons:")
    print("   1. Cookie expired (sess_map is time-limited)")
    print("   2. IP blacklisted (need residential IP via WARP/WireGuard)")
    print("   3. Additional authentication required")

print("\nRECOMMENDATION:")
print("  Extract fresh sess_map cookie from Bruno after a successful request,")
print("  then use it in your automated requests via the wafbypass module.")
