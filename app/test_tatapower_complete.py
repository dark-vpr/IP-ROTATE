"""Complete Tatapower test with all bypass methods."""
import sys
sys.path.insert(0, '/workspace/app')

from ip_rotator.httpkit import curl_chrome_request
from ip_rotator.wafbypass import smart_request, get_waf_relay
from ip_rotator.browser import BrowserAutomation

TARGET_URL = "https://analytics-dev.tatapower.com/safety-ai/api/v1/health-check"

# Bruno headers that work
BRUNO_HEADERS = {
    "Accept": "application/json, text/plain, */*",
    "Content-Type": "application/json",
    "User-Agent": "bruno-runtime/4.1.0",
    "Accept-Encoding": "gzip, deflate, br",
    "Host": "analytics-dev.tatapower.com",
    "Connection": "keep-alive",
}

print("="*70)
print("TATAPOWER COMPLETE TEST SUITE")
print("="*70)

# Test 1: curl_cffi Chrome 131 fingerprint (no proxy)
print("\n[TEST 1] curl_cffi Chrome 131 (direct, no proxy)")
print("-"*50)
result1 = curl_chrome_request(TARGET_URL, headers=BRUNO_HEADERS)
print(f"Status: {result1.get('status_code')}")
print(f"Success: {result1.get('success')}")
if result1.get('json'):
    print(f"Response: {result1['json']}")
if result1.get('error'):
    print(f"Error: {result1['error']}")

# Test 2: Smart request (tries standard first, then curl_cffi)
print("\n[TEST 2] Smart Request (auto-detect WAF)")
print("-"*50)
result2 = smart_request(TARGET_URL, headers=BRUNO_HEADERS, try_standard_first=False)
print(f"Method Used: {result2.get('method_used')}")
print(f"Status: {result2.get('status_code')}")
print(f"Success: {result2.get('success')}")
print(f"WAF Bypass Needed: {result2.get('waf_bypass_needed')}")
if result2.get('json'):
    print(f"Response: {result2['json']}")

# Test 3: Browser automation (ultimate fallback)
print("\n[TEST 3] Playwright Browser Automation")
print("-"*50)
try:
    browser = BrowserAutomation(headless=True)
    result3 = browser.request(TARGET_URL, wait_timeout=30.0)
    print(f"Status: {result3.get('status_code')}")
    print(f"Success: {result3.get('success')}")
    print(f"Method: {result3.get('method_used')}")
    if result3.get('text'):
        print(f"Response text: {result3['text'][:200]}")
    browser.close()
except Exception as e:
    print(f"Browser test failed: {e}")

# Test 4: With session cookie (if you have one from Bruno)
print("\n[TEST 4] curl_cffi with Session Cookie")
print("-"*50)
# Replace with actual cookie from Bruno if you have it
TEST_COOKIE = {
    "sess_map": "aawzyvazcxfdyuaxaefxrytdezudswxuryqyvxexxtzzwycrzxqycdudwvzbsbeysstfvuaqwrddetvuczeyqcdceexcysewsvrtsaeqyabbayvfeyydrfdcwqxtadufyrctxxtywysqsxutqvrwryayefxyuwtssqyvxcutdcstdesq"
}
result4 = curl_chrome_request(TARGET_URL, headers=BRUNO_HEADERS, cookies=TEST_COOKIE)
print(f"Status: {result4.get('status_code')}")
print(f"Success: {result4.get('success')}")
if result4.get('json'):
    print(f"Response: {result4['json']}")

print("\n" + "="*70)
print("TEST SUMMARY")
print("="*70)
tests = [
    ("curl_cffi direct", result1.get('success', False)),
    ("smart_request", result2.get('success', False)),
    ("browser_automation", result3.get('success', False) if 'result3' in dir() else False),
    ("with_session_cookie", result4.get('success', False)),
]

for name, success in tests:
    status = "✓ PASS" if success else "✗ FAIL"
    print(f"{status}: {name}")

print("\nRecommendation:")
if result1.get('success'):
    print("→ Use curl_cffi for fast WAF bypass (recommended)")
elif result3.get('success'):
    print("→ Use Playwright browser automation (slower but 100% reliable)")
else:
    print("→ All methods failed - may need IP whitelisting or residential IPs")
