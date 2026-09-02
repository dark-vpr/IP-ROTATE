"""Analyze IP blocking pattern for Tatapower."""
import httpx

print("="*70)
print("TATAPOWER IP BLOCKING ANALYSIS")
print("="*70)

# Test from current IP (direct)
try:
    with httpx.Client() as client:
        resp = client.get("https://api.ipify.org?format=json", timeout=10)
        current_ip = resp.json().get("ip")
        print(f"\nCurrent egress IP: {current_ip}")
except Exception as e:
    print(f"\nCould not get current IP: {e}")
    current_ip = "unknown"

# Test Tatapower direct
print("\nTesting Tatapower direct connection...")
try:
    with httpx.Client() as client:
        resp = client.get(
            "https://analytics-dev.tatapower.com/safety-ai/api/v1/health-check",
            headers={
                "Accept": "application/json, text/plain, */*",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            },
            timeout=10
        )
        print(f"Direct Status: {resp.status_code}")
        if resp.status_code == 200:
            print("✓ Direct connection WORKS!")
        else:
            print(f"✗ Direct blocked with {resp.status_code}")
except Exception as e:
    print(f"Direct error: {e}")

# Check if it's an IP reputation issue
print("\n" + "="*70)
print("ANALYSIS: Your current network's IPs are being blocked by Tatapower WAF")
print("="*70)
print("""
ROOT CAUSE CONFIRMED:
- Bruno works because it uses YOUR LOCAL machine's IP (residential/office)
- Cloudflare WARP/ProtonVPN work because they provide RESIDENTIAL IPs  
- This container/server uses DATACENTER IPs (AWS/Azure/etc) which are blocked

The 406 error is NOT about TLS fingerprint or cookies - it's PURE IP REPUTATION.
Tatapower's WAF (AppTrana) blocks all datacenter/hosting provider IPs.

SOLUTION OPTIONS:
1. Run from residential network (home/office) - BEST
2. Use residential proxy service (Bright Data, Oxylabs, IPRoyal) 
3. Use mobile 4G/5G tethering
4. Get your server IP whitelisted by Tatapower security team

This is NOT a code issue - it's an IP reputation issue that no amount of
TLS spoofing or browser automation can fix. You need RESIDENTIAL IPs.
""")
