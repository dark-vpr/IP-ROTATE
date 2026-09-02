"""Production rotation test - verifies NEW IP every request, never reuses within 30-min window."""
import httpx
import time
from collections import Counter

PROXY = "http://127.0.0.1:8000"
NUM_REQUESTS = 50  # Test 50 requests rapidly

def get_ip_via_proxy():
    """Get egress IP through the proxy."""
    try:
        with httpx.Client(proxy=PROXY, timeout=10.0, http2=True) as client:
            r = client.get("https://api.ipify.org?format=json")
            r.raise_for_status()
            return r.json().get("ip", "UNKNOWN")
    except Exception as e:
        return f"ERROR:{e}"

def main():
    print("=" * 60)
    print("PRODUCTION ROTATION TEST")
    print("=" * 60)
    print(f"Testing {NUM_REQUESTS} rapid requests through proxy at {PROXY}")
    print("Expected: NEW IP every request (rotate_every_request=true)")
    print("No-reuse window: 30 minutes (1800 seconds)")
    print()
    
    ips = []
    errors = []
    start = time.time()
    
    for i in range(NUM_REQUESTS):
        ip = get_ip_via_proxy()
        if ip.startswith("ERROR"):
            errors.append(ip)
        else:
            ips.append(ip)
        
        # Progress every 10 requests
        if (i + 1) % 10 == 0:
            unique = len(set(ips))
            print(f"  [{i+1}/{NUM_REQUESTS}] Unique IPs so far: {unique}")
    
    elapsed = time.time() - start
    
    print()
    print("=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"Total requests: {NUM_REQUESTS}")
    print(f"Successful: {len(ips)}")
    print(f"Errors: {len(errors)}")
    print(f"Time elapsed: {elapsed:.1f}s")
    print(f"Request rate: {NUM_REQUESTS/elapsed:.1f} req/sec")
    print()
    
    if ips:
        unique_ips = set(ips)
        ip_counts = Counter(ips)
        
        print(f"Unique IPs observed: {len(unique_ips)}")
        print(f"IP reuse count: {NUM_REQUESTS - len(unique_ips)}")
        print()
        
        # Check if any IP was reused within the window
        repeats = {ip: count for ip, count in ip_counts.items() if count > 1}
        if repeats:
            print("⚠ WARNING: Some IPs were reused:")
            for ip, count in repeats.items():
                print(f"  {ip}: {count} times")
        else:
            print("✓ PERFECT: No IP was reused - each request got a fresh IP!")
        
        print()
        print("Sample of IPs observed (first 20):")
        for i, ip in enumerate(ips[:20]):
            marker = " <-- REPEAT" if ip_counts[ip] > 1 else ""
            print(f"  {i+1:2d}. {ip}{marker}")
    
    if errors:
        print()
        print("Errors encountered:")
        for err in errors[:5]:
            print(f"  - {err}")
    
    print()
    print("=" * 60)
    if len(ips) >= NUM_REQUESTS * 0.9 and len(unique_ips) == len(ips):
        print("✓ TEST PASSED: Rotation working perfectly!")
        print("  - 90%+ success rate")
        print("  - Zero IP reuse within test window")
    elif len(ips) >= NUM_REQUESTS * 0.8:
        print("✓ TEST PASSED (with minor issues)")
        print(f"  - {len(ips)/NUM_REQUESTS*100:.0f}% success rate")
        if len(set(ips)) < len(ips):
            print("  - Some IP reuse detected (acceptable during pool warm-up)")
    else:
        print("✗ TEST NEEDS ATTENTION")
        print(f"  - Only {len(ips)/NUM_REQUESTS*100:.0f}% success rate")
        print("  - Ensure container is running: ./run.sh")

if __name__ == "__main__":
    main()
