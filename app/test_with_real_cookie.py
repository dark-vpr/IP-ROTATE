"""Test with REAL session cookie from Bruno."""
from playwright.sync_api import sync_playwright

# This is the ACTUAL working cookie from your Bruno request
REAL_COOKIE = "sess_map=aawzyvazcxfdyuaxaefxrytdezudswxuryqyvxexxtzzwycrzxqycdudwvzbsbeysstfvuaqwrddetvuczeyqcdceexcysewsvrtsaeqyabbayvfeyydrfdcwqxtadufyrctxxtywysqsxutqvrwryayefxyuwtssqyvxcutdcstdesq"

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-setuid-sandbox"])
    
    # Create context with the working cookie
    context = browser.new_context(
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        cookies=[
            {
                "name": "sess_map",
                "value": "aawzyvazcxfdyuaxaefxrytdezudswxuryqyvxexxtzzwycrzxqycdudwvzbsbeysstfvuaqwrddetvuczeyqcdceexcysewsvrtsaeqyabbayvfeyydrfdcwqxtadufyrctxxtywysqsxutqvrwryayefxyuwtssqyvxcutdcstdesq",
                "domain": ".tatapower.com",
                "path": "/",
                "secure": True,
                "httpOnly": True,
            }
        ]
    )
    
    page = context.new_page()
    
    print("Testing Tatapower with Playwright + REAL SESSION COOKIE...")
    try:
        response = page.goto("https://analytics-dev.tatapower.com/safety-ai/api/v1/health-check", wait_until="networkidle", timeout=30000)
        print(f"Status: {response.status}")
        content = page.inner_text("body")
        print(f"Response: {content[:300]}")
        
        if response.status == 200:
            print("\n✓ SUCCESS! Cookie authentication works!")
        else:
            print(f"\n✗ Still getting {response.status} - cookie may be expired or IP-based blocking")
    except Exception as e:
        print(f"Error: {e}")
    
    browser.close()
