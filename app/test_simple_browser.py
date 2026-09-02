"""Simple browser test to debug Playwright issues."""
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-setuid-sandbox"])
    page = browser.new_page()
    
    # Try without proxy first
    print("Testing Tatapower with Playwright (no proxy)...")
    try:
        response = page.goto("https://analytics-dev.tatapower.com/safety-ai/api/v1/health-check", wait_until="networkidle", timeout=30000)
        print(f"Status: {response.status}")
        content = page.inner_text("body")
        print(f"Response: {content[:200]}")
    except Exception as e:
        print(f"Error: {e}")
    
    browser.close()
