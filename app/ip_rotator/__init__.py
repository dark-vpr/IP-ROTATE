"""ip_rotator — free & freemium (no credit card) self-healing IP rotation gateway.

Point your crawler at ONE local address pair:
  * HTTP proxy  : http://127.0.0.1:8000   (curl -x, requests, scrapy, ...)
  * SOCKS5 proxy: 127.0.0.1:1080          (Burp Suite, curl --socks5-hostname, ...)

Behind them the tool:
  * keeps N warm WireGuard tunnels up (wireproxy, no root): free WARP
    accounts (no card/email/login) + your own wg-quick configs — each
    tunnel is a distinct clean egress IP, and switching IP is just
    picking a different already-connected port (zero dial delay),
  * harvests free proxies from many public sources (backoff + caching),
    strictly validating them end-to-end (TLS certificate verified via
    httpx, TRUE egress IP recorded, MITM + transparent proxies rejected),
  * rotates to a NEVER-BEFORE-USED egress IP every N seconds (default 10)
    enforced by a persistent SQLite ledger; in-flight tunnels drain,
    they are never killed mid-stream,
  * fails over per-request across lanes, and when an entire chain fails
    it HOLDS the request (survival window) until any lane recovers —
    "no request left behind",
  * meters every capped free tier (Webshare 1 GB/mo, VPN 10 GB/mo,
    scraping-API credits) and auto-disables a lane at its cap,
  * opt-in dirty lanes (Psiphon, VPN Gate) for when you accept flagged
    shared egress; Tor stays REMOVED (mass-blacklisted class).

Docs: README.md + docs/01..08 (install, curl verification, Burp setup,
reliability design, provider landscape, auth guides, config, issue log).

Python 3.9+. Runtime deps: httpx[socks], python-socks, rich (uv-managed).
"""

__version__ = "3.1.0"
