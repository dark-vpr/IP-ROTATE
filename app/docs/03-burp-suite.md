# Chapter 3 — Burp Suite (crawl through rotating IPs)

Burp Suite (2020.x through current 2026 builds) can route **all** of its
traffic through a SOCKS proxy. The gateway exposes a no-auth SOCKS5
listener on `127.0.0.1:1080` precisely because **Burp's SOCKS support has
no username/password fields** — so the gateway stays on loopback without
auth and injects upstream credentials itself when a lane needs them
(Webshare).

## 3.1 Point Burp at the gateway

1. Start the gateway (leave it running):

   ```fish
   uv run ip-rotator serve            # HTTP :8000 + SOCKS5 :1080
   # with the clean WARP lane (recommended, see chapter 6):
   uv run ip-rotator serve --warp-accounts 4
   ```

2. In Burp: **Settings → Network → Connections → SOCKS proxy**
   - SOCKS proxy host: `127.0.0.1`
   - SOCKS proxy port: `1080`
   - **Do DNS lookups through the proxy: ✔ ON** (this gives socks5h
     semantics — hostnames are resolved at the egress IP, so your local
     DNS never leaks and you look like a local visitor)

3. Make sure the upstream-proxy section is EMPTY (do not stack Burp's HTTP
   proxy field on top of the SOCKS field — pick one).

4. Verify inside Burp: open **Burp's embedded browser** and visit
   `https://checkip.amazonaws.com` — you should see a foreign IP. Reload
   after 10s — a different one.

## 3.2 What Burp's traffic looks like to the target

* Every 10 seconds the gateway switches to a never-before-used egress IP;
  Burp connections opened *before* the switch keep draining on their old
  lane (rotation never kills in-flight tunnels).
* New Burp connections land on the new lane.
* DNS is resolved at the egress (if you enabled the checkbox) — no local
  resolver query for the target ever leaves your machine.

## 3.3 Session-sensitive targets (logins, carts, WAF scoring)

If the site you crawl breaks when its IP changes mid-session, enable
per-host stickiness:

```fish
uv run ip-rotator serve --sticky          # each host keeps its lane 60s
# or in config.json: "sticky_sessions": true, "sticky_ttl": 60
```

While ON, `bank.example` keeps its egress for 60s while every other host in
your crawl rotates every 10s. Default is OFF — the raw contract is a new
IP per window.

## 3.4 Burp-specific issues found while building this (all handled)

| Issue | What we do |
|---|---|
| Burp's SOCKS config has **no auth fields** | gateway binds loopback no-auth; upstream credentials (Webshare) are injected by the gateway itself |
| Burp sends hostnames, not resolved IPs, when "DNS through proxy" is ON | SOCKS5 ATYP=domain parsed and passed to the upstream for **remote resolution** |
| Some tools advertise `0x02` then fail RFC 1929 | when no creds are configured we advertise **only** method 0x00 |
| Burp reuses connections aggressively | tunnels have idle (90s) + lifetime (30min) caps; both directions bounded — no FD/thread leak |
| Crawler concurrency spikes (scanner mode) | `max_tunnels` (default 256) protects the process; raise it for big scans |
| Burp attempts `http://` (not HTTPS) targets | plain HTTP through untrusted proxies is refused by default (MITM risk); pass `--allow-http` only if you accept that |
| Port 1080 collision (Psiphon/windscribe also use 1080) | gateway checks and degrades with a clear message; change with `--socks-listen` or `windscribe_proxy_socks_port` |

## 3.5 Running the crawl

```fish
# terminal 1 — the gateway
uv run ip-rotator serve --warp-accounts 4 --sticky

# terminal 2 — watch rotation live
tail -f /dev/null &  # or just read the gateway's stderr
# every ~10s:  ROTATE #N -> <fresh IP> [fresh] via <lane> | fresh=<count>

# Burp — crawl away; every new connection rides the current lane
```

## 3.6 If Burp can't connect at all

```fish
# is the SOCKS frontend up?
curl -s --socks5-hostname 127.0.0.1:1080 https://checkip.amazonaws.com
# works in curl but not Burp? -> re-check Settings → Network → Connections
# fails in curl too? -> read the gateway log; if "SOCKS5 frontend NOT
# started", port 1080 is taken: uv run ip-rotator serve --socks-listen 127.0.0.1:1081
```
