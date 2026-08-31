# Chapter 2 — Verify it actually works (curl only)

The gateway must be running first:

```fish
uv run ip-rotator serve
```

## 2.1 Is it up? (2 seconds)

```fish
# any response (even an error JSON) proves the listener is alive
curl -s -o /dev/null -w "%{http_code}\n" -x http://127.0.0.1:8000 https://checkip.amazonaws.com
# -> 200
```

## 2.2 Does traffic egress through a foreign IP?

```fish
# your real IP
curl -s https://checkip.amazonaws.com

# your IP through the gateway (HTTP frontend)
curl -s -x http://127.0.0.1:8000 https://checkip.amazonaws.com

# your IP through the gateway (SOCKS5 frontend — the Burp path)
curl -s --socks5-hostname 127.0.0.1:1080 https://checkip.amazonaws.com
```

The last two must print a **different** IP than the first. Both front-ends
should print the *same* IP when run within the same 10s window (they share
one rotation engine).

## 2.3 Does the IP actually rotate every 10 seconds?

```fish
for i in 1 2 3 4
    echo -n "window $i: "
    curl -s --max-time 25 -x http://127.0.0.1:8000 https://checkip.amazonaws.com
    sleep 10
end
```

Expected: **four different IPs** (one per 10-second window). The never-reuse
ledger guarantees they were never used before — even across restarts.

Same test through the SOCKS5 frontend:

```fish
for i in 1 2 3 4
    echo -n "socks window $i: "
    curl -s --max-time 25 --socks5-hostname 127.0.0.1:1080 https://checkip.amazonaws.com
    sleep 10
end
```

## 2.4 Which upstream served me, and when is the next rotation?

Every HTTP CONNECT response carries observability headers:

```fish
curl -s -v -x http://127.0.0.1:8000 https://checkip.amazonaws.com -o /dev/null 2>&1 | grep -i x-rotator
# X-Rotator-Egress: 199.7.149.96
# X-Rotator-Upstream: http://199.7.149.96:3128
# X-Rotator-Provider: free-proxy
# X-Rotator-Next-Rotation-In: 6.4
```

(Through SOCKS5 the same info appears in the server log instead — SOCKS has
no header mechanism.)

## 2.5 Rotate RIGHT NOW (don't wait for the clock)

```fish
kill -USR1 (pgrep -f "bin/ip-rotator serve" | head -1)
# the log prints: ROTATE #N -> <new-never-used-IP> [fresh] via ...
```

## 2.6 Built-in self-test (both front-ends end-to-end)

```fish
uv run ip-rotator test
# warms the pool, serves both front-ends on ephemeral ports, fires 4+4
# requests, one per window, and asserts DISTINCT IPs. PASS = done.
```

## 2.7 Failure modes you might see (all expected occasionally)

| curl symptom | meaning | what happens inside |
|---|---|---|
| `curl: (56) Recv failure` after ~20s | every upstream in the chain died, survival window expired too | gateway logs `exhausted N upstreams`; emergency harvest is already running; next request usually fine |
| IP repeats across windows | recycle policy kicked in (pool exhausted) | log line says `[recycle]`; register WARP accounts (`--warp-accounts`) to add a clean lane |
| `502` JSON error | no upstream at all + survival window expired | check `ip-rotator doctor` and the log |
| First request after start fails | pool still warming (~10-30s) | warm-start from the state DB makes restarts fast; just retry |

## 2.8 Reading the log

The gateway logs to stderr. The lines that matter:

```
ROTATE #7 -> 122.246.3.12 [fresh] via http://122.246.3.12:17981 (526ms) | validated=229 fresh=207
  ^ rotation #7 picked a never-before-used IP (ledger says "fresh")
EMERGENCY harvest triggered: fresh pool below min
  ^ pool running low -> re-harvesting all sources NOW
dial host:443: all 3 upstreams failed (...) — survival window: holding request up to 5s for a rescue...
dial host:443: RESCUED after 6 upstream attempts
  ^ a request that would have been a 502 got held and served
WIREGUARD LANE DISABLED: 6 consecutive handshake failures — this network likely blocks UDP
  ^ clean-IP lane unavailable HERE; free-proxy/webshare/vpn lanes carry on
```
