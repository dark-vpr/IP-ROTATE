# Chapter 10 — The Free-Node v2ray Lane (Thousands of Community Nodes)

The single largest pool of free, rotating, non-Tor egress IPs on the
internet in 2026 is the **community proxy-node ecosystem**: thousands of
vless/vmess/trojan/shadowsocks/hysteria2 servers published as "subscription"
links by aggregator channels (Telegram-sourced, mirrored to GitHub, refreshed
every 5-15 minutes). This lane is that ecosystem, industrialized.

**Verified live (Aug 2026):** the two default subscriptions carry
~7,250 node links each refresh (5,736 vless / 820 ss / 279 vmess / 229
trojan / 80 hysteria2); random-sample testing shows 10-30% of nodes alive
at any moment — enough for hundreds of concurrent warm egress IPs.

Why it matters for you: the protocols ride **TCP 443 with TLS/Reality**,
so they work even on networks where UDP (and therefore WireGuard/WARP) is
blocked — a strict upgrade in reachability over the WG lanes.

---

## 10.1 Architecture: one sing-box, N warm ports

```
subscription URLs  -->  parse links  -->  sing-box config:
                          240 inbounds (socks, 127.0.0.1:43001..43240)
                                        route rule: inbound i -> outbound i
                          240 outbounds (vless/vmess/trojan/ss nodes)
                       --> ONE sing-box process
                       --> probe every port -> keep healthy ones
                       --> feed pool as premium-tier upstreams
```

* **Switching IP = connecting to a different local port.** Zero dial delay,
  zero teardown — the same warm-tunnel contract as the WireGuard lane.
* **A/B port sets:** when nodes die and the lane regenerates its config,
  the new sing-box process binds the *alternate* port set and is probed
  *before* the old process retires — the lane never goes dark mid-request.
* **Bad-regen rollback:** if a fresh harvest produces 0 healthy nodes, the
  old process keeps serving (free nodes die in waves; the next regen wins).
* Every outbound is schema-validated (`sing-box check`) BEFORE the big
  config starts — one malformed node can never kill the lane.

## 10.2 Quick start (uv + fish)

```fish
cd ip-rotator

# prove the supply and see real egress IPs right now:
uv run ip-rotator v2ray --probe --nodes 60
```

Expected:

```
sing-box binary  : /home/you/.ip_rotator/v2ray/bin/sing-box   (auto-downloaded)
subscriptions    : 2 (All_Configs_Sub.txt, All_Configs_Sub.txt)
pulled 5000 node links
v2ray lane UP: 12/44 nodes alive (ports 43513-43556), 12 distinct egress IPs
ALIVE: 12/44 nodes, 12 distinct egress IPs
by protocol     : shadowsocks=4, trojan=1, vless=4, vmess=3
sample egress   : 149.34.251.245, 165.140.216.239, 193.29.139.212 ...
lane ready — engage with: ip-rotator serve --v2ray
```

Engage it in the gateway:

```fish
uv run ip-rotator serve --v2ray --v2ray-nodes 120 --no-reuse-minutes 45
```

Verification is the same curl loop as every other lane:

```fish
for i in (seq 6)
    curl -s --max-time 25 --socks5-hostname 127.0.0.1:1080 https://checkip.amazonaws.com
    sleep 10
end
```

## 10.3 What the parser handles (and refuses)

Parsed into sing-box outbounds: vless over tcp/ws/grpc/httpupgrade with
tls or **Reality** (uTLS fingerprint forced — sing-box rejects Reality
clients without uTLS), vmess (both the modern URI form and legacy
base64-JSON), trojan, shadowsocks (SIP002 with base64 userinfo), hysteria2
(only when `v2ray_udp_ok: true`, since it is QUIC/UDP-based).

Refused: `xhttp` and `kcp` transports (Xray-only; sing-box cannot dial
them), Reality links without a public key, malformed ports/userinfo.
Subscriptions may be plain link lists **or base64-wrapped** — both decoded.

## 10.4 The honest security & blockability talk

* **The exit node can see your traffic metadata.** These are volunteer /
  hobbyist / sometimes research VPS boxes. The lane therefore keeps the
  gateway's existing rule: **HTTPS/TLS only** (`allowed_connect_ports` 443
  family by default, plain HTTP refused). With TLS, the node sees SNI +
  sizes, not content. For anything sensitive, prefer the WARP/WG lanes
  (Cloudflare egress) or Webshare (contractual no-logging).
* **Egress IPs are datacenter IPs** (OVH/Hetzner/DO/AWS/Vultr...). Sophisticated
  WAFs (Cloudflare bot management, Akamai) challenge datacenter ranges
  more aggressively than residential IPs. Nobody's free pool changes that
  — anyone claiming "free residential, never blocked" is lying. Rotation
  + country spread + per-host stickiness (this gateway's specialties) are
  the practical mitigation.
* Some nodes are themselves WARP endpoints — you'll occasionally see
  104.28.x.x egress from this lane. Those are among the cleanest exits.
* The validation probe (HTTPS to checkip.amazonaws.com, certificate
  verified) **blacklists any node that MITMs you** — same protection as
  the free-proxy pool.
* Lane defaults are **opt-in** (`--v2ray`) precisely because of the trust
  trade-off above. On by default it is not.

## 10.5 Config

| flag / key | default | meaning |
|------------|---------|---------|
| `--v2ray` / `enable_v2ray` | off | engage the lane |
| `--v2ray-subs URL,URL` / `v2ray_subs` | 2 aggregators | subscription URLs |
| `--v2ray-nodes N` / `v2ray_max_nodes` | 240 | outbounds per process |
| `v2ray_min_warm` | 8 | force regen when healthy nodes < this |
| `v2ray_health_seconds` | 45 | re-probe healthy ports this often |
| `v2ray_sub_refresh_seconds` | 300 | pull fresh subscriptions |
| `v2ray_socks_base_port` | 43000 | port set A; +512 for set B |
| `v2ray_udp_ok` | false | include hysteria2 (QUIC) nodes |
| `v2ray_protocols` | vless,vmess,trojan,ss,hysteria2 | which protocols to parse |

Add more aggregators freely (any URL returning node links or base64):

```fish
# any of these work as --v2ray-subs values; they are just link lists
uv run ip-rotator serve --v2ray --v2ray-subs "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt,https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub1.txt"
```
