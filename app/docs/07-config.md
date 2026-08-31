# Chapter 7 — Configuration reference

Defaults shown; every field can be set via `config.json` (load with
`--config path.json`) or CLI override where noted. `uv run ip-rotator
serve --help` lists the flags.

```jsonc
{
  // ---- local front-ends ------------------------------------------------
  "listen_host": "127.0.0.1",
  "listen_port": 8000,              // HTTP CONNECT frontend (curl -x)
  "enable_socks": true,
  "socks_listen_host": "127.0.0.1",
  "socks_listen_port": 1080,        // SOCKS5 frontend (Burp). no-auth default
  "socks_username": "",             // set BOTH for RFC 1929 auth (curl OK,
  "socks_password": "",             //   Burp does no auth -> keep empty)
  "socks_handshake_timeout": 10.0,

  // ---- rotation ---------------------------------------------------------
  "interval": 10.0,                 // seconds per fresh-IP window
  "rotate_every_request": false,    // even harder: new upstream per connection
  "policy_on_exhaustion": "recycle",// recycle | strict | backbone
  "recycle_avoid_seconds": 600.0,   // recycling prefers IPs unused this long

  // ---- sticky sessions (v2.1) --------------------------------------------
  "sticky_sessions": false,         // --sticky; default OFF (new IP per window
                                    //   is the contract). ON = per-host lanes
  "sticky_ttl": 60.0,               // seconds a host keeps its lane

  // ---- request survival (v2.1) --------------------------------------------
  "starvation_wait": 5.0,           // hold a request this long when the whole
                                    //   chain fails (rescue window)
  "starvation_retry_delay": 0.5,    // retry cadence inside the window

  // ---- pool / validation ---------------------------------------------------
  "min_pool": 20,                   // below this: emergency harvest
  "starvation": 5,                  // below this: engage backbones
  "validation_timeout": 6.0,
  "validation_workers": 64,
  "validated_pool_cap": 600,
  "revalidate_after": 90.0,
  "max_latency_ms": 6000,
  "connect_timeout": 6.0,           // per-dial; 3 dials + window < 25s

  // ---- harvesting ------------------------------------------------------------
  "harvest_interval": 240.0,
  "source_cache_ttl": 240.0,
  "source_backoff_max": 1800.0,     // per-source exponential backoff cap

  // ---- failover / robustness ---------------------------------------------------
  "max_retries": 2,                 // extra dials per request (chain = N+1)
  "max_tunnels": 256,               // concurrent tunnel cap (FD guard)
  "idle_timeout": 90.0,
  "max_tunnel_lifetime": 1800.0,
  "fail_threshold": 3,              // strikes -> blacklist
  "blacklist_minutes": 15.0,

  // ---- security -----------------------------------------------------------------
  "allow_plain_http": false,        // plain HTTP through proxies = MITM risk
  "allow_private_targets": false,   // SSRF guard (loopback/RFC1918/metadata)
  "allowed_connect_ports": [443, 8443, 2053, 2083, 2087, 2096],

  // ---- provider lanes -------------------------------------------------------------
  "enable_warp": true,              // warp-cli backbone (auto, if installed)
  "warp_proxy_port": 40000,
  "warp_reregister_cooldown": 120.0,
  "enable_psiphon": false,          // OPT-IN dirty tier
  "psiphon_socks_port": 1080,
  "psiphon_http_port": 8080,
  "enable_vpngate": false,          // OPT-IN dirty tier (openvpn + sudo)
  "enable_windscribe_proxy": false, // OPT-IN local-SOCKS lane
  "windscribe_proxy_socks_port": 1080,
  "windscribe_proxy_locations": ["US","CA","UK","FR","DE","NL","NO","CH","RO","TR"],
  "allow_direct": false,            // LAST resort: real IP, loudly flagged

  // ---- WireGuard lane (v2.1) ---------------------------------------------------------
  "warp_accounts": 0,               // --warp-accounts N; 0 = off (rec 3-6)
  "wireproxy_bin": "/usr/local/bin/wireproxy",  // or any PATH name
  "wg_socks_base_port": 42000,      // warp0=42000, warp1=42001, ...
  "wg_socks_username": "",          // optional auth ON the wireproxy SOCKS
  "wg_socks_password": "",          //   listeners (localhost -> keep empty)
  "wg_configs_dir": "",             // --wg-dir; dir of wg-quick *.conf files
  "wg_handshake_timeout": 15.0,
  "wg_reprobe_seconds": 300.0,      // re-verify egress through each tunnel
  "wg_lane_refresh_seconds": 30.0,
  "wg_lane_disable_after": 6,       // consecutive handshake fails -> lane off
  "warp_register_cooldown": 30.0,   // min seconds between account regs
  "warp_accounts_max": 64,

  // ---- metered free tiers ----------------------------------------------------------------
  "webshare_api_key": "",           // 10 proxies, 1GB/mo, forever, no card
  "static_proxies": [               // v3.1: pasted proxies (webshare dashboard
    "ip:port:user:pass"             // 'ip:port:user:pass' lines work as-is; or
  ],                                // 'socks5://u:p@ip:port'; CRLF-safe; creds
                                    // survive validation; revalidated 10 min
  "api_keys": {                     // scraping-API fetch lane (no card)
    "zenrows": "", "scrapingbee": "", "crawlbase": "", "scraperapi": ""
  },
  "fetch_priority": ["zenrows", "firecrawl", "scrapingbee", "crawlbase", "scraperapi"],

  // ---- misc ---------------------------------------------------------------------------------
  "state_path": "~/.ip_rotator/state.db",
  "fresh_ledger": false,            // forget never-reuse ledger this run
  "log_level": "INFO",              // DEBUG|INFO|WARNING|ERROR
  "country_filter": null,           // ["US","DE"] (slower: geo lookups)
  "stats_file": null,               // write JSON stats here every rotation
  "harvest_sources": [ /* 14 verified list URLs; see config.example.json */ ]
}
```

## Validation rules (fail fast at startup)

`interval >= 1` · `policy_on_exhaustion ∈ {recycle, strict, backbone}` ·
ports 0–65535 (0 = ephemeral) · socks auth: set both or neither ·
`sticky_ttl >= 0` · `warp_accounts ∈ 0..64` · `wg_socks_base_port ∈
1024..65000` · windscribe-proxy port must not collide with the Psiphon
port when both are enabled.

## Recipes

```fish
# maximum clean rotation: 5 WARP accounts + your 3 WG configs, 10s windows
uv run ip-rotator serve --warp-accounts 5 --wg-dir ~/.ip_rotator/wg-configs

# crawl a login-protected site (keep sessions stable per host)
uv run ip-rotator serve --warp-accounts 4 --sticky

# hyper-aggressive: a different upstream for EVERY connection
uv run ip-rotator serve --rotate-every-request --warp-accounts 6

# strict hygiene: never recycle, never direct, refuse rather than reuse
uv run ip-rotator serve --policy strict --warp-accounts 4

# country-locked egress (slower: geo-validated)
uv run ip-rotator serve --country US,DE
```

## v3.0 fields

### Rotation / no-reuse window

| key | default | meaning |
|-----|---------|---------|
| `no_reuse_seconds` | 2700 (45 min) | an egress IP is burned this long after use before it can be picked again; CLI: `--no-reuse-minutes` |
| `recycle_avoid_seconds` | 600 | legacy lower bound; effective window = `max(no_reuse_seconds, this)` |

### warp-plus lane (multi-country WARP)

| key | default | meaning |
|-----|---------|---------|
| `enable_warpplus` | false | engage the lane; CLI: `--warpplus N` (also sets instances) |
| `warpplus_instances` | 4 | warm SOCKS ports, each its own WARP identity |
| `warpplus_mode` | `auto` | `auto` (cfon+gool mix) / `cfon` / `gool` / `plain` |
| `warpplus_countries` | 31 ISO codes | the automatic rotation order |
| `warpplus_socks_base_port` | 44000 | instance i binds base+i |
| `warpplus_bin` | "" | explicit binary path; "" = PATH / tools dir / auto-download |
| `warpplus_download` | latest release zip | auto-download URL |
| `warpplus_scan` | true | `--scan` endpoint probing |
| `warpplus_probe_timeout` | 15 | egress probe timeout per instance |
| `warpplus_handshake_grace` | 25 | seconds to wait for SOCKS bind (= handshake) |
| `warpplus_max_instances` | 16 | validation ceiling |

### Free-node v2ray lane (community nodes via sing-box)

| key | default | meaning |
|-----|---------|---------|
| `enable_v2ray` | false | engage the lane; CLI: `--v2ray` |
| `v2ray_subs` | 2 aggregator URLs | subscription sources (plain or base64 bodies) |
| `v2ray_max_nodes` | 240 | outbounds per sing-box process; CLI: `--v2ray-nodes` |
| `v2ray_min_warm` | 8 | force a regen when healthy nodes drop below this |
| `v2ray_health_seconds` | 45 | re-probe healthy ports this often |
| `v2ray_sub_refresh_seconds` | 300 | pull fresh subscriptions this often |
| `v2ray_probe_workers` | 24 | parallel egress probes |
| `v2ray_probe_timeout` | 8 | per-probe timeout |
| `v2ray_socks_base_port` | 43000 | port set A; set B = base+512 (A/B alternate at regen) |
| `v2ray_udp_ok` | false | include hysteria2 (QUIC/UDP) nodes |
| `v2ray_protocols` | vless,vmess,trojan,ss,hysteria2 | which protocols to parse |
| `singbox_bin` | "" | explicit sing-box path; "" = PATH / tools dir / auto-download |
| `singbox_download` | v1.13.19 tarball | auto-download URL |
| `v2ray_sub_backoff_max` | 900 | max backoff for a failing subscription |

Derived paths: `warpplus_state_dir` = `<state dir>/warpplus` (bin in
`bin/`, identities in `instN/`), `v2ray_state_dir` = `<state dir>/v2ray`
(bin in `bin/`, generated configs).
