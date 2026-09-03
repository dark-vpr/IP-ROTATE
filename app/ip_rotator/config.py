"""Configuration: dataclass + JSON file loader + CLI overrides."""
import dataclasses
import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Built-in harvest sources. Raw text lists, one "host:port" (or
# "proto://host:port" for proxifly) per line. All free, no API keys.
# Each source is independently cached and backed-off, so a dead source
# never hurts the others. (All 14 verified reachable Aug-2026.)
# ---------------------------------------------------------------------------
DEFAULT_SOURCES = [
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks5.txt",
    "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all",
    "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=http",
    "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt",
]

# Endpoints used to discover the TRUE egress IP of an upstream (all HTTPS,
# certificate-verified — a proxy that MITMs these gets blacklisted).
IP_CHECK_PRIMARY = "checkip.amazonaws.com"
IP_CHECK_SECONDARY = "www.cloudflare.com"  # cdn-cgi/trace path, used for cross-checks


@dataclass
class Config:
    # --- local proxy front-ends --------------------------------------------
    listen_host: str = "127.0.0.1"
    listen_port: int = 8000            # HTTP CONNECT frontend (curl -x ...)

    # SOCKS5 frontend (Burp Suite / curl --socks5-hostname). Set
    # socks_listen_host to "" (or enable_socks False) to disable it.
    enable_socks: bool = True
    socks_listen_host: str = "127.0.0.1"
    socks_listen_port: int = 1080
    socks_username: str = ""           # "" = no-auth (Burp-compatible);
    socks_password: str = ""           # set both for RFC 1929 auth (curl OK)
    socks_handshake_timeout: float = 10.0

    # --- rotation ----------------------------------------------------------
    interval: float = 10.0            # seconds per IP window (the "new IP every 10s")
    rotate_every_request: bool = False  # even harder: new upstream per connection
    policy_on_exhaustion: str = "recycle"  # recycle | strict | backbone

    # --- no-reuse window (v3) ------------------------------------------------
    # "shouldn't use the same IP again for 30-60 minutes": an egress IP is
    # ONLY eligible again after this many seconds since its last use. Inside
    # the window it is treated as burned, whatever the pool situation. The
    # old recycle_avoid_seconds is kept as a lower bound for backward compat.
    # Default 45 min sits in the middle of the user's 30-60 min ask.
    no_reuse_seconds: float = 2700.0
    recycle_avoid_seconds: float = 600.0   # legacy lower bound (kept for old
                                           # config files; effective window =
                                           # max(no_reuse_seconds, this))

    def effective_no_reuse(self) -> float:
        return max(self.no_reuse_seconds, self.recycle_avoid_seconds)

    # --- sticky sessions (crawl-friendliness) --------------------------------
    # OFF by default: the core contract is "a NEW egress IP every `interval`
    # seconds". Enable when crawling sites whose WAF/session logic breaks
    # when the IP changes mid-session (auth flows, shopping carts): while
    # ON, requests to the SAME host keep their lane for sticky_ttl seconds
    # even as the global clock rotates everything else.
    sticky_sessions: bool = False
    sticky_ttl: float = 60.0

    # --- request survival ("no request left behind") --------------------------
    # When EVERY upstream fails a dial, wait up to this many seconds retrying
    # the lane chain (emergency harvest / WG re-registration may rescue it)
    # instead of instantly returning 502 to the crawler.
    starvation_wait: float = 5.0
    starvation_retry_delay: float = 0.5

    # --- pool / validation ---------------------------------------------------
    min_pool: int = 20                # warn + emergency harvest below this
    starvation: int = 5               # engage backbones below this
    validation_timeout: float = 6.0
    validation_workers: int = 64
    validated_pool_cap: int = 600
    revalidate_after: float = 90.0    # re-check validated proxies older than this
    max_latency_ms: int = 6000
    connect_timeout: float = 6.0

    # --- harvesting ----------------------------------------------------------
    harvest_interval: float = 240.0
    source_cache_ttl: float = 240.0
    source_backoff_max: float = 1800.0

    # --- failover / server robustness ---------------------------------------
    max_retries: int = 2              # extra upstream attempts per request
    max_tunnels: int = 256
    idle_timeout: float = 90.0
    max_tunnel_lifetime: float = 1800.0
    fail_threshold: int = 3           # fails before blacklist (v2: actually
                                      # honored by StateDB.record_fail)
    blacklist_minutes: float = 15.0   # blacklist duration after N strikes

    # --- security -------------------------------------------------------------
    allow_plain_http: bool = False    # plain HTTP through untrusted proxies = MITM playground
    allow_private_targets: bool = False  # SSRF guard for loopback/private/metadata IPs
    allowed_connect_ports: List[int] = field(
        default_factory=lambda: [443, 8443, 2053, 2083, 2087, 2096]
    )

    # --- providers ------------------------------------------------------------
    # NOTE v2: Tor is REMOVED (most mass-blacklisted egress class on the
    # internet). VPN Gate and Psiphon are reliable but their shared/volunteer
    # egress pools are frequently flagged — both OPT-IN (off by default).
    enable_warp: bool = True          # auto-engaged ONLY if warp-cli is present & starved
    warp_proxy_port: int = 40000
    warp_reregister_cooldown: float = 120.0
    enable_psiphon: bool = False      # OPT-IN backbone (shared egress IPs are
                                      # frequently flagged — enable consciously)
    psiphon_socks_port: int = 1080
    psiphon_http_port: int = 8080
    enable_vpngate: bool = False      # OPT-IN dirty-tier lane: volunteer egress,
                                      # needs openvpn + sudo; see docs/05-providers.md
    enable_windscribe_proxy: bool = False  # OPT-IN: windscribe-cli proxy mode
                                           # (local SOCKS, no full tunnel) — needs
                                           # `windscribe login` done; see docs/06
    windscribe_proxy_socks_port: int = 1080
    windscribe_proxy_locations: List[str] = field(default_factory=lambda: [
        "US", "CA", "UK", "FR", "DE", "NL", "NO", "CH", "RO", "TR"])
    allow_direct: bool = False        # LAST resort: your real IP, loudly flagged

    # --- WireGuard lane (wireproxy: WARP accounts + your own WG configs) -------
    # The crown jewel for clean 10s rotation: N warm userspace WireGuard
    # tunnels, each = one local SOCKS5 port = one distinct egress IP.
    # Switching IP = picking a different ALREADY-CONNECTED port: zero dial
    # delay, zero teardown, zero dropped requests. WARP accounts are free,
    # no card, no email (one HTTPS POST each). Drop *.conf files from
    # Proton/Windscribe/PrivadoVPN into wg_configs_dir for more tunnels.
    warp_accounts: int = 0            # how many WARP accounts to keep warm
                                      # (0 = lane off; recommend 3-6)
    wireproxy_bin: str = "/usr/local/bin/wireproxy"  # or anywhere in PATH
    wireproxy_download: str = "https://github.com/pufferffish/wireproxy/" \
                              "releases/latest/download/" \
                              "wireproxy_linux_amd64.tar.gz"
    wg_socks_base_port: int = 42000   # warp0=42000, warp1=42001, ...
    wg_socks_username: str = ""       # optional auth wireproxy requires on its
    wg_socks_password: str = ""       # local SOCKS (leave empty = no-auth)
    wg_configs_dir: str = ""          # dir of wg-quick *.conf files (Proton /
                                      # Windscribe / PrivadoVPN free configs)
    wg_handshake_timeout: float = 15.0
    wg_reprobe_seconds: float = 300.0  # re-verify egress through each tunnel
    wg_lane_refresh_seconds: float = 30.0
    wg_lane_disable_after: int = 6     # consecutive handshake fails -> lane off
    warp_register_cooldown: float = 30.0
    warp_accounts_max: int = 64

    # --- warp-plus lane (v3): multi-country WARP egress, automatic rotation ---
    # bepass-org/warp-plus: one binary, each instance = SOCKS5 port bound to a
    # WARP identity in a chosen country (--cfon --country XX) or warp-in-warp
    # (--gool). When an instance's egress IP is burned (inside the no-reuse
    # window), the lane respawns it with the NEXT country in the rotation:
    # an elastic, effectively inexhaustible IP factory. Needs UDP egress
    # (WireGuard handshakes); self-disables with a diagnosis where UDP is
    # blocked. Zero accounts, zero cards, zero logins.
    enable_warpplus: bool = False
    warpplus_bin: str = ""             # "" = auto: PATH, then tools dir, then
                                       # download from warpplus_download
    warpplus_download: str = "https://github.com/bepass-org/warp-plus/" \
                            "releases/latest/download/warp-plus_linux-amd64.zip"
    warpplus_instances: int = 4        # warm SOCKS ports (each own identity)
    warpplus_socks_base_port: int = 44000
    warpplus_mode: str = "auto"        # auto | cfon | gool | plain
                                       # auto = mix (cfon per-country + gool)
    warpplus_countries: List[str] = field(default_factory=lambda: [
        "US", "GB", "DE", "FR", "NL", "CA", "CH", "SE", "NO", "JP",
        "SG", "AU", "AT", "BE", "BG", "CZ", "DK", "EE", "ES", "FI",
        "HR", "HU", "IE", "IN", "IT", "LV", "PL", "PT", "RO", "RS", "SK"])
    warpplus_scan: bool = True         # --scan: probe for reachable endpoints
    warpplus_probe_timeout: float = 15.0
    warpplus_handshake_grace: float = 25.0
    warpplus_max_instances: int = 16

    # --- free-node v2ray lane (v3): thousands of community nodes -------------
    # Aggregated public subscriptions (Telegram-channel-sourced, refreshed
    # every few minutes by the maintainers). One sing-box process maps N
    # local SOCKS ports -> N validated nodes; rotation = picking another
    # already-warm port (zero dial delay). TCP-based protocols work even
    # where UDP is blocked. Dirty-ish shared VPS exits: PREMIUM tier for
    # supply volume, opt-in for trust-sensitive traffic (see docs/10).
    enable_v2ray: bool = False
    v2ray_subs: List[str] = field(default_factory=lambda: [
        "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
        "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt",
    ])
    v2ray_sub_backoff_max: float = 900.0
    singbox_bin: str = ""              # "" = auto: PATH, then tools dir, then
                                       # download from singbox_download
    singbox_download: str = "https://github.com/SagerNet/sing-box/" \
                           "releases/download/v1.14.0/" \
                           "sing-box-1.14.0-linux-amd64-glibc.tar.gz"
    v2ray_socks_base_port: int = 43000
    v2ray_max_nodes: int = 240         # max outbounds per sing-box process
    v2ray_min_warm: int = 8            # regen config when healthy < this
    v2ray_health_seconds: float = 45.0 # re-probe healthy ports this often
    v2ray_sub_refresh_seconds: float = 300.0  # pull fresh subs this often
    v2ray_probe_workers: int = 24
    v2ray_probe_timeout: float = 8.0
    v2ray_protocols: List[str] = field(default_factory=lambda: [
        "vless", "vmess", "trojan", "ss", "hysteria2"])  # parsed protocols
    v2ray_udp_ok: bool = False         # set true on networks with UDP egress
                                       # (enables hysteria2/quic nodes)

    # --- sing-box WARP lane (v4): Cloudflare WARP via sing-box v1.14+ --------
    # This is the ACTUAL engine behind Oblivion Desktop (not warp-plus).
    # Unlike warp-plus v1.2.6 which has a hardcoded bug (HTTP probe to
    # 1.1.1.1:80 with 500ms timeout causing 10s delays), sing-box has NO
    # hardcoded probes and starts cleanly. TCP-based WireGuard handshake
    # works where raw UDP is blocked. Each instance = one WARP identity =
    # one SOCKS5 port. Fresh identity mint = new Cloudflare egress IP.
    enable_singwarp: bool = True
    singwarp_instances: int = 8        # warm SOCKS ports (each own WARP identity)
    singwarp_socks_base_port: int = 45000
    singwarp_socks_username: str = ""  # optional auth on local SOCKS
    singwarp_socks_password: str = ""
    singwarp_handshake_grace: float = 15.0  # grace for WireGuard handshake
    singwarp_probe_timeout: float = 15.0
    singwarp_gool_mode: bool = False   # enable double-hop (WARP-in-WARP) like Oblivion's 'gool' method
    singwarp_upstream_base_port: int = 46000  # base port for first-hop upstream SOCKS in gool mode
    singbox_bin: str = ""              # shared with v2ray lane (same binary)
    
    # --- WAF validation engine (v5): Multi-vendor consensus -------------------
    # Gold standard validation: tests proxies against 7+ WAF-protected targets
    # from different vendors (Cloudflare, AWS, Akamai) simultaneously. Filters
    # blacklisted IPs using Firehol Level 1 + AbuseIPDB. Detects soft blocks
    # (CAPTCHA/challenge pages). Requires 60% consensus rate across vendors.
    enable_waf_validation: bool = True
    waf_required_consensus: float = 0.6  # minimum success rate (0.0-1.0)
    waf_blacklist_refresh_minutes: int = 60
    waf_min_vendor_coverage: int = 2     # must pass at least N different vendors
    waf_validation_config: str = "config.validation.json"  # custom targets file
    waf_custom_targets_only: bool = False  # if true, ignore built-in targets

    # --- metered free tiers (Webshare / scraping APIs) ------------------------
    # Webshare free: 10 datacenter proxies, 1GB/month, forever, NO CARD.
    # Get the API key at dashboard.webshare.io -> API Key. Bytes are counted
    # through the relay and the lane auto-disables at the 1GB cap.
    webshare_api_key: str = ""
    # Static authenticated proxies pasted directly into config — the
    # Webshare dashboard export lines ('ip:port:user:pass') work as-is, or
    # 'socks5://user:pass@host:port' / 'http://user:pass@host:port' URLs.
    # No API key needed; credentials survive validation (RFC 1929 /
    # Proxy-Authorization); revalidated every 10 min. NOT byte-metered (the
    # provider counts its own cap — 1GB/mo on webshare free).
    static_proxies: List[str] = field(default_factory=list)
    # Scraping-API fetch lane keys (see `ip-rotator fetch` + `api-status`):
    #   zenrows 5000 credits/MONTH (recurring!), firecrawl keyless (no key),
    #   scrapingbee 1000 one-time, crawlbase 1000 one-time, scraperapi 5k trial
    # All free tiers below are NO-CREDIT-CARD.
    api_keys: Dict[str, str] = field(default_factory=dict)
    fetch_priority: List[str] = field(default_factory=lambda: [
        "zenrows", "firecrawl", "scrapingbee", "crawlbase", "scraperapi"])

    # --- misc -----------------------------------------------------------------
    state_path: str = os.path.expanduser("~/.ip_rotator/state.db")
    fresh_ledger: bool = False        # start a new never-reuse ledger this run
    log_level: str = "INFO"
    country_filter: Optional[List[str]] = None  # ISO codes e.g. ["US","DE"]; needs geo lookups
    stats_file: Optional[str] = None  # write JSON stats each rotation

    harvest_sources: List[str] = field(default_factory=lambda: list(DEFAULT_SOURCES))

    # -------------------------------------------------------------------------
    # derived paths for the WireGuard / warp-plus / v2ray lanes
    def warp_accounts_path(self) -> str:
        base = os.path.dirname(os.path.abspath(self.state_path))
        return os.path.join(base, "warp_accounts.json")

    def wireproxy_state_dir(self) -> str:
        base = os.path.dirname(os.path.abspath(self.state_path))
        return os.path.join(base, "wireproxy")

    def warpplus_state_dir(self) -> str:
        base = os.path.dirname(os.path.abspath(self.state_path))
        return os.path.join(base, "warpplus")

    def v2ray_state_dir(self) -> str:
        base = os.path.dirname(os.path.abspath(self.state_path))
        return os.path.join(base, "v2ray")

    def singwarp_state_dir(self) -> str:
        base = os.path.dirname(os.path.abspath(self.state_path))
        return os.path.join(base, "singwarp")

    def validate(self) -> None:
        if self.interval < 1:
            raise ValueError("interval must be >= 1s")
        if self.policy_on_exhaustion not in ("recycle", "strict", "backbone"):
            raise ValueError("policy_on_exhaustion must be recycle|strict|backbone")
        if self.validation_workers < 4:
            self.validation_workers = 4
        # 0 is allowed: it means "kernel-assigned ephemeral port" (used by
        # the internal self-test; fine for users too, just not very useful
        # for a frontend you need to point clients at).
        for name in ("listen_port", "socks_listen_port"):
            if not (0 <= getattr(self, name) <= 65535):
                raise ValueError(f"{name} must be 0-65535 (0=ephemeral)")
        if self.enable_socks and self.socks_username and not self.socks_password:
            raise ValueError("socks_username set but socks_password empty "
                             "(set both or neither)")
        if self.socks_handshake_timeout < 2:
            raise ValueError("socks_handshake_timeout must be >= 2s")
        if self.sticky_ttl < 0:
            raise ValueError("sticky_ttl must be >= 0")
        if self.warp_accounts < 0 or self.warp_accounts > self.warp_accounts_max:
            raise ValueError(f"warp_accounts must be 0-{self.warp_accounts_max}")
        if not (1024 <= self.wg_socks_base_port <= 65000):
            raise ValueError("wg_socks_base_port must be 1024-65000")
        if self.no_reuse_seconds < 0:
            raise ValueError("no_reuse_seconds must be >= 0")
        if not (1 <= self.warpplus_instances <= self.warpplus_max_instances):
            raise ValueError(
                f"warpplus_instances must be 1-{self.warpplus_max_instances}")
        if self.warpplus_mode not in ("auto", "cfon", "gool", "plain"):
            raise ValueError("warpplus_mode must be auto|cfon|gool|plain")
        if not (1024 <= self.warpplus_socks_base_port <= 65000 -
                self.warpplus_max_instances):
            raise ValueError("warpplus_socks_base_port too low/too high")
        if self.enable_warpplus and self.enable_psiphon and \
                self.warpplus_socks_base_port == self.psiphon_socks_port:
            raise ValueError("warpplus port base collides with psiphon port")
        if not (1024 <= self.v2ray_socks_base_port <= 65000 -
                self.v2ray_max_nodes - 2):
            raise ValueError("v2ray_socks_base_port leaves too little room "
                             "for the port range it needs")
        if self.v2ray_max_nodes < 8 or self.v2ray_max_nodes > 480:
            raise ValueError("v2ray_max_nodes must be 8-480")
        if self.v2ray_min_warm < 1:
            self.v2ray_min_warm = 1
        if not self.v2ray_subs:
            raise ValueError("v2ray_subs must not be empty when v2ray lane is used")
        if self.enable_windscribe_proxy and self.enable_psiphon and \
                self.windscribe_proxy_socks_port == self.psiphon_socks_port:
            raise ValueError("windscribe proxy port collides with psiphon port "
                             "(change windscribe_proxy_socks_port)")

    def to_json(self) -> str:
        return json.dumps(dataclasses.asdict(self), indent=2)

    @staticmethod
    def load(path: Optional[str] = None, overrides: Optional[dict] = None) -> "Config":
        data = {}
        if path:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        if overrides:
            data.update({k: v for k, v in overrides.items() if v is not None})
        fields = {f.name for f in dataclasses.fields(Config)}
        cfg = Config(**{k: v for k, v in data.items() if k in fields})
        cfg.validate()
        return cfg
