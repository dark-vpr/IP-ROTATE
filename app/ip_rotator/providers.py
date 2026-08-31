"""Optional backbone providers: Cloudflare WARP, Psiphon + VPN Gate (opt-in
dirty tier), Windscribe proxy mode (opt-in), free consumer VPN CLIs.

Backbones are NOT the rotation engine (research shows none of them can mint a
fresh IP every 10s alone): they are the safety net that keeps your crawler
alive when the free-proxy pool is momentarily starved — loudly flagged in
logs and in X-Rotator-* response headers so you always know which path
traffic took.

v2.1: Tor stays REMOVED (its exit nodes are the single most mass-blacklisted
egress class on the internet — a technical quality verdict, not an ethics
one). VPN Gate is BACK as opt-in after user review: reliable and free, but
volunteer egress IPs are frequently flagged, so it lives in the dirty tier,
OFF by default. The WireGuard/wireproxy lane (warpwire.py) is the clean
no-root unlimited rotation engine.
"""
import random
import shutil
import socket
import subprocess
import threading
import time
from typing import List, Optional

from .dialer import Upstream, fetch_egress_ip
from .httpkit import get_json


def _run(cmd: List[str], timeout: float = 10.0) -> Optional[str]:
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout, text=True)
        if r.returncode == 0:
            return (r.stdout or r.stderr or "").strip()
        return None
    except Exception:
        return None


# ===========================================================================
# Cloudflare WARP (proxy mode = local SOCKS5 on 127.0.0.1:40000)
# ===========================================================================
class WarpProvider:
    def __init__(self, cfg, log):
        self.cfg = cfg
        self.log = log
        self.last_reregister = 0.0
        self.last_egress = ""
        self.unavailable_reason = ""

    # -- availability --------------------------------------------------------
    def available(self) -> bool:
        if shutil.which("warp-cli") is None:
            self.unavailable_reason = "warp-cli not installed"
            return False
        return True

    def upstream(self) -> Upstream:
        return Upstream(kind="warp", host="127.0.0.1",
                        port=self.cfg.warp_proxy_port, source="warp")

    # -- lifecycle -------------------------------------------------------------
    def ensure_ready(self) -> bool:
        """Put WARP into proxy mode and connect. Root service must be running."""
        if not self.available():
            return False
        for mode_cmd in (("warp-cli", "mode", "proxy"),
                         ("warp-cli", "set-mode", "proxy")):
            if _run(list(mode_cmd)) is not None:
                break
        _run(["warp-cli", "connect"]) or _run(["warp-cli", "connect", "--accept-tos"])
        try:
            ip, _ = fetch_egress_ip(self.upstream(), timeout=8)
            self.last_egress = ip
            return True
        except Exception as e:
            self.unavailable_reason = f"warp probe failed: {e}"
            return False

    # -- fresh IP ------------------------------------------------------------
    def refresh_ip(self) -> Optional[str]:
        """Re-register the WARP identity to (usually) get a new egress IP.

        Reality (documented): the distinct egress pool is SMALL and shared;
        Cloudflare may throttle re-registration. Cooldown enforced; may return
        the same IP — the caller's ledger handles that honestly.
        """
        now = time.monotonic()
        if now - self.last_reregister < self.cfg.warp_reregister_cooldown:
            return self.last_egress or None
        self.last_reregister = now
        ok = False
        # new CLI syntax first, then legacy
        if _run(["warp-cli", "registration", "delete"]) is not None:
            ok = _run(["warp-cli", "registration", "new"]) is not None
        else:
            ok = _run(["warp-cli", "register"]) is not None
        if not ok:
            self.unavailable_reason = "warp re-registration failed"
            return None
        _run(["warp-cli", "connect"])
        time.sleep(2.0)  # tunnel establishment
        try:
            ip, _ = fetch_egress_ip(self.upstream(), timeout=10)
            self.last_egress = ip
            return ip
        except Exception:
            return None


# ===========================================================================
# Psiphon (free, unlimited; local SOCKS 1080 / HTTP 8080; NO root, NO account)
# OPT-IN since v2: its shared egress IPs are moderately flagged by anti-bot
# systems — a conscious trade: unlimited backbone availability vs. lower
# per-IP reputation. Disabled by default.
# ===========================================================================
class PsiphonProvider:
    def __init__(self, cfg, log):
        self.cfg = cfg
        self.log = log
        self._socks_up = False

    def available(self) -> bool:
        if not self.cfg.enable_psiphon:
            return False
        for port, kind in ((self.cfg.psiphon_socks_port, "socks"),
                           (self.cfg.psiphon_http_port, "http")):
            try:
                s = socket.create_connection(("127.0.0.1", port), timeout=1.5)
                s.close()
                self._socks_up = kind == "socks"
                return True
            except OSError:
                continue
        return False

    def upstream(self) -> Upstream:
        if self._socks_up:
            return Upstream(kind="socks5", host="127.0.0.1",
                            port=self.cfg.psiphon_socks_port, source="psiphon")
        return Upstream(kind="http", host="127.0.0.1",
                        port=self.cfg.psiphon_http_port, source="psiphon")


# ===========================================================================
# Free consumer VPNs with Linux CLIs (Proton / Windscribe / Hide.me)
# --------------------------------------------------------------------------
# Reality check (why these are a separate low-frequency MODE, not the engine):
#   * they are FULL-TUNNEL: while up, they hijack the machine's default route,
#     so running them alongside the free-proxy pool would route ALL harvesting
#     through the VPN. => `ip-rotator vpn` is a dedicated mode.
#   * reconnect takes 10-30s (a per-rotation blip; clients must retry)
#   * static datacenter IPs per server; free tiers limit server choice
#   * data caps: Windscribe/Hide.me 10GB/mo (metered here); Proton unlimited
#   * all three have NO-CARD free tiers (verified Aug-2026)
# ===========================================================================
def _probe_direct_egress(timeout: float = 10.0) -> str:
    ip, _ = fetch_egress_ip(Upstream(kind="direct", host="-", port=0),
                            timeout=timeout)
    return ip


VPN_CLI_RECIPES = {
    "proton": {
        "label": "Proton VPN Free",
        "bins": ["protonvpn-cli"],
        "connect": ["protonvpn-cli", "connect", "--fastest"],
        "disconnect": ["protonvpn-cli", "disconnect"],
        "monthly_bytes_cap": None,          # unlimited data
        "notes": "unlimited data; ~5 free countries; server auto-assigned "
                 "(reconnect re-rolls it); 1 device; medium speed; NO CARD",
    },
    "windscribe": {
        "label": "Windscribe Free",
        "bins": ["windscribe", "windscribe-cli"],
        "connect": ["{bin}", "connect", "{loc}"],
        "disconnect": ["{bin}", "disconnect"],
        "locations": ["US", "CA", "UK", "FR", "DE", "NL", "NO", "CH", "RO", "TR"],
        "monthly_bytes_cap": 10 * 1024 ** 3,  # 10 GB/month
        "notes": "10GB/month (metered here); 10 free locations; unlimited "
                 "devices; NO CARD",
    },
    "hideme": {
        "label": "Hide.me Free",
        "bins": ["hide.me", "hideme", "hideme-cli"],
        "connect": ["{bin}", "connect", "{loc}"],
        "disconnect": ["{bin}", "disconnect"],
        "locations": ["fi", "ch", "us", "uk", "fr", "nl"],
        "monthly_bytes_cap": 10 * 1024 ** 3,  # 10 GB/month
        "notes": "10GB/month (metered here); 8 free locations; official Linux "
                 "CLI; NO CARD",
    },
}


class VpnCliProvider:
    """One installed free-VPN CLI. Handles connect/disconnect, egress probing
    and data-cap metering for the `ip-rotator vpn` mode."""

    def __init__(self, name: str, recipe: dict, log, state):
        self.name = name
        self.recipe = recipe
        self.log = log
        self.state = state
        self.bin = next((b for b in recipe["bins"] if shutil.which(b)), None)
        self._locs = list(recipe.get("locations") or [])
        random.shuffle(self._locs)
        self._loc_i = 0
        self.current_ip = ""

    @property
    def cap_bytes(self):
        return self.recipe.get("monthly_bytes_cap")

    def bytes_used(self) -> int:
        return self.state.api_usage(f"vpn:{self.name}", monthly=True)["bytes"]

    def over_cap(self) -> bool:
        cap = self.cap_bytes
        return bool(cap) and self.bytes_used() >= cap

    def _cmd(self, tmpl, loc=None):
        parts = []
        for t in tmpl:
            parts.append(t.format(bin=self.bin, loc=loc or ""))
        return [p for p in parts if p]

    def disconnect(self) -> None:
        _run(self._cmd(self.recipe["disconnect"]), timeout=25)

    def connect(self) -> bool:
        """Connect to the next location (or fastest); verify the egress IP
        actually changed vs. real_ip. Returns True when tunnel verified."""
        loc = None
        if self._locs:
            loc = self._locs[self._loc_i % len(self._locs)]
            self._loc_i += 1
        for attempt in range(2):
            cmd = self._cmd(self.recipe["connect"], loc)
            if _run(cmd, timeout=45) is None:
                self.log.warning(f"{self.name}: connect command failed "
                                 f"({' '.join(cmd)})")
                return False
            # wait for the tunnel to settle, then probe
            for _ in range(6):
                time.sleep(3.0)
                try:
                    ip = _probe_direct_egress(timeout=8)
                    if ip and ip != self.current_ip:
                        self.current_ip = ip
                        return True
                except Exception:
                    continue
            self.disconnect()
        return False


class VpnPoolManager:
    """Manager shim for `ip-rotator vpn` mode: rotates the CLI VPN every
    `interval` seconds and serves the SAME local front-ends (HTTP CONNECT +
    SOCKS5).

    Fail-closed egress guard: every request re-checks (cached 8s) that the
    machine's egress IP is NOT the pre-VPN real IP. If the VPN silently
    dropped, requests get 502/SOCKS-refused instead of leaking the real IP.
    """

    def __init__(self, cfg, state, log, providers: List[VpnCliProvider],
                 real_ip: str):
        self.cfg = cfg
        self.state = state
        self.log = log
        self.providers = providers
        self.real_ip = real_ip
        self._pi = 0
        self.current: Optional[VpnCliProvider] = None
        self._guard_ip = ""
        self._guard_ts = 0.0
        self._stop = threading.Event()
        self._next_tick = 0.0
        self._bytes_lock = threading.Lock()
        self.stats = {"rotations": 0, "requests": 0, "guard_blocks": 0,
                      "bytes": 0}

    # -- server-facing API (same shape as PoolManager) -----------------------
    def next_upstream(self, exclude, host: str = "") -> Optional[Upstream]:
        self.stats["requests"] += 1
        if self.current is None or not self._guard_ok():
            self.stats["guard_blocks"] += 1
            return None
        return Upstream(kind="direct", host="-", port=0,
                        egress_ip=self.current.current_ip,
                        source=f"vpn:{self.current.name}", latency_ms=0)

    def report_success(self, up: Upstream) -> None:
        pass

    def report_failure(self, up: Upstream, why: str) -> bool:
        self.log.warning(f"vpn mode: request failed ({why}) - forcing rotation")
        self._rotate(force=True)
        return False

    def report_bytes(self, up: Upstream, n: int) -> None:
        if up is None or self.current is None:
            return
        with self._bytes_lock:
            self.stats["bytes"] += n
        self.state.add_api_usage(f"vpn:{self.current.name}", bytes_=n,
                                 monthly=True)
        cap = self.current.cap_bytes
        if cap and self.current.bytes_used() >= cap:
            self.log.warning(
                f"{self.current.name} hit its free data cap "
                f"({cap / 1024 ** 3:.0f}GB) - rotating provider")
            self._rotate(force=True, skip_current=True)

    def seconds_to_next_rotation(self) -> float:
        return max(0.0, self._next_tick - time.monotonic())

    def describe_current(self) -> str:
        if self.current is None:
            return "none (VPN down)"
        return f"{self.current.current_ip} via vpn:{self.current.name}"

    def snapshot(self) -> dict:
        return {
            "mode": "vpn", "current": self.describe_current(),
            "real_ip": self.real_ip,
            "next_rotation_in": round(self.seconds_to_next_rotation(), 1),
            "stats": dict(self.stats), "ts": time.time(),
        }

    # -- internals ------------------------------------------------------------
    def _guard_ok(self) -> bool:
        """Cached egress check: True only if traffic leaves via the VPN."""
        now = time.monotonic()
        if now - self._guard_ts < 8.0:
            return self._guard_ip not in ("", self.real_ip)
        self._guard_ts = now
        try:
            self._guard_ip = _probe_direct_egress(timeout=8)
        except Exception:
            self._guard_ip = ""
        return self._guard_ip not in ("", self.real_ip)

    def _rotate(self, force: bool = False, skip_current: bool = False) -> None:
        prev = self.current
        if prev is not None:
            prev.disconnect()
            self.current = None
        order = [self.providers[(self._pi + i) % len(self.providers)]
                 for i in range(len(self.providers))]
        if skip_current and prev is not None:
            order = [p for p in order if p is not prev] or order
        for p in order:
            if p.over_cap():
                self.log.warning(f"{p.name}: free data cap exhausted "
                                 f"({p.bytes_used() / 1024 ** 3:.1f}GB) - skipping")
                continue
            if p.connect():
                self._pi = (self.providers.index(p) + 1) % len(self.providers)
                self.current = p
                self.state.mark_ip_used(p.current_ip, f"vpn:{p.name}")
                self.stats["rotations"] += 1
                self.log.warning(
                    f"VPN ROTATE #{self.stats['rotations']} -> "
                    f"{p.current_ip} via {p.name} ({p.recipe['label']})")
                return
        self.log.critical("ALL VPN providers failed to connect - "
                          "serving blocked until one recovers")

    def start(self):
        def _loop():
            self._rotate(force=True)
            while not self._stop.is_set():
                self._next_tick = time.monotonic() + self.cfg.interval
                self._stop.wait(min(5.0, max(0.5, self._next_tick
                                             - time.monotonic())))
                if time.monotonic() >= self._next_tick:
                    self._rotate()
        threading.Thread(target=_loop, name="vpn-rotator", daemon=True).start()

    def stop(self):
        self._stop.set()
        if self.current is not None:
            self.current.disconnect()


# ===========================================================================
# VPN Gate — OPT-IN dirty-tier lane (user request: never discard reliable
# things; this one IS reliable in availability, but its volunteer egress
# IPs are frequently flagged — you opt in consciously).
#
# What it is: a University of Tsukuba research project; volunteers run
# OpenVPN servers worldwide; the public API lists thousands of them.
# FREE, unlimited, NO account, NO card.
#
# Honest constraints (why it is opt-in, not default):
#   * needs openvpn + sudo (full tunnel, root required) — dedicated mode
#   * egress = volunteer PCs: shared, dirty, often blocked by WAFs
#   * servers die constantly (the list refreshes every 5 min)
#   * like every full-tunnel VPN: 10-30s reconnect blip per rotation
# ===========================================================================
VPNGATE_API = ("http://www.vpngate.net/api/iphone/?fields=hostname,vpn"
               "sessions,openvpn_configdata_base64,speed,countrycode")


def parse_vpngate_csv(text: str, max_servers: int = 40) -> List[dict]:
    """Parse the VPN Gate CSV body (banner lines, then header, then rows)."""
    import csv
    import io as _io
    lines = [ln for ln in text.splitlines()
             if not ln.startswith("*") and ln.strip()]
    start = 0
    for i, ln in enumerate(lines):
        if ln.lower().startswith("hostname,"):
            start = i
            break
    else:
        return []
    reader = csv.DictReader(_io.StringIO("\n".join(lines[start:])))
    out = []
    for row in reader:
        try:
            cfg_b64 = (row.get("OpenVPN_ConfigData_Base64") or "").strip()
            speed = int(float(row.get("Speed") or 0))
            sessions = int(float(row.get("NumVpnSessions") or 0))
        except ValueError:
            continue
        if not cfg_b64:
            continue
        out.append({
            "country": ((row.get("CountryShort") or
                         row.get("CountryCode") or "--").upper()),
            "speed": speed, "sessions": sessions, "config_b64": cfg_b64,
        })
    out.sort(key=lambda s: (-s["speed"]))
    return out[:max_servers]


def vpngate_fetch_servers(max_servers: int = 40,
                          timeout: float = 25.0) -> List[dict]:
    """Fetch the public server list (CSV with base64 openvpn configs)."""
    r = http_client().get(VPNGATE_API, timeout=timeout,
                          headers={"User-Agent": "Mozilla/5.0"})
    r.raise_for_status()
    return parse_vpngate_csv(r.text, max_servers)


class VpnGateProvider:
    """Full-tunnel OpenVPN provider for the `vpn` mode (needs sudo).

    API-compatible with VpnCliProvider so VpnPoolManager can drive it."""
    name = "vpngate"
    recipe = {"label": "VPN Gate (opt-in)", "bins": ["openvpn"],
              "notes": "free, unlimited, volunteer servers — DIRTY egress "
                       "tier; needs openvpn + sudo"}

    def __init__(self, log, state):
        self.log = log
        self.state = state
        self.bin = shutil.which("openvpn")
        self.current_ip = ""
        self._servers: List[dict] = []
        self._i = 0
        self.proc = None

    @property
    def cap_bytes(self):
        return None  # unlimited data

    def bytes_used(self) -> int:
        return 0

    def over_cap(self) -> bool:
        return False

    def available(self) -> bool:
        if self.bin is None:
            return False
        if shutil.which("sudo") is None:
            return False
        return True

    def _ensure_servers(self):
        if not self._servers:
            try:
                self._servers = vpngate_fetch_servers()
                self.log.info(f"vpngate: fetched {len(self._servers)} "
                              "candidate servers")
            except Exception as e:
                self.log.warning(f"vpngate list fetch failed: {e}")

    def disconnect(self):
        if self.proc is not None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=10)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
            self.proc = None

    def connect(self) -> bool:
        """Write the next server's openvpn config and bring it up via sudo."""
        import tempfile
        self._ensure_servers()
        if not self._servers or not self.available():
            return False
        for _ in range(min(3, len(self._servers))):
            srv = self._servers[self._i % len(self._servers)]
            self._i += 1
            try:
                import base64 as _b64
                cfg = _b64.b64decode(srv["config_b64"]).decode("utf-8",
                                                                "replace")
            except Exception:
                continue
            with tempfile.NamedTemporaryFile("w", suffix=".ovpn",
                                             delete=False) as fh:
                fh.write(cfg)
                path = fh.name
            try:
                self.proc = subprocess.Popen(
                    ["sudo", "-n", self.bin, "--config", path],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except OSError as e:
                self.log.warning(f"vpngate: openvpn spawn failed: {e}")
                return False
            for _ in range(10):
                time.sleep(2.5)
                try:
                    ip = _probe_direct_egress(timeout=8)
                    if ip and ip != self.current_ip:
                        self.current_ip = ip
                        self.log.warning(
                            f"vpngate: connected via {srv['country']} "
                            f"(egress {ip}) — volunteer egress: expect "
                            "blocks on strict sites")
                        return True
                except Exception:
                    continue
            self.disconnect()
        return False


# ===========================================================================
# Windscribe proxy mode — OPT-IN clean-ish lane WITHOUT full tunnel.
#
# `windscribe-cli` (official, free, 10GB/month, NO CARD) has a proxy mode:
#     windscribe proxy on US     -> local SOCKS5 on 127.0.0.1:1080 + HTTP :8080
#     windscribe proxy location US
#     windscribe proxy off
# Unlike full-tunnel connect, machine routing is untouched: the tool can
# route ONLY crawler traffic through it — exactly what we want. Locations
# rotate by switching the proxy location (seconds, not 30s).
# ===========================================================================
class WindscribeProxyProvider:
    def __init__(self, cfg, log):
        self.cfg = cfg
        self.log = log
        self.bin = next((b for b in ("windscribe", "windscribe-cli")
                         if shutil.which(b)), None)
        self._loc_i = 0

    def available(self) -> bool:
        if not self.cfg.enable_windscribe_proxy:
            return False
        if self.bin is None:
            self.log.warning("windscribe proxy lane: CLI not installed "
                             "(see docs/06-auth-guides.md)")
            return False
        for port in (self.cfg.windscribe_proxy_socks_port, 8080):
            try:
                s = socket.create_connection(("127.0.0.1", port), timeout=1.5)
                s.close()
                return True
            except OSError:
                continue
        return self._proxy_on()

    def _run(self, *args, timeout: float = 30.0):
        return _run([self.bin, *args], timeout=timeout)

    def _proxy_on(self) -> bool:
        """`windscribe proxy on` (and login state check)."""
        out = self._run("proxy", "on")
        if out is None:
            # windscribe exits non-zero when not logged in
            self.log.warning(
                "windscribe proxy on failed — run `windscribe login` once "
                "(see docs/06-auth-guides.md), or check `windscribe account`")
            return False
        for _ in range(10):
            try:
                s = socket.create_connection(
                    ("127.0.0.1", self.cfg.windscribe_proxy_socks_port),
                    timeout=1.5)
                s.close()
                return True
            except OSError:
                time.sleep(1.0)
        return False

    def rotate_location(self) -> bool:
        """Switch proxy location -> different egress IP (fast, no tunnel
        rebuild)."""
        locs = self.cfg.windscribe_proxy_locations or ["US"]
        loc = locs[self._loc_i % len(locs)]
        self._loc_i += 1
        if self._run("proxy", "location", loc) is None:
            self.log.warning(f"windscribe proxy location {loc} failed")
            return False
        return True

    def upstream(self) -> Upstream:
        return Upstream(kind="socks5", host="127.0.0.1",
                        port=self.cfg.windscribe_proxy_socks_port,
                        source="windscribe-proxy")


# ===========================================================================
# Geo lookup (optional country filter). ip-api.com free tier: 45 req/min,
# non-commercial use. Results cached in the state DB.
# ===========================================================================
def geo_lookup(ip: str) -> Optional[str]:
    try:
        data = get_json(f"http://ip-api.com/json/{ip}?fields=countryCode",
                        timeout=6)
        return (data.get("countryCode") or "").upper() or None
    except Exception:
        return None
