"""WireGuard lane via wireproxy — the WARP multi-account engine + a generic
"bring your own WireGuard configs" lane (Proton Free / Windscribe Free /
PrivadoVPN Free / any VPN that hands you a .conf).

Why this module exists (the 10-second-clean-IP problem):
  * Free-proxy pool: unlimited fresh IPs, but datacenter reputation.
  * Webshare free: clean but only 10 IPs and 1 GB/month.
  * WARP accounts: FREE, NO CARD, NO EMAIL — one HTTPS POST per account.
    Each registered account = its own WireGuard identity with its own
    Cloudflare egress IP. Run N warm wireproxy processes (userspace
    WireGuard, NO root, NO kernel module) and switching IP = switching
    which already-connected local SOCKS port we dial -> ZERO dial delay,
    ZERO teardown, ZERO dropped requests.
  * When every account's IP has been used: register more (auto).

Key discoveries made while building this (all live-verified):
  * wireproxy >= 1.0 config format: root key `WGConfig = path` OR inline
    `[Interface]/[Peer]` sections (the OLD `WGConfig:` Go-style section
    from blog posts is DEAD — it makes wireproxy try to `open ""`).
  * The old `Reserved = [b,b,b]` field (WARP client_id) is GONE from
    current wireproxy. It does not matter: WARP accepts standard
    WireGuard handshakes without reserved bytes (the wgcf approach).
  * OpenSSL emits X25519 keys as PKCS#8 DER (48 bytes); WireGuard needs
    the RAW last 32 bytes, base64 — convert or wireproxy rejects with
    "key should be 32 bytes".
  * The CF client API endpoint api.cloudflareclient.com/v0a2158/reg
    returns HTTP 200 with {config:{client_id, peers[0].public_key,
    endpoint.host, interface.addresses.v4/v6}} — everything needed.

Graceful degradation: WireGuard needs UDP egress. Some networks (cloud
sandboxes, strict corp NATs) allow only UDP/53 — handshakes never
complete. The lane detects this (handshake timeout on every tunnel),
reports it loudly ONCE, disables itself, and the other lanes carry on.
"""
import base64
import json
import os
import shutil
import socket
import subprocess
import threading
import time
import zipfile
from typing import Dict, List, Optional

from .dialer import Upstream, fetch_egress_ip
from .httpkit import http_client

CF_REG = "https://api.cloudflareclient.com/v0a2158/reg"
WARP_PEER_PUB = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="

# egress through a WARP account is Cloudflare edge: clean, unlimited data.
# Not metered. Cap accounts only to be polite to the API.
MAX_ACCOUNTS = 64


# ===========================================================================
# account registration (Cloudflare client API — no card, no email)
# ===========================================================================
def x25519_keypair() -> (str, str):
    """Generate (public_key_b64, raw_private_key_b64) via openssl.

    openssl outputs the private key PKCS#8-DER-wrapped (48 bytes); the
    WireGuard userspace stack needs the raw 32-byte scalar. For X25519 the
    raw key is always the LAST 32 bytes of the DER blob.
    """
    gen = subprocess.run(["openssl", "genpkey", "-algorithm", "X25519"],
                         capture_output=True, text=True, timeout=15)
    if gen.returncode != 0:
        raise RuntimeError(f"openssl genpkey failed: {gen.stderr[:120]}")
    pem = gen.stdout
    pub = "".join(l for l in subprocess.run(
        ["openssl", "pkey", "-pubout"], input=pem, capture_output=True,
        text=True, timeout=15).stdout.splitlines() if "-----" not in l)
    der = subprocess.run(["openssl", "pkey", "-outform", "DER"],
                         input=pem.encode(), capture_output=True,
                         timeout=15).stdout
    if len(der) < 32:
        raise RuntimeError("unexpected X25519 DER length")
    return pub, base64.b64encode(der[-32:]).decode()


def register_warp_account(timeout: float = 20.0) -> dict:
    """Register one FREE WARP account; returns the fields a tunnel needs."""
    pub, priv = x25519_keypair()
    body = json.dumps({
        "key": pub,
        "install_id": "",
        "fcm_token": "",
        "tos": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
        "model": "pc",
        "serial_number": os.urandom(4).hex(),
    }).encode()
    r = http_client().post(
        CF_REG, content=body, timeout=timeout,
        headers={"Content-Type": "application/json",
                 "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) "
                               "AppleWebKit/537.36"})
    if r.status_code not in (200, 201):
        raise OSError(f"WARP registration HTTP {r.status_code}: "
                      f"{r.text[:120]}")
    data = r.json()
    cfg = data.get("config") or {}
    peers = cfg.get("peers") or []
    addr = (cfg.get("interface") or {}).get("addresses") or {}
    if not peers or not addr.get("v4"):
        raise OSError("WARP registration response missing config fields")
    return {
        "registered_at": time.time(),
        "private_key": priv,
        "v4": addr["v4"],
        "v6": addr.get("v6", ""),
        "peer_pub": peers[0].get("public_key") or WARP_PEER_PUB,
        "endpoint": (peers[0].get("endpoint") or {}).get("host",
                                                         "engage.cloudflareclient.com:2408"),
    }


class WarpAccountStore:
    """JSON file of registered accounts (survives restarts)."""

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._accounts: List[dict] = []
        self._load()

    def _load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                self._accounts = json.load(fh)
        except Exception:
            self._accounts = []

    def _save(self):
        os.makedirs(os.path.dirname(os.path.abspath(self.path)) or ".",
                    exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self._accounts, fh, indent=1)
        os.replace(tmp, self.path)

    def all(self) -> List[dict]:
        with self._lock:
            return list(self._accounts)

    def count(self) -> int:
        with self._lock:
            return len(self._accounts)

    def add(self, acct: dict) -> None:
        with self._lock:
            self._accounts.append(acct)
            self._save()


# ===========================================================================
# wireproxy config generation (v1.0+ format — NOT the old WGConfig: style)
# ===========================================================================
def wireproxy_conf(acct: dict, socks_port: int, username: str = "",
                   password: str = "") -> str:
    v6 = f", {acct['v6']}/128" if acct.get("v6") else ""
    auth = ""
    if username:
        auth = (f"Username = {username}\nPassword = {password}\n")
    return f"""[Interface]
Address = {acct['v4']}/32{v6}
PrivateKey = {acct['private_key']}
DNS = 1.1.1.1

[Peer]
PublicKey = {acct['peer_pub']}
Endpoint = {acct['endpoint']}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25

[Socks5]
BindAddress = 127.0.0.1:{socks_port}
{auth}"""


def parse_wg_quick(path: str) -> dict:
    """Parse a standard wg-quick .conf into the dict wireproxy_conf needs
    (PrivateKey / Address / peer PublicKey / Endpoint). Extra keys
    (SaveConfig, Table, PostUp, fwmark...) are ignored safely."""
    iface, peer = {}, {}
    section = None
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("["):
                section = line.lower().strip("[]")
                continue
            if "=" not in line:
                continue
            k, _, v = line.partition("=")
            k, v = k.strip(), v.strip()
            tgt = iface if section == "interface" else peer if section == "peer" else None
            if tgt is not None:
                tgt[k] = v
    if not iface.get("PrivateKey") or not peer.get("PublicKey"):
        raise ValueError(f"{path}: missing PrivateKey/PublicKey")
    return {
        "private_key": iface["PrivateKey"],
        "v4": _first_v4(iface.get("Address", "")),
        "v6": _first_v6(iface.get("Address", "")),
        "peer_pub": peer["PublicKey"],
        "endpoint": peer.get("Endpoint", ""),
        "name": os.path.splitext(os.path.basename(path))[0],
    }


def _first_v4(addresses: str) -> str:
    for a in addresses.split(","):
        a = a.strip()
        if "." in a:
            return a.split("/")[0]
    return "10.0.0.2"  # placeholder; wireproxy needs SOME address


def _first_v6(addresses: str) -> str:
    for a in addresses.split(","):
        a = a.strip()
        if ":" in a:
            return a.split("/")[0]
    return ""


# ===========================================================================
# one tunnel = one wireproxy subprocess = one local SOCKS5 port
# ===========================================================================
class WireProxyTunnel:
    def __init__(self, name: str, acct: dict, port: int, cfg, log,
                 username: str = "", password: str = ""):
        self.name = name
        self.acct = acct
        self.port = port
        self.cfg = cfg
        self.log = log
        self.proc: Optional[subprocess.Popen] = None
        self.conf_path = os.path.join(
            cfg.wireproxy_state_dir(), f"{name}.conf")
        self.egress_ip = ""
        self.last_probe = 0.0
        self.failed_reason = ""
        self._lock = threading.Lock()

    # ---------------------------------------------------------------- spawn
    def start(self) -> bool:
        if self.is_running():
            return True
        try:
            os.makedirs(os.path.dirname(self.conf_path), exist_ok=True)
            with open(self.conf_path, "w", encoding="utf-8") as fh:
                fh.write(wireproxy_conf(
                    self.acct, self.port,
                    self.cfg.wg_socks_username, self.cfg.wg_socks_password))
        except OSError as e:
            self.failed_reason = f"conf write: {e}"
            return False
        try:
            self.proc = subprocess.Popen(
                [WireGuardLane.find_wireproxy(self.cfg.wireproxy_bin),
                 "-c", self.conf_path, "-s"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            self.failed_reason = (f"wireproxy binary not found at "
                                  f"{self.cfg.wireproxy_bin}")
            return False
        except OSError as e:
            self.failed_reason = f"spawn: {e}"
            return False
        return True

    def is_running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def socks_ready(self, timeout: float = 8.0) -> bool:
        """True once the local SOCKS port accepts TCP (wireproxy bound it)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                s = socket.create_connection(("127.0.0.1", self.port),
                                             timeout=1.0)
                s.close()
                return True
            except OSError:
                time.sleep(0.3)
        return False

    def probe_egress(self, timeout: float = 15.0) -> Optional[str]:
        """Fetch the egress IP THROUGH the tunnel (proves handshake done)."""
        up = Upstream(kind="socks5", host="127.0.0.1", port=self.port,
                      username=self.cfg.wg_socks_username,
                      password=self.cfg.wg_socks_password,
                      source=f"wg:{self.name}")
        try:
            ip, _ = fetch_egress_ip(up, timeout=timeout)
        except Exception as e:
            self.failed_reason = f"probe: {type(e).__name__}"
            return None
        with self._lock:
            self.egress_ip = ip
            self.last_probe = time.time()
        return ip

    def stop(self) -> None:
        if self.proc is not None:
            try:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
            except Exception:
                pass
            self.proc = None
        try:
            os.unlink(self.conf_path)
        except OSError:
            pass

    def describe(self) -> str:
        run = "up" if self.is_running() else "down"
        ip = self.egress_ip or "-"
        return f"{self.name}[{run}] 127.0.0.1:{self.port} egress={ip}"


# ===========================================================================
# the lane manager: N warm tunnels, fresh-IP selection, auto re-register
# ===========================================================================
class WireGuardLane:
    """Keeps `cfg.warp_accounts` WARP tunnels + every *.conf in
    `cfg.wg_configs_dir` warm. Each tunnel is a validated socks5 upstream
    inside the normal pool — so rotation/failover/metering all reuse the
    existing machinery.

    Lifecycle per tunnel: spawn -> wait SOCKS bind -> probe egress (this is
    where UDP-blocked networks fail: handshake never completes, probe
    times out) -> feed into pool. Dead tunnels are restarted with backoff;
    the whole lane self-disables after `lane_disable_after` consecutive
    handshake failures so a UDP-blocked network doesn't spam.
    """

    def __init__(self, cfg, log, state):
        self.cfg = cfg
        self.log = log
        self.state = state
        self.tunnels: List[WireProxyTunnel] = []
        self.store = WarpAccountStore(cfg.warp_accounts_path())
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._fail_streak = 0
        self.disabled_reason = ""
        self._last_register_attempt = 0.0
        self.stats = {"registered": 0, "tunnels_started": 0,
                      "handshake_fails": 0, "egress_probes": 0}

    # ------------------------------------------------------------- binary
    @staticmethod
    def find_wireproxy(binpath: str) -> str:
        """Resolve the wireproxy binary: explicit path, else PATH lookup."""
        if os.path.isfile(binpath):
            return binpath
        found = shutil.which(binpath)
        if found:
            return found
        return ""

    # ------------------------------------------------------------- accounts
    def ensure_accounts(self) -> None:
        """Register accounts up to cfg.warp_accounts (rate-limited)."""
        want = self.cfg.warp_accounts
        have = self.store.count()
        if have >= want or want <= 0:
            return
        now = time.monotonic()
        if now - self._last_register_attempt < self.cfg.warp_register_cooldown:
            return
        self._last_register_attempt = now
        try:
            acct = register_warp_account()
            self.store.add(acct)
            self.stats["registered"] += 1
            self.log.info(f"WARP account registered ({self.store.count()}/"
                          f"{want}) egress will be probed after handshake")
        except Exception as e:
            self.log.warning(f"WARP registration failed: {e}")

    # -------------------------------------------------------------- tunnels
    def _build_tunnels(self) -> None:
        """(Re)build the tunnel list from accounts + user WG configs."""
        with self._lock:
            wanted: List[WireProxyTunnel] = []
            taken: set = {t.port for t in self.tunnels}
            for i, acct in enumerate(self.store.all()[:self.cfg.warp_accounts]):
                if any(t.name == f"warp{i}" for t in wanted):
                    continue
                wanted.append(self._reuse_or_new(f"warp{i}", acct, taken))
            if self.cfg.wg_configs_dir:
                try:
                    names = sorted(os.listdir(self.cfg.wg_configs_dir))
                except OSError:
                    names = []
                for fn in names:
                    if not fn.endswith(".conf"):
                        continue
                    path = os.path.join(self.cfg.wg_configs_dir, fn)
                    try:
                        acct = parse_wg_quick(path)
                    except Exception as e:
                        self.log.warning(f"wg config {fn}: {e}")
                        continue
                    name = "wg-" + acct["name"]
                    if any(t.name == name for t in wanted):
                        continue
                    wanted.append(self._reuse_or_new(name, acct, taken))
            # stop tunnels no longer wanted
            for t in self.tunnels:
                if t not in wanted:
                    t.stop()
            self.tunnels = wanted

    def _reuse_or_new(self, name: str, acct: dict,
                      taken: Optional[set] = None) -> WireProxyTunnel:
        for t in self.tunnels:
            if t.name == name:
                return t
        port = self._alloc_port(taken)
        if taken is not None:
            taken.add(port)  # so sibling tunnels in the same pass differ
        t = WireProxyTunnel(name, acct, port, self.cfg, self.log)
        self.stats["tunnels_started"] += 1
        return t

    def _alloc_port(self, taken: Optional[set] = None) -> int:
        # deterministic low-free-port allocation above the base port so
        # restarts reuse the same ports; existing tunnels keep theirs
        port = self.cfg.wg_socks_base_port
        used = taken if taken is not None else {t.port for t in self.tunnels}
        while port in used:
            port += 1
        return port

    def _handshake_ok(self, t: WireProxyTunnel) -> bool:
        if not t.is_running() and not t.start():
            self.log.warning(f"{t.name}: {t.failed_reason}")
            return False
        if not t.socks_ready(timeout=8.0):
            self._fail(t, "SOCKS port never bound (wireproxy crashed?)")
            return False
        ip = t.probe_egress(timeout=self.cfg.wg_handshake_timeout)
        if ip is None:
            self._fail(t, "no egress through tunnel (handshake incomplete "
                          "-> UDP egress blocked or endpoint down)")
            return False
        self.stats["egress_probes"] += 1
        self._fail_streak = 0
        return True

    def _fail(self, t: WireProxyTunnel, why: str) -> None:
        self.stats["handshake_fails"] += 1
        self._fail_streak += 1
        t.stop()
        self.log.warning(f"WG tunnel {t.name} failed: {why}")
        if self._fail_streak >= self.cfg.wg_lane_disable_after:
            self.disabled_reason = (
                f"{self._fail_streak} consecutive handshake failures — "
                f"this network likely blocks UDP (only DNS allowed?). "
                f"Lane disabled; other lanes carry traffic. "
                f"See docs/05-providers.md 'WireGuard lane'.")
            self.log.error("WIREGUARD LANE DISABLED: " + self.disabled_reason)

    # ----------------------------------------------------------- pool feed
    def validated_upstreams(self) -> List[Upstream]:
        """Tunnels with a proven egress IP -> socks5 upstreams for the pool."""
        out = []
        for t in self.tunnels:
            if t.egress_ip and t.is_running():
                out.append(Upstream(
                    kind="socks5", host="127.0.0.1", port=t.port,
                    egress_ip=t.egress_ip, latency_ms=0,
                    validated_at=t.last_probe, source=f"wg:{t.name}",
                    username=self.cfg.wg_socks_username,
                    password=self.cfg.wg_socks_password))
        return out

    # ----------------------------------------------------------- main loop
    def start(self):
        if not self.enabled():
            return
        threading.Thread(target=self._loop, name="wg-lane",
                         daemon=True).start()

    def enabled(self) -> bool:
        if self.disabled_reason:
            return False
        if not self.find_wireproxy(self.cfg.wireproxy_bin):
            self.disabled_reason = (f"wireproxy binary not found "
                                    f"({self.cfg.wireproxy_bin}); install: "
                                    f"curl -L "
                                    f"{self.cfg.wireproxy_download} "
                                    f"| tar xz - and put it on PATH — "
                                    f"see docs/06-auth-guides.md")
            return False
        return self.cfg.warp_accounts > 0 or bool(self.cfg.wg_configs_dir)

    def _loop(self):
        while not self._stop.is_set():
            if self.disabled_reason:
                break
            self.ensure_accounts()
            self._build_tunnels()
            for t in list(self.tunnels):
                if self.disabled_reason:
                    break
                fresh = (time.time() - t.last_probe) > \
                    self.cfg.wg_reprobe_seconds
                if t.egress_ip and t.is_running() and not fresh:
                    continue
                if not self._handshake_ok(t):
                    continue
                self.log.warning(
                    f"WG TUNNEL UP: {t.name} -> egress {t.egress_ip} "
                    f"(socks5 127.0.0.1:{t.port})")
            self._stop.wait(self.cfg.wg_lane_refresh_seconds)

    def stop(self):
        self._stop.set()
        # parallel teardown (B34): N tunnels x wait(5) sequential could
        # exceed the exit-watchdog budget
        threads = [threading.Thread(target=t.stop) for t in self.tunnels]
        for th in threads:
            th.start()
        for th in threads:
            th.join(timeout=8)

    def describe(self) -> str:
        if self.disabled_reason:
            return f"disabled ({self.disabled_reason})"
        ups = [f"{t.name}={t.egress_ip or '?'}" for t in self.tunnels]
        return f"{len(ups)} tunnels: " + ", ".join(ups)


# ===========================================================================
# v3: warp-plus lane — multi-country WARP egress, automatic country rotation
# ===========================================================================
# bepass-org/warp-plus (v1.2.6, flags live-verified): one binary per instance,
# each instance = a WARP identity (its own --cache-dir) + a local SOCKS5 port.
#   --cfon --country XX : Psiphon location select (31 countries) -> egress
#                         exits in country XX
#   --gool              : warp-in-warp -> different virtual NAT location
#   --scan              : probe for reachable WARP endpoints
# When an instance's egress IP is burned (inside the no-reuse window), the
# lane wipes the instance's identity and RESPAWNS it in the NEXT country of
# the rotation: country cycling + fresh registration = an elastic stream of
# never-seen egress IPs. Needs UDP egress (WireGuard); self-disables with a
# diagnosis on UDP-blocked networks (same contract as the wireproxy lane).
# ===========================================================================
_WARPPLUS_BIN_CACHE: Dict[str, str] = {}


def resolve_warpplus_bin(cfg, log) -> str:
    """Resolve the warp-plus binary ONCE per process (module-level cache):
    explicit cfg path -> PATH -> tools dir -> auto-download+unzip."""
    if "bin" in _WARPPLUS_BIN_CACHE:
        return _WARPPLUS_BIN_CACHE["bin"]
    path = cfg.warpplus_bin or ""
    if path and os.path.isfile(path):
        _WARPPLUS_BIN_CACHE["bin"] = path
        return path
    if path:
        found = shutil.which(path)
        if found:
            _WARPPLUS_BIN_CACHE["bin"] = found
            return found
    tools = os.path.join(cfg.warpplus_state_dir(), "bin")
    cand = os.path.join(tools, "warp-plus")
    if os.path.isfile(cand) and os.access(cand, os.X_OK):
        _WARPPLUS_BIN_CACHE["bin"] = cand
        return cand
    # auto-download (zip release)
    url = cfg.warpplus_download
    try:
        os.makedirs(tools, exist_ok=True)
        log.warning(f"warp-plus lane: downloading from {url}")
        import urllib.request
        import stat as _stat
        zpath = os.path.join(tools, "warp-plus.zip")
        urllib.request.urlretrieve(url, zpath)
        with zipfile.ZipFile(zpath) as zf:
            member = [m for m in zf.namelist()
                      if m.endswith("warp-plus")][0]
            target = os.path.join(tools, "warp-plus")
            with zf.open(member) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)
            os.chmod(target, os.stat(target).st_mode | _stat.S_IEXEC)
        os.unlink(zpath)
        _WARPPLUS_BIN_CACHE["bin"] = target
        return target
    except Exception as e:
        log.error(f"warp-plus auto-download failed ({e}); install: "
                  f"curl -LO {url} && unzip — see docs/09-warp-plus.md")
        return ""


class WarpPlusInstance:
    def __init__(self, idx: int, port: int, cfg, log):
        self.idx = idx
        self.port = port
        self.cfg = cfg
        self.log = log
        self.cache_dir = os.path.join(cfg.warpplus_state_dir(), f"inst{idx}")
        self.mode = ""           # cfon | gool | plain
        self.country = ""
        self.proc: Optional[subprocess.Popen] = None
        self.egress_ip = ""
        self.latency_ms = 0
        self.last_probe = 0.0
        self.failed_reason = ""
        self.spawned_at = 0.0
        self._lock = threading.Lock()

    # ------------------------------------------------------------ spawn
    def build_args(self, mode: str, country: str) -> List[str]:
        self.mode, self.country = mode, country
        args = [resolve_warpplus_bin(self.cfg, self.log),
                "--bind", f"127.0.0.1:{self.port}",
                "--cache-dir", self.cache_dir]
        if self.cfg.warpplus_scan:
            args.append("--scan")
        if mode == "cfon" and country:
            args += ["--cfon", "--country", country]
        elif mode == "gool":
            args.append("--gool")
        return args

    def start(self, mode: str, country: str,
              fresh_identity: bool = False) -> bool:
        if self.is_running():
            return True
        try:
            if fresh_identity:
                # wipe the profile -> warp-plus registers a brand-new WARP
                # identity -> brand-new egress IP (this is the mint)
                shutil.rmtree(self.cache_dir, ignore_errors=True)
            os.makedirs(self.cache_dir, exist_ok=True)
            self.proc = subprocess.Popen(
                self.build_args(mode, country),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                preexec_fn=WarpPlusLane._pdeathsig)
            self.spawned_at = time.time()
            return True
        except FileNotFoundError:
            self.failed_reason = "warp-plus binary not found"
        except OSError as e:
            self.failed_reason = f"spawn: {e}"
        return False

    def is_running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def socks_ready(self, timeout: float = 8.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                s = socket.create_connection(("127.0.0.1", self.port),
                                             timeout=1.0)
                s.close()
                return True
            except OSError:
                if self.proc is not None and self.proc.poll() is not None:
                    return False
                time.sleep(0.3)
        return False

    def probe_egress(self, timeout: float) -> Optional[str]:
        up = Upstream(kind="socks5", host="127.0.0.1", port=self.port,
                      source="warpplus:probe")
        t0 = time.monotonic()
        try:
            ip, _ = fetch_egress_ip(up, timeout=timeout)
        except Exception:
            return None
        with self._lock:
            self.egress_ip = ip
            self.latency_ms = int((time.monotonic() - t0) * 1000)
            self.last_probe = time.time()
        return ip

    def stop(self) -> None:
        if self.proc is not None:
            try:
                self.proc.terminate()
                try:
                    self.proc.wait(5)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
            except Exception:
                pass
            self.proc = None

    def describe(self) -> str:
        run = "up" if self.is_running() else "down"
        where = self.country or self.mode
        return (f"wp{self.idx}[{run}:{where}] 127.0.0.1:{self.port} "
                f"egress={self.egress_ip or '?'}")


class WarpPlusLane:
    """N warp-plus instances = N warm country-diverse WARP SOCKS ports."""

    def __init__(self, cfg, log, state):
        self.cfg = cfg
        self.log = log
        self.state = state
        self.instances: List[WarpPlusInstance] = []
        self.disabled_reason = ""
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._fail_streak = 0
        self._country_cursor = 0
        self._bin = ""
        self._last_mint = 0.0
        self.stats = {"spawns": 0, "respawns": 0, "mints": 0,
                      "mint_ips": 0, "handshake_fails": 0}

    # ------------------------------------------------------------- binary
    def find_binary(self, path: str) -> str:
        """explicit path -> PATH lookup -> tools dir -> auto-download."""
        resolved = resolve_warpplus_bin(self.cfg, self.log)
        if resolved:
            self._bin = resolved
            return resolved
        return path


    @staticmethod
    def _pdeathsig():
        try:
            import ctypes
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            if libc.prctl(1, 15, 0, 0, 0) != 0:
                raise OSError(ctypes.get_errno())
        except Exception:
            pass

    # ------------------------------------------------------------- config
    def _mode_for(self, idx: int) -> str:
        m = self.cfg.warpplus_mode
        if m == "auto":       # half country-locked, half warp-in-warp
            return "cfon" if idx % 2 == 0 else "gool"
        return m              # cfon | gool | plain

    def _next_country(self) -> str:
        countries = self.cfg.warpplus_countries or ["US"]
        with self._lock:
            c = countries[self._country_cursor % len(countries)]
            self._country_cursor += 1
        return c

    def _build_instances(self) -> None:
        with self._lock:
            wanted = []
            for i in range(self.cfg.warpplus_instances):
                if i < len(self.instances):
                    wanted.append(self.instances[i])
                else:
                    wanted.append(WarpPlusInstance(
                        i, self.cfg.warpplus_socks_base_port + i,
                        self.cfg, self.log))
            for inst in self.instances[len(wanted):]:
                inst.stop()
            self.instances = wanted

    # ------------------------------------------------------------- health
    def _handshake_ok(self, inst: WarpPlusInstance) -> bool:
        if not inst.is_running():
            inst.start(self._mode_for(inst.idx), self._next_country())
            if not inst.is_running():
                self.log.warning(f"warp-plus wp{inst.idx}: "
                                 f"{inst.failed_reason}")
                return False
            self.stats["spawns"] += 1
        # grace for handshake (psiphon/gool take longer than plain warp).
        # Live-verified behavior: warp-plus binds its SOCKS port ONLY after
        # the WireGuard handshake completes — on UDP-blocked networks the
        # process stays alive but never binds (registration still works:
        # it rides TCP/TLS), so "never bound" == "UDP blocked", not a crash.
        if not inst.socks_ready(timeout=self.cfg.warpplus_handshake_grace):
            self._fail(inst, "SOCKS never bound — WireGuard handshake "
                          "incomplete (UDP egress blocked on this network?")
            return False
        if not inst.probe_egress(timeout=self.cfg.warpplus_probe_timeout):
            self._fail(inst, "no egress (UDP blocked? handshake incomplete?)")
            return False
        self._fail_streak = 0
        return True

    def _fail(self, inst: WarpPlusInstance, why: str) -> None:
        self.stats["handshake_fails"] += 1
        self._fail_streak += 1
        inst.stop()
        self.log.warning(f"warp-plus wp{inst.idx} failed: {why}")
        if self._fail_streak >= self.cfg.wg_lane_disable_after:
            self.disabled_reason = (
                f"{self._fail_streak} consecutive handshake failures — "
                f"this network likely blocks UDP (WireGuard handshakes "
                f"can't complete). Lane disabled; other lanes carry "
                f"traffic. See docs/09-warp-plus.md")
            self.log.error("WARPPLUS LANE DISABLED: " + self.disabled_reason)

    # ---------------------------------------------------------- the mint
    def mint_new_ip(self, exclude_ips: set = None) -> Optional[str]:
        """AUTOMATIC country rotation: respawn the most-burned instance with
        a FRESH identity in the NEXT country -> a never-seen egress IP.
        Called by the pool whenever fresh supply runs low. Rate-limited."""
        exclude_ips = exclude_ips or set()
        now = time.monotonic()
        if now - self._last_mint < self.cfg.warpplus_handshake_grace:
            return None
        self._last_mint = now
        with self._lock:
            running = [i for i in self.instances if i.is_running()]
        if not running:
            return None
        # prefer the instance whose egress is burned; else the stalest probe
        burned = [i for i in running if i.egress_ip in exclude_ips]
        pool_burned = [i for i in (burned or running)
                       if self.state.ip_seen(i.egress_ip)]
        pick_from = pool_burned or burned or running
        inst = min(pick_from, key=lambda i: i.last_probe)
        inst.stop()
        self.stats["respawns"] += 1
        inst.start(self._mode_for(inst.idx), self._next_country(),
                   fresh_identity=True)
        self.stats["mints"] += 1
        if not inst.socks_ready(timeout=8.0):
            return None
        ip = inst.probe_egress(timeout=self.cfg.warpplus_probe_timeout)
        if ip and ip not in exclude_ips:
            self.stats["mint_ips"] += 1
            self.log.warning(
                f"warp-plus MINT: wp{inst.idx} "
                f"[{inst.mode}:{inst.country}] -> {ip} (fresh identity, "
                f"next country in rotation)")
            return ip
        return None

    # --------------------------------------------------------- pool feed
    def validated_upstreams(self) -> List[Upstream]:
        out = []
        with self._lock:
            insts = list(self.instances)
        for inst in insts:
            if inst.egress_ip and inst.is_running():
                out.append(Upstream(
                    kind="socks5", host="127.0.0.1", port=inst.port,
                    egress_ip=inst.egress_ip, latency_ms=inst.latency_ms,
                    validated_at=inst.last_probe,
                    source=f"warpplus:{inst.mode}:{inst.country or '-'}"))
        return out

    # ---------------------------------------------------------- lifecycle
    def enabled(self) -> bool:
        if self.disabled_reason:
            return False
        return bool(self.cfg.enable_warpplus and
                    self.cfg.warpplus_instances > 0)

    def start(self):
        if not self.enabled():
            return
        if not self.find_binary(self.cfg.warpplus_bin):
            return
        threading.Thread(target=self._loop, name="warpplus-lane",
                         daemon=True).start()

    def _loop(self):
        while not self._stop.is_set():
            if self.disabled_reason:
                break
            try:
                self._build_instances()
                for inst in self.instances:
                    if self.disabled_reason:
                        break
                    fresh = (time.time() - inst.last_probe) > \
                        self.cfg.wg_reprobe_seconds
                    if inst.egress_ip and inst.is_running() and not fresh:
                        continue
                    if self._handshake_ok(inst):
                        self.log.warning(
                            f"WARP-PLUS UP: wp{inst.idx} "
                            f"[{inst.mode}:{inst.country or '-'}] -> egress "
                            f"{inst.egress_ip} (socks5 127.0.0.1:{inst.port})")
            except Exception as e:
                self.log.warning(f"warp-plus lane loop error: {e}")
            self._stop.wait(self.cfg.wg_lane_refresh_seconds)

    def stop(self):
        self._stop.set()
        # parallel: N instances x wait(5) sequential could exceed the exit
        # watchdog budget (B34); parallel keeps teardown inside ~5s flat
        threads = [threading.Thread(target=inst.stop) for inst in self.instances]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=8)

    def describe(self) -> str:
        if self.disabled_reason:
            return f"disabled ({self.disabled_reason})"
        if not self.cfg.enable_warpplus:
            return "off"
        with self._lock:
            insts = list(self.instances)
        if not insts:
            return "starting"
        parts = [f"{i.mode}:{i.country or '-'}={i.egress_ip or '?'}"
                 for i in insts]
        return f"{len(insts)} instances: " + ", ".join(parts)
