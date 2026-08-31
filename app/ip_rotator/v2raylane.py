"""Free-node v2ray lane: thousands of community proxies through ONE sing-box.

Supply (verified live, Aug-2026): public Telegram-sourced aggregators such as
Epodonios/v2ray-configs (~7,250 nodes, refreshed every 5 minutes) and
barry-far/V2ray-Config. Protocols: vless (reality/tls, tcp/ws/grpc/
httpupgrade), vmess, trojan, shadowsocks, hysteria2.

Architecture ("best of the best" for 10-second rotation):
  ONE sing-box process maps N local SOCKS5 ports -> N validated nodes via
  route rules (inbound tag i -> outbound tag i). Switching egress IP =
  connecting to a different ALREADY-WARM local port: zero dial delay, zero
  teardown, no per-node process (one process instead of hundreds).

  regen uses two alternating port sets (A/B): the new process binds the
  other set, gets probed, and only then the old process dies -> the lane
  never goes dark for requests mid-flight (old ports keep serving until
  swap). The pool sees only lanes that pass validated_upstreams().

Live-discovered gotchas baked into the parser (see docs/08 bug log B23..):
  * sing-box REQUIRES uTLS on reality clients -> force utls/chrome when the
    link has no fp= param ("uTLS is required by reality client").
  * xhttp / kcp transports are Xray-only -> skipped (sing-box can't dial).
  * many aggregator links are dead within minutes -> per-node validation +
    cooldown + constant re-harvest is the ONLY viable design.
  * subscription bodies may be base64-wrapped (no "://" in body) -> decode.
  * urllib has NO socks5 support (prototype bug): probes go through the
    project's own dialer (httpx + python-socks), not urllib.
  * uTLS fingerprints must be whitelisted: nodes carry fp=unsafe etc. and
    ONE unknown fingerprint aborts the whole sing-box process (B35).
"""
import base64
import concurrent.futures
import json
import os
import random
import re
import shutil
import socket
import stat
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.parse
import zipfile
from typing import Dict, List, Optional, Tuple

# uTLS fingerprints sing-box actually accepts (live-verified v1.13.19;
# everything else -> FATAL "unknown uTLS fingerprint" for the whole config)
_UTLS_FINGERPRINTS = frozenset({
    "chrome", "firefox", "edge", "safari", "360", "qq", "ios",
    "android", "random", "randomized",
})

from .dialer import Upstream, fetch_egress_ip


# ---------------------------------------------------------------------------
# link parsing -> sing-box outbound dicts
# ---------------------------------------------------------------------------
def _b64pad(s: str) -> str:
    return s + "=" * (-len(s) % 4)


def b64decode_any(s: str) -> str:
    for dec in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return dec(_b64pad(s).encode()).decode("utf-8", "replace")
        except Exception:
            continue
    return ""


def parse_node_link(link: str, udp_ok: bool = False) -> Optional[dict]:
    """vless/vmess/trojan/ss/hysteria2 URI -> sing-box outbound dict.

    Returns None for anything sing-box cannot represent (xhttp, kcp, quic
    nodes on UDP-less networks, malformed links). Pure function -> easy test.
    """
    m = re.match(r"^(vless|vmess|trojan|ss|hysteria2)://(\S+)$", link.strip())
    if not m:
        return None
    proto, rest = m.group(1), m.group(2)
    try:
        # ---- legacy vmess: base64(JSON) --------------------------------
        if proto == "vmess" and "@" not in rest:
            j = json.loads(b64decode_any(rest))
            host, port = j.get("add", ""), int(j.get("port", 0) or 0)
            if not host or not port:
                return None
            net = j.get("net", "tcp")
            if net in ("xhttp", "kcp", "quic"):
                return None
            ob = {"type": "vmess", "tag": (j.get("ps") or "vmess")[:48],
                  "server": host, "server_port": port,
                  "uuid": j.get("id", ""),
                  "security": j.get("scy") or "auto",
                  "alter_id": int(j.get("aid", 0) or 0)}
            if (j.get("tls") or "") == "tls":
                ob["tls"] = {"enabled": True,
                             "server_name": j.get("sni") or j.get("host") or host}
            if net == "ws":
                tr = {"type": "ws", "path": j.get("path") or "/"}
                if j.get("host"):
                    tr["headers"] = {"Host": j["host"]}
                ob["transport"] = tr
            elif net == "grpc":
                ob["transport"] = {"type": "grpc",
                                   "service_name": j.get("path", "")}
            elif net == "h2":
                return None  # rare; avoid subtle mismatches
            elif j.get("type") == "http" and j.get("host"):
                ob["transport"] = {"type": "http",
                                   "headers": {"Host": j["host"]}}
            if not ob["uuid"]:
                return None
            return ob

        # ---- userinfo@host:port?query#fragment -------------------------
        frag = ""
        if "#" in rest:
            rest, frag = rest.split("#", 1)
        query: Dict[str, str] = {}
        if "?" in rest:
            rest, qs = rest.split("?", 1)
            query = {k: v[0] for k, v in
                     urllib.parse.parse_qs(qs, keep_blank_values=True).items()}
        userinfo, _, hostport = rest.rpartition("@")
        host, sep, port = hostport.rpartition(":")
        if not sep or not port.isdigit() or not host:
            return None
        port = int(port)
        if not (1 <= port <= 65535):
            return None
        ttype = query.get("type", "tcp")
        sec = query.get("security", "none")
        if ttype in ("xhttp", "kcp", "quic"):
            return None  # Xray-only transports (live-verified: sing-box fails)
        if proto == "hysteria2" and not udp_ok:
            return None  # QUIC/UDP-based: dead weight on UDP-less networks

        tag = urllib.parse.unquote(frag)[:48] or f"{proto}-{host}"
        tls_block = None
        if sec in ("tls", "reality") or proto in ("trojan", "hysteria2"):
            tls_block = {"enabled": True,
                         "server_name": query.get("sni") or
                                        query.get("host") or host}
            # uTLS fingerprint whitelist (live-verified against sing-box
            # v1.13.19: anything else — e.g. 'unsafe', 'randomalpn' — makes
            # sing-box abort the WHOLE config with "unknown uTLS fingerprint")
            fp = query.get("fp", "chrome")
            if fp not in _UTLS_FINGERPRINTS:
                fp = "chrome"
            tls_block["utls"] = {"enabled": True, "fingerprint": fp}
            if query.get("alpn"):
                tls_block["alpn"] = query.get("alpn").split(",")
            if sec == "reality":
                if not query.get("pbk"):
                    return None  # reality without public key is unusable
                reality = {"enabled": True, "public_key": query["pbk"]}
                if query.get("sid"):
                    reality["short_id"] = query["sid"]
                tls_block["reality"] = reality
            if proto == "hysteria2" and query.get("insecure") in ("1", "true"):
                tls_block["insecure"] = True

        transport = None
        if ttype == "ws":
            transport = {"type": "ws", "path": query.get("path") or "/"}
            if query.get("host"):
                transport["headers"] = {"Host": query["host"]}
        elif ttype == "grpc":
            transport = {"type": "grpc",
                         "service_name": query.get(
                             "serviceName", query.get("path", ""))}
        elif ttype == "httpupgrade":
            transport = {"type": "httpupgrade",
                         "path": query.get("path") or "/"}
            if query.get("host"):
                transport["host"] = query["host"]
        elif ttype == "http" and proto != "ss":
            transport = {"type": "http", "method": "GET",
                         "path": query.get("path") or "/"}
            if query.get("host"):
                transport["headers"] = {"Host": query["host"]}

        if proto in ("vless", "vmess"):
            uuid_ = urllib.parse.unquote(userinfo)
            if not uuid_:
                return None
            ob = {"type": proto, "tag": tag, "server": host,
                  "server_port": port, "uuid": uuid_}
            if proto == "vless":
                if query.get("flow"):
                    ob["flow"] = query["flow"]
            else:
                ob["security"] = query.get("encryption", "auto")
                ob["alter_id"] = int(query.get("aid", 0) or 0)
        elif proto == "trojan":
            pwd = urllib.parse.unquote(userinfo)
            if not pwd:
                return None
            ob = {"type": "trojan", "tag": tag, "server": host,
                  "server_port": port, "password": pwd}
        elif proto == "ss":
            ui = userinfo if ":" in userinfo else b64decode_any(userinfo)
            if ":" not in ui:
                return None
            method, _, pwd = ui.partition(":")
            if not method or not pwd:
                return None
            ob = {"type": "shadowsocks", "tag": tag, "server": host,
                  "server_port": port, "method": method, "password": pwd}
        else:  # hysteria2 (udp_ok gate already passed)
            ob = {"type": "hysteria2", "tag": tag, "server": host,
                  "server_port": port,
                  "password": urllib.parse.unquote(userinfo)}
            if query.get("obfs") == "salamander":
                ob["obfs"] = {"type": "salamander",
                              "password": query.get("obfs-password", "")}

        if tls_block:
            ob["tls"] = tls_block
        if transport:
            ob["transport"] = transport
        return ob
    except Exception:
        return None


def decode_subscription(body: str) -> List[str]:
    """Plain link list OR base64-wrapped list -> list of node links."""
    lines = [l.strip() for l in body.splitlines() if l.strip()]
    if any("://" in l for l in lines):
        return [l for l in lines if "://" in l]
    decoded = b64decode_any("".join(lines))
    if "://" in decoded:
        return [l.strip() for l in decoded.splitlines()
                if "://" in l.strip()]
    return []


# ===========================================================================
# the lane
# ===========================================================================
class V2RayLane:
    """One sing-box process, N warm node ports, constant re-harvest."""

    def __init__(self, cfg, log, state):
        self.cfg = cfg
        self.log = log
        self.state = state
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self.disabled_reason = ""
        self._proc: Optional[subprocess.Popen] = None
        self._proc_ports: List[int] = []          # ports current process owns
        self._nodes: Dict[int, dict] = {}         # port -> outbound (meta)
        self._healthy: Dict[int, dict] = {}       # port -> {ip, ms, at, tag}
        self._port_set = 0                        # alternate A/B on regen
        self._sub_state = {u: {"next_ok": 0.0, "backoff": 0.0}
                           for u in cfg.v2ray_subs}
        self._last_sub_pull = 0.0
        self._candidate_links: List[str] = []
        self._bin = ""
        self.stats = {"subs_pulled": 0, "links_parsed": 0, "nodes_validated": 0,
                      "nodes_alive": 0, "regens": 0, "probes": 0,
                      "probe_fails": 0}

    # ------------------------------------------------------------ binary
    def _resolve_bin(self) -> str:
        """explicit path -> PATH -> tools dir -> auto-download+extract."""
        if self._bin:
            return self._bin
        cand = self.cfg.singbox_bin or "sing-box"
        if os.path.isfile(cand):
            self._bin = cand
        else:
            found = shutil.which(cand)
            if found:
                self._bin = found
        if not self._bin:
            tools = os.path.join(self.cfg.v2ray_state_dir(), "bin")
            path = os.path.join(tools, "sing-box")
            if os.path.isfile(path) and os.access(path, os.X_OK):
                self._bin = path
            else:
                self._bin = self._download_singbox(tools)
        return self._bin

    def _download_singbox(self, tools_dir: str) -> str:
        url = self.cfg.singbox_download
        try:
            os.makedirs(tools_dir, exist_ok=True)
            self.log.warning(f"v2ray lane: downloading sing-box from {url}")
            import urllib.request
            tgz = os.path.join(tools_dir, "sing-box.tar.gz")
            urllib.request.urlretrieve(url, tgz)
            with tarfile.open(tgz) as tf:
                member = [m for m in tf.getmembers()
                          if m.name.endswith("sing-box")][0]
                member.name = "sing-box"
                tf.extract(member, tools_dir)
            os.unlink(tgz)
            path = os.path.join(tools_dir, "sing-box")
            os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
            self._bin = path
            return path
        except Exception as e:
            self.disabled_reason = (f"sing-box unavailable ({e}); install: "
                                    f"curl -L {url} | tar xz — see docs/10")
            self.log.error("V2RAY LANE DISABLED: " + self.disabled_reason)
            return ""

    @staticmethod
    def _pdeathsig():
        """Children must die with this process (B21 parity for uv wrappers)."""
        try:
            import ctypes
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            if libc.prctl(1, 15, 0, 0, 0) != 0:  # 1=PDEATHSIG, 15=SIGTERM
                raise OSError(ctypes.get_errno())
        except Exception:
            pass

    def enabled(self) -> bool:
        if self.disabled_reason:
            return False
        return bool(self.cfg.enable_v2ray)

    # -------------------------------------------------------- subscriptions
    def _pull_subs(self) -> List[str]:
        from .httpkit import http_client
        links: List[str] = []
        now = time.monotonic()
        for url, st in self._sub_state.items():
            if now < st["next_ok"]:
                continue
            try:
                body = http_client().get(url, timeout=25.0).text
                got = decode_subscription(body)
                if got:
                    links += got
                    st["backoff"] = 0.0
                    st["next_ok"] = 0.0
                else:
                    raise ValueError("empty subscription body")
            except Exception as e:
                st["backoff"] = min(max(st["backoff"] * 2, 60),
                                    self.cfg.v2ray_sub_backoff_max)
                st["next_ok"] = now + st["backoff"]
                self.log.warning(
                    f"v2ray sub {url.rsplit('/', 2)[-1][:40]} failed "
                    f"({type(e).__name__}) - backoff {st['backoff']:.0f}s")
        # dedupe
        seen, uniq = set(), []
        for l in links:
            k = l.split("#")[0]
            if k not in seen:
                seen.add(k)
                uniq.append(l)
        if uniq:
            self.stats["subs_pulled"] += 1
        return uniq

    # ---------------------------------------------------------- config gen
    def _port_base(self) -> int:
        # alternate between base and base+512 so regen never collides
        return self.cfg.v2ray_socks_base_port + (512 * self._port_set)

    def _build_config(self, outbounds: List[dict]) -> dict:
        base = self._port_base()
        inbounds, rules = [], []
        for i, ob in enumerate(outbounds):
            port = base + 1 + i
            in_tag, ob_tag = f"in{i}", f"ob{i}"
            ob["tag"] = ob_tag
            inbounds.append({"type": "socks", "tag": in_tag,
                             "listen": "127.0.0.1", "listen_port": port})
            rules.append({"inbound": [in_tag], "outbound": ob_tag})
        return {
            "log": {"level": "error", "timestamp": False},
            "inbounds": inbounds,
            "outbounds": outbounds,
            "route": {"rules": rules, "final": outbounds[0]["tag"]},
        }

    def _check_outbound(self, ob: dict) -> bool:
        """sing-box check on a mini config: catches schema rejects BEFORE the
        big config kills the whole process.

        B35 fix: one SHARED check.json path for 16 parallel workers was a
        race (worker A validated worker B's config — bad outbounds rode
        through on a neighbour's PASS). Each call now gets its own tempfile.
        """
        cfg = {"log": {"disabled": True},
               "inbounds": [{"type": "socks", "tag": "in",
                             "listen": "127.0.0.1", "listen_port": 0}],
               "outbounds": [dict(ob)]}
        fd = path = None
        try:
            os.makedirs(self.cfg.v2ray_state_dir(), exist_ok=True)
            fd, path = tempfile.mkstemp(
                prefix="check_", suffix=".json",
                dir=self.cfg.v2ray_state_dir())
            with os.fdopen(fd, "w") as fh:
                json.dump(cfg, fh)
            r = subprocess.run([self._bin, "check", "-c", path],
                               capture_output=True, timeout=10)
            return r.returncode == 0
        except Exception:
            return False
        finally:
            if path is not None:
                try:
                    os.unlink(path)
                except OSError:
                    pass

    def _singbox_err_tail(self, errfile: str) -> str:
        """Last meaningful line of sing-box's stderr — turns 'never bound'
        into an actionable message (e.g. 'unknown uTLS fingerprint: ...')."""
        try:
            with open(errfile, "r") as fh:
                lines = [ln.strip() for ln in fh if ln.strip()]
            return lines[-1][:160] if lines else ""
        except OSError:
            return ""

    # ------------------------------------------------------------ probing
    def _probe_port(self, port: int, timeout: float) -> Optional[Tuple[str, int]]:
        up = Upstream(kind="socks5", host="127.0.0.1", port=port,
                      source="v2ray:probe")
        t0 = time.monotonic()
        ip, _ = fetch_egress_ip(up, timeout=timeout)
        return ip, int((time.monotonic() - t0) * 1000)

    def _probe_all(self, ports: List[int]) -> Dict[int, dict]:
        healthy: Dict[int, dict] = {}
        if not ports:
            return healthy
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.cfg.v2ray_probe_workers) as ex:
            futs = {ex.submit(self._probe_port, p,
                              self.cfg.v2ray_probe_timeout): p
                    for p in ports}
            for fut in concurrent.futures.as_completed(futs):
                port = futs[fut]
                self.stats["probes"] += 1
                try:
                    ip, ms = fut.result()
                except Exception:
                    self.stats["probe_fails"] += 1
                    continue
                if ip:
                    ob = self._nodes.get(port, {})
                    healthy[port] = {"ip": ip, "ms": ms, "at": time.time(),
                                     "tag": ob.get("tag", "?"),
                                     "proto": ob.get("type", "?")}
        return healthy

    # -------------------------------------------------------------- regen
    def _regen(self, links: List[str]) -> None:
        """Parse links, validate outbounds, swap sing-box process (A/B)."""
        random.shuffle(links)
        protos = set(self.cfg.v2ray_protocols)
        outbounds = []
        for l in links:
            if len(outbounds) >= self.cfg.v2ray_max_nodes:
                break
            ob = parse_node_link(l, udp_ok=self.cfg.v2ray_udp_ok)
            if not ob:
                continue
            t = "ss" if ob["type"] == "shadowsocks" else ob["type"]
            if t in protos:
                outbounds.append(ob)
        self.stats["links_parsed"] = len(outbounds)
        if not outbounds:
            self.log.warning("v2ray lane: no parseable nodes in subscriptions")
            return
        # schema-validate outbounds in parallel; keep the good ones
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=min(16, self.cfg.v2ray_probe_workers)) as ex:
            oks = list(ex.map(lambda ob: ob if self._check_outbound(ob)
                              else None, outbounds))
        outbounds = [ob for ob in oks if ob][:self.cfg.v2ray_max_nodes]
        self.stats["nodes_validated"] = len(outbounds)
        if not outbounds:
            self.log.warning("v2ray lane: all node configs rejected by "
                             "sing-box check")
            return

        # swap port set -> new process; old keeps serving until new is proven
        self._port_set ^= 1
        cfg = self._build_config(outbounds)
        new_ports = [ib["listen_port"] for ib in cfg["inbounds"]]
        conf = os.path.join(self.cfg.v2ray_state_dir(),
                            f"singbox_{self._port_set}.json")
        os.makedirs(self.cfg.v2ray_state_dir(), exist_ok=True)
        with open(conf, "w") as fh:
            json.dump(cfg, fh)
        errfile = os.path.join(self.cfg.v2ray_state_dir(),
                               f"singbox_{self._port_set}.stderr")
        try:
            errfh = open(errfile, "w")
            proc = subprocess.Popen(
                [self._bin, "run", "-c", conf],
                stdout=subprocess.DEVNULL, stderr=errfh,
                preexec_fn=self._pdeathsig)
            errfh.close()
        except Exception as e:
            self.log.warning(f"v2ray lane: sing-box spawn failed: {e}")
            self._port_set ^= 1
            return
        # wait for ports to bind
        deadline = time.time() + 12
        bound = False
        while time.time() < deadline and not bound:
            try:
                s = socket.create_connection(
                    ("127.0.0.1", new_ports[0]), timeout=1)
                s.close()
                bound = True
            except OSError:
                if proc.poll() is not None:
                    break
                time.sleep(0.3)
        if not bound:
            proc.terminate()
            detail = self._singbox_err_tail(errfile)
            self.log.warning(
                "v2ray lane: new sing-box never bound its ports"
                + (f" ({detail})" if detail else ""))
            self._port_set ^= 1
            return
        # probe the fresh process BEFORE committing (bad-regen rollback)
        nodes_new = {p: ob for p, ob in zip(new_ports, outbounds)}
        saved_nodes = self._nodes
        self._nodes = nodes_new  # _probe_all reads tags from here
        healthy = self._probe_all(new_ports)
        old_proc = self._proc
        if not healthy and old_proc is not None and \
                old_proc.poll() is None and self._healthy:
            # new harvest is all-dead: keep the proven old process serving
            self._nodes = saved_nodes
            try:
                proc.terminate()
                proc.wait(5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            self._port_set ^= 1
            self.log.warning(
                "v2ray lane: regen produced 0 healthy nodes - keeping "
                "previous process (nodes die in waves; next regen soon)")
            return
        # commit
        with self._lock:
            self._proc = proc
            self._proc_ports = new_ports
            self._healthy = healthy
        self.stats["regens"] += 1
        self.stats["nodes_alive"] = len(healthy)
        # retire old process AFTER new is proven (zero-dark-time swap)
        if old_proc is not None:
            time.sleep(1.0)  # grace: in-flight conns drain
            try:
                old_proc.terminate()
                old_proc.wait(5)
            except Exception:
                try:
                    old_proc.kill()
                except Exception:
                    pass
            old_conf = os.path.join(
                self.cfg.v2ray_state_dir(),
                f"singbox_{self._port_set ^ 1}.json")
            try:
                os.unlink(old_conf)
            except OSError:
                pass
        self.log.warning(
            f"v2ray lane UP: {len(healthy)}/{len(new_ports)} nodes alive "
            f"(ports {self._port_base() + 1}-"
            f"{self._port_base() + len(new_ports)}), "
            f"{len(set(h['ip'] for h in healthy.values()))} distinct egress IPs")

    # --------------------------------------------------------- pool feed
    def validated_upstreams(self) -> List[Upstream]:
        with self._lock:
            healthy = dict(self._healthy)
        out = []
        for port, h in healthy.items():
            out.append(Upstream(
                kind="socks5", host="127.0.0.1", port=port,
                egress_ip=h["ip"], latency_ms=h["ms"], validated_at=h["at"],
                source=f"v2ray:{h['proto']}"))
        return out

    # ---------------------------------------------------------- main loop
    def start(self):
        if not self.enabled():
            return
        if not self._resolve_bin():
            return
        threading.Thread(target=self._loop, name="v2ray-lane",
                         daemon=True).start()

    def _loop(self):
        while not self._stop.is_set():
            try:
                now = time.monotonic()
                links = []
                if now - self._last_sub_pull > \
                        self.cfg.v2ray_sub_refresh_seconds or \
                        not self._candidate_links:
                    links = self._pull_subs()
                    if links:
                        self._candidate_links = links
                    self._last_sub_pull = now
                links = links or self._candidate_links

                with self._lock:
                    healthy_n = len(self._healthy)
                need_regen = (
                    healthy_n < self.cfg.v2ray_min_warm or
                    (self._proc is not None and self._proc.poll() is not None))
                if need_regen and links:
                    self._regen(links)
                elif self._proc is not None and self._proc.poll() is None:
                    # re-probe health of live ports (drop dead nodes)
                    with self._lock:
                        ports = list(self._healthy.keys())
                    healthy = self._probe_all(ports)
                    with self._lock:
                        self._healthy = healthy
                    self.stats["nodes_alive"] = len(healthy)
                    if healthy_n and not healthy:
                        self.log.warning(
                            "v2ray lane: all previously-healthy nodes died; "
                            "forcing regen on next tick")
            except Exception as e:
                self.log.warning(f"v2ray lane loop error: {e}")
            self._stop.wait(self.cfg.v2ray_health_seconds)

    def stop(self):
        self._stop.set()
        if self._proc is not None:
            try:
                self._proc.terminate()
                self._proc.wait(5)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._proc = None

    def describe(self) -> str:
        if self.disabled_reason:
            return f"disabled ({self.disabled_reason})"
        if not self.cfg.enable_v2ray:
            return "off"
        with self._lock:
            alive = len(self._healthy)
            ips = len(set(h["ip"] for h in self._healthy.values()))
            total = len(self._nodes)
        return (f"{alive}/{total} nodes alive, {ips} distinct egress IPs "
                f"(checked every {self.cfg.v2ray_health_seconds:.0f}s)")
