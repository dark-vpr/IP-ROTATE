"""SOCKS5 frontend (RFC 1928 + RFC 1929) — the Burp Suite entry point.

Burp Suite (2020.x and later, including 2024/2025/2026 builds) supports
routing ALL of its traffic through a SOCKS proxy:
    Settings -> Network -> Connections -> SOCKS proxy
    (set "Do DNS lookups through the proxy" = ON for socks5h semantics)

Design notes / bug-proofing:
  * No-auth by default — Burp's SOCKS implementation offers method 0x00
    only, so when no credentials are configured the server advertises
    JUST 0x00 (advertising 0x02 too would make some clients pick auth).
  * Optional RFC 1929 username/password auth (curl-compatible) for when
    the listener is exposed beyond loopback.
  * CONNECT is the only supported command; BIND/UDP get REP 0x07.
  * ATYP 0x01 (IPv4), 0x03 (domain — what Burp sends when DNS-through-
    proxy is enabled), and 0x04 (IPv6) are all parsed; domains are
    forwarded to the upstream for REMOTE resolution (socks5h principle).
  * The success reply reports the actual egress IP in BND.ADDR — handy
    for debugging (visible in curl -v / Burp's event log).
  * Malformed handshakes, oversized fields and slowloris-style stalls are
    cut off by a handshake timeout + strict length checks.
"""
import hmac
import socket
import struct
import threading
from socketserver import BaseRequestHandler, ThreadingTCPServer
from typing import Optional

from . import relay
from .relay import target_allowed
from .server import bind_with_retry

# RFC 1928 reply codes
REP_SUCCESS = 0x00
REP_GENERAL_FAILURE = 0x01
REP_NOT_ALLOWED = 0x02
REP_CMD_NOT_SUPPORTED = 0x07
REP_ATYP_NOT_SUPPORTED = 0x08


class Socks5Server(ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, manager, cfg, log):
        self.manager = manager
        self.cfg = cfg
        self.log = log
        self.tunnels = 0
        self._tunnel_lock = threading.Lock()
        super().__init__(addr, _Socks5Handler)

    def tunnel_enter(self) -> bool:
        with self._tunnel_lock:
            if self.tunnels >= self.cfg.max_tunnels:
                return False
            self.tunnels += 1
            return True

    def tunnel_exit(self) -> None:
        with self._tunnel_lock:
            self.tunnels -= 1

    def active_tunnels(self) -> int:
        with self._tunnel_lock:
            return self.tunnels


def _recv_exact(conn, n: int, what: str) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise OSError(f"client closed during {what}")
        buf += chunk
    return buf


class _Socks5Handler(BaseRequestHandler):
    server: Socks5Server

    def setup(self):
        self.request.settimeout(self.server.cfg.socks_handshake_timeout)

    # ---------------------------------------------------------------- reply
    def _reply(self, rep: int, bnd_ip: str = "0.0.0.0", bnd_port: int = 0):
        try:
            addr = socket.inet_aton(bnd_ip)
        except OSError:
            addr = socket.inet_aton("0.0.0.0")
        self.request.sendall(b"\x05" + bytes([rep]) + b"\x00\x01" +
                             addr + struct.pack(">H", bnd_port))

    # ------------------------------------------------------------- handlers
    def handle(self):
        conn = self.request
        cfg = self.server.cfg
        try:
            # ---- 1) method negotiation -------------------------------
            hdr = _recv_exact(conn, 2, "greeting")
            ver, nmethods = hdr[0], hdr[1]
            if ver != 5 or nmethods == 0:
                try:
                    conn.sendall(b"\x05\xff")
                except OSError:
                    pass
                return
            methods = _recv_exact(conn, nmethods, "methods")
            need_auth = bool(cfg.socks_username)
            if need_auth:
                if 0x02 not in methods:
                    conn.sendall(b"\x05\xff")   # no acceptable methods
                    return
                conn.sendall(b"\x05\x02")
                # ---- RFC 1929 username/password subnegotiation ----
                v = _recv_exact(conn, 1, "auth version")
                if v[0] != 0x01:
                    conn.sendall(b"\x01\x01")
                    return
                ulen = _recv_exact(conn, 1, "user length")[0]
                user = _recv_exact(conn, ulen, "username")
                plen = _recv_exact(conn, 1, "pass length")[0]
                pwd = _recv_exact(conn, plen, "password")
                ok = hmac.compare_digest(
                    user, cfg.socks_username.encode()) and \
                    hmac.compare_digest(pwd, cfg.socks_password.encode())
                if not ok:
                    conn.sendall(b"\x01\x01")
                    self.server.log.warning(
                        "socks5: AUTH FAILURE from %s",
                        self.client_address[0])
                    return
                conn.sendall(b"\x01\x00")
            else:
                if 0x00 not in methods:
                    conn.sendall(b"\x05\xff")
                    return
                conn.sendall(b"\x05\x00")

            # ---- 2) request -------------------------------------------
            head = _recv_exact(conn, 4, "request head")
            if head[0] != 5:
                return
            cmd, atyp = head[1], head[3]
            if atyp == 0x01:                      # IPv4
                raw = _recv_exact(conn, 4, "dst addr")
                host = socket.inet_ntoa(raw)
            elif atyp == 0x03:                    # domain (Burp DNS-through-proxy)
                ln = _recv_exact(conn, 1, "domain length")[0]
                if ln == 0:
                    self._reply(REP_GENERAL_FAILURE)
                    return
                host = _recv_exact(conn, ln, "domain").decode(
                    "utf-8", "replace")
            elif atyp == 0x04:                    # IPv6
                raw = _recv_exact(conn, 16, "dst addr6")
                host = socket.inet_ntop(socket.AF_INET6, raw)
            else:
                self._reply(REP_ATYP_NOT_SUPPORTED)
                return
            port = struct.unpack(">H", _recv_exact(conn, 2, "dst port"))[0]

            if cmd != 0x01:                       # only CONNECT
                self._reply(REP_CMD_NOT_SUPPORTED)
                return

            ok, why = target_allowed(cfg, host, port)
            if not ok:
                self.server.log.warning(f"socks5: refused {host}:{port} - {why}")
                self._reply(REP_NOT_ALLOWED)
                return

            if not self.server.tunnel_enter():
                self._reply(REP_GENERAL_FAILURE)
                return
            try:
                up, sock, early = relay.dial_with_failover(
                    self.server.manager, cfg, self.server.log, host, port)
                if sock is None:
                    self._reply(REP_GENERAL_FAILURE)
                    return
                # report the egress IP we actually picked (observability)
                bnd = up.egress_ip if _is_ipv4(up.egress_ip) else "0.0.0.0"
                self._reply(REP_SUCCESS, bnd_ip=bnd)
                self.request.settimeout(None)     # tunnel pump sets its own
                self.server.log.info(
                    f"socks5 CONNECT {host}:{port} via {up.label} "
                    f"(egress {up.egress_ip})")
                relay.tunnel(conn, sock, early=early, up=up, cfg=cfg,
                             mgr=self.server.manager,
                             log=self.server.log)
            finally:
                self.server.tunnel_exit()
        except (OSError, TimeoutError):
            pass  # client hung up / stalled handshake — just drop it
        except Exception as e:                    # never kill the server thread
            try:
                self.server.log.debug(f"socks5 handler error: {e}")
            except Exception:
                pass


def _is_ipv4(text: str) -> bool:
    try:
        socket.inet_aton(text)
        return text.count(".") == 3
    except OSError:
        return False


def serve_socks(cfg, manager, log,
                ready_event: Optional[threading.Event] = None,
                srv_out: Optional[list] = None):
    """Run the SOCKS5 frontend. Returns the server (or raises OSError).

    srv_out: optional list; the bound server is appended right after bind so
    the caller can shutdown() it on exit (B34).
    """
    if not cfg.socks_listen_host:
        # explicit disable
        if ready_event is not None:
            ready_event.set()
        return None
    srv = bind_with_retry(
        lambda: Socks5Server((cfg.socks_listen_host, cfg.socks_listen_port),
                             manager, cfg, log),
        log, "socks5 frontend")
    if srv_out is not None:
        srv_out.append(srv)
    host, port = srv.server_address[:2]
    auth = "user/pass" if cfg.socks_username else "no-auth"
    log.warning(f"local SOCKS5 frontend LISTENING on {host}:{port} "
                f"[{auth}] — point Burp Suite here")
    if host not in ("127.0.0.1", "localhost", "::1") and not cfg.socks_username:
        log.warning("  !! SOCKS listener is NOT loopback and has NO auth — "
                    "anyone on the network can use your proxy. Set "
                    "socks_username/socks_password.")
    if ready_event is not None:
        ready_event.set()
    try:
        srv.serve_forever(poll_interval=0.25)
    finally:
        srv.server_close()
    return srv
