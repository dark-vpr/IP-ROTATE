"""Local HTTP proxy front-end (curl -x style).

Your crawler configures ONE proxy:  http://127.0.0.1:8000
  * HTTPS  -> handled via CONNECT tunneling (default, safe)
  * plain HTTP -> refused by default (MITM risk through untrusted proxies),
                  enable with --allow-http

The SOCKS5 frontend (socks_server.py) shares the exact same request path
(relay.py): guards, per-request failover, metering, tunnel reaping.

Robustness: per-request upstream failover + retry, graceful drain
(in-flight tunnels survive rotation), idle & lifetime caps per tunnel,
tunnel-count cap (FD exhaustion guard), SSRF guard, X-Rotator-*
observability headers on CONNECT responses.
"""
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import urlsplit

from . import relay
from .dialer import Upstream

_HOP_HEADERS = {"connection", "keep-alive", "proxy-connection",
                "proxy-authorization", "proxy-authenticate", "te",
                "trailer", "transfer-encoding", "upgrade", "expect"}

BIND_RETRY_SECONDS = 12.0


def bind_with_retry(make_server, log, what: str):
    """v2.1 fix: an immediately-restarting gateway used to crash with
    'Address already in use' because the OS hadn't released the port yet
    (or the old process was still draining). Retry the bind for up to
    BIND_RETRY_SECONDS with backoff instead of dying."""
    last_err = None
    deadline = time.monotonic() + BIND_RETRY_SECONDS
    while True:
        try:
            return make_server()
        except OSError as e:
            last_err = e
            if time.monotonic() >= deadline or \
                    getattr(e, "errno", None) != 98:  # EADDRINUSE
                raise
            log.warning(f"{what}: port busy ({e}) — retrying bind "
                        f"for up to {BIND_RETRY_SECONDS:.0f}s (old process "
                        f"still draining?)")
            time.sleep(0.5)


class RotatingProxyServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, manager, cfg, log):
        self.manager = manager
        self.cfg = cfg
        self.log = log
        self.tunnels = 0
        self._tunnel_lock = threading.Lock()
        super().__init__(addr, _Handler)

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


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: RotatingProxyServer

    # ------------------------------------------------------------------ util
    def log_message(self, fmt, *args):  # route stdlib logs to DEBUG
        self.server.log.debug("http: " + (fmt % args))

    def _deny(self, code: int, msg: str) -> None:
        body = (f'{{"error": "{msg}"}}').encode()
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            pass
        self.close_connection = True

    def _egress_headers(self, up: Upstream) -> bytes:
        secs = self.server.manager.seconds_to_next_rotation()
        return (f"X-Rotator-Egress: {up.egress_ip}\r\n"
                f"X-Rotator-Upstream: {up.label}\r\n"
                f"X-Rotator-Provider: {up.source or up.kind}\r\n"
                f"X-Rotator-Next-Rotation-In: {secs:.1f}\r\n").encode()

    # ---------------------------------------------------------------- CONNECT
    def do_CONNECT(self):
        cfg = self.server.cfg

        host, _, port_s = self.path.partition(":")
        try:
            port = int(port_s)
        except ValueError:
            return self._deny(400, "bad CONNECT target")

        ok, why = relay.target_allowed(cfg, host, port)
        if not ok:
            return self._deny(403, why)

        if not self.server.tunnel_enter():
            return self._deny(503, "tunnel limit reached (max_tunnels); "
                                   "raise --max-tunnels or slow down")

        try:
            up, sock, early = relay.dial_with_failover(
                self.server.manager, cfg, self.server.log, host, port)
            if sock is None:
                self._deny(502, "all upstreams failed for this request "
                                "(pool may be starved; check logs)")
                return
            # 200 to client + observability headers; then pure byte tunnel.
            # `early` (rare bytes pushed by the upstream proxy right after
            # its CONNECT 200) belong to the tunnel stream -> relayed first
            # by the upstream->client pump, AFTER our header. Correct order.
            head = (b"HTTP/1.1 200 Connection established\r\n"
                    + self._egress_headers(up)
                    + b"\r\n")
            try:
                self.connection.sendall(head)
            except OSError:
                return  # client gave up; tunnel threads not started yet
            self.close_connection = True
            relay.tunnel(self.connection, sock, early=early, up=up, cfg=cfg,
                         mgr=self.server.manager, log=self.server.log)
        finally:
            self.server.tunnel_exit()

    # ------------------------------------------------------- plain HTTP relay
    def _relay_plain(self):
        cfg = self.server.cfg
        if not cfg.allow_plain_http:
            return self._deny(
                403, "plain HTTP disabled: untrusted free proxies can rewrite "
                     "it (MITM). Use https:// targets, or pass --allow-http "
                     "if you accept the risk.")
        # parse absolute URI
        try:
            parts = urlsplit(self.path)
            host, port = parts.hostname, parts.port or 80
        except ValueError:
            return self._deny(400, "bad absolute-URI request")
        if not host:
            return self._deny(400, "proxy-style request expected")

        ok, why = relay.target_allowed(cfg, host, port)
        if not ok:
            return self._deny(403, why)

        body = b""
        length = self.headers.get("Content-Length")
        if length and length.isdigit():
            body = self.rfile.read(int(length))
            if len(body) != int(length):
                return self._deny(400, "short request body")
        elif self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            return self._deny(501, "chunked request bodies unsupported")

        up, sock, _early = relay.dial_with_failover(
            self.server.manager, cfg, self.server.log, host, port)
        if sock is None:
            return self._deny(502, "all upstreams failed for this request")
        try:
            # rebuild request in proxy form
            req_line = f"{self.command} {self.path} {self.request_version}"
            headers = [req_line]
            for k, v in self.headers.items():
                if k.lower() in _HOP_HEADERS:
                    continue
                headers.append(f"{k}: {v}")
            headers.append("Connection: close")
            payload = ("\r\n".join(headers) + "\r\n\r\n").encode() + body
            sock.settimeout(cfg.idle_timeout)
            sock.sendall(payload)
            deadline = time.monotonic() + cfg.max_tunnel_lifetime
            while time.monotonic() < deadline:
                data = sock.recv(65536)
                if not data:
                    break
                self.connection.sendall(data)
        except OSError as e:
            self.server.log.warning(f"plain relay error: {e}")
        finally:
            try:
                sock.close()
            except OSError:
                pass
        self.close_connection = True

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = \
        do_OPTIONS = _relay_plain


def serve(cfg, manager, log, ready_event: Optional[threading.Event] = None,
          srv_out: Optional[list] = None):
    """Run the HTTP frontend forever (blocking).

    srv_out: optional list; the bound server object is appended right after
    bind so the caller can shutdown() it on exit (B34: without this the
    listener kept accepting into a torn-down process).
    """
    def _mk():
        return RotatingProxyServer((cfg.listen_host, cfg.listen_port),
                                   manager, cfg, log)
    srv = bind_with_retry(_mk, log, "http frontend")
    if srv_out is not None:
        srv_out.append(srv)
    host, port = srv.server_address[:2]
    log.warning(f"local rotating proxy LISTENING on http://{host}:{port}")
    log.warning(f"rotation interval: {cfg.interval}s | policy: "
                f"{cfg.policy_on_exhaustion} | plain HTTP: "
                f"{'ALLOWED (risk!)' if cfg.allow_plain_http else 'blocked'}")
    if ready_event is not None:
        ready_event.set()
    try:
        srv.serve_forever(poll_interval=0.25)
    finally:
        srv.server_close()
    return srv
