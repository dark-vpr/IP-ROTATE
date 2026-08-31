"""Upstream dialing: HTTP CONNECT (raw), SOCKS4/4a/5 via python-socks, direct(+DoH).

Security properties:
  * Hostnames are ALWAYS sent to the upstream for remote resolution
    (the socks5h principle; python-socks is configured with rdns=True)
    — the local machine never leaks DNS for targets.
  * The only exception is the 'direct' backbone, which resolves via
    DNS-over-HTTPS (1.1.1.1) to avoid the local resolver entirely.
  * SOCKS5 username/password auth (RFC 1929, python-socks) and HTTP
    CONNECT Proxy-Authorization (Basic) are supported for credentialled
    upstreams (Webshare free plan).
  * End-to-end egress-IP probing goes through httpx with strict
    certificate verification — a proxy that MITMs the check fails.

v2 bug fixes over v1 (see README "Bug log"):
  * HTTP CONNECT: if the upstream closes mid-headers (before CRLFCRLF)
    we now FAIL instead of treating a partial 200 as success (v1 could
    push remaining header bytes into the tunnel stream = corruption).
  * SOCKS client replaced by python-socks: correct handling of split
    handshakes, 0xFF method refusal, IPv6 ATYP, over-long credentials.
"""
import dataclasses
import re
import socket
import ssl
import struct
import time
import base64
from typing import Optional, Tuple
from urllib.parse import quote

from python_socks import ProxyConnectionError, ProxyError, ProxyTimeoutError, ProxyType
from python_socks.sync import Proxy

from .httpkit import doh_resolve, http_client

_IP_RE = re.compile(r"^\s*((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{2,45})\s*$")


@dataclasses.dataclass
class Upstream:
    kind: str            # http | socks5 | socks4 | warp | direct | psiphon
    host: str
    port: int
    egress_ip: str = ""
    latency_ms: int = 0
    validated_at: float = 0.0
    source: str = ""
    username: str = ""   # optional: RFC 1929 / Proxy-Authorization
    password: str = ""

    @property
    def label(self) -> str:
        return f"{self.kind}://{self.host}:{self.port}"


# ---------------------------------------------------------------------------
# low-level socket helpers
# ---------------------------------------------------------------------------
def _recv_until(sock, marker: bytes, limit: int = 8192) -> bytes:
    buf = b""
    while marker not in buf and len(buf) < limit:
        chunk = sock.recv(1024)
        if not chunk:
            break
        buf += chunk
    return buf


def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("upstream closed early")
        buf += chunk
    return buf


# ---------------------------------------------------------------------------
# HTTP CONNECT proxy (raw socket; kept hand-rolled because no maintained
# library returns the raw tunnel socket, which our relay pump needs)
# ---------------------------------------------------------------------------
def _http_connect(sock, host: str, port: int,
                  username: str = "", password: str = "") -> bytes:
    auth = ""
    if username:
        tok = base64.b64encode(
            f"{username}:{password or ''}".encode()).decode()
        auth = f"Proxy-Authorization: Basic {tok}\r\n"
    req = (f"CONNECT {host}:{port} HTTP/1.1\r\n"
           f"Host: {host}:{port}\r\n"
           f"User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36\r\n"
           f"{auth}"
           f"Proxy-Connection: keep-alive\r\n\r\n").encode()
    sock.sendall(req)
    buf = _recv_until(sock, b"\r\n\r\n")
    if b"\r\n\r\n" not in buf:
        # v1 BUG (fixed): upstream closed / stalled before finishing the
        # response HEADERS. A partial "HTTP/1.1 200" without the blank
        # line is NOT a usable tunnel - remaining header bytes would be
        # injected into the tunnel stream.
        raise OSError("HTTP proxy closed without full CONNECT response")
    head, _, early = buf.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0]
    parts = status_line.split(None, 2)
    if len(parts) < 2 or not parts[1].startswith(b"2"):
        raise OSError(f"CONNECT failed: {status_line[:60].decode('utf-8', 'replace')!r}")
    return early  # bytes already pushed by the proxy belong to the tunnel


# ---------------------------------------------------------------------------
# Unified dialer
# ---------------------------------------------------------------------------
_SOCKS_KIND = {"socks5": ProxyType.SOCKS5, "socks4": ProxyType.SOCKS4,
               "warp": ProxyType.SOCKS5, "psiphon": ProxyType.SOCKS5}


def connect_via(up: Upstream, host: str, port: int,
                timeout: float = 8.0) -> Tuple[socket.socket, bytes]:
    """Open a raw tunnel to host:port THROUGH `up`.

    Returns (raw_socket, early_bytes) — early_bytes must be delivered to
    the client before any further proxy traffic (HTTP CONNECT edge case).
    Raises OSError/ProxyError on any failure.
    """
    if up.kind == "direct":
        ip = doh_resolve(host)
        s = socket.create_connection((ip, port), timeout=timeout)
        return s, b""

    if up.kind == "http":
        s = socket.create_connection((up.host, up.port), timeout=timeout)
        try:
            s.settimeout(timeout)
            early = _http_connect(s, host, port,
                                  username=up.username, password=up.password)
            return s, early
        except Exception:
            try:
                s.close()
            except OSError:
                pass
            raise

    ptype = _SOCKS_KIND.get(up.kind)
    if ptype is None:
        raise OSError(f"unknown upstream kind {up.kind}")
    # SOCKS4 + rdns=True == SOCKS4a (domain passed to the proxy)
    proxy = Proxy(proxy_type=ptype, host=up.host, port=up.port,
                  username=up.username or None,
                  password=up.password or None,
                  rdns=True)
    try:
        sock = proxy.connect(dest_host=host, dest_port=port, timeout=timeout)
        return sock, b""
    except ProxyError as e:
        # preserve the v1 contract: dial failures surface as OSError so
        # every caller (relay failover, tests) keeps one exception type
        raise OSError(f"socks dial via {up.label} failed: {e}") from e


def proxy_url(up: Upstream) -> str:
    """httpx-compatible proxy URL for an upstream (http/socks5 kinds)."""
    scheme = {"http": "http", "https": "http", "socks5": "socks5",
              "warp": "socks5", "psiphon": "socks5"}.get(up.kind)
    if scheme is None:
        raise ValueError(f"no httpx proxy scheme for kind {up.kind}")
    host = f"[{up.host}]" if ":" in up.host else up.host
    auth = ""
    if up.username:
        auth = (f"{quote(up.username, safe='')}:"
                f"{quote(up.password or '', safe='')}@")
    return f"{scheme}://{auth}{host}:{up.port}"


# ---------------------------------------------------------------------------
# TLS-verification-failure detection (MITM signature through httpx)
# ---------------------------------------------------------------------------
def is_tls_verification_error(exc: BaseException) -> bool:
    """True if the exception chain contains a certificate VERIFICATION
    failure (as opposed to a reset/timeout). Used to force-blacklist
    MITM'ing upstreams immediately."""
    seen = 0
    e: BaseException = exc
    while e is not None and seen < 8:
        if isinstance(e, ssl.SSLCertVerificationError):
            return True
        e = e.__cause__ or e.__context__
        seen += 1
    return False


# ---------------------------------------------------------------------------
# End-to-end egress-IP probe (validator + backbone providers)
# ---------------------------------------------------------------------------
def _parse_ip_body(text: str, check_host: str) -> str:
    text = text.strip()
    if check_host == "www.cloudflare.com":  # cdn-cgi/trace format
        for line in text.splitlines():
            if line.startswith("ip="):
                text = line[3:].strip()
                break
    m = _IP_RE.match(text)
    if not m:
        raise OSError(f"ip-check returned non-IP body {text[:40]!r}")
    return m.group(1)


def fetch_egress_ip(up: Upstream, check_host: str = "checkip.amazonaws.com",
                    timeout: float = 6.0, path: str = "/") -> Tuple[str, int]:
    """Fully verify an upstream: dial + TLS (cert-verified by httpx) + HTTP GET.

    Returns (egress_ip, latency_ms). Raises on ANY failure, including
    certificate errors (= MITM signature) and non-IP bodies (= injected junk).
    """
    t0 = time.monotonic()
    url = f"https://{check_host}{path}"
    if up.kind == "socks4":
        # httpx has no socks4 scheme -> raw path (tunnel + TLS + minimal GET)
        return _fetch_egress_ip_raw(up, check_host, timeout, path, t0)
    if up.kind == "direct":
        r = http_client().get(url, timeout=timeout,
                              headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code != 200:
            raise OSError(f"ip-check status {r.status_code}")
        return _parse_ip_body(r.text, check_host), \
            int((time.monotonic() - t0) * 1000)
    # proxied path: throwaway client bound to this upstream
    import httpx as _httpx
    with _httpx.Client(proxy=proxy_url(up),
                       timeout=timeout, verify=True, trust_env=False,
                       headers={"User-Agent": "Mozilla/5.0"}) as c:
        r = c.get(url)
        if r.status_code != 200:
            raise OSError(f"ip-check status {r.status_code}")
        return _parse_ip_body(r.text, check_host), \
            int((time.monotonic() - t0) * 1000)


def _fetch_egress_ip_raw(up: Upstream, check_host: str, timeout: float,
                         path: str, t0: float) -> Tuple[str, int]:
    sock, _ = connect_via(up, check_host, 443, timeout=timeout)
    try:
        sock.settimeout(timeout)
        ctx = ssl.create_default_context()
        tls = ctx.wrap_socket(sock, server_hostname=check_host)
        try:
            tls.sendall((f"GET {path} HTTP/1.1\r\nHost: {check_host}\r\n"
                         f"User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
                         ).encode())
            buf = b""
            while len(buf) < 8192:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                buf += chunk
        finally:
            tls.close()
        head, _, body = buf.partition(b"\r\n\r\n")
        status = head.split(b"\r\n", 1)[0]
        if b" 200" not in status:
            raise OSError(f"ip-check status {status[:40]!r}")
        return _parse_ip_body(body.decode("utf-8", "replace"), check_host), \
            int((time.monotonic() - t0) * 1000)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def looks_like_ip(text: str) -> bool:
    return bool(_IP_RE.match(text))
