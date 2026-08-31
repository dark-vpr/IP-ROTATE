"""Shared request path for BOTH frontends (HTTP CONNECT + SOCKS5):

  * target guards (SSRF / port allowlist)
  * dial-with-failover across the rotation pool
  * the bidirectional byte-pump tunnel with idle + lifetime caps and
    free-tier byte metering

Keeping this in one module is a v2 design fix: v1 had this logic welded
to the HTTP handler; the new SOCKS5 frontend (Burp Suite) must apply
EXACTLY the same guards, failover, metering and reaping semantics.
"""
import ipaddress
import socket
import threading
import time
from typing import List, Optional, Tuple

from . import dialer
from .dialer import Upstream


def is_private_target(host: str) -> bool:
    h = host.strip("[]").lower()
    if h == "localhost" or h.endswith(".localhost") or h.endswith(".internal"):
        return True
    try:
        ip = ipaddress.ip_address(h)
        return ip.is_private or ip.is_loopback or ip.is_link_local or \
            ip.is_reserved or ip.is_multicast or ip.is_unspecified
    except ValueError:
        return False


def target_allowed(cfg, host: str, port: int) -> Tuple[bool, str]:
    """Frontend-agnostic guard. Returns (ok, refusal_reason)."""
    if not host or not (1 <= port <= 65535):
        return False, "bad target"
    if not cfg.allow_private_targets and is_private_target(host):
        return False, "private/loopback targets blocked (SSRF guard)"
    if cfg.allowed_connect_ports and port not in cfg.allowed_connect_ports:
        return False, (f"port {port} not in allowed CONNECT ports "
                       f"{cfg.allowed_connect_ports}")
    return True, ""


def dial_with_failover(mgr, cfg, log, host: str, port: int):
    """Try the active/sticky upstream, then fail over across fresh standbys.

    v2.1 survival window: when an entire chain (max_retries+1 upstreams)
    fails, we do NOT 502 immediately — we hold the request up to
    cfg.starvation_wait MORE seconds, retrying selection+dial, so emergency
    harvest / WG registration can rescue it ("no request left behind").
    The window starts AFTER the first chain, because the chain itself can
    legally burn 3 x connect_timeout seconds on dead upstreams.

    Returns (upstream, socket, early_bytes) or (None, None, b"").
    """
    tried: List[Upstream] = []
    last_err = ""

    def _try_chain():
        """One full selection+dial chain. Returns (up, sock, early) on hit."""
        nonlocal last_err
        for _attempt in range(cfg.max_retries + 1):
            up = mgr.next_upstream(exclude=tried, host=host)
            if up is None:
                break
            tried.append(up)
            try:
                sock, early = dialer.connect_via(
                    up, host, port, timeout=cfg.connect_timeout)
                mgr.report_success(up)
                return up, sock, early
            except Exception as e:
                last_err = f"{type(e).__name__}: {e}"
                mgr.report_failure(up, last_err)
        return None, None, b""

    up, sock, early = _try_chain()
    if sock is not None:
        return up, sock, early

    deadline = time.monotonic() + max(0.0, cfg.starvation_wait)
    while time.monotonic() < deadline:
        log.warning(f"dial {host}:{port}: all {len(tried)} upstreams failed "
                    f"({last_err}) — survival window: holding request up to "
                    f"{cfg.starvation_wait:.0f}s for a rescue...")
        time.sleep(max(0.2, cfg.starvation_retry_delay))
        mgr.trigger_emergency_harvest("request-survival-window")
        up, sock, early = _try_chain()
        if sock is not None:
            log.warning(f"dial {host}:{port}: RESCUED after "
                        f"{len(tried)} upstream attempts")
            return up, sock, early
    if last_err:
        log.warning(f"dial {host}:{port} exhausted {len(tried)} upstreams "
                    f"({last_err})")
    return None, None, b""


def is_metered(up: Optional[Upstream]) -> bool:
    """Upstreams whose free tier is byte-capped (Webshare / vpn lane)."""
    if up is None:
        return False
    src = up.source or ""
    return src.startswith("webshare") or src.startswith("vpn:")


def tunnel(client: socket.socket, upstream: socket.socket,
           early: bytes = b"", up: Optional[Upstream] = None,
           cfg=None, mgr=None, log=None) -> None:
    """Bidirectional byte pump with idle + lifetime caps.

    Both pumps are bounded, so no thread/FD can leak; the tunnel ends
    when either side closes and the other side drains (or times out).
    Bytes are metered (in batches) for capped free-tier upstreams.
    """
    deadline = time.monotonic() + cfg.max_tunnel_lifetime
    idle = cfg.idle_timeout
    metered = is_metered(up)
    count = [0]
    count_lock = threading.Lock()
    t0 = time.monotonic()
    flowed = {"fwd": 0, "back": 0}   # zombie-tunnel detection (B36)

    def _meter(n: int) -> None:
        if not metered or n <= 0:
            return
        with count_lock:
            count[0] += n
            if count[0] < 256 * 1024:
                return
            n = count[0]
            count[0] = 0
        try:
            mgr.report_bytes(up, n)
        except Exception:
            pass

    def pump(src, dst, first: bytes = b"", direction: str = "") -> None:
        try:
            if first:
                dst.sendall(first)
                _meter(len(first))
                if direction:
                    flowed[direction] += len(first)
            src.settimeout(idle)
            while time.monotonic() < deadline:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
                _meter(len(data))
                if direction:
                    flowed[direction] += len(data)
        except (OSError, TimeoutError):
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    done = threading.Event()

    def _wrap(target, *args):
        try:
            target(*args)
        finally:
            done.set()

    t1 = threading.Thread(target=_wrap, args=(pump, client, upstream),
                          daemon=True)
    t2 = threading.Thread(target=_wrap,
                          args=(pump, upstream, client, early, "back"),
                          daemon=True)
    # NOTE: client->upstream direction is counted where the CONNECT handler
    # already relayed early bytes; here we count upstream->client so a dead
    # upstream (nothing ever comes back) is detectable.
    t1.start()
    t2.start()
    # First direction finished -> give the other a bounded drain grace
    # before force-closing (prevents a silent peer holding a thread for
    # the full idle timeout; no tunnel thread outlives close + grace).
    done.wait()
    grace = 10.0
    t1.join(timeout=grace)
    t2.join(timeout=grace)
    if metered:
        with count_lock:
            left = count[0]
            count[0] = 0
        if left > 0:
            try:
                mgr.report_bytes(up, left)
            except Exception:
                pass
    # B36 — zombie-tunnel feedback: the upstream accepted the tunnel but
    # almost nothing ever came back and the client gave up fast. That is the
    # signature of a freshly-dead (or silently MITM-ing) proxy: the CONNECT
    # succeeded so the failover chain never fired — only the CLIENT noticed.
    # Strike it (N strikes -> blacklist, same as any failure).
    if mgr is not None and up is not None and up.kind in \
            ("http", "socks4", "socks5"):
        elapsed = time.monotonic() - t0
        if flowed["back"] < 512 and elapsed < 10.0:
            try:
                mgr.report_failure(
                    up, f"zombie tunnel ({flowed['back']}B back in "
                        f"{elapsed:.1f}s)")
            except Exception:
                pass
    for s in (client, upstream):
        try:
            s.close()
        except OSError:
            pass
