"""CLI: serve | vpn | fetch | api-status | doctor | test | harvest

v2 highlights:
  * `serve` starts BOTH front-ends: HTTP CONNECT (default 127.0.0.1:8000)
    and SOCKS5 (default 127.0.0.1:1080, Burp-compatible no-auth) unless
    --no-socks. --socks-auth user:pass enables RFC 1929 auth for curl.
  * `test` verifies rotation through BOTH front-ends end-to-end.
  * `doctor` also checks the runtime dependencies (httpx / python-socks /
    rich), the SOCKS front-end config and every free lane.
"""
import argparse
import json
import os
import shutil
import signal
import socket
import sys
import threading
import time
from typing import Optional

from . import __version__
from .apiproviders import FetchLane, WebshareClient
from .config import Config
from .dialer import Upstream, fetch_egress_ip
from .log import get_logger
from .pool import PoolManager, parse_static_proxy
from .providers import (VPN_CLI_RECIPES, VpnCliProvider, VpnGateProvider,
                        VpnPoolManager)
from .server import serve
from .state import StateDB
from .v2raylane import V2RayLane
from .warpwire import (WarpPlusLane, WireGuardLane, register_warp_account,
                       wireproxy_conf)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ip-rotator",
        description="Free & freemium (no card) self-healing IP-rotation "
                    "gateway. HTTP CONNECT + SOCKS5 front-ends; point your "
                    "crawler at http://127.0.0.1:8000 (curl -x) or "
                    "127.0.0.1:1080 (Burp SOCKS) and get a "
                    "never-before-used egress IP every N seconds.")
    p.add_argument("--version", action="version",
                   version=f"ip-rotator {__version__}")
    sub = p.add_subparsers(dest="cmd")

    # ------------------------------------------------------------- serve
    s = sub.add_parser("serve", help="run the rotation gateway (default)")
    s.add_argument("--listen", default=None,
                   help="HTTP frontend host:port (default 127.0.0.1:8000)")
    s.add_argument("--socks-listen", default=None,
                   help="SOCKS5 frontend host:port (default 127.0.0.1:1080); "
                        "use this for Burp Suite")
    s.add_argument("--no-socks", action="store_true",
                   help="disable the SOCKS5 frontend")
    s.add_argument("--socks-auth", default=None, metavar="USER:PASS",
                   help="require RFC 1929 user/password auth on the SOCKS5 "
                        "frontend (curl-compatible; Burp does no auth)")
    s.add_argument("--interval", type=float, default=None,
                   help="seconds per fresh IP (default 10)")
    s.add_argument("--rotate-every-request", action="store_true",
                   help="pick a fresh upstream for every connection")
    s.add_argument("--min-pool", type=int, default=None)
    s.add_argument("--retries", type=int, default=None,
                   help="extra failover attempts per request (default 2)")
    s.add_argument("--policy", choices=["recycle", "strict", "backbone"],
                   default=None, help="what to do when no unseen IPs remain")
    s.add_argument("--allow-http", action="store_true",
                   help="allow plain-HTTP relaying (MITM risk through "
                        "untrusted proxies!)")
    s.add_argument("--allow-direct", action="store_true",
                   help="last-resort fallback to your REAL IP (flagged loudly)")
    s.add_argument("--allow-private", action="store_true",
                   help="allow CONNECT to private/loopback targets (SSRF)")
    s.add_argument("--warp-accounts", type=int, default=None, metavar="N",
                   help="keep N free WARP accounts warm as WireGuard tunnels "
                        "(clean Cloudflare egress, no card, no root; "
                        "recommend 3-6; 0=off)")
    s.add_argument("--wireproxy", default=None, metavar="PATH",
                   help="path to the wireproxy binary (default: config "
                        "value / PATH lookup)")
    s.add_argument("--wg-dir", default=None, metavar="DIR",
                   help="directory with your own wg-quick *.conf files "
                        "(Proton/Windscribe/PrivadoVPN free configs) — each "
                        "becomes another warm tunnel lane")
    s.add_argument("--sticky", action="store_true",
                   help="per-host sticky sessions: same host keeps its IP for "
                        "60s (sticky_ttl) while other hosts rotate — helps "
                        "WAF/session-heavy crawls; default OFF so every "
                        "window rotates")
    s.add_argument("--no-sticky", action="store_true",
                   help="(deprecated alias) disable sticky sessions")
    s.add_argument("--no-reuse-minutes", type=float, default=None,
                   metavar="MIN",
                   help="NO-REUSE WINDOW: once an egress IP is used it is "
                        "burned for this many minutes before it can be "
                        "picked again (default 45; your 30-60 min ask). "
                        "0 = old behavior ( IPs never reused while new "
                        "ones exist)")
    s.add_argument("--v2ray", action="store_true",
                   help="enable the free-node v2ray lane: thousands of "
                        "community nodes (vless/vmess/trojan/ss) via one "
                        "sing-box process — TCP protocols work even where "
                        "UDP is blocked; auto-downloads sing-box if missing")
    s.add_argument("--v2ray-subs", default=None, metavar="URL,URL",
                   help="comma-separated subscription URLs for the v2ray "
                        "lane (default: two maintained aggregators)")
    s.add_argument("--v2ray-nodes", type=int, default=None, metavar="N",
                   help="max warm nodes in the lane (default 240)")
    s.add_argument("--warpplus", type=int, default=None, metavar="N",
                   help="enable the warp-plus lane with N instances "
                        "(multi-country WARP egress via bepass-org/warp-plus; "
                        "AUTOMATIC country rotation mints fresh IPs on "
                        "demand; needs UDP egress; auto-downloads if missing)")
    s.add_argument("--warpplus-mode", default=None,
                   choices=["auto", "cfon", "gool", "plain"],
                   help="warp-plus mode: cfon=Psiphon country egress, "
                        "gool=warp-in-warp, plain=raw WARP, auto=mix "
                        "(default auto)")
    s.add_argument("--warpplus-bin", default=None, metavar="PATH",
                   help="path to the warp-plus binary (default: PATH / "
                        "tools dir / auto-download)")
    s.add_argument("--singbox-bin", default=None, metavar="PATH",
                   help="path to the sing-box binary (default: PATH / "
                        "tools dir / auto-download)")
    s.add_argument("--country", default=None,
                   help="comma ISO codes, e.g. US,DE (slower: geo lookups)")
    s.add_argument("--max-latency", type=int, default=None,
                   help="reject upstreams slower than this ms (default 6000)")
    s.add_argument("--workers", type=int, default=None,
                   help="validation worker threads (default 64)")
    s.add_argument("--state-path", default=None,
                   help="SQLite state file (default ~/.ip_rotator/state.db)")
    s.add_argument("--fresh-ledger", action="store_true",
                   help="forget the never-reuse ledger for this run")
    s.add_argument("--stats-file", default=None,
                   help="write JSON stats here on every rotation")
    s.add_argument("--config", default=None, help="JSON config file")
    s.add_argument("--quiet", action="store_true")

    # ------------------------------------------------------------- warp
    w = sub.add_parser(
        "warp", help="manage the free WARP/WireGuard account lane: register "
                     "accounts (no card, no email), test tunnels, print "
                     "status. Accounts are the fuel for the zero-delay "
                     "clean-IP rotation lane")
    w.add_argument("--register", type=int, default=0, metavar="N",
                   help="register N new WARP accounts now")
    w.add_argument("--probe", action="store_true",
                   help="spawn one tunnel per stored account and verify the "
                            "egress IP (proves UDP/WireGuard works on this "
                            "network)")
    w.add_argument("--wireproxy", default=None, metavar="PATH",
                   help="path to the wireproxy binary (default: config "
                        "value / PATH lookup)")
    w.add_argument("--config", default=None)
    w.add_argument("--state-path", default=None)

    # ------------------------------------------------------------ warpplus
    wp = sub.add_parser(
        "warpplus", help="manage the multi-country warp-plus lane "
                         "(bepass-org/warp-plus): N instances = N country-"
                         "diverse WARP SOCKS ports; automatic country "
                         "rotation mints never-seen IPs on demand")
    wp.add_argument("--probe", action="store_true",
                    help="spawn one instance, verify egress + country, then "
                         "exit (also proves UDP/WireGuard egress works here)")
    wp.add_argument("--instances", type=int, default=2,
                    help="instances to probe (default 2)")
    wp.add_argument("--mode", default=None,
                    choices=["auto", "cfon", "gool", "plain"],
                    help="lane mode (default auto: country mix + gool)")
    wp.add_argument("--warpplus-bin", default=None, metavar="PATH")
    wp.add_argument("--config", default=None)
    wp.add_argument("--state-path", default=None)

    # ------------------------------------------------------------- v2ray
    v2 = sub.add_parser(
        "v2ray", help="manage the free-node v2ray lane (community nodes "
                      "via sing-box): probe the live node supply and verify "
                      "egress IPs right now")
    v2.add_argument("--probe", action="store_true",
                    help="pull subscriptions, spawn sing-box with the nodes, "
                         "verify egress IPs through them, then exit")
    v2.add_argument("--nodes", type=int, default=40,
                    help="how many candidate nodes to test (default 40)")
    v2.add_argument("--subs", default=None, metavar="URL,URL",
                    help="subscription URLs (default: two maintained "
                         "aggregators)")
    v2.add_argument("--singbox-bin", default=None, metavar="PATH")
    v2.add_argument("--config", default=None)
    v2.add_argument("--state-path", default=None)

    # ------------------------------------------------------------- doctor
    sub.add_parser("doctor", help="environment & source health check")

    # ------------------------------------------------------------- test
    t = sub.add_parser("test", help="end-to-end self-test: prove rotation works "
                                    "through BOTH front-ends (HTTP + SOCKS5)")
    t.add_argument("--requests", type=int, default=4,
                   help="number of probe requests (default 4)")
    t.add_argument("--interval", type=float, default=10.0)
    t.add_argument("--timeout", type=float, default=150.0,
                   help="max seconds to wait for pool warmup")

    # ------------------------------------------------------------- harvest
    h = sub.add_parser("harvest", help="one-shot harvest + validate, print pool")
    h.add_argument("--limit", type=int, default=100,
                   help="print top N validated upstreams")
    h.add_argument("--state-path", default=None)
    h.add_argument("--fresh-ledger", action="store_true")

    # ------------------------------------------------------------- vpn
    vpn = sub.add_parser(
        "vpn", help="LOW-FREQUENCY rotation via free VPN CLIs "
        "(Proton/Windscribe/Hide.me; all no-card). Full-tunnel mode: all "
        "machine traffic rides the VPN; reconnect blip 10-30s per rotation; "
        "data caps metered")
    vpn.add_argument("--provider", default="auto",
                     choices=["auto"] + sorted(VPN_CLI_RECIPES),
                     help="which free VPN CLI to use (default: auto-detect)")
    vpn.add_argument("--listen", default=None,
                     help="HTTP frontend host:port (default 127.0.0.1:8000)")
    vpn.add_argument("--socks-listen", default=None,
                     help="SOCKS5 frontend host:port (default 127.0.0.1:1080)")
    vpn.add_argument("--no-socks", action="store_true")
    vpn.add_argument("--socks-auth", default=None, metavar="USER:PASS")
    vpn.add_argument("--interval", type=float, default=60.0,
                     help="seconds per VPN reconnect (default 60; realistic "
                          "floor for full-tunnel CLIs, NOT 10s)")
    vpn.add_argument("--state-path", default=None)
    vpn.add_argument("--config", default=None)
    vpn.add_argument("--quiet", action="store_true")

    # ------------------------------------------------------------- fetch
    f = sub.add_parser(
        "fetch", help="metered last-resort fetch through scraping-API free "
        "tiers (ZenRows 5k/mo, Firecrawl 1k/mo keyless, ScrapingBee 1k, "
        "Crawlbase 1k, ScraperAPI 5k trial — all no-card)")
    f.add_argument("url", help="target URL to fetch")
    f.add_argument("--provider", default="auto",
                   choices=["auto", "zenrows", "firecrawl", "scrapingbee",
                            "crawlbase", "scraperapi"])
    f.add_argument("--max-bytes", type=int, default=200000,
                   help="print at most this many bytes (default 200000)")
    f.add_argument("--config", default=None)
    f.add_argument("--state-path", default=None)

    # ------------------------------------------------------------- api-status
    api = sub.add_parser("api-status",
                         help="show free-tier usage + keys for Webshare and "
                              "the scraping-API fetch lane")
    api.add_argument("--config", default=None, help="JSON config file")
    return p


def _socks_overrides(a) -> dict:
    """Common SOCKS5-frontend overrides from CLI flags."""
    ov = {}
    if getattr(a, "no_socks", False):
        ov["enable_socks"] = False
    if getattr(a, "socks_listen", None):
        hp = a.socks_listen.rsplit(":", 1)
        ov["socks_listen_host"] = hp[0] or "127.0.0.1"
        if len(hp) == 2:
            ov["socks_listen_port"] = int(hp[1])
    if getattr(a, "socks_auth", None):
        user, sep, pwd = a.socks_auth.partition(":")
        if not sep or not user:
            raise SystemExit("--socks-auth expects USER:PASS")
        ov["socks_username"] = user
        ov["socks_password"] = pwd
    return {k: v for k, v in ov.items()}


def _cfg_from_args(a) -> Config:
    # B37 fix: only override the listen host/port when --listen was actually
    # passed. Previously the hardcoded "127.0.0.1":8000 defaults were injected
    # as overrides UNCONDITIONALLY, silently stomping the config FILE values
    # (a config's listen_host: "0.0.0.0" was ignored — fatal in containers,
    # where frontends must bind 0.0.0.0 for rootless port publishing).
    listen_host = listen_port = None
    if getattr(a, "listen", None):
        hp = a.listen.rsplit(":", 1)
        listen_host = hp[0] or "127.0.0.1"
        listen_port = int(hp[1]) if len(hp) == 2 else 8000
    overrides = {
        "listen_host": listen_host, "listen_port": listen_port,
        "interval": getattr(a, "interval", None),
        "rotate_every_request": getattr(a, "rotate_every_request", False) or None,
        "min_pool": getattr(a, "min_pool", None),
        "max_retries": getattr(a, "retries", None),
        "policy_on_exhaustion": getattr(a, "policy", None),
        "allow_plain_http": getattr(a, "allow_http", False) or None,
        "allow_direct": getattr(a, "allow_direct", False) or None,
        "allow_private_targets": getattr(a, "allow_private", False) or None,
        "country_filter": [c.strip().upper() for c in a.country.split(",")]
                          if getattr(a, "country", None) else None,
        "max_latency_ms": getattr(a, "max_latency", None),
        "validation_workers": getattr(a, "workers", None),
        "state_path": getattr(a, "state_path", None),
        "fresh_ledger": getattr(a, "fresh_ledger", False) or None,
        "stats_file": getattr(a, "stats_file", None),
        "warp_accounts": getattr(a, "warp_accounts", None),
        "wg_configs_dir": getattr(a, "wg_dir", None),
        "wireproxy_bin": getattr(a, "wireproxy", None),
        "sticky_sessions": (True if getattr(a, "sticky", False)
                            else False if getattr(a, "no_sticky", False)
                            else None),
        "no_reuse_seconds": (a.no_reuse_minutes * 60.0
                              if getattr(a, "no_reuse_minutes", None)
                              is not None else None),
        "enable_v2ray": True if getattr(a, "v2ray", False) else None,
        "v2ray_subs": ([u.strip() for u in a.v2ray_subs.split(",")
                         if u.strip()]
                        if getattr(a, "v2ray_subs", None) else None),
        "v2ray_max_nodes": getattr(a, "v2ray_nodes", None),
        "enable_warpplus": (True if getattr(a, "warpplus", None)
                            else None),
        "warpplus_instances": getattr(a, "warpplus", None),
        "warpplus_mode": getattr(a, "warpplus_mode", None),
        "warpplus_bin": getattr(a, "warpplus_bin", None),
        "singbox_bin": getattr(a, "singbox_bin", None),
        "log_level": "ERROR" if getattr(a, "quiet", False) else None,
    }
    overrides.update(_socks_overrides(a))
    return Config.load(getattr(a, "config", None), overrides)


def _start_frontends(cfg, mgr, log) -> list:
    """Start HTTP + SOCKS5 front-ends in threads (SOCKS failure degrades).

    Returns the list of bound server objects (may be empty/partial if a
    frontend failed to bind) so shutdown can stop them (B34).
    """
    from . import socks_server

    servers: list = []

    server_thread = threading.Thread(
        target=serve, args=(cfg, mgr, log), kwargs={"srv_out": servers},
        daemon=True)
    server_thread.start()

    if cfg.enable_socks and cfg.socks_listen_host:
        def _socks():
            try:
                socks_server.serve_socks(cfg, mgr, log, srv_out=servers)
            except OSError as e:
                log.error(f"SOCKS5 frontend NOT started ({e}) — HTTP "
                          f"frontend still serving. Is port "
                          f"{cfg.socks_listen_port} taken (e.g. by Psiphon)? "
                          f"Use --socks-listen to change it.")
        threading.Thread(target=_socks, name="socks5", daemon=True).start()
    return servers


def _stop_frontends(servers: list, log) -> None:
    """Stop accepting on every frontend FIRST — frees the ports immediately
    and guarantees no request lands in a half-torn-down process (B33/B34)."""
    for srv in list(servers):
        try:
            srv.shutdown()          # stops the serve_forever() loop
        except Exception:
            pass
        try:
            srv.server_close()      # closes the listening socket (port free)
        except Exception:
            pass


def _arm_exit_watchdog(seconds: float, log) -> dict:
    """B34: guarantee the process ALWAYS exits. A validator thread wedged in
    an un-timeout-able socket read (httpcore SOCKS5 greeting) otherwise
    blocks interpreter shutdown forever -> zombie holds the ports -> the next
    serve hits 'Address already in use'. The watchdog force-exits after a
    grace budget. serve/vpn keep it ARMED through interpreter shutdown (the
    wedge happens after 'bye'); disarm via ['armed']=False only if you are
    sure no non-daemon worker can be mid-network-read."""
    state = {"armed": True}

    def _watch():
        time.sleep(seconds)
        if state["armed"]:
            try:
                log.warning(
                    f"graceful shutdown exceeded {seconds:.0f}s budget — "
                    "forcing exit (a worker was wedged; see docs/08 B34)")
            except Exception:
                pass
            os._exit(0)

    threading.Thread(target=_watch, name="exit-watchdog",
                     daemon=True).start()
    return state


# ===========================================================================
def cmd_serve(a) -> int:
    cfg = _cfg_from_args(a)
    log = get_logger(level={"ERROR": 40, "WARNING": 30, "INFO": 20,
                            "DEBUG": 10}[cfg.log_level])
    if cfg.warp_accounts > 0 and \
            not WireGuardLane.find_wireproxy(cfg.wireproxy_bin):
        log.warning(
            f"warp_accounts={cfg.warp_accounts} but wireproxy binary not "
            f"found at '{cfg.wireproxy_bin}' — install it (one command, see "
            f"docs/06-auth-guides.md); the WireGuard lane will self-disable "
            f"and other lanes carry traffic")
    state = StateDB(cfg.state_path, fresh=cfg.fresh_ledger)
    mgr = PoolManager(cfg, state, log)
    mgr.start()

    if cfg.stats_file:
        def _stats_loop():
            while True:
                time.sleep(max(2.0, cfg.interval / 2))
                try:
                    with open(cfg.stats_file, "w") as fh:
                        json.dump(mgr.snapshot(), fh, indent=2)
                except OSError:
                    pass
        threading.Thread(target=_stats_loop, daemon=True).start()

    stop = threading.Event()
    watchdog: Optional[dict] = None

    def _sig(signum, _frame):
        nonlocal watchdog
        if signum == signal.SIGUSR1:
            mgr.rotate_now(f"signal {signum}")
            return
        log.warning(f"signal {signum} -> shutting down")
        stop.set()   # heavy teardown happens in the finally block (B34:
        # doing mgr.stop() inside the signal handler blocked the handler
        # and left listeners accepting into a closed state DB)
        if watchdog is None:
            # armed for the WHOLE shutdown incl. interpreter join: a
            # validator wedged in an un-timeout-able SOCKS5 greeting read
            # hangs threading._shutdown AFTER 'bye' — the only guaranteed
            # cure is a hard-exit budget (never disarmed).
            watchdog = _arm_exit_watchdog(25.0, log)

    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)
    if hasattr(signal, "SIGUSR1"):
        signal.signal(signal.SIGUSR1, _sig)

    frontends = _start_frontends(cfg, mgr, log)
    log.warning("READY - point your crawler at "
                f"http://{cfg.listen_host}:{cfg.listen_port} (HTTP) "
                + (f"or {cfg.socks_listen_host}:{cfg.socks_listen_port} "
                   "(SOCKS5/Burp)" if cfg.enable_socks else "(SOCKS disabled)"))
    log.warning("rotate NOW anytime: kill -USR1 <pid>  |  ledger: "
                f"{state.ledger_size()} IPs already used (never reused)")
    try:
        while not stop.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        if watchdog is None:               # Ctrl-C path without SIGINT handler
            watchdog = _arm_exit_watchdog(25.0, log)
        _stop_frontends(frontends, log)    # stop accepting FIRST
        mgr.stop()
        state.close()
        from .httpkit import close_client
        close_client()
        log.warning("bye")
        # NOTE: the watchdog stays ARMED on purpose — interpreter shutdown
        # (joining non-daemon executor workers) happens AFTER this block
        # and is exactly where a wedged validator can hang the process.
    return 0


# ===========================================================================
def cmd_warp(a) -> int:
    """WARP/WireGuard account lane management.

    * `--register N` — register N free accounts (one HTTPS POST each; no
      card, no email, no login) into ~/.ip_rotator/warp_accounts.json
    * `--probe` — spawn one wireproxy tunnel per stored account and verify
      the real egress IP through it (also proves UDP/WireGuard egress works
      on the current network — the #1 thing to check when the lane is down)
    * bare `ip-rotator warp` — status summary
    """
    overrides = {
        "state_path": a.state_path or os.path.expanduser(
            "~/.ip_rotator/state.db"),
    }
    if a.wireproxy:
        overrides["wireproxy_bin"] = a.wireproxy
    cfg = Config.load(a.config, overrides)
    log = get_logger()
    state = StateDB(cfg.state_path)
    lane = WireGuardLane(cfg, log, state)

    binpath = WireGuardLane.find_wireproxy(cfg.wireproxy_bin)
    print(f"wireproxy binary : {binpath or 'NOT FOUND'}"
          + ("" if binpath else f"  (expected at {cfg.wireproxy_bin}; "
                               f"install: curl -L "
                               f"{cfg.wireproxy_download} | tar xz)"))

    if a.register > 0:
        print(f"registering {a.register} free WARP account(s)... "
              f"(no card, no email)")
        for i in range(a.register):
            try:
                acct = register_warp_account()
                lane.store.add(acct)
                print(f"  [{i + 1}/{a.register}] OK — account "
                      f"#{lane.store.count()} "
                      f"(peer {acct['endpoint']})")
            except Exception as e:
                print(f"  [{i + 1}/{a.register}] FAILED: {e}")
            if i < a.register - 1:
                time.sleep(1.0)  # gentle with the API
    print(f"stored accounts  : {lane.store.count()} "
          f"(in {cfg.warp_accounts_path()})")

    if a.probe:
        if not binpath:
            print("cannot probe without the wireproxy binary")
            return 1
        cfg.warp_accounts = max(1, min(lane.store.count(),
                                       cfg.warp_accounts_max))
        print(f"probing {cfg.warp_accounts} tunnel(s) — verifying UDP/"
              "WireGuard egress on this network...")
        lane._build_tunnels()
        ok = 0
        ips = set()
        for t in lane.tunnels:
            if lane._handshake_ok(t):
                ok += 1
                ips.add(t.egress_ip)
                print(f"  {t.name}: EGRESS {t.egress_ip} via "
                      f"socks5://127.0.0.1:{t.port}  OK")
            else:
                print(f"  {t.name}: FAILED ({t.failed_reason})")
        lane.stop()
        if ok == 0:
            print("\nNO tunnel completed a handshake. Most likely this "
                  "network blocks UDP (only DNS/53 allowed?) — the WG lane "
                  "will stay disabled and other lanes carry traffic. Try "
                  "from a normal home/office network.")
            return 1
        print(f"\n{ok}/{len(lane.tunnels)} tunnels OK, {len(ips)} distinct "
              f"egress IPs — lane ready; add it to `serve` with "
              f"--warp-accounts {ok}")
        return 0

    print(f"warp lane config : warp_accounts={cfg.warp_accounts} "
          f"(serve with --warp-accounts N to engage)")
    if lane.store.count() and not binpath:
        print("NOTE: accounts exist but wireproxy is missing — see above.")
    state.close()
    return 0


# ===========================================================================
def cmd_warpplus(a) -> int:
    """warp-plus lane management (multi-country WARP egress).

    * `--probe [N]` — spawn N instances (each its own WARP identity +
      country), verify real egress IPs, prove automatic country rotation
      by respawning ONE instance with the next country, then exit
    * bare `ip-rotator warpplus` — status summary (binary + config)
    """
    overrides = {
        "state_path": a.state_path or os.path.expanduser(
            "~/.ip_rotator/state.db"),
        "enable_warpplus": True,
        "warpplus_instances": max(1, a.instances),
    }
    if a.mode:
        overrides["warpplus_mode"] = a.mode
    if a.warpplus_bin:
        overrides["warpplus_bin"] = a.warpplus_bin
    cfg = Config.load(a.config, overrides)
    log = get_logger()
    state = StateDB(cfg.state_path)
    lane = WarpPlusLane(cfg, log, state)

    binpath = lane.find_binary(cfg.warpplus_bin)
    print(f"warp-plus binary : {binpath or 'NOT FOUND'}"
          + ("" if binpath else f"  (auto-download failed; manual: curl -LO "
                               f"{cfg.warpplus_download} && unzip)"))
    print(f"lane config      : instances={cfg.warpplus_instances} "
          f"mode={cfg.warpplus_mode} "
          f"countries={len(cfg.warpplus_countries)}")

    if not binpath:
        state.close()
        return 1

    if a.probe:
        n = max(1, a.instances)
        print(f"probing {n} instance(s) — needs UDP egress "
              "(WireGuard handshakes)...")
        lane._build_instances()
        ok, ips = 0, set()
        for inst in lane.instances[:n]:
            if lane._handshake_ok(inst):
                ok += 1
                ips.add(inst.egress_ip)
                print(f"  wp{inst.idx} [{inst.mode}:{inst.country or '-'}]: "
                      f"EGRESS {inst.egress_ip} via "
                      f"socks5://127.0.0.1:{inst.port}  OK")
            else:
                print(f"  wp{inst.idx}: FAILED")
        if ok == 0:
            print("\nNO instance completed a handshake — this network "
                  "almost certainly blocks UDP. The lane self-disables "
                  "in `serve`; use --v2ray (TCP-based) instead here.")
            lane.stop()
            state.close()
            return 1
        # prove the mint: respawn the first instance with the NEXT country
        first = lane.instances[0]
        print(f"\nmint check: respawning wp0 with the next country in the "
              f"rotation (fresh identity)...")
        first.stop()
        first.start(lane._mode_for(0), lane._next_country(),
                    fresh_identity=True)
        if first.socks_ready(8.0) and first.probe_egress(20):
            new_ip = first.egress_ip
            print(f"  wp0 respawned [{first.mode}:{first.country or '-'}]: "
                  f"EGRESS {new_ip} "
                  + ("(NEW IP minted — country rotation works)"
                     if new_ip not in ips else
                     "(same IP this time — identity reuse varies; the lane "
                     "keeps cycling countries)"))
        else:
            print("  wp0 respawn handshake failed (transient; lane retries "
                  "automatically in serve)")
        lane.stop()
        print(f"\n{ok}/{n} instances OK, {len(ips)} distinct egress IPs — "
              f"engage the lane with: ip-rotator serve --warpplus {ok}")
        state.close()
        return 0

    print("engage with     : ip-rotator serve --warpplus N")
    state.close()
    return 0


# ===========================================================================
def cmd_v2ray(a) -> int:
    """free-node v2ray lane management (community nodes via sing-box).

    * `--probe [N]` — pull live subscriptions, spawn sing-box with N
      candidate nodes, verify real egress IPs through them, then exit
    * bare `ip-rotator v2ray` — status summary (binary + supply)
    """
    overrides = {
        "state_path": a.state_path or os.path.expanduser(
            "~/.ip_rotator/state.db"),
        "enable_v2ray": True,
    }
    if a.subs:
        overrides["v2ray_subs"] = [u.strip() for u in a.subs.split(",")
                                     if u.strip()]
    if a.singbox_bin:
        overrides["singbox_bin"] = a.singbox_bin
    cfg = Config.load(a.config, overrides)
    log = get_logger()
    state = StateDB(cfg.state_path)
    lane = V2RayLane(cfg, log, state)

    binpath = lane._resolve_bin()
    print(f"sing-box binary  : {binpath or 'NOT FOUND'}"
          + ("" if binpath else f"  (auto-download failed; manual: curl -L "
                               f"{cfg.singbox_download} | tar xz)"))
    print(f"subscriptions    : {len(cfg.v2ray_subs)} "
          f"({', '.join(u.rsplit('/', 2)[-1][:24] for u in cfg.v2ray_subs)})")
    if not binpath:
        state.close()
        return 1

    if a.probe:
        cfg.v2ray_max_nodes = max(8, a.nodes)
        print(f"pulling subscriptions and testing up to {a.nodes} nodes...")
        links = lane._pull_subs()
        if not links:
            print("no links pulled — subscriptions unreachable (offline? "
                  "GFW-blocked? try again or set --subs)")
            state.close()
            return 1
        print(f"pulled {len(links)} node links")
        lane._regen(links)
        healthy = lane._healthy
        if not healthy:
            print("0 nodes alive in this sample (they die in waves — "
                  "aggregators refresh every 5 min). Try again or raise "
                  "--nodes.")
            lane.stop()
            state.close()
            return 1
        ips = sorted({h['ip'] for h in healthy.values()})
        by_proto: dict = {}
        for h in healthy.values():
            by_proto[h['proto']] = by_proto.get(h['proto'], 0) + 1
        print(f"ALIVE: {len(healthy)}/{len(lane._nodes)} nodes, "
              f"{len(ips)} distinct egress IPs")
        print("by protocol     : " +
              ", ".join(f"{k}={v}" for k, v in sorted(by_proto.items())))
        print("sample egress   : " + ", ".join(ips[:8]) +
              (" ..." if len(ips) > 8 else ""))
        lane.stop()
        print("\nlane ready — engage with: ip-rotator serve --v2ray")
        state.close()
        return 0

    print("engage with     : ip-rotator serve --v2ray")
    state.close()
    return 0


# ===========================================================================
def cmd_doctor(a) -> int:
    log = get_logger()
    ok = True
    print(f"ip-rotator {__version__} doctor")
    print(f"  python          : {sys.version.split()[0]} "
          f"({'OK' if sys.version_info >= (3, 9) else 'TOO OLD'})")
    # runtime deps (uv sync should have installed these)
    deps = []
    for mod, name in (("httpx", "httpx"), ("python_socks", "python-socks"),
                      ("rich", "rich")):
        try:
            import importlib
            import importlib.metadata as md
            importlib.import_module(mod)
            deps.append(f"{name} {md.version(name)}")
        except Exception as e:
            deps.append(f"{name} MISSING ({e})")
            ok = False
    print(f"  dependencies    : {', '.join(deps)} "
          f"({'OK' if ok else 'RUN: uv sync'})")
    print(f"  internet        : ", end="")
    try:
        ip, ms = fetch_egress_ip(Upstream(kind="direct", host="-", port=0),
                                  timeout=8)
        print(f"OK (direct egress {ip}, {ms}ms)")
    except Exception as e:
        ok = False
        print(f"FAIL ({e})")
    print(f"  sources         : ", end="")
    from .config import DEFAULT_SOURCES
    from .httpkit import http_client
    good = 0
    for url in DEFAULT_SOURCES:
        try:
            r = http_client().get(url, timeout=12)
            r.raise_for_status()
            r.text[:512]
            good += 1
        except Exception:
            pass
    print(f"{good}/{len(DEFAULT_SOURCES)} reachable "
          f"({'OK' if good >= 3 else 'WARN'})")
    _cfg_probe = Config.load()
    socks_state = ("disabled" if not _cfg_probe.enable_socks else
                   f"{_cfg_probe.socks_listen_host}:{_cfg_probe.socks_listen_port}"
                   f" ({'user/pass auth' if _cfg_probe.socks_username else 'no-auth, Burp-compatible'})")
    print(f"  socks5 frontend : {socks_state}")
    print(f"  warp-cli        : "
          f"{'present (backbone available)' if _which('warp-cli') else 'not installed (optional backbone)'}")
    # --- WireGuard lane (v2.1) --------------------------------------------
    _cfg_wg = Config.load()
    _wp = WireGuardLane.find_wireproxy(_cfg_wg.wireproxy_bin)
    print(f"  wireproxy       : "
          f"{_wp if _wp else 'not installed (optional: WARP/WG clean-IP lane; see docs/06-auth-guides.md)'}")
    print(f"  openssl (x25519): "
          f"{'present (WARP account registration ready)' if _which('openssl') else 'MISSING (needed to register WARP accounts)'}")
    _acct_file = _cfg_wg.warp_accounts_path()
    _n_acct = 0
    try:
        with open(_acct_file) as fh:
            _n_acct = len(json.load(fh))
    except Exception:
        pass
    print(f"  warp accounts   : {_n_acct} stored"
          + ("" if _n_acct else " (register free: uv run ip-rotator warp --register 5)"))
    if _cfg_wg.wg_configs_dir:
        _n_conf = len([f for f in os.listdir(_cfg_wg.wg_configs_dir)
                       if f.endswith('.conf')]) \
            if os.path.isdir(_cfg_wg.wg_configs_dir) else 0
        print(f"  wg configs dir  : {_cfg_wg.wg_configs_dir} ({_n_conf} .conf)")
    # UDP egress probe: DNS over UDP works everywhere; a WG-shaped send to
    # Cloudflare's WARP port proves non-DNS UDP isn't silently dropped
    print("  udp egress      : ", end="")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        s.sendto(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                 b"\x06google\x03com\x00\x00\x01\x00\x01",
                 ("1.1.1.1", 53))
        s.recvfrom(512)
        s.close()
        print("OK (DNS-over-UDP works; run `warp --probe` for the "
              "definitive WireGuard test — some networks only allow :53)")
    except Exception:
        print("BLOCKED? (DNS-over-UDP failed; the WG lane will likely "
              "self-disable — other lanes unaffected)")
    _psiphon = "present (opt-in backbone)" if (_port_open(1080) or
                                               _port_open(8080)) else (
        "not running (opt-in only: free, unlimited, shared egress)")
    print(f"  psiphon 1080/8080: {_psiphon}"
          f"{'' if _cfg_probe.enable_psiphon else ' [disabled by default]'}")
    _vpn_clis = []
    for _name, _r in VPN_CLI_RECIPES.items():
        _bin = next((b for b in _r["bins"] if _which(b)), None)
        if _bin:
            _vpn_clis.append(f"{_name} ({_bin})")
    print(f"  free VPN CLIs   : {', '.join(_vpn_clis) if _vpn_clis else 'none installed (optional: protonvpn-cli / windscribe / hide.me for vpn mode)'}")
    print(f"  vpngate         : "
          f"{'openvpn+sudo present — opt-in dirty tier (enable_vpngate)' if _which('openvpn') and _which('sudo') else 'not installed (opt-in dirty tier: needs openvpn + sudo)'}")
    _ws_bin = next((b for b in ("windscribe", "windscribe-cli")
                    if _which(b)), None)
    print(f"  windscribe proxy: "
          f"{'CLI present — opt-in local-SOCKS lane (enable_windscribe_proxy)' if _ws_bin else 'not installed (opt-in: windscribe-cli proxy mode; no full tunnel)'}")
    # --- v3 lanes: warp-plus (multi-country WARP) + v2ray free nodes -------
    _wp_lane = WarpPlusLane(_cfg_probe, log, None)
    _wp_bin = _wp_lane.find_binary(_cfg_probe.warpplus_bin)
    print(f"  warp-plus       : "
          f"{_wp_bin if _wp_bin else 'not installed (optional: multi-country WARP lane; serve --warpplus N auto-downloads)'}"
          f" [lane {'ENABLED' if _cfg_probe.enable_warpplus else 'off'}]")
    _v2 = V2RayLane(_cfg_probe, log, None)
    _sb = _v2._resolve_bin()
    print(f"  sing-box        : "
          f"{_sb if _sb else 'not installed (optional: free-node v2ray lane; serve --v2ray auto-downloads)'}"
          f" [lane {'ENABLED' if _cfg_probe.enable_v2ray else 'off'}]")
    if _sb:
        try:
            _links = 0
            r = http_client().get(_cfg_probe.v2ray_subs[0], timeout=12)
            _links = len([l for l in r.text.splitlines() if "://" in l])
            print(f"  v2ray supply    : {_links} node links live in sub #1 "
                  f"({'OK' if _links > 100 else 'WARN: low'})")
        except Exception as e:
            print(f"  v2ray supply    : unreachable ({type(e).__name__})")
    print(f"  no-reuse window : {_cfg_probe.effective_no_reuse() / 60:.0f} min "
          f"(an IP is burned this long after use; --no-reuse-minutes)")
    print(f"  webshare        : "
          f"{'key configured (10 free proxies, 1GB/mo lane enabled)' if _cfg_probe.webshare_api_key else 'no API key (optional metered lane: dashboard.webshare.io)'}")
    _ok_static = [p for p in (_cfg_probe.static_proxies or [])
                  if parse_static_proxy(p) is not None]
    _bad_static = len(_cfg_probe.static_proxies or []) - len(_ok_static)
    if _ok_static:
        print(f"  static proxies  : {len(_ok_static)} configured "
              f"(credentials preserved, lane enabled)"
              + (f" — WARNING: {_bad_static} unparseable entries skipped"
                 if _bad_static else ""))
    elif _cfg_probe.static_proxies:
        print(f"  static proxies  : WARNING: all {len(_cfg_probe.static_proxies)} "
              "entries unparseable — expected 'host:port:user:pass' or "
              "'socks5://user:pass@host:port'")
    _keys = [k for k, v in (_cfg_probe.api_keys or {}).items() if v]
    print(f"  scraping APIs   : {', '.join(_keys) if _keys else 'no keys (optional fetch lane: zenrows/firecrawl/scrapingbee/crawlbase/scraperapi)'}")
    st = os.path.expanduser("~/.ip_rotator/state.db")
    print(f"  state db        : {st} "
          f"({'exists' if os.path.exists(st) else 'will be created'})")
    print("doctor " + ("PASSED" if ok else "FAILED"))
    return 0 if ok else 1


def _which(bin_name: str) -> bool:
    return shutil.which(bin_name) is not None


def _port_open(port: int) -> bool:
    try:
        socket.create_connection(("127.0.0.1", port), timeout=1).close()
        return True
    except OSError:
        return False


# ===========================================================================
def _socks5_probe(port: int, target_host: str = "checkip.amazonaws.com",
                  timeout: float = 25.0) -> str:
    """Minimal SOCKS5 client (no-auth): CONNECT + TLS GET through the
    frontend. Returns the egress IP text. Used by `test`."""
    import ssl
    import struct
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        s.settimeout(timeout)
        s.sendall(b"\x05\x01\x00")                    # greeting: no-auth
        resp = s.recv(2)
        if len(resp) < 2 or resp[0] != 5 or resp[1] != 0x00:
            raise OSError(f"socks5 handshake failed: {resp!r}")
        hb = target_host.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb +
                  struct.pack(">H", 443))
        head = s.recv(4)
        if len(head) < 4 or head[1] != 0x00:
            raise OSError(f"socks5 CONNECT refused: {head!r}")
        atyp = head[3]
        if atyp == 0x01:
            s.recv(4 + 2)
        elif atyp == 0x03:
            ln = s.recv(1)[0]
            s.recv(ln + 2)
        elif atyp == 0x04:
            s.recv(16 + 2)
        tls = ssl.create_default_context().wrap_socket(
            s, server_hostname=target_host)
        try:
            tls.sendall(f"GET / HTTP/1.1\r\nHost: {target_host}\r\n"
                        f"User-Agent: Mozilla/5.0\r\n"
                        f"Connection: close\r\n\r\n".encode())
            buf = b""
            while len(buf) < 8192:
                c = tls.recv(4096)
                if not c:
                    break
                buf += c
        finally:
            tls.close()
        body = buf.partition(b"\r\n\r\n")[2].decode("utf-8", "replace")
        return body.strip()
    finally:
        try:
            s.close()
        except OSError:
            pass


def cmd_test(a) -> int:
    """Prove it: warm the pool, serve HTTP + SOCKS5 on ephemeral ports,
    fire requests through BOTH front-ends, verify rotation + distinctness."""
    import urllib.request
    from .server import RotatingProxyServer
    from .socks_server import Socks5Server
    cfg = Config.load(overrides={
        "listen_host": "127.0.0.1", "listen_port": 0,
        "socks_listen_host": "127.0.0.1", "socks_listen_port": 0,
        "interval": a.interval,
        "state_path": os.path.expanduser("~/.ip_rotator/test_state.db"),
    })
    log = get_logger()
    state = StateDB(cfg.state_path, fresh=True)
    mgr = PoolManager(cfg, state, log)
    mgr.start()
    log.info("warming pool (harvest + validate)...")
    t0 = time.time()
    while time.time() - t0 < a.timeout:
        if mgr.fresh_count() >= max(4, a.requests):
            break
        time.sleep(2.0)
    fresh = mgr.fresh_count()
    print(f"pool warm: fresh={fresh} validated={mgr._pool_len()} "
          f"({time.time()-t0:.0f}s)")
    if fresh == 0:
        print("FAIL: no validated proxies - check connectivity")
        return 1

    srv = RotatingProxyServer(("127.0.0.1", 0), mgr, cfg, log)
    threading.Thread(target=srv.serve_forever,
                     kwargs={"poll_interval": 0.2}, daemon=True).start()
    http_port = srv.server_address[1]
    ssock = Socks5Server(("127.0.0.1", 0), mgr, cfg, log)
    threading.Thread(target=ssock.serve_forever,
                     kwargs={"poll_interval": 0.2}, daemon=True).start()
    socks_port = ssock.server_address[1]
    print(f"test front-ends: HTTP 127.0.0.1:{http_port} | "
          f"SOCKS5 127.0.0.1:{socks_port} - firing {a.requests} requests "
          f"through each, one per {a.interval}s window\n" + "-" * 60)

    http_ips, socks_ips = [], []
    for i in range(a.requests):
        t = time.time()
        proxy = urllib.request.ProxyHandler(
            {"http": f"http://127.0.0.1:{http_port}",
             "https": f"http://127.0.0.1:{http_port}"})
        opener = urllib.request.build_opener(proxy)
        try:
            with opener.open("https://checkip.amazonaws.com", timeout=25) as r:
                ip = r.read().decode().strip()
            http_ips.append(ip)
            print(f"  http  {i+1}: egress IP = {ip:16s} "
                  f"({time.time()-t:.1f}s)")
        except Exception as e:
            print(f"  http  {i+1}: FAILED ({type(e).__name__}: {e})")
        t = time.time()
        try:
            ip = _socks5_probe(socks_port)
            socks_ips.append(ip)
            print(f"  socks {i+1}: egress IP = {ip:16s} "
                  f"({time.time()-t:.1f}s)")
        except Exception as e:
            print(f"  socks {i+1}: FAILED ({type(e).__name__}: {e})")
        if i < a.requests - 1:
            time.sleep(a.interval)
    print("-" * 60)
    ips = http_ips + socks_ips
    distinct = len(set(ips))
    print(f"result: HTTP {len(http_ips)}/{a.requests}, "
          f"SOCKS {len(socks_ips)}/{a.requests}, "
          f"{distinct} DISTINCT IPs overall")
    mgr.stop()
    srv.shutdown()
    ssock.shutdown()
    state.close()
    if len(http_ips) >= 1 and len(socks_ips) >= 1 and distinct >= 2:
        print("PASS: both front-ends work and IP rotation is verified")
        return 0
    if ips and distinct < 2:
        print("WARN: requests succeeded but IP did not change - "
              "check interval vs request pacing")
        return 1
    print("FAIL: see errors above")
    return 1


# ===========================================================================
def cmd_harvest(a) -> int:
    cfg = Config.load(overrides={
        "state_path": a.state_path or os.path.expanduser(
            "~/.ip_rotator/state.db"),
        "fresh_ledger": a.fresh_ledger or None,
    })
    log = get_logger()
    state = StateDB(cfg.state_path, fresh=cfg.fresh_ledger)
    mgr = PoolManager(cfg, state, log)
    mgr.start()
    print("harvesting + validating (60s)...")
    t0 = time.time()
    while time.time() - t0 < 60 and mgr._pool_len() < a.limit:
        time.sleep(2.0)
    mgr.stop()
    rows = state.load_validated(max_age=120.0)
    rows.sort(key=lambda r: r[4] or 9999)
    print(f"\n{'proto':7s} {'upstream':24s} {'egress IP':17s} latency")
    for host, port, proto, egress, ms, _ in rows[:a.limit]:
        print(f"{proto:7s} {host + ':' + str(port):24s} {egress:17s} {ms}ms")
    print(f"\ntotal validated: {len(rows)}  (ledger: {state.ledger_size()} used IPs)")
    state.close()
    return 0


# ===========================================================================
def cmd_vpn(a) -> int:
    """Free-VPN-CLI rotation mode (Proton / Windscribe / Hide.me — no card).

    Honest limits (see README): full-tunnel => machine-wide route hijack,
    reconnect blip 10-30s per rotation, 10GB/month caps (metered), static
    datacenter IPs per server. This mode trades IP diversity for per-request
    reliability; the proxy-pool engine (serve) is the opposite trade.
    """
    listen_host, listen_port = "127.0.0.1", 8000
    if getattr(a, "listen", None):
        hp = a.listen.rsplit(":", 1)
        listen_host = hp[0] or "127.0.0.1"
        listen_port = int(hp[1]) if len(hp) == 2 else 8000
    overrides = {
        "listen_host": listen_host, "listen_port": listen_port,
        "interval": a.interval,
        "state_path": a.state_path or os.path.expanduser(
            "~/.ip_rotator/state.db"),
        "log_level": "ERROR" if getattr(a, "quiet", False) else None,
    }
    overrides.update(_socks_overrides(a))
    cfg = Config.load(getattr(a, "config", None), overrides)
    log = get_logger(level={"ERROR": 40, "WARNING": 30, "INFO": 20,
                            "DEBUG": 10}[cfg.log_level])

    # 1) which VPN CLIs are installed? (+ opt-in VPN Gate provider)
    avail: list = []
    for name, recipe in VPN_CLI_RECIPES.items():
        binname = next((b for b in recipe["bins"] if shutil.which(b)), None)
        if binname and (a.provider in ("auto", name)):
            avail.append(VpnCliProvider(name, recipe, log, None))
    if cfg.enable_vpngate and a.provider in ("auto", "vpngate"):
        vg = VpnGateProvider(log, None)
        if vg.available():
            avail.append(vg)
        else:
            print("vpngate lane: openvpn/sudo not available — skipped")
    if not avail:
        print("No free-VPN CLI found" +
              (f" matching --provider {a.provider}" if a.provider != "auto" else "") +
              ". Install ONE of:")
        for name, recipe in VPN_CLI_RECIPES.items():
            print(f"  {name:12s} {recipe['label']:20s} {recipe['notes']}")
        print("  vpngate      VPN Gate (opt-in)      free, unlimited, "
              "volunteer servers; needs openvpn + sudo; DIRTY egress tier")
        return 1

    state = StateDB(cfg.state_path, fresh=cfg.fresh_ledger)
    for p in avail:
        if hasattr(p, "state"):
            p.state = state

    # 2) real IP BEFORE any tunnel exists (guards against silent VPN drops)
    try:
        real_ip = fetch_egress_ip(Upstream(kind="direct", host="-", port=0),
                                  timeout=10)[0]
    except Exception as e:
        print(f"cannot detect your real egress IP ({e}) - aborting (the "
              "drop-guard needs it); check connectivity")
        return 1

    print("VPN rotation mode")
    print(f"  providers : " + ", ".join(
        f"{p.name} ({p.recipe['label']})" for p in avail))
    print(f"  interval  : {cfg.interval:.0f}s (reconnect blip 10-30s per "
          "rotation is unavoidable with full-tunnel CLIs)")
    print(f"  real IP   : {real_ip} (fail-closed guard: requests get 502, "
          "never your real IP, if the VPN drops)\n")

    mgr = VpnPoolManager(cfg, state, log, avail, real_ip)
    mgr.start()

    stop = threading.Event()

    def _sig(signum, _frame):
        log.warning(f"signal {signum} -> shutting down")
        stop.set()   # heavy teardown in finally (B34 pattern; see cmd_serve)

    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)

    frontends = _start_frontends(cfg, mgr, log)
    log.warning("READY - point your crawler at "
                f"http://{cfg.listen_host}:{cfg.listen_port}"
                + (f" or SOCKS5 {cfg.socks_listen_host}:"
                   f"{cfg.socks_listen_port}" if cfg.enable_socks else ""))
    try:
        while not stop.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        watchdog = _arm_exit_watchdog(25.0, log)   # B34: always exit
        _stop_frontends(frontends, log)
        mgr.stop()
        state.close()
        log.warning("bye")
        # watchdog intentionally stays armed through interpreter shutdown
    return 0


# ===========================================================================
def cmd_fetch(a) -> int:
    cfg = Config.load(getattr(a, "config", None), overrides={
        "state_path": a.state_path or os.path.expanduser(
            "~/.ip_rotator/state.db"),
    })
    log = get_logger()
    state = StateDB(cfg.state_path)
    lane = FetchLane(cfg, log, state)
    provider, content, err = lane.fetch(a.url, provider=a.provider)
    state.close()
    if err:
        print(f"FETCH FAILED: {err}")
        return 1
    print(f"# fetched via {provider} ({len(content)} bytes)")
    print(content[:a.max_bytes] +
          ("\n... [truncated]" if len(content) > a.max_bytes else ""))
    return 0


# ===========================================================================
def cmd_api_status(a) -> int:
    cfg = Config.load(getattr(a, "config", None))
    state = StateDB(cfg.state_path)
    print("Metered free tiers — usage this period (all no-credit-card)")
    print("-" * 78)

    print(f"{'provider':14s} {'free cap':>10s} {'period':9s} "
          f"{'used':>12s} {'key':11s} note")
    if cfg.webshare_api_key:
        ws = WebshareClient(cfg, None, state)
        print(f"{'webshare':14s} {'10 proxies':>10s} {'forever':9s} "
              f"{'':>12s} {'configured':11s} in the rotation pool")
        print(f"{'  (bandwidth)':14s} {'1 GB':>10s} {'monthly':9s} "
              f"{ws.describe():>12s} {'':11s} byte-metered, auto-disabled at cap")
    else:
        print(f"{'webshare':14s} {'10 proxies':>10s} {'forever':9s} "
              f"{'':>12s} {'MISSING':11s} get key: dashboard.webshare.io")

    lane = FetchLane(cfg, get_logger(), state)
    for row in lane.status_table():
        used = f"{row['credits_used']}/{row['free_cap']} cr"
        print(f"{row['provider']:14s} {row['free_cap']:>7d} cr {row['period']:9s} "
              f"{used:>12s} {row['key']:11s} {row['note']}")
        if row["docs"]:
            print(f"{'':14s} docs: {row['docs']}")

    rows = state.api_usage_rows()
    vpn_rows = [r for r in rows if r[0].startswith("vpn:")]
    if vpn_rows:
        print("\nVPN mode data caps:")
        for provider, period, credits, bytes_ in vpn_rows:
            print(f"  {provider:18s} {bytes_ / 1024 ** 2:8.0f} MB relayed ({period})")
    state.close()
    return 0


def _setup_parent_death_signal() -> None:
    """v2.1 bug fix: `uv run ip-rotator serve` spawns this process as a
    CHILD of uv. uv does not forward SIGTERM to children, so killing the
    uv wrapper (Ctrl-C in some terminals, supervisor restarts, scripts)
    left an ORPHANED gateway running and holding ports 8000/1080 — the
    next start then fought it for the port.

    Linux PR_SET_PDEATHSIG: the kernel delivers SIGTERM to this process
    the moment its parent dies -> the existing signal handler shuts down
    cleanly. Best-effort (no-op on non-Linux / in containers that block
    prctl)."""
    try:
        import ctypes
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        PR_SET_PDEATHSIG = 1
        if libc.prctl(PR_SET_PDEATHSIG, signal.SIGTERM, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno())
    except Exception:
        pass  # non-Linux or prctl blocked: rely on explicit signals


# ===========================================================================
def main(argv: Optional[list] = None) -> int:
    parser = _build_parser()
    a = parser.parse_args(argv)
    if a.cmd is None or a.cmd in ("serve", "vpn"):
        _setup_parent_death_signal()
    if a.cmd is None:
        a.cmd = "serve"
        # no args at all -> run serve with defaults
        import types
        a = types.SimpleNamespace(**vars(a))
        for attr in ("listen", "socks_listen", "no_socks", "socks_auth",
                     "interval", "rotate_every_request", "min_pool",
                     "retries", "policy", "allow_http", "allow_direct",
                     "allow_private", "country", "max_latency", "workers",
                     "state_path", "fresh_ledger", "stats_file", "config",
                     "quiet", "warp_accounts", "wg_dir", "wireproxy",
                     "no_sticky", "sticky", "no_reuse_minutes", "v2ray",
                     "v2ray_subs", "v2ray_nodes", "warpplus",
                     "warpplus_mode", "warpplus_bin", "singbox_bin"):
            if not hasattr(a, attr):
                setattr(a, attr, None)
        return cmd_serve(a)
    return {"serve": cmd_serve, "doctor": cmd_doctor, "test": cmd_test,
            "harvest": cmd_harvest, "vpn": cmd_vpn, "warp": cmd_warp,
            "warpplus": cmd_warpplus, "v2ray": cmd_v2ray,
            "fetch": cmd_fetch, "api-status": cmd_api_status}[a.cmd](a)


if __name__ == "__main__":
    raise SystemExit(main())
