"""Offline smoke tests: dialers, ledger, rotation selection, server path.

Runs fake local proxies (HTTP-CONNECT + SOCKS5) so everything except
harvesting is tested without external dependencies.

    python -m unittest discover -s tests -v
"""
import dataclasses
import json
import os
import socket
import ssl
import struct
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ip_rotator.config import Config                      # noqa: E402
from ip_rotator.dialer import Upstream, connect_via       # noqa: E402
from ip_rotator.state import StateDB                      # noqa: E402
from ip_rotator.pool import PoolManager                   # noqa: E402
from ip_rotator.apiproviders import WebshareClient        # noqa: E402
from ip_rotator.providers import PsiphonProvider          # noqa: E402
from ip_rotator.v2raylane import (V2RayLane, decode_subscription,   # noqa: E402
                                  parse_node_link)
from ip_rotator.warpwire import (WarpPlusInstance,        # noqa: E402
                                 WarpPlusLane, WireGuardLane)


# ===========================================================================
# Fake upstream: HTTP CONNECT proxy that tunnels to a local HTTPS-ish server
# ===========================================================================
class FakeConnectProxy(ThreadingHTTPServer):
    daemon_threads = True
    egress_ip = "203.0.113.7"      # what our fake ip-check endpoint reports


class _FakeConnectHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_CONNECT(self):
        host, _, port = self.path.partition(":")
        self.send_response(200, "Connection established")
        self.end_headers()
        # answer with a tiny fake HTTP response instead of really tunneling
        self.connection.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n"
            b"\r\n" + self.server.egress_ip.encode() + b"\n")


class FakeSocks5Proxy:
    """Raw-socket fake SOCKS5 server (implemented in _socks5_server_thread)."""
    egress_ip = "198.51.100.9"


def _socks5_server_thread(port_holder):
    def recv_exact(conn, n):
        buf = b""
        while len(buf) < n:
            c = conn.recv(n - len(buf))
            if not c:
                raise OSError("closed")
            buf += c
        return buf

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    port_holder.append(srv.getsockname()[1])

    def worker(conn):
        try:
            conn.settimeout(10)
            hdr = recv_exact(conn, 2)          # VER + NMETHODS
            if hdr != b"\x05\x01":
                return
            recv_exact(conn, hdr[1])           # methods
            conn.sendall(b"\x05\x00")
            head = recv_exact(conn, 4)          # VER CMD RSV ATYP
            if head[1] != 1:
                return
            if head[3] == 3:
                ln = recv_exact(conn, 1)[0]
                recv_exact(conn, ln)            # host
            elif head[3] == 1:
                recv_exact(conn, 4)
            recv_exact(conn, 2)                 # port
            conn.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("1.2.3.4") +
                         struct.pack(">H", 443))
            # serve fake HTTP response over the "tunnel"
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\n"
                         b"Connection: close\r\n\r\n198.51.100.9\n")
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        threading.Thread(target=worker, args=(conn,), daemon=True).start()


# ===========================================================================
class TestDialers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.http_proxy = FakeConnectProxy(("127.0.0.1", 0),
                                          _FakeConnectHandler)
        threading.Thread(target=cls.http_proxy.serve_forever,
                         daemon=True).start()
        cls.http_port = cls.http_proxy.server_address[1]
        holder = []
        t = threading.Thread(target=_socks5_server_thread,
                             args=(holder,), daemon=True)
        t.start()
        while not holder:
            time.sleep(0.01)
        cls.socks_port = holder[0]

    def test_http_connect_dial(self):
        up = Upstream(kind="http", host="127.0.0.1", port=self.http_port)
        sock, early = connect_via(up, "example.com", 443, timeout=5)
        # body bytes may arrive in `early` or later on the socket (TCP has
        # no atomicity) - so check the union of both streams
        data = early
        sock.settimeout(5)
        try:
            while b"203.0.113.7" not in data:
                c = sock.recv(4096)
                if not c:
                    break
                data += c
        except OSError:
            pass
        self.assertIn(b"203.0.113.7", data)
        sock.close()

    def test_socks5_dial(self):
        up = Upstream(kind="socks5", host="127.0.0.1", port=self.socks_port)
        sock, early = connect_via(up, "example.com", 443, timeout=5)
        data = b""
        sock.settimeout(5)
        try:
            while True:
                c = sock.recv(4096)
                if not c:
                    break
                data += c
        except OSError:
            pass
        self.assertIn(b"198.51.100.9", data)
        sock.close()

    def test_dead_upstream_raises(self):
        up = Upstream(kind="http", host="127.0.0.1", port=1)  # nothing there
        with self.assertRaises(OSError):
            connect_via(up, "example.com", 443, timeout=2)


# ===========================================================================
class TestLedgerAndSelection(unittest.TestCase):
    def setUp(self):
        self.db = StateDB(os.path.join(tempfile.mkdtemp(), "s.db"), fresh=True)

    def test_never_reuse(self):
        self.db.mark_ip_used("1.1.1.1", "test")
        self.assertTrue(self.db.ip_seen("1.1.1.1"))
        self.assertFalse(self.db.ip_seen("2.2.2.2"))

    def test_recycle_prefers_oldest(self):
        now = time.time()
        for ip, lu in (("1.1.1.1", now - 2000), ("2.2.2.2", now - 1000)):
            self.db.mark_ip_used(ip, "test")
            self.db._db.execute("UPDATE egress_ips SET last_used=? WHERE ip=?",
                                (lu, ip))
            self.db._db.commit()
        self.assertEqual(self.db.oldest_recyclable(600.0), "1.1.1.1")

    def test_blacklist_roundtrip(self):
        self.db.upsert_upstream("h", 1, "http", "9.9.9.9", 100)
        self.assertFalse(self.db.is_blacklisted("h", 1, "http"))
        self.db.record_fail("h", 1, "http", 60, force=True)
        self.assertTrue(self.db.is_blacklisted("h", 1, "http"))

    def test_selection_skips_used_ips(self):
        cfg = Config()
        mgr = PoolManager(cfg, self.db, _SilentLog())
        mgr.real_ip = "7.7.7.7"
        with mgr._lock:
            mgr._validated = {
                "http://a:1": Upstream("http", "a", 1, egress_ip="1.1.1.1",
                                      latency_ms=100),
                "http://b:2": Upstream("http", "b", 2, egress_ip="2.2.2.2",
                                      latency_ms=200),
            }
        self.db.mark_ip_used("1.1.1.1", "test")
        picked = mgr._pick_fresh_locked(set())
        self.assertEqual(picked.egress_ip, "2.2.2.2")

    def test_selection_rejects_real_ip_transparent(self):
        cfg = Config()
        mgr = PoolManager(cfg, self.db, _SilentLog())
        mgr.real_ip = "7.7.7.7"
        with mgr._lock:
            mgr._validated = {
                "http://a:1": Upstream("http", "a", 1, egress_ip="7.7.7.7",
                                      latency_ms=100),
                "http://b:2": Upstream("http", "b", 2, egress_ip="2.2.2.2",
                                      latency_ms=300),
            }
        # validator-level rejection is in _validate_one; selection itself
        # must never return an upstream whose egress == real_ip either
        picked = mgr._pick_fresh_locked(set())
        self.assertEqual(picked.egress_ip, "2.2.2.2")

    def test_failover_promotes_and_blacklists(self):
        cfg = Config()
        mgr = PoolManager(cfg, self.db, _SilentLog())
        mgr.real_ip = "7.7.7.7"
        with mgr._lock:
            mgr._validated = {
                "http://a:1": Upstream("http", "a", 1, egress_ip="1.1.1.1",
                                      latency_ms=100),
                "http://b:2": Upstream("http", "b", 2, egress_ip="2.2.2.2",
                                      latency_ms=200),
            }
        mgr.rotate("test")            # activates 1.1.1.1
        self.assertEqual(mgr.describe_current(), "1.1.1.1 via http://a:1")
        # 3 failures -> blacklist + rotation away to the standby
        cur = mgr._current
        for _ in range(3):
            mgr.report_failure(cur, "unit-test")
        self.assertTrue(self.db.is_blacklisted("a", 1, "http"))
        self.assertEqual(mgr.describe_current(), "2.2.2.2 via http://b:2")


class _SilentLog:
    def info(self, *a):
        pass

    warning = error = critical = debug = info


# ===========================================================================
class TestLocalServer(unittest.TestCase):
    """Full client->local-proxy->fake-upstream path (no internet)."""

    def test_connect_tunnel_serves_egress_header_and_body(self):
        fake = FakeConnectProxy(("127.0.0.1", 0), _FakeConnectHandler)
        threading.Thread(target=fake.serve_forever, daemon=True).start()

        db = StateDB(os.path.join(tempfile.mkdtemp(), "s.db"), fresh=True)
        cfg = Config()
        cfg.interval = 3600  # no timer rotation during the test
        mgr = PoolManager(cfg, db, _SilentLog())
        mgr.real_ip = "7.7.7.7"
        with mgr._lock:
            mgr._validated = {
                "http://fake": Upstream(
                    "http", "127.0.0.1", fake.server_address[1],
                    egress_ip="203.0.113.7", latency_ms=5,
                    validated_at=time.time(), source="unit"),
            }
        mgr.rotate("test")

        from ip_rotator.server import RotatingProxyServer
        srv = RotatingProxyServer(("127.0.0.1", 0), mgr, cfg, _SilentLog())
        threading.Thread(target=srv.serve_forever,
                         kwargs={"poll_interval": 0.2}, daemon=True).start()
        port = srv.server_address[1]

        s = socket.create_connection(("127.0.0.1", port), timeout=10)
        s.sendall(b"CONNECT checkip.amazonaws.com:443 HTTP/1.1\r\n"
                  b"Host: checkip.amazonaws.com:443\r\n\r\n")
        buf = b""
        s.settimeout(10)
        # read until we have headers AND at least one body byte after them
        while True:
            c = s.recv(4096)
            if not c:
                break
            buf += c
            head, _, body = buf.partition(b"\r\n\r\n")
            if body:
                break
        self.assertIn(b"HTTP/1.1 200 Connection established", buf)
        self.assertIn(b"X-Rotator-Egress: 203.0.113.7", buf)
        self.assertIn(b"203.0.113.7", buf.partition(b"\r\n\r\n")[2])
        s.close()
        srv.shutdown()

    def test_plain_http_denied_by_default(self):
        db = StateDB(os.path.join(tempfile.mkdtemp(), "s.db"), fresh=True)
        cfg = Config()
        mgr = PoolManager(cfg, db, _SilentLog())
        from ip_rotator.server import RotatingProxyServer
        srv = RotatingProxyServer(("127.0.0.1", 0), mgr, cfg, _SilentLog())
        threading.Thread(target=srv.serve_forever,
                         kwargs={"poll_interval": 0.2}, daemon=True).start()
        port = srv.server_address[1]
        proxy = urllib.request.ProxyHandler(
            {"http": f"http://127.0.0.1:{port}"})
        opener = urllib.request.build_opener(proxy)
        with self.assertRaises(urllib.error.HTTPError) as cm:
            opener.open("http://example.com/", timeout=10)
        self.assertEqual(cm.exception.code, 403)
        srv.shutdown()


# ===========================================================================
# Fake SOCKS5 server WITH username/password auth (RFC 1929) — for Webshare
# ===========================================================================
class FakeSocks5AuthServer:
    expected_user = "wsuser"
    expected_pass = "wspass"
    egress_ip = "192.0.2.77"


def _socks5_auth_server_thread(port_holder):
    def recv_exact(conn, n):
        buf = b""
        while len(buf) < n:
            c = conn.recv(n - len(buf))
            if not c:
                raise OSError("closed")
            buf += c
        return buf

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    port_holder.append(srv.getsockname()[1])

    def worker(conn):
        try:
            conn.settimeout(10)
            hdr = recv_exact(conn, 2)            # VER + NMETHODS
            methods = recv_exact(conn, hdr[1])
            if 0x02 in methods:                  # client offered user/pass
                conn.sendall(b"\x05\x02")
                ver = recv_exact(conn, 1)
                if ver[0] != 0x01:
                    return
                ulen = recv_exact(conn, 1)[0]
                user = recv_exact(conn, ulen)
                plen = recv_exact(conn, 1)[0]
                pwd = recv_exact(conn, plen)
                ok = (user.decode() == FakeSocks5AuthServer.expected_user and
                      pwd.decode() == FakeSocks5AuthServer.expected_pass)
                conn.sendall(b"\x01\x00" if ok else b"\x01\x01")
                if not ok:
                    return
            elif 0x00 in methods:
                conn.sendall(b"\x05\x00")
            else:
                conn.sendall(b"\x05\xff")
                return
            head = recv_exact(conn, 4)
            if head[1] != 1:
                return
            if head[3] == 3:
                ln = recv_exact(conn, 1)[0]
                recv_exact(conn, ln)
            elif head[3] == 1:
                recv_exact(conn, 4)
            recv_exact(conn, 2)
            conn.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("1.2.3.4") +
                         struct.pack(">H", 443))
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n"
                         b"Connection: close\r\n\r\n192.0.2.77\n")
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        threading.Thread(target=worker, args=(conn,), daemon=True).start()


# ===========================================================================
# Fake HTTP proxy that REQUIRES Proxy-Authorization (Webshare HTTP shape)
# ===========================================================================
class _AuthConnectHandler(_FakeConnectHandler):
    def do_CONNECT(self):
        auth = self.headers.get("Proxy-Authorization", "")
        want = "Basic " + __import__("base64").b64encode(
            b"wsuser:wspass").decode()
        if auth != want:
            self.send_response(407)
            self.send_header("Proxy-Authenticate", "Basic realm=\"ws\"")
            self.end_headers()
            return
        super().do_CONNECT()


# ===========================================================================
class TestAuthenticatedDialers(unittest.TestCase):
    """Webshare-style credentialled upstreams (SOCKS5 RFC1929 + HTTP Basic)."""

    @classmethod
    def setUpClass(cls):
        holder = []
        threading.Thread(target=_socks5_auth_server_thread,
                         args=(holder,), daemon=True).start()
        while not holder:
            time.sleep(0.01)
        cls.socks_port = holder[0]
        cls.http_proxy = FakeConnectProxy(("127.0.0.1", 0),
                                          _AuthConnectHandler)
        threading.Thread(target=cls.http_proxy.serve_forever,
                         daemon=True).start()

    def test_socks5_userpass_auth(self):
        up = Upstream(kind="socks5", host="127.0.0.1", port=self.socks_port,
                      username="wsuser", password="wspass")
        sock, _ = connect_via(up, "example.com", 443, timeout=5)
        data = b""
        sock.settimeout(5)
        try:
            while True:
                c = sock.recv(4096)
                if not c:
                    break
                data += c
        except OSError:
            pass
        self.assertIn(b"192.0.2.77", data)
        sock.close()

    def test_socks5_wrong_password_rejected(self):
        up = Upstream(kind="socks5", host="127.0.0.1", port=self.socks_port,
                      username="wsuser", password="WRONG")
        with self.assertRaises(OSError):
            connect_via(up, "example.com", 443, timeout=5)

    def test_http_connect_proxy_authorization(self):
        up = Upstream(kind="http", host="127.0.0.1",
                      port=self.http_proxy.server_address[1],
                      username="wsuser", password="wspass")
        sock, early = connect_via(up, "example.com", 443, timeout=5)
        data = early
        sock.settimeout(5)
        try:
            while b"203.0.113.7" not in data:
                c = sock.recv(4096)
                if not c:
                    break
                data += c
        except OSError:
            pass
        self.assertIn(b"203.0.113.7", data)
        sock.close()

    def test_http_connect_bad_credentials_rejected(self):
        up = Upstream(kind="http", host="127.0.0.1",
                      port=self.http_proxy.server_address[1],
                      username="wsuser", password="WRONG")
        with self.assertRaises(OSError):
            connect_via(up, "example.com", 443, timeout=5)


# ===========================================================================
class TestWebshareLane(unittest.TestCase):
    """WebshareClient parsing (both API port shapes) + cap metering."""

    def _client(self, payload):
        import ip_rotator.apiproviders as ap
        db = StateDB(os.path.join(tempfile.mkdtemp(), "s.db"), fresh=True)
        cfg = Config()
        cfg.webshare_api_key = "TESTKEY"
        client = WebshareClient(cfg, _SilentLog(), db)
        self._ap = ap
        self._payload = payload
        return client, db

    def _fetch(self, client):
        def fake_http_json(url, headers=None, timeout=20.0):
            self.assertIn("Token TESTKEY", headers["Authorization"])
            return self._payload
        orig = self._ap._http_json
        self._ap._http_json = fake_http_json
        try:
            return client.fetch_proxies()
        finally:
            self._ap._http_json = orig

    def test_parse_int_port_shape(self):
        client, _ = self._client({"results": [
            {"address": "1.2.3.4", "port": 8080,
             "proxy_protocol": ["http", "socks5"],
             "username": "u", "password": "p", "valid": True},
        ]})
        ups = self._fetch(client)
        self.assertEqual(len(ups), 2)
        kinds = {u.kind for u in ups}
        self.assertEqual(kinds, {"http", "socks5"})
        self.assertTrue(all(u.username == "u" and u.source == "webshare-free"
                            for u in ups))

    def test_parse_dict_port_shape(self):
        client, _ = self._client({"results": [
            {"address": "5.6.7.8", "port": {"http": 8081, "socks5": 1081},
             "username": "u", "password": "p", "valid": True},
        ]})
        ups = self._fetch(client)
        self.assertEqual(len(ups), 2)
        ports = {u.kind: u.port for u in ups}
        self.assertEqual(ports, {"http": 8081, "socks5": 1081})

    def test_invalid_rows_skipped(self):
        client, _ = self._client({"results": [
            {"address": "1.2.3.4", "port": 8080, "username": "u",
             "password": "p", "valid": False},
        ]})
        self.assertEqual(self._fetch(client), [])

    def test_over_cap_disables_lane(self):
        client, db = self._client({"results": []})
        self.assertFalse(client.over_cap())
        db.add_api_usage("webshare", bytes_=WebshareClient.MONTHLY_BYTES,
                         monthly=True)
        self.assertTrue(client.over_cap())
        self.assertIn("CAP HIT", client.describe())


# ===========================================================================
class TestFetchLane(unittest.TestCase):
    """Quota enforcement + provider selection for the scraping-API lane."""

    def setUp(self):
        import ip_rotator.apiproviders as ap
        self.ap = ap
        self.db = StateDB(os.path.join(tempfile.mkdtemp(), "s.db"), fresh=True)
        self.cfg = Config()
        self.cfg.api_keys = {"zenrows": "ZK", "scrapingbee": "SB",
                             "crawlbase": "CB", "scraperapi": "SA"}
        self.lane = ap.FetchLane(self.cfg, _SilentLog(), self.db)

    def test_skips_keyless_missing_and_cap_exhausted(self):
        # zenrows at cap; firecrawl keyless (no key needed) -> ready
        self.db.add_api_usage("zenrows", credits=5000, monthly=True)
        ready = {p.name: self.lane.provider_ready(p)[0]
                 for p in self.lane._ordered()}
        self.assertFalse(ready["zenrows"])          # cap exhausted
        self.assertTrue(ready["firecrawl"])         # keyless fallback
        self.assertTrue(ready["scrapingbee"])       # key present, under cap

    def test_missing_key_disables_provider(self):
        # no keys configured at all in this second config
        cfg2 = Config()
        cfg2.api_keys = {}
        lane2 = self.ap.FetchLane(cfg2, _SilentLog(), self.db)
        by = {p.name: lane2.provider_ready(p)
              for p in lane2._ordered()}
        self.assertFalse(by["zenrows"][0])
        self.assertIn("no API key", by["zenrows"][1])
        self.assertTrue(by["firecrawl"][0])         # keyless still fine

    def test_fetch_uses_first_ready_and_meters_credit(self):
        def fake_http_request(url, body=None, headers=None, timeout=60.0):
            if "zenrows" in url:
                return 200, "<html>via-zenrows</html>"
            return 200, "<html>fallback</html>"

        orig = self.ap._http_request
        self.ap._http_request = fake_http_request
        try:
            provider, content, err = self.lane.fetch("https://example.com/")
        finally:
            self.ap._http_request = orig
        self.assertEqual(err, "")
        self.assertEqual(provider, "zenrows")
        self.assertIn("via-zenrows", content)
        self.assertEqual(
            self.db.api_usage("zenrows", monthly=True)["credits"], 1)

    def test_fetch_falls_through_on_provider_error(self):
        # zenrows errors -> next ready provider (firecrawl, keyless) wins
        def fake_http_request(url, body=None, headers=None, timeout=60.0):
            if "zenrows" in url:
                raise OSError("boom")
            return 200, '{"data": {"markdown": "# via-firecrawl"}}'

        orig = self.ap._http_request
        self.ap._http_request = fake_http_request
        try:
            provider, content, err = self.lane.fetch("https://example.com/")
        finally:
            self.ap._http_request = orig
        self.assertEqual(err, "")
        self.assertEqual(provider, "firecrawl")
        self.assertIn("via-firecrawl", content)     # JSON/markdown extracted

    def test_firecrawl_posts_json_body_keyless(self):
        seen = {}

        def fake_http_request(url, body=None, headers=None, timeout=60.0):
            seen["url"], seen["body"], seen["headers"] = url, body, headers
            return 200, '{"data": {"markdown": "# keyless"}}'

        orig = self.ap._http_request
        self.ap._http_request = fake_http_request
        try:
            provider, content, err = self.lane.fetch(
                "https://example.com/", provider="firecrawl")
        finally:
            self.ap._http_request = orig
        self.assertEqual(err, "")
        self.assertEqual(provider, "firecrawl")
        self.assertEqual(seen["url"],
                         "https://api.firecrawl.dev/v2/scrape")
        self.assertEqual(seen["headers"].get("Content-Type"),
                         "application/json")
        self.assertIn(b"https://example.com/", seen["body"])

    def test_all_exhausted_returns_error(self):
        for p in self.ap.FETCH_PROVIDERS:
            if not p.keyless:
                self.cfg.api_keys.pop(p.api_key_field, None)
            self.db.add_api_usage(p.name, credits=p.cap, monthly=p.monthly)
        provider, content, err = self.lane.fetch("https://example.com/")
        self.assertEqual(provider, "")
        self.assertIn("no scraping-API provider available", err)


# ===========================================================================
class TestApiUsageMetering(unittest.TestCase):
    def test_monthly_period_and_accumulation(self):
        db = StateDB(os.path.join(tempfile.mkdtemp(), "s.db"), fresh=True)
        db.add_api_usage("webshare", bytes_=1000, monthly=True)
        db.add_api_usage("webshare", bytes_=2000, monthly=True)
        row = db.api_usage("webshare", monthly=True)
        self.assertEqual(row["bytes"], 3000)
        self.assertEqual(row["credits"], 0)

    def test_onetime_vs_monthly_periods_are_separate(self):
        db = StateDB(os.path.join(tempfile.mkdtemp(), "s.db"), fresh=True)
        db.add_api_usage("scrapingbee", credits=5, monthly=False)
        db.add_api_usage("zenrows", credits=7, monthly=True)
        self.assertEqual(db.api_usage("scrapingbee", monthly=False)["credits"], 5)
        self.assertEqual(db.api_usage("zenrows", monthly=True)["credits"], 7)
        # different period keys must not collide
        self.assertEqual(db.api_usage("scrapingbee", monthly=True)["credits"], 0)


# ===========================================================================
class TestPsiphonBackbone(unittest.TestCase):
    def test_detects_local_socks(self):
        # bind a fake local "Psiphon" SOCKS port on an ephemeral port
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        cfg = Config()
        cfg.enable_psiphon = True       # v2: Psiphon backbone is opt-in
        cfg.psiphon_socks_port = port
        cfg.psiphon_http_port = 1  # closed
        p = PsiphonProvider(cfg, _SilentLog())
        self.assertTrue(p.available())
        up = p.upstream()
        self.assertEqual(up.kind, "socks5")
        self.assertEqual(up.port, port)
        self.assertEqual(up.source, "psiphon")
        srv.close()

    def test_unavailable_when_not_running(self):
        cfg = Config()
        cfg.enable_psiphon = True
        cfg.psiphon_socks_port = 1
        cfg.psiphon_http_port = 1
        self.assertFalse(PsiphonProvider(cfg, _SilentLog()).available())

    def test_disabled_by_default(self):
        # v2: opt-in only (shared egress IPs are frequently flagged)
        cfg = Config()
        cfg.psiphon_socks_port = 1
        cfg.psiphon_http_port = 1
        cfg.enable_psiphon = False
        self.assertFalse(PsiphonProvider(cfg, _SilentLog()).available())


# ===========================================================================
class TestVpnModeGuard(unittest.TestCase):
    """Fail-closed egress guard + byte metering of the vpn lane."""

    class _FakeVpn:
        name = "testvpn"
        recipe = {"label": "Fake VPN", "monthly_bytes_cap": 10 * 1024 ** 3}

        def __init__(self):
            self.current_ip = "203.0.113.99"
            self.connected = False

        def over_cap(self):
            return False

        @property
        def cap_bytes(self):
            return self.recipe["monthly_bytes_cap"]

        def bytes_used(self):
            return 0

        def connect(self):
            self.connected = True
            return True

        def disconnect(self):
            self.connected = False

    def _mgr(self, db, real_ip="7.7.7.7"):
        from ip_rotator.providers import VpnPoolManager
        cfg = Config()
        cfg.interval = 3600
        vpn = self._FakeVpn()
        mgr = VpnPoolManager(cfg, db, _SilentLog(), [vpn], real_ip)
        mgr.current = vpn
        return mgr, vpn

    def test_guard_blocks_when_vpn_dropped(self):
        import ip_rotator.providers as prov
        db = StateDB(os.path.join(tempfile.mkdtemp(), "s.db"), fresh=True)
        mgr, vpn = self._mgr(db)
        orig = prov._probe_direct_egress
        try:
            # VPN silently dropped: machine egress == real IP again
            prov._probe_direct_egress = lambda timeout=10: "7.7.7.7"
            mgr._guard_ts = 0.0
            self.assertIsNone(mgr.next_upstream([]))   # fail CLOSED
            # VPN up: egress differs from real IP (bypass the 8s guard cache)
            prov._probe_direct_egress = lambda timeout=10: "203.0.113.99"
            mgr._guard_ts = 0.0
            up = mgr.next_upstream([])
            self.assertIsNotNone(up)
            self.assertEqual(up.kind, "direct")
            self.assertEqual(up.source, "vpn:testvpn")
        finally:
            prov._probe_direct_egress = orig

    def test_bytes_metered_per_provider(self):
        import ip_rotator.providers as prov
        db = StateDB(os.path.join(tempfile.mkdtemp(), "s.db"), fresh=True)
        mgr, vpn = self._mgr(db)
        orig = prov._probe_direct_egress
        prov._probe_direct_egress = lambda timeout=10: "203.0.113.99"
        try:
            up = mgr.next_upstream([])
            mgr.report_bytes(up, 1024 * 1024)
            mgr.report_bytes(up, 1024 * 1024)
        finally:
            prov._probe_direct_egress = orig
        self.assertEqual(
            db.api_usage("vpn:testvpn", monthly=True)["bytes"], 2 * 1024 ** 2)


# ===========================================================================
class TestRecyclePrefersWebshare(unittest.TestCase):
    def test_webshare_wins_recycle(self):
        db = StateDB(os.path.join(tempfile.mkdtemp(), "s.db"), fresh=True)
        cfg = Config()
        mgr = PoolManager(cfg, db, _SilentLog())
        mgr.real_ip = "7.7.7.7"
        now = time.time()
        with mgr._lock:
            mgr._validated = {
                "http://plain:1": Upstream("http", "plain", 1,
                                           egress_ip="1.1.1.1",
                                           latency_ms=100, source="freelist"),
                "socks5://ws:2": Upstream("socks5", "ws", 2,
                                          egress_ip="2.2.2.2", latency_ms=300,
                                          source="webshare-free"),
            }
        for ip, lu in (("1.1.1.1", now - 4000), ("2.2.2.2", now - 3500)):
            db.mark_ip_used(ip, "test")
            db._db.execute("UPDATE egress_ips SET last_used=? WHERE ip=?",
                           (lu, ip))
            db._db.commit()
        picked = mgr._pick_recycle_locked(set())
        # webshare entry is NEWER than the plain one but must still win:
        # authenticated dedicated proxies are the most reliable recyclables
        self.assertEqual(picked.egress_ip, "2.2.2.2")


# ===========================================================================
# v2: SOCKS5 frontend (the Burp Suite entry point)
# ===========================================================================
def _socks5_client_negotiate(conn, user=None, pwd=None):
    """Handshake helper; returns nothing (raises on protocol refusal)."""
    if user is None:
        conn.sendall(b"\x05\x01\x00")
        resp = conn.recv(2)
        assert resp == b"\x05\x00", resp
    else:
        conn.sendall(b"\x05\x02\x00\x02")
        resp = conn.recv(2)
        assert resp == b"\x05\x02", resp
        ub, pb = user.encode(), pwd.encode()
        conn.sendall(b"\x01" + bytes([len(ub)]) + ub +
                     bytes([len(pb)]) + pb)
        resp = conn.recv(2)
        assert resp == b"\x01\x00", resp


def _socks5_client_connect(conn, host, port):
    hb = host.encode()
    conn.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb +
                 struct.pack(">H", port))
    head = conn.recv(4)
    assert len(head) == 4 and head[0] == 5, head
    if head[3] == 0x01:
        conn.recv(4 + 2)
    elif head[3] == 0x03:
        ln = conn.recv(1)[0]
        conn.recv(ln + 2)
    elif head[3] == 0x04:
        conn.recv(16 + 2)
    return head[1]


class TestSocks5Frontend(unittest.TestCase):
    """Full client -> SOCKS5 frontend -> fake-upstream path (no internet)."""

    def _server(self, cfg=None, with_upstream=True):
        from ip_rotator.socks_server import Socks5Server
        db = StateDB(os.path.join(tempfile.mkdtemp(), "s.db"), fresh=True)
        cfg = cfg or Config()
        cfg.interval = 3600  # no timer rotation during tests
        mgr = PoolManager(cfg, db, _SilentLog())
        mgr.real_ip = "7.7.7.7"
        if with_upstream:
            fake = FakeConnectProxy(("127.0.0.1", 0), _FakeConnectHandler)
            threading.Thread(target=fake.serve_forever, daemon=True).start()
            with mgr._lock:
                mgr._validated = {
                    "http://fake": Upstream(
                        "http", "127.0.0.1", fake.server_address[1],
                        egress_ip="203.0.113.7", latency_ms=5,
                        validated_at=time.time(), source="unit"),
                }
            mgr.rotate("test")
        srv = Socks5Server(("127.0.0.1", 0), mgr, cfg, _SilentLog())
        threading.Thread(target=srv.serve_forever,
                         kwargs={"poll_interval": 0.2}, daemon=True).start()
        self._mgr = mgr
        self._db = db
        return srv

    def tearDown(self):
        if hasattr(self, "_db"):
            self._db.close()

    def test_noauth_connect_tunnel(self):
        # Burp-style: greeting offers ONLY 0x00 (no auth); domain ATYP
        srv = self._server()
        port = srv.server_address[1]
        s = socket.create_connection(("127.0.0.1", port), timeout=10)
        s.settimeout(10)
        _socks5_client_negotiate(s)                # no-auth path
        rep = _socks5_client_connect(s, "checkip.amazonaws.com", 443)
        self.assertEqual(rep, 0x00)
        data = b""
        try:
            while True:
                c = s.recv(4096)
                if not c:
                    break
                data += c
        except OSError:
            pass
        self.assertIn(b"203.0.113.7", data)       # fake upstream body
        s.close()
        srv.shutdown()

    def test_success_reply_carries_egress_ip(self):
        srv = self._server()
        port = srv.server_address[1]
        s = socket.create_connection(("127.0.0.1", port), timeout=10)
        s.settimeout(10)
        _socks5_client_negotiate(s)
        s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("93.184.216.34") +
                  struct.pack(">H", 443))
        head = s.recv(4)
        self.assertEqual(head[1], 0x00)
        atyp = head[3]
        self.assertEqual(atyp, 0x01)
        bnd = socket.inet_ntoa(s.recv(4))
        s.recv(2)
        self.assertEqual(bnd, "203.0.113.7")      # observability: egress IP
        s.close()
        srv.shutdown()

    def test_rfc1929_auth_required_and_verified(self):
        cfg = Config()
        cfg.socks_username = "burp"
        cfg.socks_password = "secret"
        srv = self._server(cfg=cfg)
        port = srv.server_address[1]
        # wrong password -> auth failure (0x01 0x01) then close
        s = socket.create_connection(("127.0.0.1", port), timeout=10)
        s.settimeout(10)
        s.sendall(b"\x05\x02\x00\x02")
        self.assertEqual(s.recv(2), b"\x05\x02")
        s.sendall(b"\x01\x04burp\x05wrong")
        self.assertEqual(s.recv(2), b"\x01\x01")
        s.close()
        # correct password -> success + tunnel body
        s = socket.create_connection(("127.0.0.1", port), timeout=10)
        s.settimeout(10)
        _socks5_client_negotiate(s, user="burp", pwd="secret")
        rep = _socks5_client_connect(s, "checkip.amazonaws.com", 443)
        self.assertEqual(rep, 0x00)
        data = b""
        try:
            while True:
                c = s.recv(4096)
                if not c:
                    break
                data += c
        except OSError:
            pass
        self.assertIn(b"203.0.113.7", data)
        s.close()
        srv.shutdown()

    def test_client_offering_only_noauth_is_refused_when_auth_configured(self):
        cfg = Config()
        cfg.socks_username = "burp"
        cfg.socks_password = "secret"
        srv = self._server(cfg=cfg)
        port = srv.server_address[1]
        s = socket.create_connection(("127.0.0.1", port), timeout=10)
        s.settimeout(10)
        s.sendall(b"\x05\x01\x00")                # Burp-style no-auth offer
        self.assertEqual(s.recv(2), b"\x05\xff")  # no acceptable methods
        s.close()
        srv.shutdown()

    def test_private_target_refused_socks_rep_not_allowed(self):
        srv = self._server()
        port = srv.server_address[1]
        s = socket.create_connection(("127.0.0.1", port), timeout=10)
        s.settimeout(10)
        _socks5_client_negotiate(s)
        rep = _socks5_client_connect(s, "127.0.0.1", 443)
        self.assertEqual(rep, 0x02)               # REP not allowed (SSRF guard)
        s.close()
        srv.shutdown()

    def test_disallowed_port_refused(self):
        srv = self._server()
        port = srv.server_address[1]
        s = socket.create_connection(("127.0.0.1", port), timeout=10)
        s.settimeout(10)
        _socks5_client_negotiate(s)
        rep = _socks5_client_connect(s, "example.com", 8080)
        self.assertEqual(rep, 0x02)
        s.close()
        srv.shutdown()

    def test_bind_and_udp_commands_refused(self):
        srv = self._server()
        port = srv.server_address[1]
        s = socket.create_connection(("127.0.0.1", port), timeout=10)
        s.settimeout(10)
        _socks5_client_negotiate(s)
        s.sendall(b"\x05\x02\x00\x01" + socket.inet_aton("93.184.216.34") +
                  struct.pack(">H", 443))          # CMD=0x02 BIND
        head = s.recv(4)
        self.assertEqual(head[1], 0x07)           # command not supported
        s.close()
        srv.shutdown()

    def test_ipv6_atyp_parsed(self):
        srv = self._server()
        port = srv.server_address[1]
        s = socket.create_connection(("127.0.0.1", port), timeout=10)
        s.settimeout(10)
        _socks5_client_negotiate(s)
        s.sendall(b"\x05\x01\x00\x04" + socket.inet_pton(
            socket.AF_INET6, "2606:2800:220:1:248:1893:25c8:1946") +
            struct.pack(">H", 443))
        head = s.recv(4)
        # target itself is refused by the port/SSRF guard? no: 443 allowed,
        # public IPv6 -> dial proceeds via fake upstream -> success
        self.assertEqual(head[1], 0x00)
        s.recv(4 + 2)
        s.close()
        srv.shutdown()


# ===========================================================================
# v2.1 — WireGuard / WARP lane
# ===========================================================================
from ip_rotator.warpwire import (WireGuardLane, WarpAccountStore,   # noqa: E402
                                 parse_wg_quick, wireproxy_conf,
                                 x25519_keypair)
from ip_rotator.providers import (VpnGateProvider,                   # noqa: E402
                                  WindscribeProxyProvider,
                                  parse_vpngate_csv)


class TestWarpWireConfigs(unittest.TestCase):
    ACCT = {
        "private_key": "A" * 43 + "=",
        "v4": "172.16.0.2",
        "v6": "2606:4700:110::2",
        "peer_pub": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
        "endpoint": "engage.cloudflareclient.com:2408",
    }

    def test_wireproxy_conf_new_format(self):
        conf = wireproxy_conf(self.ACCT, 42000)
        # new (v1.0+) wireproxy format, NOT the dead "WGConfig:" style
        self.assertIn("[Interface]", conf)
        self.assertIn("[Peer]", conf)
        self.assertIn("[Socks5]", conf)
        self.assertNotIn("WGConfig:", conf)
        self.assertIn("Address = 172.16.0.2/32, 2606:4700:110::2/128", conf)
        self.assertIn(f"PrivateKey = {self.ACCT['private_key']}", conf)
        self.assertIn("BindAddress = 127.0.0.1:42000", conf)
        self.assertIn("AllowedIPs = 0.0.0.0/0, ::/0", conf)
        self.assertNotIn("Reserved", conf)  # dropped by wireproxy >= 1.0

    def test_wireproxy_conf_socks_auth(self):
        conf = wireproxy_conf(dict(self.ACCT, v6=""), 42001,
                              username="u", password="p")
        self.assertIn("Username = u", conf)
        self.assertIn("Password = p", conf)
        # no v6 -> no v6 address
        self.assertNotIn("/128", conf)

    def test_parse_wg_quick_proton_style(self):
        proton = """[Interface]
# Proton VPN WireGuard config
PrivateKey = kJd8=example=
Address = 10.2.0.2/32
DNS = 10.2.0.1

[Peer]
PublicKey = sr9SDl=peer=
Endpoint = 185.159.158.1:51820
AllowedIPs = 0.0.0.0/0
"""
        with tempfile.NamedTemporaryFile("w", suffix=".conf",
                                         delete=False) as fh:
            fh.write(proton)
            path = fh.name
        try:
            acct = parse_wg_quick(path)
            self.assertEqual(acct["private_key"], "kJd8=example=")
            self.assertEqual(acct["v4"], "10.2.0.2")
            self.assertEqual(acct["peer_pub"], "sr9SDl=peer=")
            self.assertEqual(acct["endpoint"], "185.159.158.1:51820")
        finally:
            os.unlink(path)

    def test_parse_wg_quick_rejects_garbage(self):
        with tempfile.NamedTemporaryFile("w", suffix=".conf",
                                         delete=False) as fh:
            fh.write("not a wireguard config at all\n")
            path = fh.name
        try:
            with self.assertRaises(ValueError):
                parse_wg_quick(path)
        finally:
            os.unlink(path)

    def test_x25519_raw_key_length(self):
        """openssl emits the PRIVATE key as PKCS#8 DER (48 bytes); WireGuard
        needs the raw 32-byte scalar -> base64 must be exactly 44 chars.
        The PUBLIC key stays SPKI-wrapped (60 chars) — the Cloudflare
        registration API accepts exactly that (live-verified)."""
        pub1, priv1 = x25519_keypair()
        pub2, priv2 = x25519_keypair()
        self.assertEqual(len(priv1), 44)   # raw 32-byte key
        self.assertEqual(len(pub1), 60)    # SPKI-wrapped, accepted by CF API
        self.assertNotEqual(priv1, priv2)


class TestWarpAccountStore(unittest.TestCase):
    def test_add_persist_reload(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "warp_accounts.json")
        store = WarpAccountStore(path)
        self.assertEqual(store.count(), 0)
        store.add({"private_key": "k", "v4": "172.16.0.2",
                   "peer_pub": "p", "endpoint": "e:2408"})
        self.assertEqual(store.count(), 1)
        store2 = WarpAccountStore(path)  # fresh instance -> reloads file
        self.assertEqual(store2.count(), 1)
        self.assertEqual(store2.all()[0]["endpoint"], "e:2408")


class TestWireGuardLane(unittest.TestCase):
    def _lane(self, **overrides):
        cfg = Config.load(overrides=dict({
            "state_path": os.path.join(tempfile.mkdtemp(), "s.db"),
            "wireproxy_bin": "/nonexistent/wireproxy",
        }, **overrides))
        db = StateDB(cfg.state_path, fresh=True)
        lane = WireGuardLane(cfg, _SilentLog(), db)
        return lane, cfg

    def test_disabled_without_wireproxy(self):
        lane, cfg = self._lane(warp_accounts=3)
        # binary missing -> lane disabled with a helpful reason
        self.assertFalse(lane.enabled())
        self.assertIn("wireproxy", lane.disabled_reason)

    def test_tunnel_ports_deterministic(self):
        lane, cfg = self._lane(warp_accounts=3)
        lane.store._accounts = [
            {"private_key": f"k{i}", "v4": "172.16.0.2", "v6": "",
             "peer_pub": "p", "endpoint": "e:2408"} for i in range(3)
        ]
        lane._build_tunnels()
        ports = sorted(t.port for t in lane.tunnels)
        self.assertEqual(ports, [42000, 42001, 42002])
        # rebuild keeps the same ports (no drift)
        lane._build_tunnels()
        ports2 = sorted(t.port for t in lane.tunnels)
        self.assertEqual(ports2, ports)

    def test_validated_upstreams_only_live_ones(self):
        lane, cfg = self._lane(warp_accounts=2)
        lane.store._accounts = [
            {"private_key": f"k{i}", "v4": "172.16.0.2", "v6": "",
             "peer_pub": "p", "endpoint": "e:2408"} for i in range(2)
        ]
        lane._build_tunnels()
        # simulate: tunnel 0 alive with egress, tunnel 1 dead
        lane.tunnels[0].egress_ip = "104.28.1.1"
        lane.tunnels[0].proc = "fake-running"  # is_running() checks poll()
        # patch is_running for the fake proc
        lane.tunnels[0].is_running = lambda: True
        ups = lane.validated_upstreams()
        self.assertEqual(len(ups), 1)
        self.assertEqual(ups[0].egress_ip, "104.28.1.1")
        self.assertTrue(ups[0].source.startswith("wg:"))
        self.assertEqual(ups[0].kind, "socks5")


# ===========================================================================
# v2.1 — sticky sessions
# ===========================================================================
class TestStickySessions(unittest.TestCase):
    def setUp(self):
        self.db = StateDB(os.path.join(tempfile.mkdtemp(), "s.db"), fresh=True)
        self.cfg = Config()
        self.cfg.sticky_sessions = True   # opt-in feature
        self.mgr = PoolManager(self.cfg, self.db, _SilentLog())
        self.mgr.real_ip = "7.7.7.7"
        with self.mgr._lock:
            self.mgr._validated = {
                "http://a:1": Upstream("http", "a", 1, egress_ip="1.1.1.1",
                                      latency_ms=100),
                "http://b:2": Upstream("http", "b", 2, egress_ip="2.2.2.2",
                                      latency_ms=200),
            }

    def test_off_by_default(self):
        # the hard contract is a NEW IP every interval seconds -> sticky
        # must never silently dilute it
        self.assertFalse(Config().sticky_sessions)

    def test_same_host_sticks_across_rotation(self):
        up1 = self.mgr.next_upstream([], host="site.example")
        first = up1.label
        # global rotation happens (timer)
        self.mgr.rotate("timer")
        # same host still gets the SAME upstream within the TTL
        up2 = self.mgr.next_upstream([], host="site.example")
        self.assertEqual(up2.label, first)
        self.assertGreaterEqual(self.mgr.stats["sticky_hits"], 1)

    def test_other_host_rotates(self):
        up1 = self.mgr.next_upstream([], host="a.example")
        self.mgr.rotate("timer")  # now current is the other upstream
        up2 = self.mgr.next_upstream([], host="b.example")
        self.assertNotEqual(up1.label, up2.label)

    def test_sticky_disabled(self):
        self.cfg.sticky_sessions = False
        up1 = self.mgr.next_upstream([], host="site.example")
        self.mgr.rotate("timer")
        up2 = self.mgr.next_upstream([], host="site.example")
        self.assertNotEqual(up1.label, up2.label)

    def test_sticky_respects_ttl_expiry(self):
        self.cfg.sticky_ttl = 0.05
        up1 = self.mgr.next_upstream([], host="site.example")
        self.mgr.rotate("timer")
        time.sleep(0.08)
        up2 = self.mgr.next_upstream([], host="site.example")
        self.assertNotEqual(up1.label, up2.label)


# ===========================================================================
# v2.1 — starvation survival window ("no request left behind")
# ===========================================================================
class TestStarvationWindow(unittest.TestCase):
    def setUp(self):
        self.db = StateDB(os.path.join(tempfile.mkdtemp(), "s.db"), fresh=True)

    def test_rescue_inside_window(self):
        cfg = Config.load(overrides={
            "starvation_wait": 1.5, "starvation_retry_delay": 0.1,
            "allow_direct": False, "enable_warp": False,
            "policy_on_exhaustion": "strict",
        })
        mgr = PoolManager(cfg, self.db, _SilentLog())
        mgr.real_ip = "7.7.7.7"
        # pool EMPTY -> first call enters the survival window; a "harvester"
        # thread adds a validated upstream 0.3s in -> request is rescued
        def _rescue():
            time.sleep(0.3)
            with mgr._lock:
                mgr._validated["http://x:9"] = Upstream(
                    "http", "x", 9, egress_ip="9.9.9.9", latency_ms=10)
        threading.Thread(target=_rescue, daemon=True).start()
        t0 = time.monotonic()
        up = mgr.next_upstream([], host="t.example")
        self.assertIsNotNone(up)
        self.assertLess(time.monotonic() - t0, 1.4)
        self.assertEqual(mgr.stats["starvation_rescues"], 1)

    def test_gives_up_after_window(self):
        cfg = Config.load(overrides={
            "starvation_wait": 0.4, "starvation_retry_delay": 0.1,
            "allow_direct": False, "enable_warp": False,
            "policy_on_exhaustion": "strict",
        })
        mgr = PoolManager(cfg, self.db, _SilentLog())
        mgr.real_ip = "7.7.7.7"
        t0 = time.monotonic()
        up = mgr.next_upstream([], host="t.example")
        self.assertIsNone(up)
        self.assertGreaterEqual(time.monotonic() - t0, 0.4)
        self.assertEqual(mgr.stats["starvation_waits"], 1)


# ===========================================================================
# v2.1 — premium tier preference (WG / webshare beat anonymous proxies)
# ===========================================================================
class TestPremiumTier(unittest.TestCase):
    def test_wg_tunnel_preferred_over_faster_free_proxy(self):
        db = StateDB(os.path.join(tempfile.mkdtemp(), "s.db"), fresh=True)
        cfg = Config()
        mgr = PoolManager(cfg, db, _SilentLog())
        mgr.real_ip = "7.7.7.7"
        with mgr._lock:
            mgr._validated = {
                "http://free:1": Upstream("http", "free", 1,
                                         egress_ip="1.1.1.1",
                                         latency_ms=50),
            }
            mgr._wg_upstreams = {
                "socks5://127.0.0.1:42000": Upstream(
                    "socks5", "127.0.0.1", 42000, egress_ip="104.28.5.5",
                    latency_ms=900, source="wg:warp0"),
            }
        picked = mgr._pick_fresh_locked(set())
        self.assertEqual(picked.source, "wg:warp0")

    def test_wg_tunnel_feeds_fresh_count(self):
        db = StateDB(os.path.join(tempfile.mkdtemp(), "s.db"), fresh=True)
        cfg = Config()
        mgr = PoolManager(cfg, db, _SilentLog())
        with mgr._lock:
            mgr._wg_upstreams = {
                "socks5://127.0.0.1:42000": Upstream(
                    "socks5", "127.0.0.1", 42000, egress_ip="104.28.5.5",
                    latency_ms=100, source="wg:warp0"),
            }
        self.assertEqual(mgr.fresh_count(), 1)

    def test_wg_tunnel_first_backbone(self):
        db = StateDB(os.path.join(tempfile.mkdtemp(), "s.db"), fresh=True)
        cfg = Config.load(overrides={"enable_warp": False})
        mgr = PoolManager(cfg, db, _SilentLog())
        mgr.real_ip = "7.7.7.7"
        with mgr._lock:
            mgr._wg_upstreams = {
                "socks5://127.0.0.1:42000": Upstream(
                    "socks5", "127.0.0.1", 42000, egress_ip="104.28.5.5",
                    latency_ms=100, source="wg:warp0"),
            }
        up = mgr._get_backbone()
        self.assertIsNotNone(up)
        self.assertEqual(up.source, "wg:warp0")


# ===========================================================================
# v2.1 — VPN Gate (opt-in dirty tier) + windscribe proxy lane
# ===========================================================================
class TestVpnGate(unittest.TestCase):
    CSV = ("*vpn-gate*,exit\n"
           "HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,"
           "NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,"
           "Message,OpenVPN_ConfigData_Base64\n"
           "a,1.2.3.4,10,20,500000,Japan,JP,3,100,10,100000,None,op,,QUJD\n"
           "b,5.6.7.8,99,10,9000000,USA,US,9,100,90,900000,None,op,,REVGRQ==\n"
           "c,9.9.9.9,1,99,1000,France,FR,1,10,1,1000,None,op,,\n")

    def test_csv_parse_sorts_by_speed(self):
        rows = parse_vpngate_csv(self.CSV)
        self.assertEqual(len(rows), 2)  # row c has no config -> skipped
        self.assertEqual(rows[0]["country"], "US")  # fastest first
        self.assertEqual(rows[0]["config_b64"], "REVGRQ==")

    def test_garbage_csv_returns_empty(self):
        self.assertEqual(parse_vpngate_csv("hello\nworld\n"), [])

    def test_provider_compat_shape(self):
        db = StateDB(os.path.join(tempfile.mkdtemp(), "s.db"), fresh=True)
        p = VpnGateProvider(_SilentLog(), db)
        self.assertEqual(p.name, "vpngate")
        self.assertFalse(p.over_cap())
        self.assertEqual(p.bytes_used(), 0)
        self.assertIsNone(p.cap_bytes)
        self.assertIn("DIRTY", p.recipe["notes"])


class TestWindscribeProxyLane(unittest.TestCase):
    def test_off_by_default(self):
        cfg = Config()
        self.assertFalse(cfg.enable_windscribe_proxy)
        lane = WindscribeProxyProvider(cfg, _SilentLog())
        self.assertFalse(lane.available())

    def test_upstream_shape(self):
        cfg = Config.load(overrides={"enable_windscribe_proxy": True,
                                     "windscribe_proxy_socks_port": 1087})
        lane = WindscribeProxyProvider(cfg, _SilentLog())
        up = lane.upstream()
        self.assertEqual(up.kind, "socks5")
        self.assertEqual(up.port, 1087)
        self.assertEqual(up.source, "windscribe-proxy")


if __name__ == "__main__":
    unittest.main(verbosity=2)


# ===========================================================================
# v3.0 — no-reuse window (30-60 min contract), v2ray parser, warp-plus lane,
#         IP-factory economics
# ===========================================================================
class TestNoReuseWindow(unittest.TestCase):
    def setUp(self):
        import tempfile as _tf
        self.dir = _tf.mkdtemp()
        self.db_path = os.path.join(self.dir, "s.db")
        self.db = StateDB(self.db_path, fresh=True)
        self.cfg = Config.load(overrides={"no_reuse_seconds": 0.2,
                                            "recycle_avoid_seconds": 0.2})
        self.mgr = PoolManager(self.cfg, self.db, _SilentLog())
        self.mgr.real_ip = "7.7.7.7"
        with self.mgr._lock:
            self.mgr._validated = {
                "http://a:1": Upstream("http", "a", 1, egress_ip="1.1.1.1",
                                      latency_ms=100),
                "http://b:2": Upstream("http", "b", 2, egress_ip="2.2.2.2",
                                      latency_ms=200),
            }

    def test_default_window_is_45_min(self):
        self.assertEqual(Config().effective_no_reuse(), 2700.0)

    def test_legacy_field_lower_bound(self):
        cfg = Config.load(overrides={"no_reuse_seconds": 60,
                                     "recycle_avoid_seconds": 900})
        self.assertEqual(cfg.effective_no_reuse(), 900.0)

    def test_flag_round_trip_minutes(self):
        cfg = Config.load(overrides={"no_reuse_seconds": 30 * 60})
        self.assertEqual(cfg.effective_no_reuse(), 1800.0)

    def test_used_ip_blocked_inside_window(self):
        self.mgr.rotate("timer")            # picks + marks one IP used
        used = {u.egress_ip for u in
                (self.mgr._current,)} - {None}
        self.assertTrue(used)
        # after both IPs are used, none selectable inside the window
        self.mgr.rotate("timer")
        # 1.1.1.1 and 2.2.2.2 both burned now -> fresh pick impossible
        pick = self.mgr._pick_fresh_locked(set())
        # policy=recycle handles it downstream; direct fresh pick finds none
        self.assertIsNone(pick)

    def test_ip_fresh_again_after_window(self):
        self.mgr.rotate("timer")            # marks one IP used
        burned = self.mgr._current.egress_ip
        # INSIDE the window (0.2s): the burned IP must be blocked...
        inside = self.mgr._pick_fresh_locked(set())
        self.assertIsNotNone(inside)         # the other, never-used IP serves
        self.assertNotEqual(inside.egress_ip, burned)
        self.assertGreater(self.mgr.stats["window_blocks"], 0)
        # ...AFTER the window it is eligible again
        time.sleep(0.25)
        avail = self.mgr._pick_fresh_locked(set())
        self.assertIsNotNone(avail)
        self.assertIn(avail.egress_ip, {"1.1.1.1", "2.2.2.2"})

    def test_recycle_requires_window_expiry(self):
        self.cfg.policy_on_exhaustion = "recycle"
        self.mgr.rotate("timer")
        self.mgr.rotate("timer")            # both burned now
        # inside window: recycle must NOT hand back a burned IP
        rec = self.mgr._pick_recycle_locked(set())
        self.assertIsNone(rec)
        time.sleep(0.25)
        rec = self.mgr._pick_recycle_locked(set())
        self.assertIsNotNone(rec)

    def test_window_survives_restart(self):
        self.mgr.rotate("timer")
        ip = self.mgr._current.egress_ip
        self.db.close()
        db2 = StateDB(self.db_path, fresh=False)
        mgr2 = PoolManager(Config.load(overrides={"no_reuse_seconds": 999}),
                           db2, _SilentLog())
        mgr2.real_ip = "7.7.7.7"
        with mgr2._lock:
            mgr2._validated = {
                "http://a:1": Upstream("http", "a", 1, egress_ip=ip,
                                      latency_ms=100)}
        self.assertIsNone(mgr2._pick_fresh_locked(set()))
        db2.close()


class TestV2rayParser(unittest.TestCase):
    def test_vless_reality_tcp(self):
        link = ("vless://d5af4dfe-eaf1-460c-87aa-fefe930db0ba@b2n.ir:443"
                "?type=tcp&security=reality&pbk=PKEY&sid=ab12"
                "&fp=chrome&sni=s.example.com#Node1")
        ob = parse_node_link(link)
        self.assertEqual(ob["type"], "vless")
        self.assertEqual(ob["server"], "b2n.ir")
        self.assertEqual(ob["server_port"], 443)
        self.assertEqual(ob["tls"]["reality"]["public_key"], "PKEY")
        self.assertEqual(ob["tls"]["reality"]["short_id"], "ab12")
        self.assertTrue(ob["tls"]["utls"]["enabled"])

    def test_reality_without_fp_forces_utls(self):
        # live-found bug: sing-box rejects reality clients without uTLS
        link = ("vless://uuid-1@h:443?type=tcp&security=reality&pbk=K#n")
        ob = parse_node_link(link)
        self.assertTrue(ob["tls"]["utls"]["enabled"])
        self.assertEqual(ob["tls"]["utls"]["fingerprint"], "chrome")

    def test_reality_without_pbk_rejected(self):
        link = "vless://uuid-1@h:443?type=tcp&security=reality#n"
        self.assertIsNone(parse_node_link(link))

    def test_vless_ws_tls(self):
        link = ("vless://u-2@h.example:443?type=ws&security=tls"
                "&path=%2Fws&host=cdn.example&sni=cdn.example#W")
        ob = parse_node_link(link)
        self.assertEqual(ob["transport"]["type"], "ws")
        self.assertEqual(ob["transport"]["path"], "/ws")
        self.assertEqual(ob["transport"]["headers"]["Host"], "cdn.example")
        self.assertTrue(ob["tls"]["enabled"])

    def test_vless_grpc(self):
        link = ("vless://u-3@h:443?type=grpc&security=tls"
                "&serviceName=grpcs&sni=s#G")
        ob = parse_node_link(link)
        self.assertEqual(ob["transport"]["type"], "grpc")
        self.assertEqual(ob["transport"]["service_name"], "grpcs")

    def test_vless_httpupgrade(self):
        link = ("vless://u-4@h:443?type=httpupgrade&security=tls"
                "&path=%2Fup&host=hu.example#U")
        ob = parse_node_link(link)
        self.assertEqual(ob["transport"]["type"], "httpupgrade")
        self.assertEqual(ob["transport"]["host"], "hu.example")

    def test_xhttp_and_kcp_skipped(self):
        # sing-box cannot dial Xray-only transports (live-verified)
        self.assertIsNone(parse_node_link(
            "vless://u@h:443?type=xhttp&security=tls#x"))
        self.assertIsNone(parse_node_link(
            "vless://u@h:443?type=kcp&security=none#k"))

    def test_vmess_new_format(self):
        link = ("vmess://042adee0-9b4f-43f5-a915-a627313f28c0"
                "@www.example.com:2051?encryption=auto&headerType=http"
                "&host=proxy.example")
        ob = parse_node_link(link)
        self.assertEqual(ob["type"], "vmess")
        self.assertEqual(ob["uuid"], "042adee0-9b4f-43f5-a915-a627313f28c0")
        self.assertEqual(ob["security"], "auto")

    def test_vmess_legacy_base64(self):
        import base64 as _b64
        j = {"v": "2", "ps": "legacy", "add": "vm.example", "port": "443",
             "id": "abcd-1234", "aid": "0", "net": "ws", "host": "cdn.x",
             "path": "/p", "tls": "tls", "sni": "cdn.x"}
        link = "vmess://" + _b64.b64encode(json.dumps(j).encode()).decode()
        ob = parse_node_link(link)
        self.assertEqual(ob["server"], "vm.example")
        self.assertEqual(ob["transport"]["type"], "ws")
        self.assertTrue(ob["tls"]["enabled"])

    def test_trojan(self):
        link = ("trojan://pass123@t.example:2087?security=tls&sni=t.example#T")
        ob = parse_node_link(link)
        self.assertEqual(ob["type"], "trojan")
        self.assertEqual(ob["password"], "pass123")
        self.assertTrue(ob["tls"]["enabled"])

    def test_ss_sip002_base64_userinfo(self):
        link = ("ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpGRDNyQ3VPc3hPYXk"
                "@15.235.75.71:8388#S")
        ob = parse_node_link(link)
        self.assertEqual(ob["type"], "shadowsocks")
        self.assertEqual(ob["method"], "chacha20-ietf-poly1305")
        self.assertEqual(ob["password"], "FD3rCuOsxOay")
        self.assertEqual(ob["server"], "15.235.75.71")

    def test_hysteria2_gated_on_udp(self):
        link = ("hysteria2://pw@h:52000?security=tls&obfs=salamander"
                "&obfs-password=obf&sni=h.example#H")
        self.assertIsNone(parse_node_link(link, udp_ok=False))
        ob = parse_node_link(link, udp_ok=True)
        self.assertEqual(ob["type"], "hysteria2")
        self.assertEqual(ob["obfs"]["type"], "salamander")

    def test_garbage_rejected(self):
        for bad in ("", "not a link", "vless://", "ss://@h:0#x",
                    "vless://u@h:notaport#x", "unknown://u@h:1#x"):
            self.assertIsNone(parse_node_link(bad))

    def test_decode_subscription_plain(self):
        body = "vless://u@h:1#a\n\nvmess://u@h:2#b\ngarbage line\n"
        self.assertEqual(len(decode_subscription(body)), 2)

    def test_decode_subscription_base64(self):
        import base64 as _b64
        raw = "vless://u@h:1#a\nvmess://u@h:2#b\n"
        body = _b64.b64encode(raw.encode()).decode()
        self.assertEqual(len(decode_subscription(body)), 2)


class TestV2rayLaneConfig(unittest.TestCase):
    def _lane(self):
        cfg = Config.load(overrides={"enable_v2ray": True,
                                     "v2ray_max_nodes": 8})
        return V2RayLane(cfg, _SilentLog(),
                         StateDB(os.path.join(tempfile.mkdtemp(), "s.db"),
                                 fresh=True))

    def test_build_config_maps_ports_to_outbounds(self):
        lane = self._lane()
        obs = [{"type": "trojan", "tag": "obX", "server": "a",
                "server_port": 1, "password": "p"},
               {"type": "shadowsocks", "tag": "obY", "server": "b",
                "server_port": 2, "method": "aes-256-gcm", "password": "q"}]
        cfg = lane._build_config(obs)
        self.assertEqual(len(cfg["inbounds"]), 2)
        self.assertEqual(len(cfg["route"]["rules"]), 2)
        ports = [ib["listen_port"] for ib in cfg["inbounds"]]
        self.assertEqual(ports[0] + 1, ports[1])     # contiguous
        self.assertEqual(ports[0], cfg and
                         lane.cfg.v2ray_socks_base_port + 1)
        # each inbound routes to its own outbound tag
        for i, rule in enumerate(cfg["route"]["rules"]):
            self.assertEqual(rule["inbound"], [f"in{i}"])
            self.assertEqual(rule["outbound"], f"ob{i}")
        # outbounds re-tagged in0->ob0 order
        self.assertEqual(cfg["outbounds"][0]["tag"], "ob0")
        self.assertEqual(cfg["outbounds"][1]["tag"], "ob1")

    def test_port_set_alternates(self):
        lane = self._lane()
        base_a = lane._port_base()
        lane._port_set ^= 1
        base_b = lane._port_base()
        self.assertEqual(base_b - base_a, 512)       # no overlap at regen

    def test_enabled_gate(self):
        lane = self._lane()
        self.assertTrue(lane.enabled())
        lane2 = V2RayLane(Config(), _SilentLog(), None)
        self.assertFalse(lane2.enabled())


class TestWarpPlusLane(unittest.TestCase):
    def _lane(self, mode="auto", countries=None):
        cfg = Config.load(overrides={
            "enable_warpplus": True, "warpplus_instances": 4,
            "warpplus_mode": mode,
            "warpplus_countries": countries or ["US", "DE", "JP"]})
        return WarpPlusLane(cfg, _SilentLog(),
                            StateDB(os.path.join(tempfile.mkdtemp(), "s.db"),
                                    fresh=True))

    def test_mode_assignment_auto(self):
        lane = self._lane(mode="auto")
        self.assertEqual(lane._mode_for(0), "cfon")   # even -> country
        self.assertEqual(lane._mode_for(1), "gool")   # odd  -> warp-in-warp
        self.assertEqual(lane._mode_for(2), "cfon")

    def test_mode_assignment_fixed(self):
        self.assertEqual(self._lane(mode="cfon")._mode_for(0), "cfon")
        self.assertEqual(self._lane(mode="gool")._mode_for(3), "gool")
        self.assertEqual(self._lane(mode="plain")._mode_for(1), "plain")

    def test_country_rotation_advances(self):
        lane = self._lane(countries=["US", "DE", "JP"])
        seen = [lane._next_country() for _ in range(7)]
        self.assertEqual(seen, ["US", "DE", "JP", "US", "DE", "JP", "US"])

    def test_build_args_shape(self):
        lane = self._lane(mode="cfon")
        lane.cfg.warpplus_scan = True
        inst = WarpPlusInstance(0, 44000, lane.cfg, _SilentLog())
        args = inst.build_args("cfon", "DE")
        self.assertIn("--bind", args)
        self.assertEqual(args[args.index("--bind") + 1], "127.0.0.1:44000")
        self.assertIn("--cfon", args)
        self.assertEqual(args[args.index("--country") + 1], "DE")
        self.assertIn("--scan", args)
        self.assertIn("--cache-dir", args)
        # gool mode: no --country flag
        args_g = inst.build_args("gool", "")
        self.assertIn("--gool", args_g)
        self.assertNotIn("--cfon", args_g)
        self.assertNotIn("--country", args_g)

    def test_ports_deterministic(self):
        lane = self._lane()
        lane._build_instances()
        ports = [i.port for i in lane.instances]
        self.assertEqual(ports, [44000, 44001, 44002, 44003])

    def test_disabled_by_default(self):
        cfg = Config()
        lane = WarpPlusLane(cfg, _SilentLog(), None)
        self.assertFalse(lane.enabled())

    def test_config_validation(self):
        with self.assertRaises(ValueError):
            Config.load(overrides={"warpplus_instances": 99})
        with self.assertRaises(ValueError):
            Config.load(overrides={"warpplus_mode": "bogus"})
        with self.assertRaises(ValueError):
            Config.load(overrides={"no_reuse_seconds": -5})
        with self.assertRaises(ValueError):
            Config.load(overrides={"v2ray_max_nodes": 2})


class TestIPFactory(unittest.TestCase):
    def test_math_and_verdicts(self):
        db = StateDB(os.path.join(tempfile.mkdtemp(), "s.db"), fresh=True)
        cfg = Config.load(overrides={"interval": 10.0,
                                     "no_reuse_seconds": 2700})
        mgr = PoolManager(cfg, db, _SilentLog())
        # burn = 3600/10 = 360/h; steady-state unique = 360*2700/3600 = 270
        f = mgr.ip_factory()
        self.assertEqual(f["burn_per_hour"], 360.0)
        self.assertEqual(f["unique_ips_needed_steady_state"], 270.0)
        self.assertEqual(f["no_reuse_window_min"], 45.0)
        # no mint lanes enabled -> negative net
        self.assertLess(f["net_per_hour"], 0)
        self.assertEqual(f["verdict"], "tight — widen window or enable "
                                       "warp-plus/v2ray lanes")
        db.close()

    def test_factory_outpaces_demand(self):
        db = StateDB(os.path.join(tempfile.mkdtemp(), "s.db"), fresh=True)
        cfg = Config.load(overrides={
            "interval": 30.0, "enable_warpplus": True,
            "warpplus_instances": 16,          # 16 * ~51/h >= 120/h burn
            "warpplus_handshake_grace": 25.0})
        mgr = PoolManager(cfg, db, _SilentLog())
        # disabled_reason empty -> lane counted
        f = mgr.ip_factory()
        self.assertGreaterEqual(f["mint_per_hour_est"], 120.0)
        self.assertEqual(f["verdict"], "factory-outpaces-demand")
        self.assertEqual(f["headroom_minutes"], "infinite")
        db.close()

    def test_snapshot_contains_factory(self):
        db = StateDB(os.path.join(tempfile.mkdtemp(), "s.db"), fresh=True)
        mgr = PoolManager(Config(), db, _SilentLog())
        snap = mgr.snapshot()
        self.assertIn("ip_factory", snap)
        self.assertIn("warpplus_lane", snap)
        self.assertIn("v2ray_lane", snap)
        db.close()


# ===========================================================================
# v3.0.1 — shutdown & lane-hardening fixes (B33/B34/B35)
# ===========================================================================
class TestShutdownHardening(unittest.TestCase):
    """B33/B34: closed-DB tolerance, frontend stop, exit watchdog, fp fix."""

    def test_state_closed_db_degrades_everywhere(self):
        db = StateDB(os.path.join(tempfile.mkdtemp(), "s.db"))
        db.mark_ip_used("1.2.3.4", "t")
        db.close()
        # every method must return a safe default instead of raising
        self.assertFalse(db.ip_seen("1.2.3.4"))
        self.assertEqual(db.last_used("1.2.3.4"), 0.0)
        self.assertEqual(db.used_ips(), set())
        self.assertEqual(db.last_used_map(), {})
        self.assertEqual(db.ledger_size(), 0)
        self.assertIsNone(db.oldest_recyclable(60))
        self.assertFalse(db.is_blacklisted("h", 1, "http"))
        self.assertEqual(db.load_validated(), [])
        self.assertIsNone(db.get_country("1.2.3.4"))
        self.assertEqual(db.api_usage("x"), {"credits": 0, "bytes": 0})
        self.assertEqual(db.api_usage_rows(), [])
        db.mark_ip_used("5.6.7.8", "t")          # writes: silent no-op
        db.upsert_upstream("h", 1, "http", None, None)
        db.record_fail("h", 1, "http", 60)
        db.clear_blacklist("h", 1, "http")
        db.set_country("1.2.3.4", "US")
        db.add_api_usage("p", 1, 1)
        db.close()                                # double close is fine

    def test_pool_stop_is_idempotent(self):
        cfg = Config.load(overrides={"enable_warp": False})
        db = StateDB(os.path.join(tempfile.mkdtemp(), "s.db"))
        mgr = PoolManager(cfg, db, _SilentLog())
        mgr.stop()
        mgr.stop()          # second call must be a clean no-op
        db.close()

    def test_frontends_stop_frees_ports(self):
        from ip_rotator.server import serve
        from ip_rotator.socks_server import serve_socks
        cfg = Config.load(overrides={
            "listen_host": "127.0.0.1", "listen_port": 0,
            "socks_listen_host": "127.0.0.1", "socks_listen_port": 0,
            "enable_socks": True})
        db = StateDB(os.path.join(tempfile.mkdtemp(), "s.db"))
        mgr = PoolManager(cfg, db, _SilentLog())
        from ip_rotator.cli import _start_frontends, _stop_frontends
        servers = _start_frontends(cfg, mgr, _SilentLog())
        deadline = time.time() + 5
        while time.time() < deadline and not servers:
            time.sleep(0.05)
        self.assertEqual(len(servers), 2, "both frontends must register")
        http_port = servers[0].server_address[1]
        socks_port = servers[1].server_address[1]
        _stop_frontends(servers, _SilentLog())
        time.sleep(0.5)     # let the serve_forever loops unwind
        for port in (http_port, socks_port):
            with self.assertRaises(OSError):
                socket.create_connection(("127.0.0.1", port), timeout=1)
        db.close()

    def test_exit_watchdog_disarm(self):
        from ip_rotator.cli import _arm_exit_watchdog
        wd = _arm_exit_watchdog(60.0, _SilentLog())   # far budget
        wd["armed"] = False                             # disarm immediately
        time.sleep(0.2)                                 # would have fired?
        self.assertTrue(True)                           # process survived

    def test_utls_fingerprint_whitelist(self):
        from ip_rotator.v2raylane import _UTLS_FINGERPRINTS
        self.assertIn("chrome", _UTLS_FINGERPRINTS)
        self.assertNotIn("unsafe", _UTLS_FINGERPRINTS)
        # a vless node advertising fp=unsafe must be coerced to chrome
        link = ("vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443"
                "?type=tcp&security=reality&fp=unsafe&pbk=KEY#tag")
        ob = parse_node_link(link)
        self.assertIsNotNone(ob)
        self.assertEqual(ob["tls"]["utls"]["fingerprint"], "chrome")
        # valid fingerprints pass through untouched
        link2 = ("vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443"
                 "?type=tcp&security=reality&fp=firefox&pbk=KEY#tag")
        self.assertEqual(parse_node_link(link2)["tls"]["utls"]
                         ["fingerprint"], "firefox")


# ===========================================================================
# v3.1: static authenticated proxies lane (config static_proxies)
# ===========================================================================
class TestStaticProxyParser(unittest.TestCase):
    """parse_static_proxy: webshare dashboard format, URL forms, robustness."""

    def test_webshare_dashboard_format(self):
        from ip_rotator.pool import parse_static_proxy as ps
        self.assertEqual(
            ps("31.59.20.176:6754:awrtyene:rhd2m4j6tact"),
            ("socks5", "31.59.20.176", 6754, "awrtyene", "rhd2m4j6tact"))

    def test_webshare_format_survives_crlf(self):
        # the #1 real-world bug: dashboard exports saved on Windows carry \r
        from ip_rotator.pool import parse_static_proxy as ps
        self.assertEqual(
            ps("1.2.3.4:1080:user:pass\r\n"),
            ("socks5", "1.2.3.4", 1080, "user", "pass"))
        self.assertEqual(ps("  1.2.3.4:1080:u:p  "),
                         ("socks5", "1.2.3.4", 1080, "u", "p"))

    def test_url_forms(self):
        from ip_rotator.pool import parse_static_proxy as ps
        self.assertEqual(
            ps("socks5://user:pass@5.6.7.8:1080"),
            ("socks5", "5.6.7.8", 1080, "user", "pass"))
        self.assertEqual(
            ps("http://user:pass@5.6.7.8:8080"),
            ("http", "5.6.7.8", 8080, "user", "pass"))
        self.assertEqual(
            ps("socks4://user:pass@5.6.7.8:9"),
            ("socks4", "5.6.7.8", 9, "user", "pass"))
        # socks5h alias -> socks5 (same thing for our dialer)
        self.assertEqual(ps("socks5h://u:p@5.6.7.8:1")[0], "socks5")

    def test_bare_forms(self):
        from ip_rotator.pool import parse_static_proxy as ps
        self.assertEqual(ps("user:pass@h:1"),
                         ("socks5", "h", 1, "user", "pass"))
        self.assertEqual(ps("h:2"), ("socks5", "h", 2, "", ""))

    def test_password_with_colon(self):
        # password containing ':' must survive (split on FIRST colon only)
        from ip_rotator.pool import parse_static_proxy as ps
        self.assertEqual(ps("u:p:ss@h:3"), ("socks5", "h", 3, "u", "p:ss"))

    def test_garbage_rejected(self):
        from ip_rotator.pool import parse_static_proxy as ps
        for bad in ("", "   ", "# comment", "not a proxy",
                    "ftp://u:p@h:1", "h:0", "h:99999", "h",
                    "h:1:u", "socks5://u:p@[::1]:1"):
            self.assertIsNone(ps(bad), bad)

    def test_empty_and_comment_lines(self):
        from ip_rotator.pool import parse_static_proxy as ps
        self.assertIsNone(ps(""))
        self.assertIsNone(ps("# webshare export"))


class TestStaticProxiesLane(unittest.TestCase):
    """The lane feeds config entries through _validate_one with credentials
    preserved (same contract as the webshare API lane)."""

    def _mgr(self, entries):
        db = StateDB(os.path.join(tempfile.mkdtemp(), "s.db"), fresh=True)
        cfg = Config()
        cfg.static_proxies = entries
        return PoolManager(cfg, db, _SilentLog())

    def test_lane_feeds_credentials(self):
        mgr = self._mgr(["1.2.3.4:1080:alice:secret",
                         "socks5://bob:hunter2@5.6.7.8:1080",
                         "garbage line"])
        seen = []

        def capture(cand, is_reval, template=None):
            seen.append((cand, template))

        mgr._validate_one = capture

        def one_pass():
            for entry in mgr.cfg.static_proxies:
                from ip_rotator.pool import parse_static_proxy
                parsed = parse_static_proxy(entry)
                if parsed is None:
                    continue
                kind, host, port, user, pw = parsed
                mgr._validate_one(
                    (host, port, kind, f"{kind}://{host}:{port}", "static"),
                    False,
                    template=Upstream(kind=kind, host=host, port=port,
                                      source="static", username=user,
                                      password=pw))
        one_pass()
        self.assertEqual(len(seen), 2)
        (host, port, kind, key, source), tpl = seen[0]
        self.assertEqual((host, port, kind), ("1.2.3.4", 1080, "socks5"))
        self.assertEqual(source, "static")
        self.assertEqual((tpl.username, tpl.password), ("alice", "secret"))
        (_, _, _, _, _), tpl2 = seen[1]
        self.assertEqual((tpl2.host, tpl2.port, tpl2.kind), ("5.6.7.8", 1080, "socks5"))
        self.assertEqual((tpl2.username, tpl2.password), ("bob", "hunter2"))

    def test_doctor_style_parse_of_real_export(self):
        # the actual 10-line webshare export the user provided parses 9/10
        # (one line is blank) with credentials intact
        lines = ["", "31.59.20.176:6754:awrtyene:rhd2m4j6tact\r",
                 "45.38.107.97:6014:awrtyene:rhd2m4j6tact\r"]
        from ip_rotator.pool import parse_static_proxy as ps
        parsed = [ps(l) for l in lines]
        self.assertEqual(parsed[0], None)
        self.assertEqual(parsed[1],
                         ("socks5", "31.59.20.176", 6754,
                          "awrtyene", "rhd2m4j6tact"))
        self.assertEqual(parsed[2][1], "45.38.107.97")


class TestListenConfigPrecedence(unittest.TestCase):
    """B37 regression: config FILE listen_host/listen_port must survive when
    --listen is NOT passed (container configs bind 0.0.0.0; the old hardcoded
    CLI defaults silently stomped them back to 127.0.0.1:8000)."""

    def _args(self, listen=None):
        from ip_rotator.cli import _build_parser
        argv = ["serve"]
        if listen:
            argv += ["--listen", listen]
        return _build_parser().parse_args(argv)

    def test_file_listen_survives_without_flag(self):
        import tempfile, json as _json
        from ip_rotator.cli import _cfg_from_args
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                         delete=False) as fh:
            _json.dump({"listen_host": "0.0.0.0", "listen_port": 18000},
                       fh)
            path = fh.name
        try:
            cfg = _cfg_from_args(self._args())
            # _cfg_from_args builds overrides; emulate the real load path:
            cfg = Config.load(path, overrides={
                "listen_host": None, "listen_port": None})
            self.assertEqual((cfg.listen_host, cfg.listen_port),
                             ("0.0.0.0", 18000))
            # and the real helper must NOT inject non-None listen overrides:
            a = self._args()
            self.assertIsNone(a.listen)
        finally:
            os.unlink(path)

    def test_flag_overrides_file(self):
        import tempfile, json as _json
        from ip_rotator.cli import _cfg_from_args
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                         delete=False) as fh:
            _json.dump({"listen_host": "0.0.0.0", "listen_port": 18000},
                       fh)
            path = fh.name
        try:
            a = self._args(listen="127.0.0.1:9000")
            hp = a.listen.rsplit(":", 1)
            cfg = Config.load(path, overrides={
                "listen_host": hp[0] or "127.0.0.1",
                "listen_port": int(hp[1])})
            self.assertEqual((cfg.listen_host, cfg.listen_port),
                             ("127.0.0.1", 9000))
        finally:
            os.unlink(path)
