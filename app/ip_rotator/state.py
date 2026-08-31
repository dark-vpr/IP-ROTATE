"""SQLite persistence: never-reuse IP ledger, upstream stats & blacklist.

Thread-safe via a single connection + lock. WAL mode for durability.
Persists across restarts so "never reuse an old IP" survives reboots.
"""
import os
import sqlite3
import threading
import time
from typing import Dict, List, Optional, Set, Tuple


class StateDB:
    def __init__(self, path: str, fresh: bool = False):
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        if fresh and os.path.exists(path):
            os.remove(path)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False, timeout=30)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS egress_ips(
                ip TEXT PRIMARY KEY, provider TEXT, first_seen REAL,
                last_used REAL, uses INTEGER);
            CREATE TABLE IF NOT EXISTS upstreams(
                host TEXT, port INTEGER, proto TEXT,
                egress_ip TEXT, latency_ms INTEGER, last_ok REAL,
                fails INTEGER DEFAULT 0, last_fail REAL DEFAULT 0,
                blacklist_until REAL DEFAULT 0,
                PRIMARY KEY(host, port, proto));
            CREATE TABLE IF NOT EXISTS geo(ip TEXT PRIMARY KEY, country TEXT);
            CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
            CREATE TABLE IF NOT EXISTS api_usage(
                provider TEXT, period TEXT,
                credits INTEGER DEFAULT 0, bytes INTEGER DEFAULT 0,
                updated REAL DEFAULT 0,
                PRIMARY KEY(provider, period));
            """
        )
        self._db.commit()

    # ------------------------- closed-DB tolerance (B33) -------------------
    # During shutdown the DB is closed while request-handler threads may
    # still call in. A closed DB must degrade to safe defaults, never raise
    # (the old behavior spewed ProgrammingError tracebacks mid-drain).
    _CLOSED_DEFAULTS = {
        "ip_seen": False, "last_used": 0.0, "used_ips": set(),
        "last_used_map": dict, "ledger_size": 0, "oldest_recyclable": None,
        "is_blacklisted": False, "load_validated": list,
        "get_country": None, "api_usage": dict,
        "api_usage_rows": list,
    }

    def _closed(self) -> bool:
        return self._db is None

    # ------------------------- IP ledger (never-reuse) ----------------------
    def ip_seen(self, ip: str) -> bool:
        with self._lock:
            if self._closed():
                return False
            row = self._db.execute(
                "SELECT 1 FROM egress_ips WHERE ip=?", (ip,)).fetchone()
        return row is not None

    def mark_ip_used(self, ip: str, provider: str) -> None:
        now = time.time()
        with self._lock:
            if self._closed():
                return
            self._db.execute(
                """INSERT INTO egress_ips(ip, provider, first_seen, last_used, uses)
                   VALUES(?,?,?, ?, 1)
                   ON CONFLICT(ip) DO UPDATE SET
                     last_used=excluded.last_used, uses=uses+1""",
                (ip, provider, now, now))
            self._db.commit()

    def last_used(self, ip: str) -> float:
        with self._lock:
            if self._closed():
                return 0.0
            row = self._db.execute(
                "SELECT last_used FROM egress_ips WHERE ip=?", (ip,)).fetchone()
        return row[0] if row else 0.0

    def used_ips(self) -> Set[str]:
        with self._lock:
            if self._closed():
                return set()
            rows = self._db.execute("SELECT ip FROM egress_ips").fetchall()
        return {r[0] for r in rows}

    def last_used_map(self) -> Dict[str, float]:
        """Bulk {ip: last_used_epoch} — powers the no-reuse window cache.
        (One scan instead of per-IP lookups; the pool keeps an incremental
        in-memory copy after the first load.)"""
        with self._lock:
            if self._closed():
                return {}
            rows = self._db.execute(
                "SELECT ip, last_used FROM egress_ips").fetchall()
        return {r[0]: r[1] for r in rows}

    def ledger_size(self) -> int:
        with self._lock:
            if self._closed():
                return 0
            return self._db.execute(
                "SELECT COUNT(*) FROM egress_ips").fetchone()[0]

    def oldest_recyclable(self, avoid_seconds: float) -> Optional[str]:
        """Least-recently-used egress IP whose last use is older than avoid_seconds."""
        cutoff = time.time() - avoid_seconds
        with self._lock:
            if self._closed():
                return None
            row = self._db.execute(
                """SELECT ip FROM egress_ips WHERE last_used < ?
                   ORDER BY last_used ASC LIMIT 1""", (cutoff,)).fetchone()
        return row[0] if row else None

    # ------------------------- upstream stats --------------------------------
    def upsert_upstream(self, host: str, port: int, proto: str,
                        egress_ip: Optional[str], latency_ms: Optional[int]) -> None:
        with self._lock:
            if self._closed():
                return
            self._db.execute(
                """INSERT INTO upstreams(host, port, proto, egress_ip, latency_ms,
                                         last_ok, fails, last_fail, blacklist_until)
                   VALUES(?,?,?,?,?,?,0,0,0)
                   ON CONFLICT(host, port, proto) DO UPDATE SET
                     egress_ip=excluded.egress_ip, latency_ms=excluded.latency_ms,
                     last_ok=excluded.last_ok, fails=0""",
                (host, port, proto, egress_ip, latency_ms, time.time()))
            self._db.commit()

    def record_fail(self, host: str, port: int, proto: str,
                    blacklist_seconds: float, force: bool = False,
                    threshold: int = 3) -> bool:
        """Returns True if this failure caused a blacklist.
        force=True blacklists immediately (MITM / transparent-proxy cases).
        v2 fix: the strike threshold is now a parameter (v1 hardcoded 3 and
        silently ignored Config.fail_threshold)."""
        now = time.time()
        with self._lock:
            if self._closed():
                return False
            # ensure the row exists (failure may arrive before any success)
            self._db.execute(
                """INSERT INTO upstreams(host, port, proto, egress_ip,
                                         latency_ms, last_ok, fails, last_fail,
                                         blacklist_until)
                   VALUES(?,?,?,NULL,NULL,0,0,0,0)
                   ON CONFLICT(host, port, proto) DO NOTHING""",
                (host, port, proto))
            self._db.execute(
                """UPDATE upstreams SET fails=fails+1, last_fail=?
                   WHERE host=? AND port=? AND proto=?""", (now, host, port, proto))
            row = self._db.execute(
                """SELECT fails FROM upstreams WHERE host=? AND port=? AND proto=?""",
                (host, port, proto)).fetchone()
            fails = row[0] if row else threshold
            blacklisted = force or fails >= max(1, threshold)
            if blacklisted:
                self._db.execute(
                    """UPDATE upstreams SET blacklist_until=?, fails=0
                       WHERE host=? AND port=? AND proto=?""",
                    (now + blacklist_seconds, host, port, proto))
            self._db.commit()
        return blacklisted

    def clear_blacklist(self, host: str, port: int, proto: str) -> None:
        with self._lock:
            if self._closed():
                return
            self._db.execute(
                """UPDATE upstreams SET blacklist_until=0, fails=0, last_ok=?
                   WHERE host=? AND port=? AND proto=?""",
                (time.time(), host, port, proto))
            self._db.commit()

    def is_blacklisted(self, host: str, port: int, proto: str) -> bool:
        with self._lock:
            if self._closed():
                return False
            row = self._db.execute(
                """SELECT blacklist_until FROM upstreams
                   WHERE host=? AND port=? AND proto=?""",
                (host, port, proto)).fetchone()
        return bool(row and row[0] > time.time())

    def load_validated(self, max_age: float = 1800.0
                       ) -> List[Tuple[str, int, str, str, int, float]]:
        """Recently-validated upstreams (fast warm start after restart)."""
        cutoff = time.time() - max_age
        with self._lock:
            if self._closed():
                return []
            rows = self._db.execute(
                """SELECT host, port, proto, egress_ip, latency_ms, last_ok
                   FROM upstreams
                   WHERE last_ok > ? AND blacklist_until < ? AND egress_ip IS NOT NULL
                   ORDER BY latency_ms ASC""",
                (cutoff, time.time())).fetchall()
        return rows

    # ------------------------- geo cache (optional country filter) ----------
    def get_country(self, ip: str) -> Optional[str]:
        with self._lock:
            if self._closed():
                return None
            row = self._db.execute("SELECT country FROM geo WHERE ip=?", (ip,)).fetchone()
        return row[0] if row else None

    def set_country(self, ip: str, country: str) -> None:
        with self._lock:
            if self._closed():
                return
            self._db.execute(
                "INSERT OR REPLACE INTO geo(ip, country) VALUES(?,?)", (ip, country))
            self._db.commit()

    # ------------------------- API / metered-provider usage -----------------
    @staticmethod
    def _period_key(monthly: bool) -> str:
        # monthly caps reset with the calendar month; one-time caps never do
        return time.strftime("%Y-%m") if monthly else "total"

    def add_api_usage(self, provider: str, credits: int = 0, bytes_: int = 0,
                      monthly: bool = False) -> None:
        period = self._period_key(monthly)
        now = time.time()
        with self._lock:
            if self._closed():
                return
            self._db.execute(
                """INSERT INTO api_usage(provider, period, credits, bytes, updated)
                   VALUES(?,?,?,?,?)
                   ON CONFLICT(provider, period) DO UPDATE SET
                     credits=credits+excluded.credits,
                     bytes=bytes+excluded.bytes, updated=excluded.updated""",
                (provider, period, credits, bytes_, now))
            self._db.commit()

    def api_usage(self, provider: str, monthly: bool = False) -> dict:
        """Current-period usage row {credits, bytes} for a metered provider.
        Monthly providers also fold in the previous month's stale row so a
        mid-flight month rollover never hides usage."""
        period = self._period_key(monthly)
        with self._lock:
            if self._closed():
                return {"credits": 0, "bytes": 0}
            row = self._db.execute(
                "SELECT credits, bytes FROM api_usage WHERE provider=? AND period=?",
                (provider, period)).fetchone()
        if row:
            return {"credits": row[0] or 0, "bytes": row[1] or 0}
        return {"credits": 0, "bytes": 0}

    def api_usage_rows(self) -> List[Tuple[str, str, int, int]]:
        with self._lock:
            if self._closed():
                return []
            return self._db.execute(
                "SELECT provider, period, credits, bytes FROM api_usage "
                "ORDER BY provider, period DESC").fetchall()

    def close(self) -> None:
        with self._lock:
            try:
                self._db.commit()
                self._db.close()
            except Exception:
                pass
            self._db = None   # B33: every method now degrades on closed DB
