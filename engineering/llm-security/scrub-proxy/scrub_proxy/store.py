"""SQLite-backed placeholder mapping and detection cache.

Placeholders are deterministic: HMAC(local key, value) -> 8 hex chars, so the same
value always yields the same placeholder across requests and restarts. That keeps
Anthropic prompt-cache prefixes stable.
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time

PH_RE = re.compile(r"(?:PII|SEC)_[A-Z0-9]{1,20}_[0-9a-f]{8}")
# Values whose type is "word-like" only match at word boundaries in the known-value pass.
WORD_TYPES = {"NAME", "ADDRESS", "USER"}
MIN_KNOWN_LEN = 4


class CollisionError(RuntimeError):
    pass


class Store:
    def __init__(self, data_dir: str):
        os.makedirs(data_dir, mode=0o700, exist_ok=True)
        old_umask = os.umask(0o077)
        try:
            key_path = os.path.join(data_dir, "key")
            if not os.path.exists(key_path):
                fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.write(fd, secrets.token_bytes(32))
                os.close(fd)
            with open(key_path, "rb") as f:
                self.key = f.read()
            self.db = sqlite3.connect(
                os.path.join(data_dir, "map.db"), check_same_thread=False, isolation_level=None
            )
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.executescript(
                """
                CREATE TABLE IF NOT EXISTS mapping(
                    placeholder TEXT PRIMARY KEY, value TEXT UNIQUE NOT NULL,
                    type TEXT NOT NULL, created REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS cache(k TEXT PRIMARY KEY, v TEXT NOT NULL);
                """
            )
        finally:
            os.umask(old_umask)
        self.lock = threading.RLock()
        self.by_ph: dict[str, str] = {}
        self.by_val: dict[str, str] = {}
        self.types: dict[str, str] = {}
        for ph, val, typ in self.db.execute("SELECT placeholder, value, type FROM mapping"):
            self.by_ph[ph], self.by_val[val], self.types[val] = val, ph, typ
        self._known_re = None
        self._guard_re = None

    # ---- mapping -------------------------------------------------------
    def placeholder_for(self, kind: str, typ: str, value: str) -> str:
        with self.lock:
            ph = self.by_val.get(value)
            if ph:
                return ph
            digest = hmac.new(self.key, value.encode("utf-8"), hashlib.sha256).hexdigest()[:8]
            ph = f"{kind}_{typ}_{digest}"
            if ph in self.by_ph and self.by_ph[ph] != value:
                raise CollisionError(f"placeholder collision on {ph}")
            self.db.execute(
                "INSERT INTO mapping VALUES (?,?,?,?)", (ph, value, typ, time.time())
            )
            self.by_ph[ph], self.by_val[value], self.types[value] = value, ph, typ
            self._known_re = self._guard_re = None
            return ph

    def lookup(self, ph: str):
        return self.by_ph.get(ph)

    def known_regex(self):
        """Regex matching every previously mapped value (longest first)."""
        with self.lock:
            if self._known_re is None:
                vals = sorted(
                    (v for v in self.by_val if len(v) >= MIN_KNOWN_LEN), key=len, reverse=True
                )
                if not vals:
                    self._known_re = False
                else:
                    alts = []
                    for v in vals:
                        e = re.escape(v)
                        alts.append(rf"(?<!\w){e}(?!\w)" if self.types[v] in WORD_TYPES else e)
                    self._known_re = re.compile("|".join(alts))
            return self._known_re or None

    def guard_regex(self):
        """Matches any known value in raw or JSON-escaped form (final outbound check)."""
        with self.lock:
            if self._guard_re is None:
                forms = set()
                for v in self.by_val:
                    if len(v) < MIN_KNOWN_LEN:
                        continue
                    forms.add(v)
                    forms.add(json.dumps(v)[1:-1])
                    forms.add(json.dumps(v, ensure_ascii=False)[1:-1])
                if not forms:
                    self._guard_re = False
                else:
                    alts = []
                    for f in sorted(forms, key=len, reverse=True):
                        e = re.escape(f)
                        typ = self.types.get(f)
                        alts.append(rf"(?<!\w){e}(?!\w)" if typ in WORD_TYPES else e)
                    self._guard_re = re.compile("|".join(alts))
            return self._guard_re or None

    # ---- cache ---------------------------------------------------------
    def cache_get(self, k: str):
        row = self.db.execute("SELECT v FROM cache WHERE k=?", (k,)).fetchone()
        return json.loads(row[0]) if row else None

    def cache_set(self, k: str, v) -> None:
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO cache VALUES (?,?)", (k, json.dumps(v)))

    def stats(self):
        return dict(
            self.db.execute("SELECT type, COUNT(*) FROM mapping GROUP BY type ORDER BY 2 DESC")
        )
