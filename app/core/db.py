"""
OmniFetch Persistent SQLite Task Database (WAL Mode)
Crash-proof state ledger for tasks, segment offsets, and security gate audits.
"""

import base64
import re
import sqlite3
import os
import json
import threading
import time
from pathlib import Path
from urllib.parse import urlparse, urlunparse

DEFAULT_DB_PATH = str(Path.home() / ".omnifetch" / "omnifetch.db")

_ALLOWED_TASK_FIELDS = {
    "url", "filename", "destination", "staging_path", "engine_type", "status",
    "total_bytes", "downloaded_bytes", "speed_bps", "eta_seconds", "num_segments",
    "security_status", "threat_name", "threat_details", "error_message",
    "custom_headers", "resumable", "info_hash", "torrent_path", "file_priorities",
    "sequential", "stop_ratio", "selected_indices", "etag", "last_modified",
    "final_url", "origin_referer", "expires_at",
}

_ZERO_METRIC_STATUSES = {
    "PAUSED", "FAILED", "COMPLETED", "QUARANTINED", "QUEUED", "STAGED", "SCANNING", "LINK EXPIRED"
}


def extract_info_hash(value: str | None) -> str | None:
    """Extracts a normalized lowercase hex info_hash from a hex hash or magnet URI."""
    if not value or not isinstance(value, str):
        return None
    clean = value.strip()
    if re.fullmatch(r"[0-9a-fA-F]{40}", clean) or re.fullmatch(r"[0-9a-fA-F]{64}", clean):
        return clean.lower()
    m_hex = re.search(r"xt=urn:btih:([0-9a-fA-F]{40})(?:&|$)", clean, re.IGNORECASE)
    if m_hex:
        return m_hex.group(1).lower()
    m_b32 = re.search(r"xt=urn:btih:([A-Za-z2-7]{32})(?:&|$)", clean, re.IGNORECASE)
    if m_b32:
        try:
            return base64.b32decode(m_b32.group(1).upper()).hex().lower()
        except Exception:
            return m_b32.group(1).lower()
    m_v2 = re.search(r"xt=urn:btmh:1220([0-9a-fA-F]{64})(?:&|$)", clean, re.IGNORECASE)
    if m_v2:
        return m_v2.group(1).lower()
    return None


def normalize_url(url: str | None) -> str:
    """Canonicalizes HTTP/MEGA/magnet URLs for duplicate detection while preserving MEGA fragments."""
    if not url or not isinstance(url, str):
        return ""
    clean = url.strip()
    if clean.lower().startswith("magnet:"):
        ih = extract_info_hash(clean)
        return f"magnet:?xt=urn:btih:{ih}" if ih else clean
    try:
        p = urlparse(clean)
        if p.scheme and p.netloc:
            scheme = p.scheme.lower()
            netloc = p.netloc.lower()
            path = p.path or "/"
            if len(path) > 1 and path.endswith("/"):
                path = path.rstrip("/")
            # Keep fragment intact (essential for mega.nz/#key and /file/id#key)
            return urlunparse((scheme, netloc, path, p.params, p.query, p.fragment))
    except Exception:
        pass
    return clean


def _serialize_json_field(val):
    if val is None:
        return None
    if isinstance(val, str):
        return val
    return json.dumps(val)


def _deserialize_json_field(val):
    if isinstance(val, str):
        try:
            return json.loads(val)
        except Exception:
            return val
    return val


class Database:
    def __init__(self, db_path=DEFAULT_DB_PATH):
        self.db_path = db_path
        self._lock = threading.RLock()
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self):
        with self._lock, self.conn:
            if self.db_path != ":memory:":
                self.conn.execute("PRAGMA journal_mode = WAL;")
            self.conn.execute("PRAGMA foreign_keys = ON;")

            # Tasks Table
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY,
                    url TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    destination TEXT NOT NULL,
                    staging_path TEXT NOT NULL,
                    engine_type TEXT NOT NULL CHECK(engine_type IN ('HTTP', 'TORRENT', 'MEGA')),
                    status TEXT NOT NULL CHECK(status IN ('QUEUED', 'DOWNLOADING', 'PAUSED', 'STAGED', 'SCANNING', 'COMPLETED', 'QUARANTINED', 'FAILED', 'LINK EXPIRED')),
                    total_bytes INTEGER DEFAULT 0,
                    downloaded_bytes INTEGER DEFAULT 0,
                    speed_bps REAL DEFAULT 0.0,
                    eta_seconds INTEGER DEFAULT 0,
                    num_segments INTEGER DEFAULT 1,
                    security_status TEXT DEFAULT 'UNCHECKED' CHECK(security_status IN ('UNCHECKED', 'CLEAN', 'WARNING', 'CRITICAL')),
                    threat_name TEXT,
                    threat_details TEXT,
                    error_message TEXT,
                    custom_headers TEXT,
                    resumable INTEGER DEFAULT -1,
                    info_hash TEXT,
                    torrent_path TEXT,
                    file_priorities TEXT,
                    sequential INTEGER DEFAULT 0,
                    stop_ratio REAL,
                    selected_indices TEXT,
                    etag TEXT,
                    last_modified TEXT,
                    final_url TEXT,
                    origin_referer TEXT,
                    expires_at REAL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
            """)

            # Safe idempotent ALTER TABLE migrations for existing databases
            migrations = [
                ("custom_headers", "TEXT"),
                ("resumable", "INTEGER DEFAULT -1"),
                ("info_hash", "TEXT"),
                ("torrent_path", "TEXT"),
                ("file_priorities", "TEXT"),
                ("sequential", "INTEGER DEFAULT 0"),
                ("stop_ratio", "REAL"),
                ("selected_indices", "TEXT"),
                ("etag", "TEXT"),
                ("last_modified", "TEXT"),
                ("final_url", "TEXT"),
                ("origin_referer", "TEXT"),
                ("expires_at", "REAL"),
            ]
            existing_cols = {
                row["name"]
                for row in self.conn.execute("PRAGMA table_info(tasks);").fetchall()
            }
            for col_name, col_type in migrations:
                if col_name not in existing_cols:
                    try:
                        self.conn.execute(f"ALTER TABLE tasks ADD COLUMN {col_name} {col_type};")
                    except Exception:
                        pass

            # Ensure CHECK constraint allows 'LINK EXPIRED' on older databases
            tbl_row = self.conn.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='tasks';"
            ).fetchone()
            tbl_sql = tbl_row["sql"] if tbl_row and tbl_row["sql"] else ""
            if tbl_sql and "LINK EXPIRED" not in tbl_sql:
                cols = [
                    row["name"]
                    for row in self.conn.execute("PRAGMA table_info(tasks);").fetchall()
                ]
                col_list = ", ".join(cols)
                self.conn.execute("PRAGMA foreign_keys = OFF;")
                self.conn.execute("DROP TABLE IF EXISTS tasks_new;")
                self.conn.execute("""
                    CREATE TABLE tasks_new (
                        id TEXT PRIMARY KEY,
                        url TEXT NOT NULL,
                        filename TEXT NOT NULL,
                        destination TEXT NOT NULL,
                        staging_path TEXT NOT NULL,
                        engine_type TEXT NOT NULL CHECK(engine_type IN ('HTTP', 'TORRENT', 'MEGA')),
                        status TEXT NOT NULL CHECK(status IN ('QUEUED', 'DOWNLOADING', 'PAUSED', 'STAGED', 'SCANNING', 'COMPLETED', 'QUARANTINED', 'FAILED', 'LINK EXPIRED')),
                        total_bytes INTEGER DEFAULT 0,
                        downloaded_bytes INTEGER DEFAULT 0,
                        speed_bps REAL DEFAULT 0.0,
                        eta_seconds INTEGER DEFAULT 0,
                        num_segments INTEGER DEFAULT 1,
                        security_status TEXT DEFAULT 'UNCHECKED' CHECK(security_status IN ('UNCHECKED', 'CLEAN', 'WARNING', 'CRITICAL')),
                        threat_name TEXT,
                        threat_details TEXT,
                        error_message TEXT,
                        custom_headers TEXT,
                        resumable INTEGER DEFAULT -1,
                        info_hash TEXT,
                        torrent_path TEXT,
                        file_priorities TEXT,
                        sequential INTEGER DEFAULT 0,
                        stop_ratio REAL,
                        selected_indices TEXT,
                        etag TEXT,
                        last_modified TEXT,
                        final_url TEXT,
                        origin_referer TEXT,
                        expires_at REAL,
                        created_at REAL NOT NULL,
                        updated_at REAL NOT NULL
                    );
                """)
                self.conn.execute(f"INSERT INTO tasks_new ({col_list}) SELECT {col_list} FROM tasks;")
                self.conn.execute("DROP TABLE tasks;")
                self.conn.execute("ALTER TABLE tasks_new RENAME TO tasks;")
                self.conn.execute("PRAGMA foreign_keys = ON;")

            # Segments Table for Multi-Connection Resumption
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS segments (
                    task_id TEXT NOT NULL,
                    segment_index INTEGER NOT NULL,
                    start_byte INTEGER NOT NULL,
                    end_byte INTEGER NOT NULL,
                    current_byte INTEGER NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('PENDING', 'DOWNLOADING', 'COMPLETED', 'FAILED')),
                    PRIMARY KEY (task_id, segment_index),
                    FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE
                );
            """)

            # Security Audit Ledger
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS security_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL,
                    stage TEXT NOT NULL CHECK(stage IN ('PRE_DOWNLOAD', 'STAGING', 'POST_DOWNLOAD')),
                    verdict TEXT NOT NULL CHECK(verdict IN ('ALLOW_CLEAN', 'ALLOW_WARNING', 'BLOCK_CRITICAL')),
                    threat_name TEXT,
                    details TEXT,
                    timestamp REAL NOT NULL,
                    FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE
                );
            """)

    def add_task(self, task_data):
        now = time.time()
        with self._lock, self.conn:
            self.conn.execute("""
                INSERT OR REPLACE INTO tasks (
                    id, url, filename, destination, staging_path, engine_type, status,
                    total_bytes, downloaded_bytes, speed_bps, eta_seconds, num_segments,
                    security_status, threat_name, threat_details, error_message,
                    custom_headers, resumable, info_hash, torrent_path, file_priorities,
                    sequential, stop_ratio, selected_indices, etag, last_modified,
                    final_url, origin_referer, expires_at, created_at, updated_at
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                );
            """, (
                task_data["id"],
                task_data["url"],
                task_data["filename"],
                task_data["destination"],
                task_data["staging_path"],
                task_data.get("engine_type", "HTTP"),
                task_data.get("status", "QUEUED"),
                task_data.get("total_bytes", 0),
                task_data.get("downloaded_bytes", 0),
                task_data.get("speed_bps", 0.0),
                task_data.get("eta_seconds", 0),
                task_data.get("num_segments", 1),
                task_data.get("security_status", "UNCHECKED"),
                task_data.get("threat_name"),
                task_data.get("threat_details"),
                task_data.get("error_message"),
                _serialize_json_field(task_data.get("custom_headers")),
                task_data.get("resumable", -1),
                task_data.get("info_hash") or extract_info_hash(task_data.get("url")),
                task_data.get("torrent_path"),
                _serialize_json_field(task_data.get("file_priorities")),
                1 if task_data.get("sequential") else 0,
                task_data.get("stop_ratio"),
                _serialize_json_field(task_data.get("selected_indices")),
                task_data.get("etag"),
                task_data.get("last_modified"),
                task_data.get("final_url"),
                task_data.get("origin_referer"),
                task_data.get("expires_at"),
                task_data.get("created_at", now),
                now
            ))

    def update_task_fields(self, task_id, **fields):
        """Updates arbitrary allowlisted task columns safely inside the database RLock."""
        clean = {}
        for k, v in fields.items():
            if k not in _ALLOWED_TASK_FIELDS:
                continue
            if k in ("custom_headers", "file_priorities", "selected_indices"):
                clean[k] = _serialize_json_field(v)
            elif k == "sequential":
                clean[k] = 1 if v else 0
            else:
                clean[k] = v
        if not clean:
            return
        clean["updated_at"] = time.time()
        assignments = ", ".join(f"{col} = ?" for col in clean.keys())
        params = list(clean.values()) + [task_id]
        with self._lock, self.conn:
            self.conn.execute(f"UPDATE tasks SET {assignments} WHERE id = ?;", params)

    def update_task_progress(self, task_id, downloaded_bytes, total_bytes=None, speed_bps=0.0, eta_seconds=0):
        now = time.time()
        with self._lock, self.conn:
            if total_bytes is not None and total_bytes > 0:
                self.conn.execute("""
                    UPDATE tasks SET
                        downloaded_bytes = ?,
                        total_bytes = ?,
                        speed_bps = ?,
                        eta_seconds = ?,
                        updated_at = ?
                    WHERE id = ?;
                """, (downloaded_bytes, total_bytes, speed_bps, eta_seconds, now, task_id))
            else:
                self.conn.execute("""
                    UPDATE tasks SET
                        downloaded_bytes = ?,
                        speed_bps = ?,
                        eta_seconds = ?,
                        updated_at = ?
                    WHERE id = ?;
                """, (downloaded_bytes, speed_bps, eta_seconds, now, task_id))

    def update_task_filename(self, task_id, filename):
        now = time.time()
        with self._lock, self.conn:
            self.conn.execute("""
                UPDATE tasks SET filename = ?, updated_at = ? WHERE id = ?;
            """, (filename, now, task_id))

    def update_task_resumable(self, task_id, resumable: int):
        now = time.time()
        with self._lock, self.conn:
            self.conn.execute("""
                UPDATE tasks SET resumable = ?, updated_at = ? WHERE id = ?;
            """, (int(resumable), now, task_id))

    def update_task_status(self, task_id, status, error_message=None):
        now = time.time()
        with self._lock, self.conn:
            if status in _ZERO_METRIC_STATUSES:
                self.conn.execute("""
                    UPDATE tasks SET status = ?, error_message = ?, speed_bps = 0.0, eta_seconds = 0, updated_at = ? WHERE id = ?;
                """, (status, error_message, now, task_id))
            else:
                self.conn.execute("""
                    UPDATE tasks SET status = ?, error_message = ?, updated_at = ? WHERE id = ?;
                """, (status, error_message, now, task_id))

    def update_task_security(self, task_id, security_status, threat_name=None, threat_details=None):
        now = time.time()
        with self._lock, self.conn:
            self.conn.execute("""
                UPDATE tasks SET
                    security_status = ?,
                    threat_name = ?,
                    threat_details = ?,
                    updated_at = ?
                WHERE id = ?;
            """, (security_status, threat_name, threat_details, now, task_id))

    def record_security_audit(self, task_id, stage, verdict, threat_name=None, details=None):
        now = time.time()
        with self._lock, self.conn:
            self.conn.execute("""
                INSERT INTO security_audit (task_id, stage, verdict, threat_name, details, timestamp)
                VALUES (?, ?, ?, ?, ?, ?);
            """, (task_id, stage, verdict, threat_name, details, now))

    def get_security_audit(self, task_id):
        with self._lock:
            cursor = self.conn.execute("""
                SELECT id, task_id, stage, verdict, threat_name, details, timestamp
                FROM security_audit
                WHERE task_id = ?
                ORDER BY timestamp DESC, id DESC;
            """, (task_id,))
            return [dict(row) for row in cursor.fetchall()]

    def save_segments(self, task_id, segments):
        with self._lock, self.conn:
            for seg in segments:
                self.conn.execute("""
                    INSERT OR REPLACE INTO segments (
                        task_id, segment_index, start_byte, end_byte, current_byte, status
                    ) VALUES (?, ?, ?, ?, ?, ?);
                """, (
                    task_id,
                    seg["index"],
                    seg["start"],
                    seg["end"],
                    seg["current"],
                    seg["status"]
                ))

    def update_segment_progress(self, task_id, segment_index, current_byte, status="DOWNLOADING"):
        with self._lock, self.conn:
            self.conn.execute("""
                UPDATE segments SET current_byte = ?, status = ?
                WHERE task_id = ? AND segment_index = ?;
            """, (current_byte, status, task_id, segment_index))

    def update_segment_range(self, task_id, segment_index, end_byte, current_byte=None):
        with self._lock, self.conn:
            if current_byte is not None:
                self.conn.execute("""
                    UPDATE segments SET end_byte = ?, current_byte = ?
                    WHERE task_id = ? AND segment_index = ?;
                """, (end_byte, current_byte, task_id, segment_index))
            else:
                self.conn.execute("""
                    UPDATE segments SET end_byte = ?
                    WHERE task_id = ? AND segment_index = ?;
                """, (end_byte, task_id, segment_index))

    def add_segment(self, task_id, segment_index, start_byte, end_byte, current_byte, status="DOWNLOADING"):
        with self._lock, self.conn:
            self.conn.execute("""
                INSERT OR REPLACE INTO segments (
                    task_id, segment_index, start_byte, end_byte, current_byte, status
                ) VALUES (?, ?, ?, ?, ?, ?);
            """, (task_id, segment_index, start_byte, end_byte, current_byte, status))

    def get_segments(self, task_id):
        with self._lock:
            cursor = self.conn.execute("""
                SELECT * FROM segments WHERE task_id = ? ORDER BY start_byte ASC;
            """, (task_id,))
            return [dict(row) for row in cursor.fetchall()]

    def _format_task_row(self, row):
        if not row:
            return None
        d = dict(row)
        for json_col in ("custom_headers", "file_priorities", "selected_indices"):
            if d.get(json_col) is not None:
                d[json_col] = _deserialize_json_field(d[json_col])
        return d

    def get_task(self, task_id):
        with self._lock:
            cursor = self.conn.execute("SELECT * FROM tasks WHERE id = ?;", (task_id,))
            row = cursor.fetchone()
            return self._format_task_row(row)

    def get_all_tasks(self):
        with self._lock:
            cursor = self.conn.execute("SELECT * FROM tasks ORDER BY created_at DESC;")
            return [self._format_task_row(row) for row in cursor.fetchall()]

    def find_duplicate_task(self, url: str = None, info_hash: str = None):
        """
        Finds an existing matching task to prevent silent duplicate rows:
        - For Torrents: matches normalized info_hash across active/paused/completed tasks.
        - For HTTP/MEGA: matches canonical URL across active/incomplete tasks
          ('QUEUED', 'DOWNLOADING', 'PAUSED', 'STAGED', 'SCANNING').
        """
        ih = extract_info_hash(info_hash) or extract_info_hash(url)
        with self._lock:
            if ih:
                rows = self.conn.execute(
                    "SELECT * FROM tasks WHERE engine_type = 'TORRENT' ORDER BY created_at DESC;"
                ).fetchall()
                for r in rows:
                    row_ih = (r["info_hash"] or "").lower() or extract_info_hash(r["url"])
                    if row_ih == ih and r["status"] != "FAILED":
                        return self._format_task_row(r)
                return None

            norm_target = normalize_url(url)
            if not norm_target or norm_target.startswith("torrent:"):
                return None

            rows = self.conn.execute("""
                SELECT * FROM tasks
                WHERE status IN ('QUEUED', 'DOWNLOADING', 'PAUSED', 'STAGED', 'SCANNING')
                ORDER BY created_at DESC;
            """).fetchall()
            for r in rows:
                if normalize_url(r["url"]) == norm_target:
                    return self._format_task_row(r)
            return None

    def delete_task(self, task_id):
        with self._lock, self.conn:
            self.conn.execute("DELETE FROM tasks WHERE id = ?;", (task_id,))

    def close(self):
        with self._lock:
            try:
                self.conn.close()
            except Exception:
                pass
