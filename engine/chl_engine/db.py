"""Persistência em SQLite (WAL).

Decisão registrada (ADR-002): o prompt técnico sugere PostgreSQL. Esta versão usa SQLite porque
roda numa única VPS, não exige serviço extra e o ambiente de desenvolvimento não tem driver
PostgreSQL. Todo o acesso passa por esta camada, com SQL padrão, para facilitar a troca.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, role TEXT NOT NULL CHECK(role IN ('admin','researcher','viewer')),
  token_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS programs (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, platform TEXT, policy_url TEXT,
  owner_id INTEGER NOT NULL REFERENCES users(id), created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scope_versions (
  id INTEGER PRIMARY KEY, program_id INTEGER NOT NULL REFERENCES programs(id), version INTEGER NOT NULL,
  data_json TEXT NOT NULL, sha256 TEXT NOT NULL, created_by INTEGER NOT NULL, created_at TEXT NOT NULL,
  UNIQUE(program_id, version)
);
CREATE TABLE IF NOT EXISTS jobs (
  id INTEGER PRIMARY KEY, program_id INTEGER NOT NULL REFERENCES programs(id), scope_version_id INTEGER NOT NULL,
  target TEXT NOT NULL, status TEXT NOT NULL, created_by INTEGER NOT NULL, created_at TEXT NOT NULL,
  started_at TEXT, finished_at TEXT, options_json TEXT NOT NULL DEFAULT '{}', progress INTEGER NOT NULL DEFAULT 0,
  current_step TEXT, error TEXT, source_path TEXT, requests_sent INTEGER NOT NULL DEFAULT 0,
  requests_blocked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS job_steps (
  id INTEGER PRIMARY KEY, job_id INTEGER NOT NULL REFERENCES jobs(id), name TEXT NOT NULL, tool TEXT NOT NULL,
  status TEXT NOT NULL, started_at TEXT, finished_at TEXT, summary TEXT
);
CREATE TABLE IF NOT EXISTS http_evidence (
  id INTEGER PRIMARY KEY, job_id INTEGER NOT NULL, step TEXT, method TEXT NOT NULL, url TEXT NOT NULL,
  status INTEGER, decision TEXT NOT NULL, scope_rule TEXT, ts TEXT NOT NULL, duration_ms INTEGER,
  request_headers TEXT, request_body TEXT, response_headers TEXT, body_excerpt TEXT, body_sha256 TEXT
);
CREATE TABLE IF NOT EXISTS approvals (
  id INTEGER PRIMARY KEY, job_id INTEGER NOT NULL, kind TEXT NOT NULL, plan_json TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending','approved','rejected','expired')), requested_at TEXT NOT NULL,
  decided_by INTEGER, decided_at TEXT, reason TEXT
);
CREATE TABLE IF NOT EXISTS assets (
  id INTEGER PRIMARY KEY, job_id INTEGER NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL, meta_json TEXT NOT NULL DEFAULT '{}',
  UNIQUE(job_id, kind, value)
);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY, job_id INTEGER NOT NULL, program_id INTEGER NOT NULL, title TEXT NOT NULL,
  cwe TEXT, wstg TEXT, severity TEXT NOT NULL, cvss_vector TEXT, cvss_score REAL,
  state TEXT NOT NULL CHECK(state IN ('observation','hypothesis','validated','false_positive')),
  location TEXT NOT NULL, component TEXT, description TEXT, evidence_json TEXT NOT NULL DEFAULT '[]',
  recommendation TEXT, source_tool TEXT NOT NULL, fingerprint TEXT NOT NULL, group_key TEXT,
  duplicate_of INTEGER, fp_signals TEXT NOT NULL DEFAULT '[]', ai_json TEXT, references_json TEXT NOT NULL DEFAULT '[]',
  impact TEXT, repro_steps TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_job ON findings(job_id);
CREATE INDEX IF NOT EXISTS idx_findings_fp ON findings(fingerprint);
CREATE TABLE IF NOT EXISTS finding_history (
  id INTEGER PRIMARY KEY, finding_id INTEGER NOT NULL, from_state TEXT, to_state TEXT NOT NULL,
  actor TEXT NOT NULL, note TEXT, ts TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY, ts TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT,
  scope_rule TEXT, result TEXT NOT NULL, job_id INTEGER, details_json TEXT NOT NULL DEFAULT '{}',
  prev_hash TEXT NOT NULL, hash TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log é somente-inclusão'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
WHEN OLD.ts >= datetime('now', '-' || (SELECT COALESCE((SELECT value FROM meta WHERE key='audit_retention_days'), '365')) || ' days')
BEGIN SELECT RAISE(ABORT, 'audit_log é somente-inclusão dentro do período de retenção'); END;
CREATE TABLE IF NOT EXISTS ai_usage (
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, day TEXT NOT NULL, tokens INTEGER NOT NULL, calls INTEGER NOT NULL,
  UNIQUE(user_id, day)
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class Database:
    def __init__(self, path: Path | str, audit_retention_days: int = 365):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._write_lock = threading.RLock()
        self._local = threading.local()
        with self._write_lock:   # executescript faz COMMIT implícito, por isso fica fora de tx()
            conn = self._conn()
            conn.executescript("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);")
            conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('audit_retention_days', ?)", (str(audit_retention_days),))
            conn.executescript(SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=30, isolation_level=None, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=30000")
            self._local.conn = conn
        return conn

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        """Transação de escrita serializada (uma escrita por vez no processo)."""
        with self._write_lock:
            conn = self._conn()
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise

    def query(self, sql: str, params: tuple | list = ()) -> list[dict[str, Any]]:
        return [dict(r) for r in self._conn().execute(sql, params).fetchall()]

    def one(self, sql: str, params: tuple | list = ()) -> dict[str, Any] | None:
        row = self._conn().execute(sql, params).fetchone()
        return dict(row) if row else None

    def execute(self, sql: str, params: tuple | list = ()) -> int:
        with self.tx() as c:
            cur = c.execute(sql, params)
            return int(cur.lastrowid or 0)


def dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
