"""Trilha de auditoria somente-inclusão com encadeamento de hash (RF-012).

Cada registro guarda o hash do anterior. Gatilhos no banco bloqueiam UPDATE e DELETE dentro da
retenção; `verify_chain` detecta qualquer alteração feita por fora do aplicativo.
"""
from __future__ import annotations

import hashlib
from typing import Any

from .db import Database, dumps, utcnow
from .security import mask_text

GENESIS = "0" * 64


def _digest(prev_hash: str, ts: str, actor: str, action: str, target: str, scope_rule: str, result: str, job_id: Any, details: str) -> str:
    payload = "\x1f".join([prev_hash, ts, actor, action, target, scope_rule, result, str(job_id or ""), details])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, db: Database):
        self.db = db

    def record(self, actor: str, action: str, result: str, target: str = "", scope_rule: str = "",
               job_id: int | None = None, details: dict | None = None) -> int:
        details_json = mask_text(dumps(details or {}))
        ts = utcnow()
        with self.db.tx() as c:
            row = c.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
            prev = row["hash"] if row else GENESIS
            h = _digest(prev, ts, actor, action, target or "", scope_rule or "", result, job_id, details_json)
            cur = c.execute(
                "INSERT INTO audit_log(ts, actor, action, target, scope_rule, result, job_id, details_json, prev_hash, hash)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)",
                (ts, actor, action, target or "", scope_rule or "", result, job_id, details_json, prev, h),
            )
            return int(cur.lastrowid)

    def list(self, job_id: int | None = None, limit: int = 500) -> list[dict]:
        if job_id is None:
            return self.db.query("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))
        return self.db.query("SELECT * FROM audit_log WHERE job_id=? ORDER BY id DESC LIMIT ?", (job_id, limit))

    def verify_chain(self) -> tuple[bool, int | None]:
        """Retorna (íntegro, id_do_primeiro_registro_inválido)."""
        prev = None
        for r in self.db.query("SELECT * FROM audit_log ORDER BY id ASC"):
            if prev is not None and r["prev_hash"] != prev:
                return False, r["id"]
            expected = _digest(r["prev_hash"], r["ts"], r["actor"], r["action"], r["target"], r["scope_rule"],
                               r["result"], r["job_id"], r["details_json"])
            if expected != r["hash"]:
                return False, r["id"]
            prev = r["hash"]
        return True, None
