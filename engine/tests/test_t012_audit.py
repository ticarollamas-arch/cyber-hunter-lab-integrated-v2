"""T-012 — trilha de auditoria imutável e verificável."""
import sqlite3

import pytest


def test_chain_valid_and_append_only(db, audit):
    for i in range(5):
        audit.record("ana", "job.start", "ok", target=f"https://a{i}.com", scope_rule="allowed:a.com", job_id=i)
    assert audit.verify_chain() == (True, None)
    with pytest.raises(sqlite3.DatabaseError):
        db.execute("UPDATE audit_log SET result='forjado' WHERE id=2")
    with pytest.raises(sqlite3.DatabaseError):
        db.execute("DELETE FROM audit_log WHERE id=2")


def test_tampering_detected(db, audit):
    for i in range(3):
        audit.record("ana", "x", "ok", details={"i": i})
    with db.tx() as c:   # simula adulteração por fora do aplicativo
        c.execute("DROP TRIGGER audit_no_update")
        c.execute("UPDATE audit_log SET result='forjado' WHERE id=2")
    assert audit.verify_chain() == (False, 2)


def test_secrets_masked_in_audit(db, audit):
    audit.record("ana", "x", "ok", details={"header": "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123"})
    row = db.one("SELECT details_json FROM audit_log")
    assert "ghp_ABCDEFGHIJ" not in row["details_json"]
