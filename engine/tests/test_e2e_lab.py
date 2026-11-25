"""Pesquisa ponta a ponta contra a aplicação vulnerável local (ambiente controlado).

Cobre: escopo e exclusões na prática, reconhecimento, inventário, web/API, SCA/CVE, DAST com
aprovação humana, interrupção, trilha de auditoria (T-012) e ausência de falsos positivos na
versão corrigida da mesma aplicação.
"""
import socket
import time
from pathlib import Path

import pytest

from chl_engine.audit import AuditLog
from chl_engine.http import RateLimiter
from chl_engine.jobs import JobError, JobManager
from chl_engine.scope import ScopeStore
from lab import vulnapp

OSV = str(Path(__file__).parent / "fixtures" / "osv")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def lab():
    vulnapp.HITS.clear()
    port = free_port()
    server = vulnapp.serve(port, safe=False)
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


@pytest.fixture
def safe_lab():
    port = free_port()
    server = vulnapp.serve(port, safe=True)
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


@pytest.fixture
def manager(db, settings, audit):
    RateLimiter._registry.clear()
    settings.osv_offline_dir = OSV
    return JobManager(db, settings, audit)


def setup_scope(db, program, user, base, active=True):
    host = base.split("//")[1]
    return ScopeStore(db).save(program, {
        "allowed": [host], "excluded": [f"{base}/admin/"],
        "rules": {"rate_limit_rps": 20, "max_requests_per_job": 300, "active_testing_allowed": active,
                  "allow_private_network": True, "max_crawl_pages": 30}}, user)


USER = {"id": 1, "name": "pesquisadora", "role": "admin"}


def wait_status(manager, job_id, statuses, timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        job = manager.get(job_id)
        if job["status"] in statuses:
            return job
        time.sleep(0.1)
    raise AssertionError(f"status final não atingido: {manager.get(job_id)['status']}")


def test_out_of_scope_target_never_contacted(manager, db, program, user, lab):
    setup_scope(db, program, user, lab)
    with pytest.raises(JobError, match="Nenhuma requisição"):
        manager.create(program_id=program, target=f"{lab}/admin/painel", user=USER)
    with pytest.raises(JobError):
        manager.create(program_id=program, target="https://site-fora-do-escopo.example/", user=USER)
    assert vulnapp.HITS["/admin/painel"] == 0
    assert db.one("SELECT COUNT(*) AS n FROM audit_log WHERE action='job.create' AND result='blocked'")["n"] == 2


def test_full_research_with_approval(manager, db, program, user, lab):
    setup_scope(db, program, user, lab)
    job_id = manager.create(program_id=program, target=lab + "/", user=USER, options={"active": True, "ai": True})
    manager.start(job_id, USER)
    job = wait_status(manager, job_id, {"awaiting_approval", "completed", "failed"})
    assert job["status"] == "awaiting_approval", job.get("error")
    before = {k: v for k, v in vulnapp.HITS.items()}
    approval = job["approvals"][0]
    assert approval["status"] == "pending" and {p["test"] for p in approval["plan"]} >= {"xss-reflected", "sqli-error", "open-redirect"}
    time.sleep(0.5)
    assert vulnapp.HITS["/search"] == before.get("/search", 0), "nenhum payload sai antes da aprovação"
    manager.decide(approval["id"], True, USER, "programa permite testes ativos de baixo impacto")
    job = wait_status(manager, job_id, {"completed", "failed"})
    assert job["status"] == "completed", job.get("error")
    assert job["progress"] == 100

    assert vulnapp.HITS["/admin/painel"] == 0, "caminho excluído nunca é acessado, mesmo linkado na página"
    findings = manager.findings.list(job_id=job_id)
    checks = {f["title"]: f for f in findings}
    by_check = {}
    for f in findings:
        by_check.setdefault(f["cwe"], []).append(f)
    kinds = {f["source_tool"] for f in findings}
    assert {"chl-webchecks", "chl-dast", "chl-sca"} <= kinds
    titles = " | ".join(checks)
    for expected in ("XSS", "SQL injection", "open redirect", "CORS reflete", "Listagem de diretório", "stack trace", "jquery 3.4.1"):
        assert expected.lower() in titles.lower(), f"não encontrou: {expected}"
    assert all(f["state"] in ("observation", "hypothesis") for f in findings), "o motor nunca valida sozinho"
    xss = next(f for f in findings if f["cwe"] == "CWE-79" and f["source_tool"] == "chl-dast")
    assert xss["evidence_json"][0]["kind"] == "http" and "PAYLOAD" in xss["location"]
    sca_f = next(f for f in findings if f["source_tool"] == "chl-sca")
    assert "CVE-2020-11022" in sca_f["title"]

    assets = db.query("SELECT kind, value FROM assets WHERE job_id=?", (job_id,))
    kinds = {a["kind"] for a in assets}
    assert {"host", "endpoint", "tecnologia", "fora_do_escopo", "api_spec", "dependencia"} <= kinds
    assert any("externo.example.org" in a["value"] for a in assets if a["kind"] == "fora_do_escopo")
    steps = {s["name"]: s["status"] for s in job["steps"]}
    assert steps["ai"] == "unavailable", "IA sem provedor configurado é informada como indisponível"
    assert steps["sast"] == "skipped"

    # T-012: cada execução tem registro correspondente; cadeia íntegra
    audit = AuditLog(db)
    actions = [a["action"] for a in audit.list(job_id=job_id)]
    for needed in ("job.create", "job.start", "approval.requested", "approval.approved", "job.completed"):
        assert needed in actions
    assert audit.verify_chain() == (True, None)
    sent = db.one("SELECT COUNT(*) AS n FROM http_evidence WHERE job_id=? AND decision IN ('sent','error')", (job_id,))["n"]
    assert sent == manager.get(job_id)["requests_sent"] and sent <= 300


def test_rejected_approval_sends_no_payloads(manager, db, program, user, lab):
    setup_scope(db, program, user, lab)
    job_id = manager.create(program_id=program, target=lab + "/", user=USER, options={"active": True, "ai": False})
    manager.start(job_id, USER)
    job = wait_status(manager, job_id, {"awaiting_approval"})
    payloads_before = db.one("SELECT COUNT(*) AS n FROM http_evidence WHERE job_id=? AND step='dast'", (job_id,))["n"]
    manager.decide(job["approvals"][0]["id"], False, USER, "fora da janela de testes")
    job = wait_status(manager, job_id, {"completed"})
    assert db.one("SELECT COUNT(*) AS n FROM http_evidence WHERE job_id=? AND step='dast'", (job_id,))["n"] == payloads_before == 0
    assert {s["name"]: s["status"] for s in job["steps"]}["dast"] == "skipped"


def test_cancel_while_awaiting_approval(manager, db, program, user, lab):
    setup_scope(db, program, user, lab)
    job_id = manager.create(program_id=program, target=lab + "/", user=USER, options={"active": True, "ai": False})
    manager.start(job_id, USER)
    wait_status(manager, job_id, {"awaiting_approval"})
    manager.cancel(job_id, USER)
    job = wait_status(manager, job_id, {"cancelled"})
    assert job["approvals"][0]["status"] == "expired"
    assert "job.cancel" in [a["action"] for a in AuditLog(db).list(job_id=job_id)]


def test_cancel_during_recon_stops_requests(manager, db, program, user, lab):
    ScopeStore(db).save(program, {"allowed": [lab.split("//")[1]], "rules": {"rate_limit_rps": 2, "allow_private_network": True}}, user)
    job_id = manager.create(program_id=program, target=lab + "/", user=USER, options={"ai": False})
    manager.start(job_id, USER)
    time.sleep(1.2)
    manager.cancel(job_id, USER)
    job = wait_status(manager, job_id, {"cancelled"}, timeout=10)
    count = job["requests_sent"]
    time.sleep(1.5)
    assert manager.get(job_id)["requests_sent"] == count, "nenhuma requisição depois da interrupção"


def test_active_option_refused_when_program_disallows(manager, db, program, user, lab):
    setup_scope(db, program, user, lab, active=False)
    with pytest.raises(JobError, match="não permite testes ativos"):
        manager.create(program_id=program, target=lab + "/", user=USER, options={"active": True})


def test_fixed_app_produces_no_injection_hypotheses(manager, db, program, user, safe_lab):
    setup_scope(db, program, user, safe_lab)
    job_id = manager.create(program_id=program, target=safe_lab + "/", user=USER, options={"active": True, "ai": False})
    manager.start(job_id, USER)
    job = wait_status(manager, job_id, {"awaiting_approval", "completed", "failed"})
    if job["status"] == "awaiting_approval":
        manager.decide(job["approvals"][0]["id"], True, USER, "laboratório")
    job = wait_status(manager, job_id, {"completed", "failed"})
    assert job["status"] == "completed"
    hyps = [f["title"] for f in manager.findings.list(job_id=job_id) if f["state"] == "hypothesis"]
    assert hyps == [], f"falsos positivos na aplicação corrigida: {hyps}"
