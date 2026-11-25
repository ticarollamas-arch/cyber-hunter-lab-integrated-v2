"""API: autenticação, autorização por objeto, confirmação de testes ativos e fluxo completo via HTTP."""
import io
import time
import zipfile

import pytest

from chl_engine.api import create_app
from chl_engine.http import RateLimiter
from chl_engine.security import hash_token
from lab import vulnapp
from test_e2e_lab import free_port, OSV


@pytest.fixture
def client(settings):
    RateLimiter._registry.clear()
    settings.osv_offline_dir = OSV
    app = create_app(settings)
    db = app.extensions["chl"]["db"]
    db.execute("INSERT INTO users(name, role, token_hash, created_at) VALUES('ana','researcher',?,'x')", (hash_token("tok-ana"),))
    db.execute("INSERT INTO users(name, role, token_hash, created_at) VALUES('bia','researcher',?,'x')", (hash_token("tok-bia"),))
    db.execute("INSERT INTO users(name, role, token_hash, created_at) VALUES('leo','viewer',?,'x')", (hash_token("tok-leo"),))
    return app.test_client()


def H(tok):
    return {"Authorization": f"Bearer {tok}"}


def test_requires_auth(client):
    assert client.get("/api/programs").status_code == 401
    assert client.get("/api/programs", headers=H("errado")).status_code == 401
    assert client.get("/api/health").status_code == 200


def test_security_headers_and_panel(client):
    r = client.get("/")
    assert r.status_code == 200 and b"CyberHuntLab" in r.data
    assert "default-src 'self'" in r.headers["Content-Security-Policy"] and r.headers["X-Content-Type-Options"] == "nosniff"


def test_object_level_authorization(client):
    pid = client.post("/api/programs", json={"name": "Prog Ana", "scope": {"allowed": ["a.exemplo.com"]}}, headers=H("tok-ana")).json["id"]
    assert client.get(f"/api/programs/{pid}/scope", headers=H("tok-bia")).status_code == 404, "outro usuário não vê o programa"
    assert client.put(f"/api/programs/{pid}/scope", json={"allowed": ["*"]}, headers=H("tok-bia")).status_code == 404
    assert client.post("/api/jobs", json={"program_id": pid, "target": "https://a.exemplo.com/"}, headers=H("tok-bia")).status_code == 404
    assert [p["name"] for p in client.get("/api/programs", headers=H("tok-bia")).json] == []
    assert client.post("/api/programs", json={"name": "x"}, headers=H("tok-leo")).status_code == 403, "viewer não cria"


def test_job_blocked_when_out_of_scope(client):
    pid = client.post("/api/programs", json={"name": "P", "scope": {"allowed": ["a.exemplo.com"]}}, headers=H("tok-ana")).json["id"]
    r = client.post("/api/jobs", json={"program_id": pid, "target": "https://b.exemplo.com/"}, headers=H("tok-ana"))
    assert r.status_code == 400 and "Nenhuma requisição" in r.json["error"]


def test_zip_requires_authorized_repository(client):
    pid = client.post("/api/programs", json={"name": "P", "scope": {"allowed": ["127.0.0.1:9"], "repositories": ["github.com/org/app"],
                                                                     "rules": {"allow_private_network": True}}}, headers=H("tok-ana")).json["id"]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("app.py", "x = 1\n")
    data = {"program_id": str(pid), "target": "http://127.0.0.1:9/", "repository": "github.com/outra/coisa", "source": (io.BytesIO(buf.getvalue()), "src.zip")}
    r = client.post("/api/jobs", data=data, headers=H("tok-ana"), content_type="multipart/form-data")
    assert r.status_code == 400 and "repositório" in r.json["error"]


def test_full_flow_over_http(client):
    port = free_port()
    server = vulnapp.serve(port)
    try:
        base = f"http://127.0.0.1:{port}"
        pid = client.post("/api/programs", headers=H("tok-ana"), json={"name": "Lab", "scope": {
            "allowed": [f"127.0.0.1:{port}"], "excluded": [f"{base}/admin/"], "repositories": ["github.com/lab/vulnapp"],
            "rules": {"rate_limit_rps": 25, "active_testing_allowed": True, "allow_private_network": True}}}).json["id"]
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("app/views.py", "import os\nfrom flask import request\n\ndef run():\n    os.system('ls ' + request.args['d'])\n")
            z.writestr("requirements.txt", "PyYAML==5.3.1\n")
        r = client.post("/api/jobs", headers=H("tok-ana"), content_type="multipart/form-data",
                        data={"program_id": str(pid), "target": base + "/", "active": "1", "ai": "1", "repository": "github.com/lab/vulnapp",
                              "source": (io.BytesIO(buf.getvalue()), "src.zip")})
        assert r.status_code == 201, r.json
        jid = r.json["id"]
        for _ in range(200):
            job = client.get(f"/api/jobs/{jid}", headers=H("tok-ana")).json
            if job["status"] in ("awaiting_approval", "completed", "failed"):
                break
            time.sleep(0.1)
        assert job["status"] == "awaiting_approval"
        aid = job["approvals"][0]["id"]
        assert client.post(f"/api/approvals/{aid}", json={"approve": True}, headers=H("tok-ana")).status_code == 400, "sem confirmação explícita"
        assert client.post(f"/api/approvals/{aid}", json={"approve": True, "confirm": True, "reason": "lab"}, headers=H("tok-ana")).status_code == 200
        for _ in range(300):
            job = client.get(f"/api/jobs/{jid}", headers=H("tok-ana")).json
            if job["status"] in ("completed", "failed"):
                break
            time.sleep(0.1)
        assert job["status"] == "completed", job.get("error")
        findings = client.get(f"/api/jobs/{jid}/findings", headers=H("tok-ana")).json
        tools_used = {f["source_tool"] for f in findings}
        assert {"chl-pytaint", "chl-sca", "chl-dast", "chl-webchecks"} <= tools_used
        assert any("CVE-2020-14343" in f["title"] for f in findings), "SCA do requirements.txt enviado"
        # relatório sem validados → 422 com explicação
        assert client.get(f"/api/jobs/{jid}/report", headers=H("tok-ana")).status_code == 422
        xss = next(f for f in findings if f["cwe"] == "CWE-79" and f["source_tool"] == "chl-dast")
        r = client.patch(f"/api/findings/{xss['id']}", headers=H("tok-ana"), json={
            "impact": "Execução de script no navegador de quem abrir o link.", "repro_steps": "1. Abra /search?q=<payload>.\n2. O marcador aparece sem codificação."})
        assert r.status_code == 200
        r = client.post(f"/api/findings/{xss['id']}/transition", headers=H("tok-ana"), json={"to": "validated", "note": "reproduzido no navegador"})
        assert r.status_code == 200 and r.json["state"] == "validated"
        md = client.get(f"/api/jobs/{jid}/report?format=md", headers=H("tok-ana"))
        assert md.status_code == 200 and b"CWE-79" in md.data and b"CVE-2020-14343" not in md.data, "relatório só com validados"
        assert client.get(f"/api/jobs/{jid}/report?format=pdf", headers=H("tok-ana")).data.startswith(b"%PDF")
        assert client.get(f"/api/jobs/{jid}", headers=H("tok-bia")).status_code == 404
    finally:
        server.shutdown()
