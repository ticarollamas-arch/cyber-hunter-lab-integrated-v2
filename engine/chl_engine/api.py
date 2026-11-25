"""API HTTP e painel do motor de pesquisa.

Autenticação por token Bearer (hash SHA-256 no banco, comparação em tempo constante).
Autorização por objeto: cada programa pertence a um usuário; só o dono e administradores o acessam.
"""
from __future__ import annotations

import json
import tempfile
from functools import wraps
from pathlib import Path

from flask import Flask, Response, g, jsonify, request, send_from_directory

from . import __version__, reports, tools
from .ai import AiService
from .audit import AuditLog
from .config import Settings
from .cvss import CvssError
from .db import Database, utcnow
from .findings import FindingError
from .jobs import JobError, JobManager
from .scope import ScopeError
from .security import hash_token, mask_text

PANEL_DIR = Path(__file__).parent / "panel"


def create_app(settings: Settings | None = None, *, resolver=None) -> Flask:
    settings = settings or Settings()
    db = Database(settings.db_path, settings.audit_retention_days)
    audit = AuditLog(db)
    ai = AiService(db, settings)
    manager = JobManager(db, settings, audit, resolver=resolver, ai=ai)
    app = Flask(__name__, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = settings.max_zip_bytes + 1024 * 1024
    app.extensions["chl"] = {"db": db, "audit": audit, "manager": manager, "settings": settings}

    # --- segurança comum ------------------------------------------------------------------
    @app.after_request
    def security_headers(resp: Response):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        # CHL_FRAME_ANCESTORS permite embutir o painel na aba "Pesquisa" do app Next.js (ex.: https://app.seudominio.com)
        ancestors = " ".join(["'self'"] + settings.frame_ancestors)
        if not settings.frame_ancestors:
            resp.headers["X-Frame-Options"] = "SAMEORIGIN"
        resp.headers["Content-Security-Policy"] = f"default-src 'self'; img-src 'self' data:; frame-ancestors {ancestors}; base-uri 'none'; form-action 'self'"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    def auth(roles=("admin", "researcher", "viewer")):
        def deco(fn):
            @wraps(fn)
            def wrapper(*a, **kw):
                header = request.headers.get("Authorization", "")
                token = header[7:].strip() if header.startswith("Bearer ") else ""
                user = db.one("SELECT id, name, role FROM users WHERE token_hash=?", (hash_token(token),)) if token else None
                if not user:
                    return jsonify(error="não autenticado"), 401
                if user["role"] not in roles:
                    return jsonify(error="permissão insuficiente"), 403
                g.user = user
                return fn(*a, **kw)
            return wrapper
        return deco

    def program_for(pid: int) -> dict | None:
        p = db.one("SELECT * FROM programs WHERE id=?", (pid,))
        if not p or (g.user["role"] != "admin" and p["owner_id"] != g.user["id"]):
            return None      # 404 também para "existe mas não é seu" (não revela existência)
        return p

    def job_for(jid: int) -> dict | None:
        job = manager.get(jid)
        if not job or not program_for(job["program_id"]):
            return None
        return job

    def finding_for(fid: int) -> dict | None:
        f = manager.findings.get(fid)
        if not f or not program_for(f["program_id"]):
            return None
        return f

    def not_found():
        return jsonify(error="não encontrado"), 404

    # --- painel -----------------------------------------------------------------------------
    @app.get("/")
    def panel():
        return send_from_directory(PANEL_DIR, "index.html")

    @app.get("/panel/<path:name>")
    def panel_asset(name):
        return send_from_directory(PANEL_DIR, name)

    @app.get("/api/health")
    def health():
        return jsonify(ok=True, version=__version__, ai_configured=ai.configured, time=utcnow())

    @app.get("/api/me")
    @auth()
    def me():
        return jsonify(g.user)

    @app.get("/api/tools")
    @auth()
    def list_tools():
        return jsonify(tools.inventory())

    # --- programas e escopo --------------------------------------------------------------------
    @app.get("/api/programs")
    @auth()
    def programs():
        if g.user["role"] == "admin":
            rows = db.query("SELECT * FROM programs ORDER BY id DESC")
        else:
            rows = db.query("SELECT * FROM programs WHERE owner_id=? ORDER BY id DESC", (g.user["id"],))
        for r in rows:
            s = manager.scopes.current(r["id"])
            r["scope"] = {**s.to_data(), "version": s.version, "sha256": s.sha256} if s else None
        return jsonify(rows)

    @app.post("/api/programs")
    @auth(("admin", "researcher"))
    def create_program():
        body = request.get_json(force=True, silent=True) or {}
        name = str(body.get("name", "")).strip()
        if not name:
            return jsonify(error="informe o nome do programa"), 400
        pid = db.execute("INSERT INTO programs(name, platform, policy_url, owner_id, created_at) VALUES(?,?,?,?,?)",
                         (name[:200], str(body.get("platform", ""))[:100], str(body.get("policy_url", ""))[:500], g.user["id"], utcnow()))
        audit.record(g.user["name"], "program.create", "ok", target=name, details={"program_id": pid})
        if body.get("scope"):
            try:
                manager.scopes.save(pid, body["scope"], g.user["id"])
            except ScopeError as exc:
                return jsonify(error=str(exc), program_id=pid), 400
        return jsonify(id=pid), 201

    @app.get("/api/programs/<int:pid>/scope")
    @auth()
    def get_scope(pid):
        if not program_for(pid):
            return not_found()
        hist = manager.scopes.history(pid)
        for h in hist:
            h["data"] = json.loads(h.pop("data_json"))
        return jsonify(hist)

    @app.put("/api/programs/<int:pid>/scope")
    @auth(("admin", "researcher"))
    def put_scope(pid):
        if not program_for(pid):
            return not_found()
        try:
            s = manager.scopes.save(pid, request.get_json(force=True, silent=True) or {}, g.user["id"])
        except (ScopeError, ValueError, TypeError) as exc:
            return jsonify(error=str(exc)), 400
        audit.record(g.user["name"], "scope.update", "ok", target=f"program:{pid}", details={"version": s.version, "sha256": s.sha256, **s.to_data()})
        return jsonify(version=s.version, sha256=s.sha256)

    @app.post("/api/programs/<int:pid>/scope/check")
    @auth()
    def check_scope(pid):
        if not program_for(pid):
            return not_found()
        s = manager.scopes.current(pid)
        if not s:
            return jsonify(allowed=False, reason="sem escopo")
        url = str((request.get_json(force=True, silent=True) or {}).get("url", ""))
        return jsonify(s.check_url(url, resolver).as_dict())

    # --- tarefas ------------------------------------------------------------------------------
    @app.post("/api/jobs")
    @auth(("admin", "researcher"))
    def create_job():
        form = request.form if request.form else (request.get_json(force=True, silent=True) or {})
        try:
            pid = int(form.get("program_id", 0))
        except ValueError:
            return jsonify(error="program_id inválido"), 400
        if not program_for(pid):
            return not_found()
        target = str(form.get("target", "")).strip()
        truthy = lambda v: str(v).lower() in ("1", "true", "on", "sim")
        options = {"active": truthy(form.get("active", "0")), "ai": truthy(form.get("ai", "1")),
                   "repository": str(form.get("repository", "")).strip(), "external_tools": True}
        upload = request.files.get("source")
        tmp_zip = None
        try:
            if upload and upload.filename:
                if not upload.filename.lower().endswith(".zip"):
                    return jsonify(error="envie o código como .zip"), 400
                tmp_zip = Path(tempfile.mkstemp(suffix=".zip")[1])
                upload.save(tmp_zip)
            job_id = manager.create(program_id=pid, target=target, user=g.user, options=options, source_zip=tmp_zip)
        except JobError as exc:
            return jsonify(error=str(exc)), 400
        finally:
            if tmp_zip:
                tmp_zip.unlink(missing_ok=True)
        manager.start(job_id, g.user)
        return jsonify(id=job_id), 201

    @app.get("/api/jobs")
    @auth()
    def list_jobs():
        pid = request.args.get("program_id", type=int)
        if pid is not None and not program_for(pid):
            return not_found()
        if pid is not None:
            rows = db.query("SELECT id, program_id, target, status, progress, current_step, created_at, finished_at FROM jobs WHERE program_id=? ORDER BY id DESC LIMIT 100", (pid,))
        elif g.user["role"] == "admin":
            rows = db.query("SELECT id, program_id, target, status, progress, current_step, created_at, finished_at FROM jobs ORDER BY id DESC LIMIT 100")
        else:
            rows = db.query("SELECT j.id, j.program_id, j.target, j.status, j.progress, j.current_step, j.created_at, j.finished_at FROM jobs j"
                            " JOIN programs p ON p.id=j.program_id WHERE p.owner_id=? ORDER BY j.id DESC LIMIT 100", (g.user["id"],))
        return jsonify(rows)

    @app.get("/api/jobs/<int:jid>")
    @auth()
    def get_job(jid):
        job = job_for(jid)
        if not job:
            return not_found()
        job.pop("source_path", None)
        return jsonify(job)

    @app.post("/api/jobs/<int:jid>/cancel")
    @auth(("admin", "researcher"))
    def cancel_job(jid):
        if not job_for(jid):
            return not_found()
        try:
            manager.cancel(jid, g.user)
        except JobError as exc:
            return jsonify(error=str(exc)), 400
        return jsonify(ok=True)

    @app.post("/api/approvals/<int:aid>")
    @auth(("admin", "researcher"))
    def decide(aid):
        ap = db.one("SELECT * FROM approvals WHERE id=?", (aid,))
        if not ap or not job_for(ap["job_id"]):
            return not_found()
        body = request.get_json(force=True, silent=True) or {}
        approve = bool(body.get("approve"))
        if approve and body.get("confirm") is not True:
            return jsonify(error="confirmação explícita obrigatória para testes ativos"), 400
        try:
            return jsonify(manager.decide(aid, approve, g.user, str(body.get("reason", ""))[:500]))
        except JobError as exc:
            return jsonify(error=str(exc)), 400

    @app.get("/api/jobs/<int:jid>/findings")
    @auth()
    def job_findings(jid):
        if not job_for(jid):
            return not_found()
        return jsonify(manager.findings.list(job_id=jid, state=request.args.get("state") or None))

    @app.get("/api/jobs/<int:jid>/assets")
    @auth()
    def job_assets(jid):
        if not job_for(jid):
            return not_found()
        rows = db.query("SELECT kind, value, meta_json FROM assets WHERE job_id=? ORDER BY kind, value", (jid,))
        for r in rows:
            r["meta"] = json.loads(r.pop("meta_json"))
        return jsonify(rows)

    @app.get("/api/jobs/<int:jid>/evidence")
    @auth()
    def job_evidence(jid):
        if not job_for(jid):
            return not_found()
        return jsonify(db.query("SELECT id, step, method, url, status, decision, scope_rule, ts, duration_ms FROM http_evidence WHERE job_id=? ORDER BY id DESC LIMIT 500", (jid,)))

    @app.get("/api/evidence/<int:eid>")
    @auth()
    def evidence(eid):
        e = db.one("SELECT * FROM http_evidence WHERE id=?", (eid,))
        if not e or not job_for(e["job_id"]):
            return not_found()
        return jsonify(e)

    @app.get("/api/jobs/<int:jid>/audit")
    @auth()
    def job_audit(jid):
        if not job_for(jid):
            return not_found()
        return jsonify(audit.list(job_id=jid))

    @app.get("/api/audit/verify")
    @auth(("admin",))
    def verify_audit():
        ok, bad = audit.verify_chain()
        return jsonify(ok=ok, first_invalid=bad)

    # --- achados -------------------------------------------------------------------------------
    @app.get("/api/findings/<int:fid>")
    @auth()
    def get_finding(fid):
        f = finding_for(fid)
        return jsonify(f) if f else not_found()

    @app.patch("/api/findings/<int:fid>")
    @auth(("admin", "researcher"))
    def patch_finding(fid):
        if not finding_for(fid):
            return not_found()
        body = request.get_json(force=True, silent=True) or {}
        try:
            manager.findings.update_fields(fid, g.user["name"], cvss_vector=body.get("cvss_vector"), impact=body.get("impact"),
                                           repro_steps=body.get("repro_steps"), description=body.get("description"))
        except (CvssError, FindingError) as exc:
            return jsonify(error=str(exc)), 400
        return jsonify(manager.findings.get(fid))

    @app.post("/api/findings/<int:fid>/transition")
    @auth(("admin", "researcher"))
    def transition(fid):
        if not finding_for(fid):
            return not_found()
        body = request.get_json(force=True, silent=True) or {}
        try:
            return jsonify(manager.findings.transition(fid, str(body.get("to", "")), g.user["name"], str(body.get("note", ""))[:2000], g.user["role"]))
        except FindingError as exc:
            return jsonify(error=str(exc)), 400

    @app.get("/api/programs/<int:pid>/groups")
    @auth()
    def groups(pid):
        if not program_for(pid):
            return not_found()
        return jsonify(manager.findings.groups(pid))

    # --- relatório -------------------------------------------------------------------------------
    @app.get("/api/jobs/<int:jid>/report")
    @auth()
    def report(jid):
        job = job_for(jid)
        if not job:
            return not_found()
        program = program_for(job["program_id"])
        scope = manager.scopes.by_version_id(job["scope_version_id"])
        findings = [manager.findings.get(f["id"]) for f in manager.findings.list(job_id=jid, state="validated")]
        try:
            rep = reports.build(program, job, findings, {"version": scope.version, "sha256": scope.sha256, **scope.to_data()})
        except reports.ReportError as exc:
            return jsonify(error="relatório não gerado", problems=exc.problems), 422
        fmt = request.args.get("format", "md")
        audit.record(g.user["name"], "report.generate", "ok", target=f"job:{jid}", job_id=jid, details={"format": fmt, "findings": len(rep["findings"])})
        name = f"relatorio-job{jid}"
        if fmt == "pdf":
            return Response(reports.to_pdf(rep), mimetype="application/pdf", headers={"Content-Disposition": f"attachment; filename={name}.pdf"})
        if fmt == "json":
            return Response(reports.to_json(rep), mimetype="application/json", headers={"Content-Disposition": f"attachment; filename={name}.json"})
        if fmt == "sarif":
            return Response(json.dumps(reports.to_sarif(rep), indent=2), mimetype="application/sarif+json",
                            headers={"Content-Disposition": f"attachment; filename={name}.sarif"})
        return Response(reports.to_markdown(rep), mimetype="text/markdown; charset=utf-8", headers={"Content-Disposition": f"attachment; filename={name}.md"})

    @app.get("/api/ai/usage")
    @auth()
    def ai_usage():
        return jsonify(ai.usage(g.user["id"]))

    @app.errorhandler(413)
    def too_large(_):
        return jsonify(error="arquivo acima do limite configurado"), 413

    @app.errorhandler(500)
    def internal(exc):
        return jsonify(error="erro interno; detalhes registrados no servidor"), 500

    return app
