"""Orquestrador das pesquisas: etapas, progresso, aprovação humana, interrupção e registro."""
from __future__ import annotations

import json
import shutil
import tempfile
import threading
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

import requests

from . import sca, web
from .ai import AiService, AiUnavailable, QuotaExceeded
from .audit import AuditLog
from .config import Settings
from .db import Database, dumps, utcnow
from .findings import FindingStore, NewFinding
from .http import BudgetExceeded, CancelToken, Cancelled, OutOfScope, ScopedHttpClient
from .sast.runner import run_sast
from .sast.zipsafe import UnsafeArchive, safe_extract
from .scope import ScopeStore

STEPS = [
    ("scope", "Verificação de escopo", "chl-scope", 5),
    ("recon", "Reconhecimento da superfície autorizada", "chl-crawler", 25),
    ("inventory", "Inventário de ativos e tecnologias", "chl-fingerprint", 5),
    ("webapi", "Análise passiva de aplicação web e APIs", "chl-webchecks", 15),
    ("sast", "SAST — análise estática do código", "chl-pytaint + chl-rules (+ semgrep/gitleaks se instalados)", 15),
    ("sca", "SCA e correlação com CVE (OSV)", "chl-sca", 10),
    ("dast", "DAST ativo (exige aprovação humana)", "chl-dast", 15),
    ("ai", "Triagem assistida por IA", "chl-ai", 5),
    ("finalize", "Consolidação, deduplicação e falsos positivos", "chl-engine", 5),
]
TERMINAL = {"completed", "failed", "cancelled"}


class JobError(ValueError):
    pass


@dataclass
class _Runtime:
    cancel: CancelToken = field(default_factory=CancelToken)
    approval: threading.Event = field(default_factory=threading.Event)
    thread: threading.Thread | None = None


class JobManager:
    def __init__(self, db: Database, settings: Settings, audit: AuditLog, *, resolver: Callable[[str], list[str]] | None = None,
                 ai: AiService | None = None):
        self.db, self.settings, self.audit = db, settings, audit
        self.scopes = ScopeStore(db)
        self.findings = FindingStore(db, audit)
        self.ai = ai or AiService(db, settings)
        self.resolver = resolver
        self._rt: dict[int, _Runtime] = {}
        self._lock = threading.Lock()

    # --- criação ----------------------------------------------------------------------------
    def create(self, *, program_id: int, target: str, user: dict, options: dict | None = None,
               source_zip: Path | None = None) -> int:
        options = dict(options or {})
        scope = self.scopes.current(program_id)
        actor = user["name"]
        if scope is None:
            self.audit.record(actor, "job.create", "blocked", target=target, scope_rule="sem-escopo", details={"program_id": program_id})
            raise JobError("o programa não tem escopo cadastrado; nada foi executado")
        decision = scope.check_url(target, self.resolver)
        if not decision.allowed:
            self.audit.record(actor, "job.create", "blocked", target=target, scope_rule=decision.rule,
                              details={"program_id": program_id, "reason": decision.reason, "scope_version": scope.version})
            raise JobError(f"alvo bloqueado: {decision.reason}. Nenhuma requisição foi enviada.")
        if source_zip is not None:
            repo = (options.get("repository") or "").strip()
            rdec = scope.check_repository(repo) if repo else None
            if rdec is None or not rdec.allowed:
                self.audit.record(actor, "job.create", "blocked", target=repo or "(zip sem repositório)", scope_rule=rdec.rule if rdec else "repo-missing")
                raise JobError("o código enviado precisa indicar um repositório listado no escopo do programa")
        if options.get("active") and not scope.rules.get("active_testing_allowed"):
            raise JobError("o escopo deste programa não permite testes ativos; desmarque a opção ou atualize o escopo")
        job_id = self.db.execute(
            "INSERT INTO jobs(program_id, scope_version_id, target, status, created_by, created_at, options_json) VALUES(?,?,?,?,?,?,?)",
            (program_id, scope.version_id, target, "queued", user["id"], utcnow(), dumps(options)))
        if source_zip is not None:
            work = self.settings.data_dir / "jobs" / str(job_id)
            work.mkdir(parents=True, exist_ok=True)
            dest = work / "source.zip"
            shutil.copyfile(source_zip, dest)
            self.db.execute("UPDATE jobs SET source_path=? WHERE id=?", (str(dest), job_id))
        for key, name, tool, _ in STEPS:
            self.db.execute("INSERT INTO job_steps(job_id, name, tool, status) VALUES(?,?,?,?)", (job_id, key, tool, "pending"))
        self.audit.record(actor, "job.create", "ok", target=target, scope_rule=decision.rule, job_id=job_id,
                          details={"scope_version": scope.version, "scope_sha256": scope.sha256, "options": options})
        return job_id

    def start(self, job_id: int, user: dict) -> None:
        rt = _Runtime()
        with self._lock:
            if job_id in self._rt and self._rt[job_id].thread and self._rt[job_id].thread.is_alive():
                raise JobError("tarefa já em execução")
            self._rt[job_id] = rt
        rt.thread = threading.Thread(target=self._run, args=(job_id, user, rt), name=f"job-{job_id}", daemon=True)
        rt.thread.start()

    def wait(self, job_id: int, timeout: float = 120) -> dict:
        rt = self._rt.get(job_id)
        if rt and rt.thread:
            rt.thread.join(timeout)
        return self.get(job_id)

    # --- controle humano --------------------------------------------------------------------
    def cancel(self, job_id: int, user: dict) -> None:
        job = self.get(job_id)
        if not job or job["status"] in TERMINAL:
            raise JobError("tarefa não está em execução")
        rt = self._rt.get(job_id)
        if rt:
            rt.cancel.cancel()
            rt.approval.set()
        self.audit.record(user["name"], "job.cancel", "ok", target=job["target"], job_id=job_id)

    def decide(self, approval_id: int, approve: bool, user: dict, reason: str = "") -> dict:
        ap = self.db.one("SELECT * FROM approvals WHERE id=?", (approval_id,))
        if not ap or ap["status"] != "pending":
            raise JobError("aprovação inexistente ou já decidida")
        if user.get("role") not in ("admin", "researcher"):
            raise JobError("só pesquisadores podem aprovar testes ativos")
        status = "approved" if approve else "rejected"
        self.db.execute("UPDATE approvals SET status=?, decided_by=?, decided_at=?, reason=? WHERE id=?",
                        (status, user["id"], utcnow(), reason, approval_id))
        self.audit.record(user["name"], "approval." + status, "ok", target=ap["kind"], job_id=ap["job_id"], details={"reason": reason})
        rt = self._rt.get(ap["job_id"])
        if rt:
            rt.approval.set()
        return self.db.one("SELECT * FROM approvals WHERE id=?", (approval_id,))

    # --- consulta ---------------------------------------------------------------------------
    def get(self, job_id: int) -> dict | None:
        job = self.db.one("SELECT * FROM jobs WHERE id=?", (job_id,))
        if job:
            job["options"] = json.loads(job.pop("options_json") or "{}")
            job["steps"] = self.db.query("SELECT * FROM job_steps WHERE job_id=? ORDER BY id", (job_id,))
            job["approvals"] = self.db.query("SELECT * FROM approvals WHERE job_id=? ORDER BY id", (job_id,))
            for a in job["approvals"]:
                a["plan"] = json.loads(a.pop("plan_json"))
            job["counts"] = {r["state"]: r["n"] for r in self.db.query("SELECT state, COUNT(*) AS n FROM findings WHERE job_id=? GROUP BY state", (job_id,))}
        return job

    # --- execução ---------------------------------------------------------------------------
    def _step(self, job_id: int, key: str, status: str, summary: str = "") -> None:
        col = "started_at" if status == "running" else "finished_at"
        self.db.execute(f"UPDATE job_steps SET status=?, {col}=?, summary=COALESCE(NULLIF(?, ''), summary) WHERE job_id=? AND name=?",
                        (status, utcnow(), summary, job_id, key))
        if status == "running":
            label = next(n for k, n, _, _ in STEPS if k == key)
            self.db.execute("UPDATE jobs SET current_step=? WHERE id=?", (label, job_id))
        else:
            done = {r["name"] for r in self.db.query("SELECT name FROM job_steps WHERE job_id=? AND status NOT IN ('pending','running')", (job_id,))}
            self.db.execute("UPDATE jobs SET progress=? WHERE id=?", (sum(w for k, _, _, w in STEPS if k in done), job_id))

    def _evidence(self, evidence_id: int) -> dict:
        e = self.db.one("SELECT * FROM http_evidence WHERE id=?", (evidence_id,))
        if not e:
            return {"kind": "http", "summary": "evidência não encontrada"}
        req_h = json.loads(e["request_headers"] or "{}")
        resp_h = json.loads(e["response_headers"] or "{}")
        request = f"{e['method']} {e['url']}\n" + "\n".join(f"{k}: {v}" for k, v in req_h.items())
        response = f"HTTP {e['status']}\n" + "\n".join(f"{k}: {v}" for k, v in resp_h.items()) + "\n\n" + (e["body_excerpt"] or "")[:1200]
        return {"kind": "http", "evidence_id": evidence_id, "summary": f"{e['method']} {e['url']} → {e['status']} em {e['ts']}",
                "request": request, "response": response, "body_sha256": e["body_sha256"]}

    def _web_issue(self, job: dict, issue: web.WebIssue) -> int:
        ev = self._evidence(issue.evidence_id)
        repro = (f"1. Envie a requisição registrada na evidência #{issue.evidence_id}.\n2. Observe na resposta: {issue.detail}.") if issue.state == "hypothesis" else ""
        return self.findings.create(job["id"], job["program_id"], NewFinding(
            issue.check_id, issue.url, issue.component, "chl-dast" if issue.check_id in ("xss-reflected", "sqli-error", "open-redirect") else "chl-webchecks",
            evidence=[ev], description=issue.detail, snippet=issue.snippet or issue.detail, state=issue.state,
            repro_steps=repro, extra_fp_signals=issue.extra_fp))

    def _run(self, job_id: int, user: dict, rt: _Runtime) -> None:
        job = self.get(job_id)
        actor = user["name"]
        scope = self.scopes.by_version_id(job["scope_version_id"])
        client = ScopedHttpClient(db=self.db, audit=self.audit, settings=self.settings, scope=scope, job_id=job_id,
                                  actor=actor, cancel=rt.cancel, resolver=self.resolver)
        self.db.execute("UPDATE jobs SET status='running', started_at=? WHERE id=?", (utcnow(), job_id))
        self.audit.record(actor, "job.start", "ok", target=job["target"], job_id=job_id)
        opts = job["options"]
        tmp = Path(tempfile.mkdtemp(prefix=f"chl-job{job_id}-"))
        try:
            # 1. escopo
            self._step(job_id, "scope", "running")
            d = scope.check_url(job["target"], self.resolver)
            if not d.allowed:
                raise OutOfScope(job["target"], d)
            self._step(job_id, "scope", "done", f"{d.reason} · escopo v{scope.version} · {scope.rules['rate_limit_rps']} req/s · máx. {scope.rules['max_requests_per_job']} req")
            # 2. reconhecimento
            self._step(job_id, "recon", "running")
            client.step = "recon"
            rec = web.recon(client, job["target"])
            base = f"{urlsplit(job['target']).scheme}://{urlsplit(job['target']).netloc}"
            web.discover_api_specs(client, base + "/", rec)
            for host, ips in rec.dns.items():
                self._asset(job_id, "host", host, {"ips": ips})
            for ep in rec.endpoints.values():
                self._asset(job_id, "endpoint", f"{ep.method} {ep.url}", {"params": ep.params, "source": ep.source})
            for link in sorted(rec.out_of_scope_links)[:200]:
                self._asset(job_id, "fora_do_escopo", link, {"nota": "registrado sem requisição"})
            for spec, ops in rec.api_specs.items():
                self._asset(job_id, "api_spec", spec, {"operations": ops[:200]})
            self._step(job_id, "recon", "done", f"{len(rec.pages)} páginas, {len(rec.endpoints)} pontos de entrada, "
                       f"{len(rec.api_specs)} especificação(ões) de API, {len(rec.out_of_scope_links)} links fora do escopo ignorados")
            rt.cancel.raise_if_cancelled()
            # 3. inventário
            self._step(job_id, "inventory", "running")
            techs = web.fingerprint(rec.pages, rec.scripts, rec.meta)
            for t in techs:
                self._asset(job_id, "tecnologia", f"{t.name} {t.version}".strip(), {"evidence": t.evidence, "ecosystem": t.ecosystem, "package": t.package})
            self._step(job_id, "inventory", "done", ", ".join(f"{t.name} {t.version}".strip() for t in techs) or "nenhuma tecnologia identificada")
            # 4. web/API passivo
            self._step(job_id, "webapi", "running")
            client.step = "webapi"
            pages = rec.pages + web.error_probe(client, base + "/")
            issues = web.passive_checks(pages)
            cors_targets = [job["target"]] + [ep.url for ep in rec.endpoints.values()
                                              if ep.method == "GET" and ("/api" in ep.url or ep.source == "OpenAPI")][:5]
            for cors_url in dict.fromkeys(cors_targets):
                cors = web.cors_probe(client, cors_url)
                if cors:
                    issues.append(cors)
            for spec in rec.api_specs:
                issues.append(web.WebIssue("api-spec-exposed", spec, urlsplit(spec).netloc, f"{len(rec.api_specs[spec])} operações publicadas",
                                           self._last_evidence(job_id, spec)))
            for issue in issues:
                self._web_issue(job, issue)
            self._step(job_id, "webapi", "done", f"{len(issues)} observação(ões)/hipótese(s)")
            rt.cancel.raise_if_cancelled()
            # 5. SAST
            source_root = None
            if job.get("source_path"):
                self._step(job_id, "sast", "running")
                try:
                    ex = safe_extract(Path(job["source_path"]), tmp / "src", max_zip_bytes=self.settings.max_zip_bytes,
                                      max_unpacked=self.settings.max_unpacked_bytes, max_entries=self.settings.max_zip_entries,
                                      max_ratio=self.settings.max_ratio)
                    source_root = ex.root
                    rep = run_sast(ex.root, max_file_bytes=self.settings.sast_max_file_bytes, tool_timeout=self.settings.tool_timeout,
                                   use_external=opts.get("external_tools", True))
                    for h in rep.hits:
                        self.findings.create(job_id, job["program_id"], NewFinding(
                            h.check_id, f"{h.path}:{h.line}", h.path, h.tool, evidence=[{"kind": "código", "summary": h.note, "file": h.path,
                            "line": h.line, "snippet": h.snippet}], description=h.note, snippet=h.snippet, state=h.state, cwe=h.cwe))
                    unavailable = f" · indisponíveis: {', '.join(rep.tools_unavailable)}" if rep.tools_unavailable else ""
                    self._step(job_id, "sast", "done", f"{rep.files_scanned} arquivos, {len(rep.hits)} resultados · ferramentas: {', '.join(rep.tools_used)}{unavailable}")
                except UnsafeArchive as exc:
                    self.audit.record(actor, "sast.reject", "blocked", target="source.zip", job_id=job_id, details={"reason": str(exc)})
                    self._step(job_id, "sast", "failed", f"ZIP recusado: {exc}")
            else:
                self._step(job_id, "sast", "skipped", "nenhum código-fonte enviado")
            rt.cancel.raise_if_cancelled()
            # 6. SCA + CVE
            self._step(job_id, "sca", "running")
            packages: list[sca.Package] = []
            notes: list[str] = []
            if source_root is not None:
                packages, notes = sca.parse_manifests(source_root)
            packages += [sca.Package(t.ecosystem, t.package, t.version, t.evidence) for t in techs if t.ecosystem and t.version]
            res = sca.correlate(packages, online=self.settings.osv_online, api=self.settings.osv_api, offline_dir=self.settings.osv_offline_dir)
            for p in packages:
                self._asset(job_id, "dependencia", f"{p.ecosystem}:{p.name}@{p.version}", {"source": p.source})
            for pkg, adv in res.matches:
                ids = ", ".join([adv.id] + adv.aliases)
                self.findings.create(job_id, job["program_id"], NewFinding(
                    "vulnerable-component", pkg.source if not pkg.source.startswith("script ") else pkg.source[7:], f"{pkg.ecosystem}:{pkg.name}",
                    "chl-sca", title=f"{pkg.name} {pkg.version} afetado por {ids}",
                    evidence=[{"kind": "dependência", "summary": f"{pkg.ecosystem}:{pkg.name}@{pkg.version} encontrado em {pkg.source}; "
                               f"corrigido em: {', '.join(adv.fixed) or 'sem versão corrigida informada'} (fonte: {res.source})"}],
                    description=f"{adv.summary}. Versões corrigidas: {', '.join(adv.fixed) or 'não informadas'}.",
                    snippet=f"{pkg.name}@{pkg.version}:{adv.id}", state="hypothesis", cvss_vector=adv.cvss_vector,
                    references=[f"https://osv.dev/vulnerability/{adv.id}"] + adv.references[:5],
                    extra_fp_signals=[] if pkg.exact else ["versão inferida de faixa no package.json; confirme no lockfile"]))
            self._step(job_id, "sca", "done", f"{len(packages)} componentes, {len(res.matches)} correlação(ões) · fonte: {res.source}"
                       + (f" · {'; '.join((notes + res.notes)[:3])}" if notes or res.notes else ""))
            rt.cancel.raise_if_cancelled()
            # 7. DAST ativo com aprovação
            if opts.get("active"):
                plan = web.plan_active_tests(rec.endpoints, limit=int(opts.get("active_limit", 60)))
                if not plan:
                    self._step(job_id, "dast", "skipped", "nenhum parâmetro GET descoberto para testar")
                else:
                    self._step(job_id, "dast", "running", f"aguardando aprovação de {len(plan)} testes")
                    ap_id = self.db.execute("INSERT INTO approvals(job_id, kind, plan_json, status, requested_at) VALUES(?,?,?,?,?)",
                                            (job_id, "dast-active", dumps(plan), "pending", utcnow()))
                    self.db.execute("UPDATE jobs SET status='awaiting_approval' WHERE id=?", (job_id,))
                    self.audit.record("engine", "approval.requested", "pending", target=job["target"], job_id=job_id, details={"tests": len(plan)})
                    while not rt.approval.wait(timeout=1.0):
                        pass
                    rt.cancel.raise_if_cancelled()
                    ap = self.db.one("SELECT status FROM approvals WHERE id=?", (ap_id,))
                    self.db.execute("UPDATE jobs SET status='running' WHERE id=?", (job_id,))
                    if ap["status"] != "approved":
                        self._step(job_id, "dast", "skipped", "testes ativos recusados pela pesquisadora")
                    else:
                        client.step = "dast"
                        found = errors = 0
                        for item in plan:
                            rt.cancel.raise_if_cancelled()
                            try:
                                issue = web.run_active_test(client, item)
                            except (OutOfScope, requests.RequestException):
                                errors += 1
                                continue
                            except BudgetExceeded:
                                errors += 1
                                break
                            if issue:
                                self._web_issue(job, issue)
                                found += 1
                        self._step(job_id, "dast", "done", f"{len(plan)} testes aprovados executados, {found} hipótese(s), {errors} erro(s)")
            else:
                self._step(job_id, "dast", "skipped", "testes ativos não solicitados")
            # 8. IA
            if opts.get("ai", True):
                self._step(job_id, "ai", "running")
                candidates = [f for f in self.findings.list(job_id=job_id) if f["state"] in ("hypothesis",)]
                try:
                    result = self.ai.triage(user["id"], candidates)
                    for item in result.items:
                        self.findings.attach_ai(item["finding_id"], {**item, "model": result.model})
                    for fid in result.injection_flags:
                        self.db.execute("UPDATE findings SET fp_signals=json_insert(fp_signals, '$[#]', ?) WHERE id=?",
                                        ("evidência contém texto que tenta instruir a IA (ignorado)", fid))
                    msg = f"{len(result.items)} achado(s) triados por {result.model}" + (f" · {len(result.rejected)} item(ns) da IA descartados" if result.rejected else "")
                    self._step(job_id, "ai", "done", msg)
                except (AiUnavailable, QuotaExceeded) as exc:
                    self._step(job_id, "ai", "unavailable", str(exc))
            else:
                self._step(job_id, "ai", "skipped", "IA desativada nesta tarefa")
            # 9. consolidação
            self._step(job_id, "finalize", "running")
            dups = self.db.one("SELECT COUNT(*) AS n FROM findings WHERE job_id=? AND duplicate_of IS NOT NULL", (job_id,))["n"]
            fps = self.db.one("SELECT COUNT(*) AS n FROM findings WHERE job_id=? AND fp_signals != '[]'", (job_id,))["n"]
            self._step(job_id, "finalize", "done", f"{dups} provável(is) duplicata(s) de execuções anteriores · {fps} com sinais de falso positivo")
            self._finish(job_id, "completed", actor, client)
        except Cancelled:
            self._mark_remaining(job_id, "cancelled")
            self._finish(job_id, "cancelled", actor, client)
        except OutOfScope as exc:
            self._mark_remaining(job_id, "skipped")
            self._finish(job_id, "failed", actor, client, f"bloqueado pelo escopo: {exc.decision.reason}")
        except Exception as exc:   # falha inesperada: registra e encerra sem esconder
            self._mark_remaining(job_id, "skipped")
            self._finish(job_id, "failed", actor, client, f"{type(exc).__name__}: {exc}")
            traceback.print_exc()
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def _mark_remaining(self, job_id: int, status: str) -> None:
        self.db.execute("UPDATE job_steps SET status=?, finished_at=? WHERE job_id=? AND status IN ('pending','running')", (status, utcnow(), job_id))
        self.db.execute("UPDATE approvals SET status='expired' WHERE job_id=? AND status='pending'", (job_id,))

    def _finish(self, job_id: int, status: str, actor: str, client: ScopedHttpClient, error: str = "") -> None:
        self.db.execute("UPDATE jobs SET status=?, finished_at=?, error=NULLIF(?, ''), progress=CASE WHEN ?='completed' THEN 100 ELSE progress END WHERE id=?",
                        (status, utcnow(), error, status, job_id))
        self.audit.record(actor, "job." + status, "ok" if status == "completed" else status, target=self.get(job_id)["target"], job_id=job_id,
                          details={"requests_sent": client.sent, "requests_blocked": client.blocked, "error": error})

    def _asset(self, job_id: int, kind: str, value: str, meta: dict) -> None:
        self.db.execute("INSERT OR IGNORE INTO assets(job_id, kind, value, meta_json) VALUES(?,?,?,?)", (job_id, kind, value[:1000], dumps(meta)))

    def _last_evidence(self, job_id: int, url: str) -> int:
        row = self.db.one("SELECT id FROM http_evidence WHERE job_id=? AND url=? AND decision='sent' ORDER BY id DESC LIMIT 1", (job_id, url))
        return row["id"] if row else 0
