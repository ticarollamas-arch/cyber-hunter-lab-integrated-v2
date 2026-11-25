"""Achados com estados, histórico, deduplicação e sinais de falso positivo (RF-003, RF-011).

Estados: observation → hypothesis → validated | false_positive.
- O motor e a IA só criam observações e hipóteses.
- Só uma pessoa (papel admin/researcher) valida ou descarta, e a validação exige evidência, CWE e
  vetor CVSS — os campos obrigatórios do relatório (RF-004).
- A deduplicação só sugere (`duplicate_of`); a decisão final é humana.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from . import cvss, taxonomy
from .audit import AuditLog
from .db import Database, dumps, utcnow
from .security import mask_text

STATES = ("observation", "hypothesis", "validated", "false_positive")
TRANSITIONS = {
    "observation": {"hypothesis", "false_positive"},
    "hypothesis": {"validated", "false_positive", "observation"},
    "validated": {"hypothesis"},
    "false_positive": {"hypothesis"},
}
MACHINE_ACTORS = {"engine", "ai", "system"}

TEST_PATH = re.compile(r"(^|/)(tests?|__tests__|spec|specs|fixtures?|examples?|samples?|docs?|mocks?)(/|$)|(_test|\.test|\.spec)\.[a-z]+$", re.I)
PLACEHOLDER = re.compile(r"(?i)(x{4,}|example|exemplo|your[_-]?(key|token|secret)|<[^>]+>|\$\{[^}]+\}|placeholder|dummy|fake|0{8,})")


class FindingError(ValueError):
    pass


@dataclass
class NewFinding:
    check_id: str
    location: str              # URL ou arquivo:linha
    component: str             # host ou arquivo / pacote
    source_tool: str
    evidence: list[dict] = field(default_factory=list)
    description: str = ""
    snippet: str = ""          # trecho normalizado usado na deduplicação
    state: str = "observation"
    title: str | None = None
    cvss_vector: str | None = None
    references: list[str] = field(default_factory=list)
    impact: str = ""
    repro_steps: str = ""
    extra_fp_signals: list[str] = field(default_factory=list)
    cwe: str | None = None     # sobrescreve o CWE do catálogo (ex.: regra do Semgrep)


def _norm_location(location: str) -> str:
    if location.startswith(("http://", "https://")):
        p = urlsplit(location)
        params = sorted(k.split("=")[0] for k in p.query.split("&") if k)
        return f"{p.scheme}://{p.netloc}{p.path}?{'&'.join(params)}"
    return re.sub(r":\d+$", "", location)   # arquivo:linha → arquivo (linha muda com edições)


def _norm_snippet(snippet: str) -> str:
    return re.sub(r"\s+", " ", snippet or "").strip()[:500]


def fingerprint(check_id: str, cwe: str | None, location: str, snippet: str) -> str:
    raw = "|".join([cwe or check_id, _norm_location(location), _norm_snippet(snippet)])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def fp_signals(nf: NewFinding) -> list[str]:
    signals = list(nf.extra_fp_signals)
    path = nf.location.split(":")[0] if not nf.location.startswith("http") else ""
    if path and TEST_PATH.search(path):
        signals.append("arquivo de teste, exemplo ou documentação")
    if nf.check_id == "secret-hardcoded" and PLACEHOLDER.search(nf.snippet or ""):
        signals.append("valor parece um marcador de exemplo, não um segredo real")
    return signals


class FindingStore:
    def __init__(self, db: Database, audit: AuditLog):
        self.db, self.audit = db, audit

    def create(self, job_id: int, program_id: int, nf: NewFinding) -> int:
        check = taxonomy.get(nf.check_id)
        if nf.state not in ("observation", "hypothesis"):
            raise FindingError("o motor só cria observações ou hipóteses")
        vector = nf.cvss_vector or check.vector
        score = cvss.base_score(vector) if vector else None
        sev = cvss.severity(score)
        cwe = nf.cwe or check.cwe
        fp = fingerprint(check.id, cwe, nf.location, nf.snippet or nf.location)
        group_key = "|".join([cwe or check.id, nf.component, check.id])
        signals = fp_signals(nf)
        now = utcnow()
        with self.db.tx() as c:
            same_job = c.execute("SELECT id FROM findings WHERE job_id=? AND fingerprint=?", (job_id, fp)).fetchone()
            if same_job:
                return int(same_job["id"])          # mesmo achado na mesma execução: não duplica
            prior = c.execute("SELECT id FROM findings WHERE program_id=? AND fingerprint=? ORDER BY id LIMIT 1", (program_id, fp)).fetchone()
            cur = c.execute(
                "INSERT INTO findings(job_id, program_id, title, cwe, wstg, severity, cvss_vector, cvss_score, state, location, component,"
                " description, evidence_json, recommendation, source_tool, fingerprint, group_key, duplicate_of, fp_signals, references_json,"
                " impact, repro_steps, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (job_id, program_id, nf.title or check.title, cwe, check.wstg, sev, vector, score, nf.state, nf.location, nf.component,
                 mask_text(nf.description), dumps(nf.evidence), check.recommendation, nf.source_tool, fp, group_key,
                 prior["id"] if prior else None, dumps(signals), dumps(nf.references), nf.impact, nf.repro_steps, now, now))
            fid = int(cur.lastrowid)
            c.execute("INSERT INTO finding_history(finding_id, from_state, to_state, actor, note, ts) VALUES(?,?,?,?,?,?)",
                      (fid, None, nf.state, "engine", f"criado por {nf.source_tool}", now))
        return fid

    def get(self, finding_id: int) -> dict | None:
        row = self.db.one("SELECT * FROM findings WHERE id=?", (finding_id,))
        if row:
            for k in ("evidence_json", "fp_signals", "references_json"):
                row[k] = json.loads(row[k] or "[]")
            row["ai"] = json.loads(row["ai_json"]) if row.get("ai_json") else None
            row["history"] = self.db.query("SELECT * FROM finding_history WHERE finding_id=? ORDER BY id", (finding_id,))
        return row

    def list(self, job_id: int | None = None, program_id: int | None = None, state: str | None = None) -> list[dict]:
        sql, params = "SELECT * FROM findings WHERE 1=1", []
        if job_id is not None:
            sql += " AND job_id=?"; params.append(job_id)
        if program_id is not None:
            sql += " AND program_id=?"; params.append(program_id)
        if state:
            sql += " AND state=?"; params.append(state)
        sql += " ORDER BY COALESCE(cvss_score, -1) DESC, id"
        rows = self.db.query(sql, params)
        for r in rows:
            r["fp_signals"] = json.loads(r["fp_signals"] or "[]")
            r["evidence_json"] = json.loads(r["evidence_json"] or "[]")
        return rows

    def update_fields(self, finding_id: int, actor: str, *, cvss_vector: str | None = None, impact: str | None = None,
                      repro_steps: str | None = None, description: str | None = None) -> None:
        f = self.get(finding_id)
        if not f:
            raise FindingError("achado não encontrado")
        vector = cvss_vector if cvss_vector is not None else f["cvss_vector"]
        score = cvss.base_score(vector) if vector else None
        self.db.execute("UPDATE findings SET cvss_vector=?, cvss_score=?, severity=?, impact=COALESCE(?, impact), repro_steps=COALESCE(?, repro_steps),"
                        " description=COALESCE(?, description), updated_at=? WHERE id=?",
                        (vector, score, cvss.severity(score), impact, repro_steps, mask_text(description) if description else None, utcnow(), finding_id))
        self.audit.record(actor, "finding.edit", "ok", target=str(finding_id), job_id=f["job_id"], details={"cvss_vector": vector})

    def transition(self, finding_id: int, to_state: str, actor: str, note: str = "", role: str = "researcher") -> dict:
        if to_state not in STATES:
            raise FindingError("estado inválido")
        f = self.get(finding_id)
        if not f:
            raise FindingError("achado não encontrado")
        if to_state not in TRANSITIONS[f["state"]]:
            raise FindingError(f"transição {f['state']} → {to_state} não permitida")
        if to_state in ("validated", "false_positive"):
            if actor in MACHINE_ACTORS or role not in ("admin", "researcher"):
                raise FindingError("só uma pessoa com papel de pesquisa pode validar ou descartar")
            if not note.strip():
                raise FindingError("informe a justificativa da decisão")
        if to_state == "validated":
            missing = [k for k in ("cwe", "cvss_vector") if not f.get(k)]
            if not f["evidence_json"]:
                missing.append("evidências")
            if missing:
                raise FindingError("campos obrigatórios ausentes para validar: " + ", ".join(missing))
        now = utcnow()
        with self.db.tx() as c:
            c.execute("UPDATE findings SET state=?, updated_at=? WHERE id=?", (to_state, now, finding_id))
            c.execute("INSERT INTO finding_history(finding_id, from_state, to_state, actor, note, ts) VALUES(?,?,?,?,?,?)",
                      (finding_id, f["state"], to_state, actor, mask_text(note), now))
        self.audit.record(actor, "finding.transition", "ok", target=str(finding_id), job_id=f["job_id"],
                          details={"from": f["state"], "to": to_state})
        return self.get(finding_id)

    def groups(self, program_id: int) -> list[dict]:
        rows = self.db.query("SELECT group_key, COUNT(*) AS total, GROUP_CONCAT(id) AS ids, MAX(cwe) AS cwe FROM findings"
                             " WHERE program_id=? GROUP BY group_key HAVING COUNT(*) > 1 ORDER BY total DESC", (program_id,))
        for r in rows:
            r["ids"] = [int(x) for x in r["ids"].split(",")]
        return rows

    def attach_ai(self, finding_id: int, ai: dict) -> None:
        self.db.execute("UPDATE findings SET ai_json=?, updated_at=? WHERE id=?", (dumps(ai), utcnow(), finding_id))
