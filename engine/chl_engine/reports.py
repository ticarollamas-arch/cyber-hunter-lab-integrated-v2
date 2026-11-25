"""Relatórios técnicos (RF-004): Markdown, PDF, JSON e SARIF 2.1.0.

Só achados `validated` entram. Cada achado precisa dos campos obrigatórios; se faltar algum, o
relatório não é gerado e a lista de pendências é devolvida.
"""
from __future__ import annotations

import io
import json

from . import taxonomy
from .db import utcnow
from .security import mask_text

REQUIRED = ("title", "description", "repro_steps", "impact", "evidence_json", "cwe", "cvss_vector", "cvss_score", "recommendation")


class ReportError(ValueError):
    def __init__(self, problems: list[str]):
        super().__init__("; ".join(problems))
        self.problems = problems


def check_required(findings: list[dict]) -> list[str]:
    problems = []
    for f in findings:
        for field in REQUIRED:
            value = f.get(field)
            if value in (None, "", []):
                problems.append(f"achado #{f['id']}: campo obrigatório '{field}' vazio")
    return problems


def build(program: dict, job: dict, findings: list[dict], scope_info: dict) -> dict:
    validated = [f for f in findings if f["state"] == "validated"]
    if not validated:
        raise ReportError(["nenhum achado validado — relatório não gerado"])
    problems = check_required(validated)
    if problems:
        raise ReportError(problems)
    return {
        "schema": "cyberhuntlab.report/1",
        "generated_at": utcnow(),
        "program": {"name": program["name"], "platform": program.get("platform"), "policy_url": program.get("policy_url")},
        "job": {"id": job["id"], "target": job["target"], "started_at": job.get("started_at"), "finished_at": job.get("finished_at")},
        "scope": scope_info,
        "findings": [{
            "id": f["id"], "title": f["title"], "cwe": f["cwe"], "cwe_name": taxonomy.CWE_NAMES.get(f["cwe"] or "", ""),
            "wstg": f.get("wstg"), "severity": f["severity"], "cvss_vector": f["cvss_vector"], "cvss_score": f["cvss_score"],
            "location": f["location"], "description": mask_text(f["description"]), "repro_steps": mask_text(f["repro_steps"]),
            "impact": mask_text(f["impact"]), "recommendation": f["recommendation"], "evidence": f["evidence_json"],
            "references": f.get("references_json") or [], "source_tool": f["source_tool"],
        } for f in validated],
    }


def to_markdown(report: dict) -> str:
    out = [f"# Relatório de segurança — {report['program']['name']}", "",
           f"- Alvo: `{report['job']['target']}`", f"- Execução: #{report['job']['id']} ({report['job'].get('started_at') or '-'} → {report['job'].get('finished_at') or '-'})",
           f"- Escopo aplicado: versão {report['scope'].get('version')} (sha256 `{report['scope'].get('sha256', '')[:16]}…`)",
           f"- Gerado em: {report['generated_at']}", f"- Política do programa: {report['program'].get('policy_url') or 'não informada'}", "",
           "> Todos os achados abaixo foram validados manualmente. Evidências têm segredos e dados pessoais mascarados.", ""]
    for i, f in enumerate(report["findings"], 1):
        out += [f"## {i}. {f['title']}", "",
                "| Campo | Valor |", "|---|---|",
                f"| Severidade | {f['severity'].upper()} — CVSS {f['cvss_score']} |", f"| Vetor CVSS | `{f['cvss_vector']}` |",
                f"| CWE | {f['cwe']} {f['cwe_name']} |", f"| WSTG | {f['wstg'] or '—'} |", f"| Local | `{f['location']}` |",
                f"| Ferramenta | {f['source_tool']} |", "",
                "### Descrição", "", f["description"], "", "### Passos de reprodução", "", f["repro_steps"], "",
                "### Impacto", "", f["impact"], "", "### Evidências", ""]
        for ev in f["evidence"]:
            out.append(f"- {ev.get('kind', 'evidência')}: {ev.get('summary', '')}")
            if ev.get("request"):
                out += ["", "```http", ev["request"][:1500], "```"]
            if ev.get("response"):
                out += ["", "```http", ev["response"][:1500], "```"]
        out += ["", "### Recomendação", "", f["recommendation"], ""]
        if f["references"]:
            out += ["### Referências", ""] + [f"- {r}" for r in f["references"]] + [""]
    return "\n".join(out)


def to_sarif(report: dict) -> dict:
    rules, results = {}, []
    for f in report["findings"]:
        rid = (f["cwe"] or "CHL").replace(" ", "")
        rules[rid] = {"id": rid, "name": f["cwe_name"] or f["title"], "shortDescription": {"text": f["title"]},
                      "properties": {"security-severity": str(f["cvss_score"])}}
        loc = f["location"]
        if loc.startswith("http"):
            location = {"physicalLocation": {"artifactLocation": {"uri": loc}}}
        else:
            path, _, line = loc.rpartition(":")
            location = {"physicalLocation": {"artifactLocation": {"uri": path or loc}, "region": {"startLine": int(line) if line.isdigit() else 1}}}
        results.append({"ruleId": rid, "level": "error" if f["cvss_score"] >= 7 else "warning",
                        "message": {"text": f"{f['title']} — {f['description'][:300]}"}, "locations": [location]})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "CyberHuntLab", "version": "0.1.0", "rules": list(rules.values())}}, "results": results}]}


def to_pdf(report: dict) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import Paragraph, Preformatted, SimpleDocTemplate, Spacer
    from xml.sax.saxutils import escape

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm, topMargin=2 * cm, bottomMargin=2 * cm,
                            title=f"Relatório — {report['program']['name']}")
    st = getSampleStyleSheet()
    story = []
    for line in to_markdown(report).splitlines():
        if line.startswith("# "):
            story.append(Paragraph(escape(line[2:]), st["Title"]))
        elif line.startswith("## "):
            story += [Spacer(1, 8), Paragraph(escape(line[3:]), st["Heading2"])]
        elif line.startswith("### "):
            story.append(Paragraph(escape(line[4:]), st["Heading4"]))
        elif line.startswith("```") or line.startswith("|---"):
            continue
        elif line.startswith("|"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            if cells[0] != "Campo":
                story.append(Paragraph(f"<b>{escape(cells[0])}:</b> {escape(' | '.join(cells[1:]))}", st["BodyText"]))
        elif line.strip():
            if line.startswith(("GET ", "POST ", "HTTP/")):
                story.append(Preformatted(line[:110], st["Code"]))
            else:
                story.append(Paragraph(escape(line.lstrip("-> ").replace("`", "")), st["BodyText"]))
    doc.build(story)
    return buf.getvalue()


def to_json(report: dict) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2)
