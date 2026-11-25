"""Orquestra o SAST: analisadores internos + adaptadores de ferramentas externas, quando instaladas."""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from .. import tools
from . import python_taint, rules

TEXT_EXT = re.compile(r"\.(?:json|ya?ml|toml|ini|conf|cfg|config|properties|md|txt|js|jsx|ts|tsx|mjs|cjs|py|go|rs|java|kt|php|rb|sh|bash|tf|hcl|xml|html|sql|env\.example)$", re.I)

SEMGREP_CWE_TO_CHECK = {
    "78": "sast-cmdi", "95": "sast-code-injection", "94": "sast-code-injection", "89": "sast-sqli", "22": "sast-path-traversal",
    "918": "sast-ssrf", "502": "sast-deserialization", "1336": "sast-ssti", "79": "sast-xss", "601": "sast-open-redirect",
    "798": "secret-hardcoded", "295": "tls-verify-disabled",
}


@dataclass
class SastHit:
    check_id: str
    path: str
    line: int
    snippet: str
    state: str
    tool: str
    note: str
    title: str | None = None
    cwe: str | None = None


@dataclass
class SastReport:
    hits: list[SastHit] = field(default_factory=list)
    files_scanned: int = 0
    tools_used: list[str] = field(default_factory=list)
    tools_unavailable: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def run_sast(root: Path, *, max_file_bytes: int, tool_timeout: int, use_external: bool = True) -> SastReport:
    report = SastReport(tools_used=["chl-pytaint", "chl-rules"])
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".next"}]
        for fn in filenames:
            full = Path(dirpath) / fn
            rel = full.relative_to(root).as_posix()
            if full.is_symlink() or not (TEXT_EXT.search(fn) or fn.lower().startswith("dockerfile")):
                continue
            try:
                if full.stat().st_size > max_file_bytes:
                    report.notes.append(f"{rel}: ignorado (acima de {max_file_bytes} bytes)")
                    continue
                content = full.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            report.files_scanned += 1
            if fn.endswith(".py"):
                for h in python_taint.analyze_source(content):
                    state = "hypothesis" if h.tainted else "observation"
                    note = f"fonte: {h.source} → sink: {h.sink}" if h.tainted else f"chamada perigosa {h.sink} sem fluxo de entrada comprovado"
                    report.hits.append(SastHit(h.check_id, rel, h.line, h.snippet, state, "chl-pytaint", note))
            for h in rules.scan_lines(rel, content) + rules.scan_config(rel, content):
                if fn.endswith(".py") and h.check_id in ("sast-dangerous-call",):
                    continue
                report.hits.append(SastHit(h.check_id, rel, h.line, h.snippet, h.state, "chl-rules", h.note))
    if use_external:
        _semgrep(root, tool_timeout, report)
        _gitleaks(root, tool_timeout, report)
    return report


def _semgrep(root: Path, timeout: int, report: SastReport) -> None:
    if not tools.available("semgrep"):
        report.tools_unavailable.append("semgrep")
        return
    config = os.environ.get("CHL_SEMGREP_CONFIG", "p/default")
    run = tools.run(["semgrep", "scan", "--config", config, "--json", "--metrics=off", "--quiet", "--disable-version-check", str(root)],
                    cwd=str(root), timeout=timeout)
    if run.timed_out or not run.stdout.strip().startswith("{"):
        report.notes.append(f"semgrep não concluiu (código {run.returncode}): {run.stderr[:200]}")
        return
    report.tools_used.append("semgrep")
    for r in json.loads(run.stdout).get("results", []):
        cwes = r.get("extra", {}).get("metadata", {}).get("cwe") or []
        cwes = [cwes] if isinstance(cwes, str) else cwes
        num = next((m.group(1) for c in cwes for m in [re.search(r"CWE-(\d+)", str(c))] if m), None)
        check = SEMGREP_CWE_TO_CHECK.get(num or "", "sast-dangerous-call")
        path = Path(r.get("path", "")).resolve()
        try:
            rel = path.relative_to(root.resolve()).as_posix()
        except ValueError:
            rel = r.get("path", "")
        report.hits.append(SastHit(check, rel, int(r.get("start", {}).get("line", 0)), r.get("extra", {}).get("lines", "")[:300],
                                   "hypothesis", "semgrep", f"{r.get('check_id')}: {r.get('extra', {}).get('message', '')[:300]}",
                                   cwe=f"CWE-{num}" if num else None))


def _gitleaks(root: Path, timeout: int, report: SastReport) -> None:
    if not tools.available("gitleaks"):
        report.tools_unavailable.append("gitleaks")
        return
    out = root.parent / "gitleaks.json"
    run = tools.run(["gitleaks", "detect", "--no-git", "--redact", "--source", str(root), "--report-format", "json", "--report-path", str(out)],
                    cwd=str(root.parent), timeout=timeout)
    if not out.exists():
        report.notes.append(f"gitleaks não gerou relatório (código {run.returncode})")
        return
    report.tools_used.append("gitleaks")
    for r in json.loads(out.read_text() or "[]"):
        report.hits.append(SastHit("secret-hardcoded", r.get("File", ""), int(r.get("StartLine", 0)), (r.get("Match") or "")[:200],
                                   "hypothesis", "gitleaks", f"regra {r.get('RuleID')}"))
