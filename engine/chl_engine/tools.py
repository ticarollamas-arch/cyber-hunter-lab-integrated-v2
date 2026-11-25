"""Ferramentas externas: detecção, execução isolada e registro de uso.

Regras:
- Só entram ferramentas que não enviam tráfego ao alvo por conta própria (análise local ou fontes
  passivas). Scanners ativos de terceiros (nuclei, ZAP) ficam de fora até existir um proxy que
  imponha escopo e limite de taxa a eles — caso contrário contornariam os controles do RF-001.
- Execução sem shell, com tempo limite e limites de CPU/memória (RNF-002).
- Ferramenta ausente é informada como "indisponível"; nunca é simulada.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass

KNOWN_TOOLS = {
    "semgrep": {"purpose": "SAST multi-linguagem", "version": ["semgrep", "--version"], "network": "baixa regras do registro se a config for p/…"},
    "gitleaks": {"purpose": "segredos em código", "version": ["gitleaks", "version"], "network": "nenhuma"},
    "subfinder": {"purpose": "subdomínios por fontes passivas (não contata o alvo)", "version": ["subfinder", "-version"], "network": "fontes públicas"},
    "osv-scanner": {"purpose": "dependências vulneráveis", "version": ["osv-scanner", "--version"], "network": "api.osv.dev"},
}

BUILTIN_TOOLS = {
    "chl-scope": "verificação de escopo",
    "chl-crawler": "reconhecimento web dentro do escopo",
    "chl-fingerprint": "inventário de tecnologias",
    "chl-webchecks": "análise passiva de web/API",
    "chl-dast": "testes ativos com aprovação",
    "chl-pytaint": "SAST Python (taint por AST)",
    "chl-rules": "SAST por padrões (portado da auditoria ZIP original)",
    "chl-sca": "SCA + correlação CVE/OSV",
    "chl-ai": "triagem assistida por IA",
}


@dataclass
class ToolRun:
    tool: str
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


def available(name: str) -> str | None:
    return shutil.which(name)


def inventory() -> list[dict]:
    out = []
    for name, meta in KNOWN_TOOLS.items():
        path = available(name)
        version = ""
        if path:
            try:
                r = subprocess.run(meta["version"], capture_output=True, text=True, timeout=20)
                version = (r.stdout or r.stderr).strip().splitlines()[0][:80] if (r.stdout or r.stderr) else ""
            except (OSError, subprocess.TimeoutExpired):
                version = "?"
        out.append({"name": name, "kind": "externa", "available": bool(path), "version": version, "purpose": meta["purpose"], "network": meta["network"]})
    for name, purpose in BUILTIN_TOOLS.items():
        out.append({"name": name, "kind": "interna", "available": True, "version": "0.1.0", "purpose": purpose, "network": "via cliente com escopo" if name in ("chl-crawler", "chl-webchecks", "chl-dast") else "nenhuma"})
    return out


def _limits(cpu_seconds: int, memory_bytes: int):
    def apply():
        if sys.platform.startswith("linux"):
            import resource
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
            resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            os.setsid()
    return apply


def run(argv: list[str], *, cwd: str, timeout: int, cpu_seconds: int | None = None, memory_mb: int = 2048) -> ToolRun:
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": cwd, "LANG": "C.UTF-8", "SEMGREP_SEND_METRICS": "off"}
    try:
        r = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout,
                           preexec_fn=_limits(cpu_seconds or timeout, memory_mb * 1024 * 1024), stdin=subprocess.DEVNULL)
        return ToolRun(argv[0], r.returncode, r.stdout, r.stderr)
    except subprocess.TimeoutExpired as exc:
        return ToolRun(argv[0], -1, exc.stdout or "", exc.stderr or "", timed_out=True)
