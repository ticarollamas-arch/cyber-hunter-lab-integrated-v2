"""Regras por padrão de texto.

As regras de segredos, TLS, execução, CORS, debug, Docker, Kubernetes e Terraform foram portadas da
rota original `src/app/api/security-audit/route.ts` (mesmas expressões e recomendações), agora com
CWE. As regras JS de fonte→sink na mesma linha geram hipótese; as demais, observação.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class RuleHit:
    check_id: str
    line: int
    snippet: str
    state: str          # observation | hypothesis
    note: str


LINE_RULES: list[tuple[re.Pattern[str], str, str, str]] = [
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "secret-hardcoded", "hypothesis", "padrão de AWS Access Key"),
    (re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"), "secret-hardcoded", "hypothesis", "padrão de token GitHub"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "secret-hardcoded", "hypothesis", "chave privada no código"),
    (re.compile(r"(?i)(?:api[_-]?key|secret|password|token)\s*[:=]\s*[\"'][^\"'\s]{12,}[\"']"), "secret-hardcoded", "observation", "atribuição com aparência de credencial"),
    (re.compile(r"(?i)(?:password|passwd|secret|token)\s*[:=]\s*[\"'](?:changeme|password|admin|123456|test)[\"']"), "secret-hardcoded", "observation", "credencial padrão/fraca"),
    (re.compile(r"(?:rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0|verify\s*=\s*False)", re.I), "tls-verify-disabled", "observation", "validação TLS desativada"),
    (re.compile(r"(?:Access-Control-Allow-Origin\s*[:=]\s*[\"']\*[\"']|cors\s*\(\s*\{[^}]*origin\s*:\s*[\"']\*[\"'])", re.I), "cors-wildcard-config", "observation", "origem curinga"),
    (re.compile(r"(?:\bdebug\s*[:=]\s*true\b|\bDEBUG\s*=\s*True\b|\.run\([^)]*debug\s*=\s*True)"), "debug-enabled", "observation", "debug habilitado"),
]

JS_EXT = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
JS_SOURCE = r"(?:req\.(?:query|params|body|headers|cookies)|request\.(?:query|params|body)|location\.(?:hash|search|href)|document\.URL|window\.name)"
JS_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?:child_process\.)?\b(?:exec|execSync)\s*\([^)]*" + JS_SOURCE), "sast-cmdi"),
    (re.compile(r"\beval\s*\([^)]*" + JS_SOURCE + r"|new Function\s*\([^)]*" + JS_SOURCE), "sast-code-injection"),
    (re.compile(r"\.(?:query|execute|raw)\s*\(\s*(?:`[^`]*\$\{\s*" + JS_SOURCE + r"|[\"'][^\"']*[\"']\s*\+\s*" + JS_SOURCE + r")"), "sast-sqli"),
    (re.compile(r"res\.(?:send|write|end)\s*\([^)]*" + JS_SOURCE), "sast-xss"),
    (re.compile(r"\.(?:innerHTML|outerHTML)\s*=\s*[^;]*" + JS_SOURCE + r"|document\.write\s*\([^)]*" + JS_SOURCE), "sast-xss"),
    (re.compile(r"res\.redirect\s*\(\s*" + JS_SOURCE), "sast-open-redirect"),
    (re.compile(r"(?:fs\.(?:readFile|readFileSync|createReadStream)|res\.sendFile)\s*\([^)]*" + JS_SOURCE), "sast-path-traversal"),
    (re.compile(r"(?:axios\.(?:get|post)|fetch|got)\s*\(\s*" + JS_SOURCE), "sast-ssrf"),
]
JS_DANGEROUS = re.compile(r"\beval\s*\(|new Function\s*\(|child_process\.(?:exec|execSync)\s*\(")


def scan_lines(path: str, content: str) -> list[RuleHit]:
    hits: list[RuleHit] = []
    is_js = path.lower().endswith(JS_EXT)
    for i, line in enumerate(content.splitlines(), 1):
        if len(line) > 2000:          # linhas minificadas: evita custo e ruído
            continue
        for pattern, check, state, note in LINE_RULES:
            if pattern.search(line):
                hits.append(RuleHit(check, i, line.strip()[:300], state, note))
                break
        if is_js:
            matched = False
            for pattern, check in JS_RULES:
                if pattern.search(line):
                    hits.append(RuleHit(check, i, line.strip()[:300], "hypothesis", "fonte e sink na mesma instrução"))
                    matched = True
                    break
            if not matched and JS_DANGEROUS.search(line):
                hits.append(RuleHit("sast-dangerous-call", i, line.strip()[:300], "observation", "execução dinâmica"))
    return hits


def scan_config(path: str, content: str) -> list[RuleHit]:
    """Regras de arquivo inteiro (Docker, Compose, Kubernetes, Terraform) portadas da rota original."""
    hits: list[RuleHit] = []
    low = path.lower()
    name = low.rsplit("/", 1)[-1]
    if name.startswith("dockerfile"):
        if re.search(r"^\s*USER\s+root\b", content, re.I | re.M) or not re.search(r"^\s*USER\s+\S+", content, re.I | re.M):
            hits.append(RuleHit("container-root", 1, "Dockerfile sem USER não-root", "observation", "Dockerfile define root ou não declara usuário"))
    if re.search(r"docker-compose\.ya?ml$", low) and re.search(r"privileged\s*:\s*true", content, re.I):
        hits.append(RuleHit("container-root", _line_of(content, r"privileged\s*:\s*true"), "privileged: true", "observation", "container privilegiado"))
    if low.endswith((".yaml", ".yml")) and re.search(r"kind:\s*(Pod|Deployment|DaemonSet|StatefulSet|Job|CronJob)", content, re.I):
        for pat, note in [(r"privileged\s*:\s*true", "pod privilegiado"), (r"host(?:Network|PID|IPC)\s*:\s*true", "namespace do host"),
                          (r"runAsUser\s*:\s*0\b", "UID 0"), (r"hostPath\s*:", "volume hostPath")]:
            if re.search(pat, content, re.I):
                hits.append(RuleHit("k8s-privileged", _line_of(content, pat), note, "observation", note))
    if low.endswith(".tf"):
        for pat, note in [(r"publicly_accessible\s*=\s*true", "banco publicamente acessível"),
                          (r"acl\s*=\s*[\"']public-read[\"']", "ACL pública"),
                          (r"0\.0\.0\.0/0", "CIDR aberto 0.0.0.0/0")]:
            if re.search(pat, content, re.I):
                hits.append(RuleHit("iac-public-exposure", _line_of(content, pat), note, "observation", note))
    return hits


def _line_of(content: str, pattern: str) -> int:
    m = re.search(pattern, content, re.I)
    return content.count("\n", 0, m.start()) + 1 if m else 1
