"""Catálogo de verificações: CWE, caso de teste WSTG e vetor CVSS sugerido.

Os identificadores WSTG usam a forma versionada recomendada pelo projeto OWASP
(`WSTG-v42-...` para a versão estável 4.2; `WSTG-latest-...` quando o caso só existe na versão em
desenvolvimento). Vetores CVSS são sugestões para revisão humana; `None` significa que o item é
uma observação de higiene, não uma vulnerabilidade com impacto demonstrável.
"""
from __future__ import annotations

from dataclasses import dataclass

CWE_NAMES = {
    "CWE-22": "Path Traversal",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting",
    "CWE-89": "SQL Injection",
    "CWE-95": "Eval Injection",
    "CWE-209": "Error Message Containing Sensitive Information",
    "CWE-250": "Execution with Unnecessary Privileges",
    "CWE-284": "Improper Access Control",
    "CWE-295": "Improper Certificate Validation",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-489": "Active Debug Code",
    "CWE-497": "Exposure of Sensitive System Information",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-548": "Exposure of Information Through Directory Listing",
    "CWE-601": "Open Redirect",
    "CWE-614": "Sensitive Cookie Without 'Secure' Attribute",
    "CWE-693": "Protection Mechanism Failure",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-918": "Server-Side Request Forgery",
    "CWE-942": "Permissive Cross-domain Policy with Untrusted Domains",
    "CWE-1004": "Sensitive Cookie Without 'HttpOnly' Flag",
    "CWE-1021": "Improper Restriction of Rendered UI Layers (Clickjacking)",
    "CWE-1104": "Use of Unmaintained Third Party Components",
    "CWE-1275": "Sensitive Cookie with Improper SameSite Attribute",
    "CWE-1336": "Server-Side Template Injection",
    "CWE-1395": "Dependency on Vulnerable Third-Party Component",
}


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    cwe: str | None
    wstg: str | None
    vector: str | None
    category: str
    recommendation: str
    invasive: bool = False


_CHECKS = [
    # Web passivo -------------------------------------------------------------------------
    Check("hdr-hsts-missing", "Cabeçalho Strict-Transport-Security ausente", "CWE-319", "WSTG-v42-CONF-07", None, "Configuração",
          "Envie Strict-Transport-Security com max-age adequado nas respostas HTTPS."),
    Check("hdr-csp-missing", "Content-Security-Policy ausente", "CWE-693", "WSTG-latest-CONF-12", None, "Configuração",
          "Defina uma CSP restritiva (script-src sem 'unsafe-inline')."),
    Check("hdr-clickjacking", "Sem proteção contra clickjacking (X-Frame-Options / frame-ancestors)", "CWE-1021", "WSTG-v42-CLNT-09", None, "Cliente",
          "Use CSP frame-ancestors 'none' ou 'self', ou X-Frame-Options: DENY."),
    Check("hdr-nosniff-missing", "X-Content-Type-Options ausente", "CWE-693", "WSTG-latest-CONF-14", None, "Configuração",
          "Envie X-Content-Type-Options: nosniff."),
    Check("cookie-no-secure", "Cookie sem atributo Secure", "CWE-614", "WSTG-v42-SESS-02", None, "Sessão",
          "Marque cookies de sessão com Secure."),
    Check("cookie-no-httponly", "Cookie sem atributo HttpOnly", "CWE-1004", "WSTG-v42-SESS-02", None, "Sessão",
          "Marque cookies de sessão com HttpOnly."),
    Check("cookie-no-samesite", "Cookie sem atributo SameSite", "CWE-1275", "WSTG-v42-SESS-02", None, "Sessão",
          "Defina SameSite=Lax ou Strict nos cookies de sessão."),
    Check("cors-reflect-credentials", "CORS reflete origem arbitrária com credenciais", "CWE-942", "WSTG-v42-CLNT-07",
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N", "Cliente",
          "Valide Origin contra uma allowlist exata; não combine origem refletida com Allow-Credentials: true."),
    Check("cors-wildcard", "CORS com Access-Control-Allow-Origin: *", "CWE-942", "WSTG-v42-CLNT-07", None, "Cliente",
          "Confirme que o recurso é público; caso contrário restrinja as origens."),
    Check("info-server-version", "Versão de software exposta em cabeçalho", "CWE-497", "WSTG-v42-INFO-02", None, "Informação",
          "Remova ou generalize os cabeçalhos Server / X-Powered-By."),
    Check("info-stack-trace", "Mensagem de erro com detalhes internos (stack trace)", "CWE-209", "WSTG-v42-ERRH-01",
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "Erros",
          "Desative páginas de erro detalhadas em produção e registre o erro só no servidor."),
    Check("dir-listing", "Listagem de diretório habilitada", "CWE-548", "WSTG-v42-CONF-02",
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "Configuração",
          "Desative a listagem automática de diretórios no servidor web."),
    Check("api-spec-exposed", "Especificação de API publicada (OpenAPI/Swagger)", None, "WSTG-v42-INFO-06", None, "Inventário",
          "Confirme se a especificação deve ser pública; ela amplia o mapa de pontos de entrada."),
    Check("vulnerable-component", "Componente com vulnerabilidade conhecida", "CWE-1395", None, None, "Componentes",
          "Atualize para uma versão corrigida indicada no aviso."),
    # DAST ativo (exige aprovação humana) ---------------------------------------------------
    Check("xss-reflected", "Entrada refletida sem codificação (possível XSS refletido)", "CWE-79", "WSTG-v42-INPV-01",
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Injeção",
          "Codifique a saída conforme o contexto (HTML, atributo, JS) e adote CSP.", invasive=True),
    Check("sqli-error", "Erro de banco de dados provocado por entrada (possível SQL injection)", "CWE-89", "WSTG-v42-INPV-05",
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Injeção",
          "Use consultas parametrizadas; nunca concatene entrada em SQL.", invasive=True),
    Check("open-redirect", "Redirecionamento para destino controlado pela entrada (open redirect)", "CWE-601", "WSTG-v42-CLNT-04",
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N", "Redirecionamento",
          "Redirecione só para destinos de uma allowlist ou caminhos relativos.", invasive=True),
    # SAST ----------------------------------------------------------------------------------
    Check("sast-cmdi", "Entrada não confiável chega a comando do sistema", "CWE-78", None,
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Injeção", "Use APIs sem shell e listas de argumentos fixas; valide com allowlist."),
    Check("sast-code-injection", "Entrada não confiável chega a eval/exec", "CWE-95", None,
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Injeção", "Remova eval/exec com dados externos; use parsers seguros."),
    Check("sast-sqli", "Entrada não confiável concatenada em consulta SQL", "CWE-89", None,
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "Injeção", "Use parâmetros (placeholders) do driver."),
    Check("sast-path-traversal", "Entrada não confiável usada como caminho de arquivo", "CWE-22", None,
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Arquivos", "Normalize o caminho e confirme que ele fica dentro do diretório base."),
    Check("sast-ssrf", "Entrada não confiável usada como URL de requisição do servidor", "CWE-918", None,
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N", "SSRF", "Valide o destino contra allowlist e bloqueie redes internas."),
    Check("sast-deserialization", "Desserialização insegura de dados externos", "CWE-502", None,
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Desserialização", "Use formatos seguros (JSON) ou yaml.safe_load."),
    Check("sast-ssti", "Entrada não confiável usada como template", "CWE-1336", None,
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Injeção", "Passe a entrada como variável do template, nunca como o template."),
    Check("sast-xss", "Entrada não confiável escrita em HTML sem codificação", "CWE-79", None,
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Injeção", "Use a codificação automática do framework."),
    Check("sast-open-redirect", "Entrada não confiável usada como destino de redirecionamento", "CWE-601", None,
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N", "Redirecionamento", "Use allowlist de destinos."),
    Check("sast-dangerous-call", "Chamada perigosa (sem fluxo de entrada comprovado)", None, None, None, "Revisão",
          "Revise o fluxo de dados até esta chamada."),
    Check("secret-hardcoded", "Possível segredo no código", "CWE-798", None,
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Segredos", "Revogue/rotacione a credencial e use um cofre de segredos."),
    Check("tls-verify-disabled", "Validação TLS desativada", "CWE-295", None,
          "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N", "Criptografia", "Reative a validação de certificados."),
    Check("debug-enabled", "Modo debug habilitado", "CWE-489", None, None, "Configuração", "Desative debug em produção."),
    Check("cors-wildcard-config", "CORS permissivo na configuração", "CWE-942", None, None, "Web", "Restrinja CORS às origens necessárias."),
    Check("container-root", "Container pode executar como root", "CWE-250", None, None, "Container", "Use USER sem privilégios no estágio final."),
    Check("k8s-privileged", "Pod Kubernetes privilegiado ou com namespace do host", "CWE-250", None, None, "Kubernetes",
          "Remova privileged/hostNetwork/hostPID e aplique Pod Security Standards."),
    Check("iac-public-exposure", "Recurso de infraestrutura exposto publicamente", "CWE-284", None, None, "IaC",
          "Restrinja CIDRs e desative acesso público por padrão."),
]

CHECKS: dict[str, Check] = {c.id: c for c in _CHECKS}


def get(check_id: str) -> Check:
    return CHECKS[check_id]
