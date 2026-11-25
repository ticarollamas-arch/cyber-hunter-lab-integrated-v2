"""Reconhecimento, inventário de tecnologias, análise passiva de web/API e DAST ativo com aprovação.

Todo tráfego passa pelo `ScopedHttpClient`. Links fora do escopo encontrados nas páginas são
apenas registrados (sem requisição).
"""
from __future__ import annotations

import json
import re
import secrets
import socket
from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import requests

from .http import BudgetExceeded, HttpResult, OutOfScope, ScopedHttpClient


# --- utilitários de HTML ----------------------------------------------------------------------
class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[dict] = []
        self.meta: dict[str, str] = {}
        self.title = ""
        self._in_title = False
        self._form: dict | None = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "script" and a.get("src"):
            self.scripts.append(a["src"])
        elif tag == "link" and a.get("href") and a.get("rel", "").lower() in ("stylesheet", "alternate"):
            self.links.append(a["href"])
        elif tag == "meta" and a.get("name"):
            self.meta[a["name"].lower()] = a.get("content", "")
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "method": (a.get("method") or "GET").upper(), "inputs": []}
        elif tag in ("input", "textarea", "select") and self._form is not None and a.get("name"):
            if a.get("type", "").lower() not in ("submit", "button", "image", "file", "password", "hidden"):
                self._form["inputs"].append(a["name"])
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data


def parse_html(text: str) -> _LinkParser:
    p = _LinkParser()
    try:
        p.feed(text[:500_000])
    except Exception:   # HTML quebrado não interrompe o reconhecimento
        pass
    return p


def strip_fragment(url: str) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, p.path or "/", p.query, ""))


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    params: list[str] = field(default_factory=list)
    source: str = "link"


@dataclass
class ReconResult:
    pages: list[HttpResult] = field(default_factory=list)
    endpoints: dict[str, Endpoint] = field(default_factory=dict)
    out_of_scope_links: set[str] = field(default_factory=set)
    scripts: set[str] = field(default_factory=set)
    meta: dict[str, str] = field(default_factory=dict)
    dns: dict[str, list[str]] = field(default_factory=dict)
    metafiles: dict[str, int] = field(default_factory=dict)
    api_specs: dict[str, list[str]] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


def _add_endpoint(res: ReconResult, url: str, method: str, params: list[str], source: str):
    p = urlsplit(url)
    key = f"{method} {p.scheme}://{p.netloc}{p.path}"
    ep = res.endpoints.get(key)
    if ep is None:
        ep = res.endpoints[key] = Endpoint(urlunsplit((p.scheme, p.netloc, p.path or "/", "", "")), method, [], source)
    for name in params:
        if name not in ep.params:
            ep.params.append(name)


def recon(client: ScopedHttpClient, target: str) -> ReconResult:
    """Rastreamento em largura limitado por profundidade/páginas, só dentro do escopo."""
    rules = client.scope.rules
    max_pages, max_depth = int(rules["max_crawl_pages"]), int(rules["max_crawl_depth"])
    res = ReconResult()
    host = urlsplit(target).hostname or ""
    try:
        res.dns[host] = sorted({i[4][0] for i in socket.getaddrinfo(host, None)})
    except socket.gaierror:
        res.dns[host] = []
    base = f"{urlsplit(target).scheme}://{urlsplit(target).netloc}"
    for meta_path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt"):
        url = base + meta_path
        if not client.scope.check_url(url, client.resolver).allowed:
            continue
        try:
            r = client.get(url, follow_redirects=False)
            res.metafiles[meta_path] = r.status
            if r.status == 200 and meta_path == "/robots.txt":
                for m in re.finditer(r"(?im)^\s*(?:dis)?allow:\s*(/\S*)", r.text):
                    path = m.group(1).replace("*", "").split("$")[0]
                    if path and path != "/":
                        candidate = urljoin(base, path)
                        if client.scope.check_url(candidate, client.resolver).allowed:
                            _add_endpoint(res, candidate, "GET", [], "robots.txt")
        except (OutOfScope, requests.RequestException) as exc:
            res.notes.append(f"{meta_path}: {exc}")
    queue: deque[tuple[str, int]] = deque([(strip_fragment(target), 0)])
    seen: set[str] = set()
    while queue and len(res.pages) < max_pages:
        url, depth = queue.popleft()
        if url in seen:
            continue
        seen.add(url)
        try:
            page = client.get(url)
        except OutOfScope:
            continue
        except BudgetExceeded:
            res.notes.append("orçamento de requisições atingido durante o reconhecimento")
            break
        except requests.RequestException as exc:
            res.notes.append(f"{url}: {exc}")
            continue
        res.pages.append(page)
        _add_endpoint(res, page.url, "GET", [k for k, _ in parse_qsl(urlsplit(page.url).query)], "crawler")
        if "html" not in page.headers.get("content-type", ""):
            continue
        parsed = parse_html(page.text)
        res.meta.update(parsed.meta)
        for s in parsed.scripts:
            res.scripts.add(urljoin(page.url, s))
        for form in parsed.forms:
            action = urljoin(page.url, form["action"] or page.url)
            if client.scope.check_url(action, client.resolver).allowed:
                _add_endpoint(res, action, form["method"], form["inputs"], "formulário")
            else:
                res.out_of_scope_links.add(action)
        for href in parsed.links:
            if href.startswith(("mailto:", "javascript:", "tel:", "data:")):
                continue
            absolute = strip_fragment(urljoin(page.url, href))
            if not client.scope.check_url(absolute, client.resolver).allowed:
                res.out_of_scope_links.add(absolute)
                continue
            params = [k for k, _ in parse_qsl(urlsplit(absolute).query)]
            _add_endpoint(res, absolute, "GET", params, "link")
            if depth + 1 <= max_depth and absolute not in seen:
                queue.append((absolute, depth + 1))
    return res


# --- descoberta de especificações de API ------------------------------------------------------
API_SPEC_PATHS = ("/openapi.json", "/swagger.json", "/v3/api-docs", "/api/openapi.json", "/swagger/v1/swagger.json")


def discover_api_specs(client: ScopedHttpClient, base: str, res: ReconResult) -> None:
    for path in API_SPEC_PATHS:
        url = urljoin(base, path)
        if not client.scope.check_url(url, client.resolver).allowed:
            continue
        try:
            r = client.get(url, follow_redirects=False)
        except (OutOfScope, BudgetExceeded, requests.RequestException):
            continue
        if r.status != 200:
            continue
        try:
            spec = json.loads(r.text)
        except ValueError:
            continue
        if not isinstance(spec, dict) or not ("openapi" in spec or "swagger" in spec) or "paths" not in spec:
            continue
        server = base
        if isinstance(spec.get("servers"), list) and spec["servers"] and isinstance(spec["servers"][0], dict):
            server = urljoin(base, spec["servers"][0].get("url", "/"))
        ops = []
        for p, item in (spec.get("paths") or {}).items():
            for method, op in (item or {}).items():
                if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                    continue
                params = [prm.get("name") for prm in (op or {}).get("parameters", []) if isinstance(prm, dict) and prm.get("in") == "query" and prm.get("name")]
                full = urljoin(server.rstrip("/") + "/", p.lstrip("/"))
                ops.append(f"{method.upper()} {p}")
                if client.scope.check_url(full, client.resolver).allowed and "{" not in p:
                    _add_endpoint(res, full, method.upper(), params, "OpenAPI")
        res.api_specs[url] = ops
        res.metafiles[path] = 200


# --- inventário de tecnologias ----------------------------------------------------------------
@dataclass
class Technology:
    name: str
    version: str
    evidence: str
    ecosystem: str = ""     # npm/PyPI quando a versão pode ser correlacionada no OSV
    package: str = ""


SCRIPT_LIBS = [
    (re.compile(r"jquery[.-](\d+\.\d+\.\d+)(?:\.min)?\.js", re.I), "jQuery", "npm", "jquery"),
    (re.compile(r"bootstrap[.-](\d+\.\d+\.\d+)(?:\.bundle)?(?:\.min)?\.js", re.I), "Bootstrap", "npm", "bootstrap"),
    (re.compile(r"angular(?:js)?[.-](\d+\.\d+\.\d+)(?:\.min)?\.js", re.I), "AngularJS", "npm", "angular"),
    (re.compile(r"lodash[.-](\d+\.\d+\.\d+)(?:\.min)?\.js", re.I), "Lodash", "npm", "lodash"),
    (re.compile(r"/(?:npm/)?jquery@(\d+\.\d+\.\d+)", re.I), "jQuery", "npm", "jquery"),
]
COOKIE_TECH = {"phpsessid": "PHP", "jsessionid": "Java (servlet)", "asp.net_sessionid": "ASP.NET", "csrftoken": "Django",
               "laravel_session": "Laravel", "connect.sid": "Express (Node.js)", "_rails_session": "Ruby on Rails", "session": "Flask/genérico"}


def fingerprint(pages: list[HttpResult], scripts: set[str], meta: dict[str, str]) -> list[Technology]:
    techs: dict[tuple[str, str], Technology] = {}

    def add(t: Technology):
        techs.setdefault((t.name, t.version), t)

    for page in pages:
        h = page.headers
        for header in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
            if h.get(header):
                value = h[header]
                m = re.match(r"([A-Za-z][A-Za-z0-9 ._-]*?)[/ ]v?(\d+(?:\.\d+)+)", value)
                add(Technology(m.group(1).strip() if m else value.split("/")[0], m.group(2) if m else "", f"cabeçalho {header}: {value}"))
        for cookie in _set_cookies(h):
            name = cookie.split("=", 1)[0].strip().lower()
            if name in COOKIE_TECH:
                add(Technology(COOKIE_TECH[name], "", f"cookie {name}"))
    gen = meta.get("generator")
    if gen:
        m = re.match(r"(.+?)\s+(\d+(?:\.\d+)+)", gen)
        add(Technology(m.group(1) if m else gen, m.group(2) if m else "", f"meta generator: {gen}"))
    for src in scripts:
        for pattern, name, eco, pkg in SCRIPT_LIBS:
            m = pattern.search(src)
            if m:
                add(Technology(name, m.group(1), f"script {src}", eco, pkg))
                break
    return list(techs.values())


def _set_cookies(headers: dict) -> list[str]:
    raw = headers.get("set-cookie", "")
    # requests junta múltiplos Set-Cookie com ", "; separa só onde começa um novo par nome=valor
    return [c for c in re.split(r", (?=[^;,= ]+=)", raw) if c] if raw else []


# --- análise passiva --------------------------------------------------------------------------
@dataclass
class WebIssue:
    check_id: str
    url: str
    component: str
    detail: str
    evidence_id: int
    snippet: str = ""
    state: str = "observation"
    extra_fp: list[str] = field(default_factory=list)


STACK_PATTERNS = [
    re.compile(r"Traceback \(most recent call last\)"), re.compile(r"\bat [a-z]+(?:\.[a-zA-Z$_]+)+\([A-Za-z]+\.java:\d+\)"),
    re.compile(r"Fatal error: .+ on line \d+"), re.compile(r"Werkzeug Debugger"), re.compile(r"System\.[A-Za-z.]+Exception"),
    re.compile(r"SQLSTATE\[\w+\]"), re.compile(r"(?:sqlite3|psycopg2|pymysql)\.[A-Za-z]*Error"),
]


def passive_checks(pages: list[HttpResult]) -> list[WebIssue]:
    issues: list[WebIssue] = []
    seen_hosts: set[str] = set()
    for page in pages:
        p = urlsplit(page.url)
        host = p.netloc
        h = page.headers
        is_html = "html" in h.get("content-type", "")
        if 200 <= page.status < 300 and is_html and host not in seen_hosts:
            seen_hosts.add(host)
            if p.scheme == "https" and "strict-transport-security" not in h:
                issues.append(WebIssue("hdr-hsts-missing", page.url, host, "resposta HTTPS sem HSTS", page.evidence_id))
            csp = h.get("content-security-policy", "")
            if not csp:
                issues.append(WebIssue("hdr-csp-missing", page.url, host, "página HTML sem CSP", page.evidence_id))
            if "x-frame-options" not in h and "frame-ancestors" not in csp:
                issues.append(WebIssue("hdr-clickjacking", page.url, host, "sem X-Frame-Options e sem frame-ancestors", page.evidence_id))
            if h.get("x-content-type-options", "").lower() != "nosniff":
                issues.append(WebIssue("hdr-nosniff-missing", page.url, host, "sem X-Content-Type-Options: nosniff", page.evidence_id))
        for header in ("server", "x-powered-by"):
            if re.search(r"\d+\.\d+", h.get(header, "")):
                issues.append(WebIssue("info-server-version", page.url, host, f"{header}: {h[header]}", page.evidence_id, snippet=f"{header}:{h[header]}"))
        for cookie in _set_cookies(h):
            attrs = cookie.lower()
            name = cookie.split("=", 1)[0].strip()
            if p.scheme == "https" and "; secure" not in attrs and not attrs.endswith("secure"):
                issues.append(WebIssue("cookie-no-secure", page.url, host, f"cookie {name} sem Secure", page.evidence_id, snippet=name))
            if "httponly" not in attrs:
                issues.append(WebIssue("cookie-no-httponly", page.url, host, f"cookie {name} sem HttpOnly", page.evidence_id, snippet=name))
            if "samesite" not in attrs:
                issues.append(WebIssue("cookie-no-samesite", page.url, host, f"cookie {name} sem SameSite", page.evidence_id, snippet=name))
        if h.get("access-control-allow-origin") == "*":
            issues.append(WebIssue("cors-wildcard", page.url, host, "Access-Control-Allow-Origin: *", page.evidence_id))
        if is_html and re.search(r"<title>\s*Index of /", page.text, re.I):
            issues.append(WebIssue("dir-listing", page.url, host, "página 'Index of /'", page.evidence_id, state="hypothesis"))
        for pat in STACK_PATTERNS:
            m = pat.search(page.text)
            if m:
                issues.append(WebIssue("info-stack-trace", page.url, host, f"padrão de erro interno: {m.group(0)[:80]}", page.evidence_id,
                                       snippet=m.group(0)[:80], state="hypothesis"))
                break
    # deduplica por (regra, host, trecho)
    unique, keys = [], set()
    for i in issues:
        k = (i.check_id, i.component, i.snippet)
        if k not in keys:
            keys.add(k)
            unique.append(i)
    return unique


def cors_probe(client: ScopedHttpClient, url: str) -> WebIssue | None:
    """Envia GET com Origin arbitrária (não altera estado) e verifica reflexão + credenciais."""
    origin = f"https://chl-{secrets.token_hex(4)}.example"
    try:
        r = client.get(url, headers={"Origin": origin}, follow_redirects=False)
    except (OutOfScope, BudgetExceeded, requests.RequestException):
        return None
    if r.headers.get("access-control-allow-origin") == origin and r.headers.get("access-control-allow-credentials", "").lower() == "true":
        return WebIssue("cors-reflect-credentials", url, urlsplit(url).netloc,
                        f"Origin {origin} refletida com Access-Control-Allow-Credentials: true", r.evidence_id, state="hypothesis")
    return None


def error_probe(client: ScopedHttpClient, base: str) -> list[HttpResult]:
    """Solicita um caminho inexistente para observar o tratamento de erro (WSTG-ERRH-01)."""
    url = urljoin(base, f"/chl-nao-existe-{secrets.token_hex(4)}")
    try:
        return [client.get(url, follow_redirects=False)]
    except (OutOfScope, BudgetExceeded, requests.RequestException):
        return []


# --- DAST ativo (somente após aprovação) --------------------------------------------------------
REDIRECT_PARAMS = re.compile(r"^(?:url|next|redirect|redirect_uri|redirect_url|return|returnto|return_to|dest|destination|continue|goto|target|r|u)$", re.I)
SQL_ERRORS = re.compile(r"(?i)(you have an error in your sql syntax|sqlstate\[|sqlite3\.operationalerror|unterminated quoted string|"
                        r"unclosed quotation mark|syntax error at or near|ora-0\d{4}|quoted string not properly terminated|pg::syntaxerror)")


def plan_active_tests(endpoints: dict[str, Endpoint], limit: int = 60) -> list[dict]:
    plan: list[dict] = []
    for ep in endpoints.values():
        if ep.method != "GET":
            continue        # nesta versão o DAST ativo só usa GET; formulários POST ficam para revisão manual
        for param in ep.params:
            plan.append({"test": "xss-reflected", "url": ep.url, "param": param, "method": "GET"})
            plan.append({"test": "sqli-error", "url": ep.url, "param": param, "method": "GET"})
            if REDIRECT_PARAMS.match(param):
                plan.append({"test": "open-redirect", "url": ep.url, "param": param, "method": "GET"})
            if len(plan) >= limit:
                return plan[:limit]
    return plan


def _with_param(url: str, param: str, value: str) -> str:
    p = urlsplit(url)
    q = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if k != param] + [(param, value)]
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(q), ""))


def run_active_test(client: ScopedHttpClient, item: dict) -> WebIssue | None:
    url, param, test = item["url"], item["param"], item["test"]
    host = urlsplit(url).netloc
    if test == "xss-reflected":
        token = "chl" + secrets.token_hex(4)
        payload = f'{token}"><i>{token}</i>'     # marcador inofensivo, sem script
        r = client.get(_with_param(url, param, payload), follow_redirects=False)
        if f"<i>{token}</i>" in r.text and '">' + "<i>" in r.text:
            fp = [] if "html" in r.headers.get("content-type", "") else ["resposta não é HTML (navegador não renderiza)"]
            return WebIssue(test, _with_param(url, param, "PAYLOAD"), host, f"marcador refletido sem codificação no parâmetro '{param}'",
                            r.evidence_id, snippet=param, state="hypothesis", extra_fp=fp)
        return None
    if test == "sqli-error":
        baseline = client.get(_with_param(url, param, "1"), follow_redirects=False)
        if SQL_ERRORS.search(baseline.text):
            return None      # erro já existe sem a aspa: não atribuível ao parâmetro
        r = client.get(_with_param(url, param, "1'"), follow_redirects=False)
        m = SQL_ERRORS.search(r.text)
        if m:
            return WebIssue(test, _with_param(url, param, "PAYLOAD"), host,
                            f"aspa simples em '{param}' provocou erro de banco: {m.group(0)}", r.evidence_id, snippet=param, state="hypothesis")
        return None
    if test == "open-redirect":
        dest = "https://chl-redirect-check.invalid/"
        r = client.get(_with_param(url, param, dest), follow_redirects=False)   # nunca segue para o destino externo
        if r.status in (301, 302, 303, 307, 308) and r.headers.get("location", "").startswith(dest):
            return WebIssue(test, _with_param(url, param, "PAYLOAD"), host, f"Location aponta para destino externo controlado via '{param}'",
                            r.evidence_id, snippet=param, state="hypothesis")
    return None
