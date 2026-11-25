"""Análise de fluxo (taint) intraprocedural para Python, baseada em AST. O código nunca é executado.

Rastreia valores vindos de fontes não confiáveis (request.*, input(), sys.argv, parâmetros de rota)
por atribuições até funções perigosas. Quando há caminho fonte → sink, gera *hipótese*; uma chamada
perigosa sem fluxo comprovado gera só *observação*.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass

SOURCE_ROOTS = {"request"}
SOURCE_CALLS = {"input"}
SOURCE_ATTRS = {("sys", "argv")}
SANITIZERS = {"int", "float", "bool", "len", "shlex.quote", "html.escape", "markupsafe.escape", "escape",
              "secure_filename", "werkzeug.utils.secure_filename", "os.path.basename", "urllib.parse.quote", "quote"}

PROPAGATORS = {"str", "bytes", "os.path.join", "posixpath.join", "pathlib.Path", "Path", "urljoin", "urllib.parse.urljoin",
               "base64.b64decode", "bytes.decode", "json.loads", "dict", "list", "tuple"}
PROPAGATOR_METHODS = {"format", "join", "strip", "lstrip", "rstrip", "lower", "upper", "replace", "split", "encode", "decode", "get"}

SINKS: dict[str, str] = {
    "os.system": "sast-cmdi", "os.popen": "sast-cmdi", "commands.getoutput": "sast-cmdi",
    "eval": "sast-code-injection", "exec": "sast-code-injection",
    "open": "sast-path-traversal", "send_file": "sast-path-traversal", "flask.send_file": "sast-path-traversal",
    "os.remove": "sast-path-traversal", "os.unlink": "sast-path-traversal", "shutil.rmtree": "sast-path-traversal",
    "requests.get": "sast-ssrf", "requests.post": "sast-ssrf", "requests.put": "sast-ssrf", "requests.delete": "sast-ssrf",
    "requests.request": "sast-ssrf", "urllib.request.urlopen": "sast-ssrf", "urlopen": "sast-ssrf", "httpx.get": "sast-ssrf",
    "httpx.post": "sast-ssrf",
    "pickle.loads": "sast-deserialization", "pickle.load": "sast-deserialization", "marshal.loads": "sast-deserialization",
    "render_template_string": "sast-ssti", "flask.render_template_string": "sast-ssti", "jinja2.Template": "sast-ssti", "Template": "sast-ssti",
    "redirect": "sast-open-redirect", "flask.redirect": "sast-open-redirect",
}
SUBPROCESS = {"subprocess.call", "subprocess.run", "subprocess.Popen", "subprocess.check_output", "subprocess.check_call"}
SQL_METHODS = {"execute", "executemany", "executescript", "raw"}
ALWAYS_DANGEROUS = {"eval", "exec", "os.system", "pickle.loads", "pickle.load", "marshal.loads"}


@dataclass
class TaintHit:
    check_id: str
    line: int
    snippet: str
    source: str
    sink: str
    tainted: bool


def dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return dotted(node.func)
    if isinstance(node, ast.Subscript):
        return dotted(node.value)
    return ""


class _FunctionAnalyzer(ast.NodeVisitor):
    def __init__(self, lines: list[str], initial: dict[str, str]):
        self.lines = lines
        self.tainted: dict[str, str] = dict(initial)
        self.hits: list[TaintHit] = []

    # --- avaliação de expressões -----------------------------------------------------------
    def source_of(self, node: ast.AST | None) -> str:
        """Retorna a descrição da fonte se a expressão carrega dado não confiável; '' caso contrário."""
        if node is None:
            return ""
        if isinstance(node, ast.Call):
            name = dotted(node.func)
            if name in SANITIZERS:
                return ""
            if name in SOURCE_CALLS:
                return f"{name}()"
            if isinstance(node.func, ast.Attribute):
                base = self.source_of(node.func.value)
                if base:
                    return base
            short = name.split(".")[-1]
            if name in PROPAGATORS or short in PROPAGATOR_METHODS:
                for a in list(node.args) + [k.value for k in node.keywords]:
                    s = self.source_of(a)
                    if s:
                        return s
            return ""
        if isinstance(node, ast.Name):
            return self.tainted.get(node.id, "")
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            name = dotted(node)
            root = name.split(".")[0] if name else ""
            if root in SOURCE_ROOTS:
                return name
            if tuple(name.split(".")[:2]) in SOURCE_ATTRS:
                return name
            return self.source_of(node.value)
        if isinstance(node, ast.JoinedStr):
            for v in node.values:
                if isinstance(v, ast.FormattedValue):
                    s = self.source_of(v.value)
                    if s:
                        return s
            return ""
        if isinstance(node, ast.BinOp):
            return self.source_of(node.left) or self.source_of(node.right)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for e in node.elts:
                s = self.source_of(e)
                if s:
                    return s
            return ""
        if isinstance(node, ast.Dict):
            for v in node.values:
                s = self.source_of(v)
                if s:
                    return s
            return ""
        if isinstance(node, ast.IfExp):
            return self.source_of(node.body) or self.source_of(node.orelse)
        if isinstance(node, ast.BoolOp):
            for v in node.values:
                s = self.source_of(v)
                if s:
                    return s
        return ""

    def _line(self, node: ast.AST) -> tuple[int, str]:
        n = getattr(node, "lineno", 0)
        return n, (self.lines[n - 1].strip() if 0 < n <= len(self.lines) else "")

    def _hit(self, node: ast.AST, check: str, source: str, sink: str, tainted: bool):
        line, snippet = self._line(node)
        self.hits.append(TaintHit(check, line, snippet[:300], source, sink, tainted))

    # --- propagação ------------------------------------------------------------------------
    def _assign(self, targets: list[ast.AST], value: ast.AST | None):
        src = self.source_of(value)
        for t in targets:
            for name in _names(t):
                if src:
                    self.tainted[name] = src
                else:
                    self.tainted.pop(name, None)

    def visit_Assign(self, node: ast.Assign):
        self.generic_visit(node)
        self._assign(node.targets, node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        self.generic_visit(node)
        self._assign([node.target], node.value)

    def visit_AugAssign(self, node: ast.AugAssign):
        self.generic_visit(node)
        src = self.source_of(node.value)
        if src:
            for name in _names(node.target):
                self.tainted[name] = src

    def visit_For(self, node: ast.For):
        src = self.source_of(node.iter)
        if src:
            for name in _names(node.target):
                self.tainted[name] = src
        self.generic_visit(node)

    def visit_With(self, node: ast.With):
        for item in node.items:
            if item.optional_vars is not None:
                self._assign([item.optional_vars], item.context_expr)
        self.generic_visit(node)

    def visit_FunctionDef(self, node):   # funções aninhadas são analisadas separadamente
        return

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node):
        return

    # --- sinks -------------------------------------------------------------------------------
    def visit_Call(self, node: ast.Call):
        self.generic_visit(node)
        name = dotted(node.func)
        short = name.split(".")[-1]
        first = node.args[0] if node.args else None
        shell = any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords)

        if name in SUBPROCESS or short in {"Popen", "check_output"} and name.startswith("subprocess"):
            src = self.source_of(first)
            if shell:
                self._hit(node, "sast-cmdi" if src else "sast-dangerous-call", src, name + "(shell=True)", bool(src))
            return
        if isinstance(node.func, ast.Attribute) and short in SQL_METHODS and first is not None:
            src = self.source_of(first)
            if src and isinstance(first, (ast.JoinedStr, ast.BinOp, ast.Name, ast.Call)):
                self._hit(node, "sast-sqli", src, name, True)
            return
        if name in ("yaml.load",) or (short == "load" and name.startswith("yaml")):
            safe = any(k.arg == "Loader" and "Safe" in dotted(k.value) for k in node.keywords) or (
                len(node.args) > 1 and "Safe" in dotted(node.args[1]))
            if not safe:
                src = self.source_of(first)
                self._hit(node, "sast-deserialization" if src else "sast-dangerous-call", src, name, bool(src))
            return
        check = SINKS.get(name) or (SINKS.get(short) if short in {"render_template_string", "send_file", "redirect", "urlopen"} else None)
        if check:
            src = self.source_of(first) or next((self.source_of(k.value) for k in node.keywords if k.arg in ("url", "path", "source")), "")
            if src:
                self._hit(node, check, src, name, True)
            elif name in ALWAYS_DANGEROUS and not (isinstance(first, ast.Constant)):
                self._hit(node, "sast-dangerous-call", "", name, False)

    def visit_Return(self, node: ast.Return):
        self.generic_visit(node)
        value = node.value
        if isinstance(value, (ast.JoinedStr, ast.BinOp)):
            literal = "".join(c.value for c in ast.walk(value) if isinstance(c, ast.Constant) and isinstance(c.value, str))
            src = self.source_of(value)
            if src and "<" in literal:
                self._hit(node, "sast-xss", src, "return HTML", True)


def _names(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        out: list[str] = []
        for e in target.elts:
            out.extend(_names(e))
        return out
    return []


def _route_params(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, str]:
    """Parâmetros de rota Flask (`@app.route('/u/<nome>')`) são entrada do usuário."""
    tainted: dict[str, str] = {}
    for dec in fn.decorator_list:
        if isinstance(dec, ast.Call) and dotted(dec.func).split(".")[-1] in {"route", "get", "post", "put", "delete", "patch"}:
            if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str) and "<" in dec.args[0].value:
                for a in fn.args.args:
                    if f"<{a.arg}>" in dec.args[0].value or f":{a.arg}>" in dec.args[0].value:
                        tainted[a.arg] = f"parâmetro de rota <{a.arg}>"
    return tainted


def analyze_source(code: str) -> list[TaintHit]:
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError):
        return []
    lines = code.splitlines()
    hits: list[TaintHit] = []
    module = _FunctionAnalyzer(lines, {})
    for stmt in tree.body:
        module.visit(stmt)
    hits.extend(module.hits)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fa = _FunctionAnalyzer(lines, _route_params(node))
            for stmt in node.body:
                fa.visit(stmt)
            hits.extend(fa.hits)
    # remove repetições (mesma linha/regra)
    seen, unique = set(), []
    for h in hits:
        key = (h.check_id, h.line)
        if key not in seen:
            seen.add(key)
            unique.append(h)
    return unique
