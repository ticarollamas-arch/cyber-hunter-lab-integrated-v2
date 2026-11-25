"""Cliente HTTP com escopo obrigatório — a única porta de saída do motor para os alvos.

Cada requisição: checa cancelamento → checa escopo → checa método/modo → checa orçamento →
aguarda o limitador de taxa → envia (sem seguir redirecionamentos automaticamente) → grava a
evidência mascarada. Redirecionamentos são seguidos manualmente, com nova checagem de escopo.
"""
from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urljoin

import requests

from .audit import AuditLog
from .config import Settings
from .db import Database, utcnow
from .scope import Decision, Scope
from .security import mask_headers, mask_text


class OutOfScope(Exception):
    def __init__(self, url: str, decision: Decision):
        super().__init__(f"{url}: {decision.reason}")
        self.url, self.decision = url, decision


class Cancelled(Exception):
    pass


class BudgetExceeded(Exception):
    pass


class MethodNotAllowed(Exception):
    pass


class CancelToken:
    def __init__(self):
        self._event = threading.Event()

    def cancel(self):
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def raise_if_cancelled(self):
        if self._event.is_set():
            raise Cancelled("tarefa interrompida pelo usuário")

    def sleep(self, seconds: float):
        """Espera interrompível."""
        if self._event.wait(timeout=max(0.0, seconds)):
            raise Cancelled("tarefa interrompida pelo usuário")


class RateLimiter:
    """Intervalo mínimo entre requisições (rps) compartilhado por programa."""

    _registry: dict[int, "RateLimiter"] = {}
    _registry_lock = threading.Lock()

    def __init__(self, rps: float):
        self.interval = 1.0 / rps
        self._next = 0.0
        self._lock = threading.Lock()

    @classmethod
    def for_program(cls, program_id: int, rps: float) -> "RateLimiter":
        with cls._registry_lock:
            limiter = cls._registry.get(program_id)
            if limiter is None or abs(limiter.interval - 1.0 / rps) > 1e-9:
                limiter = cls(rps)
                cls._registry[program_id] = limiter
            return limiter

    def wait(self, cancel: CancelToken):
        with self._lock:
            now = time.monotonic()
            slot = max(now, self._next)
            self._next = slot + self.interval
        delay = slot - time.monotonic()
        if delay > 0:
            cancel.sleep(delay)


@dataclass
class HttpResult:
    url: str
    status: int
    headers: dict
    text: str
    elapsed_ms: int
    evidence_id: int
    redirects: list[str] = field(default_factory=list)


class ScopedHttpClient:
    def __init__(self, *, db: Database, audit: AuditLog, settings: Settings, scope: Scope, job_id: int,
                 actor: str, cancel: CancelToken, resolver: Callable[[str], list[str]] | None = None):
        self.db, self.audit, self.settings, self.scope = db, audit, settings, scope
        self.job_id, self.actor, self.cancel, self.resolver = job_id, actor, cancel, resolver
        self.limiter = RateLimiter.for_program(scope.program_id, float(scope.rules["rate_limit_rps"]))
        self.active_mode = False      # só vira True dentro de um bloco aprovado (DAST ativo)
        self.step = ""
        self._session = requests.Session()
        self._session.trust_env = settings.http_use_system_proxy
        self._count_lock = threading.Lock()
        self.sent = 0
        self.blocked = 0

    # --- controles -----------------------------------------------------------------------
    def _check(self, method: str, url: str) -> Decision:
        self.cancel.raise_if_cancelled()
        decision = self.scope.check_url(url, self.resolver)
        if not decision.allowed:
            with self._count_lock:
                self.blocked += 1
            self.db.execute(
                "INSERT INTO http_evidence(job_id, step, method, url, status, decision, scope_rule, ts) VALUES(?,?,?,?,?,?,?,?)",
                (self.job_id, self.step, method, url, None, "blocked", decision.rule, utcnow()))
            self.db.execute("UPDATE jobs SET requests_blocked = requests_blocked + 1 WHERE id=?", (self.job_id,))
            self.audit.record(self.actor, "http.blocked", "blocked", target=url, scope_rule=decision.rule,
                              job_id=self.job_id, details={"reason": decision.reason, "method": method, "step": self.step})
            raise OutOfScope(url, decision)
        passive_methods = {m.upper() for m in self.scope.rules.get("allowed_methods_passive", ["GET", "HEAD", "OPTIONS"])}
        if method.upper() not in passive_methods and not self.active_mode:
            raise MethodNotAllowed(f"método {method} exige teste ativo aprovado")
        with self._count_lock:
            if self.sent >= int(self.scope.rules["max_requests_per_job"]):
                raise BudgetExceeded("limite de requisições da tarefa atingido")
            self.sent += 1
        return decision

    # --- envio ---------------------------------------------------------------------------
    def request(self, method: str, url: str, *, headers: dict | None = None, data: str | bytes | None = None,
                follow_redirects: bool = True, max_redirects: int = 5) -> HttpResult:
        chain: list[str] = []
        current = url
        for _ in range(max_redirects + 1):
            result = self._send_once(method, current, headers=headers, data=data)
            if follow_redirects and result.status in (301, 302, 303, 307, 308) and result.headers.get("location"):
                nxt = urljoin(current, result.headers["location"])
                chain.append(nxt)
                if result.status == 303 or (result.status in (301, 302) and method.upper() == "POST"):
                    method, data = "GET", None
                current = nxt
                continue          # o próximo salto passa por _check de novo (pode ser bloqueado)
            result.redirects = chain
            return result
        raise requests.TooManyRedirects(f"mais de {max_redirects} redirecionamentos")

    def get(self, url: str, **kw) -> HttpResult:
        return self.request("GET", url, **kw)

    def _send_once(self, method: str, url: str, *, headers: dict | None, data) -> HttpResult:
        decision = self._check(method, url)
        self.limiter.wait(self.cancel)
        self.cancel.raise_if_cancelled()
        hdrs = {"User-Agent": self.settings.user_agent}
        hdrs.update(self.scope.rules.get("required_headers") or {})
        hdrs.update(headers or {})
        started = time.monotonic()
        status, resp_headers, body = 0, {}, b""
        error = ""
        try:
            with self._session.request(method, url, headers=hdrs, data=data, allow_redirects=False, stream=True,
                                       timeout=self.settings.http_timeout, verify=True) as resp:
                status = resp.status_code
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                chunks, size = [], 0
                for chunk in resp.iter_content(16384):
                    chunks.append(chunk)
                    size += len(chunk)
                    if size >= self.settings.http_max_body:
                        break
                body = b"".join(chunks)[: self.settings.http_max_body]
                encoding = resp.encoding or "utf-8"
        except requests.RequestException as exc:
            error = f"{type(exc).__name__}: {exc}"
            encoding = "utf-8"
        elapsed = int((time.monotonic() - started) * 1000)
        text = body.decode(encoding, errors="replace") if body else ""
        req_body = data.decode("utf-8", "replace") if isinstance(data, bytes) else (data or "")
        ev_id = self.db.execute(
            "INSERT INTO http_evidence(job_id, step, method, url, status, decision, scope_rule, ts, duration_ms,"
            " request_headers, request_body, response_headers, body_excerpt, body_sha256) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (self.job_id, self.step, method, url, status or None, "sent" if not error else "error", decision.rule, utcnow(), elapsed,
             _json(mask_headers(hdrs)), mask_text(req_body[:2000]), _json(mask_headers(resp_headers)),
             mask_text(text[:4000] if not error else error), hashlib.sha256(body).hexdigest()))
        self.db.execute("UPDATE jobs SET requests_sent = requests_sent + 1 WHERE id=?", (self.job_id,))
        if error:
            raise requests.ConnectionError(error)
        return HttpResult(url, status, resp_headers, text, elapsed, ev_id)


def _json(value) -> str:
    import json
    return json.dumps(value, ensure_ascii=False)
