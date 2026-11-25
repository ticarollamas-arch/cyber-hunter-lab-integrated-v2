"""Gestão de escopo autorizado (RF-001, AM-001).

Regras de decisão, nesta ordem:
1. Sem escopo, nada roda (negação por padrão).
2. Exclusões vencem inclusões.
3. Padrão de host (`app.exemplo.com`, `*.exemplo.com`) cobre apenas as portas 80/443, salvo `host:porta`.
   `*.exemplo.com` não inclui o domínio raiz `exemplo.com` (convenção das plataformas de bug bounty).
4. Padrão de URL (`https://app.exemplo.com/api/`) exige mesmo esquema, host e porta, e caminho com o prefixo.
5. Endereços IP só entram se estiverem listados literalmente.
6. Destinos que resolvem para rede privada/loopback são bloqueados, salvo `allow_private_network`
   (laboratório local). Isso evita DNS rebinding contra a infraestrutura da própria plataforma.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import asdict, dataclass, field
from typing import Any, Callable
from urllib.parse import urlsplit

from .db import Database, dumps, utcnow
from .security import sha256_text

DEFAULT_RULES = {
    "rate_limit_rps": 1.0,            # RNF-001: padrão conservador
    "max_requests_per_job": 500,
    "max_crawl_pages": 50,
    "max_crawl_depth": 2,
    "active_testing_allowed": False,  # o programa permite testes ativos (DAST com payloads)?
    "allow_private_network": False,
    "required_headers": {},           # ex.: {"X-Bug-Bounty": "usuario-h1"}
    "allowed_methods_passive": ["GET", "HEAD", "OPTIONS"],
    "notes": "",
}


class ScopeError(ValueError):
    pass


@dataclass
class Decision:
    allowed: bool
    reason: str
    rule: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class Pattern:
    raw: str
    kind: str          # "host" | "url"
    host: str
    wildcard: bool
    port: int | None
    scheme: str | None
    path: str

    @classmethod
    def parse(cls, raw: str) -> "Pattern":
        text = (raw or "").strip()
        if not text:
            raise ScopeError("padrão de escopo vazio")
        if "://" in text:
            parts = urlsplit(text)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                raise ScopeError(f"URL de escopo inválida: {raw}")
            port = parts.port or (443 if parts.scheme == "https" else 80)
            host = parts.hostname.lower().rstrip(".")
            wildcard = host.startswith("*.")
            return cls(text, "url", host[2:] if wildcard else host, wildcard, port, parts.scheme, parts.path or "/")
        host, port = text.lower(), None
        if host.count(":") == 1:
            host, port_text = host.split(":")
            if not port_text.isdigit():
                raise ScopeError(f"porta inválida em {raw}")
            port = int(port_text)
        host = host.rstrip(".").strip("/")
        if "/" in host or not host:
            raise ScopeError(f"use URL completa para restringir caminho: {raw}")
        wildcard = host.startswith("*.")
        return cls(text, "host", host[2:] if wildcard else host, wildcard, port, None, "/")

    def matches(self, scheme: str, host: str, port: int, path: str) -> bool:
        if self.wildcard:
            if not host.endswith("." + self.host):
                return False
        elif host != self.host:
            return False
        if self.kind == "url":
            return scheme == self.scheme and port == self.port and (path or "/").startswith(self.path)
        if self.port is not None:
            return port == self.port
        return port in (80, 443)


@dataclass
class Scope:
    program_id: int
    version: int
    allowed: list[str]
    excluded: list[str] = field(default_factory=list)
    repositories: list[str] = field(default_factory=list)
    rules: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_RULES))
    version_id: int = 0
    sha256: str = ""

    def __post_init__(self):
        self._allowed = [Pattern.parse(p) for p in self.allowed]
        self._excluded = [Pattern.parse(p) for p in self.excluded]
        merged = dict(DEFAULT_RULES)
        merged.update(self.rules or {})
        rps = float(merged["rate_limit_rps"])
        if rps <= 0 or rps > 50:
            raise ScopeError("rate_limit_rps deve estar entre 0 e 50")
        self.rules = merged

    def check_url(self, url: str, resolver: Callable[[str], list[str]] | None = None) -> Decision:
        try:
            parts = urlsplit(url)
        except ValueError:
            return Decision(False, "URL malformada", "parse")
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return Decision(False, "só http/https com host são permitidos", "scheme")
        if parts.username or parts.password:
            return Decision(False, "URL com credenciais embutidas não é aceita", "userinfo")
        host = parts.hostname.lower().rstrip(".")
        try:
            port = parts.port or (443 if parts.scheme == "https" else 80)
        except ValueError:
            return Decision(False, "porta inválida", "port")
        path = parts.path or "/"
        for p in self._excluded:
            if p.matches(parts.scheme, host, port, path):
                return Decision(False, f"alvo excluído pelo programa ({p.raw})", f"excluded:{p.raw}")
        is_ip = _is_ip(host)
        for p in self._allowed:
            if is_ip and (p.wildcard or p.host != host):
                continue
            if p.matches(parts.scheme, host, port, path):
                if not self.rules.get("allow_private_network"):
                    private = _resolves_private(host, resolver)
                    if private:
                        return Decision(False, f"{host} resolve para rede privada ({private}); bloqueado", "private-network")
                return Decision(True, f"permitido por {p.raw}", f"allowed:{p.raw}")
        return Decision(False, "fora do escopo (nenhuma regra de inclusão corresponde)", "default-deny")

    def check_repository(self, repo: str) -> Decision:
        norm = repo.strip().rstrip("/").lower().removesuffix(".git")
        for r in self.repositories:
            if norm == r.strip().rstrip("/").lower().removesuffix(".git"):
                return Decision(True, f"repositório listado no escopo ({r})", f"repo:{r}")
        return Decision(False, "repositório não listado no escopo", "repo-default-deny")

    def to_data(self) -> dict:
        return {"allowed": self.allowed, "excluded": self.excluded, "repositories": self.repositories, "rules": self.rules}


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _default_resolver(host: str) -> list[str]:
    try:
        return sorted({info[4][0] for info in socket.getaddrinfo(host, None)})
    except socket.gaierror:
        return []


def _resolves_private(host: str, resolver: Callable[[str], list[str]] | None) -> str:
    addrs = [host.strip("[]")] if _is_ip(host) else (resolver or _default_resolver)(host)
    for a in addrs:
        try:
            ip = ipaddress.ip_address(a)
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            return a
    return ""


class ScopeStore:
    """Escopo versionado: cada alteração gera nova versão imutável com hash."""

    def __init__(self, db: Database):
        self.db = db

    def save(self, program_id: int, data: dict, user_id: int) -> Scope:
        candidate = Scope(program_id, 0, list(data.get("allowed") or []), list(data.get("excluded") or []),
                          list(data.get("repositories") or []), dict(data.get("rules") or {}))
        if not candidate.allowed and not candidate.repositories:
            raise ScopeError("o escopo precisa de pelo menos um ativo permitido")
        payload = dumps(candidate.to_data())
        digest = sha256_text(payload)
        with self.db.tx() as c:
            row = c.execute("SELECT COALESCE(MAX(version),0) AS v FROM scope_versions WHERE program_id=?", (program_id,)).fetchone()
            version = int(row["v"]) + 1
            cur = c.execute("INSERT INTO scope_versions(program_id, version, data_json, sha256, created_by, created_at) VALUES(?,?,?,?,?,?)",
                            (program_id, version, payload, digest, user_id, utcnow()))
        candidate.version, candidate.version_id, candidate.sha256 = version, int(cur.lastrowid), digest
        return candidate

    def current(self, program_id: int) -> Scope | None:
        row = self.db.one("SELECT * FROM scope_versions WHERE program_id=? ORDER BY version DESC LIMIT 1", (program_id,))
        return self._from_row(row) if row else None

    def by_version_id(self, version_id: int) -> Scope | None:
        row = self.db.one("SELECT * FROM scope_versions WHERE id=?", (version_id,))
        return self._from_row(row) if row else None

    def history(self, program_id: int) -> list[dict]:
        return self.db.query("SELECT id, version, sha256, created_by, created_at, data_json FROM scope_versions WHERE program_id=? ORDER BY version DESC", (program_id,))

    @staticmethod
    def _from_row(row: dict) -> Scope:
        import json
        data = json.loads(row["data_json"])
        s = Scope(row["program_id"], row["version"], data["allowed"], data["excluded"], data.get("repositories", []), data["rules"])
        s.version_id, s.sha256 = row["id"], row["sha256"]
        return s
