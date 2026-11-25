"""Funções de segurança compartilhadas: tokens, comparação em tempo constante e mascaramento."""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets

SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key", "x-auth-token", "x-app-token"}

# Padrões de segredos e dados pessoais mascarados antes de gravar evidência ou enviar à IA.
_MASKS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AKIA****************"),
    (re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"), "gh*_****"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"), "sk-****"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "<jwt-mascarado>"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "<chave-privada-mascarada>"),
    (re.compile(r"(?i)((?:api[_-]?key|secret|password|passwd|token)\s*[:=]\s*[\"']?)([^\"'\s&]{6,})"), r"\1****"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "<email>"),
    (re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b"), "<cpf>"),
    (re.compile(r"\b(?:\d[ -]?){13,19}\b"), "<numero-longo>"),
]


def mask_text(text: str | None) -> str:
    if not text:
        return ""
    out = text
    for pattern, repl in _MASKS:
        out = pattern.sub(repl, out)
    return out


def mask_headers(headers: dict | None) -> dict:
    result = {}
    for k, v in (headers or {}).items():
        result[k] = "****" if k.lower() in SENSITIVE_HEADERS else mask_text(str(v))
    return result


def new_token() -> str:
    return "chl_" + secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def tokens_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
