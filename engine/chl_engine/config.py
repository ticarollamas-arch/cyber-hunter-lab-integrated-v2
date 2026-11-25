"""Configuração lida do ambiente. Segredos (chaves de IA) só existem aqui, no servidor."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(os.environ.get("CHL_DATA_DIR", Path(__file__).resolve().parent.parent / "data")))
    # Rede
    http_timeout: float = field(default_factory=lambda: _float("CHL_HTTP_TIMEOUT", 15.0))
    http_max_body: int = field(default_factory=lambda: _int("CHL_HTTP_MAX_BODY", 1_000_000))
    http_use_system_proxy: bool = field(default_factory=lambda: os.environ.get("CHL_USE_SYSTEM_PROXY", "0") == "1")
    user_agent: str = field(default_factory=lambda: os.environ.get("CHL_USER_AGENT", "CyberHuntLab-Research/0.1 (+authorized bug bounty research)"))
    # Análise de código
    max_zip_bytes: int = field(default_factory=lambda: _int("CHL_MAX_ZIP_BYTES", 200 * 1024 * 1024))
    max_unpacked_bytes: int = field(default_factory=lambda: _int("CHL_MAX_UNPACKED_BYTES", 1024 * 1024 * 1024))
    max_zip_entries: int = field(default_factory=lambda: _int("CHL_MAX_ZIP_ENTRIES", 50_000))
    max_ratio: int = field(default_factory=lambda: _int("CHL_MAX_COMPRESSION_RATIO", 200))
    sast_max_file_bytes: int = field(default_factory=lambda: _int("CHL_SAST_MAX_FILE_BYTES", 1_000_000))
    tool_timeout: int = field(default_factory=lambda: _int("CHL_TOOL_TIMEOUT", 900))
    # Base OSV local (diretório com JSONs no formato OSV) — usada quando a API não é alcançável
    osv_offline_dir: str = field(default_factory=lambda: os.environ.get("CHL_OSV_OFFLINE_DIR", ""))
    osv_api: str = field(default_factory=lambda: os.environ.get("CHL_OSV_API", "https://api.osv.dev/v1/querybatch"))
    osv_online: bool = field(default_factory=lambda: os.environ.get("CHL_OSV_ONLINE", "1") == "1")
    # IA (compatível com /v1/chat/completions: 9Router, Groq, OpenAI)
    ai_base_url: str = field(default_factory=lambda: os.environ.get("CHL_AI_BASE_URL") or os.environ.get("NINEROUTER_BASE_URL", ""))
    ai_api_key: str = field(default_factory=lambda: os.environ.get("CHL_AI_API_KEY") or os.environ.get("NINEROUTER_API_KEY", ""))
    ai_model: str = field(default_factory=lambda: os.environ.get("CHL_AI_MODEL") or os.environ.get("NINEROUTER_DEFAULT_COMBO", ""))
    ai_timeout: float = field(default_factory=lambda: _float("CHL_AI_TIMEOUT", 45.0))
    ai_retries: int = field(default_factory=lambda: _int("CHL_AI_RETRIES", 2))
    ai_max_tokens_request: int = field(default_factory=lambda: _int("CHL_AI_MAX_TOKENS_REQUEST", 1500))
    ai_daily_tokens_per_user: int = field(default_factory=lambda: _int("CHL_AI_DAILY_TOKENS_PER_USER", 60_000))
    ai_daily_tokens_global: int = field(default_factory=lambda: _int("CHL_AI_DAILY_TOKENS_GLOBAL", 300_000))
    frame_ancestors: list = field(default_factory=lambda: [o for o in os.environ.get("CHL_FRAME_ANCESTORS", "").split() if o.startswith("https://") or o.startswith("http://localhost")])
    # Retenção
    audit_retention_days: int = field(default_factory=lambda: _int("CHL_AUDIT_RETENTION_DAYS", 365))

    @property
    def db_path(self) -> Path:
        return self.data_dir / "cyberhuntlab.sqlite3"
