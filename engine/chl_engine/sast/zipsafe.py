"""Extração segura de ZIP para análise (AM-002: zip bomb, zip slip, links simbólicos).

O tamanho real é contado durante a leitura (não se confia no tamanho declarado pelo ZIP).
"""
from __future__ import annotations

import os
import re
import stat
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

SKIP = re.compile(
    r"(^|/)(node_modules|\.git|\.next|dist|build|coverage|vendor|\.venv|venv|__pycache__)(/|$)"
    r"|(^|/)\.env(?:$|\.(?!example$)[^/]+$)|(^|/)(.*\.(?:pem|key|p12|pfx)|id_rsa|id_ed25519|credentials\.json|\.npmrc|\.pypirc)$",
    re.I,
)


class UnsafeArchive(ValueError):
    pass


@dataclass
class ExtractResult:
    root: Path
    files: list[str] = field(default_factory=list)
    skipped_sensitive: int = 0
    total_bytes: int = 0


def safe_extract(zip_path: Path, dest: Path, *, max_zip_bytes: int, max_unpacked: int, max_entries: int, max_ratio: int) -> ExtractResult:
    size = zip_path.stat().st_size
    if size <= 0 or size > max_zip_bytes:
        raise UnsafeArchive(f"ZIP vazio ou acima do limite ({max_zip_bytes} bytes)")
    dest = dest.resolve()
    dest.mkdir(parents=True, exist_ok=True)
    result = ExtractResult(dest)
    try:
        zf = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile as exc:
        raise UnsafeArchive("arquivo não é um ZIP válido") from exc
    with zf:
        infos = zf.infolist()
        if len(infos) > max_entries:
            raise UnsafeArchive(f"mais de {max_entries} entradas")
        declared = sum(i.file_size for i in infos)
        if declared > max_unpacked or (size and declared / size > max_ratio and declared > 10 * 1024 * 1024):
            raise UnsafeArchive("tamanho descompactado ou taxa de compressão acima do limite (possível zip bomb)")
        for info in infos:
            name = info.filename.replace("\\", "/")
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                raise UnsafeArchive(f"link simbólico não permitido: {name}")
            pure = PurePosixPath(name)
            if pure.is_absolute() or ".." in pure.parts or re.match(r"^[A-Za-z]:", name):
                raise UnsafeArchive(f"caminho fora do diretório de destino: {name}")
            if info.is_dir():
                continue
            if SKIP.search(name):
                result.skipped_sensitive += 1
                continue
            target = (dest / pure).resolve()
            if os.path.commonpath([str(dest), str(target)]) != str(dest):
                raise UnsafeArchive(f"caminho fora do diretório de destino: {name}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                while True:
                    chunk = src.read(65536)
                    if not chunk:
                        break
                    result.total_bytes += len(chunk)
                    if result.total_bytes > max_unpacked:
                        raise UnsafeArchive("conteúdo descompactado real excede o limite (possível zip bomb)")
                    out.write(chunk)
            os.chmod(target, 0o600)          # nada extraído fica executável
            result.files.append(str(pure))
    return result
