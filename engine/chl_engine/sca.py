"""SCA: inventário de dependências e correlação com vulnerabilidades conhecidas (CVE/OSV).

Fontes de dados, em ordem:
1. API pública do OSV (`api.osv.dev/v1/querybatch`), se `CHL_OSV_ONLINE=1` e houver rede.
2. Diretório local com registros no formato OSV (`CHL_OSV_OFFLINE_DIR`), para VPS sem saída ou testes.
Se nenhuma fonte responder, o passo informa "correlação indisponível" — não inventa resultado.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import requests


@dataclass(frozen=True)
class Package:
    ecosystem: str      # PyPI | npm
    name: str
    version: str
    source: str         # arquivo de manifesto ou evidência de fingerprint
    exact: bool = True


@dataclass
class Advisory:
    id: str
    aliases: list[str]
    summary: str
    cvss_vector: str | None
    fixed: list[str]
    references: list[str]


@dataclass
class ScaResult:
    packages: list[Package] = field(default_factory=list)
    matches: list[tuple[Package, Advisory]] = field(default_factory=list)
    source: str = ""
    notes: list[str] = field(default_factory=list)


# --- manifestos ---------------------------------------------------------------------------
def _norm_py(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_manifests(root: Path) -> tuple[list[Package], list[str]]:
    pkgs: dict[tuple[str, str], Package] = {}
    notes: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink() or "node_modules" in path.parts:
            continue
        rel = path.relative_to(root).as_posix()
        name = path.name.lower()
        try:
            if re.fullmatch(r"requirements.*\.txt", name):
                for line in path.read_text(errors="replace").splitlines():
                    line = line.split("#", 1)[0].strip()
                    m = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9_.+!\-]+)", line)
                    if m:
                        pkgs.setdefault(("PyPI", _norm_py(m.group(1))), Package("PyPI", _norm_py(m.group(1)), m.group(2), rel))
                    elif re.match(r"^[A-Za-z0-9_.\-]+", line or "") and line:
                        notes.append(f"{rel}: '{line}' sem versão fixa (==); não correlacionado")
            elif name == "package-lock.json":
                data = json.loads(path.read_text(errors="replace"))
                for key, info in (data.get("packages") or {}).items():
                    if key.startswith("node_modules/") and info.get("version"):
                        n = key.split("node_modules/")[-1]
                        pkgs[("npm", n)] = Package("npm", n, info["version"], rel)
                for n, info in (data.get("dependencies") or {}).items():   # lockfile v1
                    if isinstance(info, dict) and info.get("version"):
                        pkgs.setdefault(("npm", n), Package("npm", n, info["version"], rel))
            elif name == "package.json":
                data = json.loads(path.read_text(errors="replace"))
                for section in ("dependencies", "devDependencies"):
                    for n, spec in (data.get(section) or {}).items():
                        m = re.match(r"^[\^~=v]?(\d+\.\d+\.\d+[0-9A-Za-z.\-+]*)$", str(spec).strip())
                        if m and ("npm", n) not in pkgs:
                            pkgs[("npm", n)] = Package("npm", n, m.group(1), rel, exact=str(spec)[0].isdigit())
                        elif not m:
                            notes.append(f"{rel}: {n}@{spec} sem versão resolvível; use package-lock.json")
        except (OSError, json.JSONDecodeError) as exc:
            notes.append(f"{rel}: não foi possível ler ({type(exc).__name__})")
    return list(pkgs.values()), notes


# --- comparação de versões ----------------------------------------------------------------
def _key(v: str) -> tuple:
    parts = re.split(r"[.\-+]", v.lower().lstrip("v"))
    out = []
    for p in parts:
        m = re.match(r"^(\d+)(.*)$", p)
        if m:
            suffix = m.group(2)
            rank = 0 if not suffix else (1 if suffix.startswith(("post", "p")) else -1)   # 5.4b1 < 5.4 < 5.4.post1
            out.append((1, int(m.group(1)), rank, suffix))
        else:
            rank = 1 if p.startswith("post") else -1   # pré-lançamento (a, b, rc, dev) vem antes
            out.append((0 if rank < 0 else 2, 0, rank, p))
    while out and out[-1] == (1, 0, 0, ""):
        out.pop()
    return tuple(out)


def vcmp(a: str, b: str) -> int:
    ka, kb = _key(a), _key(b)
    return (ka > kb) - (ka < kb)


def affected(version: str, record: dict, ecosystem: str, name: str) -> tuple[bool, list[str]]:
    for aff in record.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("ecosystem") != ecosystem:
            continue
        pname = _norm_py(pkg.get("name", "")) if ecosystem == "PyPI" else pkg.get("name", "")
        if pname != name:
            continue
        if version in (aff.get("versions") or []):
            return True, _fixed(aff)
        for rng in aff.get("ranges", []):
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            introduced, hit = None, False
            for ev in rng.get("events", []):
                if "introduced" in ev:
                    introduced = ev["introduced"]
                elif "fixed" in ev and introduced is not None:
                    if (introduced == "0" or vcmp(version, introduced) >= 0) and vcmp(version, ev["fixed"]) < 0:
                        hit = True
                    introduced = None
                elif "last_affected" in ev and introduced is not None:
                    if (introduced == "0" or vcmp(version, introduced) >= 0) and vcmp(version, ev["last_affected"]) <= 0:
                        hit = True
                    introduced = None
            if introduced is not None and (introduced == "0" or vcmp(version, introduced) >= 0):
                hit = True
            if hit:
                return True, _fixed(aff)
    return False, []


def _fixed(aff: dict) -> list[str]:
    return [ev["fixed"] for r in aff.get("ranges", []) for ev in r.get("events", []) if "fixed" in ev]


def _advisory(record: dict, fixed: list[str]) -> Advisory:
    vector = None
    for sev in record.get("severity", []) or []:
        score = str(sev.get("score", ""))
        if sev.get("type") == "CVSS_V3" and score.startswith(("CVSS:3.1/", "CVSS:3.0/")):
            vector = "CVSS:3.1/" + score.split("/", 1)[1]
    refs = [r.get("url") for r in record.get("references", []) if r.get("url")][:8]
    return Advisory(record["id"], record.get("aliases", []), record.get("summary") or record.get("details", "")[:200], vector, fixed, refs)


# --- consulta --------------------------------------------------------------------------------
def correlate(packages: list[Package], *, online: bool, api: str, offline_dir: str, timeout: float = 20) -> ScaResult:
    result = ScaResult(packages=list(packages))
    if not packages:
        result.source = "sem dependências identificadas"
        return result
    if online:
        try:
            _online(packages, api, timeout, result)
            result.source = "api.osv.dev"
            return result
        except (requests.RequestException, ValueError) as exc:
            result.notes.append(f"OSV online indisponível: {type(exc).__name__}")
    if offline_dir and Path(offline_dir).is_dir():
        records = []
        for f in Path(offline_dir).rglob("*.json"):
            try:
                records.append(json.loads(f.read_text()))
            except (OSError, json.JSONDecodeError):
                result.notes.append(f"registro OSV ilegível: {f.name}")
        for p in packages:
            for rec in records:
                hit, fixed = affected(p.version, rec, p.ecosystem, p.name)
                if hit:
                    result.matches.append((p, _advisory(rec, fixed)))
        result.source = f"base OSV local ({len(records)} registros)"
        return result
    result.source = "indisponível"
    result.notes.append("Correlação CVE não executada: sem acesso à API OSV e sem base local configurada (CHL_OSV_OFFLINE_DIR).")
    return result


def _online(packages: list[Package], api: str, timeout: float, result: ScaResult) -> None:
    queries = [{"package": {"ecosystem": p.ecosystem, "name": p.name}, "version": p.version} for p in packages]
    session = requests.Session()
    for start in range(0, len(queries), 500):
        resp = session.post(api, json={"queries": queries[start:start + 500]}, timeout=timeout)
        resp.raise_for_status()
        for p, entry in zip(packages[start:start + 500], resp.json().get("results", [])):
            for v in entry.get("vulns", []) or []:
                full = session.get(f"https://api.osv.dev/v1/vulns/{v['id']}", timeout=timeout)
                full.raise_for_status()
                rec = full.json()
                _, fixed = affected(p.version, rec, p.ecosystem, p.name)
                result.matches.append((p, _advisory(rec, fixed)))
