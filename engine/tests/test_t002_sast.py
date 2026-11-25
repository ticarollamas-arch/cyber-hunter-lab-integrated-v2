"""T-002 — SAST: todas as falhas conhecidas apontadas; amostras seguras sem alerta alto."""
import io
import zipfile
from pathlib import Path

import pytest

from chl_engine import cvss, taxonomy
from chl_engine.sast.runner import run_sast
from chl_engine.sast.zipsafe import UnsafeArchive, safe_extract

SAMPLES = Path(__file__).parent / "fixtures" / "sast"

EXPECTED_VULN = {
    ("vuln/cmd.py", "sast-cmdi"), ("vuln/sqli.py", "sast-sqli"), ("vuln/path.py", "sast-path-traversal"),
    ("vuln/ssrf.py", "sast-ssrf"), ("vuln/deser.py", "sast-deserialization"), ("vuln/ssti.py", "sast-ssti"),
    ("vuln/xss.py", "sast-xss"), ("vuln/redir.py", "sast-open-redirect"), ("vuln/evalx.py", "sast-code-injection"),
    ("vuln/app.js", "sast-xss"), ("vuln/app.js", "sast-cmdi"), ("vuln/settings.py", "secret-hardcoded"),
}


def _severity(check_id: str) -> str:
    vec = taxonomy.get(check_id).vector
    return cvss.severity(cvss.base_score(vec)) if vec else "info"


def test_all_known_flaws_detected():
    rep = run_sast(SAMPLES / "vuln", max_file_bytes=1_000_000, tool_timeout=60, use_external=False)
    got = {(f"vuln/{h.path}", h.check_id) for h in rep.hits if h.state == "hypothesis"}
    missing = EXPECTED_VULN - got
    assert not missing, f"falhas não detectadas: {sorted(missing)}"
    # as duas desserializações (pickle e yaml.load sem SafeLoader) são apontadas
    assert sum(1 for h in rep.hits if h.path == "deser.py" and h.check_id == "sast-deserialization") == 2


def test_safe_samples_raise_no_high_alert():
    rep = run_sast(SAMPLES / "safe", max_file_bytes=1_000_000, tool_timeout=60, use_external=False)
    high = [(h.path, h.check_id, h.line) for h in rep.hits if h.state == "hypothesis" or _severity(h.check_id) in ("high", "critical")]
    assert high == [], f"alertas altos/hipóteses em código seguro: {high}"


def test_code_is_never_executed(tmp_path):
    marker = tmp_path / "executou.txt"
    src = tmp_path / "src"
    src.mkdir()
    (src / "boom.py").write_text(f"open({str(marker)!r}, 'w').write('x')\nimport os\nos.system('touch {marker}')\n")
    run_sast(src, max_file_bytes=1_000_000, tool_timeout=60, use_external=False)
    assert not marker.exists()


def _zip(entries: dict, symlink: str | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries.items():
            z.writestr(name, data)
        if symlink:
            info = zipfile.ZipInfo(symlink)
            info.external_attr = (0o120777 << 16)
            z.writestr(info, "/etc/passwd")
    return buf.getvalue()


LIMITS = dict(max_zip_bytes=5_000_000, max_unpacked=2_000_000, max_entries=100, max_ratio=200)


def test_zip_slip_rejected(tmp_path):
    p = tmp_path / "a.zip"
    p.write_bytes(_zip({"../../fora.txt": "x"}))
    with pytest.raises(UnsafeArchive):
        safe_extract(p, tmp_path / "out", **LIMITS)
    assert not (tmp_path.parent / "fora.txt").exists()


def test_symlink_rejected(tmp_path):
    p = tmp_path / "a.zip"
    p.write_bytes(_zip({"ok.txt": "x"}, symlink="link"))
    with pytest.raises(UnsafeArchive):
        safe_extract(p, tmp_path / "out", **LIMITS)


def test_zip_bomb_rejected(tmp_path):
    p = tmp_path / "bomba.zip"
    p.write_bytes(_zip({"zeros.bin": b"\0" * 5_000_000}))
    with pytest.raises(UnsafeArchive):
        safe_extract(p, tmp_path / "out", **LIMITS)


def test_sensitive_files_skipped(tmp_path):
    p = tmp_path / "a.zip"
    p.write_bytes(_zip({"app.py": "x=1", ".env": "SECRET=1", "keys/id_rsa": "k", "node_modules/a.js": "1"}))
    res = safe_extract(p, tmp_path / "out", **LIMITS)
    assert res.files == ["app.py"] and res.skipped_sensitive == 3
