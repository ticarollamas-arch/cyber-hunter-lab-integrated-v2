"""SCA: manifestos, faixas de versão OSV e honestidade quando não há fonte de dados."""
import json
from pathlib import Path

from chl_engine import sca

OSV = str(Path(__file__).parent / "fixtures" / "osv")


def test_parse_and_correlate(tmp_path):
    (tmp_path / "requirements.txt").write_text("PyYAML==5.3.1\nflask>=2\nrequests==2.32.0  # comentário\n")
    (tmp_path / "package-lock.json").write_text(json.dumps({"packages": {"": {}, "node_modules/jquery": {"version": "3.4.1"}}}))
    pkgs, notes = sca.parse_manifests(tmp_path)
    names = {(p.ecosystem, p.name, p.version) for p in pkgs}
    assert ("PyPI", "pyyaml", "5.3.1") in names and ("npm", "jquery", "3.4.1") in names
    assert any("flask" in n for n in notes), "dependência sem versão fixa é informada, não adivinhada"
    res = sca.correlate(pkgs, online=False, api="", offline_dir=OSV)
    found = {(p.name, a.id) for p, a in res.matches}
    assert found == {("pyyaml", "GHSA-8q59-q68h-6hv4"), ("jquery", "GHSA-gxr4-xjj5-5px2")}
    adv = next(a for p, a in res.matches if p.name == "pyyaml")
    assert "CVE-2020-14343" in adv.aliases and adv.fixed == ["5.4"] and adv.cvss_vector.startswith("CVSS:3.1/")


def test_fixed_versions_not_flagged():
    pkgs = [sca.Package("PyPI", "pyyaml", "5.4", "x"), sca.Package("PyPI", "pyyaml", "6.0.1", "x"),
            sca.Package("npm", "jquery", "3.5.0", "x"), sca.Package("npm", "jquery", "1.1.4", "x")]
    assert sca.correlate(pkgs, online=False, api="", offline_dir=OSV).matches == []


def test_version_compare():
    assert sca.vcmp("5.3.1", "5.4") < 0 and sca.vcmp("5.4.0", "5.4") == 0 and sca.vcmp("5.4b1", "5.4") < 0
    assert sca.vcmp("1.10.0", "1.9.9") > 0


def test_no_source_is_reported_honestly():
    res = sca.correlate([sca.Package("PyPI", "pyyaml", "5.3.1", "x")], online=False, api="", offline_dir="")
    assert res.matches == [] and res.source == "indisponível" and res.notes
