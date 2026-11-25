"""T-003 estados e filtro do relatório · T-004 campos obrigatórios · T-011 deduplicação · CVSS."""
import pytest

from chl_engine import cvss, reports
from chl_engine.findings import FindingError, FindingStore, NewFinding

EV = [{"kind": "http", "summary": "GET /search?q=PAYLOAD → 200", "request": "GET /search", "response": "HTTP 200"}]


@pytest.fixture
def store(db, audit):
    return FindingStore(db, audit)


@pytest.fixture
def job(db, program):
    return db.execute("INSERT INTO jobs(program_id, scope_version_id, target, status, created_by, created_at) VALUES(?,1,'http://a','completed',1,'2026')", (program,))


def _complete(store, fid):
    store.update_fields(fid, "ana", impact="Execução de script no navegador da vítima.", repro_steps="1. Abra a URL.\n2. Veja o alerta.",
                        description="O parâmetro q é refletido sem codificação.")


@pytest.mark.parametrize("vector,score", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:L/A:N", 6.9),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N", 4.7),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N", 0.0),
])
def test_cvss_reference_vectors(vector, score):
    assert cvss.base_score(vector) == score


def test_cvss_rejects_invalid():
    with pytest.raises(cvss.CvssError):
        cvss.base_score("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    with pytest.raises(cvss.CvssError):
        cvss.base_score("AV:N/AC:L")


def test_state_machine_and_human_only_validation(store, job, program):
    fid = store.create(job, program, NewFinding("xss-reflected", "http://a/search?q=1", "a", "chl-dast", evidence=EV, state="hypothesis", snippet="q"))
    with pytest.raises(FindingError):
        store.transition(fid, "validated", "engine", "auto")                 # máquina não valida
    with pytest.raises(FindingError):
        store.transition(fid, "validated", "ana", "", role="researcher")     # exige justificativa
    with pytest.raises(FindingError):
        store.transition(fid, "validated", "ana", "ok", role="viewer")       # papel sem permissão
    f = store.transition(fid, "validated", "ana", "reproduzido manualmente")
    assert f["state"] == "validated" and [h["to_state"] for h in f["history"]] == ["hypothesis", "validated"]
    with pytest.raises(FindingError):
        store.transition(fid, "false_positive", "ana", "x")                  # validated → fp não é direto


def test_observation_cannot_jump_to_validated(store, job, program):
    fid = store.create(job, program, NewFinding("hdr-csp-missing", "http://a/", "a", "chl-webchecks", evidence=EV))
    with pytest.raises(FindingError):
        store.transition(fid, "validated", "ana", "x")


def test_validation_requires_evidence_and_vector(store, job, program):
    fid = store.create(job, program, NewFinding("hdr-csp-missing", "http://a/", "a", "chl-webchecks", evidence=EV))
    store.transition(fid, "hypothesis", "ana", "")
    with pytest.raises(FindingError, match="cvss_vector"):
        store.transition(fid, "validated", "ana", "x")


def test_report_only_contains_validated(store, job, program, db):
    keep = store.create(job, program, NewFinding("xss-reflected", "http://a/search?q=1", "a", "chl-dast", evidence=EV, state="hypothesis", snippet="q"))
    hyp = store.create(job, program, NewFinding("sqli-error", "http://a/item?id=1", "a", "chl-dast", evidence=EV, state="hypothesis", snippet="id"))
    _complete(store, keep)
    store.transition(keep, "validated", "ana", "reproduzido")
    findings = [store.get(i) for i in (keep, hyp)]
    for f in findings:
        f["evidence_json"] = f["evidence_json"]
    rep = reports.build({"name": "Lab"}, {"id": job, "target": "http://a"}, findings, {"version": 1, "sha256": "ab" * 32})
    assert [f["id"] for f in rep["findings"]] == [keep], "hipótese não pode aparecer no relatório"
    md = reports.to_markdown(rep)
    assert "Passos de reprodução" in md and "CWE-79" in md and "CVSS:3.1/" in md
    pdf = reports.to_pdf(rep)
    assert pdf.startswith(b"%PDF")
    sarif = reports.to_sarif(rep)
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"][0]["ruleId"] == "CWE-79"


def test_report_requires_all_fields(store, job, program):
    fid = store.create(job, program, NewFinding("xss-reflected", "http://a/s?q=1", "a", "chl-dast", evidence=EV, state="hypothesis", snippet="q"))
    store.transition(fid, "validated", "ana", "ok")       # validado, mas sem impacto/passos
    with pytest.raises(reports.ReportError) as exc:
        reports.build({"name": "Lab"}, {"id": job, "target": "x"}, [store.get(fid)], {})
    assert any("impact" in p for p in exc.value.problems) and any("repro_steps" in p for p in exc.value.problems)
    with pytest.raises(reports.ReportError):
        reports.build({"name": "Lab"}, {"id": job, "target": "x"}, [], {})


def test_dedup_groups_same_cwe_and_snippet(store, db, program, job):
    job2 = db.execute("INSERT INTO jobs(program_id, scope_version_id, target, status, created_by, created_at) VALUES(?,1,'http://a','completed',1,'2026')", (program,))
    a = store.create(job, program, NewFinding("sast-sqli", "app/db.py:10", "app/db.py", "chl-pytaint", snippet='cur.execute(f"SELECT {x}")', state="hypothesis"))
    same_run = store.create(job, program, NewFinding("sast-sqli", "app/db.py:10", "app/db.py", "chl-pytaint", snippet='cur.execute(f"SELECT {x}")', state="hypothesis"))
    moved = store.create(job2, program, NewFinding("sast-sqli", "app/db.py:14", "app/db.py", "chl-pytaint", snippet='cur.execute(f"SELECT  {x}")', state="hypothesis"))
    other = store.create(job2, program, NewFinding("sast-sqli", "app/db.py:30", "app/db.py", "chl-pytaint", snippet='cur.execute("DELETE " + y)', state="hypothesis"))
    assert same_run == a, "mesmo achado na mesma execução não é duplicado"
    assert store.get(moved)["duplicate_of"] == a, "mesma CWE e mesmo trecho (linha mudou) → duplicata provável"
    assert store.get(other)["duplicate_of"] is None, "trecho diferente não é duplicata"
    groups = store.groups(program)
    assert groups and set(groups[0]["ids"]) == {a, moved, other}, "mesmo CWE + componente ficam no mesmo grupo"
    assert store.get(moved)["state"] == "hypothesis", "a decisão final de duplicata é humana"


def test_false_positive_signals(store, job, program):
    fid = store.create(job, program, NewFinding("secret-hardcoded", "tests/fixtures/conf.py:3", "tests/fixtures/conf.py", "chl-rules",
                                                snippet='API_KEY = "your_api_key_here_xxxx"', state="observation"))
    signals = store.get(fid)["fp_signals"]
    assert any("teste" in s for s in signals) and any("marcador" in s for s in signals)
