"""T-001 — escopo obrigatório: alvo excluído é bloqueado, registrado e nenhuma requisição sai."""
import time

import pytest

from chl_engine.http import CancelToken, MethodNotAllowed, OutOfScope, BudgetExceeded, Cancelled, ScopedHttpClient, RateLimiter
from chl_engine.scope import Scope, ScopeError, ScopeStore

from conftest import CountingServer

PUBLIC = lambda host: ["93.184.216.34"]  # resolvedor fixo: evita DNS real nos testes


def mk_scope(program, allowed, excluded=(), **rules):
    return Scope(program, 1, list(allowed), list(excluded), rules=rules)


def test_pattern_semantics(program):
    s = mk_scope(program, ["*.exemplo.com", "https://api.outro.com/v1/"], ["admin.exemplo.com"])
    assert s.check_url("https://app.exemplo.com/x", PUBLIC).allowed
    assert not s.check_url("https://exemplo.com/", PUBLIC).allowed, "curinga não inclui o domínio raiz"
    assert not s.check_url("https://admin.exemplo.com/", PUBLIC).allowed, "exclusão vence inclusão"
    assert not s.check_url("https://app.exemplo.com:8443/", PUBLIC).allowed, "porta fora de 80/443 exige regra explícita"
    assert s.check_url("https://api.outro.com/v1/users", PUBLIC).allowed
    assert not s.check_url("https://api.outro.com/v2/users", PUBLIC).allowed
    assert not s.check_url("http://api.outro.com/v1/users", PUBLIC).allowed, "esquema diferente"
    assert not s.check_url("https://evil.com/?q=app.exemplo.com", PUBLIC).allowed
    assert not s.check_url("https://app.exemplo.com.evil.com/", PUBLIC).allowed
    assert not s.check_url("https://user:pw@app.exemplo.com/", PUBLIC).allowed
    assert not s.check_url("ftp://app.exemplo.com/", PUBLIC).allowed
    assert not s.check_url("https://93.184.216.34/", PUBLIC).allowed, "IP só se listado"


def test_private_network_blocked_unless_allowed(program):
    s = mk_scope(program, ["app.exemplo.com"])
    d = s.check_url("https://app.exemplo.com/", lambda h: ["10.0.0.5"])
    assert not d.allowed and d.rule == "private-network"
    s2 = mk_scope(program, ["app.exemplo.com"], allow_private_network=True)
    assert s2.check_url("https://app.exemplo.com/", lambda h: ["10.0.0.5"]).allowed


def test_empty_scope_rejected(db, program, user):
    with pytest.raises(ScopeError):
        ScopeStore(db).save(program, {"allowed": []}, user)


def test_scope_versioning(db, program, user):
    store = ScopeStore(db)
    v1 = store.save(program, {"allowed": ["a.com"]}, user)
    v2 = store.save(program, {"allowed": ["a.com"], "excluded": ["b.a.com"]}, user)
    assert (v1.version, v2.version) == (1, 2)
    assert v1.sha256 != v2.sha256
    assert store.current(program).version == 2
    assert store.by_version_id(v1.version_id).excluded == []


def _client(db, audit, settings, scope, program, cancel=None):
    job = db.execute("INSERT INTO jobs(program_id, scope_version_id, target, status, created_by, created_at) VALUES(?,?,?,?,?,?)",
                     (program, 1, "x", "running", 1, "2026"))
    return ScopedHttpClient(db=db, audit=audit, settings=settings, scope=scope, job_id=job, actor="teste",
                            cancel=cancel or CancelToken()), job


def test_excluded_target_sends_zero_requests(db, audit, settings, program):
    with CountingServer() as allowed_srv, CountingServer() as excluded_srv:
        scope = mk_scope(program, [f"127.0.0.1:{allowed_srv.port}", f"127.0.0.1:{excluded_srv.port}"],
                         [f"127.0.0.1:{excluded_srv.port}"], allow_private_network=True, rate_limit_rps=50)
        client, job = _client(db, audit, settings, scope, program)
        with pytest.raises(OutOfScope):
            client.get(f"http://127.0.0.1:{excluded_srv.port}/qualquer")
        assert excluded_srv.hits == [], "nenhuma requisição pode chegar ao ativo excluído"
        ok = client.get(f"http://127.0.0.1:{allowed_srv.port}/")
        assert ok.status == 200 and len(allowed_srv.hits) == 1
        blocked = db.query("SELECT * FROM audit_log WHERE action='http.blocked'")
        assert len(blocked) == 1 and blocked[0]["scope_rule"].startswith("excluded:")
        assert db.one("SELECT requests_blocked, requests_sent FROM jobs WHERE id=?", (job,)) == {"requests_blocked": 1, "requests_sent": 1}


def test_redirect_to_out_of_scope_is_not_followed(db, audit, settings, program):
    with CountingServer() as outside:
        routes = {"/go": (302, {"Location": f"http://127.0.0.1:{outside.port}/pwn"}, b"")}
        with CountingServer(routes) as inside:
            scope = mk_scope(program, [f"127.0.0.1:{inside.port}"], allow_private_network=True, rate_limit_rps=50)
            client, _ = _client(db, audit, settings, scope, program)
            with pytest.raises(OutOfScope):
                client.get(f"http://127.0.0.1:{inside.port}/go")
            assert outside.hits == []


def test_rate_limit_respected(db, audit, settings, program):
    RateLimiter._registry.clear()
    with CountingServer() as srv:
        scope = mk_scope(program, [f"127.0.0.1:{srv.port}"], allow_private_network=True, rate_limit_rps=5)
        client, _ = _client(db, audit, settings, scope, program)
        t0 = time.monotonic()
        for _ in range(4):
            client.get(f"http://127.0.0.1:{srv.port}/")
        assert time.monotonic() - t0 >= 0.6 - 0.05, "4 requisições a 5 req/s levam ao menos 0,6 s"


def test_budget_method_and_cancel(db, audit, settings, program):
    with CountingServer() as srv:
        scope = mk_scope(program, [f"127.0.0.1:{srv.port}"], allow_private_network=True, rate_limit_rps=50, max_requests_per_job=2)
        cancel = CancelToken()
        client, _ = _client(db, audit, settings, scope, program, cancel)
        with pytest.raises(MethodNotAllowed):
            client.request("POST", f"http://127.0.0.1:{srv.port}/", data="a=1")
        client.get(f"http://127.0.0.1:{srv.port}/")
        client.get(f"http://127.0.0.1:{srv.port}/")
        with pytest.raises(BudgetExceeded):
            client.get(f"http://127.0.0.1:{srv.port}/")
        cancel.cancel()
        with pytest.raises(Cancelled):
            client.get(f"http://127.0.0.1:{srv.port}/")
        assert len(srv.hits) == 2
