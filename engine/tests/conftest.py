import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from chl_engine.audit import AuditLog  # noqa: E402
from chl_engine.config import Settings  # noqa: E402
from chl_engine.db import Database  # noqa: E402


class CountingServer:
    """Servidor HTTP local que conta cada requisição recebida (prova de "zero requisições")."""

    def __init__(self, routes=None):
        self.hits: list[tuple[str, str]] = []
        server = self
        routes = routes or {}

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _serve(self):
                server.hits.append((self.command, self.path))
                status, headers, body = routes.get(self.path.split("?")[0], (200, {"Content-Type": "text/html"}, b"<html>ok</html>"))
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            do_GET = do_HEAD = do_OPTIONS = do_POST = _serve

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def settings(tmp_path):
    s = Settings()
    s.data_dir = tmp_path
    s.osv_online = False
    s.http_timeout = 5
    s.ai_base_url = ""
    return s


@pytest.fixture
def db(settings):
    return Database(settings.db_path)


@pytest.fixture
def audit(db):
    return AuditLog(db)


@pytest.fixture
def user(db):
    from chl_engine.security import hash_token
    uid = db.execute("INSERT INTO users(name, role, token_hash, created_at) VALUES('pesquisadora','admin',?, '2026-01-01')", (hash_token("t"),))
    return uid


@pytest.fixture
def program(db, user):
    return db.execute("INSERT INTO programs(name, platform, owner_id, created_at) VALUES('Lab', 'local', ?, '2026-01-01')", (user,))
