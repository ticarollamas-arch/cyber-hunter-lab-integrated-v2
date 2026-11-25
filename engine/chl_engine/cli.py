"""Linha de comando: usuários, servidor e laboratório.

    python -m chl_engine.cli create-user --name ana --role admin
    python -m chl_engine.cli serve --host 127.0.0.1 --port 8787
    python -m chl_engine.cli lab --port 8081            # app vulnerável local, só para testes
"""
from __future__ import annotations

import argparse
import sys

from .config import Settings
from .db import Database, utcnow
from .security import hash_token, new_token


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="chl_engine")
    sub = ap.add_subparsers(dest="cmd", required=True)
    cu = sub.add_parser("create-user", help="cria usuário e mostra o token uma única vez")
    cu.add_argument("--name", required=True)
    cu.add_argument("--role", choices=["admin", "researcher", "viewer"], default="researcher")
    sv = sub.add_parser("serve", help="inicia API + painel")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8787)
    lb = sub.add_parser("lab", help="inicia a aplicação vulnerável de laboratório em 127.0.0.1")
    lb.add_argument("--port", type=int, default=8081)
    lb.add_argument("--safe", action="store_true")
    args = ap.parse_args(argv)
    settings = Settings()

    if args.cmd == "create-user":
        db = Database(settings.db_path, settings.audit_retention_days)
        token = new_token()
        db.execute("INSERT INTO users(name, role, token_hash, created_at) VALUES(?,?,?,?)", (args.name, args.role, hash_token(token), utcnow()))
        print(f"Usuário {args.name} ({args.role}) criado. Token (guarde agora; não será mostrado de novo):\n{token}")
        return 0
    if args.cmd == "serve":
        from werkzeug.serving import run_simple
        from .api import create_app
        if args.host not in ("127.0.0.1", "localhost", "::1"):
            print("Aviso: expondo fora do localhost. Use HTTPS (Cloudflare Tunnel/Nginx) na frente.", file=sys.stderr)
        run_simple(args.host, args.port, create_app(settings), threaded=True)
        return 0
    if args.cmd == "lab":
        from lab.vulnapp import create_app as lab_app
        lab_app(args.safe).run("127.0.0.1", args.port)
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
