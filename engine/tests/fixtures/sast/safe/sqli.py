import sqlite3
from flask import request

def find():
    name = request.args.get("n")
    cur = sqlite3.connect("app.db").cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))
    return cur.fetchall()
