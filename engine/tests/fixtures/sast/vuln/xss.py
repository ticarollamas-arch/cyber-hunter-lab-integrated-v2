from flask import Flask

app = Flask(__name__)

@app.route("/oi/<nome>")
def oi(nome):
    return f"<h1>Olá {nome}</h1>"
