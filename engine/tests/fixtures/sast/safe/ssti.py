from flask import render_template, request

def page():
    return render_template("page.html", termo=request.args.get("t", ""))
