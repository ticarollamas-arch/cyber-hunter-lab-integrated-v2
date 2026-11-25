from flask import redirect, url_for

def back():
    return redirect(url_for("home"))
