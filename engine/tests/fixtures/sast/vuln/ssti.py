from flask import render_template_string, request

def page():
    tpl = request.args.get("t", "")
    return render_template_string(tpl)
