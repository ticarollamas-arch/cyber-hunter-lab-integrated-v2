import os
from flask import request

BASE = "/srv/files"

def download():
    wanted = request.args.get("f")
    with open(os.path.join(BASE, wanted)) as fh:
        return fh.read()
