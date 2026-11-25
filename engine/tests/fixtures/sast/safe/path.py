import os
from flask import request

BASE = "/srv/files"

def download():
    wanted = os.path.basename(request.args.get("f"))
    with open(os.path.join(BASE, wanted)) as fh:
        return fh.read()
