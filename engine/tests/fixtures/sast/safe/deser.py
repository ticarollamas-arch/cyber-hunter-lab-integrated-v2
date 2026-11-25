import json
import yaml
from flask import request

def load_obj():
    return json.loads(request.data)

def load_cfg():
    return yaml.safe_load(request.data)
