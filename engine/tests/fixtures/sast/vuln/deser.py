import pickle
import yaml
from flask import request

def load_obj():
    return pickle.loads(request.data)

def load_cfg():
    return yaml.load(request.data)
