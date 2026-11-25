import requests
from flask import request

def fetch():
    target = request.json["url"]
    return requests.get(target, timeout=5).text
