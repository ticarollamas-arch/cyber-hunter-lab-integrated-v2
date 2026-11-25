import requests

def fetch():
    return requests.get("https://api.exemplo.com/status", timeout=5).text
