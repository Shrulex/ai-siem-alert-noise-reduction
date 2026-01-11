# test_backend.py
import requests
data = [{"event_type": "Failed Login", "severity": 8, "frequency": 25}]
resp = requests.post("http://127.0.0.1:8000/analyze/", json=data)
print(f"Status: {resp.status_code}")
print(resp.json())
