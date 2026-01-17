import requests
import time
import json

URL = "https://carmela-unpublished-lou.ngrok-free.dev/api/v1/logs"
TOKEN = "Server@123"

headers = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json"
}

# Test cases: one with string, one with float
logs = [
    {
        "timestamp": "2025-12-23T12:00:00Z",
        "hostname": "test-host",
        "ip_address": "127.0.0.1",
        "os_type": "Linux",
        "log_source": "test",
        "message": "String timestamp test"
    },
    {
        "timestamp": time.time(),
        "hostname": "test-host",
        "ip_address": "127.0.0.1",
        "os_type": "Linux",
        "log_source": "test",
        "message": "Float timestamp test"
    }
]

print(f"Sending request to {URL}...")
try:
    response = requests.post(URL, json=logs, headers=headers, timeout=10)
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.text}")
except Exception as e:
    print(f"Error: {e}")
