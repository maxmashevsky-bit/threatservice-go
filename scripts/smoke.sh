#!/bin/sh
set -eu

# No third-party dependencies; uses the Python 3 standard library.
python3 - <<'PY'
import hashlib
import json
import os
import urllib.error
import urllib.request

base = os.environ.get("BASE_URL", "http://localhost:8080").rstrip("/")
token = os.environ.get("API_TOKEN", "")
md5 = hashlib.md5(os.urandom(32)).hexdigest()

def request(method, path, expected, body=None, content_type="application/json"):
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    if body is not None:
        headers["Content-Type"] = content_type
        body = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(base + path, data=body, headers=headers, method=method)
    try:
        response = urllib.request.urlopen(req, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read()
        if response.status != expected:
            raise AssertionError(f"{method} {path}: expected {expected}, got {response.status}: {raw!r}")
        data = json.loads(raw) if raw else None
        return data, response.headers

request("GET", "/health/live", 200)
request("GET", "/health/ready", 200)
created, headers = request("POST", "/info", 201, {
    "md5": md5.upper(), "name": "Smoke.Test", "description": "Smoke test", "severity": "low"
})
assert headers.get("Location") == "/info/" + md5
assert created["md5"] == md5
assert created["created_at"] == created["updated_at"]
assert set(created) == {"md5", "name", "description", "severity", "created_at", "updated_at"}
read, _ = request("GET", "/info/" + md5.upper(), 200)
assert read == created
request("POST", "/info", 409, {"md5": md5, "name": "Duplicate"})
updated, _ = request("PUT", "/info/" + md5, 200, {"name": "Smoke.Updated"})
assert updated["description"] == "" and updated["severity"] == "unknown"
assert updated["created_at"] == created["created_at"]
repeated, _ = request("PUT", "/info/" + md5, 200, {"name": "Smoke.Updated"})
assert repeated == updated
read, _ = request("GET", "/info/" + md5, 200)
assert read == updated
request("GET", "/info/not-an-md5", 400)
missing = hashlib.md5(os.urandom(32)).hexdigest()
request("GET", "/info/" + missing, 404)
request("PUT", "/info/" + missing, 404, {"name": "Missing"})
request("POST", "/info", 400, {"md5": missing, "name": "   "})
request("POST", "/info", 400, {"md5": missing, "name": "Bad", "extra": True})
request("POST", "/info", 400, b"null")
request("POST", "/info", 415, b"{}", "text/plain")
request("POST", "/info", 413, b" " * 65537)
_, headers = request("DELETE", "/info/" + md5, 405)
assert "GET" in headers.get("Allow", "") and "PUT" in headers.get("Allow", "")
print("Smoke checks passed; test record retained: " + md5)
PY
