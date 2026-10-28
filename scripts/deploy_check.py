#!/usr/bin/env python3
"""Exercise a disposable Docker deployment without touching existing projects."""

import hashlib
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid


class CheckFailure(Exception):
    pass


def check(condition, message):
    if not condition:
        raise CheckFailure(message)


def main():
    for executable in ("docker", "openssl"):
        check(shutil.which(executable), executable + " is required")
    source = Path(__file__).resolve().parent.parent
    temporary = Path(tempfile.mkdtemp(prefix="threatservice-deploy-check-", dir="/tmp"))
    context = temporary / "threatservice"
    project = "threatservice-audit-" + uuid.uuid4().hex[:10]
    tls_container = project + "-tls"
    protected_container = project + "-protected"
    bearer_token = "audit-bearer-SECRET-0123456789abcdef"
    owner_password = "audit-owner-SECRET:@/?#%$ with space'quote"
    app_password = "audit-app-SECRET:@/?#%$ with space'quote"
    secret_markers = ("audit-owner-SECRET", "audit-app-SECRET", "audit-dsn-SECRET", bearer_token)
    environment = os.environ.copy()
    for key in ("POSTGRES_PASSWORD", "APP_DB_PASSWORD", "API_TOKEN", "RATE_LIMIT_RPS", "RATE_LIMIT_BURST",
                "PG_MAX_CONNS", "REQUEST_TIMEOUT", "QUERY_TIMEOUT", "SHUTDOWN_TIMEOUT", "COMPOSE_FILE",
                "COMPOSE_PROJECT_NAME", "DATABASE_URL", "PGPASSWORD", "TLS_CERT_FILE", "TLS_KEY_FILE"):
        environment.pop(key, None)

    def command(args, *, expected=0, timeout=180, sensitive_output=False):
        result = subprocess.run(args, cwd=context, env=environment, capture_output=True, text=True, timeout=timeout)
        output = result.stdout + result.stderr
        if not sensitive_output:
            check(not any(marker in output for marker in secret_markers), "a command leaked a test password (output redacted)")
        if expected is not None:
            check(result.returncode == expected,
                  "command failed: " + args[0] + " (exit " + str(result.returncode) + "; output withheld)")
        return result

    def compose(*args, **kwargs):
        return command(["docker", "compose", "--project-name", project, "--env-file", str(context / ".env"), *args], **kwargs)

    def dotenv(value):
        return "'" + value.replace("'", "\\'") + "'"

    def write_env(owner=owner_password, app=app_password):
        path = context / ".env"
        path.write_text("POSTGRES_PASSWORD=" + dotenv(owner) + "\nAPP_DB_PASSWORD=" + dotenv(app) + "\n", encoding="utf-8")
        path.chmod(0o600)

    def http(base, method, path, expected=200, body=None, tls_context=None, headers=None):
        headers = dict(headers or {})
        if body is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(base + path, method=method, data=body, headers=headers)
        try:
            response = urllib.request.urlopen(request, timeout=3, context=tls_context)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            check(response.status == expected, method + " " + path + " returned " + str(response.status))
            return json.loads(response.read())

    def ready(base, tls_context=None):
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            try:
                response = http(base, "GET", "/health/ready", tls_context=tls_context)
                if response.get("status") == "ok":
                    return
            except (OSError, CheckFailure):
                time.sleep(1.1)
        raise CheckFailure("service did not become ready")

    def failing_app(*args):
        result = compose("run", "--rm", "--no-deps", *args, "app", expected=None, timeout=20)
        check(result.returncode != 0, "invalid app configuration was accepted")

    try:
        shutil.copytree(source, context, ignore=shutil.ignore_patterns(".git", ".env", ".env.*", "bin", "certs", "__pycache__"))
        path = context / "compose.yaml"
        definition = path.read_text(encoding="utf-8")
        check(definition.count('"127.0.0.1:8080:8080"') == 1, "update audit script for the changed published port")
        definition = definition.replace('"127.0.0.1:8080:8080"', '"127.0.0.1::8080"')
        definition = definition.replace("threatservice:local", "threatservice:" + project)
        path.write_text(definition, encoding="utf-8")
        write_env()
        command(["docker", "info"], timeout=10)

        # config output contains secrets by design: inspect in memory, never print it.
        (context / ".env").write_text("", encoding="utf-8")
        defaults = json.loads(compose("config", "--format", "json", sensitive_output=True).stdout)
        check(defaults["services"]["postgres"]["environment"]["POSTGRES_PASSWORD"] == "dev-owner-change-me",
              "absent owner password did not use the documented development default")
        check(defaults["services"]["app"]["environment"]["PGPASSWORD"] == "dev-app-change-me",
              "absent app password did not use the documented development default")
        write_env()
        configured = json.loads(compose("config", "--format", "json", sensitive_output=True).stdout)
        for service, password in (("migrate", owner_password), ("app", app_password)):
            values = configured["services"][service]["environment"]
            check(values["PGPASSWORD"].replace("$$", "$") == password, ".env did not preserve special password characters")
            check("SECRET" not in values["DATABASE_URL"], "password was interpolated into a database URI")
        print("Compose preserves special password characters without URI interpolation")

        compose("up", "--build", "-d")
        port = compose("port", "app", "8080").stdout.strip()
        base = "http://" + port
        ready(base)
        with ThreadPoolExecutor(max_workers=12) as probes:
            results = list(probes.map(lambda _: http(base, "GET", "/health/ready"), range(40)))
        check(all(value == {"status": "ok"} for value in results), "concurrent readiness probes rejected a healthy service")
        print("Concurrent readiness probes succeed without 429")
        md5 = hashlib.md5(os.urandom(32)).hexdigest()
        created = http(base, "POST", "/info", 201, {"md5": md5, "name": "Deployment.Check"})
        compose("up", "--build", "-d")
        base = "http://" + compose("port", "app", "8080").stdout.strip()
        ready(base)
        check(http(base, "GET", "/info/" + md5) == created, "repeated up/build lost or changed stored data")
        container = compose("ps", "-q", "app").stdout.strip()
        runtime = command(["docker", "inspect", "--format", "{{.Config.User}}|{{.HostConfig.ReadonlyRootfs}}", container]).stdout.strip()
        check(runtime == "65532:65532|true", "runtime is not nonroot with a read-only root filesystem")
        print("Special-password bootstrap, nonroot runtime and repeated up/build persistence passed")

        for key, value in (("PG_MAX_CONNS", "0"), ("RATE_LIMIT_RPS", "NaN"),
                           ("API_TOKEN", "short"), ("TLS_CERT_FILE", "/missing.crt"),
                           ("DATABASE_URL", "postgres://user:audit-dsn-SECRET%zz@localhost/db")):
            failing_app("-e", key + "=" + value)
        print("Malformed configuration fails without exposing credentials")

        for args in (("up", "status"), ("status", "-app-role=threat_app"), ("-unknown",),
                     ("-app-role",), ("down",), ("-app-role=missing_audit_role", "up")):
            result = compose("run", "--rm", "--no-deps", "migrate", *args, expected=None, timeout=40)
            check(result.returncode != 0, "invalid migration CLI operation succeeded")
        compose("run", "--rm", "--no-deps", "migrate", "-app-role=threat_app", "up")
        check(http(base, "GET", "/info/" + md5) == created, "failed CLI operation changed threat data")
        print("Migration argument errors, destructive-down guard and recovery passed")

        compose("stop", "postgres")
        http(base, "GET", "/health/live")
        http(base, "GET", "/health/ready", 503)
        failed_md5 = hashlib.md5(os.urandom(32)).hexdigest()
        failure = http(base, "POST", "/info", 500, {"md5": failed_md5, "name": "Unavailable.Database"})
        check(failure == {"message": "Internal server error"}, "database outage response exposed internal details")
        compose("start", "postgres")
        ready(base)
        check(compose("ps", "-q", "app").stdout.strip() == container, "recovery restarted the application")
        check(http(base, "GET", "/info/" + md5) == created, "database restart changed stored data")
        http(base, "GET", "/info/" + failed_md5, 404)
        print("Database outage fails safely; the same app process recovers without a delayed write")

        compose("run", "--rm", "--no-deps", "-d", "--name", protected_container,
                "-p", "127.0.0.1::8080", "-e", "API_TOKEN=" + bearer_token,
                "-e", "RATE_LIMIT_RPS=0.000001", "-e", "RATE_LIMIT_BURST=1", "app")
        protected_base = "http://" + command(["docker", "port", protected_container, "8080"]).stdout.strip()
        ready(protected_base)
        http(protected_base, "GET", "/info/" + md5, 401)
        authorization = {"Authorization": "Bearer " + bearer_token}
        check(http(protected_base, "GET", "/info/" + md5, headers=authorization) == created,
              "authorized request changed the response")
        http(protected_base, "GET", "/info/" + md5, 429, headers=authorization)
        http(protected_base, "GET", "/health/live")
        command(["docker", "logs", protected_container])
        command(["docker", "rm", "-f", protected_container])
        print("Bearer access and rate limit work in the built image without leaking the token")

        certs = temporary / "certs"
        certs.mkdir(mode=0o755)
        cert = certs / "server.crt"
        key = certs / "server.key"
        command(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                 "-out", str(cert), "-days", "1", "-subj", "/CN=localhost",
                 "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"])
        cert.chmod(0o644)
        key.chmod(0)
        mounts = ["-v", str(cert) + ":/run/tls/server.crt:ro", "-v", str(key) + ":/run/tls/server.key:ro",
                  "-e", "TLS_CERT_FILE=/run/tls/server.crt", "-e", "TLS_KEY_FILE=/run/tls/server.key"]
        failing_app(*mounts)
        key.chmod(0o644)  # Test-only key in an isolated temp directory.
        compose("run", "--rm", "--no-deps", "-d", "--name", tls_container,
                "-p", "127.0.0.1::8080", *mounts, "app")
        tls_port = command(["docker", "port", tls_container, "8080"]).stdout.strip()
        tls_context = ssl.create_default_context(cafile=str(cert))
        ready("https://" + tls_port, tls_context)
        check(http("https://" + tls_port, "GET", "/info/" + md5, tls_context=tls_context) == created,
              "TLS changed the API response")
        command(["docker", "rm", "-f", tls_container])
        print("Unreadable TLS key fails closed; readable certificate/key serve verified HTTPS")

        compose("down", "--volumes", "--remove-orphans")
        for owner, app, expected_message in ((owner_password, "", "APP_DB_PASSWORD must not be empty"),
                                             ("", app_password, "Database is uninitialized and superuser password is not specified")):
            write_env(owner, app)
            compose("up", "-d", "postgres")
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                logs = compose("logs", "--no-color", "postgres").stdout
                if expected_message in logs:
                    break
                time.sleep(0.5)
            else:
                raise CheckFailure("empty password did not produce the expected safe bootstrap error")
            check(not compose("ps", "-q", "app").stdout.strip(), "app started after failed password bootstrap")
            compose("down", "--volumes", "--remove-orphans")
        print("Explicit empty passwords fail bootstrap without starting the app or leaking secrets")
        print("Docker deployment checks passed")
    finally:
        # Every mutation is scoped to our random project or explicitly named containers.
        if context.exists():
            try:
                command(["docker", "rm", "-f", tls_container, protected_container], expected=None, timeout=15)
                containers = command(["docker", "ps", "-aq", "--filter", "label=com.docker.compose.project=" + project],
                                     expected=None, timeout=15)
                if containers.returncode == 0 and containers.stdout.split():
                    command(["docker", "rm", "-f", *containers.stdout.split()], expected=None, timeout=20)
                compose("down", "--volumes", "--remove-orphans", expected=None, timeout=45)
                command(["docker", "image", "rm", "threatservice:" + project], expected=None, timeout=15)
            finally:
                shutil.rmtree(temporary, ignore_errors=True)


if __name__ == "__main__":
    try:
        main()
    except (CheckFailure, subprocess.SubprocessError, OSError) as error:
        # Never include captured command output, DSNs or environment values.
        print("Deployment checks failed: " + (str(error) if isinstance(error, CheckFailure) else type(error).__name__), file=sys.stderr)
        sys.exit(1)
