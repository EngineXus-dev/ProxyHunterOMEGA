"""Start the local Scrapoxy service and provision its public-list project."""

import base64
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
from urllib.parse import urlsplit

import requests

ROOT = Path(__file__).resolve().parent
RUNTIME = ROOT / ".scrapoxy"
PROJECT_FILE = RUNTIME / "project.json"


def load_project_config():
    if PROJECT_FILE.exists():
        return json.loads(PROJECT_FILE.read_text(encoding="utf-8"))
    return {}


def prepare_service():
    (RUNTIME / "data").mkdir(parents=True, exist_ok=True)
    env_file = RUNTIME / "service.env"
    if not env_file.exists():
        values = {
            "AUTH_LOCAL_USERNAME": "admin",
            "AUTH_LOCAL_PASSWORD": secrets.token_urlsafe(24),
            "BACKEND_JWT_SECRET": secrets.token_urlsafe(48),
            "FRONTEND_JWT_SECRET": secrets.token_urlsafe(48),
        }
        env_file.write_text("".join(f"{k}={v}\n" for k, v in values.items()), encoding="utf-8")
    return dict(line.split("=", 1) for line in env_file.read_text(encoding="utf-8").splitlines() if "=" in line)


def prepare_source():
    """Build the user's archived source instead of the discontinued Docker image."""
    destination = (RUNTIME / "source").resolve()
    if not (destination / "package.json").is_file():
        raise FileNotFoundError(
            "Local Scrapoxy source is not bundled with the public repository. "
            "Provide your own licensed source at .scrapoxy/source or configure "
            "an existing Scrapoxy service with SCRAPOXY_AUTOSTART=0."
        )
    # The original fingerprint host is gone. Preserve the replacement URL's query
    # instead of appending Scrapoxy-specific telemetry to an unrelated IP service.
    fingerprint = destination / "packages/backend/sdk/src/fingerprint/fingerprint.helpers.ts"
    body = fingerprint.read_text(encoding="utf-8")
    marker = "    urlOpts.pathname += '?version=2'"
    if marker in body:
        start = body.index(marker)
        end = body.index("    const reqArgs =", start)
        body = body[:start] + "    urlOpts.pathname += urlOpts.search ?? '';\n    urlOpts.search = undefined;\n\n" + body[end:]
        fingerprint.write_text(body, encoding="utf-8")


def provision_project(settings, credentials):
    """Reuse our project and only create free-list resources; never paid connectors."""
    api_url = settings["scrapoxy_url"].rstrip("/")
    with requests.Session() as session:
        session.trust_env = False

        def api(method, path, **kwargs):
            response = session.request(method, f"{api_url}/api/{path}", timeout=15, **kwargs)
            response.raise_for_status()
            return response.json() if response.content else None

        api("POST", "users/auths/local", json={
            "username": credentials["AUTH_LOCAL_USERNAME"],
            "password": credentials["AUTH_LOCAL_PASSWORD"],
        })
        projects = api("GET", "frontend/projects")
        project = next((p for p in projects if p["name"] == "ProxyHunter"), None)
        if project is None:
            project = api("POST", "frontend/projects", json={
                "name": "ProxyHunter",
                "autoRotate": {"enabled": False, "min": 1800000, "max": 1800000},
                "autoScaleUp": False,
                "autoScaleDown": {"enabled": False, "value": 600000},
                "cookieSession": False, "mitm": False, "proxiesMin": 1,
                "useragentOverride": False, "ciphersShuffle": False,
            })
        prefix = f"frontend/projects/{project['id']}"
        token = api("GET", f"{prefix}/token")["token"]
        username, password = base64.b64decode(token).decode().split(":", 1)
        settings.update(scrapoxy_user=username, scrapoxy_pass=password)
        PROJECT_FILE.write_text(json.dumps({"username": username, "password": password,
                                           "project_id": project["id"]}, indent=2), encoding="utf-8")

        connectors = [entry.get("connector", entry) for entry in api("GET", f"{prefix}/connectors")]
        connector = next((c for c in connectors if c["name"] == "ProxyHunter Public Lists"), None)
        if connector is None:
            credentials_list = api("GET", f"{prefix}/credentials")
            credential = next((c for c in credentials_list if c["type"] == "freeproxies"), None)
            if credential is None:
                credential = api("POST", f"{prefix}/credentials", json={
                    "name": "Public proxy lists", "type": "freeproxies", "config": {},
                })
            connector = api("POST", f"{prefix}/connectors", json={
                "name": "ProxyHunter Public Lists", "credentialId": credential["id"],
                "proxiesMax": 20, "proxiesTimeoutDisconnected": 5000,
                "proxiesTimeoutUnreachable": {"enabled": True, "value": 600000},
                "config": {"freeproxiesTimeoutDisconnected": 5000,
                           "freeproxiesTimeoutUnreachable": {"enabled": True, "value": 600000}},
                "certificateDurationInMs": 31536000000,
            })
        connector_path = f"{prefix}/connectors/{connector['id']}"
        existing = api("GET", f"{connector_path}/sourcesfreeproxies")
        existing_urls = {s["url"] for s in existing["sources"]}
        # Use a small selection of the same Tier 1 lists used by the hunter.
        from constants import SOURCES_GITHUB
        sources = [{"url": url, "delay": 900000} for url, proto, tier in SOURCES_GITHUB
                   if proto == "http" and tier == 1 and any(provider in url for provider in
                       ("/monosans/", "/elliottophellia/", "/vakhov/"))]
        retired = [s["id"] for s in existing["sources"] if "/UptimerBot/" in s["url"]]
        if retired:
            api("POST", f"{connector_path}/sources/remove", json=retired)
        missing = [s for s in sources if s["url"] not in existing_urls]
        if missing:
            api("POST", f"{connector_path}/sources", json=missing)
        if not connector.get("active"):
            api("POST", f"{connector_path}/activate", json={"active": True})
        api("POST", f"{prefix}/default", json={"connectorDefaultId": connector["id"]})
        if project.get("status") != "HOT":
            api("POST", f"{prefix}/status", json={"status": "HOT"})


# Cpu quota is specified in Docker CPU cores (0.50 means half of ONE logical core).
# Docker's container limit does not limit Python validation threads or WSL VM overhead.
DEFAULT_CPU_LIMIT = 0.50


def scrapoxy_cpu_limit():
    """Parse a bounded operator override without allowing bogus Compose values."""
    value = os.getenv("SCRAPOXY_CPU_LIMIT", str(DEFAULT_CPU_LIMIT))
    try:
        cores = float(value)
    except (ValueError, TypeError) as exc:
        raise ValueError("SCRAPOXY_CPU_LIMIT must be a number between 0.10 and 4.00") from exc
    if not 0.10 <= cores <= 4.00:
        raise ValueError("SCRAPOXY_CPU_LIMIT must be between 0.10 and 4.00")
    return cores


def enforce_scrapoxy_cpu_limit(cpu_limit, *, runner=subprocess.run):
    """Update the *existing* Compose-owned container and verify the live limit.

    Compose creates/recreates services on configuration changes. Docker update
    additionally enforces the quota on a previously running container and
    inspect checks whether Docker actually accepted it.
    """
    compose = ["docker", "compose", "-p", "proxyhunter", "-f", str(ROOT / "compose.scrapoxy.yml")]
    options = {"cwd": ROOT, "capture_output": True, "text": True, "timeout": 20,
               "creationflags": subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0}
    ps = runner([*compose, "ps", "-q", "scrapoxy"], **options)
    if ps.returncode:
        return f"Could not identify the managed Scrapoxy container: {ps.stderr[-180:].strip()}"
    container_id = ps.stdout.strip().splitlines()[0] if ps.stdout.strip() else ""
    if not container_id:
        return "No Compose-managed Scrapoxy container was found; CPU limit could not be verified."
    result = runner(["docker", "update", "--cpus", f"{cpu_limit:g}", container_id], **options)
    if result.returncode:
        return f"Docker did not apply the {cpu_limit:g}-core Scrapoxy limit: {result.stderr[-180:].strip()}"
    inspection = runner(["docker", "inspect", "--format", "{{.HostConfig.NanoCpus}}", container_id], **options)
    if inspection.returncode:
        return "Scrapoxy CPU update was requested but its live quota could not be verified."
    try:
        active_cores = int(inspection.stdout.strip()) / 1_000_000_000
    except ValueError:
        return "Scrapoxy CPU update was requested but Docker returned an unknown quota."
    if abs(active_cores - cpu_limit) > 0.001:
        return f"Scrapoxy CPU update was not confirmed (Docker reported {active_cores:g} cores)."
    return None


def ensure_scrapoxy(state):
    """Start only the bundled local service; leave remote/custom instances alone."""
    settings = state.settings
    if not settings.get("scrapoxy_enabled"):
        return False, "Scrapoxy is disabled."
    if not settings.get("scrapoxy_autostart"):
        return True, "Using the configured Scrapoxy service."
    target = urlsplit(settings["scrapoxy_url"])
    if target.hostname not in ("127.0.0.1", "localhost") or target.port != 8890:
        return True, "Using an external Scrapoxy service."
    try:
        # Do not replace an independently managed local instance.
        with requests.Session() as session:
            session.trust_env = False
            try:
                running = session.get(f"{settings['scrapoxy_url']}/api/users/auths", timeout=2)
                if running.ok and not (RUNTIME / "service.env").exists():
                    return True, "Existing Scrapoxy service detected; configure its project credentials."
            except requests.RequestException:
                pass
        cpu_limit = scrapoxy_cpu_limit()
        credentials = prepare_service()
        prepare_source()
        # Compose interpolation does not read service.env; pass this separately.
        # Only the Scrapoxy container is resource-limited, not Docker's image build.
        compose_env = dict(os.environ, SCRAPOXY_CPU_LIMIT=f"{cpu_limit:g}")
        result = subprocess.run(
            ["docker", "compose", "-p", "proxyhunter", "-f", str(ROOT / "compose.scrapoxy.yml"), "up", "-d", "scrapoxy"],
            cwd=ROOT, capture_output=True, text=True, timeout=900, env=compose_env,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        if result.returncode:
            return False, "Could not start Scrapoxy. Ensure Docker Desktop is running. " + result.stderr[-500:].strip()
        # A previous Docker container may still have old CPU settings. Update it
        # without relying solely on Compose configuration reconciliation.
        quota_warning = enforce_scrapoxy_cpu_limit(cpu_limit)
        deadline = time.monotonic() + 45
        with requests.Session() as session:
            session.trust_env = False
            while True:
                try:
                    response = session.get(f"{settings['scrapoxy_url']}/api/users/auths", timeout=2)
                    if response.ok:
                        break
                except requests.RequestException:
                    pass
                if time.monotonic() >= deadline:
                    return False, "Scrapoxy did not become ready; check docker compose logs scrapoxy."
                time.sleep(1)
        provision_project(settings, credentials)
        message = f"Scrapoxy connected; container CPU quota: {cpu_limit:g} logical core(s)."
        if quota_warning:
            message = f"Scrapoxy connected; CPU LIMIT NOT CONFIRMED: {quota_warning}"
        return True, message
    except (OSError, ValueError, KeyError, TypeError, requests.RequestException, subprocess.TimeoutExpired) as exc:
        return False, f"Scrapoxy startup failed: {exc}"


if __name__ == "__main__":
    from state import State
    ok, message = ensure_scrapoxy(State())
    print(message)
    raise SystemExit(0 if ok else 1)
