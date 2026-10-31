"""Turn published VPNGate OpenVPN profiles into a verified local SOCKS5 route."""
import base64
import csv
import io
import ipaddress
import json
from pathlib import Path
import re
import shutil
import subprocess
import time

import requests

from run_control import data_dir

CONTAINER = "proxyhunter-vpngate"
IMAGE = "proxyhunter/vpngate:local"
URLS = ("https://www.vpngate.net/api/iphone/", "http://www.vpngate.net/api/iphone/")


def parse_directory(text):
    lines = [line.lstrip("#") for line in text.lstrip("\ufeff").splitlines() if line and not line.startswith("*")]
    result = []
    for row in csv.DictReader(lines):
        try:
            address = str(ipaddress.ip_address(row["IP"]))
            if not ipaddress.ip_address(address).is_global:
                continue
            config = base64.b64decode(row["OpenVPN_ConfigData_Base64"], validate=True).decode("utf-8")
            profile, remote, port, protocol = sanitize_profile(config, address)
            result.append({"ip": address, "name": row.get("HostName"), "country": row.get("CountryLong"),
                           "score": int(row.get("Score") or 0), "speed": int(row.get("Speed") or 0),
                           "config": profile, "remote": remote, "port": port, "protocol": protocol})
        except (KeyError, ValueError, UnicodeError, TypeError):
            continue
    return sorted(result, key=lambda item: (item["score"], item["speed"]), reverse=True)


def sanitize_profile(config, expected_ip):
    if len(config) > 100000:
        raise ValueError("VPN configuration is too large")
    inline = None
    output = []
    remote, port, protocol = None, None, "tcp"
    allowed = {"client", "dev", "proto", "remote", "cipher", "data-ciphers", "data-ciphers-fallback",
               "auth", "nobind", "persist-key", "persist-tun", "verb", "remote-cert-tls", "tls-client",
               "tls-version-min", "auth-nocache", "setenv", "reneg-sec", "keepalive"}
    for original in config.splitlines():
        line = original.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line in ("<ca>", "<cert>", "<key>", "<tls-auth>", "<tls-crypt>"):
            inline = line[1:-1]
            output.append(line)
            continue
        if inline:
            output.append(line)
            if line == f"</{inline}>":
                inline = None
            continue
        parts = line.split()
        if parts[0] not in allowed:
            continue
        if parts[0] == "remote":
            if len(parts) < 3 or str(ipaddress.ip_address(parts[1])) != expected_ip:
                raise ValueError("VPN remote does not match its published address")
            remote, port = expected_ip, int(parts[2])
            if not 1 <= port <= 65535:
                raise ValueError("Invalid VPN port")
        elif parts[0] == "proto":
            protocol = "udp" if parts[1].startswith("udp") else "tcp"
        elif parts[0] == "dev":
            line = "dev tun0"
        elif parts[0] == "setenv":
            continue
        output.append(line)
    if not remote or inline or "<ca>" not in output:
        raise ValueError("Incomplete OpenVPN profile")
    output.extend(["redirect-gateway def1", "remote-cert-tls server", "auth-nocache", "verb 3"])
    return "\n".join(output) + "\n", remote, port, protocol


def docker(*args, timeout=30, cancelled=None):
    if cancelled is None:
        return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    process = subprocess.Popen(["docker", *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    deadline = time.monotonic() + timeout
    while True:
        if cancelled() or time.monotonic() > deadline:
            process.terminate()
            try:
                stdout, stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
            return subprocess.CompletedProcess(process.args, 130, stdout, stderr or "Cancelled or timed out")
        try:
            stdout, stderr = process.communicate(timeout=0.2)
            return subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
        except subprocess.TimeoutExpired:
            continue


def discover(state):
    for url in URLS:
        if state.control.is_cancelled():
            return []
        try:
            response = requests.get(url, timeout=12)
            response.raise_for_status()
            profiles = parse_directory(response.text)
            if profiles:
                state.source_health[url] = {"url": url, "category": "vpngate", "status": "OK",
                    "count": len(profiles), "transport": "OpenVPN", "error": None}
                return profiles
        except (requests.RequestException, ValueError) as exc:
            state.source_health[url] = {"url": url, "category": "vpngate", "status": "ERROR", "count": 0, "error": str(exc)}
    return []


def gateway_exit(port, cancelled=None):
    route = f"socks5h://127.0.0.1:{port}"
    last_error = None
    with requests.Session() as session:
        session.trust_env = False
        for url in ("https://api.ipify.org?format=json", "https://checkip.amazonaws.com"):
            if cancelled and cancelled():
                raise RuntimeError("VPN gateway verification cancelled")
            try:
                response = session.get(url, proxies={"http": route, "https": route}, timeout=8)
                response.raise_for_status()
                try:
                    value = response.json()["ip"]
                except (ValueError, KeyError, TypeError):
                    value = response.text.strip()
                address = ipaddress.ip_address(value)
                if not address.is_global:
                    raise ValueError("VPN gateway did not return a public exit address")
                return str(address)
            except (requests.RequestException, ValueError) as exc:
                last_error = exc
    raise last_error


def harvest_vpngate(state):
    def command(*args, **kwargs):
        return docker(*args, cancelled=state.control.is_cancelled, **kwargs)
    state.vpngate = {"status": "DISCOVERING", "profiles": 0, "error": None}
    profiles = discover(state)
    state.vpngate["profiles"] = len(profiles)
    if not profiles:
        state.vpngate.update(status="UNAVAILABLE", error="No valid OpenVPN profiles could be retrieved.")
        return {}, 0
    folder = data_dir() / "vpngate"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "profiles.json").write_text(json.dumps(profiles, indent=2), encoding="utf-8")
    port = state.settings.get("vpngate_port", 1088)
    endpoint = f"127.0.0.1:{port}"

    def ready(exit_ip):
        state.vpngate.update(status="READY", exit_ip=exit_ip, proxy=endpoint, error=None)
        state.vpngate_endpoints.add(endpoint)
        print(f"  VPNGate: {len(profiles)} OpenVPN profiles; SOCKS5 gateway verified at {endpoint} (exit {exit_ip}).")
        return {endpoint: "socks5"}, 1

    if not shutil.which("docker"):
        state.vpngate.update(status="PROFILES_READY", error="OpenVPN profiles saved; a Docker/TUN gateway is required on this host.")
        print(f"  VPNGate: {len(profiles)} OpenVPN profiles saved; Docker/TUN gateway unavailable.")
        return {}, 0
    try:
        inspected = command("inspect", CONTAINER)
        if inspected.returncode == 0:
            description = json.loads(inspected.stdout)[0]
            if description["State"]["Running"] and description["Config"]["Image"] == IMAGE:
                try:
                    return ready(gateway_exit(port, state.control.is_cancelled))
                except (requests.RequestException, ValueError):
                    pass
        if not state.settings.get("vpngate_autostart", True):
            state.vpngate.update(status="PROFILES_READY", error="Automatic VPN gateway startup is disabled.")
            return {}, 0
        if command("info", "--format", "{{.OSType}}").returncode:
            state.vpngate.update(status="PROFILES_READY", error="Start Docker Desktop to connect the saved VPN profiles.")
            print(f"  VPNGate: {len(profiles)} profiles ready; Docker Desktop is not running.")
            return {}, 0
        if command("image", "inspect", IMAGE).returncode:
            state.vpngate["status"] = "BUILDING_GATEWAY"
            build = command("build", "-t", IMAGE, str(Path(__file__).resolve().parent / "vpngate"), timeout=300)
            if build.returncode:
                raise RuntimeError(build.stderr[-500:])
        for profile in profiles[:state.settings.get("vpngate_max_attempts", 3)]:
            if state.control.is_cancelled():
                break
            state.vpngate.update(status="CONNECTING", country=profile["country"])
            # Remove only this application's named gateway, never other containers.
            existing = command("inspect", CONTAINER)
            if existing.returncode == 0:
                if json.loads(existing.stdout)[0]["Config"]["Image"] != IMAGE:
                    raise RuntimeError("The VPN gateway container name belongs to a different image.")
                command("rm", "-f", CONTAINER)
            (folder / "client.ovpn").write_text(profile["config"], encoding="utf-8")
            created = command("run", "-d", "--name", CONTAINER, "--label", "com.proxyhunter.component=vpngate",
                "--cap-add=NET_ADMIN", "--device=/dev/net/tun",
                "-p", f"127.0.0.1:{port}:1080", "--mount", f"type=bind,source={folder.resolve()},target=/vpn,readonly",
                "-e", f"VPN_REMOTE_IP={profile['remote']}", "-e", f"VPN_REMOTE_PORT={profile['port']}",
                "-e", f"VPN_REMOTE_PROTO={profile['protocol']}", IMAGE)
            if created.returncode:
                raise RuntimeError(created.stderr[-400:])
            for _ in range(70):
                if state.control.wait(0.5):
                    docker("rm", "-f", CONTAINER)
                    return {}, 0
                logs = command("logs", CONTAINER).stdout
                if "VPN_READY" in logs:
                    try:
                        return ready(gateway_exit(port, state.control.is_cancelled))
                    except (requests.RequestException, ValueError):
                        break
                if "VPN_FAILED" in logs:
                    break
        state.vpngate.update(status="CONNECTION_FAILED", error="Published VPN profiles were found, but no tunnel connected within the attempt limit.")
        print(f"  VPNGate: {len(profiles)} profiles discovered; {state.vpngate['error']}")
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        state.vpngate.update(status="GATEWAY_ERROR", error=str(exc))
        if state.control.is_cancelled():
            state.vpngate.update(status="CANCELLED", error=state.control.reason)
        print(f"  VPNGate: {len(profiles)} profiles discovered; gateway error: {exc}")
    return {}, 0
