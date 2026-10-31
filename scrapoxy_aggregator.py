#!/usr/bin/env python3
"""
ProxyHunter v2 - Scrapoxy Super Proxy Aggregator Integration Layer
Connects to a separately managed Scrapoxy service, enumerates active proxy gateways
and checks observed exit-IP rotation. Connector metadata is not proof of residential
or mobile device ownership.
"""

import base64
import time
import requests
from urllib.parse import quote, urlsplit, urlunsplit
from scrapoxy_runtime import load_project_config
from ui import cp, dim, clr, BANNER, P, C, G, R, Y, B, DIM, RST, safe_input
from constants import SCRAPOXY_DEFAULTS, SCRAPOXY_HEADERS, TEST_URLS

class ScrapoxyClient:
    def __init__(self, api_url=None, proxy_url=None, username=None, password=None, timeout=8):
        self.api_url = (api_url or SCRAPOXY_DEFAULTS["api_url"]).rstrip("/")
        self.proxy_url = (proxy_url or SCRAPOXY_DEFAULTS["proxy_url"]).rstrip("/")
        project = load_project_config()
        self.username = username if username is not None else project.get("username", SCRAPOXY_DEFAULTS["username"])
        self.password = password if password is not None else project.get("password", SCRAPOXY_DEFAULTS["password"])
        self.timeout = timeout
        self.last_error = None
        self.session = requests.Session()
        self.session.trust_env = False

    @classmethod
    def from_settings(cls, settings):
        return cls(api_url=settings["scrapoxy_url"], proxy_url=settings["scrapoxy_proxy"],
                   username=settings["scrapoxy_user"], password=settings["scrapoxy_pass"],
                   timeout=settings["timeout"])

    @property
    def authenticated_proxy_url(self):
        parts = urlsplit(self.proxy_url)
        if parts.username is not None or not self.username:
            return self.proxy_url
        auth = f"{quote(self.username, safe='')}:{quote(self.password, safe='')}@"
        return urlunsplit(parts._replace(netloc=auth + parts.netloc))

    @property
    def auth_headers(self):
        token = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
        return {
            "Authorization": f"Basic {token}",
            "Content-Type": "application/json",
            "User-Agent": "ProxyHunter-v2/ScrapoxyClient",
        }

    def check_health(self):
        """Checks if Scrapoxy API is reachable and returns project info."""
        try:
            r = self.session.get(f"{self.api_url}/api/scraper/project",
                             headers=self.auth_headers,
                             timeout=self.timeout)
            if r.status_code == 200:
                data = r.json()
                if not isinstance(data, dict) or "status" not in data:
                    return False, {"error": "Unexpected Scrapoxy project response."}
                return True, data
            error = ("Project credentials are required (these differ from the dashboard login)."
                     if r.status_code in (401, 403) else f"HTTP {r.status_code}: {r.text[:100]}")
            return False, {"error": error, "http_status": r.status_code}
        except Exception as e:
            return False, {"error": str(e)}

    def set_project_status(self, status):
        """Sets project status: 'OFF', 'CALM', or 'HOT'."""
        try:
            status = status.upper()
            if status not in ("OFF", "CALM", "HOT"):
                return False, "Invalid status. Must be OFF, CALM, or HOT."
            r = self.session.post(f"{self.api_url}/api/scraper/project/status",
                              json={"status": status},
                              headers=self.auth_headers,
                              timeout=self.timeout)
            if r.status_code in (200, 204):
                return True, f"Project status set to {status}"
            return False, f"HTTP {r.status_code}: {r.text[:100]}"
        except Exception as e:
            return False, str(e)

    def get_connectors_and_proxies(self):
        """
        Retrieves all connectors (Rayobyte, IPRoyal, Proxidize 4G, Zyte, etc.)
        and their active proxy nodes.
        """
        try:
            r = self.session.get(f"{self.api_url}/api/scraper/project/connectors",
                             headers=self.auth_headers,
                             timeout=self.timeout)
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, list):
                    self.last_error = None
                    return True, data
                self.last_error = "Unexpected Scrapoxy connector response."
                return False, []
            self.last_error = f"Connector query failed: HTTP {r.status_code}"
            return False, []
        except Exception as e:
            self.last_error = str(e)
            return False, []

    def extract_all_proxies(self):
        """
        Return live exit metadata and the real authenticated forward-proxy route.
        A fingerprint IP is an exit address, not a proxy listening on port 80.
        """
        ok, connectors = self.get_connectors_and_proxies()
        if not ok or not connectors:
            return []

        extracted = []
        for c_entry in connectors:
            connector = c_entry.get("connector", {})
            c_name = connector.get("name", "Unknown")
            c_type = connector.get("type", "generic")
            if not connector.get("active", False):
                continue
            proxies = c_entry.get("proxies", [])

            for p in proxies:
                fingerprint = p.get("fingerprint", {})
                ip = fingerprint.get("ip") if fingerprint else None
                status = p.get("status", "UNKNOWN")
                key = p.get("key", "")

                # Keep the observed exit separate from its authenticated gateway.
                if ip and status == "STARTED" and not p.get("fingerprintError") and not p.get("removing"):
                    extracted.append({
                        "ip": ip,
                        "proxy": self.authenticated_proxy_url,
                        "proto": "http",
                        "provider_type": c_type,
                        "connector_name": c_name,
                        "status": status,
                        "key": key,
                        "source": f"Scrapoxy/{c_type}",
                    })
        return extracted

    def test_tunnel_rotation(self, rounds=5):
        """
        Sends requests through Scrapoxy's forward super-proxy endpoint
        to observe IP rotation across providers and measure latency.
        """
        results = []
        proxies = {
            "http": self.authenticated_proxy_url,
            "https": self.authenticated_proxy_url,
        }

        # Include proxy auth if specified in proxy URL or credentials
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ProxyHunter/ScrapoxyTest",
        }

        for i in range(rounds):
            t0 = time.time()
            try:
                r = self.session.get("https://api.ipify.org?format=json",
                                 proxies=proxies,
                                 headers=headers,
                                 timeout=self.timeout)
                lat = round(time.time() - t0, 3)
                if r.status_code == 200:
                    exit_ip = r.json().get("ip", "?")
                    scrapoxy_count = r.headers.get(SCRAPOXY_HEADERS["header_proxy_count"], "?")
                    results.append({
                        "round": i + 1,
                        "success": True,
                        "exit_ip": exit_ip,
                        "latency": lat,
                        "proxy_count": scrapoxy_count,
                    })
                else:
                    results.append({
                        "round": i + 1,
                        "success": False,
                        "error": f"HTTP {r.status_code}",
                        "latency": lat,
                    })
            except Exception as e:
                lat = round(time.time() - t0, 3)
                results.append({
                    "round": i + 1,
                    "success": False,
                    "error": str(e),
                    "latency": lat,
                })
            if i + 1 < rounds:
                time.sleep(0.5)

        return results

def refresh_scrapoxy_status(state):
    if not state.settings.get("scrapoxy_enabled"):
        state.scrapoxy = {"status": "DISABLED", "error": None, "proxy_count": 0}
        return state.scrapoxy
    client = ScrapoxyClient.from_settings(state.settings)
    ok, project = client.check_health()
    if not ok:
        status = "AUTH_REQUIRED" if project.get("http_status") in (401, 403) else "OFFLINE"
        state.scrapoxy = {"status": status, "error": project.get("error"), "proxy_count": 0}
        return state.scrapoxy
    proxies = client.extract_all_proxies()
    status = project["status"]
    error = client.last_error
    if error:
        status = "ERROR"
    elif not proxies and status == "HOT":
        status = "WARMING_UP"
        error = "Public lists are loading or have no reachable proxies yet."
    state.scrapoxy = {"status": status, "error": error, "proxy_count": len(proxies),
                      "project": project.get("name"), "project_status": project["status"]}
    return state.scrapoxy


def pull_scrapoxy_into_state(state, interactive=False):
    """
    Ingests all active proxy nodes from the configured Scrapoxy instance
    into the active ProxyHunter session state.
    """
    status = refresh_scrapoxy_status(state)
    if status["status"] != "HOT":
        print(f"  {cp(Y, '[!]')} Scrapoxy {status['status']}: {status.get('error') or 'No live pool available.'}")
        if interactive:
            safe_input(dim("  press enter ..."))
        return 0
    client = ScrapoxyClient.from_settings(state.settings)
    proxy_key = client.authenticated_proxy_url
    added = int(proxy_key not in state.raw_proxies)
    state.raw_proxies[proxy_key] = "http"
    state.scrapoxy_endpoints.add(proxy_key)
    print(f"  {cp(G, '[+]')} Scrapoxy forward proxy connected to {status['proxy_count']} live pool exits.")
    if interactive:
        safe_input(dim("  press enter to continue ..."))
    return added

def scrapoxy_menu(state):
    """Interactive TUI menu for Scrapoxy Aggregator management."""
    s = state.settings
    while True:
        clr(); print(BANNER)
        client = ScrapoxyClient(
            api_url=s["scrapoxy_url"],
            proxy_url=s["scrapoxy_proxy"],
            username=s["scrapoxy_user"],
            password=s["scrapoxy_pass"],
            timeout=s["timeout"],
        )

        print(f"{P}{B}  SCRAPOXY SUPER PROXY AGGREGATOR LAYER{RST}\n")
        print(f"  {dim('Current Target:')} {cp(C, client.api_url)}  {dim('| Proxy Port:')} {cp(C, client.proxy_url)}")
        print(f"  {dim('Credentials :')} {cp(C, client.username)}:****")
        print(f"\n  {P}{B}{'─' * 52}{RST}\n")
        print(f"  {cp(C, '[1]')} Test Connection & Connector Status {dim('(Rayobyte, Proxidize, Zyte, etc.)')}")
        print(f"  {cp(C, '[2]')} Toggle Project Status             {dim('(HOT / CALM / OFF)')}")
        print(f"  {cp(G, '[3]')} Ingest Connector Proxies into Hunt {dim('(Import active gateway)')}")
        print(f"  {cp(C, '[4]')} Test Super Proxy Tunnel Rotation    {dim('(Verify rotating exits)')}")
        print(f"  {cp(Y, '[5]')} Configure API URL / Proxy / Auth")
        print(f"\n  {dim('[0]')} Back to Main Menu\n")
        print(f"  {P}{B}{'─' * 52}{RST}\n")

        choice = safe_input(f"  {P}{B}>{RST} ").strip()
        if choice == "0":
            break

        elif choice == "1":
            print(f"\n  {cp(C, '[*]')} Probing Scrapoxy API ...")
            ok, info = client.check_health()
            if ok:
                print(f"  {cp(G, '[✓]')} Connection OK!")
                print(f"      Project Name: {cp(P, info.get('name', 'N/A'))}")
                print(f"      Project Status: {cp(G, info.get('status', 'N/A'))}")
                ok_c, conn_list = client.get_connectors_and_proxies()
                if ok_c:
                    print(f"\n  {P}{B}  Active Connectors ({len(conn_list)}):{RST}")
                    for c_entry in conn_list:
                        conn = c_entry.get("connector", {})
                        proxies = c_entry.get("proxies", [])
                        c_type = conn.get("type", "unknown")
                        c_name = conn.get("name", "unnamed")
                        is_active = conn.get("active", False)
                        status_col = G if is_active else R
                        print(f"    • {cp(C, c_name)} [{c_type}] - {cp(status_col, 'ACTIVE' if is_active else 'DISABLED')} ({len(proxies)} proxies)")
            else:
                print(f"  {cp(R, '[!]')} Connection failed: {info.get('error')}")
            safe_input(dim("\n  press enter to continue ..."))

        elif choice == "2":
            new_st = safe_input("\n  Enter new status (HOT / CALM / OFF): ").strip().upper()
            if new_st in ("HOT", "CALM", "OFF"):
                ok, msg = client.set_project_status(new_st)
                col = G if ok else R
                print(f"  {cp(col, msg)}")
            else:
                print(f"  {cp(R, '[!]')} Invalid choice. Use HOT, CALM, or OFF.")
            safe_input(dim("  press enter ..."))

        elif choice == "3":
            pull_scrapoxy_into_state(state, interactive=True)

        elif choice == "4":
            print(f"\n  {cp(C, '[*]')} Testing rotation via Scrapoxy proxy tunnel ({client.proxy_url}) ...")
            results = client.test_tunnel_rotation(rounds=5)
            print(f"\n  {P}{B}  Rotation Test Results:{RST}")
            for r in results:
                if r.get("success"):
                    print(f"    Round {r['round']}: Exit IP = {cp(G, r['exit_ip'])} | Latency = {cp(C, str(r['latency']) + 's')} | Pool Count = {r.get('proxy_count')}")
                else:
                    print(f"    Round {r['round']}: {cp(R, 'FAILED')} - {r.get('error')}")
            safe_input(dim("\n  press enter to continue ..."))

        elif choice == "5":
            print("\n  Configure Scrapoxy Settings:")
            new_url = safe_input(f"  API URL [{s['scrapoxy_url']}]: ").strip()
            if new_url: s["scrapoxy_url"] = new_url
            new_proxy = safe_input(f"  Proxy URL [{s['scrapoxy_proxy']}]: ").strip()
            if new_proxy: s["scrapoxy_proxy"] = new_proxy
            new_user = safe_input(f"  Username [{s['scrapoxy_user']}]: ").strip()
            if new_user: s["scrapoxy_user"] = new_user
            new_pass = safe_input(f"  Password [****]: ").strip()
            if new_pass: s["scrapoxy_pass"] = new_pass
            print(f"  {cp(G, '[✓]')} Settings updated.")
            safe_input(dim("  press enter ..."))
