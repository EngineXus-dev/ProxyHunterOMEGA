"""Regression checks for default startup, gateway routing, and truthful API errors."""
import ipaddress
import base64
import os
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import MagicMock, Mock, patch

import requests

from state import State
from scrapoxy_aggregator import ScrapoxyClient, pull_scrapoxy_into_state, refresh_scrapoxy_status
from validator import build_proxy_dict, port_open, validate_one


_history_test_environment = patch.dict("os.environ", {"PROXYHUNTER_HISTORY_ENABLED": "false"})


def setUpModule():
    _history_test_environment.start()


def tearDownModule():
    _history_test_environment.stop()


class ScrapoxyTests(unittest.TestCase):
    def setUp(self):
        self.state = State()
        self.state.settings["scrapoxy_enabled"] = True

    def test_disabled_by_default_and_can_opt_in(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(State().settings["scrapoxy_enabled"])
        with patch.dict(os.environ, {"SCRAPOXY_ENABLED": "true"}):
            self.assertTrue(State().settings["scrapoxy_enabled"])

    def test_custom_credentials_disable_local_provisioning(self):
        with patch.dict(os.environ, {"SCRAPOXY_USERNAME": "existing-project"}):
            self.assertFalse(State().settings["scrapoxy_autostart"])

    def test_disabled_does_not_query_service(self):
        self.state.settings["scrapoxy_enabled"] = False
        with patch.object(ScrapoxyClient, "from_settings") as factory:
            self.assertEqual(refresh_scrapoxy_status(self.state)["status"], "DISABLED")
            factory.assert_not_called()

    def test_wrong_project_credentials_are_reported(self):
        client = ScrapoxyClient(username="wrong", password="wrong")
        client.session = Mock()
        client.session.get.return_value = Mock(status_code=403)
        with patch.object(ScrapoxyClient, "from_settings", return_value=client):
            status = refresh_scrapoxy_status(self.state)
        self.assertEqual(status["status"], "AUTH_REQUIRED")
        self.assertIn("Project credentials", status["error"])

    def test_inventory_uses_gateway_and_only_live_active_exits(self):
        client = ScrapoxyClient(username="user", password="p@ss:word")
        live = {"status": "STARTED", "fingerprint": {"ip": "203.0.113.9"}}
        stopped = {"status": "STOPPED", "fingerprint": {"ip": "203.0.113.10"}}
        inventory = [
            {"connector": {"active": True, "type": "freeproxies"}, "proxies": [live, stopped]},
            {"connector": {"active": False}, "proxies": [live]},
        ]
        with patch.object(client, "get_connectors_and_proxies", return_value=(True, inventory)):
            nodes = client.extract_all_proxies()
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0]["proxy"], "http://user:p%40ss%3Aword@127.0.0.1:8888")
        self.assertNotIn("203.0.113.9:80", nodes[0]["proxy"])

    def test_pool_sync_deduplicates_gateway_and_never_prompts(self):
        client = ScrapoxyClient(username="project", password="secret")
        client.check_health = Mock(return_value=(True, {"name": "test", "status": "HOT"}))
        client.extract_all_proxies = Mock(return_value=[{"ip": "203.0.113.1"}, {"ip": "203.0.113.2"}])
        with patch.object(ScrapoxyClient, "from_settings", return_value=client), \
                patch("scrapoxy_aggregator.safe_input", side_effect=AssertionError("unexpected input")):
            self.assertEqual(pull_scrapoxy_into_state(self.state), 1)
            self.assertEqual(pull_scrapoxy_into_state(self.state), 0)
        self.assertEqual(self.state.scrapoxy["proxy_count"], 2)
        self.assertEqual(len(self.state.raw_proxies), 1)
        self.assertIn(client.authenticated_proxy_url, self.state.scrapoxy_endpoints)

    def test_unavailable_sync_never_waits_for_input(self):
        client = Mock()
        client.check_health.return_value = (False, {"error": "connection refused"})
        with patch.object(ScrapoxyClient, "from_settings", return_value=client), \
                patch("scrapoxy_aggregator.safe_input", side_effect=AssertionError("unexpected input")):
            self.assertEqual(pull_scrapoxy_into_state(self.state), 0)
        self.assertEqual(self.state.scrapoxy["status"], "OFFLINE")

    def test_authenticated_gateway_is_preserved_and_tcp_targets_host(self):
        endpoint = "http://user:secret@127.0.0.1:8888"
        self.assertEqual(build_proxy_dict(endpoint, "http")["https"], endpoint)
        with patch("validator.socket.create_connection") as connect:
            self.assertTrue(port_open(endpoint))
            connect.assert_called_once_with(("127.0.0.1", 8888), timeout=1.5)

    def test_gateway_validation_records_observed_exit(self):
        response = Mock(status_code=200)
        response.json.return_value = {"ip": "203.0.113.10"}
        with patch("validator.requests.get", return_value=response):
            result = validate_one("http://user:secret@127.0.0.1:8888", "http", 5, aggregated=True)
        self.assertEqual(result["exit_ip"], "203.0.113.10")
        self.assertTrue(result["rotating"])

    def test_gateway_survives_cidr_and_profiles_observed_exit(self):
        from filters import run_cidr_filter
        from profiler import run_profile
        endpoint = "http://user:secret@127.0.0.1:8888"
        self.state.raw_proxies[endpoint] = "http"
        self.state.scrapoxy_endpoints.add(endpoint)
        self.state.dc_networks = [ipaddress.ip_network("127.0.0.0/8")]
        run_cidr_filter(self.state, interactive=False)
        self.assertIn(endpoint, self.state.filtered)
        self.state.valid = [{"proxy": endpoint, "proto": "http", "latency": 0.5, "exit_ip": "203.0.113.10"}]
        response = Mock(status_code=200)
        response.json.return_value = [{"status": "success", "isp": "Test ISP"}]
        with patch("profiler.requests.post", return_value=response) as query:
            run_profile(self.state, deep_mode=False, interactive=False)
        self.assertEqual(query.call_args.kwargs["json"][0]["query"], "203.0.113.10")
        self.assertEqual(self.state.profiled[0]["isp"], "Test ISP")

    def test_automated_launcher_preserves_default_scrapoxy_enablement(self):
        import run_optimal
        with patch("sys.argv", ["run_optimal.py", "--auto"]), \
                patch.object(run_optimal, "run_optimal_automated_pipeline") as run:
            run_optimal.main()
        self.assertIsNone(run.call_args.kwargs["use_scrapoxy"])
        with patch("sys.argv", ["run_optimal.py", "--auto", "--no-scrapoxy"]), \
                patch.object(run_optimal, "run_optimal_automated_pipeline") as run:
            run_optimal.main()
        self.assertFalse(run.call_args.kwargs["use_scrapoxy"])

    def test_reopening_reuses_existing_project_and_wrapped_connector(self):
        import scrapoxy_runtime
        session = MagicMock()
        project = {"id": "project-id", "name": "ProxyHunter", "status": "HOT"}
        connector = {"id": "connector-id", "name": "ProxyHunter Public Lists", "active": True}
        token = base64.b64encode(b"test-user:test-password").decode()
        existing_sources = [{"id": str(i), "url": url} for i, (url, proto, tier) in
                            enumerate(__import__("constants").SOURCES_GITHUB)
                            if proto == "http" and tier == 1 and any(p in url for p in
                                ("/monosans/", "/elliottophellia/", "/vakhov/"))]

        def respond(method, url, **kwargs):
            if url.endswith("/users/auths/local") or url.endswith("/default"):
                return Mock(content=b"", raise_for_status=Mock())
            if url.endswith("/projects"):
                value = [project]
            elif url.endswith("/token"):
                value = {"token": token}
            elif url.endswith("/connectors"):
                value = [{"connector": connector, "proxies": []}]
            elif url.endswith("/sourcesfreeproxies"):
                value = {"sources": existing_sources}
            else:
                self.fail(f"Unexpected resource mutation or request: {method} {url}")
            return Mock(content=b"{}", json=Mock(return_value=value), raise_for_status=Mock())

        session.request.side_effect = respond
        context = MagicMock()
        context.__enter__.return_value = session
        with patch("scrapoxy_runtime.requests.Session", return_value=context), \
                patch("scrapoxy_runtime.PROJECT_FILE"):
            scrapoxy_runtime.provision_project(self.state.settings,
                {"AUTH_LOCAL_USERNAME": "admin", "AUTH_LOCAL_PASSWORD": "dashboard-password"})
        self.assertEqual(self.state.settings["scrapoxy_user"], "test-user")
        self.assertEqual(self.state.settings["scrapoxy_pass"], "test-password")


if __name__ == "__main__":
    unittest.main()
