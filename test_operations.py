"""Regression tests for unattended runs, durable checkpoints and real cancellation."""
import base64
from contextlib import redirect_stdout
import io
import ipaddress
import json
import os
from pathlib import Path
import shutil
import signal
import threading
import time
import unittest
from unittest.mock import Mock, patch
import uuid

from state import State
from run_control import operation, bounded_results, request_cancel
from scan_history import ScanHistory, endpoint_key, protocol_key, select_unseen
from validator import run_port_filter, run_validate, validate_one
from filters import NetworkIndex
from pipeline import execute_pipeline, apply_resource_profile, export_results
from vpngate_client import parse_directory, sanitize_profile, harvest_vpngate, gateway_exit


class OperationTests(unittest.TestCase):
    def setUp(self):
        self.parent = Path(__file__).resolve().parent / ".cache" / "operation-tests"
        self.directory = self.parent / uuid.uuid4().hex
        self.directory.mkdir(parents=True)
        self.environment = patch.dict(os.environ, {"PROXYHUNTER_DATA_DIR": str(self.directory), "PROXYHUNTER_HISTORY_ENABLED": "true"})
        self.environment.start()
        self.state = State()
        self.state.settings.update(port_threads=2, threads=2, quiet_progress=True,
                                   scrapoxy_enabled=False, vpngate_enabled=False, recheck=False)
        self.capture = redirect_stdout(io.StringIO())
        self.capture.__enter__()

    def tearDown(self):
        self.capture.__exit__(None, None, None)
        self.environment.stop()
        self.assertTrue(self.directory.resolve().is_relative_to(self.parent.resolve()))
        shutil.rmtree(self.directory)

    def test_large_queue_cancellation_starts_only_a_bounded_number_of_tasks(self):
        started = []
        def worker(value):
            started.append(value)
            time.sleep(0.02)
            return value
        beginning = time.monotonic()
        for _, _ in bounded_results(self.state, worker, range(150000), 2):
            self.state.control.cancel()
        self.assertLessEqual(len(started), 4)
        self.assertLess(time.monotonic() - beginning, 1)

    def test_keyboard_interrupt_cancels_instead_of_draining_the_queue(self):
        def worker(_):
            raise KeyboardInterrupt()
        self.assertEqual(list(bounded_results(self.state, worker, range(150000), 1)), [])
        self.assertTrue(self.state.control.is_cancelled())

    def test_other_terminal_can_request_cancellation(self):
        with operation(self.state):
            self.assertEqual(request_cancel(os.getpid()), 1)
            self.assertTrue(self.state.control.is_cancelled())
        self.assertEqual(list((self.directory / "runs").glob("*.json")), [])

    def test_ctrl_c_signal_sets_cancel_and_restores_the_previous_handler(self):
        previous = signal.getsignal(signal.SIGINT)
        with operation(self.state):
            signal.raise_signal(signal.SIGINT)
            self.assertTrue(self.state.control.is_cancelled())
        self.assertEqual(signal.getsignal(signal.SIGINT), previous)

    def test_completed_port_check_is_reused_after_restart(self):
        self.state.raw_proxies = {"8.8.8.8:8080": "http"}
        with patch("validator.port_open", return_value=True) as probe:
            run_port_filter(self.state, interactive=False)
        self.assertEqual(probe.call_count, 1)
        resumed = State()
        resumed.settings['recheck'] = False  # explicit opt-in resume behavior
        resumed.raw_proxies = dict(self.state.raw_proxies)
        with patch("validator.port_open", side_effect=AssertionError("rescan")):
            run_port_filter(resumed, interactive=False)
        self.assertEqual(resumed.history_stats["port_reused"], 1)
        self.assertIn("8.8.8.8:8080", resumed.filtered)

    def test_cancelled_work_does_not_mark_all_remaining_ports_closed(self):
        self.state.raw_proxies = {f"8.8.8.{index}:8080": "http" for index in range(1, 50)}
        def probe(*_):
            time.sleep(0.02)
            return True
        with patch("validator.port_open", side_effect=probe):
            run_port_filter(self.state, interactive=False,
                            progress_callback=lambda *_: self.state.control.cancel())
        with ScanHistory(self.state.settings) as history:
            saved = history.recent("port")
        self.assertGreater(len(saved), 0)
        self.assertLessEqual(len(saved), 4)

    def test_failed_ports_are_skipped_on_the_next_run(self):
        with ScanHistory(self.state.settings) as history:
            history.record("port", endpoint_key("8.8.8.8:80"), False)
        self.state.raw_proxies = {"8.8.8.8:80": "http", "1.1.1.1:80": "http"}
        self.assertEqual(select_unseen(self.state), 1)
        self.assertEqual(list(self.state.raw_proxies), ["1.1.1.1:80"])

    def test_expired_history_is_eligible_again(self):
        with ScanHistory(self.state.settings) as history:
            history.record("port", endpoint_key("8.8.8.8:80"), False, checked_at=time.time() - 90000)
        self.state.raw_proxies = {"8.8.8.8:80": "http"}
        self.assertEqual(select_unseen(self.state), 0)

    def test_alternate_history_scope_does_not_suppress_local_network_checks(self):
        self.state.settings["history_scope"] = "alternate-test-scope"
        with ScanHistory(self.state.settings) as history:
            history.record("port", endpoint_key("8.8.8.8:80"), False)
        local = State()
        local.raw_proxies = {"8.8.8.8:80": "http"}
        self.assertEqual(select_unseen(local), 0)
        self.state.raw_proxies = dict(local.raw_proxies)
        self.assertEqual(select_unseen(self.state), 1)

    def test_recheck_explicitly_bypasses_history(self):
        with ScanHistory(self.state.settings) as history:
            history.record("port", endpoint_key("8.8.8.8:80"), False)
        self.state.settings["recheck"] = True
        self.state.raw_proxies = {"8.8.8.8:80": "http"}
        self.assertEqual(select_unseen(self.state), 0)

    def test_new_protocol_is_not_suppressed_by_an_old_protocol_result(self):
        with ScanHistory(self.state.settings) as history:
            history.record("profile", protocol_key("8.8.8.8:80", "http"), True, {"proxy": "8.8.8.8:80"})
        self.state.raw_proxies = {"8.8.8.8:80": "http"}
        self.state.proxy_protocols = {"8.8.8.8:80": {"http", "socks5"}}
        self.assertEqual(select_unseen(self.state), 0)

    def test_http_and_socks_validation_checkpoints_are_separate(self):
        endpoint = "8.8.8.8:1080"
        self.state.raw_proxies = {endpoint: "http"}
        self.state.proxy_protocols = {endpoint: {"http", "socks5"}}
        valid = {"proxy": endpoint, "proto": "socks5", "exit_ip": "1.1.1.1", "latency": 1}
        with patch("validator.validate_one", side_effect=[None, valid]):
            run_validate(self.state, interactive=False)
        resumed = State()
        resumed.settings['recheck'] = False  # explicit opt-in resume behavior
        resumed.raw_proxies = dict(self.state.raw_proxies)
        resumed.proxy_protocols = dict(self.state.proxy_protocols)
        with patch("validator.validate_one", side_effect=AssertionError("rescan")):
            run_validate(resumed, interactive=False)
        self.assertEqual(resumed.valid[0]["proto"], "socks5")
        self.assertEqual(resumed.history_stats["validation_reused"], 1)

    def test_cancelled_http_attempt_is_not_cached_as_a_failure(self):
        self.state.raw_proxies = {"8.8.8.8:80": "http"}
        def check(*_, **__):
            self.state.control.cancel()
            return None
        with patch("validator.validate_one", side_effect=check):
            run_validate(self.state, interactive=False)
        with ScanHistory(self.state.settings) as history:
            self.assertEqual(history.recent("validation"), {})

    def test_cancellation_stops_http_fallback_attempts(self):
        def reply(*_, **__):
            self.state.control.cancel()
            return Mock(status_code=503)
        with patch("validator.requests.get", side_effect=reply) as get:
            validate_one("8.8.8.8:80", "http", 1, cancelled=self.state.control.is_cancelled)
        self.assertEqual(get.call_count, 1)

    def test_all_five_stages_run_without_input(self):
        def filtered(state, **_):
            state.filtered = dict(state.raw_proxies)
            state.filtered_ready = True
        def validated(state, **_):
            state.valid = [{"proxy": "8.8.8.8:80", "proto": "http", "exit_ip": "1.1.1.1", "latency": 1}]
        def profiled(state, **_):
            state.profiled = [dict(state.valid[0], threat_tag="CLEAN_RESIDENTIAL")]
        with patch("builtins.input", side_effect=AssertionError("stage prompt")), \
                patch("pipeline.scrape_github_api", return_value=({"8.8.8.8:80": "http"}, 1)), \
                patch("pipeline.scrape_telegram", return_value=({}, 0)), patch("pipeline.scrape_html", return_value=({}, 0)), \
                patch("pipeline.select_unseen"), patch("pipeline.run_cidr_filter", side_effect=filtered), \
                patch("pipeline.run_port_filter", side_effect=filtered), patch("pipeline.run_validate", side_effect=validated), \
                patch("pipeline.run_profile", side_effect=profiled):
            execute_pipeline(self.state, output_dir=self.directory / "results")
        self.assertEqual(self.state.pipeline_result, "completed")
        self.assertTrue((self.directory / "results" / "clean_residential_verified.txt").exists())

    def test_cancel_after_ports_prevents_validation_and_preserves_report(self):
        def filtered(state, **_):
            state.filtered, state.filtered_ready = dict(state.raw_proxies), True
        def cancel(state, **_):
            state.control.cancel("test cancel")
        with patch("pipeline.scrape_github_api", return_value=({"8.8.8.8:80": "http"}, 1)), \
                patch("pipeline.scrape_telegram", return_value=({}, 0)), patch("pipeline.scrape_html", return_value=({}, 0)), \
                patch("pipeline.select_unseen"), patch("pipeline.run_cidr_filter", side_effect=filtered), \
                patch("pipeline.run_port_filter", side_effect=cancel), patch("pipeline.run_validate") as validate:
            execute_pipeline(self.state)
        validate.assert_not_called()
        self.assertEqual(self.state.pipeline_result, "cancelled")
        self.assertTrue(json.loads((self.directory / "latest_hunt.json").read_text())["cancelled"])

    def test_notebook_style_interrupt_during_harvest_saves_cancelled_status(self):
        with patch("pipeline.scrape_github_api", side_effect=KeyboardInterrupt()):
            execute_pipeline(self.state)
        self.assertEqual(self.state.pipeline_result, "cancelled")
        self.assertTrue(json.loads((self.directory / "latest_hunt.json").read_text())["cancelled"])

    def test_completed_export_removes_stale_entries(self):
        output = self.directory / "results"
        output.mkdir()
        saved = output / "clean_residential_verified.txt"
        saved.write_text("8.8.8.8:80\n", encoding="utf-8")
        os.utime(saved, (1600000000, 1600000000))
        export_results(self.state, output)
        self.assertEqual(saved.read_text(), "")

    def test_cancelled_profile_does_not_overwrite_completed_results(self):
        def filtered(state, **_):
            state.filtered, state.filtered_ready = dict(state.raw_proxies), True
        def validated(state, **_):
            state.valid = [{"proxy": "8.8.8.8:80", "proto": "http", "exit_ip": "1.1.1.1"}]
        def partial_profile(state, **_):
            state.profiled = [dict(state.valid[0], threat_tag="CLEAN_RESIDENTIAL")]
            state.control.cancel()
        output = self.directory / "results"
        with patch("pipeline.scrape_github_api", return_value=({"8.8.8.8:80": "http"}, 1)), \
                patch("pipeline.scrape_telegram", return_value=({}, 0)), patch("pipeline.scrape_html", return_value=({}, 0)), \
                patch("pipeline.select_unseen"), patch("pipeline.run_cidr_filter", side_effect=filtered), \
                patch("pipeline.run_port_filter", side_effect=filtered), patch("pipeline.run_validate", side_effect=validated), \
                patch("pipeline.run_profile", side_effect=partial_profile):
            execute_pipeline(self.state, output_dir=output)
        self.assertEqual(self.state.pipeline_result, "cancelled")
        self.assertFalse((output / "clean_residential_verified.txt").exists())
        self.assertTrue((self.directory / "interrupted_results.json").exists())

    def test_new_run_does_not_report_previous_run_results(self):
        self.state.valid = [{"proxy": "8.8.8.8:80"}]
        self.state.profiled = [{"proxy": "8.8.8.8:80", "threat_tag": "CLEAN_RESIDENTIAL"}]
        self.state.vpngate_endpoints.add("127.0.0.1:1088")
        with patch("pipeline.scrape_github_api", return_value=({}, 0)), \
                patch("pipeline.scrape_telegram", return_value=({}, 0)), patch("pipeline.scrape_html", return_value=({}, 0)), \
                patch("pipeline.select_unseen"):
            execute_pipeline(self.state)
        self.assertEqual(self.state.valid, [])
        self.assertEqual(self.state.profiled, [])
        self.assertEqual(self.state.vpngate_endpoints, set())

    def test_laptop_profile_has_no_forced_three_hundred_thread_override(self):
        apply_resource_profile(self.state, "laptop")
        self.assertEqual(self.state.settings["port_threads"], 32)
        self.assertEqual(self.state.settings["threads"], 12)

    def test_indexed_cidr_matches_reference_membership(self):
        networks = [ipaddress.ip_network(value) for value in ("8.8.0.0/16", "8.8.8.0/24", "1.1.1.0/24", "2001:db8::/32")]
        index = NetworkIndex(networks)
        for value in ("8.8.8.8", "8.9.0.1", "1.1.1.1", "1.0.0.1", "2001:db8::7", "2606:4700::1"):
            address = ipaddress.ip_address(value)
            self.assertEqual(index.contains(address), any(address in net for net in networks))

    def test_geo_rate_limit_wait_can_be_cancelled(self):
        from profiler import GeoBatchClient
        client = GeoBatchClient(clock=lambda: 0, post=Mock(side_effect=AssertionError("network after cancel")))
        client.ready_at = 60
        self.state.control.cancel()
        self.assertEqual(client.lookup([{}], cancelled=self.state.control.is_cancelled, waiter=self.state.control.wait), [{}])

    def profile_csv(self):
        config = "client\ndev tun\nproto tcp\nremote 8.8.8.8 443\n<ca>\nTEST\n</ca>\n"
        return "*vpn_servers\n#HostName,IP,Score,Speed,CountryLong,OpenVPN_ConfigData_Base64\nexample,8.8.8.8,10,20,Test," + base64.b64encode(config.encode()).decode() + "\n*\n"

    def test_vpngate_directory_decodes_real_profile_fields(self):
        profiles = parse_directory(self.profile_csv())
        self.assertEqual(len(profiles), 1)
        self.assertEqual(profiles[0]["port"], 443)
        self.assertIn("redirect-gateway def1", profiles[0]["config"])

    def test_vpngate_verification_uses_another_service_after_a_timeout(self):
        import requests
        response = requests.Response()
        response.status_code = 200
        response._content = b"1.1.1.1\n"
        client = Mock()
        client.get.side_effect = [requests.Timeout("echo service timeout"), response]
        with patch("vpngate_client.requests.Session") as session:
            session.return_value.__enter__.return_value = client
            self.assertEqual(gateway_exit(1088), "1.1.1.1")
        self.assertEqual(client.get.call_count, 2)

    def test_vpngate_rejects_mismatched_remote_addresses(self):
        with self.assertRaises(ValueError):
            sanitize_profile("remote 1.1.1.1 443\n<ca>\nTEST\n</ca>", "8.8.8.8")

    def test_vpngate_profiles_cannot_inject_local_scripts(self):
        config = parse_directory(self.profile_csv())[0]["config"] + "up /bin/evil\nplugin /tmp/evil.so\nscript-security 3\n"
        safe, *_ = sanitize_profile(config, "8.8.8.8")
        self.assertNotIn("evil", safe)
        self.assertNotIn("script-security", safe)

    def test_vpngate_reports_profiles_when_host_cannot_connect_tunnels(self):
        profiles = parse_directory(self.profile_csv())
        with patch("vpngate_client.discover", return_value=profiles), patch("vpngate_client.shutil.which", return_value=None):
            routes, count = harvest_vpngate(self.state)
        self.assertEqual(count, 0)
        self.assertEqual(routes, {})
        self.assertEqual(self.state.vpngate["profiles"], 1)
        self.assertEqual(self.state.vpngate["status"], "PROFILES_READY")
        self.assertTrue((self.directory / "vpngate" / "profiles.json").exists())


if __name__ == "__main__":
    unittest.main()
