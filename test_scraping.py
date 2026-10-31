import json
import io
from contextlib import redirect_stdout
from pathlib import Path
import uuid
import time
import unittest
from unittest.mock import MagicMock, Mock, patch, mock_open

import requests

from source_engine import SourceFetcher, extract_proxies, parse_payload
from state import State
from scraper import _harvest, begin_scrape, scrape_vpngate
from validator import run_validate, validate_one, build_proxy_dict


def response(status=200, text="8.8.8.8:8080", headers=None):
    return Mock(status_code=status, text=text, headers=headers or {})


_history_test_environment = patch.dict("os.environ", {"PROXYHUNTER_HISTORY_ENABLED": "false"})


def setUpModule():
    _history_test_environment.start()


def tearDownModule():
    _history_test_environment.stop()


class ParsingTests(unittest.TestCase):
    def test_mixed_protocols_do_not_become_http(self):
        entries = extract_proxies("socks5://8.8.8.8:1080\nhttp://8.8.8.8:1080\nhttps://1.1.1.1:443")
        self.assertEqual(set(entries), {("8.8.8.8:1080", "socks5"), ("8.8.8.8:1080", "http"), ("1.1.1.1:443", "https")})

    def test_single_digit_port_and_ipv6(self):
        self.assertIn(("8.8.8.8:9", "http"), extract_proxies("8.8.8.8:9"))
        self.assertIn(("[2606:4700:4700::1111]:1080", "socks5"), extract_proxies("socks5://[2606:4700:4700::1111]:1080"))

    def test_invalid_private_and_out_of_range_addresses_are_discarded(self):
        self.assertEqual(extract_proxies("999.8.8.8:80 127.0.0.1:80 10.0.0.1:8080 8.8.8.8:99999"), [])

    def test_structured_json_separate_fields_and_multiple_protocols(self):
        payload = {"data": [{"ip": "8.8.8.8", "port": "1080", "protocols": ["socks4", "socks5"]}]}
        entries, _ = parse_payload(json.dumps(payload))
        self.assertEqual(set(entries), {("8.8.8.8:1080", "socks4"), ("8.8.8.8:1080", "socks5")})

    def test_nested_html_table_cells(self):
        entries, _ = parse_payload('<table><tr><td><span>8.8.8.8</span></td><td>8080</td></tr></table>', kind="html")
        self.assertEqual(entries, [("8.8.8.8:8080", "http")])

    def test_published_telegram_socks_links_preserve_protocol_and_auth(self):
        entries = extract_proxies('tg://socks?server=8.8.8.8&amp;port=1080&amp;user=a&amp;pass=b%40c')
        self.assertEqual(entries, [("socks5://a:b%40c@8.8.8.8:1080", "socks5")])

    def test_mtproto_is_not_mislabelled_as_http(self):
        self.assertEqual(extract_proxies('tg://proxy?server=8.8.8.8&port=443&secret=abc'), [])

    def test_shadowsocks_and_vless_endpoints_are_not_http_candidates(self):
        entries, metadata = parse_payload('ss://encoded@8.8.8.8:443#label vless://id@1.1.1.1:443?security=tls')
        self.assertEqual(entries, [])
        self.assertEqual(metadata["other_transports"], ["ss", "vless"])

    def test_plain_endpoints_still_work_beside_other_transports(self):
        entries = extract_proxies('ss://encoded@8.8.8.8:443#label\nsocks5://1.1.1.1:1080\n9.9.9.9:8080')
        self.assertEqual(set(entries), {("1.1.1.1:1080", "socks5"), ("9.9.9.9:8080", "http")})

    def test_telegram_cursor_is_available_for_bounded_pagination(self):
        _, metadata = parse_payload('<div data-post="channel/123"></div><div data-post="channel/121"></div>', kind="telegram")
        self.assertEqual(metadata["cursor"], 121)


class FetchTests(unittest.TestCase):
    def setUp(self):
        self.test_root = (Path(__file__).resolve().parent / ".cache" / "test-runs").resolve()
        self.test_root.mkdir(parents=True, exist_ok=True)
        self.directory = self.test_root / ("source-tests-" + uuid.uuid4().hex)
        self.directory.mkdir()
        self.session = MagicMock()
        context = MagicMock()
        context.__enter__.return_value = self.session
        self.context = context
        self.factory = Mock(return_value=context)
        self.fetcher = SourceFetcher({"scrape_retries": 1}, self.directory, self.factory)
        self.sleep = patch("source_engine.time.sleep")
        self.sleep.start()
        self.url = "https://example.org/public-proxies.txt"

    def tearDown(self):
        self.sleep.stop()
        self.assertTrue(Path(self.directory).resolve().is_relative_to(self.test_root))
        for path in self.directory.iterdir():
            path.unlink()
        self.directory.rmdir()

    def seed(self):
        self.session.get.side_effect = None
        self.session.get.return_value = response(headers={"ETag": '"first"'})
        result = self.fetcher.fetch(self.url)
        self.assertEqual(result["status"], "OK")

    def test_304_preserves_cached_candidates(self):
        self.seed()
        self.session.get.return_value = response(304, "")
        result = self.fetcher.fetch(self.url)
        self.assertEqual(result["entries"], [("8.8.8.8:8080", "http")])
        self.assertEqual(result["cache"], "revalidated")
        self.assertEqual(self.session.get.call_args.kwargs["headers"]["If-None-Match"], '"first"')

    def test_transient_failure_uses_labelled_last_good_cache(self):
        self.seed()
        self.session.get.side_effect = requests.Timeout()
        result = self.fetcher.fetch(self.url)
        self.assertEqual(result["status"], "STALE_CACHE")
        self.assertEqual(result["error"], "Timeout")
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["attempts"], 2)

    def test_failure_without_cache_is_not_reported_as_empty(self):
        self.session.get.side_effect = requests.ConnectionError()
        result = self.fetcher.fetch(self.url)
        self.assertEqual(result["status"], "NETWORK_ERROR")
        self.assertEqual(result["count"], 0)

    def test_404_is_not_retried_or_hidden_by_cached_results(self):
        self.seed()
        self.session.get.return_value = response(404, "not found")
        result = self.fetcher.fetch(self.url)
        self.assertEqual(result["status"], "NOT_FOUND")
        self.assertEqual(result["attempts"], 1)
        self.assertEqual(result["count"], 0)

    def test_empty_page_does_not_destroy_last_good_cache(self):
        self.seed()
        self.session.get.return_value = response(200, "no proxies published")
        result = self.fetcher.fetch(self.url)
        self.assertEqual(result["status"], "EMPTY")
        self.session.get.side_effect = requests.Timeout()
        self.assertEqual(self.fetcher.fetch(self.url)["count"], 1)

    def test_expired_cache_is_not_used_for_failure(self):
        self.seed()
        path = next(Path(self.directory).glob("*.json"))
        saved = json.loads(path.read_text())
        saved["fetched_at"] = time.time() - 90000
        path.write_text(json.dumps(saved))
        self.session.get.side_effect = requests.Timeout()
        result = self.fetcher.fetch(self.url)
        self.assertEqual(result["status"], "TIMEOUT")
        self.assertEqual(result["count"], 0)

    def test_429_with_long_retry_after_is_respected(self):
        self.session.get.return_value = response(429, "", {"Retry-After": "120"})
        result = self.fetcher.fetch(self.url)
        self.assertEqual(result["status"], "RATE_LIMITED")
        self.assertEqual(result["attempts"], 1)

    def test_retry_can_recover_a_temporary_server_error(self):
        self.session.get.side_effect = [response(503, ""), response()]
        result = self.fetcher.fetch(self.url)
        self.assertEqual(result["status"], "OK")
        self.assertEqual(result["attempts"], 2)

    def test_revalidation_after_retry_clears_the_previous_http_error(self):
        self.seed()
        self.session.get.side_effect = [response(503, ""), response(304, "")]
        result = self.fetcher.fetch(self.url)
        self.assertEqual(result["status"], "NOT_MODIFIED")
        self.assertIsNone(result["error"])

    def test_corrupted_cache_does_not_break_a_live_fetch(self):
        self.seed()
        next(Path(self.directory).glob("*.json")).write_text("broken json")
        self.assertEqual(self.fetcher.fetch(self.url)["status"], "OK")

    def test_access_challenge_is_not_reported_as_empty(self):
        self.session.get.return_value = response(200, "<html>Verify you are human: captcha</html>")
        self.assertEqual(self.fetcher.fetch(self.url)["status"], "BLOCKED")

    def test_gist_index_with_no_links_is_explicitly_empty(self):
        self.session.get.return_value = response(200, "<html>No search results</html>")
        self.assertEqual(self.fetcher.fetch(self.url, kind="gist_index")["status"], "EMPTY")

    def test_each_fetch_owns_its_session_and_closes_it(self):
        self.session.get.return_value = response()
        self.fetcher.fetch(self.url)
        self.fetcher.fetch(self.url)
        self.assertEqual(self.factory.call_count, 2)
        self.assertEqual(self.context.__exit__.call_count, 2)

    def test_empty_telegram_page_can_still_advance_to_older_posts(self):
        self.session.get.return_value = response(200, '<div data-post="public/42">no endpoints here</div>')
        result = self.fetcher.fetch(self.url, kind="telegram")
        self.assertEqual(result["status"], "EMPTY")
        self.assertEqual(result["metadata"]["cursor"], 42)

    def test_telegram_user_or_private_channel_page_is_not_an_empty_feed(self):
        self.session.get.return_value = response(200, '<html>Send Message</html>')
        result = self.fetcher.fetch(self.url, kind="telegram")
        self.assertEqual(result["status"], "NO_PUBLIC_POSTS")

    def test_other_transports_have_an_explanatory_status(self):
        self.session.get.return_value = response(200, 'ss://encoded@8.8.8.8:443#label')
        self.assertEqual(self.fetcher.fetch(self.url)["status"], "OTHER_TRANSPORTS")


class GeoLookupTests(unittest.TestCase):
    def client(self, responses):
        from profiler import GeoBatchClient
        ticks = [0.0]
        waits = []

        def sleep(delay):
            waits.append(delay)
            ticks[0] += delay

        post = Mock(side_effect=responses)
        client = GeoBatchClient(clock=lambda: ticks[0], sleep=sleep, post=post)
        return client, waits, post

    def test_batch_requests_are_paced_below_fifteen_per_minute(self):
        good = response(headers={"X-Rl": "14", "X-Ttl": "59"})
        good.json.return_value = [{"status": "success"}]
        client, waits, _ = self.client([good, good])
        client.lookup([{"query": "8.8.8.8"}])
        client.lookup([{"query": "1.1.1.1"}])
        self.assertGreaterEqual(sum(waits), 4.1)

    def test_rate_limit_waits_for_the_provider_reset(self):
        limited = response(429, "", {"X-Rl": "0", "X-Ttl": "32"})
        good = response(headers={"X-Rl": "14", "X-Ttl": "60"})
        good.json.return_value = [{"status": "success"}]
        client, waits, post = self.client([limited, good])
        self.assertEqual(client.lookup([{"query": "8.8.8.8"}])[0]["status"], "success")
        self.assertGreaterEqual(sum(waits), 32)
        self.assertEqual(post.call_count, 2)
        self.assertIsNone(client.last_error)

    def test_success_with_no_remaining_budget_delays_the_next_request(self):
        good = response(headers={"X-Rl": "0", "X-Ttl": "12"})
        good.json.return_value = [{"status": "success"}]
        client, waits, _ = self.client([good, good])
        client.lookup([{"query": "8.8.8.8"}])
        client.lookup([{"query": "1.1.1.1"}])
        self.assertGreaterEqual(sum(waits), 12)

    def test_repeated_exit_ips_share_one_enrichment_lookup(self):
        import profiler
        state = State()
        state.valid = [{"proxy": "8.8.8.8:8080", "exit_ip": "1.1.1.1", "latency": 1},
                       {"proxy": "9.9.9.9:8080", "exit_ip": "1.1.1.1", "latency": 2}]
        good = response()
        good.json.return_value = [{"status": "success", "isp": "Test ISP"}]
        client, _, post = self.client([good])
        with patch.object(profiler, "GEO_CLIENT", client), redirect_stdout(io.StringIO()):
            profiler.run_profile(state, deep_mode=False, interactive=False)
        self.assertEqual(len(post.call_args.kwargs["json"]), 1)
        self.assertEqual(len(state.profiled), 2)
        self.assertEqual(state.stage_counts["profile"]["incomplete"], 0)

    def test_missing_enrichment_is_visible_instead_of_silently_clean(self):
        import profiler
        state = State()
        state.valid = [{"proxy": "8.8.8.8:8080", "latency": 1}]
        failed = response(503, "")
        client, _, _ = self.client([failed])
        with patch.object(profiler, "GEO_CLIENT", client), redirect_stdout(io.StringIO()):
            profiler.run_profile(state, deep_mode=False, interactive=False)
        self.assertEqual(state.stage_counts["profile"]["incomplete"], 1)
        self.assertTrue(state.profile_warnings)
        self.assertIn("profile_error", state.profiled[0])
        self.assertEqual(state.profiled[0]["type"], "unknown")


class PipelineTests(unittest.TestCase):
    def test_loading_a_new_file_resets_the_old_filter_completion(self):
        import proxyhunterV2
        state = State()
        state.filtered_ready = True
        with patch.object(proxyhunterV2, "state", state), \
                patch.object(proxyhunterV2, "clr"), \
                patch.object(proxyhunterV2, "safe_input", side_effect=["proxies.txt", ""]), \
                patch("os.path.exists", return_value=True), \
                patch("builtins.open", mock_open(read_data="8.8.8.8:8080\n")), redirect_stdout(io.StringIO()):
            proxyhunterV2.run_load()
        self.assertFalse(state.filtered_ready)
        self.assertIn("8.8.8.8:8080", state.raw_proxies)

    def test_duplicate_category_is_reported_as_found_with_zero_new(self):
        import proxyhunterV2
        state = State()
        state.settings["src_telegram"] = True
        candidates = {"8.8.8.8:8080": "http"}
        output = io.StringIO()
        with patch.object(proxyhunterV2, "state", state), \
                patch.object(proxyhunterV2, "scrape_github_api", return_value=(candidates, 1)), \
                patch.object(proxyhunterV2, "scrape_telegram", return_value=(candidates, 1)), \
                patch.object(proxyhunterV2, "clr"), patch.object(proxyhunterV2, "safe_input"), redirect_stdout(output):
            proxyhunterV2.run_scrape(skip_menu=True)
        self.assertEqual(state.last_sources["telegram"], 1)
        self.assertIn("0 new; 1 duplicates", output.getvalue())

    def test_same_endpoint_keeps_protocol_alternatives_and_source_provenance(self):
        state = State()
        begin_scrape(state)

        def fetch(url, proto, kind, proxies):
            return {"url": url, "status": "OK", "count": 1, "entries": [("8.8.8.8:1080", proto)]}

        with patch("scraper.SourceFetcher.fetch", side_effect=fetch):
            results, _ = _harvest(state, [("https://example.org/a", "http", "plain"),
                                         ("https://example.org/b", "socks5", "plain")], "test")
        self.assertEqual(state.proxy_protocols["8.8.8.8:1080"], {"http", "socks5"})
        self.assertEqual(len(state.proxy_sources["8.8.8.8:1080"]), 2)
        self.assertEqual(len(results), 1)

    def test_worker_exceptions_are_recorded(self):
        state = State()
        with patch("scraper.SourceFetcher.fetch", side_effect=ValueError("bad format")):
            _harvest(state, [("https://example.org/a", "http", "plain")], "test")
        self.assertEqual(state.source_health["https://example.org/a"]["status"], "ERROR")

    def test_empty_filtered_pool_does_not_fall_back_to_raw_candidates(self):
        state = State()
        state.raw_proxies = {"8.8.8.8:8080": "http"}
        state.filtered_ready = True
        with patch("validator.validate_one") as validate:
            run_validate(state, interactive=False)
        validate.assert_not_called()
        self.assertEqual(state.valid, [])

    def test_alternate_protocol_is_tried_after_first_label_fails(self):
        state = State()
        state.raw_proxies = {"8.8.8.8:1080": "http"}
        state.proxy_protocols = {"8.8.8.8:1080": {"http", "socks5"}}
        valid = {"proxy": "8.8.8.8:1080", "proto": "socks5", "latency": 1}
        with patch("validator.validate_one", side_effect=[None, valid]) as validate:
            run_validate(state, interactive=False)
        self.assertEqual(validate.call_args_list[1].args[1], "socks5")
        self.assertEqual(state.valid[0]["proto"], "socks5")

    def test_http_200_captive_portal_is_not_a_verified_proxy(self):
        portal = Mock(status_code=200, text="<html>Please login</html>")
        portal.json.side_effect = ValueError()
        with patch("validator.requests.get", return_value=portal):
            self.assertIsNone(validate_one("8.8.8.8:8080", "http", 1))

    def test_plain_ip_echo_is_recorded_for_direct_proxies(self):
        echo = Mock(status_code=200, text="1.1.1.1\n")
        echo.json.side_effect = ValueError()
        with patch("validator.requests.get", return_value=echo):
            result = validate_one("8.8.8.8:8080", "http", 1)
        self.assertEqual(result["exit_ip"], "1.1.1.1")

    def test_https_proxy_transport_is_preserved(self):
        self.assertEqual(build_proxy_dict("8.8.8.8:443", "https")["https"], "https://8.8.8.8:443")

    def test_vpngate_does_not_invent_http_listeners(self):
        state = State()
        with patch("vpngate_client.discover", return_value=[]), patch("vpngate_client.docker") as docker:
            self.assertEqual(scrape_vpngate(state), ({}, 0))
        docker.assert_not_called()
        self.assertEqual(state.vpngate["status"], "UNAVAILABLE")



if __name__ == "__main__":
    unittest.main()

