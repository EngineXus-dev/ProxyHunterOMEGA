"""Regression coverage for full refresh, canceled runs, and stale-result removal."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from pipeline import execute_pipeline, export_results
from recent_results import save_latest, export_latest
from scan_history import ScanHistory, endpoint_key, protocol_key, restore_verified_candidates
from state import State
from desktop import hunt_command


class FreshRunChecks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)
        self.env = patch.dict(os.environ, {'PROXYHUNTER_DATA_DIR': self.tmp.name,
                                           'PROXYHUNTER_HISTORY_ENABLED': 'true'})
        self.env.start()
        self.state = State()
        self.state.settings.update(scrapoxy_enabled=False, vpngate_enabled=False,
                                   quiet_progress=True, src_gists=False)

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def seed(self, endpoint, proto='socks5'):
        r = {'proxy': endpoint, 'proto': proto, 'exit_ip': '1.1.1.1', 'latency': .25,
             'threat_tag': 'CLEAN_RESIDENTIAL'}
        with ScanHistory(self.state.settings) as h:
            h.record('validation', protocol_key(endpoint, proto), True, r)
            h.record('profile', protocol_key(endpoint, proto), True, r)
        return r

    def test_fresh_is_default_and_resume_is_opt_in(self):
        self.assertTrue(self.state.settings['recheck'])
        self.assertIn('--recheck', hunt_command())
        self.assertIn('--resume', hunt_command(recheck=False))

    def test_restore_previous_verified_from_real_cache_shapes_without_network(self):
        result = self.seed('8.8.8.8:1080')
        path = save_latest_stub(self.path, [result])
        self.state.raw_proxies = {'8.8.8.8:1080': 'http', '1.1.1.1:1080': 'http'}
        number_added = restore_verified_candidates(self.state, output_dir=self.path)
        self.assertEqual(number_added, 0)
        self.assertEqual(self.state.settings['recheck'], True)
        self.assertEqual(self.state.raw_proxies['8.8.8.8:1080'], 'socks5')
        self.assertEqual(self.state.history_stats['previously_verified_rechecked'], 1)
        self.assertEqual(self.state.proxy_protocols['8.8.8.8:1080'], {'socks5'})

    def test_readds_previous_validated_endpoint_not_in_current_feed(self):
        self.seed('8.8.8.8:1080', 'socks5')
        self.state.raw_proxies = {}
        self.assertEqual(restore_verified_candidates(self.state, output_dir=self.path), 1)
        self.assertEqual(self.state.raw_proxies, {'8.8.8.8:1080': 'socks5'})

    def test_restoring_harvested_endpoint_preserves_set_provenance(self):
        """Regression: scraper._record stores URLs as a set, not a list."""
        from scraper import _record

        self.seed('8.8.8.8:1080')
        result = {}
        _record(self.state, {
            'url': 'https://feeds.example/socks5.txt',
            'status': 'OK',
            'entries': [('8.8.8.8:1080', 'socks5')],
        }, 'github/api', result)
        self.state.raw_proxies = result
        self.assertIsInstance(self.state.proxy_sources['8.8.8.8:1080'], set)

        self.assertEqual(restore_verified_candidates(self.state, output_dir=self.path), 0)
        self.assertEqual(self.state.history_stats['previously_verified_rechecked'], 1)
        self.assertEqual(self.state.proxy_sources['8.8.8.8:1080'], {
            'https://feeds.example/socks5.txt', 'previously_validated_local_history'
        })

        # Repeat recovery must not create duplicate provenance entries.
        self.assertEqual(restore_verified_candidates(self.state, output_dir=self.path), 0)
        self.assertEqual(len(self.state.proxy_sources['8.8.8.8:1080']), 2)

    def test_restore_normalizes_legacy_list_provenance(self):
        self.seed('8.8.8.8:1080')
        self.state.raw_proxies = {'8.8.8.8:1080': 'socks5'}
        self.state.proxy_sources['8.8.8.8:1080'] = ['https://feeds.example/list']
        self.assertEqual(restore_verified_candidates(self.state, output_dir=self.path), 0)
        self.assertEqual(self.state.proxy_sources['8.8.8.8:1080'], {
            'https://feeds.example/list', 'previously_validated_local_history'
        })

    def test_pipeline_with_vpngate_scrapoxy_and_harvested_history_reaches_next_stage(self):
        """Simulate the precise gateway -> restore failure reported on Windows.

        No external source, VPNGate, Scrapoxy or public endpoint is contacted.
        """
        from scraper import _record

        self.seed('8.8.8.8:1080')
        self.state.settings.update(scrapoxy_enabled=True, vpngate_enabled=True)

        def feed(state):
            result = {}
            _record(state, {'url': 'https://feeds.example/socks5.txt',
                            'status': 'OK', 'entries': [('8.8.8.8:1080', 'socks5')]},
                    'github/api', result)
            return result, 1

        def vpn(state):
            state.vpngate_endpoints.add('127.0.0.1:1088')
            return {'127.0.0.1:1088': 'socks5'}, 1

        def scrapoxy(state):
            endpoint = 'http://127.0.0.1:8888'
            state.raw_proxies[endpoint] = 'http'
            state.scrapoxy_endpoints.add(endpoint)
            return 1

        # harvest_only exits after fresh-history restoration, before network probes.
        with patch('pipeline.scrape_github_api', side_effect=feed), \
             patch('pipeline.scrape_telegram', return_value=({}, 0)), \
             patch('pipeline.scrape_html', return_value=({}, 0)), \
             patch('pipeline.scrape_vpngate', side_effect=vpn), \
             patch('pipeline.pull_scrapoxy_into_state', side_effect=scrapoxy), \
             patch('pipeline.shutil.which', return_value='/usr/bin/docker'):
            execute_pipeline(self.state, harvest_only=True, output_dir=self.path)
        self.assertEqual(self.state.pipeline_result, 'harvested')
        self.assertIn('8.8.8.8:1080', self.state.raw_proxies)
        self.assertIn('http://127.0.0.1:8888', self.state.scrapoxy_endpoints)
        self.assertIn('127.0.0.1:1088', self.state.vpngate_endpoints)
        self.assertEqual(self.state.history_stats['previously_verified_rechecked'], 1)

    def test_complete_run_removes_dead_history_and_replaces_old_exports(self):
        old = self.seed('8.8.8.8:1080')
        alive = self.seed('1.1.1.1:8080', 'http')
        save_latest_stub(self.path, [old, alive])
        output = self.path / 'results'
        output.mkdir()
        for name in ('clean_residential_verified.txt', 'clean_residential_mobile_combined.txt'):
            (output / name).write_text('8.8.8.8:1080\n1.1.1.1:8080\n')

        def cidr(state, **_):
            state.filtered = dict(state.raw_proxies)
            state.filtered_ready = True

        def port(state, **_):
            self.assertEqual(set(state.raw_proxies), {'8.8.8.8:1080', '1.1.1.1:8080'})
            state.filtered = {'1.1.1.1:8080': 'http'}
            state.filtered_ready = True

        def validation(state, **_):
            state.valid = [dict(alive, checked_at=2.0)]

        def profile(state, **_):
            state.profiled = [dict(state.valid[0])]

        with patch('pipeline.scrape_github_api', return_value=({}, 0)), \
             patch('pipeline.scrape_telegram', return_value=({}, 0)), \
             patch('pipeline.scrape_html', return_value=({}, 0)), \
             patch('pipeline.run_cidr_filter', side_effect=cidr), \
             patch('pipeline.run_port_filter', side_effect=port), \
             patch('pipeline.run_validate', side_effect=validation), \
             patch('pipeline.run_profile', side_effect=profile), \
             patch('pipeline.run_confirmation', side_effect=lambda state, **_: None):
            execute_pipeline(self.state, output_dir=output)
        self.assertEqual(self.state.pipeline_result, 'completed')
        self.assertEqual((output / 'clean_residential_verified.txt').read_text(), '')
        self.assertEqual((output / 'isp_network_candidates_live.txt').read_text(), '1.1.1.1:8080\n')
        self.assertEqual((output / 'clean_residential_mobile_combined.txt').read_text(), '')
        self.assertEqual((output / 'clean_mobile_verified.txt').read_text(), '')
        snapshot = json.loads((self.path / 'latest_results.json').read_text())
        self.assertEqual([r['proxy'] for r in snapshot['validated']], ['1.1.1.1:8080'])
        with ScanHistory(self.state.settings) as history:
            keys = [k for (k,) in history.connection.execute("SELECT key FROM checks WHERE stage='validation' AND success=1")]
        self.assertNotIn(protocol_key('8.8.8.8:1080','socks5'), keys)

    def test_completed_empty_ports_clears_old_verified_lists(self):
        old = self.seed('8.8.8.8:1080')
        save_latest_stub(self.path, [old])
        output = self.path/'results'
        output.mkdir()
        (output/'clean_residential_verified.txt').write_text('8.8.8.8:1080\n')
        def cidr(state, **_):
            state.filtered = dict(state.raw_proxies)
            state.filtered_ready = True
        def port(state, **_):
            state.filtered = {}
            state.filtered_ready = True
        with patch('pipeline.scrape_github_api', return_value=({},0)), \
             patch('pipeline.scrape_telegram', return_value=({},0)), \
             patch('pipeline.scrape_html', return_value=({},0)), \
             patch('pipeline.run_cidr_filter', side_effect=cidr), \
             patch('pipeline.run_port_filter', side_effect=port), \
             patch('pipeline.run_validate') as validate:
            execute_pipeline(self.state, output_dir=output)
        validate.assert_not_called()
        self.assertEqual(self.state.pipeline_result, 'completed')
        self.assertEqual((output/'clean_residential_verified.txt').read_text(), '')
        self.assertEqual(json.loads((self.path/'latest_results.json').read_text())['validated'], [])

    def test_cancelled_run_preserves_previous_completed_snapshot(self):
        row = self.seed('8.8.8.8:1080')
        save_latest_stub(self.path, [row])
        self.state.pipeline_result = 'cancelled'
        self.state.control.cancel()
        self.state.valid = [{'proxy':'9.9.9.9:1080', 'proto':'socks5'}]
        save_latest(self.state)
        self.assertEqual(json.loads((self.path/'latest_results.json').read_text())['validated'][0]['proxy'], '8.8.8.8:1080')
        self.assertEqual(json.loads((self.path/'interrupted_results.json').read_text())['validated'][0]['proxy'], '9.9.9.9:1080')
        self.assertEqual(export_latest(self.path/'verified.txt'), 1)


def save_latest_stub(folder, rows):
    path = folder/'latest_results.json'
    path.write_text(json.dumps({'validated': rows, 'result': 'completed'}))
    return path
