"""No external network: verify independent confirmation, split, cancellation, exports."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from confirmation import confirm_one, run_confirmation, CONFIRMATION_URLS
from pipeline import export_results
from recent_results import save_latest, export_latest
from state import State


class ConfirmationChecks(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {'PROXYHUNTER_DATA_DIR': self.folder.name})
        self.env.start()
        self.state = State()
        self.state.settings.update(threads=5, timeout=6, quiet_progress=True)
        self.base = Path(self.folder.name)

    def tearDown(self):
        self.env.stop()
        self.folder.cleanup()

    def check(self, endpoint='8.8.8.8:8080', proto='http', ip='1.1.1.1', tag='CLEAN_RESIDENTIAL'):
        return {'proxy': endpoint, 'proto': proto, 'exit_ip': ip, 'latency': .2, 'threat_tag': tag}

    def test_different_services_both_required(self):
        calls = []
        def check(endpoint, proto, timeout, **kw):
            calls.append(kw['test_urls'][0])
            return {'exit_ip': '9.9.9.9'}
        result = confirm_one(self.check(), check=check)
        self.assertTrue(result['confirmed'])
        self.assertEqual(result['confirmation_checks'], 2)
        self.assertEqual(calls, list(CONFIRMATION_URLS))

    def test_one_failed_request_rejects_proxy(self):
        seen = []
        def check(endpoint, proto, timeout, **kw):
            seen.append(kw['test_urls'][0])
            return {'exit_ip': '8.8.8.8'} if len(seen) == 1 else None
        self.assertIsNone(confirm_one(self.check(), check=check))
        self.assertEqual(len(seen), 2)

    def test_mismatched_exits_rejected(self):
        ips = iter(('1.1.1.1', '8.8.8.8'))
        self.assertIsNone(confirm_one(self.check(), check=lambda *a, **k: {'exit_ip': next(ips)}))

    def test_private_ip_rejected(self):
        self.assertIsNone(confirm_one(self.check(), check=lambda *a, **k: {'exit_ip': '127.0.0.1'}))

    def test_bad_data_rejected(self):
        for result in ({}, {'exit_ip': 'no ip'}, {'exit_ip': None}):
            self.assertIsNone(confirm_one(self.check(), check=lambda *a, **k: result))

    def test_cancel_before_network(self):
        invoked = []
        self.assertIsNone(confirm_one(self.check(), cancelled=lambda: True,
            check=lambda *a, **k: invoked.append(True)))
        self.assertEqual(invoked, [])

    def test_current_run_only_no_cached_acceptance(self):
        self.state.valid = [self.check(), self.check('8.8.4.4:1080', 'socks5', tag='DATACENTER')]
        self.state.profiled = list(self.state.valid)
        def check(row, **kw):
            if row['proto'] == 'socks5':
                return None
            return {'confirmed': True, 'exit_ip': '1.1.1.1', 'confirmation_checks': 2,
                    'confirmation_checked_at': 100.0}
        with patch('confirmation.confirm_one', side_effect=check):
            self.assertEqual(run_confirmation(self.state), 1)
        self.assertEqual(len(self.state.valid), 1)
        self.assertEqual(self.state.stage_counts['confirmation']['rejected'], 1)
        self.assertTrue(self.state.profiled[0]['confirmed'])
        self.assertEqual(self.state.profiled[0]['confirmation_checks'], 2)

    def test_outputs_separate_potential_res_and_all_other_live(self):
        rows = [self.check(), self.check('8.8.4.4:1080', 'socks5', tag='CLEAN_MOBILE'),
                self.check('9.9.9.9:3128', 'http', tag='DATACENTER'),
                self.check('4.2.2.2:8080', 'http', tag='UNKNOWN_COMMUNITY')]
        self.state.valid = rows
        self.state.profiled = rows
        output = self.base/'output'
        # Running a successful full scan creates these files from current successful rows.
        export_results(self.state, output)
        self.assertEqual((output/'potential_residential_live.txt').read_text(), '')
        self.assertEqual((output/'isp_network_candidates_live.txt').read_text(), '8.8.8.8:8080\n8.8.4.4:1080\n')
        self.assertEqual((output/'potential_mobile_live.txt').read_text(), '')
        self.assertEqual((output/'carrier_network_candidates_live.txt').read_text(), '')
        self.assertEqual((output/'other_live.txt').read_text(), '9.9.9.9:3128\n4.2.2.2:8080\n')
        self.assertEqual(len((output/'all_confirmed_live.txt').read_text().splitlines()), 4)
        self.assertIn('socks5://8.8.4.4:1080', (output/'all_confirmed_live_protocols.txt').read_text())
        self.assertEqual((output/'potential_residential_live_protocols.txt').read_text(), '')
        self.assertIn('socks5://8.8.4.4:1080', (output/'isp_network_candidates_live_protocols.txt').read_text())
        # A new completed empty run replaces obsolete endpoints.
        self.state.valid = []
        self.state.profiled = []
        export_results(self.state, output)
        for name in ('potential_residential_live.txt', 'potential_mobile_live.txt', 'other_live.txt',
                     'all_confirmed_live.txt', 'all_confirmed_live_protocols.txt', 'other_live_protocols.txt',
                     'potential_mobile_live_protocols.txt', 'potential_residential_live_protocols.txt',
                     'isp_network_candidates_live.txt', 'carrier_network_candidates_live.txt',
                     'isp_network_candidates_live_protocols.txt', 'carrier_network_candidates_live_protocols.txt'):
            self.assertEqual((output/name).read_text(), '')

    def test_completed_snapshot_export_includes_confirmation_evidence(self):
        self.state.valid = [dict(self.check(), confirmed=True, confirmation_checks=2,
                                 confirmation_checked_at=200.0, confirmation_method='two_independent_https_echo_services')]
        self.state.pipeline_result = 'completed'
        path = save_latest(self.state)
        saved = json.loads(path.read_text())['validated'][0]
        self.assertTrue(saved['confirmed'])
        self.assertEqual(saved['confirmation_checks'], 2)
        self.assertEqual(export_latest(self.base/'recent.json'), 1)

    def test_cancel_does_not_replace_last_completed_list(self):
        self.state.valid = [self.check()]
        self.state.pipeline_result = 'completed'
        save_latest(self.state)
        self.state.control.cancel()
        self.state.valid = [self.check('4.4.4.4:8888')]
        save_latest(self.state)
        self.assertEqual(json.loads((self.base/'latest_results.json').read_text())['validated'][0]['proxy'], '8.8.8.8:8080')
        self.assertEqual(json.loads((self.base/'interrupted_results.json').read_text())['validated'][0]['proxy'], '4.4.4.4:8888')

if __name__ == '__main__':
    unittest.main()
