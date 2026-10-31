"""Offline tests: native launcher, async probing, snapshots and output safety."""
import asyncio
import errno
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

import desktop
from async_ports import probe_ports
from pipeline import apply_resource_profile
from recent_results import export_latest, save_latest
from state import State
from validator import run_port_filter, run_validate


class DesktopChecks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.environment = patch.dict(os.environ, {'PROXYHUNTER_DATA_DIR': self.tmp.name,
                                                    'PROXYHUNTER_HISTORY_ENABLED': 'true'})
        self.environment.start()
        self.state = State()
        self.state.settings.update(scrapoxy_enabled=False, vpngate_enabled=False,
                                   quiet_progress=True, history_enabled=False)

    def tearDown(self):
        self.environment.stop()
        self.tmp.cleanup()

    def test_turbo_uses_async_1000_and_64_validation(self):
        apply_resource_profile(self.state, 'turbo')
        self.assertEqual(self.state.settings['port_threads'], 1000)
        self.assertEqual(self.state.settings['threads'], 64)
        self.assertEqual(self.state.settings['port_engine'], 'async')
        self.assertEqual(self.state.settings['port_retries'], 0)
        self.assertEqual(self.state.settings['validation_test_urls'], 1)

    def test_argv_has_no_shell_and_optional_services_off(self):
        cmd = desktop.hunt_command(full=True)
        self.assertEqual(cmd[0], __import__('sys').executable)
        self.assertIn('--full', cmd)
        self.assertIn('--no-scrapoxy', cmd)
        self.assertIn('--no-vpngate', cmd)
        with self.assertRaises(ValueError):
            desktop.hunt_command(profile='turbo && echo unsafe')

    def test_async_probe_open_and_closed_local_port(self):
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(5)
        try:
            live_port = listener.getsockname()[1]
            results = {}
            probe_ports([(f'127.0.0.1:{live_port}', 'http'),
                         ('127.0.0.1:0', 'http')], 1000, 0.3, lambda: False,
                        lambda item, value: results.__setitem__(item[0], value))
            self.assertTrue(results[f'127.0.0.1:{live_port}'])
            self.assertFalse(results['127.0.0.1:0'])
        finally:
            listener.close()

    def test_async_port_filter_updates_local_history(self):
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(5)
        try:
            endpoint = f'127.0.0.1:{listener.getsockname()[1]}'
            apply_resource_profile(self.state, 'turbo')
            self.state.raw_proxies = {endpoint: 'http', '127.0.0.1:0': 'http'}
            run_port_filter(self.state, interactive=False)
            self.assertIn(endpoint, self.state.filtered)
            self.assertNotIn('127.0.0.1:0', self.state.filtered)
        finally:
            listener.close()

    def test_cancelled_async_does_not_queue_every_item(self):
        output = []
        def cancel_after_one(item, success):
            output.append(item)
            self.state.control.cancel()
        probe_ports([(f'127.0.0.1:{n}', 'http') for n in range(15000, 30000)],
                    4, 0.1, self.state.control.is_cancelled, cancel_after_one)
        self.assertLessEqual(len(output), 4)

    def test_latest_snapshot_contains_only_this_run_and_export_formats(self):
        self.state.valid = [{'proxy': '127.0.0.1:3128', 'proto': 'http',
                             'exit_ip': '203.0.113.3', 'latency': 0.2}]
        self.state.profiled = [{**self.state.valid[0], 'threat_tag': 'CLEAN_RESIDENTIAL'}]
        self.state.pipeline_result = 'completed'
        path = save_latest(self.state)
        self.assertEqual(len(json.loads(path.read_text())['validated']), 1)
        for ext in ('txt', 'csv', 'json'):
            destination = Path(self.tmp.name) / f'export.{ext}'
            self.assertEqual(export_latest(destination), 1)
            self.assertIn('127.0.0.1:3128', destination.read_text())
        self.state.valid = []
        self.state.profiled = []
        self.state.pipeline_result = 'no_new_candidates'
        save_latest(self.state)
        self.assertEqual(len(json.loads(path.read_text())['validated']), 1)
        self.assertEqual(json.loads((Path(self.tmp.name) / 'interrupted_results.json').read_text())['validated'], [])
        self.assertEqual(export_latest(Path(self.tmp.name) / 'still-completed.txt'), 1)

    def test_export_rejects_unknown_suffix(self):
        self.state.pipeline_result = 'completed'
        save_latest(self.state)
        with self.assertRaises(ValueError):
            export_latest(Path(self.tmp.name) / 'results.exe')

    def test_turbo_limits_protocol_fallbacks(self):
        apply_resource_profile(self.state, 'turbo')
        endpoint = '127.0.0.1:1080'
        self.state.raw_proxies = {endpoint: 'http'}
        self.state.proxy_protocols = {endpoint: {'http', 'socks4', 'socks5'}}
        with patch('validator.validate_one', return_value=None) as validate:
            run_validate(self.state, interactive=False)
        self.assertEqual(validate.call_count, 2)

    def test_turbo_validation_uses_one_url_and_threadlocal_session(self):
        apply_resource_profile(self.state, 'turbo')
        self.state.raw_proxies = {'127.0.0.1:1080': 'socks5'}
        with patch('validator.validate_one', return_value=None) as validate:
            run_validate(self.state, interactive=False)
        self.assertEqual(validate.call_count, 1)
        self.assertEqual(validate.call_args.kwargs['max_test_urls'], 1)
        self.assertIsNotNone(validate.call_args.kwargs['session'])


class DesktopTelemetryTests(unittest.TestCase):
    """Aggregate-only status transport; no network and no GUI event loop needed."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.environment = patch.dict(os.environ, {'PROXYHUNTER_DATA_DIR': self.tmp.name})
        self.environment.start()

    def tearDown(self):
        self.environment.stop()
        self.tmp.cleanup()

    def test_reporter_atomic_progress_and_final_state(self):
        from desktop_status import ProgressReporter, read_status, status_path
        reporter = ProgressReporter()
        doc = read_status()
        self.assertEqual(doc['result'], 'running')
        self.assertIsInstance(doc['pid'], int)
        reporter.update(3, 'PORT CHECK', 'Ports: 100/200; 25 open', 48,
                        {'ports_alive': 25, 'proxy': 'secret@127.0.0.1', 'valid': 0})
        reporter.finish('completed')
        doc = read_status()
        self.assertEqual(doc['stage'], 3)
        self.assertEqual(doc['result'], 'completed')
        self.assertEqual(doc['counters'], {'ports_alive': 25, 'valid': 0})
        self.assertNotIn('secret@', status_path().read_text())

    def test_windows_access_denied_retries_status_without_pipeline_error(self):
        """A short file-sharing conflict must not become a hunt exception."""
        from desktop_status import ProgressReporter, read_status
        reporter = ProgressReporter()
        real_replace = os.replace
        calls = []

        def temporarily_locked(source, target):
            calls.append((source, target))
            if len(calls) < 3:
                raise PermissionError(errno.EACCES, 'Simulated WinError 5')
            return real_replace(source, target)

        with patch('desktop_status.os.replace', side_effect=temporarily_locked), \
                patch('desktop_status.time.sleep') as sleep:
            reporter.update(3, 'PORT CHECK', 'Ports: 1/100; 0 open', 36)
        self.assertEqual(len(calls), 3)
        self.assertEqual(sleep.call_count, 2)
        self.assertEqual(read_status()['name'], 'PORT CHECK')
        self.assertEqual(list(Path(self.tmp.name).glob('.progress-*.tmp')), [])

    def test_permanent_winerror5_is_nonfatal_and_recovers_after_release(self):
        """Telemetry is optional; even finish() must not crash a real hunt."""
        from desktop_status import ProgressReporter, read_status
        reporter = ProgressReporter()
        previous = read_status()
        with patch('desktop_status.os.replace', side_effect=PermissionError(errno.EACCES, 'locked')), \
                patch('desktop_status.time.sleep'), patch('builtins.print') as warning:
            self.assertIsNone(reporter.update(3, 'PORT CHECK', 'Ports: 100/200', 48))
            self.assertIsNone(reporter.finish('completed'))
        self.assertTrue(warning.called)
        self.assertEqual(previous['result'], read_status()['result'])
        self.assertFalse(list(Path(self.tmp.name).glob('.progress-*.tmp')))
        # A later write can recover and shows the actual completed result.
        with patch('builtins.print'):
            reporter.finish('completed')
        self.assertEqual(read_status()['result'], 'completed')
        self.assertEqual(read_status()['stage'], 3)

    def test_unwritable_status_folder_does_not_stop_pipeline(self):
        """No exception should escape status initialization or progress callbacks."""
        from run_optimal import run_optimal_automated_pipeline

        def fake_pipeline(state, **kwargs):
            kwargs['progress'](3, 'PORT CHECK', 'Port check underway', 42, {})
            state.pipeline_result = 'completed'
            return state

        with patch('desktop_status.tempfile.mkstemp', side_effect=PermissionError(errno.EACCES, 'locked')), \
                patch('builtins.print'), patch('run_optimal.execute_pipeline', side_effect=fake_pipeline):
            result = run_optimal_automated_pipeline(use_scrapoxy=False, use_vpngate=False,
                                                    desktop_status=True)
        self.assertEqual(result.pipeline_result, 'completed')

    def test_status_does_not_persist_exception_text(self):
        from desktop_status import ProgressReporter, read_status
        reporter = ProgressReporter()
        reporter.update(0, 'ERROR', 'Error accessing /home/private with token secret-123', 0)
        reporter.finish('error')
        self.assertNotIn('secret-123', str(read_status()))
        self.assertEqual(read_status()['result'], 'error')

    def test_read_status_rejects_corrupt_or_wrong_schema(self):
        from desktop_status import read_status
        path = Path(self.tmp.name) / 'bad.json'
        path.write_text('{nope')
        self.assertIsNone(read_status(path))
        path.write_text(json.dumps({'schema': 99}))
        self.assertIsNone(read_status(path))

    def test_snapshot_summary_categorizes_without_showing_endpoints(self):
        from desktop_status import snapshot_summary
        path = Path(self.tmp.name) / 'latest_results.json'
        path.write_text(json.dumps({'validated': [
            {'proxy': 'secret:pass@127.0.0.1:8080', 'threat_tag': 'CLEAN_RESIDENTIAL'},
            {'threat_tag': 'CLEAN_MOBILE'}, {'threat_tag': 'SPOOFED_DC'},
            {'threat_tag': 'BOTNET_RELAY'}, {'proto': 'socks5'},
        ], 'result': 'completed'}))
        summary = snapshot_summary(path)
        self.assertEqual(summary['total'], 5)
        self.assertEqual(summary['counters'], dict(isp=2, carrier=0,
                         datacenter=1, risk=1, other=1))
        self.assertNotIn('secret', str(summary))

    def test_command_preserves_terminal_entrypoint_and_recheck(self):
        cmd = desktop.hunt_command(profile='turbo', recheck=True, vpngate=True)
        self.assertIn('--desktop-status', cmd)
        self.assertIn('--recheck', cmd)
        self.assertNotIn('--no-vpngate', cmd)
        self.assertTrue(cmd[1].endswith('terminal_runner.py'))
        with self.assertRaises(ValueError):
            desktop.hunt_command(profile='turbo & calc')

    def test_optimal_runner_wires_progress_and_finishes_without_network(self):
        from run_optimal import run_optimal_automated_pipeline
        from desktop_status import read_status
        def fake_pipeline(state, **kwargs):
            self.assertTrue(callable(kwargs['progress']))
            kwargs['progress'](4, 'VALIDATION', 'Validation: 10/10; 3 live', 80,
                               {'valid': 3})
            state.pipeline_result = 'completed'
            return state
        with patch('run_optimal.execute_pipeline', side_effect=fake_pipeline):
            run_optimal_automated_pipeline(use_scrapoxy=False, use_vpngate=False,
                                            desktop_status=True)
        self.assertEqual(read_status()['result'], 'completed')
        self.assertEqual(read_status()['counters']['valid'], 3)


if __name__ == '__main__':
    unittest.main()
