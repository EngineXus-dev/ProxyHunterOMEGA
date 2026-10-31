"""Offline CPU quota and profile regressions. No Docker or network access."""
import os
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import desktop
import pipeline
import scrapoxy_runtime
from state import State


class CpuControlTests(unittest.TestCase):
    def test_desktop_selects_balanced_by_default_and_keeps_turbo(self):
        self.assertIn('balanced', desktop.PROFILES)
        self.assertIn('quiet', desktop.PROFILES)
        self.assertIn('turbo', desktop.PROFILES)
        self.assertEqual(desktop.hunt_command()[3], '--profile')
        self.assertEqual(desktop.hunt_command()[4], 'balanced')
        self.assertEqual(desktop.WORKERS['turbo'], (1000,64,24))
        self.assertEqual(desktop.WORKERS['balanced'], (256,24,12))

    def test_quiet_balanced_use_async_not_hundreds_of_python_threads(self):
        state=State()
        for profile in ('quiet','balanced'):
            pipeline.apply_resource_profile(state, profile)
            self.assertEqual(state.settings['port_engine'], 'async')
            self.assertLess(state.settings['threads'], 64)

    def test_low_cpu_quota_default_and_operator_override(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(scrapoxy_runtime.scrapoxy_cpu_limit(), .5)
        with patch.dict(os.environ, {'SCRAPOXY_CPU_LIMIT':'0.25'}):
            self.assertEqual(scrapoxy_runtime.scrapoxy_cpu_limit(), .25)
        for bad in ('-1','0','100','nan','inf','nothing'):
            with patch.dict(os.environ, {'SCRAPOXY_CPU_LIMIT':bad}):
                with self.assertRaises(ValueError): scrapoxy_runtime.scrapoxy_cpu_limit()

    def test_compose_quota_is_real_runtime_quota(self):
        config=(scrapoxy_runtime.ROOT/'compose.scrapoxy.yml').read_text()
        self.assertIn('cpus: ${SCRAPOXY_CPU_LIMIT:-0.50}', config)
        self.assertIn('cpus: "${SCRAPOXY_CPU_LIMIT:-0.50}"', config)

    def test_running_container_updated_and_verified(self):
        def runner(cmd, **kwargs):
            if cmd[-3:]==['ps','-q','scrapoxy']:
                return SimpleNamespace(returncode=0,stdout='managed-id\n',stderr='')
            if cmd[:3]==['docker','update','--cpus']:
                self.assertEqual(cmd[-1],'managed-id')
                self.assertEqual(cmd[-2],'0.5')
                return SimpleNamespace(returncode=0,stdout='managed-id',stderr='')
            if cmd[:2]==['docker','inspect']:
                return SimpleNamespace(returncode=0,stdout='500000000\n',stderr='')
            raise AssertionError(cmd)
        self.assertIsNone(scrapoxy_runtime.enforce_scrapoxy_cpu_limit(.5, runner=runner))

    def test_failed_enforcement_is_reported_not_silently_ignored(self):
        def runner(cmd, **kwargs):
            if cmd[-3:]==['ps','-q','scrapoxy']:
                return SimpleNamespace(returncode=0,stdout='managed-id\n',stderr='')
            return SimpleNamespace(returncode=1,stdout='',stderr='quota not supported')
        message=scrapoxy_runtime.enforce_scrapoxy_cpu_limit(.5,runner=runner)
        self.assertIn('did not apply',message)
        self.assertIn('not supported',message)

    def test_runtime_enforces_after_compose_start(self):
        state=State();state.settings.update(scrapoxy_enabled=True,scrapoxy_autostart=True,
             scrapoxy_url='http://127.0.0.1:8890')
        fake_session=Mock()
        fake_session.__enter__=Mock(return_value=fake_session)
        fake_session.__exit__=Mock(return_value=False)
        fake_session.get.side_effect=[SimpleNamespace(ok=False), SimpleNamespace(ok=True)]
        with patch('scrapoxy_runtime.prepare_service',return_value={}), \
             patch('scrapoxy_runtime.prepare_source'), \
             patch('scrapoxy_runtime.provision_project'), \
             patch('scrapoxy_runtime.requests.Session',return_value=fake_session), \
             patch('scrapoxy_runtime.subprocess.run',return_value=SimpleNamespace(returncode=0,stderr='')) as run, \
             patch('scrapoxy_runtime.enforce_scrapoxy_cpu_limit',return_value=None) as enforce:
            result, message=scrapoxy_runtime.ensure_scrapoxy(state)
        self.assertTrue(result,message)
        enforce.assert_called_once_with(.5)
        self.assertEqual(run.call_args.kwargs['env']['SCRAPOXY_CPU_LIMIT'],'0.5')

    def test_obsolete_entrypoints_removed(self):
        root=desktop.ROOT
        for name in ('web_gui.py','run_web_gui.bat','web_ui','build_kaggle_bundle.py','kaggle'):
            self.assertFalse((root/name).exists(), name)
        self.assertFalse((root/'.scrapoxy/source/package.json').exists())
        self.assertFalse((root/'.cache/scan_history.sqlite3').exists())

if __name__ == '__main__': unittest.main()
