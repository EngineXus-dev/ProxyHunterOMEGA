"""Offline checks that public distribution has no embedded private runtime data."""
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from state import State
import scrapoxy_runtime

ROOT = Path(__file__).resolve().parent

class PublicReleaseTests(unittest.TestCase):
    def test_no_private_history_or_scrapoxy_data(self):
        for rel in ('.scrapoxy', 'Clean', 'NewProxies',
                    'decentralized_providers.py', 'unbounded_p2p.py', 'NETWORK_CLASSIFICATION_AUDIT.md',
                    'build_kaggle_bundle.py', 'web_gui.py', 'RELEASE_NOTES.md'):
            self.assertFalse((ROOT / rel).exists(), rel)

    def test_ignore_rules_cover_runtime_cache(self):
        ignore=(ROOT/'.gitignore').read_text(encoding='utf-8')
        self.assertIn('.cache/', ignore)
        self.assertIn('.scrapoxy/', ignore)

    def test_optional_services_off_by_default(self):
        with patch.dict('os.environ', {}, clear=True):
            settings = State().settings
        self.assertFalse(settings['scrapoxy_enabled'])
        self.assertFalse(settings['scrapoxy_autostart'])
        self.assertFalse(settings['vpngate_enabled'])
        self.assertFalse(settings['vpngate_autostart'])

    def test_local_scrapoxy_autostart_requires_user_supplied_source(self):
        with self.assertRaisesRegex(FileNotFoundError, 'not bundled'):
            scrapoxy_runtime.prepare_source()

    def test_manifest_and_source_attribution(self):
        feeds = json.loads((ROOT / 'community_sources.json').read_text(encoding='utf-8'))
        self.assertEqual(len(feeds), 18)
        self.assertEqual(sum(bool(feed['enabled']) for feed in feeds), 9)
        self.assertEqual(len({feed['upstream'] for feed in feeds}), 6)
        self.assertTrue(all(feed['url'].startswith('https://') for feed in feeds))
        self.assertTrue((ROOT / 'SOURCES.md').exists())

if __name__ == '__main__': unittest.main()
