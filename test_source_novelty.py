"""Offline regression checks for researched feed manifest and yield accounting."""
import json
from pathlib import Path
from types import SimpleNamespace
from contextlib import redirect_stdout
from io import StringIO
from state import State
import unittest
from unittest.mock import patch

from scraper import _extra_sources, source_novelty, community_source_diagnostics, scrape_github_api, load_community_manifest
from constants import SOURCES_GITHUB, SOURCES_API

ROOT = Path(__file__).resolve().parent


class NewSourceTests(unittest.TestCase):
    def test_researched_sources_have_distinct_urls_and_supported_protocols(self):
        feeds = json.loads((ROOT / 'community_sources.json').read_text(encoding='utf-8'))
        self.assertEqual(len(feeds), 18)
        self.assertEqual(len([feed for feed in feeds if feed['enabled']]), 9)
        self.assertEqual(len({feed['url'] for feed in feeds}), len(feeds))
        existing = {entry[0] for entry in SOURCES_GITHUB + SOURCES_API}
        for feed in feeds:
            self.assertNotIn(feed['url'], existing)
            self.assertIn(feed['protocol'], {'http', 'socks4', 'socks5'})
            self.assertEqual(feed['format'], 'plain')
            self.assertTrue(feed['url'].startswith('https://'))
            self.assertIn('upstream', feed)

    def test_disabled_feeds_are_not_harvested_by_default(self):
        state = SimpleNamespace(settings={'extra_sources': [], 'non_github': False}, source_health={})
        tasks = _extra_sources(state)
        self.assertEqual(len(tasks), 9)
        self.assertEqual(len({t[0] for t in tasks}), 9)
        self.assertTrue(all('raw.githubusercontent.com' in t[0] for t in tasks))

    def test_no_github_mode_suppresses_all_new_feeds(self):
        state = SimpleNamespace(settings={'extra_sources': [], 'non_github': True}, source_health={})
        self.assertEqual(_extra_sources(state), [])

    def test_actual_github_api_harvest_schedules_all_nine_curated_feeds(self):
        state = State()
        state.settings.update(src_github=False, src_api=False, src_community=True,
                              protocols=['http', 'socks4', 'socks5'],
                              non_github=False, extra_sources=[])
        requested = []

        def fake_harvest(_state, tasks, category, proxies=None):
            requested.extend(tasks)
            for url, proto, _ in tasks:
                _state.source_health[url] = {'url': url, 'status': 'OK', 'accepted': 3,
                                             'http_status': 200, 'cache': 'none', 'error': None}
            return {}, 0

        capture = StringIO()
        with patch('scraper._harvest', side_effect=fake_harvest), redirect_stdout(capture):
            scrape_github_api(state)
        enabled = [s for s in load_community_manifest() if s['enabled']]
        self.assertEqual({url for url, _, _ in requested}, {s['url'] for s in enabled})
        self.assertIn('9 scheduled', capture.getvalue())
        self.assertEqual(capture.getvalue().count('[feed]'), 9)
        diagnostics = community_source_diagnostics(state)
        self.assertEqual(diagnostics['scheduled'], 9)
        self.assertTrue(all(s['accepted_candidates'] == 3 for s in diagnostics['sources'] if s['scheduled']))

    def test_cli_lists_manifest_without_network_or_starting_a_hunt(self):
        from run_optimal import main
        from unittest.mock import patch
        capture = StringIO()
        with patch('sys.argv', ['run_optimal.py', '--list-sources']), \
             patch('run_optimal.run_optimal_automated_pipeline', side_effect=AssertionError('Started scan')), \
             redirect_stdout(capture):
            main()
        self.assertIn('9 enabled / 9 disabled', capture.getvalue())
        self.assertIn('IPLocate', capture.getvalue())
        self.assertIn('community_sources.json', capture.getvalue())

    def test_invalid_source_manifest_fails_visibility_without_network(self):
        from unittest.mock import patch
        with patch('scraper.load_community_manifest', side_effect=ValueError('Broken manifest')):
            diagnostics = community_source_diagnostics(SimpleNamespace(settings={}, source_health={}))
        self.assertIn('Broken manifest', diagnostics['error'])

    def test_real_harvest_records_researched_feed_provenance_and_counts(self):
        """SourceFetcher is the ONLY mocked boundary; _harvest and _record are real."""
        state = State()
        state.settings.update(src_github=False, src_api=False, src_community=True,
                              scrape_threads=4, protocols=['http', 'socks4', 'socks5'],
                              non_github=False, extra_sources=[])
        manifest = [f for f in load_community_manifest() if f['enabled']]
        def offline_fetch(_fetcher, url, proto, kind, proxies=None):
            return {'url': url, 'status': 'OK', 'http_status': 200,
                    'entries': [('8.8.8.8:8080', proto)], 'cache': 'none',
                    'metadata': {}, 'count': 1, 'error': None}
        output = StringIO()
        with patch('scraper.SourceFetcher.fetch', new=offline_fetch), redirect_stdout(output):
            proxies, count = scrape_github_api(state)
        self.assertEqual(count, 1)  # nine source files publish the same address
        self.assertEqual(len(state.source_health), 9)
        self.assertEqual(len(state.proxy_sources['8.8.8.8:8080']), 9)
        self.assertEqual(state.proxy_protocols['8.8.8.8:8080'], {'http', 'socks4', 'socks5'})
        diagnostics = community_source_diagnostics(state)
        self.assertEqual(diagnostics['scheduled'], 9)
        self.assertTrue(all(row['status'] == 'OK' and row['accepted_candidates'] == 1
                            for row in diagnostics['sources'] if row['scheduled']))
        self.assertEqual(len(source_novelty(state)['feeds']), 9)
        self.assertTrue(all(row['sole_source_endpoints'] == 0
                            for row in source_novelty(state)['feeds']))
        self.assertIn('9 scheduled', output.getvalue())
        self.assertIn('9', str(len(manifest)))

    def test_sole_source_and_overlap_are_not_confused(self):
        state = SimpleNamespace(proxy_sources={
            '1.1.1.1:443': {'https://feed-a', 'https://feed-b'},
            '8.8.8.8:443': {'https://feed-a'},
            '9.9.9.9:1080': {'https://feed-b'},
        })
        novelty = source_novelty(state)
        self.assertEqual(novelty['candidate_endpoints'], 3)
        results = {row['url']: row for row in novelty['feeds']}
        self.assertEqual(results['https://feed-a']['sole_source_endpoints'], 1)
        self.assertEqual(results['https://feed-b']['sole_source_endpoints'], 1)
        self.assertEqual(results['https://feed-a']['shared_endpoints'], 1)
        self.assertIn('not verified unique', novelty['definition'])

    def test_empty_run_novelty_has_no_feeds(self):
        result = source_novelty(SimpleNamespace(proxy_sources={}))
        self.assertEqual(result['candidate_endpoints'], 0)
        self.assertEqual(result['feeds'], [])


if __name__ == '__main__':
    unittest.main()
