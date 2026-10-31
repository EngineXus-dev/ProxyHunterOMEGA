#!/usr/bin/env python3
"""Harvest public feeds with source health, caching, and protocol provenance."""
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from pathlib import Path
import re
from urllib.parse import urlencode, urlsplit, parse_qs, urlunsplit

import requests

from constants import (SOURCES_GITHUB, SOURCES_API, TELEGRAM_CHANNELS, GIST_QUERIES,
                       SOURCES_HTML, SOURCES_TOR, SOURCES_VPNGATE)
from source_engine import SourceFetcher, extract_proxies, normalize_protocol
from ui import cp, G, Y
from run_control import bounded_results, data_dir


def make_session(proxies=None, ua=None):
    session = requests.Session()
    session.headers['User-Agent'] = ua or 'ProxyHunter/2 public-feed-reader'
    if proxies:
        session.trust_env = False
        session.proxies.update(proxies)
    return session


def begin_scrape(state):
    state.source_health = {}
    state.proxy_protocols = {}
    state.proxy_sources = {}
    state.filtered = {}
    state.filtered_ready = False
    state.stage_counts = {}
    state.profile_warnings = []
    state.history_stats = {}


def _record(state, report, category, results):
    report = dict(report)
    entries = report.pop('entries', [])
    report['category'] = ('github' if urlsplit(report['url']).hostname in ('raw.githubusercontent.com', 'github.com', 'gist.githubusercontent.com') else 'direct') if category == 'github/api' else category
    allowed = set(state.settings['protocols'])
    accepted = 0
    for endpoint, proto in entries:
        proto = normalize_protocol(proto)
        if proto not in allowed and not (proto == 'https' and 'http' in allowed):
            continue
        state.proxy_protocols.setdefault(endpoint, set()).add(proto)
        state.proxy_sources.setdefault(endpoint, set()).add(report['url'])
        results.setdefault(endpoint, proto)
        accepted += 1
    report['accepted'] = accepted
    state.source_health[report['url']] = report
    return entries


def source_summary(state):
    reports = list(state.source_health.copy().values())
    good = {'OK', 'NOT_MODIFIED'}
    return {'total': len(reports), 'healthy': sum(r['status'] in good for r in reports),
            'cached': sum(r['status'] == 'STALE_CACHE' for r in reports),
            'empty': sum(r['status'] == 'EMPTY' for r in reports),
            'unsupported': sum(r['status'] in {'UNSUPPORTED', 'OTHER_TRANSPORTS'} for r in reports),
            'failed': sum(r['status'] not in good | {'STALE_CACHE', 'EMPTY', 'UNSUPPORTED', 'OTHER_TRANSPORTS'} for r in reports)}


def source_novelty(state):
    """Per-feed overlap within this run; not proof of third-party exclusivity.

    Count on endpoint identity rather than source-list line counts, so a feed
    that repackages another cannot claim those shared endpoints as exclusive.
    """
    from collections import Counter
    seen = Counter()
    sole_source = Counter()
    for sources in state.proxy_sources.values():
        urls = set(sources)
        for url in urls:
            seen[url] += 1
        if len(urls) == 1:
            sole_source[next(iter(urls))] += 1
    return {
        "definition": "sole_source means observed in exactly one configured feed in this hunt, not verified unique on the Internet",
        "candidate_endpoints": len(state.proxy_sources),
        "feeds": [
            {"url": url, "candidate_endpoints": count,
             "sole_source_endpoints": sole_source[url],
             "shared_endpoints": count - sole_source[url]}
            for url, count in sorted(seen.items(), key=lambda item: (-sole_source[item[0]], -item[1], item[0]))
        ],
    }


def save_hunt_report(state):
    from collections import Counter
    from datetime import datetime, timezone
    path = data_dir() / 'latest_hunt.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {'finished_at': datetime.now(timezone.utc).isoformat(),
               'sources': source_summary(state), 'community_sources': community_source_diagnostics(state),
               'source_novelty': source_novelty(state),
               'source_health': list(state.source_health.copy().values()),
               'stages': dict(state.stage_counts), 'raw_count': len(state.raw_proxies),
               'valid_count': len(state.valid),
               'profile_warnings': list(state.profile_warnings),
               'history': dict(state.history_stats), 'cancelled': state.control.is_cancelled(),
               'classifications': dict(Counter(p.get('threat_tag', 'UNKNOWN') for p in state.profiled))}
    path.write_text(json.dumps(payload, indent=2), encoding='utf-8')
    return path


def _harvest(state, tasks, category, proxies=None):
    results = {}
    fetcher = SourceFetcher(state.settings, cancelled=state.control.is_cancelled)
    unique = list(dict.fromkeys(tasks))
    def worker(item):
        url, proto, kind = item
        try:
            return fetcher.fetch(url, proto, kind, proxies)
        except Exception as exc:
            return {'url': url, 'status': 'ERROR', 'count': 0,
                    'entries': [], 'error': f'{type(exc).__name__}: {exc}'}
    for _, report in bounded_results(state, worker, unique, state.settings['scrape_threads']):
        _record(state, report, category, results)
    related = [state.source_health[url] for url, _, _ in unique if url in state.source_health]
    failed = sum(r['status'] not in ('OK', 'NOT_MODIFIED', 'EMPTY', 'STALE_CACHE', 'OTHER_TRANSPORTS') for r in related)
    cached = sum(r['status'] == 'STALE_CACHE' for r in related)
    print(f"  {cp(G, '[+]')} {category}: {len(results)} candidates; {failed} failed sources; {cached} cache fallbacks.")
    return results, len(results)


def community_manifest_path():
    """Source manifest is always resolved beside the installed scraper module."""
    return Path(__file__).resolve().parent / 'community_sources.json'


def load_community_manifest():
    """Return the actual installed JSON manifest; no network requests."""
    path = community_manifest_path()
    data = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data, list):
        raise ValueError('Community sources must be a JSON array.')
    for index, source in enumerate(data):
        if not isinstance(source, dict):
            raise ValueError(f'Community source #{index + 1} is not an object.')
        if not isinstance(source.get('name'), str) or not source['name'].strip():
            raise ValueError(f'Community source #{index + 1} requires a name.')
        if source.get('protocol') not in ('http', 'https', 'socks4', 'socks5'):
            raise ValueError(f'Community source #{index + 1} requires a supported protocol.')
        if source.get('format', 'plain') != 'plain':
            raise ValueError(f'Community source #{index + 1} must use plain format.')
        parsed = urlsplit(source.get('url', ''))
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError(f'Community source #{index + 1} requires an HTTPS feed URL without credentials.')
        if not isinstance(source.get('enabled', True), bool):
            raise ValueError(f'Community source #{index + 1} requires a boolean enabled flag.')
    urls = [s['url'] for s in data]
    if len(set(urls)) != len(urls):
        raise ValueError('Duplicate community feed URL in manifest.')
    return data


def community_source_diagnostics(state):
    """Current source visibility; all counts are from this run, not upstream claims."""
    try:
        manifest = load_community_manifest()
    except (OSError, ValueError, TypeError) as exc:
        return {'manifest': str(community_manifest_path()), 'error': str(exc), 'sources': [],
                'enabled': 0, 'scheduled': 0, 'disabled': 0}
    allowed = set(state.settings.get('protocols', ['http', 'https', 'socks4', 'socks5']))
    non_github = state.settings.get('non_github', False)
    community_on = state.settings.get('src_community', True)
    items = []
    for source in manifest:
        hostname = urlsplit(source['url']).hostname
        scheduled = (community_on and source.get('enabled', True)
                     and (source['protocol'] in allowed or source['protocol'] == 'https' and 'http' in allowed)
                     and not (non_github and hostname in ('raw.githubusercontent.com', 'github.com', 'gist.githubusercontent.com')))
        health = state.source_health.get(source['url'], {}) if scheduled else {}
        items.append({'name': source['name'], 'url': source['url'],
                      'enabled': source.get('enabled', True), 'scheduled': scheduled,
                      'status': health.get('status', 'NOT_RUN' if scheduled else ('DISABLED' if not source.get('enabled', True) else 'SKIPPED')),
                      'http_status': health.get('http_status'),
                      'accepted_candidates': health.get('accepted', 0),
                      'cached': health.get('cache', 'none'),
                      'error': health.get('error')})
    return {'manifest': str(community_manifest_path()),
            'enabled': sum(s['enabled'] for s in items),
            'scheduled': sum(s['scheduled'] for s in items),
            'disabled': sum(not s['enabled'] for s in items),
            'sources': items}


def _extra_sources(state):
    path = community_manifest_path()
    configured = list(state.settings.get('extra_sources', []))
    if path.exists():
        try:
            configured.extend(load_community_manifest())
        except (OSError, ValueError, TypeError) as exc:
            state.source_health[str(path)] = {'url': str(path), 'category': 'community',
                'status': 'CONFIG_ERROR', 'count': 0, 'error': str(exc)}
    tasks = []
    for source in configured[:50]:
        if not isinstance(source, dict) or not source.get('enabled', True):
            continue
        url = source.get('url', '')
        if state.settings.get('non_github') and urlsplit(url).hostname in ('raw.githubusercontent.com', 'github.com', 'gist.githubusercontent.com'):
            continue
        if urlsplit(url).scheme != 'https':
            continue
        proto = source.get('protocol', 'http')
        if proto not in state.settings.get('protocols', ['http', 'https', 'socks4', 'socks5']) and not (proto == 'https' and 'http' in state.settings.get('protocols', ['http', 'https', 'socks4', 'socks5'])):
            continue
        tasks.append((url, proto, source.get('format', 'plain')))
    return tasks


def scrape_one_url(url, proto, session):
    from source_engine import parse_payload
    response = session.get(url, timeout=15)
    return parse_payload(response.text, proto)[0] if response.status_code == 200 else []


def scrape_github_api(state):
    settings = state.settings
    allowed = set(settings['protocols'])
    tasks = []
    if settings['src_github']:
        tasks.extend((u, p, 'plain') for u, p, tier in SOURCES_GITHUB
                     if tier <= settings['source_tier'] and (p in allowed or p == 'auto' or p == 'https' and 'http' in allowed))
    if settings['src_api']:
        for url, proto, tier in SOURCES_API:
            if tier > settings['source_tier'] or proto not in allowed:
                continue
            pages = settings.get('api_pages', 3) if 'proxylist.geonode.com' in url else 1
            for page in range(1, max(1, min(5, pages)) + 1):
                parts = urlsplit(url)
                query = parse_qs(parts.query)
                if pages > 1:
                    query['page'] = [str(page)]
                tasks.append((urlunsplit(parts._replace(query=urlencode(query, doseq=True))), proto, 'plain'))
    if settings.get('src_community', True):
        tasks = _extra_sources(state) + tasks
    diagnostics = community_source_diagnostics(state)
    if diagnostics.get('error'):
        print(f"  [sources] Manifest error: {diagnostics['error']}")
    else:
        print(f"  [sources] Community feeds: {diagnostics['scheduled']} scheduled / "
              f"{diagnostics['disabled']} disabled; manifest: {diagnostics['manifest']}")
    results, count = _harvest(state, tasks, 'github/api')
    diagnostics = community_source_diagnostics(state)
    for feed in diagnostics['sources']:
        if not feed['scheduled']:
            continue
        print(f"    [feed] {feed['status']:<15} {feed['accepted_candidates']:>6} parsed  "
              f"{feed['name']}  cache={feed['cached']}" + (f"  [{feed['error']}]" if feed['error'] else ''))
    return results, count


def scrape_telegram(state):
    if not state.settings.get('src_telegram'):
        return {}, 0
    channels = list(dict.fromkeys(TELEGRAM_CHANNELS + state.settings.get('extra_telegram', [])))
    channels = [channel for channel in channels if re.fullmatch(r'[A-Za-z0-9_]{3,64}', channel)]
    tasks = [(f'https://t.me/s/{channel}', 'socks5' if 'socks5' in channel.lower() else 'http', 'telegram')
             for channel in channels]
    results, _ = _harvest(state, tasks, 'telegram')
    seen = set(url for url, _, _ in tasks)
    for _ in range(max(0, min(5, state.settings.get('telegram_pages', 3)) - 1)):
        if state.control.is_cancelled():
            break
        pages = []
        for url, proto, _ in tasks:
            cursor = state.source_health.get(url, {}).get('metadata', {}).get('cursor')
            next_url = url.split('?')[0] + f'?before={cursor}' if cursor else None
            if next_url and next_url not in seen:
                seen.add(next_url)
                pages.append((next_url, proto, 'telegram'))
        if not pages:
            break
        more, _ = _harvest(state, pages, 'telegram')
        results.update(more)
        tasks = pages
    return results, len(results)


def scrape_html(state):
    if not state.settings.get('src_html'):
        return {}, 0
    return _harvest(state, [(u, 'http', 'html') for u in SOURCES_HTML], 'html')


def scrape_gists(state):
    if not state.settings.get('src_gists'):
        return {}, 0
    tasks = [('https://gist.github.com/search?' + urlencode({'q': q, 's': 'updated'}), 'http', 'gist_index')
             for q in GIST_QUERIES]
    results, _ = _harvest(state, tasks, 'gists')
    raw = []
    for url, _, _ in tasks:
        for gid in state.source_health.get(url, {}).get('metadata', {}).get('links', []):
            raw.append((f'https://gist.githubusercontent.com/{gid}/raw', 'http', 'plain'))
    more, _ = _harvest(state, raw, 'gists')
    results.update(more)
    return results, len(results)


def scrape_tor(state):
    if not state.settings.get('src_tor'):
        return {}, 0
    urls = [url for url in SOURCES_TOR + state.settings.get('extra_tor_sources', [])
            if re.fullmatch(r'[a-z2-7]{56}\.onion', urlsplit(url).hostname or '')]
    if not urls:
        print(f"  {cp(Y, '[!]')} Tor: no current v3 public feeds configured.")
        return {}, 0
    proxies = {'http': state.settings['tor_proxy'], 'https': state.settings['tor_proxy']}
    return _harvest(state, [(u, 'http', 'plain') for u in urls], 'tor', proxies=proxies)


def scrape_vpngate(state):
    from vpngate_client import harvest_vpngate
    return harvest_vpngate(state)
