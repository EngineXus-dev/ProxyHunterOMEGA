#!/usr/bin/env python3
import ipaddress
import socket
import time
import threading
from urllib.parse import urlsplit

import requests

from constants import TEST_URLS
from run_control import bounded_results, operation
from scan_history import ScanHistory, endpoint_key, protocol_key
from ui import cp, G, R, C, progress_bar
from async_ports import probe_ports


def port_open(proxy_str, timeout=1.5):
    try:
        parsed = urlsplit(proxy_str if '://' in proxy_str else 'http://' + proxy_str)
        with socket.create_connection((parsed.hostname, parsed.port or 80), timeout=timeout):
            return True
    except OSError:
        return False


def build_proxy_dict(proxy_str, proto):
    if '://' in proxy_str:
        return {'http': proxy_str, 'https': proxy_str}
    scheme = {'socks5': 'socks5h', 'socks5h': 'socks5h', 'socks4': 'socks4a',
              'socks4a': 'socks4a', 'https': 'https'}.get(proto, 'http')
    return {'http': f'{scheme}://{proxy_str}', 'https': f'{scheme}://{proxy_str}'}


_session_local = threading.local()


def validation_session():
    """Keep a small connection pool per validation thread; never share Session objects."""
    if not hasattr(_session_local, 'session'):
        session = requests.Session()
        session.trust_env = False
        adapter = requests.adapters.HTTPAdapter(pool_connections=32, pool_maxsize=8, max_retries=0)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        _session_local.session = session
    return _session_local.session


def validate_one(proxy_str, proto, timeout, aggregated=False, cancelled=None,
                 max_test_urls=None, session=None, test_urls=None):
    proxies = build_proxy_dict(proxy_str, proto)
    urls = tuple(test_urls) if test_urls is not None else TEST_URLS[:max_test_urls] if max_test_urls else TEST_URLS
    for url in urls:
        if cancelled and cancelled():
            return None
        try:
            started = time.monotonic()
            response = (session.get if session else requests.get)(url, proxies=proxies, headers={'User-Agent': 'ProxyHunter/2'},
                                    timeout=timeout, allow_redirects=False)
            if response.status_code != 200:
                continue
            try:
                exit_ip = response.json().get('ip', '')
            except (ValueError, AttributeError):
                exit_ip = response.text.strip()
            exit_ip = str(ipaddress.ip_address(exit_ip))
            result = {'proxy': proxy_str, 'proto': proto, 'exit_ip': exit_ip,
                      'latency': round(time.monotonic() - started, 2), 'checked_at': time.time()}
            if aggregated:
                result.update(source='Scrapoxy', rotating=True)
            return result
        except (requests.RequestException, ValueError, TypeError):
            continue
    return None


def _managed(state, endpoint):
    return endpoint in state.scrapoxy_endpoints or endpoint in state.vpngate_endpoints or endpoint in state.extra_gateway_sources


def run_port_filter(state, interactive=True, progress_callback=None):
    if interactive and not state.control.active:
        with operation(state):
            return run_port_filter(state, interactive=False, progress_callback=progress_callback)
    source = state.filtered if state.filtered_ready or state.filtered else state.raw_proxies
    total = len(source)
    alive, work = {}, []
    completed = reused = 0
    threads, timeout = state.settings['port_threads'], state.settings['port_timeout']
    print(f"\n  {cp(C, '[*]')} Port check {total} proxies ({threads} workers, {timeout}s). Ctrl+C cancels.\n")
    with ScanHistory(state.settings) as history:
        cached = history.recent('port')
        for endpoint, proto in source.items():
            if state.control.is_cancelled():
                break
            previous = None if _managed(state, endpoint) else cached.get(endpoint_key(endpoint))
            if previous is not None:
                completed += 1
                reused += 1
                if previous[0]:
                    alive[endpoint] = proto
            else:
                work.append((endpoint, proto))

        def worker(item):
            endpoint, _ = item
            if state.control.is_cancelled():
                return None
            opened = port_open(endpoint, timeout)
            if not opened and state.settings.get('port_retries', 1):
                if state.control.is_cancelled():
                    return None
                opened = port_open(endpoint, max(2, timeout * 1.5))
            return opened

        last_progress = 0.0

        def complete(item, opened):
            nonlocal completed, last_progress
            endpoint, proto = item
            if opened is None:
                return
            completed += 1
            if opened:
                alive[endpoint] = proto
            if not _managed(state, endpoint):
                history.record('port', endpoint_key(endpoint), opened)
            now = time.monotonic()
            if now - last_progress >= 0.2 or completed == total:
                if not state.settings.get('quiet_progress'):
                    print(f"  {progress_bar(completed, total)} {len(alive)} open {completed}/{total}", end='\r')
                if progress_callback:
                    progress_callback(completed, total, len(alive))
                last_progress = now

        if state.settings.get('port_engine') == 'async':
            probe_ports(work, threads, timeout, state.control.is_cancelled,
                        complete, retry=bool(state.settings.get('port_retries', 0)))
        else:
            for item, opened in bounded_results(state, worker, work, threads):
                complete(item, opened)
    state.filtered, state.filtered_ready = alive, True
    state.history_stats['port_reused'] = reused
    state.stage_counts['ports'] = {'input': total, 'processed': completed, 'kept': len(alive),
                                  'dropped': completed - len(alive), 'reused': reused,
                                  'cancelled': state.control.is_cancelled()}
    print(f"\n  {len(alive)} open; {completed - len(alive)} closed; {reused} prior checks reused.")


def run_validate(state, interactive=True, progress_callback=None):
    if interactive and not state.control.active:
        with operation(state):
            return run_validate(state, interactive=False, progress_callback=progress_callback)
    source = state.filtered if state.filtered_ready or state.filtered else state.raw_proxies
    total, valid, completed, reused = len(source), [], 0, 0
    print(f"\n  {cp(C, '[*]')} Validating {total} endpoints ({state.settings['threads']} workers).\n")
    with ScanHistory(state.settings) as history:
        cached = history.recent('validation')

        def worker(item):
            endpoint, default = item
            choices = [default] + sorted(state.proxy_protocols.get(endpoint, set()) - {default})
            if state.settings.get('resource_profile') == 'turbo':
                # Limit protocol fallback time; prefer a broad recheck on slower profiles.
                choices = choices[:2]
            checked = []
            for proto in choices:
                if state.control.is_cancelled():
                    return None, checked, False
                previous = None if _managed(state, endpoint) else cached.get(protocol_key(endpoint, proto))
                if previous is not None:
                    if previous[0] and previous[1]:
                        return dict(previous[1], validation_cached=True), checked, True
                    continue
                fast = state.settings.get('resource_profile') == 'turbo'
                options = dict(aggregated=endpoint in state.scrapoxy_endpoints,
                               cancelled=state.control.is_cancelled)
                if fast:
                    options.update(max_test_urls=state.settings.get('validation_test_urls', 1),
                                   session=validation_session())
                result = validate_one(endpoint, proto, state.settings['timeout'], **options)
                if state.control.is_cancelled() and result is None:
                    return None, checked, False
                checked.append((proto, result))
                if result:
                    if endpoint in state.vpngate_endpoints:
                        result.update(source='VPNGate', rotating=False)
                    if endpoint in state.extra_gateway_sources:
                        result.update(source=state.extra_gateway_sources[endpoint], rotating=True)
                    result['sources'] = sorted(state.proxy_sources.get(endpoint, []))
                    return result, checked, False
            return None, checked, False

        last_progress = 0.0
        for (endpoint, _), (result, checked, was_cached) in bounded_results(state, worker, source.items(), state.settings['threads']):
            completed += 1
            reused += int(was_cached)
            if result:
                valid.append(result)
            if not _managed(state, endpoint):
                for proto, outcome in checked:
                    history.record('validation', protocol_key(endpoint, proto), outcome is not None, outcome)
            now = time.monotonic()
            if now - last_progress >= 0.2 or completed == total:
                if not state.settings.get('quiet_progress'):
                    print(f"  {progress_bar(completed, total)} {len(valid)} live {completed}/{total}", end='\r')
                if progress_callback:
                    progress_callback(completed, total, len(valid))
                last_progress = now
    state.valid = valid
    state.history_stats['validation_reused'] = reused
    state.stage_counts['validation'] = {'input': total, 'processed': completed, 'kept': len(valid),
        'dropped': completed - len(valid), 'reused': reused, 'cancelled': state.control.is_cancelled()}
    print(f"\n  {cp(G, str(len(valid)))} live; {reused} prior validations reused.")
