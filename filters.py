#!/usr/bin/env python3
from bisect import bisect_right
import ipaddress
import time
import requests
from ui import cp, P, G, Y, progress_bar
from constants import DC_CIDRS_FALLBACK, CIDR_FETCH_URLS
from source_engine import proxy_address
from run_control import operation


def load_dc_networks(lines):
    result = []
    for line in lines:
        try:
            result.append(ipaddress.ip_network(line.strip(), strict=False))
        except ValueError:
            continue
    return result


class NetworkIndex:
    def __init__(self, networks):
        self.intervals = {}
        for version in (4, 6):
            merged = []
            for start, end in sorted((int(net.network_address), int(net.broadcast_address))
                                     for net in networks if net.version == version):
                if merged and start <= merged[-1][1] + 1:
                    merged[-1] = (merged[-1][0], max(merged[-1][1], end))
                else:
                    merged.append((start, end))
            self.intervals[version] = ([start for start, _ in merged], [end for _, end in merged])

    def contains(self, address):
        starts, ends = self.intervals[address.version]
        value = int(address)
        position = bisect_right(starts, value) - 1
        return position >= 0 and value <= ends[position]


def fetch_fresh_cidrs(state=None):
    print(f"\n  {cp(P, '[*]')} Fetching DC CIDR list ...", end='', flush=True)
    for url in CIDR_FETCH_URLS:
        if state is not None and state.control.is_cancelled():
            break
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                networks = load_dc_networks(response.text.splitlines())
                if networks:
                    print(f' {len(networks)} ranges loaded')
                    return networks
        except requests.RequestException:
            pass
    result = load_dc_networks(DC_CIDRS_FALLBACK)
    print(f' fallback ({len(result)} ranges)')
    return result


def run_cidr_filter(state, interactive=True, progress_callback=None):
    if interactive and not state.control.active:
        with operation(state):
            return run_cidr_filter(state, interactive=False, progress_callback=progress_callback)
    if not state.dc_networks:
        state.dc_networks = fetch_fresh_cidrs(state)
    index = NetworkIndex(state.dc_networks)
    total, kept, dropped, processed = len(state.raw_proxies), {}, 0, 0
    last_progress = 0.0
    print(f'\n  CIDR filtering {total} proxies using an indexed network lookup.\n')
    for endpoint, proto in state.raw_proxies.items():
        if state.control.is_cancelled():
            break
        processed += 1
        if (endpoint in state.previously_verified_endpoints or endpoint in state.scrapoxy_endpoints
                or endpoint in state.vpngate_endpoints or endpoint in state.extra_gateway_sources):
            kept[endpoint] = proto
        else:
            try:
                address = ipaddress.ip_address(proxy_address(endpoint)[0])
                if index.contains(address):
                    dropped += 1
                else:
                    kept[endpoint] = proto
            except ValueError:
                dropped += 1
        now = time.monotonic()
        if now - last_progress >= 0.2 or processed == total:
            if not state.settings.get('quiet_progress'):
                print(f'  {progress_bar(processed, total)} {len(kept)} kept; {dropped} dropped', end='\r')
            if progress_callback:
                progress_callback(processed, total, len(kept), dropped)
            last_progress = now
    state.filtered, state.filtered_ready = kept, True
    state.stage_counts['cidr'] = {'input': total, 'processed': processed, 'kept': len(kept),
                                 'dropped': dropped, 'cancelled': state.control.is_cancelled()}
    print(f'\n  {len(kept)} kept; {dropped} DC ranges / invalid addresses dropped.\n')
