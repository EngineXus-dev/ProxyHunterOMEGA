#!/usr/bin/env python3
import time
import threading
import requests
from ui import cp, dim, G, Y, C, R, P, B, RST, safe_input
from constants import IP_API_FIELDS, IP_API_BATCH, RESIDENTIAL_KEYWORDS, MOBILE_KEYWORDS, DC_KEYWORDS
from threat_intelligence import enrich_proxy_intel, threat_badge
from source_engine import proxy_address
from scan_history import ScanHistory, protocol_key
from run_control import operation


class GeoBatchClient:
    """Serialize free batch lookups and honor the provider's 15/minute window."""
    def __init__(self, clock=None, sleep=None, post=None):
        self.clock = clock or time.monotonic
        self.sleep = sleep or time.sleep
        self.post = post
        self.ready_at = 0.0
        self.lock = threading.Lock()
        self.last_error = None

    def lookup(self, payload, cancelled=None, waiter=None):
        with self.lock:
            self.last_error = None
            for attempt in range(3):
                if cancelled and cancelled():
                    self.last_error = "Geolocation cancelled"
                    return [{} for _ in payload]
                delay = max(0, self.ready_at - self.clock())
                if delay:
                    if waiter:
                        if waiter(delay):
                            self.last_error = "Geolocation cancelled"
                            return [{} for _ in payload]
                    else:
                        self.sleep(delay)
                try:
                    response = (self.post or requests.post)(IP_API_BATCH, json=payload, timeout=15)
                    try:
                        remaining = int(response.headers.get("X-Rl", -1))
                        reset = max(0, float(response.headers.get("X-Ttl", 60)))
                    except (TypeError, ValueError):
                        remaining, reset = -1, 60
                    wait = max(4.1, reset) if remaining == 0 or response.status_code == 429 else 4.1
                    self.ready_at = self.clock() + wait
                    if response.status_code == 429:
                        self.last_error = "Geolocation rate limit; waiting for the provider reset."
                        continue
                    if response.status_code == 200:
                        data = response.json()
                        if isinstance(data, list) and len(data) == len(payload):
                            self.last_error = None
                            return data
                        self.last_error = "Unexpected geolocation batch response."
                    else:
                        self.last_error = f"Geolocation HTTP {response.status_code}"
                    return [{} for _ in payload]
                except (requests.RequestException, ValueError) as exc:
                    self.ready_at = self.clock() + 4.1
                    self.last_error = f"Geolocation request failed: {type(exc).__name__}"
                    if attempt == 2:
                        break
            return [{} for _ in payload]


GEO_CLIENT = GeoBatchClient()

def classify_type(isp, org, hosting):
    """Provider-affiliation hints only; not proof of fixed residential/mobile access.

    Never infer mobile from generic `wireless`, `4g`, `5g`, or `lte` in
    network/business names: those can describe broadband providers and equipment.
    """
    from constants import DC_KEYWORDS, RESIDENTIAL_KEYWORDS
    txt = f"{isp} {org}".lower()
    if hosting or any(keyword in txt for keyword in DC_KEYWORDS):
        return "datacenter"
    mobile_carrier_names = (
        't-mobile', 'tmobile', 'verizon wireless', 'at&t mobility',
        'boost mobile', 'cricket wireless', 'metro pcs', 'us cellular',
        'airtel mobile', 'jio mobile',
    )
    if any(name in txt for name in mobile_carrier_names):
        return "carrier_unverified"
    if any(keyword in txt for keyword in RESIDENTIAL_KEYWORDS):
        return "isp_unverified"
    return "unknown"

def score_proxy(latency, ptype, hosting):
    if latency < 0.5:
        speed = 40
    elif latency < 1.0:
        speed = 35
    elif latency < 2.0:
        speed = 25
    elif latency < 3.0:
        speed = 15
    elif latency < 5.0:
        speed = 5
    else:
        speed = 0
    tscores = {"isp_unverified": 20, "carrier_unverified": 20, "unknown": 20, "datacenter": 5}
    return min(100, speed + tscores.get(ptype, 20) + (0 if hosting else 20))

def run_profile(state, deep_mode=True, interactive=True, progress_callback=None):
    if interactive and not state.control.active:
        with operation(state):
            return run_profile(state, deep_mode=deep_mode, interactive=False, progress_callback=progress_callback)
    total = len(state.valid)
    profiled, pending, geo_cache = [], [], {}
    missing_geo = reused = 0
    state.profile_warnings = []
    with ScanHistory(state.settings) as history:
        cached = history.recent('profile')
        for entry in state.valid:
            previous = cached.get(protocol_key(entry['proxy'], entry.get('proto', 'http')))
            if (not state.settings.get('recheck', False) and previous and previous[1] and
                    not previous[1].get('imported_export') and
                    previous[1].get('exit_ip') == entry.get('exit_ip') and
                    entry['proxy'] not in state.scrapoxy_endpoints and entry['proxy'] not in state.vpngate_endpoints and entry['proxy'] not in state.extra_gateway_sources):
                profiled.append(dict(previous[1], profile_cached=True))
                reused += 1
            else:
                pending.append(entry)
        chunks = [pending[index:index + 100] for index in range(0, len(pending), 100)]
        print(f'\n  Profiling {len(pending)} live proxies; {reused} completed profiles reused.\n')
        for chunk in chunks:
            if state.control.is_cancelled():
                break
            ips = [p.get('exit_ip') or proxy_address(p['proxy'])[0] for p in chunk]
            missing_ips = list(dict.fromkeys(ip for ip in ips if ip not in geo_cache))
            if missing_ips:
                payload = [{'query': ip, 'fields': IP_API_FIELDS} for ip in missing_ips]
                data = GEO_CLIENT.lookup(payload, cancelled=state.control.is_cancelled, waiter=state.control.wait)
                for ip, info in zip(missing_ips, data):
                    if isinstance(info, dict) and info.get('status') == 'success':
                        geo_cache[ip] = info
                if GEO_CLIENT.last_error:
                    state.profile_warnings.append(GEO_CLIENT.last_error)
            if state.control.is_cancelled():
                break
            for pd, ip in zip(chunk, ips):
                if state.control.is_cancelled():
                    break
                geo = geo_cache.get(ip, {})
                if not geo:
                    missing_geo += 1
                isp, org, hosting = geo.get('isp', 'Unknown'), geo.get('org', ''), geo.get('hosting', False)
                ptype = classify_type(isp, org, hosting)
                base = dict(pd, isp=isp, org=org, hosting=hosting, type=ptype,
                            country=geo.get('country', '?'), cc=geo.get('countryCode', '?'),
                            city=geo.get('city', '?'), score=score_proxy(pd['latency'], ptype, hosting))
                if not geo:
                    base['profile_error'] = 'Geolocation enrichment unavailable; classification is incomplete.'
                result = enrich_proxy_intel(base, geo) if deep_mode else base
                profiled.append(result)
                if geo and pd['proxy'] not in state.scrapoxy_endpoints and pd['proxy'] not in state.vpngate_endpoints and pd['proxy'] not in state.extra_gateway_sources:
                    history.record('profile', protocol_key(pd['proxy'], pd.get('proto', 'http')), True, result)
            if progress_callback:
                progress_callback(len(profiled), total)
    state.profiled = sorted(profiled, key=lambda p: p.get('trust_score' if deep_mode else 'score', 0), reverse=True)
    state.history_stats['profile_reused'] = reused
    state.stage_counts['profile'] = {'input': total, 'processed': len(profiled),
        'enriched': len(profiled) - missing_geo, 'incomplete': missing_geo, 'reused': reused,
        'cancelled': state.control.is_cancelled()}
    if missing_geo:
        warning = f'{missing_geo} live proxies have incomplete geolocation enrichment.'
        state.profile_warnings.append(warning)
        print(f"  {cp(Y, '[!]')} {warning}")
    from network_classification import candidate_groups, distinct_exit_count
    groups = candidate_groups(profiled)
    print(f'\n  Profiling complete: {len(profiled)} processed; '
          f'{len(groups["isp"])} ISP-affiliated candidates / {len(groups["carrier"])} carrier candidates '
          f'(access type UNVERIFIED); {distinct_exit_count(profiled)} distinct observed exit IPs.\n')
