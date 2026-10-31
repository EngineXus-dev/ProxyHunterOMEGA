"""Independent, current-run confirmation of HTTP/SOCKS exits.

Two distinct HTTPS echo services must agree on a global, publicly routable exit
IP. This is a point-in-time traffic check, NOT proof of authorization, privacy,
residential status, or future uptime. No historical cache can satisfy a check.
"""
import ipaddress
import time

from run_control import bounded_results
from validator import validate_one, validation_session

# Deliberately fixed, independent TLS endpoints. No untrusted source controls these.
CONFIRMATION_URLS = (
    'https://api.ipify.org?format=json',
    'https://checkip.amazonaws.com',
)


def confirm_one(row, timeout=7, cancelled=None, session=None, check=validate_one):
    """Return fresh confirmation metadata or None after either failure/mismatch."""
    if cancelled and cancelled():
        return None
    endpoint, protocol = row.get('proxy'), row.get('proto')
    if not endpoint or not protocol:
        return None
    observed = []
    for url in CONFIRMATION_URLS:
        if cancelled and cancelled():
            return None
        result = check(endpoint, protocol, timeout, cancelled=cancelled,
                       test_urls=(url,), session=session)
        if not result:
            return None
        try:
            ip = ipaddress.ip_address(result['exit_ip'])
        except (ValueError, KeyError, TypeError):
            return None
        if not ip.is_global:
            return None
        observed.append(str(ip))
    if observed[0] != observed[1]:
        return None
    return {'confirmed': True, 'exit_ip': observed[0],
            'confirmation_checked_at': time.time(),
            'confirmation_checks': len(CONFIRMATION_URLS),
            'confirmation_method': 'two_independent_https_echo_services'}


def run_confirmation(state, progress_callback=None):
    """Check all current-run validated proxies; discard every unconfirmed entry.

    Cancellation never publishes a new completed result; the caller handles it.
    """
    candidates = list(state.valid)
    original_profiles = {(r.get('proxy'), r.get('proto')): r for r in state.profiled}
    confirmed, confirmed_profiles = [], []
    completed, total = 0, len(candidates)
    workers = min(64, max(1, int(state.settings.get('threads', 12))))
    timeout = max(6.0, float(state.settings.get('timeout', 8)))
    print(f'\n  [*] Independent final confirmation: {total} candidates, {workers} workers, '
          '2 HTTPS exit-IP checks per endpoint.\n')

    def check(row):
        if state.control.is_cancelled():
            return None
        return confirm_one(row, timeout=timeout, cancelled=state.control.is_cancelled,
                           session=validation_session())

    for row, evidence in bounded_results(state, check, candidates, workers):
        completed += 1
        if evidence:
            item = dict(row, **evidence)
            confirmed.append(item)
            profile = original_profiles.get((row.get('proxy'), row.get('proto')))
            if profile is not None:
                confirmed_profiles.append(dict(profile, **evidence))
            else:
                # Keep a validated endpoint even if classification is not available.
                confirmed_profiles.append(dict(item, threat_tag='UNKNOWN_COMMUNITY'))
        if progress_callback:
            progress_callback(completed, total, len(confirmed))
    state.stage_counts['confirmation'] = {
        'input': total, 'processed': completed, 'confirmed': len(confirmed),
        'rejected': completed - len(confirmed), 'cancelled': state.control.is_cancelled(),
        'checks_per_candidate': len(CONFIRMATION_URLS),
    }
    if state.control.is_cancelled():
        print(f'  Confirmation cancelled after {completed}/{total}; previous completed exports preserved.')
        return 0
    state.valid = confirmed
    state.profiled = confirmed_profiles
    print(f'  Confirmation complete: {len(confirmed)} confirmed / {total} candidates; '
          f'{total-len(confirmed)} removed from final lists.')
    return len(confirmed)
