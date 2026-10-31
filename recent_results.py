"""Current-run snapshots and explicit opt-in export, separate from historical lists."""
from datetime import datetime, timezone
import csv
import io
import json
import os
from pathlib import Path
import tempfile

from run_control import data_dir
from network_classification import evidence_tag, distinct_exit_count

RESULTS_FILE = 'latest_results.json'
INTERRUPTED_FILE = 'interrupted_results.json'


def _minimal(record):
    allowed = ('proxy', 'proto', 'exit_ip', 'latency', 'checked_at', 'threat_tag',
               'score', 'source', 'rotating', 'sources', 'isp', 'org', 'hosting', 'country', 'asn', 'asn_org', 'type', 'access_type_verified', 'access_type_evidence',
               'validation_cached', 'confirmed', 'confirmation_checked_at',
               'confirmation_checks', 'confirmation_method')
    result = {k: record[k] for k in allowed if k in record}
    if 'threat_tag' in result:
        result['threat_tag'] = evidence_tag(result)
    result['access_type_verified'] = False
    return result


def save_latest(state):
    folder = data_dir()
    folder.mkdir(parents=True, exist_ok=True)
    complete = getattr(state, 'pipeline_result', None) == 'completed' and not state.control.is_cancelled()
    path = folder / (RESULTS_FILE if complete else INTERRUPTED_FILE)
    by_proxy = {(p.get('proxy'), p.get('proto')): _minimal(p) for p in state.valid}
    for p in state.profiled:
        key = (p.get('proxy'), p.get('proto'))
        if key in by_proxy:
            by_proxy[key].update(_minimal(p))
    payload = {
        'schema': 2,
        'distinct_observed_exit_ips': distinct_exit_count(list(by_proxy.values())),
        'residential_access_proven': 0,
        'mobile_access_proven': 0,
        'finished_at_utc': datetime.now(timezone.utc).isoformat(),
        'result': getattr(state, 'pipeline_result', 'unknown'),
        'cancelled': state.control.is_cancelled(),
        'note': ('Latest COMPLETED hunt; endpoints passed two HTTPS checks at that time. ISP/carrier affiliation is NOT residential/mobile access proof.'
                 if complete else 'Interrupted or incomplete hunt; not the latest completed verified list.'),
        'validated': list(by_proxy.values()),
    }
    # Replace atomically. Avoid accidentally exposing endpoints and credentials via permissions.
    fd, temporary = tempfile.mkstemp(prefix='.latest-', suffix='.tmp', dir=folder)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as output:
            os.chmod(temporary, 0o600)
            json.dump(payload, output, indent=2)
            output.write('\n')
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return path


def atomic_write_text(destination, value):
    """Replace a text export without ever appending stale endpoints."""
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.verified-', dir=destination.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            os.chmod(tmp, 0o600)
            f.write(value)
        os.replace(tmp, destination)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def export_latest(destination):
    source = data_dir() / RESULTS_FILE
    if not source.is_file():
        raise FileNotFoundError('No completed hunt yet. Finish a hunt first.')
    data = json.loads(source.read_text(encoding='utf-8'))
    rows = [dict(row, threat_tag=evidence_tag(row), access_type_verified=False) for row in data['validated'] if isinstance(row, dict)]
    data = dict(data, validated=rows, residential_access_proven=0, mobile_access_proven=0,
                distinct_observed_exit_ips=distinct_exit_count(rows))
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    suffix = destination.suffix.lower()
    if suffix == '.json':
        value = json.dumps(data, indent=2) + '\n'
    elif suffix == '.csv':
        cols = ('proxy', 'proto', 'exit_ip', 'latency', 'checked_at', 'threat_tag', 'source')
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=cols, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)
        value = output.getvalue()
    elif suffix == '.txt':
        value = '\n'.join(dict.fromkeys(row['proxy'] for row in rows if row.get('proxy')))
        value += '\n' if value else ''
    else:
        raise ValueError('Choose a .txt, .csv, or .json file')
    # No exports into the program's source folder by default; explicitly chosen path.
    fd, tmp = tempfile.mkstemp(prefix='.export-', dir=destination.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            os.chmod(tmp, 0o600)
            f.write(value)
        os.replace(tmp, destination)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return len(rows)
