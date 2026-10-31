"""Persistent completed-check history. Incomplete work is never marked finished."""
import json
from pathlib import Path
import sqlite3
import time
from run_control import data_dir
from source_engine import proxy_address


def endpoint_key(endpoint):
    host, port = proxy_address(endpoint)
    return f"{host}:{port}"


def protocol_key(endpoint, proto):
    # Credentials and advertised transport matter for authenticated proxies.
    return f"{proto}|{endpoint}"


class ScanHistory:
    def __init__(self, settings):
        self.enabled = settings.get("history_enabled", True) and not settings.get("recheck", False)
        self.settings = settings
        self.connection = None
        self.pending = 0
        self.last_commit = time.monotonic()
        self.cutoff = time.time() - settings.get("history_ttl_hours", 24) * 3600
        self.scope = settings.get("history_scope", "local")

    def __enter__(self):
        if self.settings.get("history_enabled", True):
            path = Path(self.settings.get("history_path") or data_dir() / "scan_history.sqlite3")
            path.parent.mkdir(parents=True, exist_ok=True)
            self.connection = sqlite3.connect(path, timeout=10)
            self.connection.execute("PRAGMA journal_mode=WAL")
            self.connection.execute("PRAGMA synchronous=NORMAL")
            self.connection.execute("CREATE TABLE IF NOT EXISTS checks(stage TEXT,key TEXT,checked REAL,success INTEGER,data TEXT,PRIMARY KEY(stage,key))")
            self.connection.execute("CREATE INDEX IF NOT EXISTS idx_checks_stage_checked ON checks(stage, checked)")
            self.connection.commit()
        return self

    def recent(self, stage):
        if not self.enabled or not self.connection:
            return {}
        rows = self.connection.execute(
            "SELECT key,success,data FROM checks WHERE checked>=? AND "
            "((stage=? AND (success=1 OR ?='local')) OR stage=?) ORDER BY checked",
            (self.cutoff, stage, self.scope, stage + "@" + self.scope))
        return {key: (bool(success), json.loads(data) if data else None) for key, success, data in rows}

    def record(self, stage, key, success, data=None, checked_at=None):
        if self.connection:
            if stage in ("port", "validation") and not success:
                stage = stage + "@" + self.scope
            self.connection.execute("INSERT OR REPLACE INTO checks VALUES(?,?,?,?,?)",
                (stage, key, time.time() if checked_at is None else checked_at, int(success), json.dumps(data) if data is not None else None))
            self.pending += 1
            if self.pending >= 200 or time.monotonic() - self.last_commit >= 1:
                self.connection.commit()
                self.pending = 0
                self.last_commit = time.monotonic()

    def __exit__(self, *_):
        if self.connection:
            self.connection.commit()
            self.connection.close()


def select_unseen(state):
    with ScanHistory(state.settings) as history:
        ports, validated, profiled = (history.recent(stage) for stage in ("port", "validation", "profile"))
    kept, skipped = {}, 0
    for endpoint, proto in state.raw_proxies.items():
        if endpoint in state.scrapoxy_endpoints or endpoint in state.vpngate_endpoints or endpoint in state.extra_gateway_sources:
            kept[endpoint] = proto
            continue
        port_result = ports.get(endpoint_key(endpoint))
        choices = state.proxy_protocols.get(endpoint) or {proto}
        complete = all((protocol_key(endpoint, choice) in profiled or
                        protocol_key(endpoint, choice) in validated and not validated[protocol_key(endpoint, choice)][0])
                       for choice in choices)
        if port_result and not port_result[0] or complete:
            skipped += 1
        else:
            kept[endpoint] = proto
    state.raw_proxies = kept
    state.history_stats["skipped_recent"] = skipped
    state.history_stats["scope"] = state.settings.get("history_scope", "local")
    print(f"  History: skipped {skipped} recently completed endpoints; {len(kept)} need work.")
    return skipped


def seed_known_exports(state):
    """Only exported successes are recoverable from versions without scan history."""
    root = Path(__file__).resolve().parent
    if state.settings.get("recheck"):
        return
    paths = [root / "clean_residential_verified.txt", root / "Clean" / "clean_residential_verified.txt"]
    with ScanHistory(state.settings) as history:
        known = history.recent("profile")
        for path in paths:
            if not path.exists():
                continue
            if path.stat().st_mtime < history.cutoff:
                continue
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                key = protocol_key(line.strip(), "http")
                if key not in known:
                    history.record("profile", key, True, {"proxy": line.strip(), "proto": "http", "imported_export": True}, checked_at=path.stat().st_mtime)


def restore_verified_candidates(state, output_dir=None):
    """Re-introduce previously validated endpoints for a NEW run, even if sources drop them.

    The local history is private; nothing in it is shipped with public releases.
    An endpoint is only accepted after syntax/public-IP checks and fresh validation.
    """
    from source_engine import candidate
    from recent_results import RESULTS_FILE
    rows = []
    with ScanHistory(state.settings) as history:
        if history.connection is not None:
            for (data,) in history.connection.execute(
                    "SELECT data FROM checks WHERE success=1 AND stage IN ('validation', 'profile') AND data IS NOT NULL"):
                try:
                    record = json.loads(data)
                except (TypeError, ValueError):
                    continue
                if isinstance(record, dict):
                    rows.append(record)
    path = data_dir() / RESULTS_FILE
    if path.is_file():
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
            rows.extend(row for row in data.get('validated', []) if isinstance(row, dict))
        except (OSError, ValueError, TypeError):
            pass
    # Legacy clean lists can survive migration without a SQLite database.
    folder = Path(output_dir or state.settings.get('output_dir') or Path(__file__).resolve().parent)
    for file_name in ('clean_residential_verified.txt', 'clean_mobile_verified.txt',
                      'clean_residential_mobile_combined.txt'):
        legacy = folder / file_name
        if legacy.is_file():
            try:
                rows.extend({'proxy': raw.strip(), 'proto': 'http'} for raw in
                            legacy.read_text(encoding='utf-8').splitlines() if raw.strip())
            except OSError:
                pass
    added = 0
    previously_verified = set()
    for row in rows:
        value = row.get('proxy')
        protocol = row.get('proto', 'http')
        if not isinstance(value, str) or not isinstance(protocol, str):
            continue
        parsed = candidate(value, protocol)
        if parsed is None:
            continue
        endpoint, proto = parsed
        state.proxy_protocols.setdefault(endpoint, set()).add(proto)
        previously_verified.add(endpoint)
        state.previously_verified_endpoints.add(endpoint)
        if endpoint not in state.raw_proxies:
            added += 1
            state.raw_proxies[endpoint] = proto
        elif row.get('exit_ip'):
            # The previously successful transport takes priority over a newly
            # harvested guessed protocol. Especially important in Turbo, which
            # limits protocol fallbacks.
            state.raw_proxies[endpoint] = proto
        # The harvester stores source provenance as sets (scraper._record).
        # Legacy/manual state can still contain a list, so normalize it here.
        # Using list.append() on harvested sets used to crash the whole hunt
        # after optional gateways connected, before CIDR/port probing began.
        sources = state.proxy_sources.setdefault(endpoint, set())
        if not isinstance(sources, set):
            sources = set(sources)
            state.proxy_sources[endpoint] = sources
        sources.add('previously_validated_local_history')
    state.history_stats['previously_verified_reintroduced'] = added
    state.history_stats['previously_verified_rechecked'] = len(previously_verified)
    return added


def prune_obsolete_successes(state):
    """Forget historical successes for endpoints tested in a fully completed fresh run.

    Keeps older positives that were *not* attempted (e.g. explicit max_candidates).
    Ports which failed or no longer pass validation cannot reappear indefinitely
    merely because an old success remains in the history database.
    """
    if not state.settings.get('recheck', True):
        return 0
    scanned = {endpoint_key(e) for e in state.raw_proxies}
    verified = {endpoint_key(p['proxy']) for p in state.valid if p.get('proxy')}
    stale = scanned - verified
    if not stale:
        return 0
    deleted = 0
    with ScanHistory(state.settings) as history:
        if history.connection is None:
            return 0
        # Restrict the scan to positive histories, which are typically small.
        positive_rows = history.connection.execute(
                "SELECT stage,key,data FROM checks WHERE success=1 AND stage IN ('validation','profile')").fetchall()
        for stage, key, raw in positive_rows:
            try:
                data = json.loads(raw) if raw else None
                endpoint = data.get('proxy') if isinstance(data, dict) else None
                if endpoint and endpoint_key(endpoint) in stale:
                    history.connection.execute('DELETE FROM checks WHERE stage=? AND key=?', (stage, key))
                    deleted += 1
            except (ValueError, TypeError):
                continue
        history.connection.commit()
    state.history_stats['expired_previously_verified'] = deleted
    return deleted
