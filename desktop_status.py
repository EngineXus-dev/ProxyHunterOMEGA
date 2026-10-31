"""Local, aggregate-only progress channel from the console to the native launcher.

Progress reporting is advisory: Windows file-sharing conflicts, anti-virus scans,
or unwritable cache directories must NEVER terminate a hunt.
"""
import errno
import json
import os
from pathlib import Path
import tempfile
import time
import uuid

from run_control import data_dir

STATUS_FILE = 'desktop_status.json'
STAGES = ('INGEST', 'CIDR', 'PORT CHECK', 'VALIDATION', 'PROFILING')
COUNTER_KEYS = ('scraped', 'skipped_recent', 'dropped', 'ports_alive', 'valid', 'confirmed', 'isp_candidates')
FINAL_RESULTS = frozenset(('completed', 'harvested', 'no_new_candidates', 'no_results', 'cancelled', 'error'))
# Windows raises WinError 5 (access denied), 32 (sharing violation), or 33
# (lock violation) when the desktop reader or a security product has a file open.
_RETRYABLE_WINERRORS = frozenset((5, 32, 33))
_RETRYABLE_ERRNOS = frozenset((errno.EACCES, errno.EPERM, errno.EBUSY))
_REPLACE_DELAYS = (0.01, 0.025, 0.05, 0.08, 0.12)
_RETRY_BACKOFF_SECONDS = 1.5


def status_path():
    return data_dir() / STATUS_FILE


def _read_text(path):
    """On Windows share DELETE as well as READ/WRITE to allow atomic os.replace.

    Ordinary CRT file reads may deny FILE_SHARE_DELETE, intermittently making
    os.replace fail with WinError 5 while the Tk status poller holds the file.
    No WinAPI dependency is used on macOS/Linux.
    """
    if os.name != 'nt':
        return path.read_text(encoding='utf-8')

    import ctypes
    from ctypes import wintypes
    import msvcrt

    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    create_file.restype = wintypes.HANDLE
    handle = create_file(str(path), 0x80000000, 0x00000001 | 0x00000002 | 0x00000004,
                         None, 3, 0x80, None)
    if handle == wintypes.HANDLE(-1).value:
        raise OSError(ctypes.get_last_error(), 'Cannot read local status')
    try:
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY)
    except BaseException:
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel32.CloseHandle(handle)
        raise
    # The fd takes ownership of the original Win32 handle; closing it closes
    # the handle. Never call CloseHandle again after open_osfhandle succeeds.
    with os.fdopen(fd, 'r', encoding='utf-8') as stream:
        return stream.read()


def read_status(path=None):
    path = Path(path) if path else status_path()
    try:
        if path.stat().st_size > 16_384:
            return None
        doc = json.loads(_read_text(path))
        return doc if isinstance(doc, dict) and doc.get('schema') == 1 else None
    except (OSError, ValueError, UnicodeError):
        return None


def snapshot_summary(path):
    """Read an opt-in run snapshot; only display aggregate values, never endpoints."""
    path = Path(path)
    if not path.exists():
        return None
    try:
        # Protect the GUI event loop from exceptionally large or corrupted snapshots.
        if path.stat().st_size > 80 * 1024 * 1024:
            raise ValueError('Snapshot is too large to preview; export from the terminal.')
        data = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(data, dict) or not isinstance(data.get('validated'), list):
            raise ValueError('Unsupported snapshot format')
        rows = data['validated']
        counters = {'isp': 0, 'carrier': 0, 'datacenter': 0, 'risk': 0, 'other': 0}
        from network_classification import category, distinct_exit_count
        for entry in rows:
            group = category(entry)
            counters[group] += 1
        return {'total': len(rows), 'counters': counters,
                'distinct_exits': distinct_exit_count(rows),
                'finished_at': str(data.get('finished_at_utc') or ''),
                'result': str(data.get('result') or 'unknown'),
                'cancelled': bool(data.get('cancelled'))}
    except (OSError, ValueError, UnicodeError):
        return {'error': 'Recent results could not be previewed. Check the export file.'}


class ProgressReporter:
    """Best-effort aggregate telemetry, throttled to ~4 updates/second.

    Status is a convenience for the GUI, not a pipeline dependency. During a
    Windows lock conflict, retry the atomic replace briefly and temporarily
    back off. The terminal keeps scanning and later writes can recover.
    """
    def __init__(self, path=None):
        self.path = Path(path) if path else status_path()
        self.run_id = uuid.uuid4().hex
        self._last_write = 0.0
        self._next_retry = 0.0
        self._warned = False
        self._data = {
            'schema': 1, 'run_id': self.run_id, 'pid': os.getpid(),
            'stage': 0, 'name': 'STARTING', 'message': 'Initializing the terminal engine',
            'percent': 0, 'counters': {}, 'result': 'running', 'updated_at': time.time(),
        }
        self._write()

    def _write(self, *, final=False):
        if not final and time.monotonic() < self._next_retry:
            return False
        temp = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._data['updated_at'] = time.time()
            fd, temp = tempfile.mkstemp(prefix='.progress-', suffix='.tmp', dir=self.path.parent)
            # mkstemp already uses restrictive 0600 permissions; no chmod call
            # (which also can produce WinError 5 on Windows/Defender).
            with os.fdopen(fd, 'w', encoding='utf-8') as handle:
                json.dump(self._data, handle, separators=(',', ':'))
            for attempt in range(len(_REPLACE_DELAYS) + 1):
                try:
                    os.replace(temp, self.path)
                    temp = None
                    self._last_write = time.monotonic()
                    self._next_retry = 0.0
                    if self._warned:
                        print('[dashboard] Live progress updates restored.', flush=True)
                    self._warned = False
                    return True
                except OSError as exc:
                    retryable = (getattr(exc, 'winerror', None) in _RETRYABLE_WINERRORS or
                                 exc.errno in _RETRYABLE_ERRNOS)
                    if not retryable or attempt >= len(_REPLACE_DELAYS):
                        raise
                    time.sleep(_REPLACE_DELAYS[attempt])
        except OSError:
            # Never turn a successful hunt into ERROR because an optional GUI
            # telemetry file is locked, read-only, or scanned by antivirus.
            self._next_retry = time.monotonic() + _RETRY_BACKOFF_SECONDS
            if not self._warned:
                print('[dashboard] Live status temporarily unavailable; hunt continues in terminal.', flush=True)
            self._warned = True
            return False
        finally:
            if temp is not None:
                try:
                    os.unlink(temp)
                except OSError:
                    pass

    def update(self, stage, name, message, percent, counters=None):
        # Avoid serializing arbitrary API errors, URLs, endpoints or credentials.
        safe_name = str(name) if name in (*STAGES, 'HARVEST', 'COMPLETED', 'CANCELLED', 'ERROR') else 'RUNNING'
        safe_message = ('See terminal for details' if name == 'ERROR' else
                        str(message)[:160] if name in ('HARVEST', 'CIDR', 'PORT CHECK', 'VALIDATION', 'PROFILING', 'COMPLETED', 'CANCELLED') else '')
        clean = {k: int(v) for k, v in (counters or {}).items()
                 if k in COUNTER_KEYS and isinstance(v, (int, float)) and not isinstance(v, bool)}
        previous_stage = self._data['stage']
        self._data.update(stage=max(0, min(int(stage), 6)), name=safe_name,
                          message=safe_message, percent=max(0, min(int(percent), 100)))
        self._data['counters'].update(clean)
        if (self._data['stage'] != previous_stage or time.monotonic() - self._last_write > 0.25
                or name in ('COMPLETED', 'CANCELLED', 'ERROR')):
            self._write()

    def finish(self, result):
        result = result if result in FINAL_RESULTS else 'error'
        self._data['result'] = result
        self._data['name'] = 'CANCELLED' if result == 'cancelled' else 'ERROR' if result == 'error' else 'COMPLETED'
        self._data['message'] = ('Check terminal for details' if result == 'error' else
                                 'Run cancelled' if result == 'cancelled' else 'Run finished')
        self._data['percent'] = 100 if result not in ('error', 'cancelled') else self._data['percent']
        self._write(final=True)
