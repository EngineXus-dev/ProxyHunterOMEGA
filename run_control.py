"""Cooperative cancellation and bounded work queues for the terminal and desktop."""
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextlib import contextmanager
import json
import os
from pathlib import Path
import signal
import sys
import threading
import time
import uuid


def data_dir():
    return Path(os.getenv("PROXYHUNTER_DATA_DIR", str(Path(__file__).resolve().parent / ".cache")))


class RunControl:
    def __init__(self):
        self.event = threading.Event()
        self.reason = ""
        self.request_file = None
        self._next_check = 0.0
        self.active = False

    def cancel(self, reason="Cancelled by operator"):
        self.reason = reason
        self.event.set()

    def is_cancelled(self):
        if self.event.is_set():
            return True
        now = time.monotonic()
        if self.request_file and now >= self._next_check:
            self._next_check = now + 0.2
            if self.request_file.exists():
                self.cancel("Cancellation requested from another terminal")
        return self.event.is_set()

    def wait(self, seconds):
        deadline = time.monotonic() + max(0, seconds)
        while not self.is_cancelled():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            self.event.wait(min(0.2, remaining))
        return True


@contextmanager
def operation(state):
    control = state.control
    control.event.clear()
    control.reason = ""
    control.active = True
    run_id = uuid.uuid4().hex
    folder = data_dir() / "runs"
    folder.mkdir(parents=True, exist_ok=True)
    registration = folder / f"{os.getpid()}.json"
    control.request_file = folder / f"{os.getpid()}-{run_id}.cancel"
    registration.write_text(json.dumps({"pid": os.getpid(), "run_id": run_id,
        "cancel_file": str(control.request_file.resolve()), "started": time.time()}), encoding="utf-8")
    originals = {}
    stop_keyboard = threading.Event()
    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGINT, getattr(signal, "SIGBREAK", signal.SIGINT)):
            if sig not in originals:
                originals[sig] = signal.getsignal(sig)
                signal.signal(sig, lambda *_: control.cancel("Keyboard interrupt"))
    if os.name == "nt" and sys.stdin.isatty():
        def keyboard():
            import msvcrt
            while not stop_keyboard.wait(0.1):
                if msvcrt.kbhit():
                    if msvcrt.getwch().lower() in ("q", "\x1b", "\x03"):
                        control.cancel("Q / Esc pressed")
                        return
        threading.Thread(target=keyboard, daemon=True).start()
    try:
        yield control
    except KeyboardInterrupt:
        control.cancel("Keyboard interrupt")
    finally:
        stop_keyboard.set()
        for sig, handler in originals.items():
            signal.signal(sig, handler)
        registration.unlink(missing_ok=True)
        control.request_file.unlink(missing_ok=True)
        control.request_file = None
        control.active = False


def bounded_results(state, worker, items, workers):
    """At most 2×workers futures exist; cancellation never drains a giant queue."""
    workers = max(1, int(workers))
    iterator = iter(items)
    pool = ThreadPoolExecutor(max_workers=workers)
    pending = {}

    def submit():
        while len(pending) < workers * 2 and not state.control.is_cancelled():
            try:
                item = next(iterator)
            except StopIteration:
                break
            pending[pool.submit(worker, item)] = item

    try:
        submit()
        while pending and not state.control.is_cancelled():
            completed, _ = wait(pending, timeout=0.1, return_when=FIRST_COMPLETED)
            for future in completed:
                item = pending.pop(future)
                yield item, future.result()
            submit()
    except KeyboardInterrupt:
        state.control.cancel("Keyboard interrupt")
    finally:
        for future in pending:
            future.cancel()
        pool.shutdown(wait=True, cancel_futures=True)


def request_cancel(pid=None):
    folder = data_dir() / "runs"
    count = 0
    for path in folder.glob(f"{pid}.json" if pid else "*.json"):
        record = json.loads(path.read_text(encoding="utf-8"))
        target = Path(record["cancel_file"]).resolve()
        if target.parent != folder.resolve():
            continue
        target.write_text("cancel", encoding="utf-8")
        count += 1
    return count
