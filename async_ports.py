"""Bounded, asynchronous TCP reachability checks (not a proxy validation).

No daemon and no external dependencies. The caller supplies state-controlled
cancellation and consumes completed results in the main thread.
"""
import asyncio
from urllib.parse import urlsplit


def _address(endpoint):
    parts = urlsplit(endpoint if '://' in endpoint else 'http://' + endpoint)
    if not parts.hostname or not parts.port or not 1 <= parts.port <= 65535:
        raise ValueError('Invalid endpoint')
    return parts.hostname, parts.port


async def _check(endpoint, timeout):
    try:
        host, port = _address(endpoint)
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        # A TCP handshake is enough; waiting for remote shutdown slows probes.
        return True
    except (ValueError, OSError, asyncio.TimeoutError, RuntimeError):
        return False


async def _run(items, concurrency, timeout, cancelled, callback, retry=False):
    iterator = iter(items)
    pending = {}
    concurrency = max(1, min(1000, int(concurrency)))

    def fill():
        while len(pending) < concurrency and not cancelled():
            try:
                item = next(iterator)
            except StopIteration:
                break
            pending[asyncio.create_task(_check(item[0], timeout))] = item

    fill()
    try:
        while pending and not cancelled():
            done, _ = await asyncio.wait(pending, timeout=0.15, return_when=asyncio.FIRST_COMPLETED)
            for future in done:
                item = pending.pop(future)
                result = future.result()
                if not result and retry and not cancelled():
                    result = await _check(item[0], max(2.0, timeout * 1.5))
                callback(item, result)
            fill()
    finally:
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)


def probe_ports(items, concurrency, timeout, cancelled, callback, retry=False):
    """Run from a non-async terminal. Report only completed probes."""
    return asyncio.run(_run(items, concurrency, timeout, cancelled, callback, retry))
