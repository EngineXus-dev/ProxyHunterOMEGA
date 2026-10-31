"""Public-feed parsing, bounded retries, and explicitly labelled last-good caching."""
import hashlib
import html
from html.parser import HTMLParser
import ipaddress
import json
from pathlib import Path
import re
import time
from urllib.parse import parse_qs, quote, urlsplit
from run_control import data_dir
import uuid

import requests

PROTOCOLS = {"http", "https", "socks4", "socks5"}
PARSER_VERSION = 2
ANY_URI_RE = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s<>\"']+", re.I)
OTHER_TRANSPORT_RE = re.compile(r"\b(ssr?|vmess|vless|trojan|hysteria2?|tuic)://", re.I)
URI_RE = re.compile(r"\b(https?|socks4a?|socks5h?)://(?:[^\s<>\"'@/]+@)?(?:\[[0-9a-f:.]+\]|\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}(?!\d)", re.I)
BARE_RE = re.compile(r"(?<![\w.:])(?:\[[0-9a-fA-F:.]+\]|\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}(?!\d)")
SOCKS_LINK_RE = re.compile(r"(?:tg://socks|https?://t\.me/socks)\?[^\s<>\"']+", re.I)
CACHE_DIR = data_dir() / "sources"


def normalize_protocol(proto):
    proto = str(proto).lower()
    return {"socks4a": "socks4", "socks5h": "socks5"}.get(proto, proto)


def proxy_address(value):
    parsed = urlsplit(value if "://" in value else "http://" + value)
    return parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)


def candidate(value, default_proto="http"):
    try:
        explicit = "://" in value
        parsed = urlsplit(value if explicit else "http://" + value)
        proto = normalize_protocol(parsed.scheme if explicit else default_proto)
        address = ipaddress.ip_address(parsed.hostname or "")
        port = parsed.port
        if proto not in PROTOCOLS or not address.is_global or port is None or not 1 <= port <= 65535:
            return None
        host = f"[{address}]" if address.version == 6 else str(address)
        endpoint = f"{host}:{port}"
        if parsed.username is not None:
            endpoint = value
        return endpoint, proto
    except (ValueError, TypeError):
        return None


def extract_proxies(text, default_proto="http"):
    text = html.unescape(str(text))
    found = []
    spans = [match.span() for match in ANY_URI_RE.finditer(text)]
    for match in URI_RE.finditer(text):
        entry = candidate(match.group(), default_proto)
        if entry:
            found.append(entry)
    for match in SOCKS_LINK_RE.finditer(text):
        query = parse_qs(urlsplit(match.group()).query)
        host, port = query.get("server", [""])[0], query.get("port", [""])[0]
        username, password = query.get("user", [""])[0], query.get("pass", [""])[0]
        auth = f"{quote(username, safe='')}:{quote(password, safe='')}@" if username or password else ""
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        entry = candidate(f"socks5://{auth}{host}:{port}")
        if entry:
            found.append(entry)
    span_index = 0
    for match in BARE_RE.finditer(text):
        while span_index < len(spans) and spans[span_index][1] <= match.start():
            span_index += 1
        if span_index < len(spans) and spans[span_index][0] <= match.start() < spans[span_index][1]:
            continue
        entry = candidate(match.group(), default_proto)
        if entry:
            found.append(entry)
    return list(dict.fromkeys(found))


class ProxyTableParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.rows, self.row, self.cell = [], None, None

    def handle_starttag(self, tag, attrs):
        if tag == "tr":
            self.row = []
        elif tag == "td" and self.row is not None:
            self.cell = []

    def handle_data(self, data):
        if self.cell is not None:
            self.cell.append(data)

    def handle_endtag(self, tag):
        if tag == "td" and self.cell is not None:
            self.row.append("".join(self.cell).strip())
            self.cell = None
        elif tag == "tr" and self.row is not None:
            self.rows.append(self.row)
            self.row = None


def parse_payload(text, default_proto="http", kind="plain"):
    entries, metadata = [], {}
    transports = sorted({match.group(1).lower() for match in OTHER_TRANSPORT_RE.finditer(text)})
    if transports:
        metadata["other_transports"] = transports
    if text.lstrip().startswith(("[", "{")):
        try:
            data = json.loads(text)
        except ValueError:
            data = None

        def walk(value):
            if isinstance(value, list):
                for item in value:
                    walk(item)
            elif isinstance(value, dict):
                host = value.get("ip") or value.get("host") or value.get("ipAddress")
                port = value.get("port")
                if host and port:
                    protocols = value.get("protocols") or value.get("protocol") or [default_proto]
                    protocols = [protocols] if isinstance(protocols, str) else protocols
                    host = f"[{host}]" if ":" in str(host) and not str(host).startswith("[") else host
                    for proto in protocols:
                        entry = candidate(f"{host}:{port}", proto)
                        if entry:
                            entries.append(entry)
                for key, item in value.items():
                    if key not in ("ip", "host", "ipAddress", "port", "protocols", "protocol"):
                        walk(item)
            elif isinstance(value, str):
                entries.extend(extract_proxies(value, default_proto))

        if data is not None:
            walk(data)
            if isinstance(data, dict):
                metadata["has_more"] = bool(data.get("data"))
            return list(dict.fromkeys(entries)), metadata
    entries = extract_proxies(text, default_proto)
    if kind == "html":
        parser = ProxyTableParser()
        parser.feed(text)
        for row in parser.rows:
            if len(row) >= 2:
                entry = candidate(f"{row[0]}:{row[1]}", default_proto)
                if entry:
                    entries.append(entry)
    if kind == "telegram":
        ids = [int(i) for i in re.findall(r'data-post=["\'][^/]+/(\d+)', text)]
        metadata["cursor"] = min(ids) if ids else None
    if kind == "gist_index":
        metadata["links"] = list(dict.fromkeys(re.findall(
            r'href="/([a-zA-Z0-9][a-zA-Z0-9-]*/[a-f0-9]{20,})"', text)))[:8]
    return list(dict.fromkeys(entries)), metadata


class SourceFetcher:
    def __init__(self, settings=None, cache_dir=None, session_factory=None, cancelled=None):
        self.settings = settings or {}
        self.cache_dir = Path(cache_dir if cache_dir is not None else self.settings.get("source_cache_dir", CACHE_DIR))
        self.session_factory = session_factory or requests.Session
        self.cancelled = cancelled or (lambda: False)

    def fetch(self, url, proto="http", kind="plain", proxies=None):
        started = time.monotonic()
        path = self.cache_dir / (hashlib.sha256(f"{PARSER_VERSION}:{kind}:{proto}:{url}".encode()).hexdigest() + ".json")
        cached = None
        if self.settings.get("source_cache_enabled", True):
            try:
                cached = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(cached.get("entries"), list) or not isinstance(cached.get("fetched_at"), (int, float)):
                    cached = None
            except (OSError, ValueError, AttributeError):
                pass
        headers = {"User-Agent": "ProxyHunter/2 public-feed-reader"}
        if cached:
            if cached.get("etag"):
                headers["If-None-Match"] = cached["etag"]
            if cached.get("last_modified"):
                headers["If-Modified-Since"] = cached["last_modified"]
        result = {"url": url, "status": "ERROR", "http_status": None, "attempts": 0,
                  "count": 0, "entries": [], "metadata": {}, "cache": "none", "error": None}
        retries = max(0, min(3, int(self.settings.get("scrape_retries", 2))))
        with self.session_factory() as session:
            if proxies:
                session.trust_env = False
                session.proxies.update(proxies)
            for attempt in range(retries + 1):
                if self.cancelled():
                    result.update(status="CANCELLED", error="Operation cancelled")
                    break
                result["attempts"] = attempt + 1
                retry_after = 0
                try:
                    response = session.get(url, headers=headers, timeout=self.settings.get("scrape_timeout", 15))
                    status = response.status_code
                    result["http_status"] = status
                    if status == 304 and cached:
                        result.update(status="NOT_MODIFIED", entries=cached["entries"],
                                      metadata=cached.get("metadata", {}), cache="revalidated", error=None)
                        cached["fetched_at"] = time.time()
                        self._save(path, cached, result)
                        break
                    if status == 304:
                        headers.pop("If-None-Match", None)
                        headers.pop("If-Modified-Since", None)
                        result["error"] = "304 response without a local cached body."
                    elif status == 200:
                        entries, metadata = parse_payload(response.text, proto, kind)
                        result.update(status="OK" if entries or metadata.get("links") else "EMPTY",
                                      entries=entries, metadata=metadata, error=None)
                        if not entries and not metadata.get("links") and any(marker in response.text[:4000].lower()
                                for marker in ("cf-chl-", "challenge-platform", "verify you are human", "captcha")):
                            result.update(status="BLOCKED", error="Source returned an access challenge.")
                        elif not entries and metadata.get("other_transports"):
                            result.update(status="OTHER_TRANSPORTS", error="Contains Shadowsocks/V2Ray links; use the Xray pipeline.")
                        elif not entries and kind == "telegram" and metadata.get("cursor") is None:
                            result.update(status="NO_PUBLIC_POSTS", error="No public channel posts are accessible; the channel may be missing, private, or a user/bot.")
                        if entries or metadata.get("links"):
                            self._save(path, {"fetched_at": time.time(), "etag": response.headers.get("ETag"),
                                             "last_modified": response.headers.get("Last-Modified"),
                                             "entries": entries, "metadata": metadata}, result)
                        break
                    else:
                        result["status"] = {404: "NOT_FOUND", 410: "NOT_FOUND", 403: "BLOCKED", 429: "RATE_LIMITED"}.get(status, "HTTP_ERROR")
                        result["error"] = f"HTTP {status}"
                        if status not in (408, 429, 500, 502, 503, 504):
                            break
                        try:
                            retry_after = float(response.headers.get("Retry-After", 0))
                        except (ValueError, TypeError):
                            pass
                        if retry_after > 3:
                            break
                except requests.RequestException as exc:
                    result["status"] = "TIMEOUT" if isinstance(exc, requests.Timeout) else "NETWORK_ERROR"
                    result["error"] = type(exc).__name__
                except (ValueError, TypeError) as exc:
                    result["status"] = "PARSE_ERROR"
                    result["error"] = type(exc).__name__
                    break
                if attempt < retries:
                    time.sleep(max(retry_after, min(2, 0.25 * 2 ** attempt)))
        if result["status"] not in ("OK", "EMPTY", "NOT_MODIFIED", "NOT_FOUND", "OTHER_TRANSPORTS", "CANCELLED") and cached:
            age = max(0, time.time() - cached["fetched_at"])
            if age <= self.settings.get("source_cache_max_age", 86400):
                result.update(status="STALE_CACHE", cache="fallback", cache_age_seconds=round(age),
                              entries=cached["entries"], metadata=cached.get("metadata", {}))
        result["entries"] = [tuple(entry) for entry in result["entries"]]
        result["count"] = len(result["entries"])
        result["elapsed"] = round(time.monotonic() - started, 3)
        return result

    def _save(self, path, data, result):
        if not self.settings.get("source_cache_enabled", True):
            return
        temporary = path.with_suffix("." + uuid.uuid4().hex + ".tmp")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary.write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")
            temporary.replace(path)
        except OSError as exc:
            result["cache_warning"] = f"Cache write failed: {type(exc).__name__}"
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
