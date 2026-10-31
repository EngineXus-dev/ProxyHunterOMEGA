#!/usr/bin/env python3
import os
from run_control import RunControl, data_dir
from constants import SCRAPOXY_DEFAULTS
from scrapoxy_runtime import load_project_config

class State:
    def __init__(self):
        self.raw_proxies = {}
        self.control = RunControl()
        self.history_stats = {}
        self.vpngate = {"status": "NOT_CHECKED", "profiles": 0, "error": None}
        self.vpngate_endpoints = set()
        self.extra_gateway_sources = {}
        self.filtered = {}
        self.valid = []
        self.profiled = []
        self.threat_intel = {}
        self.xray_nodes = []
        self.xray_filtered = []
        self.xray_alive = []
        self.xray_profiled = []
        self.dc_networks = []
        self.last_sources = {}
        self.source_health = {}
        self.proxy_protocols = {}
        self.proxy_sources = {}
        self.stage_counts = {}
        self.profile_warnings = []
        self.previously_verified_endpoints = set()
        self.filtered_ready = False
        self.scrapoxy = {"status": "CHECKING", "error": None, "proxy_count": 0}
        self.scrapoxy_endpoints = set()
        project = load_project_config()
        self.settings = {
            "protocols": ["http", "socks4", "socks5"],
            "source_tier": 2,
            "threads": 12,
            "scrape_threads": 8,
            "port_threads": 32,
            "timeout": 8,
            "port_timeout": 1.5,
            "show_rows": 40,
            "tor_proxy": "socks5://127.0.0.1:9050",
            "src_github": True,
            "src_api": True,
            "src_telegram": False,
            "src_gists": False,
            "src_html": False,
            "src_tor": False,
            "extra_telegram": [],
            "extra_sources": [],
            "src_community": True,
            "extra_tor_sources": [],
            "scrape_timeout": 15,
            "scrape_retries": 2,
            "source_cache_enabled": True,
            "source_cache_max_age": 86400,
            "telegram_pages": 3,
            "api_pages": 3,
            "port_retries": 1,
            "port_engine": "thread",
            "validation_test_urls": 3,
            "resource_profile": "laptop",
            "history_enabled": os.getenv("PROXYHUNTER_HISTORY_ENABLED", "true").lower() not in ("false", "0", "no"),
            "history_path": str(data_dir() / "scan_history.sqlite3"),
            "history_ttl_hours": 24,
            "history_scope": os.getenv("PROXYHUNTER_HISTORY_SCOPE", "local"),
            "recheck": True,
            "vpngate_enabled": False,
            "vpngate_autostart": False,
            "vpngate_max_attempts": 3,
            "vpngate_port": 1088,
            # Scrapoxy Aggregator Settings
            "scrapoxy_url": os.getenv("SCRAPOXY_API_URL", SCRAPOXY_DEFAULTS["api_url"]),
            "scrapoxy_proxy": os.getenv("SCRAPOXY_PROXY_URL", SCRAPOXY_DEFAULTS["proxy_url"]),
            "scrapoxy_user": os.getenv("SCRAPOXY_USERNAME", project.get("username", "")),
            "scrapoxy_pass": os.getenv("SCRAPOXY_PASSWORD", project.get("password", "")),
            "scrapoxy_enabled": os.getenv("SCRAPOXY_ENABLED", "false").lower() not in ("0", "false", "no"),
            "scrapoxy_autostart": os.getenv("SCRAPOXY_AUTOSTART", "false").lower() not in ("0", "false", "no")
                and not any(os.getenv(key) for key in ("SCRAPOXY_API_URL", "SCRAPOXY_PROXY_URL", "SCRAPOXY_USERNAME", "SCRAPOXY_PASSWORD")),
            # Deep Threat Intel & Behavioral Profiling
            "deep_profiling": True,
            "asn_enrichment": True,
            "threat_ioc_check": True,
            "filter_botnets": False,
        }

