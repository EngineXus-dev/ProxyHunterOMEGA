"""One unattended pipeline shared by the TUI, CLI, native desktop launcher and notebooks."""
from contextlib import nullcontext
from pathlib import Path
import json
import shutil
import time

from run_control import operation, data_dir
from scan_history import select_unseen, restore_verified_candidates, prune_obsolete_successes
from scraper import (begin_scrape, scrape_github_api, scrape_telegram, scrape_html,
                     scrape_gists, scrape_vpngate, save_hunt_report)
from filters import run_cidr_filter
from validator import run_port_filter, run_validate
from profiler import run_profile
from confirmation import run_confirmation
from scrapoxy_aggregator import pull_scrapoxy_into_state
from recent_results import save_latest

PROFILES = {
    "laptop": (32, 12, 8),
    "notebook": (32, 16, 6),
    "server": (128, 40, 16),
    "quiet": (128, 12, 6),
    "balanced": (256, 24, 12),
    "turbo": (1000, 64, 24),
}


def apply_resource_profile(state, name):
    ports, validation, scraping = PROFILES[name]
    state.settings.update(resource_profile=name, port_threads=ports, threads=validation,
                          scrape_threads=scraping, port_engine='async' if name in ('turbo', 'balanced', 'quiet') else 'thread',
                          port_retries=0 if name == 'turbo' else 1,
                          validation_test_urls=1 if name == 'turbo' else 3,
                          timeout=4 if name == 'turbo' else 8)


def export_results(state, output_dir=None):
    folder = Path(output_dir or state.settings.get("output_dir") or Path(__file__).resolve().parent)
    folder.mkdir(parents=True, exist_ok=True)
    from network_classification import candidate_groups, distinct_exit_count
    groups_by_evidence = candidate_groups(state.profiled)
    isp = groups_by_evidence['isp']
    carrier = groups_by_evidence['carrier']
    others = groups_by_evidence['other']
    groups = {
        'isp_network_candidates_live.txt': isp,
        'carrier_network_candidates_live.txt': carrier,
        'other_live.txt': others,
        'all_confirmed_live.txt': state.profiled,
        # Legacy names must NOT contain unsubstantiated residential/mobile claims.
        'potential_residential_live.txt': [],
        'potential_mobile_live.txt': [],
        'clean_residential_verified.txt': [],
        'clean_mobile_verified.txt': [],
        'clean_residential_mobile_combined.txt': [],
    }
    from recent_results import atomic_write_text
    for name, rows in groups.items():
        # A completed hunt is a fresh snapshot, never an accumulating stale list.
        endpoints = list(dict.fromkeys(p['proxy'] for p in rows))
        content = "\n".join(endpoints) + ("\n" if endpoints else "")
        atomic_write_text(folder / name, content)
        if name in ('isp_network_candidates_live.txt', 'carrier_network_candidates_live.txt',
                    'other_live.txt', 'all_confirmed_live.txt',
                    'potential_residential_live.txt', 'potential_mobile_live.txt'):
            # Plain ip:port alone loses SOCKS/HTTP protocol information.
            # Also publish a scheme-qualified version for unambiguous use.
            uri_rows = []
            for entry in rows:
                endpoint = entry['proxy']
                proto = entry.get('proto', 'http')
                uri_rows.append(endpoint if '://' in endpoint else f'{proto}://{endpoint}')
            uris = list(dict.fromkeys(uri_rows))
            atomic_write_text(folder / name.replace('.txt', '_protocols.txt'),
                              "\n".join(uris) + ("\n" if uris else ""))
    (folder / "threat_intelligence_audit.json").write_text(json.dumps(state.profiled, indent=2), encoding="utf-8")
    return len(isp) + len(carrier)


def execute_pipeline(state, full=False, progress=None, log=None, harvest_only=False, output_dir=None):
    log = log or print
    progress = progress or (lambda *args: None)
    state.pipeline_result = "running"

    def update(stage, name, message, percent, counters=None):
        progress(stage, name, message, percent, counters or {})

    context = nullcontext() if state.control.active else operation(state)
    with context:
        try:
            begin_scrape(state)
            state.raw_proxies = {}
            state.previously_verified_endpoints.clear()
            state.valid = []
            state.profiled = []
            state.scrapoxy_endpoints.clear()
            state.vpngate_endpoints.clear()
            state.extra_gateway_sources.clear()
            state.vpngate = {"status": "NOT_CHECKED", "profiles": 0, "error": None}
            if full:
                state.settings.update(src_telegram=True, src_html=True, src_gists=not state.settings.get("non_github", False))
            log(f"Workers: port={state.settings['port_threads']}, validation={state.settings['threads']}, scrape={state.settings['scrape_threads']}.")
            log("Cancel with Ctrl+C; Q / Esc also work in the Windows terminal. Completed checks are saved.")
            update(1, "HARVEST", "Fetching public sources...", 1)
            results = {}
            stages = [("GitHub / direct APIs / community feeds", scrape_github_api),
                      ("Telegram", scrape_telegram), ("HTML", scrape_html)]
            if state.settings.get("src_gists"):
                stages.append(("Gists", scrape_gists))
            if state.settings.get("vpngate_enabled") and shutil.which("docker"):
                stages.append(("VPNGate", scrape_vpngate))
            for name, harvest in stages:
                if state.control.is_cancelled():
                    return state
                found, _ = harvest(state)
                added = len(set(found) - results.keys())
                results.update(found)
                if name != "VPNGate":
                    log(f"{name}: {len(found)} found; {added} new; {len(found) - added} duplicates.")
                update(1, "HARVEST", f"{name} finished; {len(results)} unique endpoints.", 15,
                       {"scraped": len(results)})
            state.raw_proxies = results
            if state.settings.get("scrapoxy_enabled") and not state.control.is_cancelled():
                pull_scrapoxy_into_state(state)
            harvested = len(state.raw_proxies)
            if state.control.is_cancelled():
                return state
            if state.settings.get('recheck', True):
                restored = restore_verified_candidates(state, output_dir=output_dir)
                count = state.history_stats.get('previously_verified_rechecked', 0)
                log(f"  History: {count} previously verified endpoints selected for fresh checks "
                    f"({restored} not present in current sources); 0 previous checks reused.")
            else:
                select_unseen(state)
            maximum = state.settings.get("max_candidates")
            if maximum and len(state.raw_proxies) > maximum:
                def priority(item):
                    endpoint, _ = item
                    managed = endpoint in state.scrapoxy_endpoints or endpoint in state.vpngate_endpoints or endpoint in state.extra_gateway_sources
                    from urllib.parse import urlsplit
                    urls = state.proxy_sources.get(endpoint, [])
                    direct = any(urlsplit(url).hostname not in ("raw.githubusercontent.com", "github.com", "gist.githubusercontent.com") for url in urls)
                    return managed, direct, len(urls)
                state.raw_proxies = dict(sorted(state.raw_proxies.items(), key=priority, reverse=True)[:maximum])
            log(f"Harvested {harvested}; {len(state.raw_proxies)} eligible after scan history.")
            if harvest_only or not state.raw_proxies:
                state.pipeline_result = "harvested" if harvest_only else "no_new_candidates"
                update(6, "COMPLETED", "Harvest complete." if harvest_only else "No new candidates need checking.", 100,
                       {"scraped": harvested, "skipped_recent": state.history_stats.get("skipped_recent", 0)})
                return state
            update(2, "CIDR", "Filtering known datacenter ranges...", 18)
            run_cidr_filter(state, interactive=False, progress_callback=lambda done, total, kept, dropped:
                update(2, "CIDR", f"CIDR: {done}/{total}", 18 + int(16 * done / max(1, total)), {"dropped": dropped}))
            if state.control.is_cancelled():
                return state
            if not state.filtered:
                prune_obsolete_successes(state)
                export_results(state, output_dir)
                state.pipeline_result = 'completed'
                update(6, 'COMPLETED', 'No candidates survived CIDR screening; fresh lists are empty.', 100)
                return state
            update(3, "PORT CHECK", "Checking responsive ports...", 35)
            run_port_filter(state, interactive=False, progress_callback=lambda done, total, alive:
                update(3, "PORT CHECK", f"Ports: {done}/{total}; {alive} open", 35 + int(27 * done / max(1, total)), {"ports_alive": alive}))
            if state.control.is_cancelled():
                return state
            if not state.filtered:
                prune_obsolete_successes(state)
                export_results(state, output_dir)
                state.pipeline_result = 'completed'
                update(6, 'COMPLETED', 'No open ports; prior verified results were removed.', 100)
                return state
            update(4, "VALIDATION", "Verifying proxy traffic...", 63)
            run_validate(state, interactive=False, progress_callback=lambda done, total, alive:
                update(4, "VALIDATION", f"Validation: {done}/{total}; {alive} live", 63 + int(21 * done / max(1, total)), {"valid": alive}))
            if state.control.is_cancelled():
                return state
            if not state.valid:
                prune_obsolete_successes(state)
                export_results(state, output_dir)
                state.pipeline_result = 'completed'
                update(6, 'COMPLETED', 'No proxies validated; prior verified results were removed.', 100)
                return state
            update(5, "PROFILING", "Enriching verified exit IPs...", 85)
            run_profile(state, deep_mode=True, interactive=False, progress_callback=lambda done, total:
                update(5, "PROFILING", f"Profile: {done}/{total}", 85 + int(9 * done / max(1, total))))
            if state.control.is_cancelled():
                return state
            update(5, 'CONFIRM', 'Two independent HTTPS checks for each live candidate...', 94)
            run_confirmation(state, progress_callback=lambda done, total, good:
                update(5, 'CONFIRM', f'Confirm: {done}/{total}; {good} confirmed',
                       94 + int(5 * done / max(1, total)), {'confirmed': good, 'checked': done}))
            if state.control.is_cancelled():
                return state
            prune_obsolete_successes(state)
            isp_candidates = export_results(state, output_dir)
            state.pipeline_result = "completed"
            update(6, "COMPLETED", f"Completed: {len(state.valid)} point-in-time confirmed; {isp_candidates} ISP/carrier candidates (ACCESS UNVERIFIED).",
                   100, {"confirmed": len(state.valid), "isp_candidates": isp_candidates})
            return state
        except KeyboardInterrupt:
            state.control.cancel("Keyboard interrupt")
            return state
        except Exception as exc:
            state.pipeline_result = "error"
            state.pipeline_error = str(exc)
            log(f"Pipeline error: {exc}")
            update(0, "ERROR", str(exc), 0)
            return state
        finally:
            if state.control.is_cancelled():
                state.pipeline_result = "cancelled"
                log("Cancelled. Queued work stopped; completed checks remain in scan history.")
                update(0, "CANCELLED", state.control.reason, 0)
            elif state.pipeline_result == "running":
                state.pipeline_result = "no_results"
                update(6, "COMPLETED", "No candidates passed this run; previous exports are preserved.", 100)
            save_hunt_report(state)
            save_latest(state)
