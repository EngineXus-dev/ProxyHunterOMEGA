#!/usr/bin/env python3
"""Unattended CLI runner with portable history and resource profiles."""
import argparse
import os
import sys
from pathlib import Path
from state import State
from pipeline import execute_pipeline, apply_resource_profile
from run_control import request_cancel
from scrapoxy_runtime import ensure_scrapoxy


def configure_optimal_settings(state, full_mode=False, resource_profile='laptop'):
    apply_resource_profile(state, resource_profile)
    state.settings.update(source_tier=3 if full_mode else 2, src_api=True,
                          src_telegram=True, src_html=True, src_gists=full_mode, deep_profiling=True)


def run_optimal_automated_pipeline(full_mode=False, use_scrapoxy=None,
                                   resource_profile='laptop', history_path=None, recheck=True,
                                   non_github=False, max_candidates=None, use_vpngate=False,
                                   output_dir=None, history_ttl_hours=24, desktop_status=False):
    reporter = None
    if desktop_status:
        from desktop_status import ProgressReporter
        reporter = ProgressReporter()
    state = State()
    configure_optimal_settings(state, full_mode, resource_profile)
    state.settings.update(recheck=recheck, non_github=non_github, max_candidates=max_candidates,
                          vpngate_enabled=use_vpngate, output_dir=output_dir,
                          history_ttl_hours=history_ttl_hours)
    if history_path:
        state.settings['history_path'] = str(Path(history_path).resolve())
    if non_github:
        state.settings.update(src_github=False, src_gists=False)
    if use_scrapoxy is not None:
        state.settings['scrapoxy_enabled'] = use_scrapoxy
    try:
        if state.settings['scrapoxy_enabled']:
            _, message = ensure_scrapoxy(state)
            print(message)
        return execute_pipeline(state, full=full_mode, output_dir=output_dir,
                                progress=reporter.update if reporter else None)
    finally:
        if reporter:
            reporter.finish(getattr(state, 'pipeline_result', 'error'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--auto', action='store_true')
    parser.add_argument('--full', action='store_true')
    parser.add_argument('--profile', choices=['laptop','notebook','server','quiet','balanced','turbo'], default='laptop')
    parser.add_argument('--scrapoxy', action='store_true')
    parser.add_argument('--no-scrapoxy', action='store_true')
    parser.add_argument('--vpngate', action='store_true', help='Enable the optional VPNGate integration')
    parser.add_argument('--no-vpngate', action='store_true', help='Disable VPNGate (default)')
    parser.add_argument('--list-sources', action='store_true',
                        help='List configured community feeds and the active manifest path without scanning')
    parser.add_argument('--non-github', action='store_true')
    parser.add_argument('--history')
    parser.add_argument('--history-ttl-hours', type=float, default=24)
    history_mode = parser.add_mutually_exclusive_group()
    history_mode.add_argument('--recheck', action='store_true', dest='recheck', default=True,
                              help='Freshly check all candidates (default)')
    history_mode.add_argument('--resume', action='store_false', dest='recheck',
                              help='Opt in to recent completed-check reuse; may skip stale endpoints')
    parser.add_argument('--max-candidates', type=int)
    parser.add_argument('--output-dir')
    parser.add_argument('--desktop-status', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--cancel', nargs='?', const='all', metavar='PID')
    args = parser.parse_args()
    if args.list_sources:
        from scraper import load_community_manifest, community_manifest_path
        print(f'Manifest: {community_manifest_path()}')
        try:
            feeds = load_community_manifest()
        except (OSError, ValueError, TypeError) as exc:
            parser.exit(1, f'Invalid source manifest: {exc}\n')
        print(f'Community feeds: {sum(s.get("enabled", True) for s in feeds)} enabled / '
              f'{sum(not s.get("enabled", True) for s in feeds)} disabled')
        for source in feeds:
            status = 'ENABLED ' if source.get('enabled', True) else 'DISABLED'
            print(f'  [{status}] {source["protocol"]:<6}  {source["name"]}: {source["url"]}')
        return
    if args.max_candidates is not None and args.max_candidates < 1:
        parser.error('--max-candidates must be positive')
    if args.history_ttl_hours <= 0:
        parser.error('--history-ttl-hours must be positive; use --recheck to bypass history')
    if args.cancel:
        count = request_cancel(None if args.cancel == 'all' else int(args.cancel))
        print(f'Cancellation requested for {count} active local operation(s).')
        return
    if len(sys.argv) == 1:
        import proxyhunterV2
        proxyhunterV2.main_menu()
        return
    use_scrapoxy = False if args.no_scrapoxy else True if args.scrapoxy else None
    return run_optimal_automated_pipeline(full_mode=args.full, use_scrapoxy=use_scrapoxy,
        resource_profile=args.profile, history_path=args.history,
        history_ttl_hours=args.history_ttl_hours, recheck=args.recheck, non_github=args.non_github,
        max_candidates=args.max_candidates, use_vpngate=args.vpngate and not args.no_vpngate, output_dir=args.output_dir,
        desktop_status=args.desktop_status)


if __name__ == '__main__':
    main()
