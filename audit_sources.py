"""Read-only audit of public feeds; does not probe or validate proxy candidates."""
import argparse
from collections import Counter
import json
from pathlib import Path

from state import State
from scraper import (begin_scrape, scrape_github_api, scrape_telegram, scrape_html,
                     source_summary, _extra_sources, _harvest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--community-only", action="store_true")
    parser.add_argument("--include-social", action="store_true")
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument("--output", default="source_audit.json")
    args = parser.parse_args()
    state = State()
    state.settings["source_cache_enabled"] = not args.no_cache
    begin_scrape(state)
    if args.community_only:
        proxies, _ = _harvest(state, _extra_sources(state), "community")
    else:
        proxies, _ = scrape_github_api(state)
    if args.include_social:
        state.settings.update(src_telegram=True, src_html=True)
        for scrape in (scrape_telegram, scrape_html):
            found, _ = scrape(state)
            proxies.update(found)
    report = {"summary": source_summary(state), "unique_candidates": len(proxies),
              "protocol_counts": dict(Counter(proto for choices in state.proxy_protocols.values() for proto in choices)),
              "sources": list(state.source_health.values())}
    output = Path(args.output).resolve()
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({key: report[key] for key in ("summary", "unique_candidates", "protocol_counts")}, indent=2))
    print(f"Source report: {output}")


if __name__ == "__main__":
    main()
