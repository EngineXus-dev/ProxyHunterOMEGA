#!/usr/bin/env python3
"""Console entry point used by the desktop button; keeps output visible on exit."""
import sys
import traceback


def main():
    try:
        from run_optimal import main as run
        run()
    except Exception:
        traceback.print_exc()
    finally:
        if sys.stdin.isatty():
            try:
                input('\nHunt finished. Press ENTER to close this terminal...')
            except (EOFError, KeyboardInterrupt):
                pass


if __name__ == '__main__':
    main()
