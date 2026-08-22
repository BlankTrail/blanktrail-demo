"""Command line entry point."""

from __future__ import annotations

import argparse
import sys
import threading
import webbrowser

from .webui import create_app


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="blanktrail-demo",
        description="Compare a bare HTTP client against BlankTrail Proxy on "
                    "challenge-protected targets.")
    # This is the port of the demo's own web UI, not a BlankTrail proxy port.
    parser.add_argument("--port", type=int, default=8790, help="web UI port")
    parser.add_argument("--host", default="127.0.0.1", help="web UI bind address")
    parser.add_argument("--no-open", action="store_true",
                       help="do not open a browser on start")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass
    url = f"http://{args.host}:{args.port}/"
    print(f"BlankTrail demo -> {url}")
    if not args.no_open:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    create_app().run(host=args.host, port=args.port, threaded=True, debug=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
