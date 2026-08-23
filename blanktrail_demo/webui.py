"""The Flask layer. Serialises events; holds no logic of its own."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from flask import Flask, Response, jsonify, request, stream_with_context

from .btapi import ApiError, BlankTrailApi
from .runner import execute


def _assets_dir() -> Path:
    """Where index.html / app.js / style.css live.

    Un-frozen (the normal `python -m blanktrail_demo` case, and every test in
    this suite), this is the assets/ folder next to this module — unchanged
    from before.

    Frozen into a PyInstaller one-file exe, the source tree this module
    thinks it lives in does not exist on disk: at startup PyInstaller unpacks
    the bundle's data files into a fresh temporary directory and publishes
    its path as `sys._MEIPASS`. build-windows.ps1 adds the assets folder to
    that bundle at the same `blanktrail_demo/assets` relative layout, so the
    frozen lookup mirrors the source layout instead of guessing at
    `__file__`, which PyInstaller does not promise to leave pointing at a
    real file for a bundled module.
    """
    bundle_root = getattr(sys, "_MEIPASS", None)
    if bundle_root:
        return Path(bundle_root) / "blanktrail_demo" / "assets"
    return Path(__file__).parent / "assets"


ASSETS = _assets_dir()
ASSETS_RESOLVED = ASSETS.resolve()


def create_app() -> Flask:
    app = Flask(__name__, static_folder=None)

    @app.get("/")
    def index() -> Response:
        return Response((ASSETS / "index.html").read_text(encoding="utf-8"),
                        mimetype="text/html")

    @app.get("/assets/<path:name>")
    def asset(name: str) -> Response:
        path = (ASSETS / name).resolve()
        if not path.is_file() or ASSETS_RESOLVED not in path.parents:
            return Response("not found", status=404)
        types = {".js": "text/javascript", ".css": "text/css"}
        return Response(path.read_bytes(),
                        mimetype=types.get(path.suffix, "application/octet-stream"))

    @app.post("/run")
    def run_route() -> Response:
        config = request.get_json(force=True, silent=True) or {}

        def generate():
            try:
                for event in execute(config):
                    yield json.dumps(event, ensure_ascii=False) + "\n"
            except Exception as exc:  # noqa: BLE001
                yield json.dumps({"type": "error",
                                  "text": f"{type(exc).__name__}: {exc}"}) + "\n"
                yield json.dumps({"type": "done"}) + "\n"

        return Response(stream_with_context(generate()),
                        mimetype="application/x-ndjson",
                        headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"})

    @app.post("/api/probe")
    def probe_route() -> Response:
        payload = request.get_json(force=True, silent=True) or {}
        # A JSON body that is valid but not an object (42, "x", [1,2]) parses to a
        # non-dict, and `or {}` does not replace a truthy one. Without this guard the
        # next .get() raises AttributeError and Flask answers 500 — the one thing this
        # tool promises never to do on bad input.
        if not isinstance(payload, dict):
            payload = {}
        api = BlankTrailApi(str(payload.get("api_base") or "http://127.0.0.1:8891"),
                            str(payload.get("api_key") or ""))
        try:
            api.health()
            ports = api.ports()
            # Same principle as the payload guard above: the API is someone else's
            # process, and a "ports" value that is not a list — or a list with
            # non-dict entries — must not turn into a 500 here.
            raw_ports = ports.get("ports", [])
            if not isinstance(raw_ports, list):
                raw_ports = []
            result = {"ok": True, "total_open": ports.get("total_open", 0),
                      "max_ports": ports.get("max_ports", 0),
                      "ports": [p.get("port") for p in raw_ports if isinstance(p, dict)]}
            if payload.get("want_ca"):
                # Only whether it worked. The certificate itself is not echoed
                # back into the page.
                api.ca()
                result["ca"] = "ok"
            return jsonify(result)
        except ApiError as exc:
            return jsonify({"ok": False, "error": str(exc)})
        finally:
            api.close()

    return app
