"""The Flask layer. Serialises events; holds no logic of its own."""

from __future__ import annotations

import json
from pathlib import Path

from flask import Flask, Response, jsonify, request, stream_with_context

from .btapi import ApiError, BlankTrailApi
from .runner import execute

ASSETS = Path(__file__).parent / "assets"


def create_app() -> Flask:
    app = Flask(__name__, static_folder=None)

    @app.get("/")
    def index() -> Response:
        return Response((ASSETS / "index.html").read_text(encoding="utf-8"),
                        mimetype="text/html")

    @app.get("/assets/<path:name>")
    def asset(name: str) -> Response:
        path = (ASSETS / name).resolve()
        if not path.is_file() or ASSETS.resolve() not in path.parents:
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
    def probe_route():
        payload = request.get_json(force=True, silent=True) or {}
        api = BlankTrailApi(str(payload.get("api_base") or "http://127.0.0.1:8891"),
                            str(payload.get("api_key") or ""))
        try:
            api.health()
            ports = api.ports()
            result = {"ok": True, "total_open": ports.get("total_open", 0),
                      "max_ports": ports.get("max_ports", 0),
                      "ports": [p.get("port") for p in ports.get("ports", [])]}
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
