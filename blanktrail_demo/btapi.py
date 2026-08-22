"""A thin client for the BlankTrail REST API.

Only the public client-facing contract lives here: open a port, use it, close
it. The API key is taken from the form, kept in memory, and never written to
disk or into an event.
"""

from __future__ import annotations

from collections.abc import Mapping

import requests

# Fields POST /api/v1/ports/open accepts that this demo exposes. Anything else
# in the form (the API key above all) must not reach the wire as a port setting.
OPEN_FIELDS = (
    "port", "protocol", "mode", "browser", "os", "specific_profile", "upstream",
    "h2_spoofing", "spoof_user_agent", "max_concurrent", "skip_retry", "auto_rotate",
    "js_solver", "keep_sessions",
)


class ApiError(Exception):
    """Anything the API refused, plus the local validation that precedes it."""


def open_body(form: Mapping[str, object]) -> dict:
    """Build the ports/open payload from the form. Pure.

    Blank strings are dropped: an empty "browser" means "no filter", and sending
    "" would read as a filter for a browser literally named empty string.
    Booleans are kept even when False — False is a real setting.
    """
    port = form.get("port")
    try:
        port = int(port)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ApiError("a port number is required to open a BlankTrail port") from exc
    if not 1 <= port <= 65535:
        raise ApiError(f"port {port} is outside 1-65535")

    body: dict = {"port": port}
    for field in OPEN_FIELDS:
        if field == "port":
            continue
        value = form.get(field)
        if value is None:
            continue
        if isinstance(value, str):
            value = value.strip()
            if not value:
                continue
        body[field] = value
    return body


class BlankTrailApi:
    def __init__(self, base_url: str, api_key: str, timeout: int = 30):
        self.base = (base_url or "").strip().rstrip("/")
        self.api_key = (api_key or "").strip()
        self.timeout = timeout
        self._session = requests.Session()
        self._session.trust_env = False

    # ------------------------------------------------------------------ plumbing

    def _headers(self) -> dict:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers

    def _call(self, method: str, path: str, payload: dict | None = None):
        url = f"{self.base}{path}"
        try:
            response = self._session.request(method, url, json=payload,
                                             headers=self._headers(),
                                             timeout=self.timeout)
        except Exception as exc:  # noqa: BLE001
            raise ApiError(f"cannot reach the BlankTrail API at {url}: "
                           f"{type(exc).__name__}: {exc}") from exc
        if response.status_code == 401:
            raise ApiError("the BlankTrail API rejected the API key (HTTP 401). Check the "
                           "key, or open the dashboard to issue one.")
        return response

    @staticmethod
    def _payload(response, what: str) -> dict:
        try:
            data = response.json()
        except Exception:  # noqa: BLE001
            data = None
        if response.status_code >= 400:
            detail = ""
            if isinstance(data, dict) and data.get("error"):
                detail = f": {data['error']}"
            elif getattr(response, "text", ""):
                detail = f": {response.text[:200]}"
            raise ApiError(f"{what} failed (HTTP {response.status_code}){detail}")
        return data if isinstance(data, dict) else {}

    # -------------------------------------------------------------------- calls

    def health(self) -> dict:
        response = self._call("GET", "/api/v1/health")
        return self._payload(response, "health check")

    def ports(self) -> dict:
        response = self._call("GET", "/api/v1/ports")
        return self._payload(response, "listing ports")

    def open_port(self, body: dict) -> dict:
        response = self._call("POST", "/api/v1/ports/open", body)
        return self._payload(response, f"opening port {body.get('port')}")

    def close_port(self, port: int) -> dict:
        response = self._call("POST", "/api/v1/ports/close", {"port": int(port)})
        return self._payload(response, f"closing port {port}")

    def ca(self) -> bytes:
        response = self._call("GET", "/api/v1/ca")
        if response.status_code >= 400 or not response.content:
            raise ApiError(f"fetching the CA failed (HTTP {response.status_code})")
        return response.content

    def close(self) -> None:
        try:
            self._session.close()
        except Exception:  # noqa: BLE001
            pass
