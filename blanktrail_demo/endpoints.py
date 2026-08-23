"""Where lane B's proxy URL comes from.

Two ways to reach BlankTrail — proxy links the operator already opened, or the
REST API — behind one interface, so the orchestrator never branches on the mode.
"""

from __future__ import annotations

import socket
from abc import ABC, abstractmethod
from urllib.parse import urlsplit

from .btapi import ApiError, BlankTrailApi
from .proxyurl import hostport


def tcp_reachable(url: str, timeout: float = 5.0) -> str:
    """Empty string when the endpoint accepts a TCP connection, else the reason."""
    pair = hostport(url)
    if not pair:
        return f"cannot parse host:port from {url!r}"
    try:
        with socket.create_connection(pair, timeout=timeout):
            return ""
    except Exception as exc:  # noqa: BLE001
        return f"{pair[0]}:{pair[1]} unreachable — {type(exc).__name__}: {exc}"


class Endpoint(ABC):
    @abstractmethod
    def preflight(self) -> str:
        """Empty string when ready, else ONE explicit sentence. Failing here stops
        the run before the first request, instead of printing N silent errors."""

    @abstractmethod
    def acquire(self, i: int) -> str:
        """Proxy URL for the target with index i."""

    def release(self, i: int) -> None:
        return None

    @abstractmethod
    def describe(self) -> dict:
        """Shown in the run header and carried in the meta event."""

    def close(self) -> None:
        return None


class PresetEndpoint(Endpoint):
    """Ports the operator opened in BlankTrail beforehand.

    One URL is a fixed port; several are a pool, round-robined by target index.
    The two are the same thing at different lengths, so they share one branch.
    """

    def __init__(self, urls: list[str]):
        self.urls = list(urls)

    def preflight(self) -> str:
        if not self.urls:
            return ("lane B: no proxy URL given — open a port in BlankTrail and paste its "
                    "address, or switch to the API mode")
        broken = []
        for url in self.urls:
            error = tcp_reachable(url)
            if error:
                broken.append(f"{url} ({error})")
        if broken:
            return "lane B: unreachable — " + "; ".join(broken)
        return ""

    def acquire(self, i: int) -> str:
        return self.urls[i % len(self.urls)]

    def describe(self) -> dict:
        return {"mode": "preset", "count": len(self.urls), "urls": list(self.urls)}

    def close(self) -> None:
        # The operator owns these ports. Closing them here would be a surprise.
        return None


class ApiEndpoint(Endpoint):
    """One port opened over REST for the whole run, then closed."""

    def __init__(self, api: BlankTrailApi, body: dict, close_when_done: bool = True):
        self.api = api
        self.body = body
        self.close_when_done = close_when_done
        self.port = int(body.get("port") or 0)
        self.protocol = str(body.get("protocol") or "http")
        self.profile = ""
        self._opened = False
        # The port is opened on whatever machine the API lives on, so the proxy
        # host is the API's host — not necessarily this machine.
        self.host = urlsplit(api.base).hostname or "127.0.0.1"

    def preflight(self) -> str:
        try:
            self.api.health()
        except ApiError as exc:
            return f"lane B: {exc}"
        try:
            result = self.api.open_port(self.body)
        except ApiError as exc:
            return f"lane B: {exc}"
        self._opened = True
        profile = result.get("current_profile") or {}
        if isinstance(profile, dict):
            self.profile = str(profile.get("name") or "")
        error = tcp_reachable(self.acquire(0))
        if error:
            return f"lane B: port {self.port} opened but is not reachable — {error}"
        return ""

    def acquire(self, i: int) -> str:
        scheme = "socks5h" if self.protocol == "socks5" else "http"
        return f"{scheme}://{self.host}:{self.port}"

    def describe(self) -> dict:
        return {"mode": "api", "port": self.port, "protocol": self.protocol,
                "profile": self.profile, "js_solver": bool(self.body.get("js_solver"))}

    def close(self) -> None:
        # self.api.close() must run on every path — including the two where the
        # port itself is left alone — or the session leaks: a validation error,
        # close_when_done=False, and a failed preflight all end up here.
        try:
            if self._opened and self.close_when_done:
                try:
                    self.api.close_port(self.port)
                except ApiError:
                    # Closing is best effort: the port also closes itself on idle
                    # timeout, and a failure here must not mask the run's real
                    # result.
                    pass
            self._opened = False
        finally:
            self.api.close()
