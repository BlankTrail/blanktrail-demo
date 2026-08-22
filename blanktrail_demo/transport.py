"""The two HTTP clients and the single-request probe."""

from __future__ import annotations

import ssl
import time

import httpx
import requests
from requests.adapters import HTTPAdapter

from .detect import classify
from .proxyurl import for_httpx
from .trust import explain_tls_error

# Raw dumps are for reading a VOID by hand, not for archiving a site.
RAW_CAP = 300_000

# Document-navigation headers — what Chrome sends when opening a page.
#
# Accept-Encoding advertises br and zstd deliberately: the body MUST reach
# classify() decompressed, or Cloudflare's body markers are not found and a
# `blocked` target silently reports `unknown` -> a false VOID. The CLIENT
# decompresses, and the clients are not equal: gzip/deflate come built in, br
# needs the `brotli` package, and zstd needs `zstandard` for httpx but
# `backports.zstd` for requests — urllib3 gates zstd on compression.zstd /
# backports.zstd and never touches the `zstandard` package at all.
DOC_HEADERS = {
    "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
               "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-User": "?1",
    "Sec-Fetch-Dest": "document",
    "Upgrade-Insecure-Requests": "1",
}


class _ContextAdapter(HTTPAdapter):
    """requests accepts only a path or a bool in `verify`, so an SSLContext has
    to be injected at the pool manager. Both hooks are needed: every request
    here goes through a proxy, which uses proxy_manager_for rather than
    init_poolmanager."""

    def __init__(self, ssl_context: ssl.SSLContext, **kwargs):
        self._ctx = ssl_context
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = self._ctx
        return super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        kwargs["ssl_context"] = self._ctx
        return super().proxy_manager_for(*args, **kwargs)


class RequestsFetcher:
    """HTTP/1.1 client."""

    proto_label = "HTTP/1.1"

    def __init__(self, proxy: str | None, verify):
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        self.verify = verify

    def _session(self) -> requests.Session:
        session = requests.Session()
        # trust_env=False is load-bearing, not tidiness. The measurement rests on
        # both lanes sharing one egress; requests otherwise reads HTTP(S)_PROXY
        # from the environment, so on a machine behind a corporate proxy the
        # lane with proxy=None would quietly leave through it while the other
        # went direct. The lanes would diverge INVISIBLY and the tool would keep
        # printing verdicts.
        session.trust_env = False
        if isinstance(self.verify, ssl.SSLContext):
            session.mount("https://", _ContextAdapter(self.verify))
        return session

    def get(self, url, headers, timeout):
        # A fresh session per request: a keep-alive session would carry cookies
        # (cf_clearance among them) between targets and colour their neighbours.
        session = self._session()
        try:
            verify = True if isinstance(self.verify, ssl.SSLContext) else self.verify
            return session.get(url, proxies=self.proxies, verify=verify, timeout=timeout,
                               allow_redirects=True, headers=headers)
        finally:
            session.close()

    def proto_of(self, response) -> str:
        version = getattr(getattr(response, "raw", None), "version", 11)
        return {10: "HTTP/1.0", 11: "HTTP/1.1", 20: "HTTP/2"}.get(version, "HTTP/1.1")

    def close(self) -> None:
        pass


class HttpxFetcher:
    """HTTP/2 client."""

    proto_label = "HTTP/2"

    def __init__(self, proxy: str | None, verify):
        self.proxy = for_httpx(proxy)
        self.verify = verify

    def get(self, url, headers, timeout):
        kwargs = dict(http2=True, verify=self.verify, follow_redirects=True,
                      trust_env=False)
        if self.proxy:
            kwargs["proxy"] = self.proxy
        with httpx.Client(**kwargs) as client:
            return client.get(url, headers=headers, timeout=timeout)

    def proto_of(self, response) -> str:
        return getattr(response, "http_version", "?")

    def close(self) -> None:
        pass


def make_fetcher(protocol: str, proxy: str | None, verify):
    return HttpxFetcher(proxy, verify) if protocol == "h2" else RequestsFetcher(proxy, verify)


def decoded_text(response) -> str:
    """UTF-8 text. With no declared charset, decode the already-decompressed
    bytes as UTF-8 — requests would otherwise fall back to ISO-8859-1 and
    produce mojibake."""
    content_type = (response.headers.get("Content-Type") or "").lower()
    if "charset=" not in content_type:
        try:
            return response.content.decode("utf-8", "replace")
        except Exception:
            return response.text
    return response.text


def cookie_names(response) -> list[str]:
    """Names of the cookies the RESPONSE set.

    .keys() comes first because it works for both clients: httpx.Cookies
    iterates over NAMES (str), so {c.name for c in ...} raises AttributeError
    there. The .name form exists only on requests' jar.
    """
    try:
        return sorted(response.cookies.keys())
    except Exception:
        pass
    try:
        return sorted({c.name for c in response.cookies})
    except Exception:
        return []


def tls_error_message(exc: BaseException) -> str | None:
    """The TLS reason behind an exception, or None when it is not a TLS failure."""
    if isinstance(exc, (ssl.SSLError, requests.exceptions.SSLError)):
        return str(exc)
    cause = getattr(exc, "__cause__", None)
    if isinstance(cause, ssl.SSLError):
        return str(cause)
    return None


def probe(fetcher, url: str, timeout: int, lane: str, trust_source: str):
    """One lane against one target: GET, then classify.

    NEVER raises. A network failure becomes an observation with state="error",
    and verdict() handles it down the same path as everything else.

    Returns (log_entry, observation).
    """
    entry = {
        "lane": lane, "url": url, "status": None, "ms": None, "kb": 0,
        "final_url": None, "redirects": [], "error": None, "kind": None, "raw": None,
        "ctype": None, "location": None, "proto": None, "server": None,
        "state": None, "reason": None, "vendor": "", "cookies": [], "signals": {},
    }
    started = time.time()
    try:
        response = fetcher.get(url, DOC_HEADERS, timeout)
        text = decoded_text(response)
        cookies = cookie_names(response)
        observation = classify(response.status_code, dict(response.headers), text, cookies)
        entry.update({
            "status": response.status_code,
            "final_url": str(response.url),
            "kb": round(len(response.content) / 1024, 1),
            "ctype": response.headers.get("Content-Type", ""),
            "server": response.headers.get("Server", ""),
            "redirects": [{"status": h.status_code, "url": str(h.url)}
                          for h in response.history],
            "raw": text[:RAW_CAP],
            "location": response.headers.get("Location"),
            "proto": fetcher.proto_of(response),
            "cookies": cookies,
            "state": observation["state"],
            "reason": observation["reason"],
            "vendor": observation["vendor"],
            "signals": observation["signals"],
        })
        return entry, observation
    except Exception as exc:  # noqa: BLE001
        tls = tls_error_message(exc)
        if tls is not None:
            reason = explain_tls_error(tls, trust_source)
            entry["kind"] = "tls"
        else:
            reason = f"{type(exc).__name__}: {exc}"
            entry["kind"] = "net"
        observation = {"state": "error", "vendor": "", "reason": reason, "signals": {}}
        entry.update({"error": reason, "state": "error", "reason": reason})
        return entry, observation
    finally:
        entry["ms"] = int((time.time() - started) * 1000)
