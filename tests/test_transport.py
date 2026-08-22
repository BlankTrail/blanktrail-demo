import ssl

import httpx
import requests

from blanktrail_demo.detect import BLOCKED, PASSED
from blanktrail_demo.transport import (
    DOC_HEADERS, RAW_CAP, HttpxFetcher, RequestsFetcher, _ContextAdapter,
    cookie_names, decoded_text, make_fetcher, probe, tls_error_message,
)
from blanktrail_demo.trust import SOURCE_SYSTEM


class FakeResponse:
    def __init__(self, status=200, headers=None, body=b"", url="https://example.com",
                 cookies=None):
        self.status_code = status
        self.headers = headers or {}
        self.content = body
        self.text = body.decode("utf-8", "replace")
        self.url = url
        self.history = []
        self.cookies = cookies if cookies is not None else {}


class FakeFetcher:
    proto_label = "HTTP/2"

    def __init__(self, response=None, error=None):
        self._response = response
        self._error = error
        self.seen_headers = None

    def get(self, url, headers, timeout):
        self.seen_headers = headers
        if self._error:
            raise self._error
        return self._response

    def proto_of(self, response):
        return "HTTP/2"

    def close(self):
        pass


def test_doc_headers_advertise_the_encodings_the_client_can_actually_decode():
    # The body must reach classify() DECOMPRESSED; otherwise Cloudflare's body
    # markers are not found and `blocked` silently becomes `unknown`.
    assert "br" in DOC_HEADERS["Accept-Encoding"]
    assert "zstd" in DOC_HEADERS["Accept-Encoding"]
    assert DOC_HEADERS["Sec-Fetch-Dest"] == "document"


def test_probe_returns_an_entry_and_an_observation():
    fetcher = FakeFetcher(FakeResponse(200, {"Content-Type": "text/html"}, b"<html>ok"))
    entry, observation = probe(fetcher, "https://example.com", 30, "B", SOURCE_SYSTEM)
    assert observation["state"] == PASSED
    assert entry["status"] == 200
    assert entry["lane"] == "B"
    assert entry["ms"] is not None


def test_probe_sends_the_document_navigation_headers():
    fetcher = FakeFetcher(FakeResponse())
    probe(fetcher, "https://example.com", 30, "A", SOURCE_SYSTEM)
    assert fetcher.seen_headers == DOC_HEADERS


def test_probe_classifies_a_challenge():
    fetcher = FakeFetcher(FakeResponse(403, {"cf-mitigated": "challenge"}, b""))
    _, observation = probe(fetcher, "https://example.com", 30, "A", SOURCE_SYSTEM)
    assert observation["state"] == BLOCKED


def test_probe_never_raises_and_turns_a_network_failure_into_an_observation():
    fetcher = FakeFetcher(error=OSError("connection refused"))
    entry, observation = probe(fetcher, "https://example.com", 30, "B", SOURCE_SYSTEM)
    assert observation["state"] == "error"
    assert "connection refused" in entry["error"]
    assert entry["kind"] == "net"


def test_probe_marks_a_tls_failure_apart_from_a_network_one():
    # "the certificate did not verify" and "could not reach the port" are
    # different diagnoses. Merging them sends the user to fix networking when
    # they need to supply a CA.
    error = requests.exceptions.SSLError(
        "certificate verify failed: unable to get local issuer certificate")
    fetcher = FakeFetcher(error=error)
    entry, observation = probe(fetcher, "https://example.com", 30, "B", SOURCE_SYSTEM)
    assert entry["kind"] == "tls"
    assert "OS trust store" in observation["reason"]


def test_probe_truncates_the_raw_dump():
    fetcher = FakeFetcher(FakeResponse(200, {}, b"x" * (RAW_CAP + 1000)))
    entry, _ = probe(fetcher, "https://example.com", 30, "A", SOURCE_SYSTEM)
    assert len(entry["raw"]) == RAW_CAP


def test_tls_error_message_recognises_both_client_families():
    assert tls_error_message(requests.exceptions.SSLError("boom")) == "boom"
    inner = ssl.SSLCertVerificationError("certificate verify failed")
    assert tls_error_message(httpx.ConnectError("wrapped", request=None)) is None
    wrapped = httpx.ConnectError("wrapped", request=None)
    wrapped.__cause__ = inner
    assert "certificate verify failed" in tls_error_message(wrapped)


def test_tls_error_message_returns_none_for_an_ordinary_failure():
    assert tls_error_message(OSError("connection refused")) is None


def test_decoded_text_falls_back_to_utf8_when_no_charset_is_declared():
    response = FakeResponse(200, {"Content-Type": "text/html"}, "привет".encode("utf-8"))
    assert decoded_text(response) == "привет"


def test_cookie_names_works_for_a_plain_mapping():
    response = FakeResponse(cookies={"cf_clearance": "x", "other": "y"})
    assert cookie_names(response) == ["cf_clearance", "other"]


# Tests for real fetcher implementations without network access.
# These cover load-bearing properties: trust_env=False, fresh sessions, context
# injection, proxy handling, and verify parameter passing.


class RecordingSession:
    """Stand-in for requests.Session that records call arguments."""

    def __init__(self):
        self.kwargs = None
        self.closed = False
        self.trust_env = None
        self._adapter = None

    def get(self, url, **kwargs):
        self.kwargs = kwargs
        return FakeResponse()

    def mount(self, prefix, adapter):
        """Record mounted adapter for inspection."""
        if prefix == "https://":
            self._adapter = adapter

    def get_adapter(self, url):
        """Return the adapter for this URL, or a non-adapter by default."""
        if url.startswith("https://") and self._adapter:
            return self._adapter
        return "NotAnAdapter"

    def close(self):
        self.closed = True


def test_make_fetcher_returns_httpx_fetcher_for_h2():
    fetcher = make_fetcher("h2", None, True)
    assert isinstance(fetcher, HttpxFetcher)


def test_make_fetcher_returns_requests_fetcher_for_h1_or_other():
    fetcher = make_fetcher("h1", None, True)
    assert isinstance(fetcher, RequestsFetcher)
    fetcher = make_fetcher("anything_else", None, True)
    assert isinstance(fetcher, RequestsFetcher)


def test_requests_fetcher_session_has_trust_env_false():
    # trust_env=False is load-bearing. Without it, on a machine with HTTP_PROXY
    # set, the lane with proxy=None would quietly leave through the proxy while
    # the other went direct. The lanes would diverge INVISIBLY and the tool would
    # keep printing verdicts.
    fetcher = RequestsFetcher(None, True)
    session = fetcher._session()
    assert session.trust_env is False
    session.close()


def test_requests_fetcher_mounts_context_adapter_when_verify_is_ssl_context():
    # When given an SSLContext, mount it on https:// so it flows through the pool manager.
    ctx = ssl.create_default_context()
    fetcher = RequestsFetcher(None, ctx)
    session = fetcher._session()
    adapter = session.get_adapter("https://example.com")
    assert isinstance(adapter, _ContextAdapter)
    session.close()


def test_requests_fetcher_does_not_mount_adapter_when_verify_is_bool():
    # When given a bool, use the default adapter (not _ContextAdapter).
    fetcher = RequestsFetcher(None, True)
    session = fetcher._session()
    adapter = session.get_adapter("https://example.com")
    assert not isinstance(adapter, _ContextAdapter)
    session.close()


def test_requests_fetcher_proxies_dict_when_proxy_given():
    # proxies should be {"http": p, "https": p} when a proxy is given.
    fetcher = RequestsFetcher("http://127.0.0.1:9000", True)
    assert fetcher.proxies == {"http": "http://127.0.0.1:9000",
                               "https": "http://127.0.0.1:9000"}


def test_requests_fetcher_proxies_none_when_no_proxy():
    # proxies should be None when no proxy is given, not an empty dict.
    fetcher = RequestsFetcher(None, True)
    assert fetcher.proxies is None


def test_httpx_fetcher_converts_proxy_via_for_httpx():
    # socks5h (which requests understands) becomes socks5 (which httpx requires).
    fetcher = HttpxFetcher("socks5h://127.0.0.1:9000", True)
    assert fetcher.proxy == "socks5://127.0.0.1:9000"


def test_context_adapter_carries_the_ssl_context_through_both_hooks():
    # Every request in this tool goes through a proxy, and proxied requests use
    # proxy_manager_for. Overriding only init_poolmanager would silently drop the
    # context and verification would stop using the configured trust source.
    ctx = ssl.create_default_context()
    adapter = _ContextAdapter(ctx)
    assert adapter.poolmanager.connection_pool_kw.get("ssl_context") is ctx
    proxy_manager = adapter.proxy_manager_for("http://127.0.0.1:9000")
    assert proxy_manager.connection_pool_kw.get("ssl_context") is ctx


def test_requests_fetcher_get_passes_verify_true_when_given_ssl_context():
    # When given an SSLContext, pass verify=True to session.get().
    ctx = ssl.create_default_context()
    fetcher = RequestsFetcher(None, ctx)
    recorder = RecordingSession()
    fetcher._session = lambda: recorder
    fetcher.get("https://example.com", {}, 30)
    assert recorder.kwargs["verify"] is True
    assert recorder.closed


def test_requests_fetcher_get_passes_verify_bool_unchanged():
    # When given a bool, pass it through unchanged.
    fetcher = RequestsFetcher(None, False)
    recorder = RecordingSession()
    fetcher._session = lambda: recorder
    fetcher.get("https://example.com", {}, 30)
    assert recorder.kwargs["verify"] is False
    assert recorder.closed


def test_requests_fetcher_get_passes_verify_path_unchanged():
    # When given a path string, pass it through unchanged.
    fetcher = RequestsFetcher(None, "/path/to/ca.pem")
    recorder = RecordingSession()
    fetcher._session = lambda: recorder
    fetcher.get("https://example.com", {}, 30)
    assert recorder.kwargs["verify"] == "/path/to/ca.pem"
    assert recorder.closed


def test_requests_fetcher_proto_of_maps_versions_to_labels():
    # Map HTTP version numbers to labels: 10→HTTP/1.0, 11→HTTP/1.1, 20→HTTP/2, default→HTTP/1.1.
    class FakeRaw:
        version = 11
    class ResponseLike:
        raw = FakeRaw()

    fetcher = RequestsFetcher(None, True)
    assert fetcher.proto_of(ResponseLike()) == "HTTP/1.1"

    ResponseLike.raw.version = 10
    assert fetcher.proto_of(ResponseLike()) == "HTTP/1.0"

    ResponseLike.raw.version = 20
    assert fetcher.proto_of(ResponseLike()) == "HTTP/2"

    # Default when raw or version is missing.
    class NoRaw:
        pass
    assert fetcher.proto_of(NoRaw()) == "HTTP/1.1"


def test_httpx_fetcher_proto_of_returns_http_version():
    # Extract http_version attribute from response, default to "?" if missing.
    class ResponseLike:
        http_version = "HTTP/2"

    fetcher = HttpxFetcher(None, True)
    assert fetcher.proto_of(ResponseLike()) == "HTTP/2"

    class NoVersion:
        pass
    assert fetcher.proto_of(NoVersion()) == "?"
