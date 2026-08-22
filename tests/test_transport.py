import ssl

import httpx
import pytest
import requests

from blanktrail_demo.detect import BLOCKED, PASSED
from blanktrail_demo.transport import (
    DOC_HEADERS, RAW_CAP, cookie_names, decoded_text, probe, tls_error_message,
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
