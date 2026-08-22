import os
import re
import ssl

import certifi
import pytest

from blanktrail_demo.trust import (
    SOURCE_API, SOURCE_FILE, SOURCE_SYSTEM, Trust, TrustError, build,
    combined_bundle, explain_tls_error, system_context,
)

# A syntactically valid but meaningless PEM block: enough to prove concatenation
# without shipping a real certificate in the repo.
FAKE_PEM = b"-----BEGIN CERTIFICATE-----\nQkxBTktUUkFJTA==\n-----END CERTIFICATE-----\n"


# Tests that call build() need a PARSEABLE certificate, because build() hands the
# bundle to ssl.create_default_context(cafile=...), which parses it. certifi's own
# first certificate serves: it is real, already present in every environment, and
# ships nothing new in this repo. A duplicate certificate inside a CA bundle is fine.
def _first_certifi_cert() -> bytes:
    blob = open(certifi.where(), "rb").read()
    match = re.search(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", blob, re.S)
    assert match, "certifi bundle contains no certificate"
    return match.group(0) + b"\n"


REAL_PEM = _first_certifi_cert()


def test_disabled_yields_verify_false_and_says_so():
    trust = build(SOURCE_SYSTEM, disabled=True)
    assert trust.verify is False
    assert "disabled" in trust.label.lower()
    trust.close()


def test_system_source_produces_a_usable_context():
    trust = build(SOURCE_SYSTEM)
    assert isinstance(trust.verify, ssl.SSLContext)
    assert trust.bundle_path is None
    trust.close()


def test_system_context_falls_back_to_stdlib_without_truststore(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def no_truststore(name, *args, **kwargs):
        if name == "truststore":
            raise ImportError("no truststore")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_truststore)
    ctx = system_context()
    assert isinstance(ctx, ssl.SSLContext)


def test_combined_bundle_contains_both_certifi_and_the_extra_pem():
    path = combined_bundle(FAKE_PEM)
    try:
        blob = open(path, "rb").read()
        assert open(certifi.where(), "rb").read() in blob
        assert FAKE_PEM.strip() in blob
        # Without a newline between blocks the concatenation reads as
        # -----END-----BEGIN----- and parses as nothing.
        assert b"-----END CERTIFICATE----------BEGIN" not in blob
    finally:
        os.unlink(path)


def test_file_source_reads_the_pem_and_builds_a_bundle(tmp_path):
    ca = tmp_path / "ca.crt"
    ca.write_bytes(REAL_PEM)
    trust = build(SOURCE_FILE, ca_path=str(ca))
    try:
        assert isinstance(trust.verify, ssl.SSLContext)
        assert trust.bundle_path is not None
        assert os.path.exists(trust.bundle_path)
    finally:
        trust.close()


def test_close_removes_the_temporary_bundle(tmp_path):
    ca = tmp_path / "ca.crt"
    ca.write_bytes(REAL_PEM)
    trust = build(SOURCE_FILE, ca_path=str(ca))
    path = trust.bundle_path
    trust.close()
    assert not os.path.exists(path)


def test_close_is_idempotent(tmp_path):
    ca = tmp_path / "ca.crt"
    ca.write_bytes(REAL_PEM)
    trust = build(SOURCE_FILE, ca_path=str(ca))
    trust.close()
    trust.close()


def test_missing_ca_file_raises_instead_of_silently_disabling_verification():
    # The invariant of this module. Falling back to verify=False would show the
    # user green verdicts and let them believe certificates were checked.
    with pytest.raises(TrustError):
        build(SOURCE_FILE, ca_path="")
    with pytest.raises(TrustError):
        build(SOURCE_FILE, ca_path="/no/such/ca.crt")


def test_api_source_without_a_fetched_pem_raises():
    with pytest.raises(TrustError):
        build(SOURCE_API, ca_pem=None)


def test_api_source_uses_the_fetched_pem():
    trust = build(SOURCE_API, ca_pem=REAL_PEM)
    try:
        assert isinstance(trust.verify, ssl.SSLContext)
    finally:
        trust.close()


def test_unknown_source_raises():
    with pytest.raises(TrustError):
        build("whatever")


def test_issuer_error_on_the_system_source_names_the_real_cause():
    text = explain_tls_error("unable to get local issuer certificate", SOURCE_SYSTEM)
    assert "OS trust store" in text
    assert "Fetch from API" in text


def test_issuer_error_on_a_file_source_does_not_blame_the_os_store():
    text = explain_tls_error("unable to get local issuer certificate", SOURCE_FILE)
    assert "OS trust store" not in text
