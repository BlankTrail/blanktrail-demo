"""Where lane B's TLS trust comes from.

Verification on lane B is ON by default and is part of the measurement: a
successful handshake proves the MITM chain is well-formed and the substituted
certificate's SAN matches the requested host.

The trap this module exists for: Python DOES read the OS trust store, but
`requests` and `httpx` do not use it — both pass cafile=certifi.where() and
thereby discard the system roots. Measured on Windows 10 / CPython 3.13.5:

    ssl.create_default_context() -> 228 roots, 'BlankTrail Proxy CA' among them
    requests.certs.where()       -> ...\\certifi\\cacert.pem

So the context has to be built here and handed to the client explicitly.
"""

from __future__ import annotations

import os
import ssl
import tempfile
from dataclasses import dataclass

import certifi

SOURCE_SYSTEM = "system"
SOURCE_API = "api"
SOURCE_FILE = "file"


class TrustError(Exception):
    """The chosen trust source could not be honoured. Never downgraded to
    verify=False: the user would read green verdicts as proof that certificates
    were checked."""


@dataclass
class Trust:
    verify: object              # False | ssl.SSLContext
    label: str                  # shown in the run header
    bundle_path: str | None     # temp file to remove, if any

    def close(self) -> None:
        if self.bundle_path and os.path.exists(self.bundle_path):
            try:
                os.unlink(self.bundle_path)
            except OSError:
                pass
        self.bundle_path = None


def system_context() -> ssl.SSLContext:
    """A context backed by the operating system's trust store.

    `truststore` reaches the store through native APIs — CryptoAPI on Windows,
    Security framework on macOS — and is the only way to see a Keychain-installed
    root, which CPython does not read. Without the package the stdlib context
    still covers Windows and Linux, so the import is soft rather than required.
    """
    try:
        import truststore
    except ImportError:
        return ssl.create_default_context()
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


def combined_bundle(pem: bytes) -> str:
    """certifi's roots PLUS the given PEM, in one temp file.

    Combined rather than substituted: hosts excluded from MITM on the port serve
    their real origin certificate, and a bundle holding only the BlankTrail root
    would stop verifying them.
    """
    handle, path = tempfile.mkstemp(prefix="blanktrail-ca-", suffix=".pem")
    with os.fdopen(handle, "wb") as out:
        out.write(open(certifi.where(), "rb").read())
        out.write(b"\n")
        out.write(pem.strip())
        out.write(b"\n")
    return path


def build(source: str, *, disabled: bool = False, ca_pem: bytes | None = None,
          ca_path: str | None = None) -> Trust:
    """Resolve the form's TLS settings into something a client can use."""
    if disabled:
        return Trust(verify=False, label="verification disabled", bundle_path=None)

    if source == SOURCE_SYSTEM:
        try:
            import truststore  # noqa: F401
            label = "OS trust store (truststore)"
        except ImportError:
            label = "OS trust store (stdlib)"
        return Trust(verify=system_context(), label=label, bundle_path=None)

    if source == SOURCE_FILE:
        if not ca_path:
            raise TrustError("CA file source selected but no path was given")
        if not os.path.isfile(ca_path):
            raise TrustError(f"CA file not found: {ca_path}")
        try:
            pem = open(ca_path, "rb").read()
        except OSError as exc:
            raise TrustError(f"cannot read the CA file: {exc}") from exc
        label = f"CA file + certifi ({os.path.basename(ca_path)})"

    elif source == SOURCE_API:
        if not ca_pem:
            raise TrustError("CA could not be fetched from the BlankTrail API")
        pem = ca_pem
        label = "CA fetched from the API + certifi"

    else:
        raise TrustError(f"unknown trust source: {source!r}")

    path = combined_bundle(pem)
    return Trust(verify=ssl.create_default_context(cafile=path), label=label,
                 bundle_path=path)


def explain_tls_error(message: str, source: str) -> str:
    """Turn an OpenSSL string into something the user can act on."""
    low = message.lower()
    if "unable to get local issuer certificate" in low or "self-signed" in low:
        if source == SOURCE_SYSTEM:
            return ("certificate not trusted: the BlankTrail CA was not found in the OS "
                    "trust store. Install it, or switch the trust source to "
                    "'Fetch from API'. Original error: " + message)
        return ("certificate not trusted: the supplied CA does not sign this chain. "
                "Original error: " + message)
    if "hostname mismatch" in low or "certificate verify failed: hostname" in low:
        return ("certificate SAN does not match the requested host. Original error: "
                + message)
    return "TLS error: " + message
