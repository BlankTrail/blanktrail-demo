"""Pure handling of proxy URLs. No network."""

from __future__ import annotations

from urllib.parse import urlsplit

from .targets import ParseError

# Values a user types when they mean "no proxy at all".
_EMPTY = ("direct", "none", "-")


def normalize(raw: str | None) -> str | None:
    """Canonical proxy URL, or None when the field means "no proxy".

    Two deliberate rules:
      * a bare `host:port` becomes `http://` — HTTP CONNECT is the simpler and
        more reliable of the two proxy protocols, so it is the default;
      * `socks5://` becomes `socks5h://` — the `h` makes the proxy resolve DNS.
        Without it the local resolver picks the target address and the baseline
        lane stops sharing an egress with the BlankTrail lane, which is the one
        assumption the whole measurement rests on.
    """
    text = (raw or "").strip()
    if not text or text.lower() in _EMPTY:
        return None
    if "://" not in text:
        text = "http://" + text
    if text.startswith("socks5://"):
        text = "socks5h://" + text[len("socks5://"):]
    return text


def for_httpx(url: str | None) -> str | None:
    """httpx rejects the socks5h scheme but resolves proxy-side anyway."""
    if not url:
        return None
    if url.startswith("socks5h://"):
        return "socks5://" + url[len("socks5h://"):]
    return url


def hostport(url: str) -> tuple[str, int] | None:
    """(host, port) for the TCP preflight, or None when there is nothing to parse."""
    try:
        parts = urlsplit(url if "://" in url else "http://" + url)
        if parts.hostname and parts.port:
            return parts.hostname, parts.port
    except ValueError:
        pass
    return None


def parse_list(text: str) -> tuple[list[str], list[ParseError]]:
    """Textarea of preset proxy URLs -> (urls, errors), order preserved, deduped."""
    urls: list[str] = []
    errors: list[ParseError] = []
    seen: set[str] = set()

    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        cut = raw_line.find(" #")
        line = (raw_line if cut < 0 else raw_line[:cut]).strip()
        if not line or line.startswith("#"):
            continue
        url = normalize(line)
        if url is None:
            errors.append(ParseError(line_no, line, "not a proxy URL"))
            continue
        if hostport(url) is None:
            errors.append(ParseError(line_no, line, "no port in the proxy URL"))
            continue
        if url in seen:
            continue
        seen.add(url)
        urls.append(url)

    return urls, errors
