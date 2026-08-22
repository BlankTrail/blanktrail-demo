"""Pure parsing of the user-supplied target list. No network, no Flask."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

# A run is a demo, not a crawler. The cap keeps a pasted sitemap from turning
# the form into one.
MAX_TARGETS = 200

ALLOWED_SCHEMES = ("http", "https")


@dataclass(frozen=True)
class Target:
    id: str
    url: str


@dataclass(frozen=True)
class ParseError:
    line_no: int
    text: str
    error: str


def _strip_comment(line: str) -> str:
    """Drop a trailing ` # ...` comment. The space matters: a bare '#' can be a
    legitimate URL fragment separator."""
    cut = line.find(" #")
    return line if cut < 0 else line[:cut]


def _normalize(raw: str) -> str:
    """Add the default scheme and lowercase the host. The path keeps its case —
    some origins route on it."""
    text = raw if "://" in raw else "https://" + raw
    parts = urlsplit(text)
    if parts.scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"unsupported scheme {parts.scheme!r}; use http or https")
    if not parts.hostname:
        raise ValueError("no host in the URL")
    netloc = parts.netloc.lower()
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, ""))


def _make_id(url: str, used: set[str]) -> str:
    host = (urlsplit(url).hostname or "target").removeprefix("www.")
    candidate = host
    n = 1
    while candidate in used:
        n += 1
        candidate = f"{host}-{n}"
    used.add(candidate)
    return candidate


def parse_targets(text: str) -> tuple[list[Target], list[ParseError]]:
    """Textarea contents -> (targets, errors).

    Errors carry the 1-based line number so the UI can report every bad line at
    once, before the run starts, instead of dribbling them out mid-run.
    """
    targets: list[Target] = []
    errors: list[ParseError] = []
    seen: set[str] = set()
    used_ids: set[str] = set()

    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = _strip_comment(raw_line).strip()
        if not line or line.startswith("#"):
            continue
        if len(targets) >= MAX_TARGETS:
            errors.append(ParseError(line_no, line,
                                     f"more than {MAX_TARGETS} targets; the rest were dropped"))
            break
        try:
            url = _normalize(line)
        except ValueError as exc:
            errors.append(ParseError(line_no, line, str(exc)))
            continue
        if url in seen:
            continue
        seen.add(url)
        targets.append(Target(id=_make_id(url, used_ids), url=url))

    return targets, errors
