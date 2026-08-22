"""Pure classification and verdict logic. Knows nothing about network or Flask."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

PASSED = "passed"
BLOCKED = "blocked"
UNKNOWN = "unknown"
ERROR = "error"

# x-amzn-waf-action values that mean the request was stopped. AWS sends this
# header for nothing else, which is why it alone decides.
AWS_ACTIONS = ("captcha", "challenge")

# Cloudflare only serves an interstitial on these statuses.
CF_CHALLENGE_STATUS = (403, 503)

# Verdict -> counter key. Keys are JS-safe (no dashes): the UI reads them as
# properties.
STAT_KEY = {"PASS": "passed", "FAIL": "failed", "VOID": "void", "ERROR": "err"}


def _hdr(headers: Mapping[str, str] | None, name: str) -> str:
    """Case-insensitive header read. Tests pass a plain dict; requests and httpx
    pass their own case-insensitive mappings. Both must behave the same."""
    if not headers:
        return ""
    value = headers.get(name)
    if value is None:
        low = name.lower()
        for key, val in headers.items():
            if str(key).lower() == low:
                value = val
                break
    return (value or "").strip()


def _signals(headers, body, cookies) -> dict:
    """Every raw signal in one place, so the verdict and the report read the
    same set."""
    low = (body or "").lower()
    names = set(cookies or [])
    return {
        "waf_action": _hdr(headers, "x-amzn-waf-action").lower(),
        "cf_mitigated": _hdr(headers, "cf-mitigated").lower(),
        "cf_chl_opt": "_cf_chl_opt" in low,
        "blocked_phrase": "you have been blocked" in low,
        # Cloudflare injects this into ordinary 200 pages too. Reported, never
        # decisive.
        "chl_platform": "/cdn-cgi/challenge-platform/" in low,
        "cf_clearance": "cf_clearance" in names,
        "aws_waf_token": "aws-waf-token" in names,
        "server": _hdr(headers, "server"),
        "via": _hdr(headers, "via"),
    }


def _soft_vendor(signals: dict) -> str:
    """Best-effort vendor label for the report when nothing was blocked."""
    server = signals["server"].lower()
    via = signals["via"].lower()
    if "cloudflare" in server or signals["cf_clearance"] or signals["chl_platform"]:
        return "cloudflare"
    if "cloudfront" in via or "cloudfront" in server or signals["aws_waf_token"]:
        return "awswaf"
    return ""


def classify(status: int, headers: Mapping[str, str], body: str,
             cookies: Sequence[str]) -> dict:
    """One observation of one response.

    `cookies` is a list of cookie NAMES (list[str]) — not a jar and not Cookie
    objects. Names are looked up by membership, so objects would silently miss
    forever instead of raising.

    Returns {"state": passed|blocked|unknown, "vendor": str, "reason": str,
    "signals": dict}.
    """
    signals = _signals(headers, body, cookies)

    # 1. AWS first. The HEADER decides, not the status: 405 is a captcha and 202
    #    is a challenge. Putting this below the "200 = passed" rule would turn a
    #    202 challenge into a pass.
    action = signals["waf_action"]
    if action in AWS_ACTIONS:
        return {"state": BLOCKED, "vendor": "awswaf",
                "reason": f"HTTP {status}: x-amzn-waf-action: {action}",
                "signals": signals}

    # 2. Cloudflare: a DISJUNCTION of three signals, status-gated. A jschl
    #    challenge carries no cf-mitigated header, so requiring it would mean
    #    never seeing jschl.
    if status in CF_CHALLENGE_STATUS:
        hits = []
        if signals["cf_mitigated"] == "challenge":
            hits.append("cf-mitigated: challenge")
        if signals["cf_chl_opt"]:
            hits.append("_cf_chl_opt in body")
        if signals["blocked_phrase"]:
            hits.append('"you have been blocked" in body')
        if hits:
            return {"state": BLOCKED, "vendor": "cloudflare",
                    "reason": f"HTTP {status}: " + ", ".join(hits),
                    "signals": signals}

    if action:
        return {"state": UNKNOWN, "vendor": "awswaf",
                "reason": f"HTTP {status}: unrecognised x-amzn-waf-action: {action}",
                "signals": signals}

    # 3. THE MAIN INVARIANT: 200 means passed regardless of the body. Markers
    #    lie on their own — Cloudflare injects challenge-platform into ordinary
    #    pages, and Turnstile widgets sit embedded in open ones.
    if status == 200:
        extra = []
        if signals["cf_clearance"]:
            extra.append("+cf_clearance")
        if signals["aws_waf_token"]:
            extra.append("+aws-waf-token")
        if signals["chl_platform"]:
            extra.append("challenge-platform in body — injected into ordinary 200s too, "
                         "not decisive")
        reason = "HTTP 200" + (" (" + "; ".join(extra) + ")" if extra else "")
        return {"state": PASSED, "vendor": _soft_vendor(signals), "reason": reason,
                "signals": signals}

    return {"state": UNKNOWN, "vendor": _soft_vendor(signals),
            "reason": f"HTTP {status} with no recognised challenge signal — likely the "
                      f"site's own page; check the raw dump",
            "signals": signals}


def verdict(obs_a: dict | None, obs_b: dict, no_baseline: bool = False) -> dict:
    """Verdict from the two lanes. Pure.

    obs_a is the baseline lane, obs_b the BlankTrail lane. When no_baseline is
    True the baseline lane was switched off and obs_a is None.
    """
    b = obs_b["state"]

    if no_baseline:
        if b == ERROR:
            return {"verdict": "ERROR", "why": f"BlankTrail lane: {obs_b['reason']}"}
        if b == UNKNOWN:
            return {"verdict": "VOID",
                    "why": f"unrecognised response ({obs_b['reason']}) — read the raw dump"}
        if b == PASSED:
            return {"verdict": "PASS",
                    "why": "got through. With no baseline lane this does not prove the "
                           "target challenges anyone at all"}
        return {"verdict": "FAIL",
                "why": f"did not get through ({obs_b['reason']}) — read the raw dump"}

    a = obs_a["state"]

    # Baseline did not run -> nothing to measure against.
    if a == ERROR:
        return {"verdict": "ERROR", "why": f"baseline lane: {obs_a['reason']}"}

    # Checked ABOVE lane B's error on purpose: if the bare lane got through,
    # there is nothing left to prove, whatever happened on lane B.
    if a == PASSED:
        return {"verdict": "VOID",
                "why": "protection is not active: the bare lane got through, so the target "
                       "proves nothing (rule disabled, or the site changed defences)"}

    if b == ERROR:
        return {"verdict": "ERROR", "why": f"BlankTrail lane: {obs_b['reason']}"}

    # An unrecognised observation never becomes PASS or FAIL.
    if a == UNKNOWN or b == UNKNOWN:
        lane, o = ("baseline", obs_a) if a == UNKNOWN else ("BlankTrail", obs_b)
        return {"verdict": "VOID",
                "why": f"{lane} lane unrecognised ({o['reason']}) — read the raw dump"}

    if b == PASSED:
        return {"verdict": "PASS",
                "why": "protection is active (baseline blocked) and BlankTrail gets through"}
    return {"verdict": "FAIL",
            "why": f"baseline blocked and BlankTrail did not get through either "
                   f"({obs_b['reason']}) — read the BlankTrail lane's raw dump"}
