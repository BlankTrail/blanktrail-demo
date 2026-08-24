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

# Statuses on which DataDome, PerimeterX/HUMAN, Imperva and Akamai were
# observed to challenge or block, across a probe of 784 domains: DataDome
# answered with 401 and 403; Akamai with 403 and 429; PerimeterX and Imperva
# with 403; and 405/406 turned up on other blocks in the same sweep. Kept
# separate from CF_CHALLENGE_STATUS so Cloudflare's own pinned behaviour can
# never drift when this one changes.
ANTIBOT_CHALLENGE_STATUS = (401, 403, 405, 406, 429, 503)

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


def _has_header_prefix(headers: Mapping[str, str] | None, prefix: str) -> bool:
    """True if any header NAME starts with `prefix`, case-insensitive. For
    families like Akamai's x-akamai-* where the values are unpredictable but
    no other vendor uses the prefix."""
    if not headers:
        return False
    low = prefix.lower()
    return any(str(name).lower().startswith(low) for name in headers)


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
        # DataDome.
        "dd_header": bool(_hdr(headers, "x-datadome")),
        "dd_cookie": "datadome" in names,
        "dd_body": "captcha-delivery.com" in low
                   or ("#cmsg" in low and "@keyframes a" in low),
        # PerimeterX / HUMAN. Cookies are prefix-matched: PerimeterX sets
        # several `_px*` names and `_pxhd` is one of them, not a separate
        # family of its own.
        "px_header": bool(_hdr(headers, "x-px")),
        "px_cookie": any(name.startswith("_px") for name in names),
        "px_body": any(marker in low for marker in
                       ("px-captcha", "perimeterx", "human-challenge")),
        # Imperva.
        "imp_header": bool(_hdr(headers, "x-iinfo")),
        "imp_cookie": "incap_ses" in names or "visid_incap" in names,
        "imp_body": "_incapsula_resource" in low or "incapsula incident" in low,
        # Akamai. Weakest evidence of the four -- no header here is exclusive
        # to it, which is why it is checked last in classify().
        "ak_server": "akamai" in _hdr(headers, "server").lower(),
        "ak_header": bool(_hdr(headers, "x-akamai-transformed")),
        "ak_cookie": bool(names & {"_abck", "bm_sz", "ak_bmsc"}),
        "ak_body": "errors.edgesuite.net" in low,
        # Edge attribution (see classify()'s final fallback): identifies which
        # CDN or load balancer answered, independent of whether anything above
        # recognised an actual challenge or block.
        "cf_ray": bool(_hdr(headers, "cf-ray")),
        "ak_edge_header": _has_header_prefix(headers, "x-akamai-"),
        "cloudfront_via": "cloudfront" in _hdr(headers, "via").lower(),
        "cloudfront_server": "cloudfront" in _hdr(headers, "server").lower(),
        "amz_cf_id": bool(_hdr(headers, "x-amz-cf-id")),
        "awselb_server": "awselb" in _hdr(headers, "server").lower(),
        "fastly_request_id": bool(_hdr(headers, "x-fastly-request-id")),
        "via_varnish": "varnish" in _hdr(headers, "via").lower(),
        "x_served_by": bool(_hdr(headers, "x-served-by")),
        # True only on classify()'s edge-attribution fallback path. Set here
        # (not just left absent) so the key is always present for callers to
        # check, whichever path actually returned.
        "edge_attributed": False,
    }


def _soft_vendor(signals: dict) -> str:
    """Best-effort vendor label for the report when nothing was blocked. Same
    precedence as classify(): the more specific vendors first, Akamai last --
    this never affects state, only the label."""
    server = signals["server"].lower()
    via = signals["via"].lower()
    if signals["dd_header"] or signals["dd_cookie"]:
        return "datadome"
    if signals["px_header"] or signals["px_cookie"]:
        return "perimeterx"
    if signals["imp_header"] or signals["imp_cookie"]:
        return "imperva"
    if "cloudflare" in server or signals["cf_clearance"] or signals["chl_platform"]:
        return "cloudflare"
    if "cloudfront" in via or "cloudfront" in server or signals["aws_waf_token"]:
        return "awswaf"
    if signals["ak_server"] or signals["ak_header"] or signals["ak_cookie"]:
        return "akamai"
    return ""


# Human-readable label for classify()'s edge-attribution fallback, keyed by
# the same vendor code it returns. The reason string below uses this instead
# of the raw vendor code ("awselb edge") on purpose -- "an AWS load balancer"
# reads as English and, for that one specifically, does not look like it says
# "AWS WAF" at a glance.
EDGE_LABEL = {
    "cloudflare": "a Cloudflare edge",
    "akamai": "an Akamai edge",
    "cloudfront": "a CloudFront edge",
    "awselb": "an AWS load balancer",
    "fastly": "a Fastly edge",
}


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

    # 2. DataDome, PerimeterX/HUMAN and Imperva are checked before
    #    Cloudflare's rule below on purpose: all three can sit behind a
    #    Cloudflare edge (a Cloudflare `server` header, sometimes even a
    #    Cloudflare challenge of its own) while the block page actually
    #    belongs to them. Checking the more specific vendor first attributes
    #    the site to whoever actually blocked it, not to the CDN in front of
    #    it. Each is its own status-gated disjunction, same shape as
    #    Cloudflare's below.
    if status in ANTIBOT_CHALLENGE_STATUS:
        hits = []
        if signals["dd_header"]:
            hits.append("x-datadome header present")
        if signals["dd_cookie"]:
            hits.append("datadome cookie")
        if signals["dd_body"]:
            hits.append("DataDome block markers in body")
        if hits:
            return {"state": BLOCKED, "vendor": "datadome",
                    "reason": f"HTTP {status}: " + ", ".join(hits),
                    "signals": signals}

    # 3. PerimeterX / HUMAN.
    if status in ANTIBOT_CHALLENGE_STATUS:
        hits = []
        if signals["px_header"]:
            hits.append("x-px header present")
        if signals["px_cookie"]:
            hits.append("_px*/_pxhd cookie")
        if signals["px_body"]:
            hits.append("PerimeterX/HUMAN markers in body")
        if hits:
            return {"state": BLOCKED, "vendor": "perimeterx",
                    "reason": f"HTTP {status}: " + ", ".join(hits),
                    "signals": signals}

    # 4. Imperva.
    if status in ANTIBOT_CHALLENGE_STATUS:
        hits = []
        if signals["imp_header"]:
            hits.append("x-iinfo header present")
        if signals["imp_cookie"]:
            hits.append("incap_ses/visid_incap cookie")
        if signals["imp_body"]:
            hits.append("Imperva markers in body")
        if hits:
            return {"state": BLOCKED, "vendor": "imperva",
                    "reason": f"HTTP {status}: " + ", ".join(hits),
                    "signals": signals}

    # 5. Cloudflare: a DISJUNCTION of three signals, status-gated. A jschl
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

    # 6. Akamai last: its evidence is the weakest of the four -- mostly
    #    cookie-based, and the one header it has is not exclusive to it --
    #    so anything checked above gets first claim on an ambiguous response.
    if status in ANTIBOT_CHALLENGE_STATUS:
        hits = []
        if signals["ak_server"]:
            hits.append("server header contains akamai")
        if signals["ak_header"]:
            hits.append("x-akamai-transformed header present")
        if signals["ak_cookie"]:
            hits.append("_abck/bm_sz/ak_bmsc cookie")
        if signals["ak_body"]:
            hits.append("errors.edgesuite.net in body")
        if hits:
            return {"state": BLOCKED, "vendor": "akamai",
                    "reason": f"HTTP {status}: " + ", ".join(hits),
                    "signals": signals}

    if action:
        return {"state": UNKNOWN, "vendor": "awswaf",
                "reason": f"HTTP {status}: unrecognised x-amzn-waf-action: {action}",
                "signals": signals}

    # Edge attribution: the final fallback. Nothing above recognised a
    # specific challenge or block, but the response still identifies which
    # CDN or load balancer answered -- so call it `blocked`, attributed to
    # that edge, instead of leaving a measurable 403 as `unknown` and forcing
    # a VOID verdict. This is deliberately the weakest attribution in the
    # module (see the reason string below): unlike every check above, it has
    # no vendor-specific challenge evidence at all, only the fact that a
    # known edge answered. It is the last thing tried, and only for the five
    # edges the owner has asked for -- every other edge (awselb aside, every
    # other CDN) stays `unknown` until asked.
    #
    # Checked in a fixed order -- Cloudflare, Akamai, CloudFront, AWS ELB,
    # Fastly -- and returns on the first match. The order itself is
    # arbitrary; only its being fixed matters, so a response that happens to
    # identify more than one edge resolves the same way on every run instead
    # of depending on dict/iteration order.
    if status in ANTIBOT_CHALLENGE_STATUS:
        server = signals["server"].lower()
        edge = ""
        if "cloudflare" in server or signals["cf_ray"]:
            edge = "cloudflare"
        elif "akamai" in server or signals["ak_edge_header"]:
            edge = "akamai"
        elif (signals["cloudfront_via"] or signals["cloudfront_server"]
              or signals["amz_cf_id"]):
            edge = "cloudfront"
        elif signals["awselb_server"]:
            edge = "awselb"
        elif signals["fastly_request_id"] or (
                signals["via_varnish"] and signals["x_served_by"]):
            edge = "fastly"

        if edge:
            signals["edge_attributed"] = True
            return {"state": BLOCKED, "vendor": edge,
                    "reason": f"HTTP {status}: response came from behind "
                              f"{EDGE_LABEL[edge]}, but no check above recognised a "
                              f"specific challenge or block on it — edge attribution, "
                              f"not a recognised challenge; could equally be the "
                              f"site's own rule, a geographic restriction or an "
                              f"authentication requirement",
                    "signals": signals}

    # 7. THE MAIN INVARIANT: 200 means passed regardless of the body. Markers
    #    lie on their own — Cloudflare injects challenge-platform into ordinary
    #    pages, and Turnstile widgets sit embedded in open ones. The same is
    #    true of every check above: DataDome, PerimeterX, Imperva and Akamai
    #    all set their cookies on ordinary successful pages too, which is
    #    exactly why every one of them is gated on ANTIBOT_CHALLENGE_STATUS /
    #    CF_CHALLENGE_STATUS above and never runs on its own against a 200.
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


def _edge_caveat(obs_a: dict | None, obs_b: dict) -> str:
    """Name any lane whose `blocked` rests only on edge attribution.

    classify() calls a gated status `blocked` when it can name the CDN in front
    of a site but recognised no vendor challenge on the response. That is a
    weaker fact than a solved challenge, and the verdict must not spend it as if
    it were the stronger one: behind such a block there may be no bot protection
    at all.

    Reads `signals`, which is already a key of the observations verdict() is
    handed — so this stays a pure function of its arguments, with no new
    interface. Observations built by hand without that key are tolerated.
    """
    lanes = [name for name, o in (("baseline", obs_a), ("BlankTrail", obs_b))
             if o and o["state"] == BLOCKED
             and (o.get("signals") or {}).get("edge_attributed")]
    if not lanes:
        return ""
    which = " and ".join(lanes)
    plural = "lanes'" if len(lanes) > 1 else "lane's"
    return (f" — but the {which} {plural} block carried no recognised challenge signal and "
            f"was attributed to the edge in front of the site, so it may equally have been "
            f"the site's own rule, a geographic restriction or an authentication requirement")


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
                "why": f"did not get through ({obs_b['reason']}) — read the raw dump"
                       + _edge_caveat(None, obs_b)}

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

    caveat = _edge_caveat(obs_a, obs_b)
    if b == PASSED:
        if caveat:
            # The strong claim is only made on strong evidence.
            return {"verdict": "PASS",
                    "why": "the baseline lane was blocked and BlankTrail gets through"
                           + caveat}
        return {"verdict": "PASS",
                "why": "protection is active (baseline blocked) and BlankTrail gets through"}
    return {"verdict": "FAIL",
            "why": f"baseline blocked and BlankTrail did not get through either "
                   f"({obs_b['reason']}) — read the BlankTrail lane's raw dump" + caveat}
