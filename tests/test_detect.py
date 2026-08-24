import pytest

from blanktrail_demo.detect import BLOCKED, PASSED, UNKNOWN, classify, verdict


def obs(state, reason="r", vendor=""):
    return {"state": state, "reason": reason, "vendor": vendor, "signals": {}}


# --------------------------------------------------------------- classify: AWS

@pytest.mark.parametrize("status", [200, 202, 405, 403])
def test_aws_waf_action_header_decides_regardless_of_status(status):
    # AWS answers a captcha with 405 and a challenge with 202. The header, not
    # the status, is what says "blocked" — so this check must run before the
    # "200 means passed" rule, or a 202 challenge silently becomes passed.
    o = classify(status, {"x-amzn-waf-action": "challenge"}, "", [])
    assert o["state"] == BLOCKED
    assert o["vendor"] == "awswaf"


def test_aws_header_is_case_insensitive():
    o = classify(405, {"X-Amzn-Waf-Action": "CAPTCHA"}, "", [])
    assert o["state"] == BLOCKED


def test_unknown_aws_action_is_not_a_verdict():
    o = classify(200, {"x-amzn-waf-action": "something-new"}, "", [])
    assert o["state"] == UNKNOWN


# -------------------------------------------------------- classify: Cloudflare

@pytest.mark.parametrize("status", [403, 503])
@pytest.mark.parametrize("headers,body", [
    ({"cf-mitigated": "challenge"}, ""),
    ({}, "<html>_cf_chl_opt</html>"),
    ({}, "<html>You have been blocked</html>"),
])
def test_cloudflare_signals_are_a_disjunction(status, headers, body):
    # A jschl challenge carries no cf-mitigated header at all. Requiring it
    # would mean never seeing jschl.
    o = classify(status, headers, body, [])
    assert o["state"] == BLOCKED
    assert o["vendor"] == "cloudflare"


def test_403_without_any_cloudflare_signal_is_unknown():
    o = classify(403, {}, "<html>Access denied by the site</html>", [])
    assert o["state"] == UNKNOWN


# ---------------------------------------------------------- classify: DataDome

@pytest.mark.parametrize("status", [401, 403, 405, 406, 429, 503])
def test_all_new_vendor_challenge_statuses_are_recognised(status):
    # DataDome answered with 401 and 403 in the probe; Akamai with 403 and
    # 429; PerimeterX and Imperva with 403; 405 and 406 turned up on other
    # blocks in the same sweep. All four new checks share one status gate, so
    # proving it here for one vendor proves the gate itself for all four.
    o = classify(status, {"x-datadome": "protected"}, "", [])
    assert o["state"] == BLOCKED
    assert o["vendor"] == "datadome"


@pytest.mark.parametrize("headers,body,cookies", [
    ({"x-datadome": "protected"}, "", []),
    ({}, "", ["datadome"]),
    ({}, "<html>captcha-delivery.com</html>", []),
    ({}, "<style>#cmsg{display:block} @keyframes a { from { opacity: 0 } }</style>", []),
])
def test_datadome_signals_are_a_disjunction(headers, body, cookies):
    o = classify(403, headers, body, cookies)
    assert o["state"] == BLOCKED
    assert o["vendor"] == "datadome"


def test_datadome_body_marker_needs_both_cmsg_and_keyframes():
    # Either alone is too weak on its own -- both together are the measured
    # DataDome block-page signature.
    o = classify(403, {}, "<style>#cmsg{display:block}</style>", [])
    assert o["state"] != BLOCKED


def test_200_is_passed_even_with_datadome_cookie_present():
    # The invariant that guards Cloudflare above must hold for every new
    # vendor too: DataDome sets this cookie on ordinary successful pages.
    o = classify(200, {}, "", ["datadome"])
    assert o["state"] == PASSED
    assert o["vendor"] == "datadome"


# -------------------------------------------------------- classify: PerimeterX

@pytest.mark.parametrize("headers,body,cookies", [
    ({"x-px": "1"}, "", []),
    ({}, "", ["_px"]),
    ({}, "", ["_pxhd"]),
    ({}, "<html>px-captcha</html>", []),
    ({}, "<html>perimeterx</html>", []),
    ({}, "<html>human-challenge</html>", []),
])
def test_perimeterx_signals_are_a_disjunction(headers, body, cookies):
    o = classify(403, headers, body, cookies)
    assert o["state"] == BLOCKED
    assert o["vendor"] == "perimeterx"


def test_200_is_passed_even_with_perimeterx_cookies_present():
    o = classify(200, {}, "", ["_px", "_pxhd"])
    assert o["state"] == PASSED
    assert o["vendor"] == "perimeterx"


# ----------------------------------------------------------- classify: Imperva

@pytest.mark.parametrize("headers,body,cookies", [
    ({"x-iinfo": "12-3456789-0"}, "", []),
    ({}, "", ["incap_ses"]),
    ({}, "", ["visid_incap"]),
    ({}, "<html>_incapsula_resource</html>", []),
    ({}, "<html>Incapsula incident ID: 12345</html>", []),
])
def test_imperva_signals_are_a_disjunction(headers, body, cookies):
    o = classify(403, headers, body, cookies)
    assert o["state"] == BLOCKED
    assert o["vendor"] == "imperva"


def test_200_is_passed_even_with_imperva_cookies_present():
    o = classify(200, {}, "", ["incap_ses", "visid_incap"])
    assert o["state"] == PASSED
    assert o["vendor"] == "imperva"


# ------------------------------------------------------------ classify: Akamai

@pytest.mark.parametrize("headers,body,cookies", [
    ({"server": "AkamaiGHost"}, "", []),
    ({"x-akamai-transformed": "1 - 2 - 3"}, "", []),
    ({}, "", ["_abck"]),
    ({}, "", ["bm_sz"]),
    ({}, "", ["ak_bmsc"]),
    ({}, "<html>errors.edgesuite.net</html>", []),
])
def test_akamai_signals_are_a_disjunction(headers, body, cookies):
    o = classify(403, headers, body, cookies)
    assert o["state"] == BLOCKED
    assert o["vendor"] == "akamai"


def test_200_is_passed_even_with_akamai_cookies_present():
    o = classify(200, {}, "", ["_abck", "bm_sz", "ak_bmsc"])
    assert o["state"] == PASSED
    assert o["vendor"] == "akamai"


# ------------------------------------------------- classify: new vendor bodies

@pytest.mark.parametrize("body,vendor", [
    ("<html>CAPTCHA-DELIVERY.COM</html>", "datadome"),
    ("<html>PerimeterX</html>", "perimeterx"),
    ("<html>INCAPSULA INCIDENT</html>", "imperva"),
    ("<html>Errors.Edgesuite.Net</html>", "akamai"),
])
def test_new_vendor_body_markers_are_case_insensitive(body, vendor):
    o = classify(403, {}, body, [])
    assert o["state"] == BLOCKED
    assert o["vendor"] == vendor


# --------------------------------------------------- classify: vendor ordering

@pytest.mark.parametrize("vendor_headers,vendor", [
    ({"x-datadome": "protected"}, "datadome"),
    ({"x-px": "1"}, "perimeterx"),
    ({"x-iinfo": "12-3456789-0"}, "imperva"),
])
def test_new_vendor_wins_over_a_cloudflare_server_header(vendor_headers, vendor):
    # A Cloudflare `server` header alone never decides Cloudflare's own block
    # (see the disjunction above) -- but a naive "Cloudflare first" ordering
    # could still misattribute a different vendor's block page to Cloudflare
    # merely because it runs first and a `server` header happens to be
    # present. This mirrors an observed, real pattern: a site fronted by a
    # Cloudflare edge while a different vendor is the one actually blocking.
    headers = {"server": "cloudflare", **vendor_headers}
    o = classify(403, headers, "", [])
    assert o["state"] == BLOCKED
    assert o["vendor"] == vendor


def test_datadome_wins_even_against_a_genuine_cloudflare_challenge():
    # Stronger than the case above: Cloudflare's own decisive signal
    # (cf-mitigated) is present too, so this only passes if DataDome's check
    # genuinely runs first -- not merely because Cloudflare's own disjunction
    # stayed silent.
    o = classify(403, {"cf-mitigated": "challenge", "x-datadome": "protected"}, "", [])
    assert o["state"] == BLOCKED
    assert o["vendor"] == "datadome"


def test_akamai_evidence_does_not_preempt_cloudflares_own_challenge():
    # Akamai is checked last because its evidence is the weakest of the
    # four -- mostly cookie-based -- so it must never preempt a genuine
    # Cloudflare challenge appearing on the same response.
    o = classify(403, {"cf-mitigated": "challenge",
                        "x-akamai-transformed": "1 - 2 - 3"}, "", [])
    assert o["state"] == BLOCKED
    assert o["vendor"] == "cloudflare"


@pytest.mark.parametrize("cookies,vendor", [
    (["datadome"], "datadome"),
    (["_px"], "perimeterx"),
    (["incap_ses"], "imperva"),
    (["_abck"], "akamai"),
])
def test_ungated_status_with_only_vendor_cookies_is_not_blocked(cookies, vendor):
    # 302 is not in the new vendors' status gate. These vendors set their
    # cookies on ordinary pages too, so cookie presence alone at an ungated
    # status must never read as blocked.
    o = classify(302, {}, "", cookies)
    assert o["state"] != BLOCKED


@pytest.mark.parametrize("cookies,vendor", [
    (["datadome"], "datadome"),
    (["_pxhd"], "perimeterx"),
    (["incap_ses"], "imperva"),
    (["_abck"], "akamai"),
])
def test_soft_vendor_names_the_new_vendors_even_when_unrecognised(cookies, vendor):
    # _soft_vendor() must never affect state -- only the reporting label.
    o = classify(500, {}, "", cookies)
    assert o["state"] == UNKNOWN
    assert o["vendor"] == vendor


# ------------------------------------------------- classify: edge attribution

@pytest.mark.parametrize("edge,headers", [
    ("cloudflare", {"server": "cloudflare"}),
    ("cloudflare", {"cf-ray": "7d3a1c9f2e4b0011-SJC"}),
    ("akamai", {"x-akamai-session-info": "true"}),
    ("cloudfront", {"via": "1.1 abc123.cloudfront.net (CloudFront)"}),
    ("cloudfront", {"server": "CloudFront"}),
    ("cloudfront", {"x-amz-cf-id": "abcDEF123=="}),
    ("awselb", {"server": "awselb/2.0"}),
    ("fastly", {"x-fastly-request-id": "abc123"}),
    ("fastly", {"via": "1.1 varnish", "x-served-by": "cache-abc123-XYZ"}),
])
def test_edge_is_attributed_at_a_gated_status_when_nothing_else_recognised(edge, headers):
    o = classify(403, headers, "", [])
    assert o["state"] == BLOCKED
    assert o["vendor"] == edge
    assert o["signals"]["edge_attributed"] is True


@pytest.mark.parametrize("status", [401, 403, 405, 406, 429, 503])
def test_edge_attribution_shares_the_antibot_status_gate(status):
    # Same gate as DataDome/PerimeterX/Imperva/Akamai, not the narrower
    # Cloudflare-only CF_CHALLENGE_STATUS -- proven once here for all five
    # edges, same as the existing vendors' shared-gate test above.
    o = classify(status, {"server": "cloudflare"}, "", [])
    assert o["state"] == BLOCKED
    assert o["vendor"] == "cloudflare"
    assert o["signals"]["edge_attributed"] is True


@pytest.mark.parametrize("headers", [
    {"server": "cloudflare"},
    {"cf-ray": "7d3a1c9f2e4b0011-SJC"},
    {"x-akamai-session-info": "true"},
    {"via": "1.1 abc123.cloudfront.net (CloudFront)"},
    {"x-amz-cf-id": "abcDEF123=="},
    {"server": "awselb/2.0"},
    {"x-fastly-request-id": "abc123"},
    {"via": "1.1 varnish", "x-served-by": "cache-abc123-XYZ"},
])
def test_200_with_edge_headers_is_still_passed(headers):
    # THE MAIN INVARIANT holds for every edge, not just Cloudflare: 200 is
    # passed regardless of which CDN or load balancer answered.
    o = classify(200, headers, "", [])
    assert o["state"] == PASSED
    assert o["signals"]["edge_attributed"] is False


@pytest.mark.parametrize("headers", [
    {"server": "cloudflare"},
    {"cf-ray": "7d3a1c9f2e4b0011-SJC"},
    {"x-akamai-session-info": "true"},
    {"via": "1.1 abc123.cloudfront.net (CloudFront)"},
    {"x-amz-cf-id": "abcDEF123=="},
    {"server": "awselb/2.0"},
    {"x-fastly-request-id": "abc123"},
    {"via": "1.1 varnish", "x-served-by": "cache-abc123-XYZ"},
])
def test_edge_headers_at_an_ungated_status_do_not_attribute(headers):
    # 302 is not in ANTIBOT_CHALLENGE_STATUS -- edge attribution must not fire
    # any more than a real vendor check would.
    o = classify(302, headers, "", [])
    assert o["state"] == UNKNOWN
    assert o["signals"]["edge_attributed"] is False


def test_genuine_cloudflare_challenge_still_takes_the_strong_path():
    # The weak fallback must never swallow the strong, existing rule.
    o = classify(403, {"cf-mitigated": "challenge"}, "", [])
    assert o["state"] == BLOCKED
    assert o["vendor"] == "cloudflare"
    assert o["signals"]["edge_attributed"] is False


def test_a_real_vendor_signal_wins_over_the_edge_fallback():
    o = classify(403, {"server": "cloudflare", "x-datadome": "protected"}, "", [])
    assert o["state"] == BLOCKED
    assert o["vendor"] == "datadome"
    assert o["signals"]["edge_attributed"] is False


def test_aws_waf_header_wins_over_the_awselb_edge_fallback():
    # The header path must not be shadowed by the new fallback: a
    # captcha/challenge action still means AWS WAF, not "attributed to an AWS
    # load balancer" -- BLOCK mode is the only case with no header at all.
    o = classify(403, {"x-amzn-waf-action": "captcha", "server": "awselb/2.0"}, "", [])
    assert o["state"] == BLOCKED
    assert o["vendor"] == "awswaf"
    assert o["signals"]["edge_attributed"] is False


def test_varnish_server_header_alone_does_not_attribute_to_fastly():
    # Plenty of sites run Varnish themselves without Fastly in front of them.
    # Only x-fastly-request-id, or via:varnish PLUS x-served-by together,
    # count -- server: Varnish by itself must not.
    o = classify(403, {"server": "Varnish"}, "", [])
    assert o["state"] == UNKNOWN
    assert o["signals"]["edge_attributed"] is False


def test_403_with_no_edge_identification_at_all_is_unknown():
    o = classify(403, {}, "", [])
    assert o["state"] == UNKNOWN
    assert o["signals"]["edge_attributed"] is False


def test_edge_attribution_reason_names_the_edge_and_disclaims_the_challenge():
    o = classify(403, {"server": "awselb/2.0"}, "", [])
    reason = o["reason"].lower()
    assert "awselb" not in reason
    assert "waf" not in reason
    assert "load balancer" in reason
    assert "not a recognised challenge" in reason


# ------------------------------------------------------------ classify: passed

def test_200_is_passed_even_with_challenge_platform_in_the_body():
    # Cloudflare injects challenge-platform into ordinary 200 pages. Treating it
    # as a block would mark unprotected sites as blocked on both lanes and
    # manufacture a fake FAIL.
    o = classify(200, {}, "<script src='/cdn-cgi/challenge-platform/x'></script>", [])
    assert o["state"] == PASSED


def test_200_reports_cf_clearance_as_a_supporting_signal_only():
    o = classify(200, {}, "", ["cf_clearance"])
    assert o["state"] == PASSED
    assert o["signals"]["cf_clearance"] is True


def test_200_reports_aws_waf_token_as_a_supporting_signal_only():
    o = classify(200, {}, "", ["aws-waf-token"])
    assert o["state"] == PASSED
    assert o["signals"]["aws_waf_token"] is True


def test_vendor_label_on_a_passed_response_comes_from_soft_signals():
    o = classify(200, {"server": "cloudflare"}, "", [])
    assert o["state"] == PASSED
    assert o["vendor"] == "cloudflare"


def test_unexpected_status_is_unknown():
    o = classify(500, {}, "", [])
    assert o["state"] == UNKNOWN


# ------------------------------------------------------------------- verdict

def test_baseline_error_means_there_is_nothing_to_measure():
    assert verdict(obs("error"), obs(PASSED))["verdict"] == "ERROR"


def test_baseline_passed_is_void_even_when_lane_b_errored():
    # Checked ABOVE lane B's error on purpose: if the bare lane got through,
    # there is nothing left to prove, whatever happened on lane B.
    assert verdict(obs(PASSED), obs("error"))["verdict"] == "VOID"


def test_lane_b_error_is_an_error():
    assert verdict(obs(BLOCKED), obs("error"))["verdict"] == "ERROR"


@pytest.mark.parametrize("a,b", [(UNKNOWN, PASSED), (BLOCKED, UNKNOWN)])
def test_an_unknown_observation_never_becomes_pass_or_fail(a, b):
    assert verdict(obs(a), obs(b))["verdict"] == "VOID"


def test_protection_active_and_we_get_through_is_a_pass():
    assert verdict(obs(BLOCKED), obs(PASSED))["verdict"] == "PASS"


def test_protection_active_and_we_do_not_get_through_is_a_fail():
    assert verdict(obs(BLOCKED), obs(BLOCKED))["verdict"] == "FAIL"


# --------------------------------------------------------- verdict: no baseline

@pytest.mark.parametrize("state,want", [
    (PASSED, "PASS"), (BLOCKED, "FAIL"), (UNKNOWN, "VOID"), ("error", "ERROR"),
])
def test_without_a_baseline_the_verdict_comes_from_lane_b_alone(state, want):
    v = verdict(None, obs(state), no_baseline=True)
    assert v["verdict"] == want


def test_no_baseline_pass_says_what_it_did_not_prove():
    v = verdict(None, obs(PASSED), no_baseline=True)
    assert "challenge" in v["why"].lower()


# ------------------------------------------- verdict: edge-attributed evidence
#
# classify() calls a gated status `blocked` when it can name the CDN in front of
# a site but recognised no vendor challenge on the response. That is a weaker
# fact than a solved challenge, and the verdict text must not spend it as if it
# were the stronger one — "protection is active" is exactly the claim the
# edge-attribution reason string was written to avoid making.


def edge_obs(state=BLOCKED, reason="r", vendor="cloudflare"):
    return {"state": state, "reason": reason, "vendor": vendor,
            "signals": {"edge_attributed": True}}


def test_a_pass_on_edge_attributed_evidence_does_not_claim_protection_is_active():
    v = verdict(edge_obs(), obs(PASSED))
    assert v["verdict"] == "PASS"
    assert "protection is active" not in v["why"]


def test_a_pass_on_edge_attributed_evidence_says_why_it_is_weaker():
    v = verdict(edge_obs(), obs(PASSED))
    low = v["why"].lower()
    assert "no recognised challenge signal" in low
    assert "baseline" in low


def test_a_pass_on_a_recognised_challenge_still_claims_protection_is_active():
    v = verdict(obs(BLOCKED), obs(PASSED))
    assert v["why"] == "protection is active (baseline blocked) and BlankTrail gets through"


def test_a_fail_carries_the_caveat_when_the_blanktrail_lane_was_edge_attributed():
    v = verdict(obs(BLOCKED), edge_obs())
    assert v["verdict"] == "FAIL"
    assert "no recognised challenge signal" in v["why"].lower()
    assert "blanktrail" in v["why"].lower()


def test_a_fail_on_two_recognised_challenges_is_worded_exactly_as_before():
    v = verdict(obs(BLOCKED), obs(BLOCKED, reason="HTTP 403: x"))
    assert "no recognised challenge signal" not in v["why"].lower()
    assert v["why"].startswith("baseline blocked and BlankTrail did not get through either")


def test_both_lanes_edge_attributed_names_both():
    v = verdict(edge_obs(), edge_obs())
    low = v["why"].lower()
    assert "baseline" in low and "blanktrail" in low


def test_no_baseline_fail_carries_the_caveat_when_edge_attributed():
    v = verdict(None, edge_obs(), no_baseline=True)
    assert v["verdict"] == "FAIL"
    assert "no recognised challenge signal" in v["why"].lower()


def test_no_baseline_fail_on_a_recognised_challenge_has_no_caveat():
    v = verdict(None, obs(BLOCKED), no_baseline=True)
    assert "no recognised challenge signal" not in v["why"].lower()


@pytest.mark.parametrize("a,b,want", [
    (edge_obs(state=PASSED), obs(PASSED), "VOID"),
    (edge_obs(), obs("error"), "ERROR"),
    (edge_obs(), obs(UNKNOWN), "VOID"),
])
def test_edge_attribution_does_not_disturb_the_non_pass_fail_verdicts(a, b, want):
    assert verdict(a, b)["verdict"] == want


def test_verdict_survives_an_observation_with_no_signals_key():
    # runner._brief() and older callers build observation-shaped dicts by hand.
    bare_a = {"state": BLOCKED, "reason": "r", "vendor": ""}
    bare_b = {"state": PASSED, "reason": "r", "vendor": ""}
    assert verdict(bare_a, bare_b)["verdict"] == "PASS"
