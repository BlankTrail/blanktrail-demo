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
