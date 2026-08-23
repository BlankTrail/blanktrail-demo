import json

from blanktrail_demo.runner import execute


def events_of(config):
    return list(execute(config))


def kinds(events):
    return [e["type"] for e in events]


BASE = {
    "targets": "https://example.com",
    "lane_a": "off",
    "lane_b": "preset",
    "preset_urls": "http://127.0.0.1:9000",
    "trust_source": "system",
    "tls_disabled": True,
    "protocol": "h2",
    "timeout": 30,
    "delay_min": 0,
    "delay_max": 0,
}


def test_no_targets_is_one_explicit_error_then_done():
    events = events_of({**BASE, "targets": ""})
    assert kinds(events) == ["error", "done"]
    assert "no targets" in events[0]["text"].lower()


def test_a_bad_target_line_is_reported_before_anything_runs():
    events = events_of({**BASE, "targets": "ftp://example.com"})
    assert kinds(events) == ["error", "done"]
    assert "line 1" in events[0]["text"]


def test_lane_a_upstream_mode_requires_an_upstream():
    events = events_of({**BASE, "lane_a": "upstream", "lane_a_upstream": ""})
    assert kinds(events) == ["error", "done"]
    assert "upstream" in events[0]["text"].lower()


def test_preflight_failure_stops_the_run_before_the_first_request(monkeypatch):
    import blanktrail_demo.endpoints as endpoints

    monkeypatch.setattr(endpoints, "tcp_reachable",
                        lambda url, timeout=5.0: "connection refused")
    events = events_of(BASE)
    assert kinds(events) == ["error", "done"]
    assert "9000" in events[0]["text"]


def test_a_successful_run_emits_the_expected_event_sequence(monkeypatch):
    import blanktrail_demo.endpoints as endpoints
    import blanktrail_demo.runner as runner

    monkeypatch.setattr(endpoints, "tcp_reachable", lambda url, timeout=5.0: "")

    def fake_probe(fetcher, url, timeout, lane, trust_source):
        entry = {"lane": lane, "url": url, "status": 200, "ms": 12, "state": "passed",
                 "reason": "HTTP 200", "vendor": "", "signals": {}, "proto": "HTTP/2",
                 "raw": "", "kind": None, "error": None, "kb": 0.1, "cookies": [],
                 "redirects": [], "final_url": url, "ctype": "", "location": None,
                 "server": ""}
        return entry, {"state": "passed", "reason": "HTTP 200", "vendor": "", "signals": {}}

    monkeypatch.setattr(runner, "probe", fake_probe)
    events = events_of(BASE)
    assert kinds(events)[0] == "meta"
    assert kinds(events)[-1] == "done"
    assert "target" in kinds(events)
    assert "result" in kinds(events)
    assert [e for e in events if e["type"] == "result"][0]["verdict"] == "PASS"


def test_meta_warns_when_the_lanes_do_not_share_an_egress(monkeypatch):
    import blanktrail_demo.endpoints as endpoints
    monkeypatch.setattr(endpoints, "tcp_reachable", lambda url, timeout=5.0: "")
    events = events_of({**BASE, "lane_a": "direct"})
    meta = events[0]
    assert meta["type"] == "meta"
    assert any("egress" in w.lower() for w in meta["warnings"])


def test_meta_warns_when_tls_verification_is_disabled(monkeypatch):
    import blanktrail_demo.endpoints as endpoints
    monkeypatch.setattr(endpoints, "tcp_reachable", lambda url, timeout=5.0: "")
    events = events_of(BASE)
    assert any("verification" in w.lower() for w in events[0]["warnings"])


def test_a_target_that_explodes_fails_alone_and_the_run_continues(monkeypatch):
    import blanktrail_demo.endpoints as endpoints
    import blanktrail_demo.runner as runner

    monkeypatch.setattr(endpoints, "tcp_reachable", lambda url, timeout=5.0: "")

    calls = {"n": 0}

    def exploding_probe(fetcher, url, timeout, lane, trust_source):
        calls["n"] += 1
        if "one" in url:
            raise RuntimeError("boom")
        entry = {"lane": lane, "url": url, "status": 200, "ms": 1, "state": "passed",
                 "reason": "HTTP 200", "vendor": "", "signals": {}, "proto": "HTTP/2",
                 "raw": "", "kind": None, "error": None, "kb": 0, "cookies": [],
                 "redirects": [], "final_url": url, "ctype": "", "location": None,
                 "server": ""}
        return entry, {"state": "passed", "reason": "HTTP 200", "vendor": "", "signals": {}}

    monkeypatch.setattr(runner, "probe", exploding_probe)
    events = events_of({**BASE,
                        "targets": "https://example.com/one\nhttps://example.com/two"})
    results = [e for e in events if e["type"] == "result"]
    assert len(results) == 2
    assert results[0]["verdict"] == "ERROR"
    assert results[1]["verdict"] == "PASS"


def test_the_endpoint_is_closed_even_when_the_consumer_walks_away(monkeypatch):
    import blanktrail_demo.endpoints as endpoints
    import blanktrail_demo.runner as runner

    monkeypatch.setattr(endpoints, "tcp_reachable", lambda url, timeout=5.0: "")
    closed = {"n": 0}
    original = endpoints.PresetEndpoint.close
    monkeypatch.setattr(endpoints.PresetEndpoint, "close",
                        lambda self: closed.__setitem__("n", closed["n"] + 1))

    generator = execute(BASE)
    next(generator)          # meta
    generator.close()        # consumer hangs up mid-run
    assert closed["n"] >= 1


def test_the_api_key_never_appears_in_any_event(monkeypatch):
    import blanktrail_demo.endpoints as endpoints
    monkeypatch.setattr(endpoints, "tcp_reachable", lambda url, timeout=5.0: "")
    events = events_of({**BASE, "api_key": "super-secret-value"})
    assert "super-secret-value" not in json.dumps(events)


def test_build_run_closes_the_api_session_on_a_validation_error(monkeypatch):
    # ApiEndpoint.close() is never called on this path — build_run returns
    # (None, errors) before a RunPlan, let alone a run, exists. The API's HTTP
    # session must still be closed instead of leaking.
    import blanktrail_demo.runner as runner

    closed = {"n": 0}

    class FakeApi:
        def __init__(self, base, key):
            self.base = base

        def close(self):
            closed["n"] += 1

    monkeypatch.setattr(runner, "BlankTrailApi", FakeApi)
    plan, errors = runner.build_run({**BASE, "targets": "", "lane_b": "api",
                                     "api_base": "http://127.0.0.1:8891",
                                     "port": 9000, "protocol_b": "http"})
    assert plan is None
    assert errors
    assert closed["n"] == 1


def test_protocol_and_protocol_b_do_not_overwrite_each_other():
    # protocol picks the HTTP client (h1/h2); protocol_b picks the BlankTrail
    # port's own protocol. Renaming protocol_b to protocol too early once
    # overwrote the client selector and silently pinned every run to HTTP/2 —
    # this pins the fix.
    import blanktrail_demo.runner as runner

    plan, errors = runner.build_run({**BASE, "lane_b": "api", "protocol": "h1",
                                     "protocol_b": "socks5",
                                     "api_base": "http://127.0.0.1:8891",
                                     "port": 9000})
    assert errors == []
    assert plan.protocol == "h1"
    assert plan.endpoint.body["protocol"] == "socks5"
    plan.endpoint.close()


def test_log_events_for_a_target_land_between_its_target_and_result_events(monkeypatch):
    # Commit 9f14c97 fixed raw dumps attaching to the wrong result card. The
    # invariant that makes that fix correct: every "log" event for a target
    # arrives after that target's "target" event and before its "result"
    # event. A log event landing outside that window is exactly how the
    # original defect happened.
    import blanktrail_demo.endpoints as endpoints
    import blanktrail_demo.runner as runner

    monkeypatch.setattr(endpoints, "tcp_reachable", lambda url, timeout=5.0: "")

    def fake_probe(fetcher, url, timeout, lane, trust_source):
        entry = {"lane": lane, "url": url, "status": 200, "ms": 1, "state": "passed",
                 "reason": "HTTP 200", "vendor": "", "signals": {}, "proto": "HTTP/2",
                 "raw": "dump", "kind": None, "error": None, "kb": 0, "cookies": [],
                 "redirects": [], "final_url": url, "ctype": "", "location": None,
                 "server": ""}
        return entry, {"state": "passed", "reason": "HTTP 200", "vendor": "", "signals": {}}

    monkeypatch.setattr(runner, "probe", fake_probe)
    events = events_of({**BASE, "lane_a": "direct",
                        "targets": "https://example.com/one\nhttps://example.com/two"})

    all_log_positions = [i for i, e in enumerate(events) if e["type"] == "log"]
    for n in (1, 2):
        target_pos = next(i for i, e in enumerate(events)
                          if e["type"] == "target" and e["n"] == n)
        result_pos = next(i for i, e in enumerate(events)
                          if e["type"] == "result" and e["n"] == n)
        assert target_pos < result_pos
        # Both lanes (baseline + BlankTrail) logged for this target, strictly
        # inside its own [target, result) window.
        in_window = [i for i in all_log_positions if target_pos < i < result_pos]
        assert len(in_window) == 2

    # Every log event was accounted for by exactly one target's window —
    # none landed in no man's land between targets.
    assert len(all_log_positions) == 4
