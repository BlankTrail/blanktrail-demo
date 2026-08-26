import json
import time

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


# --------------------------------------------------------------- concurrency

def test_workers_defaults_to_one_and_out_of_range_values_are_clamped():
    # Anything outside 1-16 is clamped, not rejected: a stray 0 or 200 in
    # the form should not fail the whole run over one bad number.
    import blanktrail_demo.runner as runner

    plan, errors = runner.build_run({**BASE})
    assert errors == []
    assert plan.workers == 1
    plan.endpoint.close()

    plan, errors = runner.build_run({**BASE, "workers": 0})
    assert plan.workers == 1
    plan.endpoint.close()

    plan, errors = runner.build_run({**BASE, "workers": 200})
    assert plan.workers == 16
    plan.endpoint.close()

    plan, errors = runner.build_run({**BASE, "workers": "banana"})
    assert plan.workers == 1
    plan.endpoint.close()

    plan, errors = runner.build_run({**BASE, "workers": 6})
    assert plan.workers == 6
    plan.endpoint.close()


def test_log_events_stay_contiguous_per_target_under_concurrency(monkeypatch):
    # THE regression this whole change is at risk of reintroducing. Commit
    # 9f14c97 fixed raw dumps landing on the wrong result card because a
    # "log" event could drift across a target boundary; naive threading —
    # workers writing events as they happen — brings that bug back, and
    # non-deterministically, which is worse than the original because it
    # will not reproduce on demand. This pins the fix for workers > 1: each
    # target's whole event block — its "target" event, its "log" events,
    # its "result" event — lands together with nothing foreign between
    # them, even though targets finish in a different order than they were
    # submitted.
    import blanktrail_demo.endpoints as endpoints
    import blanktrail_demo.runner as runner

    monkeypatch.setattr(endpoints, "tcp_reachable", lambda url, timeout=5.0: "")

    # Target 1 is the slowest, target 4 the fastest: completion order is
    # the reverse of submission order — exactly the scenario naive
    # threading (and index-based reasoning about "who runs when") gets
    # wrong.
    latency = [0.16, 0.10, 0.05, 0.0]

    def fake_probe(fetcher, url, timeout, lane, trust_source):
        n = int(url.rsplit("/t", 1)[1])
        time.sleep(latency[n - 1])
        entry = {"lane": lane, "url": url, "status": 200, "ms": 1, "state": "passed",
                 "reason": "HTTP 200", "vendor": "", "signals": {}, "proto": "HTTP/2",
                 "raw": "dump", "kind": None, "error": None, "kb": 0, "cookies": [],
                 "redirects": [], "final_url": url, "ctype": "", "location": None,
                 "server": ""}
        return entry, {"state": "passed", "reason": "HTTP 200", "vendor": "", "signals": {}}

    monkeypatch.setattr(runner, "probe", fake_probe)
    targets = "\n".join(f"https://example.com/t{i}" for i in range(1, 5))
    events = events_of({**BASE, "lane_a": "direct", "workers": 4, "targets": targets})

    assert events[0]["type"] == "meta"
    assert events[0]["workers"] == 4

    # Confirms this test is actually exercising out-of-order completion —
    # otherwise it would not be testing what it claims to.
    result_order = [e["n"] for e in events if e["type"] == "result"]
    assert result_order == [4, 3, 2, 1]

    all_log_positions = [i for i, e in enumerate(events) if e["type"] == "log"]
    for n in (1, 2, 3, 4):
        target_pos = next(i for i, e in enumerate(events)
                          if e["type"] == "target" and e["n"] == n)
        result_pos = next(i for i, e in enumerate(events)
                          if e["type"] == "result" and e["n"] == n)
        assert target_pos < result_pos
        in_window = [i for i in all_log_positions if target_pos < i < result_pos]
        assert len(in_window) == 2

    # Every log event was accounted for by exactly one target's window —
    # none landed in no man's land between targets.
    assert len(all_log_positions) == 8


def test_every_target_completes_exactly_once_under_concurrency(monkeypatch):
    import blanktrail_demo.endpoints as endpoints
    import blanktrail_demo.runner as runner

    monkeypatch.setattr(endpoints, "tcp_reachable", lambda url, timeout=5.0: "")

    def fake_probe(fetcher, url, timeout, lane, trust_source):
        entry = {"lane": lane, "url": url, "status": 200, "ms": 1, "state": "passed",
                 "reason": "HTTP 200", "vendor": "", "signals": {}, "proto": "HTTP/2",
                 "raw": "", "kind": None, "error": None, "kb": 0, "cookies": [],
                 "redirects": [], "final_url": url, "ctype": "", "location": None,
                 "server": ""}
        return entry, {"state": "passed", "reason": "HTTP 200", "vendor": "", "signals": {}}

    monkeypatch.setattr(runner, "probe", fake_probe)
    n_targets = 15
    targets = "\n".join(f"https://example.com/n{i}" for i in range(n_targets))
    events = events_of({**BASE, "workers": 4, "targets": targets})

    results = [e for e in events if e["type"] == "result"]
    assert len(results) == n_targets
    assert sorted(e["n"] for e in results) == list(range(1, n_targets + 1))
    assert all(e["verdict"] == "PASS" for e in results)


def test_workers_equal_to_one_matches_the_serial_event_sequence(monkeypatch):
    # Explicit workers=1 must take the exact same path as leaving workers
    # out entirely — the identical-to-today guarantee this change rests on.
    import blanktrail_demo.endpoints as endpoints
    import blanktrail_demo.runner as runner

    monkeypatch.setattr(endpoints, "tcp_reachable", lambda url, timeout=5.0: "")

    def fake_probe(fetcher, url, timeout, lane, trust_source):
        entry = {"lane": lane, "url": url, "status": 200, "ms": 12, "state": "passed",
                 "reason": "HTTP 200", "vendor": "", "signals": {}, "proto": "HTTP/2",
                 "raw": "dump", "kind": None, "error": None, "kb": 0.1, "cookies": [],
                 "redirects": [], "final_url": url, "ctype": "", "location": None,
                 "server": ""}
        return entry, {"state": "passed", "reason": "HTTP 200", "vendor": "", "signals": {}}

    monkeypatch.setattr(runner, "probe", fake_probe)
    config = {**BASE, "lane_a": "direct",
             "targets": "https://example.com/one\nhttps://example.com/two"}

    default_events = events_of(config)
    explicit_events = events_of({**config, "workers": 1})

    def strip_volatile(evs):
        cleaned = []
        for e in evs:
            e = dict(e)
            e.pop("started", None)
            e.pop("elapsed", None)
            e.pop("rpm", None)
            cleaned.append(e)
        return cleaned

    # Same event types, same target numbering and content, in the same
    # order. "started"/"elapsed"/"rpm" are wall-clock and excluded.
    assert strip_volatile(default_events) == strip_volatile(explicit_events)
    assert default_events[0]["workers"] == 1
    assert explicit_events[0]["workers"] == 1


def test_a_target_that_explodes_fails_alone_under_concurrency(monkeypatch):
    import blanktrail_demo.endpoints as endpoints
    import blanktrail_demo.runner as runner

    monkeypatch.setattr(endpoints, "tcp_reachable", lambda url, timeout=5.0: "")

    def flaky_probe(fetcher, url, timeout, lane, trust_source):
        if "boom" in url:
            raise RuntimeError("simulated failure")
        entry = {"lane": lane, "url": url, "status": 200, "ms": 1, "state": "passed",
                 "reason": "HTTP 200", "vendor": "", "signals": {}, "proto": "HTTP/2",
                 "raw": "", "kind": None, "error": None, "kb": 0, "cookies": [],
                 "redirects": [], "final_url": url, "ctype": "", "location": None,
                 "server": ""}
        return entry, {"state": "passed", "reason": "HTTP 200", "vendor": "", "signals": {}}

    monkeypatch.setattr(runner, "probe", flaky_probe)
    targets = "\n".join([
        "https://example.com/ok1", "https://example.com/boom",
        "https://example.com/ok2", "https://example.com/ok3",
    ])
    events = events_of({**BASE, "workers": 4, "targets": targets})

    results = {e["n"]: e for e in events if e["type"] == "result"}
    assert len(results) == 4
    assert results[2]["verdict"] == "ERROR"
    assert results[1]["verdict"] == "PASS"
    assert results[3]["verdict"] == "PASS"
    assert results[4]["verdict"] == "PASS"


def test_stats_totals_are_correct_under_concurrency(monkeypatch):
    # Every completed target folds into "stats" from one place — the main
    # thread, as each future completes — rather than from inside worker
    # threads. That is what rules out a lost update from a shared counter.
    import blanktrail_demo.endpoints as endpoints
    import blanktrail_demo.runner as runner

    monkeypatch.setattr(endpoints, "tcp_reachable", lambda url, timeout=5.0: "")

    def fake_probe(fetcher, url, timeout, lane, trust_source):
        # Baseline blocked, BlankTrail through — the classic PASS, and the
        # only way a "direct" baseline lane actually produces one instead
        # of VOID ("the bare lane got through, so the target proves
        # nothing").
        state = "blocked" if lane == "A" else "passed"
        entry = {"lane": lane, "url": url, "status": 200, "ms": 1, "state": state,
                 "reason": "HTTP 200", "vendor": "", "signals": {}, "proto": "HTTP/2",
                 "raw": "", "kind": None, "error": None, "kb": 0, "cookies": [],
                 "redirects": [], "final_url": url, "ctype": "", "location": None,
                 "server": ""}
        return entry, {"state": state, "reason": "HTTP 200", "vendor": "", "signals": {}}

    monkeypatch.setattr(runner, "probe", fake_probe)
    n_targets = 20
    targets = "\n".join(f"https://example.com/s{i}" for i in range(n_targets))
    events = events_of({**BASE, "lane_a": "direct", "workers": 8, "targets": targets})

    stats_events = [e for e in events if e["type"] == "stats"]
    final = stats_events[-1]
    assert final["done"] == n_targets
    assert final["passed"] == n_targets
    assert final["failed"] == 0
    assert final["void"] == 0
    assert final["err"] == 0
    assert final["req"] == n_targets * 2
    # One "stats" event per completed target, plus the trailing one after
    # "Done." — none lost, none duplicated.
    assert len(stats_events) == n_targets + 1


def test_the_api_key_never_appears_in_any_event_under_concurrency(monkeypatch):
    import blanktrail_demo.endpoints as endpoints

    monkeypatch.setattr(endpoints, "tcp_reachable", lambda url, timeout=5.0: "")
    targets = "\n".join(f"https://example.com/k{i}" for i in range(6))
    events = events_of({**BASE, "workers": 4, "targets": targets,
                        "api_key": "super-secret-value"})
    assert "super-secret-value" not in json.dumps(events)


def test_generator_close_under_concurrency_shuts_the_pool_down_promptly(monkeypatch):
    # The obvious way to wire up an executor — the stdlib context-manager
    # exit, or any shutdown() call without cancel_futures — lets every
    # already-queued task run to completion before returning. For a tool
    # whose whole point is "the browser tab closed, stop working", that
    # would mean the run keeps grinding through the rest of the target list
    # in the background instead of actually stopping. This proves the
    # shutdown cancels not-yet-started work instead of draining the queue.
    import blanktrail_demo.endpoints as endpoints
    import blanktrail_demo.runner as runner

    monkeypatch.setattr(endpoints, "tcp_reachable", lambda url, timeout=5.0: "")
    closed = {"n": 0}
    monkeypatch.setattr(endpoints.PresetEndpoint, "close",
                        lambda self: closed.__setitem__("n", closed["n"] + 1))

    started = []

    def slow_probe(fetcher, url, timeout, lane, trust_source):
        started.append(url)
        time.sleep(0.2)
        entry = {"lane": lane, "url": url, "status": 200, "ms": 1, "state": "passed",
                 "reason": "HTTP 200", "vendor": "", "signals": {}, "proto": "HTTP/2",
                 "raw": "", "kind": None, "error": None, "kb": 0, "cookies": [],
                 "redirects": [], "final_url": url, "ctype": "", "location": None,
                 "server": ""}
        return entry, {"state": "passed", "reason": "HTTP 200", "vendor": "", "signals": {}}

    monkeypatch.setattr(runner, "probe", slow_probe)
    n_targets = 20
    targets = "\n".join(f"https://example.com/g{i}" for i in range(n_targets))

    generator = execute({**BASE, "workers": 2, "targets": targets})
    next(generator)  # meta
    next(generator)  # first event of whichever target finishes first

    start = time.time()
    generator.close()
    elapsed = time.time() - start

    # Draining the full 20-target queue at 2 workers / 0.2s each would take
    # roughly 2 seconds; a prompt cancel finishes in a small fraction of
    # that, bounded by the handful of tasks already in flight rather than
    # by the length of the target list.
    assert elapsed < 1.0
    assert len(started) < n_targets
    assert closed["n"] >= 1
