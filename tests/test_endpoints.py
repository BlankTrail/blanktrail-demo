from blanktrail_demo.btapi import ApiError
from blanktrail_demo.endpoints import ApiEndpoint, PresetEndpoint


# ------------------------------------------------------------ PresetEndpoint

def test_a_single_url_is_a_fixed_port():
    endpoint = PresetEndpoint(["http://127.0.0.1:9000"])
    assert [endpoint.acquire(i) for i in range(4)] == ["http://127.0.0.1:9000"] * 4


def test_several_urls_round_robin_by_target_index():
    endpoint = PresetEndpoint(["http://127.0.0.1:9000", "http://127.0.0.1:9001"])
    assert [endpoint.acquire(i) for i in range(5)] == [
        "http://127.0.0.1:9000", "http://127.0.0.1:9001",
        "http://127.0.0.1:9000", "http://127.0.0.1:9001",
        "http://127.0.0.1:9000",
    ]


def test_preset_describe_reports_the_pool_size():
    endpoint = PresetEndpoint(["http://127.0.0.1:9000", "http://127.0.0.1:9001"])
    described = endpoint.describe()
    assert described["mode"] == "preset"
    assert described["count"] == 2


def test_preset_preflight_rejects_an_empty_pool():
    assert "no proxy" in PresetEndpoint([]).preflight().lower()


def test_preset_preflight_names_the_unreachable_entries(monkeypatch):
    import blanktrail_demo.endpoints as module

    def fake_reachable(url, timeout=5.0):
        return "" if url.endswith("9000") else "connection refused"

    monkeypatch.setattr(module, "tcp_reachable", fake_reachable)
    endpoint = PresetEndpoint(["http://127.0.0.1:9000", "http://127.0.0.1:9001"])
    error = endpoint.preflight()
    assert "9001" in error
    assert "9000" not in error


def test_preset_close_does_not_touch_ports_it_did_not_open():
    # The operator opened them; closing them here would be a surprise.
    endpoint = PresetEndpoint(["http://127.0.0.1:9000"])
    endpoint.close()
    endpoint.close()


# --------------------------------------------------------------- ApiEndpoint

class FakeApi:
    def __init__(self, fail_open=None, fail_ports=None):
        self.base = "http://127.0.0.1:8891"
        self.opened = []
        self.closed = []
        self.health_calls = 0
        self.close_calls = 0
        self._fail_open = fail_open
        # Ports that individually refuse to open — for testing a partial
        # failure across several ports, as opposed to fail_open's "every
        # attempt fails" or the happy path's "every attempt succeeds".
        self._fail_ports = fail_ports or set()

    def health(self):
        self.health_calls += 1
        return {"status": "ok"}

    def open_port(self, body):
        if self._fail_open:
            raise ApiError(self._fail_open)
        if body["port"] in self._fail_ports:
            raise ApiError(f"port {body['port']} is already open")
        self.opened.append(body)
        return {"port": body["port"], "status": "opened",
                "current_profile": {"name": "Chrome_145_win_0265"}}

    def close_port(self, port):
        self.closed.append(port)
        return {"port": port, "status": "closed"}

    def close(self):
        self.close_calls += 1


def _stub_reachable(monkeypatch, error: str = "") -> None:
    """The B1 check in ApiEndpoint.preflight() makes a real TCP connection.
    Stub it so these stay unit tests instead of depending on a real listener."""
    import blanktrail_demo.endpoints as module

    monkeypatch.setattr(module, "tcp_reachable", lambda url, timeout=5.0: error)


def test_api_preflight_checks_health_then_opens_the_port(monkeypatch):
    _stub_reachable(monkeypatch)
    api = FakeApi()
    endpoint = ApiEndpoint(api, {"port": 9000, "protocol": "http", "js_solver": True})
    assert endpoint.preflight() == ""
    assert api.health_calls == 1
    assert api.opened == [{"port": 9000, "protocol": "http", "js_solver": True}]


def test_api_preflight_fails_when_the_opened_port_is_not_reachable(monkeypatch):
    # The port was opened over the API, but nothing answers on it: one
    # explicit failure, not N silent per-target errors later.
    _stub_reachable(monkeypatch, "connection refused")
    api = FakeApi()
    endpoint = ApiEndpoint(api, {"port": 9000})
    error = endpoint.preflight()
    assert "9000" in error
    assert "not reachable" in error


def test_api_endpoint_returns_the_same_proxy_for_the_whole_run(monkeypatch):
    _stub_reachable(monkeypatch)
    api = FakeApi()
    endpoint = ApiEndpoint(api, {"port": 9000, "protocol": "http"})
    endpoint.preflight()
    assert endpoint.acquire(0) == "http://127.0.0.1:9000"
    assert endpoint.acquire(7) == "http://127.0.0.1:9000"


def test_the_proxy_host_follows_the_api_base_not_localhost():
    # A remote BlankTrail instance: the API lives elsewhere, so the opened
    # port's proxy URL must follow it there — not be hardcoded to this machine.
    api = FakeApi()
    api.base = "http://203.0.113.10:8891"
    endpoint = ApiEndpoint(api, {"port": 9000, "protocol": "http"})
    assert endpoint.acquire(0) == "http://203.0.113.10:9000"


def test_socks5_protocol_yields_a_socks5h_url(monkeypatch):
    _stub_reachable(monkeypatch)
    api = FakeApi()
    endpoint = ApiEndpoint(api, {"port": 9001, "protocol": "socks5"})
    endpoint.preflight()
    assert endpoint.acquire(0) == "socks5h://127.0.0.1:9001"


def test_the_chosen_profile_is_surfaced_for_the_run_header(monkeypatch):
    _stub_reachable(monkeypatch)
    api = FakeApi()
    endpoint = ApiEndpoint(api, {"port": 9000})
    endpoint.preflight()
    assert endpoint.describe()["profile"] == "Chrome_145_win_0265"


def test_a_refused_open_becomes_one_explicit_preflight_error():
    api = FakeApi(fail_open="port 9000 is already open")
    endpoint = ApiEndpoint(api, {"port": 9000})
    assert "already open" in endpoint.preflight()


def test_close_closes_the_port_it_opened_exactly_once(monkeypatch):
    _stub_reachable(monkeypatch)
    api = FakeApi()
    endpoint = ApiEndpoint(api, {"port": 9000})
    endpoint.preflight()
    endpoint.close()
    endpoint.close()
    assert api.closed == [9000]


def test_close_leaves_the_port_alone_when_asked_to(monkeypatch):
    # Regression: close() used to return early on this path and never reach
    # self.api.close(), leaking the HTTP session.
    _stub_reachable(monkeypatch)
    api = FakeApi()
    endpoint = ApiEndpoint(api, {"port": 9000}, close_when_done=False)
    endpoint.preflight()
    endpoint.close()
    assert api.closed == []
    assert api.close_calls == 1


def test_close_does_nothing_when_the_port_was_never_opened():
    # Regression: close() used to return early on this path too, leaking the
    # HTTP session whenever the port failed to open in the first place.
    api = FakeApi(fail_open="busy")
    endpoint = ApiEndpoint(api, {"port": 9000})
    endpoint.preflight()
    endpoint.close()
    assert api.closed == []
    assert api.close_calls == 1


# ------------------------------------------------------- ApiEndpoint workers

def test_workers_defaults_to_a_single_port(monkeypatch):
    # Backward compatibility: an ApiEndpoint built with no workers argument
    # behaves exactly like the single-port endpoint of before.
    _stub_reachable(monkeypatch)
    api = FakeApi()
    endpoint = ApiEndpoint(api, {"port": 9000, "protocol": "http"})
    assert endpoint.preflight() == ""
    assert [call["port"] for call in api.opened] == [9000]


def test_workers_opens_that_many_consecutive_ports(monkeypatch):
    _stub_reachable(monkeypatch)
    api = FakeApi()
    endpoint = ApiEndpoint(api, {"port": 9000, "protocol": "http"}, workers=4)
    assert endpoint.preflight() == ""
    assert [call["port"] for call in api.opened] == [9000, 9001, 9002, 9003]


def test_acquire_hands_a_different_port_to_each_concurrent_target(monkeypatch):
    _stub_reachable(monkeypatch)
    api = FakeApi()
    endpoint = ApiEndpoint(api, {"port": 9000, "protocol": "http"}, workers=4)
    endpoint.preflight()
    proxies = [endpoint.acquire(i) for i in range(4)]
    assert proxies == ["http://127.0.0.1:9000", "http://127.0.0.1:9001",
                       "http://127.0.0.1:9002", "http://127.0.0.1:9003"]
    assert len(set(proxies)) == 4
    # Round-robins past the pool, same as PresetEndpoint.
    assert endpoint.acquire(4) == "http://127.0.0.1:9000"


def test_close_closes_every_port_it_opened(monkeypatch):
    _stub_reachable(monkeypatch)
    api = FakeApi()
    endpoint = ApiEndpoint(api, {"port": 9000}, workers=3)
    endpoint.preflight()
    endpoint.close()
    assert api.closed == [9000, 9001, 9002]


def test_partial_port_failure_proceeds_on_what_opened(monkeypatch):
    # Losing port 9002 of 4 to "already open" must not fail a run that
    # could otherwise succeed on the 3 ports that did open — failing the
    # whole run over one busy port would be worse than useless.
    _stub_reachable(monkeypatch)
    api = FakeApi(fail_ports={9002})
    endpoint = ApiEndpoint(api, {"port": 9000}, workers=4)
    error = endpoint.preflight()
    assert error == ""
    assert [call["port"] for call in api.opened] == [9000, 9001, 9003]
    assert any("requested 4" in w and "3 opened" in w for w in endpoint.warnings)


def test_partial_port_failure_close_only_closes_what_opened(monkeypatch):
    _stub_reachable(monkeypatch)
    api = FakeApi(fail_ports={9001})
    endpoint = ApiEndpoint(api, {"port": 9000}, workers=3)
    endpoint.preflight()
    endpoint.close()
    assert api.closed == [9000, 9002]


def test_every_port_failing_is_still_one_explicit_preflight_error(monkeypatch):
    _stub_reachable(monkeypatch)
    api = FakeApi(fail_ports={9000, 9001, 9002, 9003})
    endpoint = ApiEndpoint(api, {"port": 9000}, workers=4)
    error = endpoint.preflight()
    assert error != ""
    assert "already open" in error
    endpoint.close()
    assert api.closed == []
    assert api.close_calls == 1
