import pytest

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
    def __init__(self, fail_open=None):
        self.opened = []
        self.closed = []
        self.health_calls = 0
        self._fail_open = fail_open

    def health(self):
        self.health_calls += 1
        return {"status": "ok"}

    def open_port(self, body):
        if self._fail_open:
            raise ApiError(self._fail_open)
        self.opened.append(body)
        return {"port": body["port"], "status": "opened",
                "current_profile": {"name": "Chrome_145_win_0265"}}

    def close_port(self, port):
        self.closed.append(port)
        return {"port": port, "status": "closed"}

    def close(self):
        pass


def test_api_preflight_checks_health_then_opens_the_port():
    api = FakeApi()
    endpoint = ApiEndpoint(api, {"port": 9000, "protocol": "http", "js_solver": True})
    assert endpoint.preflight() == ""
    assert api.health_calls == 1
    assert api.opened == [{"port": 9000, "protocol": "http", "js_solver": True}]


def test_api_endpoint_returns_the_same_proxy_for_the_whole_run():
    api = FakeApi()
    endpoint = ApiEndpoint(api, {"port": 9000, "protocol": "http"})
    endpoint.preflight()
    assert endpoint.acquire(0) == "http://127.0.0.1:9000"
    assert endpoint.acquire(7) == "http://127.0.0.1:9000"


def test_socks5_protocol_yields_a_socks5h_url():
    api = FakeApi()
    endpoint = ApiEndpoint(api, {"port": 9001, "protocol": "socks5"})
    endpoint.preflight()
    assert endpoint.acquire(0) == "socks5h://127.0.0.1:9001"


def test_the_chosen_profile_is_surfaced_for_the_run_header():
    api = FakeApi()
    endpoint = ApiEndpoint(api, {"port": 9000})
    endpoint.preflight()
    assert endpoint.describe()["profile"] == "Chrome_145_win_0265"


def test_a_refused_open_becomes_one_explicit_preflight_error():
    api = FakeApi(fail_open="port 9000 is already open")
    endpoint = ApiEndpoint(api, {"port": 9000})
    assert "already open" in endpoint.preflight()


def test_close_closes_the_port_it_opened_exactly_once():
    api = FakeApi()
    endpoint = ApiEndpoint(api, {"port": 9000})
    endpoint.preflight()
    endpoint.close()
    endpoint.close()
    assert api.closed == [9000]


def test_close_leaves_the_port_alone_when_asked_to():
    api = FakeApi()
    endpoint = ApiEndpoint(api, {"port": 9000}, close_when_done=False)
    endpoint.preflight()
    endpoint.close()
    assert api.closed == []


def test_close_does_nothing_when_the_port_was_never_opened():
    api = FakeApi(fail_open="busy")
    endpoint = ApiEndpoint(api, {"port": 9000})
    endpoint.preflight()
    endpoint.close()
    assert api.closed == []
