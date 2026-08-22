import pytest

from blanktrail_demo.btapi import ApiError, BlankTrailApi, open_body


# ------------------------------------------------------------------ open_body

def test_open_body_keeps_the_port_and_the_solver_flag():
    body = open_body({"port": 9000, "js_solver": True})
    assert body["port"] == 9000
    assert body["js_solver"] is True


def test_open_body_omits_blank_string_fields():
    # An empty "browser" means "no filter", and sending "" would be a filter for
    # a browser named empty string.
    body = open_body({"port": 9000, "browser": "", "os": "  ", "upstream": ""})
    assert "browser" not in body
    assert "os" not in body
    assert "upstream" not in body


def test_open_body_keeps_false_booleans():
    # False is a real setting, not an absent one.
    body = open_body({"port": 9000, "js_solver": False, "auto_rotate": False})
    assert body["js_solver"] is False
    assert body["auto_rotate"] is False


def test_open_body_drops_unknown_fields():
    body = open_body({"port": 9000, "api_key": "secret", "nonsense": 1})
    assert "api_key" not in body
    assert "nonsense" not in body


def test_open_body_requires_a_port():
    with pytest.raises(ApiError):
        open_body({"browser": "chrome"})


def test_open_body_rejects_a_port_out_of_range():
    with pytest.raises(ApiError):
        open_body({"port": 70000})


# ------------------------------------------------------------ BlankTrailApi

class FakeResponse:
    def __init__(self, status=200, payload=None, content=b"", text=""):
        self.status_code = status
        self._payload = payload
        self.content = content
        self.text = text or ""

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class FakeSession:
    def __init__(self, response):
        self.response = response
        self.calls = []
        self.headers = {}

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.response

    def close(self):
        pass


def make_api(response, key="k"):
    api = BlankTrailApi("http://127.0.0.1:8891", key)
    api._session = FakeSession(response)
    return api


def test_base_url_trailing_slash_does_not_double_up():
    api = BlankTrailApi("http://127.0.0.1:8891/", "k")
    api._session = FakeSession(FakeResponse(200, {"status": "ok"}))
    api.health()
    _, url, _ = api._session.calls[0]
    assert url == "http://127.0.0.1:8891/api/v1/health"


def test_api_key_travels_in_the_x_api_key_header():
    api = make_api(FakeResponse(200, {"ports": []}), key="secret-key")
    api.ports()
    _, _, kwargs = api._session.calls[0]
    assert kwargs["headers"]["X-API-Key"] == "secret-key"


def test_open_port_posts_the_body():
    api = make_api(FakeResponse(200, {"port": 9000, "status": "opened"}))
    result = api.open_port({"port": 9000, "js_solver": True})
    method, url, kwargs = api._session.calls[0]
    assert method == "POST"
    assert url.endswith("/api/v1/ports/open")
    assert kwargs["json"] == {"port": 9000, "js_solver": True}
    assert result["status"] == "opened"


def test_close_port_posts_the_port_number():
    api = make_api(FakeResponse(200, {"port": 9000, "status": "closed"}))
    api.close_port(9000)
    _, url, kwargs = api._session.calls[0]
    assert url.endswith("/api/v1/ports/close")
    assert kwargs["json"] == {"port": 9000}


def test_401_becomes_a_human_sentence_not_a_bare_status():
    api = make_api(FakeResponse(401, {"error": "authentication required"}))
    with pytest.raises(ApiError) as excinfo:
        api.ports()
    assert "API key" in str(excinfo.value)


def test_an_error_payload_is_surfaced_verbatim():
    api = make_api(FakeResponse(409, {"error": "port 9000 is already open"}))
    with pytest.raises(ApiError) as excinfo:
        api.open_port({"port": 9000})
    assert "already open" in str(excinfo.value)


def test_ca_returns_raw_pem_bytes():
    pem = b"-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n"
    api = make_api(FakeResponse(200, None, content=pem))
    assert api.ca() == pem


def test_ca_failure_raises():
    api = make_api(FakeResponse(404, None, content=b"", text="not found"))
    with pytest.raises(ApiError):
        api.ca()
