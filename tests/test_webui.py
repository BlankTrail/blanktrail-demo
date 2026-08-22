import json

import pytest

from blanktrail_demo.webui import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def test_index_serves_the_page(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"<form" in response.data or b"id=\"targets\"" in response.data


def test_static_assets_are_served(client):
    assert client.get("/assets/app.js").status_code == 200
    assert client.get("/assets/style.css").status_code == 200


def test_run_streams_ndjson(client):
    response = client.post("/run", json={"targets": ""})
    assert response.mimetype == "application/x-ndjson"
    lines = [json.loads(line) for line in response.data.splitlines() if line.strip()]
    assert lines[-1]["type"] == "done"


def test_run_reports_a_bad_form_as_an_error_event_not_a_500(client):
    response = client.post("/run", json={"targets": "ftp://example.com"})
    assert response.status_code == 200
    lines = [json.loads(line) for line in response.data.splitlines() if line.strip()]
    assert lines[0]["type"] == "error"


def test_probe_endpoint_reports_an_unreachable_api_without_raising(client):
    response = client.post("/api/probe", json={"api_base": "http://127.0.0.1:1",
                                               "api_key": "x"})
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["ok"] is False
    assert "error" in payload


def test_probe_endpoint_never_echoes_the_api_key(client):
    response = client.post("/api/probe", json={"api_base": "http://127.0.0.1:1",
                                               "api_key": "super-secret-value"})
    assert "super-secret-value" not in response.get_data(as_text=True)


def test_the_page_ships_no_external_resources(client):
    body = client.get("/").get_data(as_text=True)
    for marker in ("http://", "https://cdn", "//cdn.", "googleapis"):
        assert marker not in body.replace("http://127.0.0.1", "")
