import blanktrail_demo.cli as cli
from blanktrail_demo.cli import parse_args


def test_defaults_bind_to_loopback():
    args = parse_args([])
    assert args.host == "127.0.0.1"
    assert args.port == 8790
    assert args.no_open is False


def test_host_and_port_can_be_overridden():
    args = parse_args(["--host", "0.0.0.0", "--port", "9999"])
    assert args.host == "0.0.0.0"
    assert args.port == 9999


def test_no_open_suppresses_the_browser():
    assert parse_args(["--no-open"]).no_open is True


def test_main_reports_a_taken_port_instead_of_a_traceback(monkeypatch):
    class FakeApp:
        def run(self, **kwargs):
            raise OSError("[Errno 98] Address already in use")

    monkeypatch.setattr(cli, "create_app", lambda: FakeApp())
    assert cli.main(["--no-open"]) == 1
