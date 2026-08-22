from blanktrail_demo.proxyurl import for_httpx, hostport, normalize, parse_list


def test_empty_and_placeholder_values_mean_no_proxy():
    for raw in ("", "   ", None, "direct", "DIRECT", "none", "-"):
        assert normalize(raw) is None


def test_bare_hostport_defaults_to_http_connect():
    assert normalize("127.0.0.1:9000") == "http://127.0.0.1:9000"


def test_socks5_is_upgraded_to_socks5h():
    # DNS must resolve on the proxy side; otherwise the local resolver picks the
    # target address and the two lanes stop sharing one egress.
    assert normalize("socks5://127.0.0.1:9000") == "socks5h://127.0.0.1:9000"


def test_socks5h_is_left_alone():
    assert normalize("socks5h://127.0.0.1:9000") == "socks5h://127.0.0.1:9000"


def test_http_and_https_schemes_are_left_alone():
    assert normalize("http://127.0.0.1:9000") == "http://127.0.0.1:9000"
    assert normalize("https://proxy.example.com:8443") == "https://proxy.example.com:8443"


def test_credentials_survive_normalization():
    assert normalize("user:pass@127.0.0.1:9000") == "http://user:pass@127.0.0.1:9000"


def test_for_httpx_unwinds_socks5h():
    # httpx does not know the socks5h scheme; it resolves proxy-side regardless.
    assert for_httpx("socks5h://127.0.0.1:9000") == "socks5://127.0.0.1:9000"
    assert for_httpx("http://127.0.0.1:9000") == "http://127.0.0.1:9000"
    assert for_httpx(None) is None


def test_hostport_extracts_the_tcp_endpoint():
    assert hostport("socks5h://127.0.0.1:9000") == ("127.0.0.1", 9000)
    assert hostport("http://user:pass@127.0.0.1:9000") == ("127.0.0.1", 9000)


def test_hostport_returns_none_when_there_is_no_port():
    assert hostport("http://127.0.0.1") is None


def test_parse_list_skips_blanks_and_comments_and_dedupes():
    urls, errors = parse_list(
        "# pool opened by the operator\n"
        "\n"
        "http://127.0.0.1:9000\n"
        "socks5://127.0.0.1:9001  # second port\n"
        "http://127.0.0.1:9000\n"
    )
    assert errors == []
    assert urls == ["http://127.0.0.1:9000", "socks5h://127.0.0.1:9001"]


def test_parse_list_reports_a_portless_entry_with_its_line_number():
    urls, errors = parse_list("http://127.0.0.1:9000\nhttp://127.0.0.1\n")
    assert urls == ["http://127.0.0.1:9000"]
    assert len(errors) == 1
    assert errors[0].line_no == 2
