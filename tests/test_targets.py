from blanktrail_demo.targets import MAX_TARGETS, parse_targets


def test_blank_input_yields_nothing():
    targets, errors = parse_targets("   \n\n  ")
    assert targets == []
    assert errors == []


def test_comment_lines_and_trailing_comments_are_stripped():
    targets, errors = parse_targets(
        "# a whole-line comment\n"
        "https://example.com/  # trailing comment\n"
    )
    assert errors == []
    assert [t.url for t in targets] == ["https://example.com/"]


def test_missing_scheme_defaults_to_https():
    targets, errors = parse_targets("example.com")
    assert errors == []
    assert targets[0].url == "https://example.com"


def test_path_and_query_are_preserved():
    targets, _ = parse_targets("https://example.com/store?a=1")
    assert targets[0].url == "https://example.com/store?a=1"


def test_host_is_lowercased_but_path_is_not():
    targets, _ = parse_targets("https://EXAMPLE.com/Path")
    assert targets[0].url == "https://example.com/Path"


def test_non_http_scheme_is_an_error_with_line_number():
    targets, errors = parse_targets("\nftp://example.com\n")
    assert targets == []
    assert len(errors) == 1
    assert errors[0].line_no == 2
    assert "ftp" in errors[0].error


def test_duplicates_are_dropped_preserving_order():
    targets, errors = parse_targets(
        "https://example.org\n"
        "https://example.com\n"
        "https://example.org\n"
    )
    assert errors == []
    assert [t.url for t in targets] == ["https://example.org", "https://example.com"]


def test_id_strips_www_and_disambiguates_collisions():
    targets, _ = parse_targets(
        "https://example.com/one\n"
        "https://www.example.com/two\n"
    )
    assert [t.id for t in targets] == ["example.com", "example.com-2"]


def test_limit_is_reported_as_an_error_and_extra_targets_are_dropped():
    text = "\n".join(f"https://example.com/{i}" for i in range(MAX_TARGETS + 5))
    targets, errors = parse_targets(text)
    assert len(targets) == MAX_TARGETS
    assert len(errors) == 1
    assert str(MAX_TARGETS) in errors[0].error


def test_line_with_no_host_is_an_error():
    targets, errors = parse_targets("https://")
    assert targets == []
    assert len(errors) == 1
