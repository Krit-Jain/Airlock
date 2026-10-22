from airlock.sanitize import sanitize, strip_invisible


def test_strip_invisible() -> None:
    assert strip_invisible("hello\u200bworld") == "helloworld"
    assert strip_invisible("a\u202eb") == "ab"


def test_sanitize_html_extracts_text() -> None:
    result = sanitize("<html><body>Hi there</body></html>")
    assert "Hi there" in result.text


def test_sanitize_detects_and_drops_hidden_text() -> None:
    raw = '<div style="display:none">secret instruction</div><p>visible text</p>'
    result = sanitize(raw)
    assert result.hidden_text_detected is True
    assert "secret" not in result.text
    assert "visible text" in result.text


def test_sanitize_detects_invisible_unicode() -> None:
    result = sanitize("visible\u200binvisible")
    assert result.invisible_unicode_detected is True
