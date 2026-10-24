from airlock.ingest import load_messages


def test_whatsapp_android_and_continuation(tmp_path):
    path = tmp_path / "chat.txt"
    path.write_text(
        "12/31/23, 9:41 PM - Alice: first line\n"
        "continuation line\n"
        "1/1/24, 9:00 AM - Bob: second message\n",
        encoding="utf-8",
    )
    messages = load_messages(path)
    assert len(messages) == 2
    assert messages[0].sender == "Alice"
    assert "continuation line" in messages[0].raw_text
    assert messages[1].sender == "Bob"


def test_whatsapp_ios_format(tmp_path):
    path = tmp_path / "chat.txt"
    path.write_text(
        "[31/12/23, 9:41:00 PM] Carol: hello\n",
        encoding="utf-8",
    )
    messages = load_messages(path)
    assert len(messages) == 1
    assert messages[0].sender == "Carol"


def test_eml_parsing(tmp_path):
    path = tmp_path / "msg.eml"
    path.write_text(
        "From: Alice <alice@example.com>\n"
        "To: me@example.com\n"
        "Subject: Hello\n"
        "Date: Mon, 1 Jan 2024 10:00:00 +0000\n"
        "Content-Type: text/plain; charset=\"utf-8\"\n"
        "\n"
        "Hello body\n",
        encoding="utf-8",
    )
    messages = load_messages(path)
    assert len(messages) == 1
    assert messages[0].sender == "Alice <alice@example.com>"
    assert "Hello body" in messages[0].raw_text
    assert messages[0].headers["Subject"] == "Hello"


def test_eml_with_leading_bom(tmp_path):
    path = tmp_path / "bom.eml"
    path.write_bytes(
        b"\xef\xbb\xbfFrom: Alice <alice@example.com>\nSubject: Hi\n\nBody\n"
    )
    messages = load_messages(path)
    assert len(messages) == 1
    assert messages[0].sender == "Alice <alice@example.com>"
    assert "Body" in messages[0].raw_text
