from datetime import datetime

import pytest

from airlock.gate import TaintViolation, new_approval_token, write_ics
from airlock.taint import untrusted


def test_untrusted_value_requires_approval() -> None:
    with pytest.raises(TaintViolation):
        write_ics(untrusted(datetime.now()), "m1")


def test_untrusted_value_with_approval() -> None:
    token = new_approval_token()
    ics = write_ics(untrusted(datetime.now()), "m1", approval_token=token)
    assert "BEGIN:VCALENDAR" in ics


def test_event_title_never_contains_sender_text() -> None:
    token = new_approval_token()
    ics = write_ics(untrusted(datetime.now()), "message-1234", approval_token=token)
    assert "message-1234" not in ics.split("SUMMARY:")[1].split("\n")[0]
