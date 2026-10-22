from airlock.models import TrustLabel
from airlock.rank import rank
from airlock.schema import Category, Extraction, RequestType, Urgency


def _extraction(urgency=Urgency.HIGH, asks=True, request_type=RequestType.REPLY_NEEDED):
    return Extraction(
        category=Category.WORK,
        urgency=urgency,
        request_type=request_type,
        asks_user_to_act=asks,
        evidence=[],
    )


def test_unknown_trust_caps_urgency() -> None:
    result = rank(_extraction(), TrustLabel.UNKNOWN, False, False, False, False)
    assert result.urgency == Urgency.LOW
    assert result.section == "needs_you"


def test_suspicious_goes_to_review_regardless_of_model() -> None:
    result = rank(_extraction(), TrustLabel.SUSPICIOUS, False, False, False, False)
    assert result.section == "review"


def test_deadline_section() -> None:
    extraction = _extraction(urgency=Urgency.NONE, asks=False, request_type=RequestType.NONE)
    result = rank(extraction, TrustLabel.VERIFIED_KNOWN, False, False, True, False)
    assert result.section == "deadlines_amounts"
