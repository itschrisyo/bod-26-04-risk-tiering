"""
test_tier_engine.py

Validates TierEngine against every row of the real BOD 26-04 Table 1,
plus the trigger-date/deadline math and the Undetermined path.

Run with: python3 -m pytest tests/test_tier_engine.py -v
"""

import sys
import os
from datetime import date

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

from tier_engine import TierEngine, Timeline  # noqa: E402


# Every row of Table 1, hand-transcribed from the directive PDF a second
# time, independently of data/bod_26_04_table1.json, specifically so this
# test can catch a transcription error in the data file rather than just
# re-checking the data file against itself.
EXPECTED_ROWS = [
    # (exposed, kev, automatable, impact) -> (timeline, forensic)
    ((True,  True,  True,  "total"),   (Timeline.THREE_DAYS_FORENSIC, True)),
    ((True,  True,  True,  "partial"), (Timeline.THREE_DAYS, False)),
    ((True,  True,  False, "total"),   (Timeline.THREE_DAYS_FORENSIC, True)),
    ((True,  True,  False, "partial"), (Timeline.FOURTEEN_DAYS, False)),
    ((True,  False, True,  "total"),   (Timeline.THREE_DAYS, False)),
    ((True,  False, True,  "partial"), (Timeline.FOURTEEN_DAYS, False)),
    ((True,  False, False, "total"),   (Timeline.FOURTEEN_DAYS, False)),
    ((True,  False, False, "partial"), (Timeline.SIXTY_DAYS, False)),
    ((False, True,  True,  "total"),   (Timeline.THREE_DAYS_FORENSIC, True)),
    ((False, True,  True,  "partial"), (Timeline.FOURTEEN_DAYS, False)),
    ((False, True,  False, "total"),   (Timeline.FOURTEEN_DAYS, False)),   # row 11 -- the one that broke the hand-rolled version
    ((False, True,  False, "partial"), (Timeline.FOURTEEN_DAYS, False)),
    ((False, False, True,  "total"),   (Timeline.SIXTY_DAYS, False)),
    ((False, False, True,  "partial"), (Timeline.SIXTY_DAYS, False)),
    ((False, False, False, "total"),   (Timeline.FIX_ON_UPGRADE, False)),
    ((False, False, False, "partial"), (Timeline.FIX_ON_UPGRADE, False)),
]


def test_all_16_rows_match_directive():
    engine = TierEngine()
    assert len(EXPECTED_ROWS) == 16, "Test itself must cover all 16 rows"

    failures = []
    for (exposed, kev, automatable, impact), (expected_timeline, expected_forensic) in EXPECTED_ROWS:
        result = engine.compute_tier(
            publicly_exposed=exposed,
            in_kev=kev,
            automatable=automatable,
            technical_impact=impact,
        )
        if result.timeline != expected_timeline or result.forensic_triage_required != expected_forensic:
            failures.append(
                f"exposed={exposed} kev={kev} automatable={automatable} "
                f"impact={impact}: expected ({expected_timeline}, forensic={expected_forensic}), "
                f"got ({result.timeline}, forensic={result.forensic_triage_required})"
            )

    assert not failures, "Tier mismatches found:\n" + "\n".join(failures)


def test_row_11_specifically_the_one_that_broke_the_hand_rolled_version():
    """
    Regression test for the exact mistake made earlier in this project:
    assuming KEV + Total Impact always yields 3-day+forensic regardless
    of exposure/automatability. Row 11 (Not Exposed, In KEV, Not
    Automatable, Total Impact) is 14 days, not 3-day+forensic.
    """
    engine = TierEngine()
    result = engine.compute_tier(
        publicly_exposed=False,
        in_kev=True,
        automatable=False,
        technical_impact="total",
    )
    assert result.timeline == Timeline.FOURTEEN_DAYS
    assert result.forensic_triage_required is False
    assert result.matched_row == 11


def test_deadline_uses_earlier_of_kev_date_and_first_detected():
    engine = TierEngine()
    result = engine.compute_tier(
        publicly_exposed=True,
        in_kev=True,
        automatable=True,
        technical_impact="partial",  # row 2 -> 3 days
        kev_date_added=date(2026, 7, 1),
        first_detected_date=date(2026, 6, 15),  # earlier than KEV add date
        today=date(2026, 7, 10),
    )
    assert result.trigger_date == date(2026, 6, 15)
    assert result.deadline == date(2026, 6, 18)
    assert result.days_remaining == -22  # already overdue


def test_deadline_when_only_first_detected_known_not_in_kev():
    engine = TierEngine()
    result = engine.compute_tier(
        publicly_exposed=True,
        in_kev=False,
        automatable=False,
        technical_impact="partial",  # row 8 -> 60 days
        first_detected_date=date(2026, 7, 1),
        today=date(2026, 7, 15),
    )
    assert result.trigger_date == date(2026, 7, 1)
    assert result.deadline == date(2026, 8, 30)
    assert result.days_remaining == 46


def test_fix_on_upgrade_has_no_deadline():
    engine = TierEngine()
    result = engine.compute_tier(
        publicly_exposed=False,
        in_kev=False,
        automatable=False,
        technical_impact="total",
        first_detected_date=date(2026, 1, 1),
        today=date(2026, 7, 15),
    )
    assert result.timeline == Timeline.FIX_ON_UPGRADE
    assert result.deadline is None
    assert result.days_remaining is None


def test_missing_automatable_returns_undetermined_not_a_guess():
    engine = TierEngine()
    result = engine.compute_tier(
        publicly_exposed=True,
        in_kev=True,
        automatable=None,  # Vulnrichment has no data for this CVE
        technical_impact="total",
    )
    assert result.timeline == Timeline.UNDETERMINED
    assert result.matched_row is None
    assert "automatable" in result.reason.lower()


def test_missing_technical_impact_returns_undetermined():
    engine = TierEngine()
    result = engine.compute_tier(
        publicly_exposed=False,
        in_kev=True,
        automatable=True,
        technical_impact=None,
    )
    assert result.timeline == Timeline.UNDETERMINED
    assert "technical_impact" in result.reason.lower()


def test_missing_publicly_exposed_returns_undetermined():
    """Covers the Foundation-tier license case where exposure data isn't available."""
    engine = TierEngine()
    result = engine.compute_tier(
        publicly_exposed=None,
        in_kev=True,
        automatable=True,
        technical_impact="total",
    )
    assert result.timeline == Timeline.UNDETERMINED
    assert "publicly_exposed" in result.reason.lower()


if __name__ == "__main__":
    # Allow running without pytest installed, for a quick sanity check.
    tests = [obj for name, obj in list(globals().items()) if name.startswith("test_")]
    passed, failed = 0, 0
    for t in tests:
        try:
            t()
            print(f"PASS: {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"FAIL: {t.__name__}\n  {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
