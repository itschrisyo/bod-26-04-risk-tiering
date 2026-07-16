"""
tier_engine.py

Computes a BOD 26-04 remediation tier for a single vulnerability-asset pair.

Design principle: Table 1 in the directive is implemented as a literal
16-row lookup, not as hand-rolled if/else boolean logic. A hand-written
version of this logic was drafted earlier in this project and got row 11
wrong (assumed KEV + Total Impact always means 3-day+forensic; the real
table requires Publicly Exposed OR Automatable as well -- row 11 is
Not-Exposed / KEV / Not-Automatable / Total, and it's a 14-day tier, not
3-day). A lookup table keyed on the same four inputs as the directive's
own table can't drift from it the way hand-written conditionals can.

This module does NOT fetch any data. It is a pure function over four
already-known input variables. Data collection (Tenable + CVE enrichment)
lives in cve_enrichment.py and the orchestration script.
"""

import json
import os
from dataclasses import dataclass
from datetime import date, timedelta
from enum import Enum
from typing import Optional


class Timeline(str, Enum):
    THREE_DAYS_FORENSIC = "3_days_forensic"
    THREE_DAYS = "3_days"
    FOURTEEN_DAYS = "14_days"
    SIXTY_DAYS = "60_days"
    FIX_ON_UPGRADE = "fix_on_upgrade"
    UNDETERMINED = "undetermined"


@dataclass
class TierResult:
    timeline: Timeline
    timeline_days: Optional[int]
    forensic_triage_required: bool
    trigger_date: Optional[date]
    deadline: Optional[date]
    days_remaining: Optional[int]
    matched_row: Optional[int]
    reason: Optional[str] = None  # populated when timeline is UNDETERMINED


class TierEngine:
    def __init__(self, table_path: Optional[str] = None):
        if table_path is None:
            table_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "data",
                "bod_26_04_table1.json",
            )
        with open(table_path, "r") as f:
            self._table = json.load(f)

        # Index rows for O(1) lookup on the four boolean/enum inputs.
        self._index = {}
        for row in self._table["rows"]:
            key = (
                row["publicly_exposed"],
                row["in_kev"],
                row["automatable"],
                row["technical_impact"],
            )
            self._index[key] = row

        if len(self._index) != 16:
            raise ValueError(
                f"Expected 16 unique rows in {table_path}, found "
                f"{len(self._index)}. The lookup table is corrupt or has "
                f"been edited incorrectly -- do not use for tiering until "
                f"this is fixed."
            )

    def compute_tier(
        self,
        publicly_exposed: Optional[bool],
        in_kev: bool,
        automatable: Optional[bool],
        technical_impact: Optional[str],
        kev_date_added: Optional[date] = None,
        first_detected_date: Optional[date] = None,
        today: Optional[date] = None,
    ) -> TierResult:
        """
        Look up the BOD 26-04 tier for one vulnerability-asset pair.

        publicly_exposed, automatable, technical_impact may be None if the
        underlying data wasn't available (e.g. no Vulnrichment coverage for
        this CVE, or the Tenable license tier doesn't expose exposure data).
        In that case this returns Timeline.UNDETERMINED rather than
        guessing -- given known Vulnrichment coverage gaps, this is an
        expected, common return value, not an edge case. Callers should
        treat it as a first-class output, not an error.

        technical_impact must be "total" or "partial" (matches the
        directive's and Vulnrichment's own vocabulary).
        """
        if today is None:
            today = date.today()

        missing = []
        if publicly_exposed is None:
            missing.append("publicly_exposed")
        if automatable is None:
            missing.append("automatable")
        if technical_impact not in ("total", "partial"):
            missing.append("technical_impact")

        if missing:
            return TierResult(
                timeline=Timeline.UNDETERMINED,
                timeline_days=None,
                forensic_triage_required=False,
                trigger_date=None,
                deadline=None,
                days_remaining=None,
                matched_row=None,
                reason=f"Missing required input(s): {', '.join(missing)}. "
                       f"Most commonly this means CISA's Vulnrichment "
                       f"program has not yet published Automatable / "
                       f"Technical Impact data for this CVE, or the "
                       f"Tenable license tier does not expose asset "
                       f"exposure data (see README licensing note).",
            )

        key = (publicly_exposed, in_kev, automatable, technical_impact)
        row = self._index.get(key)
        if row is None:
            # Should be unreachable given 16 rows cover all 2x2x2x2
            # combinations, but fail loudly rather than silently
            # mis-tiering if the table is ever edited incorrectly.
            raise ValueError(
                f"No Table 1 row matches inputs {key}. The lookup table "
                f"may be corrupted."
            )

        timeline = Timeline(row["timeline"])
        timeline_days = row["timeline_days"]

        # Per directive Appendix A item (f): the remediation clock starts
        # at whichever comes first -- the KEV-add date, or the date the
        # organization first detected the vulnerability on the asset.
        trigger_date = None
        candidates = [d for d in (kev_date_added, first_detected_date) if d is not None]
        if candidates:
            trigger_date = min(candidates)

        deadline = None
        days_remaining = None
        if trigger_date is not None and timeline_days is not None:
            deadline = trigger_date + timedelta(days=timeline_days)
            days_remaining = (deadline - today).days

        return TierResult(
            timeline=timeline,
            timeline_days=timeline_days,
            forensic_triage_required=row["forensic_triage_required"],
            trigger_date=trigger_date,
            deadline=deadline,
            days_remaining=days_remaining,
            matched_row=row["row"],
        )
