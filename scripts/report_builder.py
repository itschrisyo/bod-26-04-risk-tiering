"""
report_builder.py

Takes a list of already-tiered findings (output of tier_engine.compute_tier,
one per vulnerability-asset pair) and produces the views this skill exists
to deliver:

  1. Three-day action queue      -- anything due in <= 3 days, sorted by
                                     days_remaining ascending (most overdue first)
  2. Forensic triage required    -- the subset needing forensic triage per
                                     the directive's Appendix A item (d)
  3. Tier distribution           -- counts per tier, for the "how bad is it"
                                     executive view
  4. Deferral population         -- fix-on-upgrade findings, so they're
                                     visible and explicitly deprioritized
                                     rather than silently dropped from view
  5. Coverage summary            -- % of findings with a determined tier vs.
                                     Undetermined, broken out by whether the
                                     finding is KEV-listed (coverage matters
                                     most exactly where it's most likely
                                     concentrated -- see note in cve_enrichment.py
                                     and the README's coverage-gap section)

Explicitly NOT in scope for this version (see README "Out of scope"):
SSVC decision output (Track/Track*/Attend/Act) and Mission Prevalence /
Well-Being Impact scoring. Do not add these without also updating the
lookup table and tier_engine -- they are separate SSVC decision points
this directive's Table 1 does not require.
"""

import csv
import io
from dataclasses import dataclass, asdict
from typing import List, Optional

from tier_engine import TierResult, Timeline


@dataclass
class TieredFinding:
    asset_id: str
    asset_name: str
    cve_id: str
    plugin_id: Optional[str]
    plugin_name: Optional[str]
    in_kev: bool
    tier: TierResult


def three_day_action_queue(findings: List[TieredFinding]) -> List[TieredFinding]:
    urgent = [
        f for f in findings
        if f.tier.timeline in (Timeline.THREE_DAYS, Timeline.THREE_DAYS_FORENSIC)
    ]
    return sorted(
        urgent,
        key=lambda f: (f.tier.days_remaining if f.tier.days_remaining is not None else 999999),
    )


def forensic_triage_required(findings: List[TieredFinding]) -> List[TieredFinding]:
    return [f for f in findings if f.tier.forensic_triage_required]


def tier_distribution(findings: List[TieredFinding]) -> dict:
    counts = {t.value: 0 for t in Timeline}
    for f in findings:
        counts[f.tier.timeline.value] += 1
    counts["_total"] = len(findings)
    return counts


def deferral_population(findings: List[TieredFinding]) -> List[TieredFinding]:
    return [f for f in findings if f.tier.timeline == Timeline.FIX_ON_UPGRADE]


def coverage_summary(findings: List[TieredFinding]) -> dict:
    """
    Breaks out Undetermined-tier findings by KEV status, since Vulnrichment
    coverage is expected to concentrate on KEV-listed / actively-exploited
    CVEs (CISA prioritizes those for triage). A low coverage rate on
    non-KEV findings is expected and less urgent; a low coverage rate on
    KEV-listed findings is the case that actually matters, since those are
    exactly the findings that might belong in the 3-day tier -- so it's
    broken out separately rather than buried in one overall percentage.
    """
    total = len(findings)
    determined = [f for f in findings if f.tier.timeline != Timeline.UNDETERMINED]
    undetermined = [f for f in findings if f.tier.timeline == Timeline.UNDETERMINED]

    kev_findings = [f for f in findings if f.in_kev]
    kev_undetermined = [f for f in kev_findings if f.tier.timeline == Timeline.UNDETERMINED]

    return {
        "total_findings": total,
        "determined": len(determined),
        "undetermined": len(undetermined),
        "coverage_pct": round(100 * len(determined) / total, 1) if total else None,
        "kev_findings_total": len(kev_findings),
        "kev_findings_undetermined": len(kev_undetermined),
        "kev_coverage_pct": (
            round(100 * (len(kev_findings) - len(kev_undetermined)) / len(kev_findings), 1)
            if kev_findings
            else None
        ),
    }


def to_csv(findings: List[TieredFinding]) -> str:
    """Defensible-reporting export: every finding, every contributing
    variable, so the tier assignment is auditable rather than a black box."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "asset_id", "asset_name", "cve_id", "plugin_id", "plugin_name", "in_kev",
        "tier", "forensic_triage_required", "trigger_date", "deadline",
        "days_remaining", "table1_row", "undetermined_reason",
    ])
    for f in findings:
        t = f.tier
        writer.writerow([
            f.asset_id, f.asset_name, f.cve_id, f.plugin_id or "", f.plugin_name or "", f.in_kev,
            t.timeline.value, t.forensic_triage_required,
            t.trigger_date.isoformat() if t.trigger_date else "",
            t.deadline.isoformat() if t.deadline else "",
            t.days_remaining if t.days_remaining is not None else "",
            t.matched_row if t.matched_row is not None else "",
            t.reason or "",
        ])
    return output.getvalue()


def build_full_report(findings: List[TieredFinding]) -> dict:
    return {
        "three_day_action_queue": [asdict(f) for f in three_day_action_queue(findings)],
        "forensic_triage_required": [asdict(f) for f in forensic_triage_required(findings)],
        "tier_distribution": tier_distribution(findings),
        "deferral_population_count": len(deferral_population(findings)),
        "coverage": coverage_summary(findings),
    }
