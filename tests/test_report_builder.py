"""
test_report_builder.py

Builds a small synthetic set of TieredFindings covering each tier plus an
Undetermined case, and checks each report view against hand-counted
expectations.
"""

import sys
import os
from datetime import date

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

from tier_engine import TierEngine, Timeline  # noqa: E402
from report_builder import (  # noqa: E402
    TieredFinding,
    three_day_action_queue,
    forensic_triage_required,
    tier_distribution,
    deferral_population,
    coverage_summary,
    to_csv,
)


def _make_findings():
    engine = TierEngine()
    specs = [
        # (asset, cve, exposed, kev, automatable, impact, kev_date, first_seen)
        ("host-1", "CVE-A", True,  True,  True,  "total",   date(2026, 7, 1), None),   # 3d forensic
        ("host-2", "CVE-B", True,  True,  True,  "partial", date(2026, 7, 10), None),  # 3d
        ("host-3", "CVE-C", False, False, False, "partial", None, date(2026, 1, 1)),   # fix-on-upgrade
        ("host-4", "CVE-D", None,  True,  None,  None,      None, None),               # undetermined, KEV
        ("host-5", "CVE-E", True,  False, False, "partial", None, date(2026, 6, 1)),   # 60d, not KEV
    ]
    findings = []
    for asset, cve, exposed, kev, auto, impact, kev_date, first_seen in specs:
        tier = engine.compute_tier(
            publicly_exposed=exposed, in_kev=kev, automatable=auto,
            technical_impact=impact, kev_date_added=kev_date,
            first_detected_date=first_seen, today=date(2026, 7, 15),
        )
        findings.append(TieredFinding(
            asset_id=asset, asset_name=asset, cve_id=cve,
            plugin_id="12345", plugin_name="Test Plugin",
            in_kev=kev, tier=tier,
        ))
    return findings


def test_three_day_queue_contains_only_3day_tiers_sorted_by_urgency():
    findings = _make_findings()
    queue = three_day_action_queue(findings)
    assert [f.cve_id for f in queue] == ["CVE-A", "CVE-B"]  # A's deadline (7/4) before B's (7/13)


def test_forensic_triage_list_is_exactly_the_forensic_row():
    findings = _make_findings()
    forensic = forensic_triage_required(findings)
    assert [f.cve_id for f in forensic] == ["CVE-A"]


def test_deferral_population_is_the_fix_on_upgrade_row():
    findings = _make_findings()
    deferred = deferral_population(findings)
    assert [f.cve_id for f in deferred] == ["CVE-C"]


def test_tier_distribution_counts_add_up_to_total():
    findings = _make_findings()
    dist = tier_distribution(findings)
    assert dist["_total"] == 5
    assert dist[Timeline.THREE_DAYS_FORENSIC.value] == 1
    assert dist[Timeline.THREE_DAYS.value] == 1
    assert dist[Timeline.SIXTY_DAYS.value] == 1
    assert dist[Timeline.FIX_ON_UPGRADE.value] == 1
    assert dist[Timeline.UNDETERMINED.value] == 1


def test_coverage_summary_breaks_out_kev_specifically():
    findings = _make_findings()
    cov = coverage_summary(findings)
    assert cov["total_findings"] == 5
    assert cov["undetermined"] == 1
    assert cov["kev_findings_total"] == 3         # CVE-A, CVE-B, CVE-D all have in_kev=True
    assert cov["kev_findings_undetermined"] == 1  # only CVE-D
    assert round(cov["kev_coverage_pct"], 1) == 66.7


def test_csv_export_includes_undetermined_reason_for_undetermined_rows():
    findings = _make_findings()
    csv_text = to_csv(findings)
    assert "CVE-D" in csv_text
    assert "undetermined" in csv_text
    # The undetermined row should carry a human-readable reason, not a blank field
    lines = [l for l in csv_text.splitlines() if l.startswith("host-4")]
    assert len(lines) == 1
    assert "Missing required input" in lines[0]


if __name__ == "__main__":
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
        except Exception as e:
            print(f"ERROR: {t.__name__}\n  {type(e).__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
