"""
run_tiering.py

Orchestrates the full pipeline: read Tenable vulnerability/asset data
(already fetched by Claude via Hexa MCP tool calls, see SKILL.md) ->
enrich each unique CVE via CveEnrichmentClient -> compute a tier for
every vulnerability-asset pair via TierEngine -> build the report views.

This script does NOT call Hexa MCP itself. Claude, running live inside
Claude Code with the Hexa MCP server connected, is responsible for
calling the actual Tenable tools (workbenches_list_vulnerabilities,
tenable_one_search_assets, etc. -- see SKILL.md) and writing their output
into the input JSON shape this script expects. This split exists because
the exact Hexa MCP tool names and parameters could not be verified from
this build environment (no live Hexa MCP connection available here) --
better to have Claude discover and call the real tools at runtime than
have this script guess at a tool signature and silently fail or call the
wrong thing.

Expected input JSON shape (see also examples/sample_input.json):
{
  "findings": [
    {
      "asset_id": "...",
      "asset_name": "...",
      "cve_id": "CVE-2024-12345",
      "plugin_id": "...",              // optional
      "plugin_name": "...",            // optional
      "publicly_exposed": true|false|null,   // null if not available (e.g. Foundation tier)
      "first_detected_date": "YYYY-MM-DD",   // optional but recommended
      "in_kev_per_tenable": true|false        // optional, see note below on provenance
    },
    ...
  ]
}

A note on KEV provenance: this pipeline treats CISA's own ADP "kev" block
(fetched per-CVE in cve_enrichment.py) as the primary source for in_kev
and kev_date_added, because it's the only source that reliably carries
the dateAdded value the trigger-date calculation needs. If Tenable's own
data (in_kev_per_tenable) says a CVE is KEV-listed but the CVE-level
lookup didn't find a KEV block (e.g. a transient API failure, or a lag
between KEV catalog updates and CISA re-publishing the ADP container),
this script trusts Tenable and treats it as KEV anyway -- but WITHOUT a
kev_date_added in that fallback case, meaning the deadline will fall back
to first_detected_date only. This is a defensive OR, not a full
reconciliation between the two sources; if you see the two sources
disagreeing often in practice, that's worth investigating rather than
just trusting this fallback indefinitely.
"""

import json
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tier_engine import TierEngine  # noqa: E402
from cve_enrichment import CveEnrichmentClient  # noqa: E402
from report_builder import TieredFinding, build_full_report, to_csv  # noqa: E402


def _parse_date(date_str):
    if not date_str:
        return None
    return datetime.strptime(date_str, "%Y-%m-%d").date()


def run(input_path: str, output_dir: str):
    with open(input_path, "r") as f:
        data = json.load(f)

    raw_findings = data.get("findings", [])
    if not raw_findings:
        raise ValueError(
            "Input has no findings. Check that the Hexa MCP tool calls "
            "in the preceding step actually returned data -- an empty "
            "environment and a failed fetch look the same here unless "
            "you check upstream."
        )

    engine = TierEngine()
    enrichment_client = CveEnrichmentClient()

    unique_cve_ids = sorted({f["cve_id"] for f in raw_findings})
    enrichment_by_cve = enrichment_client.get_enrichment_bulk(unique_cve_ids)

    tiered_findings = []
    for raw in raw_findings:
        cve_id = raw["cve_id"]
        enrichment = enrichment_by_cve[cve_id]

        in_kev = enrichment.in_kev or bool(raw.get("in_kev_per_tenable"))
        kev_date_added = enrichment.kev_date_added  # see provenance note above -- not backfilled from Tenable

        tier = engine.compute_tier(
            publicly_exposed=raw.get("publicly_exposed"),
            in_kev=in_kev,
            automatable=enrichment.automatable,
            technical_impact=enrichment.technical_impact,
            kev_date_added=kev_date_added,
            first_detected_date=_parse_date(raw.get("first_detected_date")),
        )

        tiered_findings.append(TieredFinding(
            asset_id=raw["asset_id"],
            asset_name=raw.get("asset_name", raw["asset_id"]),
            cve_id=cve_id,
            plugin_id=raw.get("plugin_id"),
            plugin_name=raw.get("plugin_name"),
            in_kev=in_kev,
            tier=tier,
        ))

    os.makedirs(output_dir, exist_ok=True)

    report = build_full_report(tiered_findings)
    report_path = os.path.join(output_dir, "bod_26_04_report.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    csv_path = os.path.join(output_dir, "bod_26_04_findings.csv")
    with open(csv_path, "w") as f:
        f.write(to_csv(tiered_findings))

    print(f"Processed {len(tiered_findings)} findings across {len(unique_cve_ids)} unique CVEs.")
    print(f"Report:  {report_path}")
    print(f"CSV:     {csv_path}")
    print(f"Coverage: {report['coverage']['coverage_pct']}% overall, "
          f"{report['coverage']['kev_coverage_pct']}% of KEV-listed findings.")
    return report


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 run_tiering.py <input_findings.json> <output_dir>")
        sys.exit(1)
    run(sys.argv[1], sys.argv[2])
