---
name: bod-26-04-risk-tiering
description: Computes CISA BOD 26-04 remediation tiers (3-day+forensic / 3-day / 14-day / 60-day / fix-on-upgrade) for Tenable One / Tenable Vulnerability Management findings, using the directive's own four-variable model. Use when the user asks about BOD 26-04, CISA risk-based vulnerability prioritization, SSVC-based tiering, or "which vulnerabilities need 3-day remediation."
---

# BOD 26-04 Risk Tiering

## What this does

Computes the CISA BOD 26-04 remediation tier for vulnerability findings in
a Tenable One / TVM environment, implementing the complete four-variable
model from the directive's Table 1 (Appendix A): Publicly Exposed × In KEV
× Automatable × Technical Impact → remediation deadline + forensic triage
flag where required.

This skill bridges Tenable's vulnerability and exposure data with CISA's
Vulnrichment risk assessments to produce compliance-ready BOD 26-04 tier
assignments for organizations subject to the directive.

**Official References:**
- CISA BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-risk-based-vulnerability-management
- Tenable BOD 26-04 Guide: https://www.tenable.com/blog/tenables-guide-to-cisa-bod-26-04
- CISA KEV Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- CISA Vulnrichment (SSVC): https://github.com/cisagov/vulnrichment

## Before you start

1. **Confirm Hexa MCP is connected and the license tier.** Check for
   Tenable tools (names like `workbenches_list_vulnerabilities`,
   `tenable_one_search_assets`, `tenable_one_search_assets`). If they're
   not available, tell the user Hexa AI needs to be connected (requires
   Tenable One Foundation or Advanced, plus an admin enabling the feature
   for their account -- see
   https://docs.tenable.com/vulnerability-management/Content/getting-started/hexa-AI-MCP.htm).

2. **Ask (or check) the license tier if not already known.** Tenable One
   *Foundation* does not include the Advanced-tier exposure/ACR data that
   the Publicly Exposed variable likely depends on. If the user is on
   Foundation, tell them up front that Variable 1 (Publicly Exposed) may
   come back empty for every finding, which will push everything to
   Undetermined -- this is expected given the license, not a bug in this
   skill. Confirm this by trying step 3 below and checking whether an
   exposure/internet-facing field actually comes back on a few assets
   before running the full pipeline.

3. **Pull vulnerability and asset data using the connected Hexa MCP tools.**
   The exact tool names and parameters were not verified against a live
   Hexa MCP connection during this skill's development (no Hexa MCP
   access was available in that environment) -- discover the actual tool
   schemas available to you right now and use your judgment on the right
   calls. As a starting point, based on Tenable's own documented example
   workflows:
   - A tool like `workbenches_list_vulnerabilities` for the finding list
     (CVE ID, plugin ID/name, first-seen date, and KEV status if the tool
     surfaces it)
   - A tool like `tenable_one_search_assets` for asset identity and, if
     available, a publicly-exposed / internet-facing field
   - If a single tool call doesn't return everything needed, join what
     you get from multiple calls by asset ID.

4. **Write the combined data into the input JSON shape `scripts/run_tiering.py`
   expects** (documented in that file's docstring, and in
   `examples/sample_input.json`). Save it somewhere in the working
   directory, e.g. `/tmp/bod_findings_input.json`.

## Running the pipeline

Once the input JSON exists:

```bash
python3 scripts/run_tiering.py /tmp/bod_findings_input.json /tmp/bod_output
```

This will (see `scripts/run_tiering.py` for the full pipeline):
- Look up Automatable / Technical Impact for each unique CVE ID via
  CISA's Vulnrichment (ADP) data, with local caching (`data/cve_enrichment_cache.json`)
  so repeat runs don't re-fetch CVEs already looked up.
- Compute a tier for every vulnerability-asset pair via the Table 1
  lookup in `data/bod_26_04_table1.json`.
- Write `bod_26_04_report.json` (action queue, forensic triage list, tier
  distribution, deferral population, coverage summary) and
  `bod_26_04_findings.csv` (every finding, every contributing variable,
  for defensible/auditable reporting) to the output directory.

## Presenting results to the user

Lead with the coverage numbers before the tier breakdown -- if
`kev_coverage_pct` is low, say so plainly before presenting the "3-day
action queue" as if it were complete. An incomplete 3-day queue presented
with false confidence is worse than no queue at all, given what this
tool is for.

Then show, in order: 3-day action queue (this is the whole point of the
directive -- lead with it), forensic triage required list, tier
distribution, deferral population count. Offer the CSV for download.

If `coverage_pct` is at or near 0% and the user has working internet
access, warn them explicitly to check whether their network can reach
`https://cveawg.mitre.org` at all (see the warning text in
`cve_enrichment.py` -- an egress-restricted corporate network will
produce this exact symptom and it is easy to mistake for "Vulnrichment
has no data" when the real cause is a blocked domain).

## Out of scope for this version

Do not extend this skill to compute SSVC decision output (Track / Track*
/ Attend / Act) or Mission Prevalence / Well-Being Impact scoring without
also updating `data/bod_26_04_table1.json` and `tier_engine.py` -- those
are separate SSVC decision points that BOD 26-04's own Table 1 does not
require, and folding them in casually risks conflating two different
frameworks (BOD 26-04's four-variable model vs. full SSVC).

## Known limitations (tell the user these, don't bury them)

- Tenable One Foundation may not expose the data needed for Publicly
  Exposed -- see step 2 above.
- CISA's Vulnrichment coverage is not complete across the CVE corpus.
  Undetermined results are expected, not rare, especially for older or
  lower-profile CVEs. Coverage is expected to be better for KEV-listed
  CVEs specifically, since CISA prioritizes those for triage -- which is
  why the coverage summary breaks KEV coverage out separately.
- This directive is federal-agency-mandated (BOD = Binding Operational
  Directive, applies to FCEB agencies). The underlying four-variable
  risk model is useful for any organization's vulnerability
  prioritization, federal or not -- frame it that way for a general
  audience rather than as compliance-only.
- Table 1's timelines are reassessed annually by CISA. Re-verify
  `data/bod_26_04_table1.json` against the current published directive
  at least once a year.
