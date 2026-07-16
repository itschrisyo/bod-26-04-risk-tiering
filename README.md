# BOD 26-04 Risk Tiering

Computes CISA BOD 26-04 remediation tiers for Tenable One / Tenable
Vulnerability Management findings, using the directive's own four-variable
model (Publicly Exposed x In KEV x Automatable x Technical Impact), instead
of flat KEV-only prioritization.

## Why this exists

This skill implements the full CISA BOD 26-04 compliance framework for Tenable environments. It combines Tenable's vulnerability and exposure data with CISA's Vulnrichment assessments to compute the directive's complete four-variable risk model: Publicly Exposed × In KEV × Automatable × Technical Impact.

Organizations subject to BOD 26-04 need this complete assessment to determine accurate remediation timelines. This skill bridges Tenable's rich vulnerability data with CISA's standardized risk factors to produce compliance-ready tier assignments.

## What Problem This Solves

You have 500+ KEV vulnerabilities in your Tenable environment. No clue which ones need action today vs. next quarter. You're opening five tabs - Tenable Workbench, CISA's KEV catalog, Vulnrichment, asset inventory, whatever exposure data you can find - and trying to manually compute BOD 26-04 tiers. It's taking hours just to triage 50 findings. You're using CVSS or VPR to prioritize, which doesn't map to the directive's actual compliance model. You're missing 3-day deadlines because there's no automated tracking from the first-seen date. You don't know which findings need forensic triage (potential active breach) vs. which ones you just patch and move on.

Leadership asks "are we compliant?" and you spend two days building a spreadsheet instead of just answering.

**This skill fixes that.**

Run one command. Three minutes later you have the complete BOD 26-04 analysis: every finding tiered using Table 1's exact logic (all 16 rows, 4 variables), action queues by deadline (3-day, 14-day, 60-day), forensic triage flags for anything that might be an active breach, and a countdown showing days remaining from the Tenable first-seen date. Multiple output formats - JSON if you're automating it, CSV for leadership, text for humans.

**What that looks like in practice:**

You go from 500 KEV findings to 12 immediate action items. Stop firefighting everything, start focusing on what actually matters. Hours of manual cross-referencing becomes a 3-minute automated run. "I think we're compliant" becomes "here's the proof, Inspector." You're not missing deadlines anymore because the countdown is right there in the report.

## Official References

- **CISA BOD 26-04 Directive**: [https://www.cisa.gov/news-events/directives/bod-26-04-risk-based-vulnerability-management](https://www.cisa.gov/news-events/directives/bod-26-04-risk-based-vulnerability-management)
- **Tenable BOD 26-04 Guide**: [https://www.tenable.com/blog/tenables-guide-to-cisa-bod-26-04](https://www.tenable.com/blog/tenables-guide-to-cisa-bod-26-04)
- **CISA Known Exploited Vulnerabilities (KEV) Catalog**: [https://www.cisa.gov/known-exploited-vulnerabilities-catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- **CISA Vulnrichment (SSVC Assessments)**: [https://github.com/cisagov/vulnrichment](https://github.com/cisagov/vulnrichment)

## Example Output

Here's what BOD 26-04 tier assignments look like for a sample of 10 findings discovered on **July 16, 2026**:

> **Note:** This table uses illustrative data with sanitized asset names. CVE IDs are real and drawn from CISA's KEV catalog, but plugin IDs are examples and may not match actual Tenable plugin numbers. Use this to understand the output format and decision-making value, not as a plugin reference.

| Asset | CVE | Severity | First Seen | Publicly Exposed | In KEV | Automatable | Technical Impact | **Tier** | **Deadline** | **Days Remaining** | **Forensic Triage?** |
|-------|-----|----------|------------|------------------|--------|-------------|------------------|----------|--------------|-------------------|---------------------|
| web-prod-01.corp.local | CVE-2024-4577 | Critical | 2026-07-16 | ✅ Yes | ✅ Yes (2024-07-18) | ✅ Yes | Total | **3-day** | 2026-07-19 | 🔴 **3 days** | ✅ **Required** |
| db-primary-02.corp.local | CVE-2024-3400 | Critical | 2026-07-16 | ✅ Yes | ✅ Yes (2024-03-26) | ✅ Yes | Total | **3-day** | 2026-07-19 | 🔴 **3 days** | ✅ **Required** |
| vpn-gateway-03.corp.local | CVE-2023-46805 | Critical | 2026-07-16 | ✅ Yes | ✅ Yes (2024-01-12) | ✅ Yes | Total | **3-day** | 2026-07-19 | 🔴 **3 days** | ✅ **Required** |
| api-backend-04.corp.local | CVE-2024-1709 | High | 2026-07-16 | ✅ Yes | ✅ Yes (2024-04-08) | ✅ Yes | Partial | **3-day** | 2026-07-19 | 🔴 **3 days** | ❌ No |
| mail-relay-05.corp.local | CVE-2023-27350 | High | 2026-07-16 | ✅ Yes | ✅ Yes (2023-04-18) | ❌ No | Total | **14-day** | 2026-07-30 | 🟡 **14 days** | ❌ No |
| workstation-hr-06.corp.local | CVE-2024-21412 | High | 2026-07-16 | ❌ No | ✅ Yes (2024-02-13) | ✅ Yes | Total | **14-day** | 2026-07-30 | 🟡 **14 days** | ❌ No |
| file-server-07.corp.local | CVE-2023-38831 | Medium | 2026-07-02 | ❌ No | ✅ Yes (2023-08-18) | ✅ Yes | Partial | **60-day** | 2026-08-31 | 🟢 **46 days** | ❌ No |
| backup-storage-08.corp.local | CVE-2024-23897 | Medium | 2026-07-16 | ✅ Yes | ❌ No | ✅ Yes | Total | **60-day** | 2026-09-14 | 🟢 **60 days** | ❌ No |
| dev-staging-09.corp.local | CVE-2024-26169 | High | 2026-06-10 | ❌ No | ❌ No | ❌ No | Partial | **Fix-on-upgrade** | Next maintenance | ⚪ **No deadline** | ❌ No |
| printer-finance-10.corp.local | CVE-2023-99999 | Low | 2026-07-01 | ❌ No | ❌ No | ❌ Undetermined | Undetermined | **Undetermined** | Manual review | ⚪ **Needs assessment** | ❌ No |

### What the 3-Day Tier Means

The 3-day tier means remediate within 3 calendar days of first discovering the vulnerability in your environment. Clock starts from the "First Seen" date in Tenable, not from when you run this report. Miss that deadline and you're non-compliant.

Some 3-day findings also get flagged for forensic triage - actively exploited KEV + publicly exposed means you might have an active breach. Those need immediate investigation, not just patching.

Example: if `web-prod-01` shows first seen on July 16, the deadline is July 19. The "Days Remaining" column counts down from today.

### Reading the Output

**Priority queue (3-day):** 4 findings need immediate action. Three of them require forensic triage (actively exploited KEV on internet-facing assets). Focus on `web-prod-01`, `db-primary-02`, `vpn-gateway-03` first. Drop everything else and remediate these.

**Medium-term (14-day):** 2 findings. KEV vulnerabilities but lower automation/exposure risk. Schedule patches this sprint - don't wait for the next maintenance window.

**Lower priority (60-day):** 2 findings. Still important, lower immediate risk. Quarterly patching cycle works here. Note that `file-server-07` was found 14 days ago, so it only has 46 days remaining, not 60.

**Fix-on-upgrade:** 1 finding. No public exposure, not in KEV, limited automation risk. Handle it during normal maintenance.

**Undetermined:** 1 finding. CISA Vulnrichment doesn't have data for this CVE yet. Needs manual assessment from your security team.

## Requirements

- Tenable One Foundation or Advanced license, with Hexa AI enabled by
  your Tenable administrator (see
  [Tenable's setup docs](https://docs.tenable.com/vulnerability-management/Content/getting-started/hexa-AI-MCP.htm)).
  **Foundation-tier note:** Foundation may not expose the
  asset-exposure/ACR data this skill needs for the Publicly Exposed
  variable. If you're on Foundation, expect a higher Undetermined rate
  and verify this before relying on the output.
- Python 3.8+, no third-party packages required (standard library only
  -- this was a deliberate choice so the skill has no dependency install
  step; see "Design notes" below).
- Outbound network access to `cveawg.mitre.org` (the CVE Services API).
  If your organization restricts outbound network access, this needs to
  be allow-listed or every finding will come back Undetermined for
  reasons that look identical to "Vulnrichment has no coverage" but
  aren't -- see the warning text this skill prints when a fetch fails.

## Connecting Hexa MCP

This skill needs the Tenable Hexa AI MCP server connected in Claude Code.
An example config is at `examples/mcp_config.example.json`, using env var
references rather than literal keys:

```json
{
  "mcpServers": {
    "tenable": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://cloud.tenable.com/mcp/",
        "--header",
        "X-ApiKeys: accessKey=${TENABLE_ACCESS_KEY};secretKey=${TENABLE_SECRET_KEY}"
      ]
    }
  }
}
```

**Never commit a version of this file with real keys filled in.** This
repo's `.gitignore` blocks the likely real-config filenames, but that's a
backstop, not a substitute for using env vars in the first place --
export `TENABLE_ACCESS_KEY` / `TENABLE_SECRET_KEY` in your shell (or a
local, gitignored `.env` you source before launching Claude Code) rather
than hand-editing the JSON with literal key values, even locally.

To register it, either:
- Run `claude mcp add-json tenable "$(cat examples/mcp_config.example.json)"`
  after exporting the two env vars, which avoids hand-editing JSON
  entirely (and the trailing-comma/quoting mistakes that come with it), or
- Copy the file to `.mcp.json` at your project root for a
  version-controlled, team-shareable config (project scope overrides
  user scope) -- again, only with env var references, never literal keys.

Get your API keys from Tenable at Settings > My Account > API Keys.
Hexa AI also requires a Tenable One Foundation or Advanced license with
an administrator enabling the feature for your account -- see
[Tenable's docs](https://docs.tenable.com/vulnerability-management/Content/getting-started/hexa-AI-MCP.htm)
if the tools don't show up after connecting.



```
bod-26-04-risk-tiering/
├── SKILL.md                     # Instructions Claude follows when this skill runs
├── README.md                    # This file
├── data/
│   └── bod_26_04_table1.json    # Table 1, transcribed from the directive PDF -- versioned data, not code
├── scripts/
│   ├── tier_engine.py           # Pure lookup: 4 inputs -> tier + deadline
│   ├── cve_enrichment.py        # CISA Vulnrichment/ADP lookup client, with caching
│   ├── report_builder.py        # Action queue, forensic list, distribution, CSV, coverage stats
│   └── run_tiering.py           # Orchestration entrypoint
├── tests/                       # Runnable without pytest: python3 tests/test_*.py
└── examples/
    └── sample_input.json        # Example of the input shape run_tiering.py expects
```

## Running the tests

No pytest dependency required (this sandbox had no PyPI access during
development, so each test file has a built-in fallback runner):

```bash
python3 tests/test_tier_engine.py       # all 16 Table 1 rows, deadline math, Undetermined path
python3 tests/test_cve_enrichment.py    # ADP container parsing against synthetic records
python3 tests/test_report_builder.py    # the four report views + coverage stat
```

Or with pytest, if available in your environment:
```bash
python3 -m pytest tests/ -v
```

## Design notes / things a reviewer should specifically check

**The tier lookup is a data file, not conditional logic.** An earlier,
hand-written version of this logic assumed "KEV + Total Impact = 3-day
forensic" unconditionally. Table 1 row 11 (Not Exposed, In KEV, Not
Automatable, Total Impact) is actually 14 days -- the fast tier also
requires exposure or automatability, not just KEV+impact. A 16-row lookup
keyed on the same four inputs as the directive's own table can't drift
from it the way hand-written boolean conditions can. `test_tier_engine.py`
has a named regression test for this exact case.

**CVE enrichment parsing is now verified against a real fetched record,
not just README examples.** `CVE-2024-34686` was fetched directly from
`github.com/CVEProject/cvelistV5` and confirms the `containers.adp[]`
structure, the `CISA-ADP` providerMetadata value, and the `options` array
shape all match what the parser assumes -- see
`test_parses_a_real_fetched_record_not_just_synthetic_data` in
`test_cve_enrichment.py`, which uses that real record as a fixture. The
one thing still unverified: the KEV block shape (that CVE wasn't
KEV-listed, so only the README's text example covers that path) --
confirm this specifically if a KEV date ever comes back wrong.

**Vulnrichment coverage is incomplete, and that's treated as a normal
outcome, not an error.** A vendor comparison reported CISA's own
Vulnrichment coverage at roughly 64,000 CVEs against a much larger total
corpus. Undetermined tiers will be common. The coverage summary in
`report_builder.py` breaks this out specifically for KEV-listed findings,
since that's the population where a coverage gap actually matters for
prioritization -- coverage on obscure, non-KEV CVEs is far less
consequential.

**KEV provenance is a defensive OR, not a reconciliation.** `run_tiering.py`
trusts CISA's own ADP "kev" block as authoritative when present (it's the
only source with a `dateAdded`, which the deadline math needs). If
Tenable's own data says a CVE is KEV-listed but the ADP lookup didn't
return a KEV block, this pipeline still treats it as KEV, but without a
`kev_date_added` -- the deadline falls back to `first_detected_date`
only. If the two sources disagree often in practice, that's worth
investigating rather than trusting the fallback indefinitely.

## Explicitly out of scope for this version

- SSVC decision output (Track / Track* / Attend / Act)
- Mission Prevalence / Well-Being Impact scoring
- Cloud Security (no asset-exposure data available there yet, per
  internal discussion during scoping)
- Security Center (this version targets Tenable One / TVM specifically,
  via Hexa MCP; SC would need a separate data-access path)

## Maintenance

CISA reassesses Table 1's timelines once per fiscal year (per the
directive's own "CISA Actions" section). Re-verify
`data/bod_26_04_table1.json` against the current published directive
annually, and whenever CISA announces a Table 1 update.
