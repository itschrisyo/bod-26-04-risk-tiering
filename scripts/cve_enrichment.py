"""
cve_enrichment.py

Fetches CISA Vulnrichment (ADP) data for a CVE -- specifically the
Automatable and Technical Impact SSVC decision points, plus KEV status
and KEV date-added if present in the same record.

IMPORTANT -- verified against a real fetched record:
The parsing logic below was originally built against example field values
from CISA's Vulnrichment README, unverified against a live response. It
has since been checked against an actual record fetched from
github.com/CVEProject/cvelistV5 (CVE-2024-34686) during this project --
see test_parses_a_real_fetched_record_not_just_synthetic_data in
test_cve_enrichment.py, which uses that real record verbatim as a fixture.
The containers.cna / containers.adp[] structure, the CISA-ADP
providerMetadata.shortName value, and the options-array shape for
Exploitation/Automatable/Technical Impact are all confirmed correct.

What is still NOT independently verified: the exact shape of the KEV
block (type: "kev", content.dateAdded) -- the one real record checked
happened not to be KEV-listed, so that path is only tested against the
example in CISA's README text, not a live KEV-listed record. If a KEV
date comes back wrong or missing in practice, check that specific path
first.

This module was also never able to make a live call to the CVE Services
API from its original development sandbox (network egress there was
restricted to a specific domain allowlist that didn't include
cveawg.mitre.org) -- _fetch_cve_record is written defensively for that
reason, degrading to Undetermined on any HTTP or network error rather
than crashing. That defensive handling is worth keeping regardless of
network access, since a 403 there turned out to be a realistic failure
mode, not a hypothetical one.

Caching rationale: Automatable and Technical Impact are properties of the
CVE itself, not of any customer's environment. They don't change per
organization and rarely change over time (only if CISA revises an
assessment). Caching by CVE ID is safe and avoids re-fetching the same
CVE's enrichment data on every run, which matters at enterprise scale
where the same handful of high-prevalence CVEs (e.g. a widely deployed
OS or browser vuln) show up across thousands of assets.
"""

import json
import os
import sys
import time
import urllib.request
import urllib.error
from dataclasses import dataclass
from datetime import date, datetime
from typing import Optional


CVE_SERVICES_API_BASE = "https://cveawg.mitre.org/api/cve"
# NOTE: cveawg.mitre.org is the CVE Services API used by CNAs/ADPs to
# publish records; it is also the standard read endpoint referenced in
# CISA's own Vulnrichment README ("...can access this data in the normal
# ways, including the GitHub API and the CVE Services API"). If this
# endpoint proves unsuitable (auth requirements, rate limits), the
# fallback is reading raw JSON directly from the CVEProject/cvelistV5
# GitHub repo (path pattern: cves/<year>/<Nxxx>xx/CVE-<year>-<n>.json),
# which is the public mirror CISA's Vulnrichment data flows into.


@dataclass
class CveEnrichment:
    cve_id: str
    automatable: Optional[bool]       # True/False/None (None = no Vulnrichment data)
    technical_impact: Optional[str]   # "total" / "partial" / None
    in_kev: bool
    kev_date_added: Optional[date]
    source: str                       # "vulnrichment", "cache", or "unavailable"


class CveEnrichmentClient:
    def __init__(self, cache_path: Optional[str] = None, rate_limit_seconds: float = 0.5):
        if cache_path is None:
            cache_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "data",
                "cve_enrichment_cache.json",
            )
        self._cache_path = cache_path
        self._rate_limit_seconds = rate_limit_seconds
        self._cache = self._load_cache()

    def _load_cache(self) -> dict:
        if os.path.exists(self._cache_path):
            with open(self._cache_path, "r") as f:
                return json.load(f)
        return {}

    def _save_cache(self):
        with open(self._cache_path, "w") as f:
            json.dump(self._cache, f, indent=2)

    def get_enrichment(self, cve_id: str, use_cache: bool = True) -> CveEnrichment:
        if use_cache and cve_id in self._cache:
            cached = self._cache[cve_id]
            return CveEnrichment(
                cve_id=cve_id,
                automatable=cached["automatable"],
                technical_impact=cached["technical_impact"],
                in_kev=cached["in_kev"],
                kev_date_added=(
                    datetime.strptime(cached["kev_date_added"], "%Y-%m-%d").date()
                    if cached.get("kev_date_added")
                    else None
                ),
                source="cache",
            )

        record = self._fetch_cve_record(cve_id)
        if record is None:
            result = CveEnrichment(
                cve_id=cve_id,
                automatable=None,
                technical_impact=None,
                in_kev=False,
                kev_date_added=None,
                source="unavailable",
            )
        else:
            result = self._parse_adp_container(cve_id, record)

        # Cache regardless of whether enrichment was found -- a CVE with
        # no Vulnrichment coverage today is worth re-checking on a future
        # run (CISA continuously enriches new CVEs), but re-fetching it
        # on every single run of this skill against a large environment
        # is wasteful. Callers that want a forced re-check can pass
        # use_cache=False, or the cache file can be cleared/aged out
        # (not implemented here -- see README for the suggested TTL).
        self._cache[cve_id] = {
            "automatable": result.automatable,
            "technical_impact": result.technical_impact,
            "in_kev": result.in_kev,
            "kev_date_added": result.kev_date_added.isoformat() if result.kev_date_added else None,
        }
        self._save_cache()
        return result

    def get_enrichment_bulk(self, cve_ids: list) -> dict:
        """Convenience wrapper for tiering a full vulnerability export. Respects
        rate_limit_seconds between live fetches (cache hits are not throttled)."""
        results = {}
        for cve_id in cve_ids:
            was_cached = cve_id in self._cache
            results[cve_id] = self.get_enrichment(cve_id)
            if not was_cached:
                time.sleep(self._rate_limit_seconds)
        return results

    def _fetch_cve_record(self, cve_id: str) -> Optional[dict]:
        url = f"{CVE_SERVICES_API_BASE}/{cve_id}"
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            # Any HTTP error -- not just 404 -- degrades to "unavailable"
            # rather than crashing the whole run. This matters in
            # practice, not just in theory: a 403 here (egress-restricted
            # corporate network blocking cveawg.mitre.org, rate limiting,
            # or the endpoint being temporarily down) should not take down
            # tiering for every other finding just because one CVE lookup
            # failed. Print a warning so the coverage gap is visible
            # rather than silently swallowed.
            print(
                f"WARNING: CVE enrichment fetch for {cve_id} failed with "
                f"HTTP {e.code}. Treating as unavailable -- this CVE will "
                f"tier as Undetermined. If this happens for most/all "
                f"CVEs, check whether your network can reach "
                f"{CVE_SERVICES_API_BASE} at all (e.g. an egress "
                f"allowlist blocking it), rather than assuming Vulnrichment "
                f"simply has no coverage.",
                file=sys.stderr,
            )
            return None
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            print(
                f"WARNING: CVE enrichment fetch for {cve_id} failed "
                f"({type(e).__name__}: {e}). Treating as unavailable.",
                file=sys.stderr,
            )
            return None

    def _parse_adp_container(self, cve_id: str, record: dict) -> CveEnrichment:
        """
        Expected shape (CVE JSON 5, unverified against a live response --
        see module docstring):

        record["containers"]["adp"] is a list of ADP containers. The CISA
        one is identified by title/provider containing "CISA"; its
        `metrics` list contains an entry with an `other` block whose
        `content.options` is a list of single-key dicts like
        {"Automatable": "YES"} / {"Technical Impact": "TOTAL"}.
        KEV data lives in a separate `other` block with type "kev" and a
        content.dateAdded field.
        """
        automatable = None
        technical_impact = None
        in_kev = False
        kev_date_added = None

        try:
            adp_containers = record.get("containers", {}).get("adp", [])
        except AttributeError:
            adp_containers = []

        for adp in adp_containers:
            provider = str(adp.get("providerMetadata", {}).get("shortName", "")).upper()
            # Match on "CISA" specifically. A generic "ADP" substring check
            # is too loose -- e.g. "Siemens-SADP".upper() contains "ADP" and
            # would be wrongly treated as CISA's assessment. Other
            # Authorized Data Publishers (suppliers, other agencies) use
            # the same ADP container mechanism and must not be conflated
            # with CISA's SSVC/KEV data.
            if "CISA" not in provider:
                continue  # not the CISA ADP container; another ADP's or the CNA's data

            for metric in adp.get("metrics", []):
                other = metric.get("other", {})
                content = other.get("content", {})

                if other.get("type") == "ssvc" or "options" in content:
                    for option in content.get("options", []):
                        if "Automatable" in option:
                            automatable = str(option["Automatable"]).strip().lower() == "yes"
                        if "Technical Impact" in option:
                            technical_impact = str(option["Technical Impact"]).strip().lower()

                if other.get("type") == "kev":
                    in_kev = True
                    date_str = other.get("content", {}).get("dateAdded")
                    if date_str:
                        try:
                            kev_date_added = datetime.strptime(date_str, "%Y-%m-%d").date()
                        except ValueError:
                            pass  # malformed date from source -- leave as None, don't crash

        return CveEnrichment(
            cve_id=cve_id,
            automatable=automatable,
            technical_impact=technical_impact,
            in_kev=in_kev,
            kev_date_added=kev_date_added,
            source="vulnrichment" if (automatable is not None or technical_impact is not None) else "unavailable",
        )
