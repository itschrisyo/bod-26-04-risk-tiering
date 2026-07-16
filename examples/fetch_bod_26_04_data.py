#!/usr/bin/env python3
"""
Fetch BOD 26-04 data from Tenable Workbench APIs.

This script demonstrates how to:
1. Get critical vulnerabilities from Workbench
2. Check which ones have CISA KEV dates
3. Get assets with ACR scores and exposure indicators
4. Match vulnerabilities to assets
"""

import json
import requests
from typing import Dict, List, Optional
from datetime import datetime

# API Configuration
ACCESS_KEY = "***REMOVED***"
SECRET_KEY = "***REMOVED***"
BASE_URL = "https://cloud.tenable.com"

HEADERS = {
    "X-ApiKeys": f"accessKey={ACCESS_KEY};secretKey={SECRET_KEY}",
    "Accept": "application/json",
}


class TenableAPI:
    """Wrapper for Tenable API calls."""

    def __init__(self, base_url: str, headers: Dict[str, str]):
        self.base_url = base_url
        self.headers = headers

    def get(self, endpoint: str, params: Optional[Dict] = None) -> Optional[Dict]:
        """Make GET request to Tenable API."""
        url = f"{self.base_url}{endpoint}"
        try:
            response = requests.get(url, headers=self.headers, params=params)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Error calling {endpoint}: {e}")
            return None


def get_kev_vulnerabilities(api: TenableAPI, severity: str = "Critical") -> List[Dict]:
    """
    Get vulnerabilities that are on CISA KEV list.

    Returns list of vulnerabilities with KEV dates.
    """
    print(f"Fetching {severity} vulnerabilities...")

    # Get vulnerabilities from workbench
    params = {
        "filter.0.filter": "severity",
        "filter.0.quality": "eq",
        "filter.0.value": severity
    }

    data = api.get("/workbenches/vulnerabilities", params)
    if not data or "vulnerabilities" not in data:
        return []

    vulns = data["vulnerabilities"]
    print(f"Found {len(vulns)} {severity} vulnerabilities")

    # Check each plugin for KEV attribute
    kev_vulns = []

    for i, vuln in enumerate(vulns):
        plugin_id = vuln["plugin_id"]

        # Show progress every 50 plugins
        if i > 0 and i % 50 == 0:
            print(f"  Checked {i}/{len(vulns)} plugins, found {len(kev_vulns)} with KEV dates...")

        # Get plugin details to check for KEV
        plugin_data = api.get(f"/plugins/plugin/{plugin_id}")
        if not plugin_data:
            continue

        # Look for cisa-known-exploited attribute and CVE list
        kev_date = None
        cve_list = []
        for attr in plugin_data.get("attributes", []):
            if attr["attribute_name"] == "cisa-known-exploited":
                kev_date = attr["attribute_value"]
            elif attr["attribute_name"] == "cve":
                # CVE attribute can be a single CVE or comma-separated list
                cve_value = attr["attribute_value"]
                if cve_value:
                    cve_list = [c.strip() for c in cve_value.split(',')]

        if kev_date:
            kev_vulns.append({
                "plugin_id": plugin_id,
                "plugin_name": vuln.get("plugin_name"),
                "plugin_family": vuln.get("plugin_family"),
                "severity": severity,
                "count": vuln.get("count", 0),
                "vpr_score": vuln.get("vpr_score"),
                "cvss3_base_score": vuln.get("cvss3_base_score"),
                "cisa_kev_date": kev_date,
                "cves": cve_list  # Store all CVEs from this plugin
            })

    print(f"Found {len(kev_vulns)} vulnerabilities with KEV dates")
    return kev_vulns


def get_assets_with_acr(api: TenableAPI, limit: int = 1000) -> List[Dict]:
    """
    Get assets with ACR scores and exposure indicators.

    Returns list of assets with ACR and exposure data.
    """
    print(f"Fetching assets (limit={limit})...")

    data = api.get("/assets")
    if not data or "assets" not in data:
        return []

    assets = data["assets"][:limit]
    print(f"Found {len(assets)} assets")

    result = []
    for asset in assets:
        result.append({
            "id": asset.get("id"),
            "ipv4": asset.get("ipv4", []),
            "fqdn": asset.get("fqdn", []),
            "hostname": asset.get("hostname", []),
            "operating_system": asset.get("operating_system", []),
            "acr_score": asset.get("acr_score"),
            "exposure_score": asset.get("exposure_score"),
            "last_seen": asset.get("last_seen"),
            "has_agent": asset.get("has_agent", False)
        })

    return result


def get_asset_vulnerabilities(api: TenableAPI, asset_id: str, kev_plugin_ids: set) -> List[Dict]:
    """
    Get vulnerabilities for a specific asset, filtered to KEV plugins.

    Args:
        asset_id: Asset UUID
        kev_plugin_ids: Set of plugin IDs that are on KEV list

    Returns:
        List of KEV vulnerabilities on this asset
    """
    data = api.get(f"/workbenches/assets/{asset_id}/vulnerabilities")
    if not data or "vulnerabilities" not in data:
        return []

    # Filter to only KEV vulnerabilities
    asset_kevs = []
    for vuln in data["vulnerabilities"]:
        plugin_id = vuln.get("plugin_id")
        if plugin_id in kev_plugin_ids:
            asset_kevs.append({
                "plugin_id": plugin_id,
                "severity": vuln.get("severity"),
                "count": vuln.get("count", 1)
            })

    return asset_kevs


def generate_bod_26_04_report(api: TenableAPI, output_file: str = "bod_26_04_report.json"):
    """
    Generate BOD 26-04 compliance report.

    This combines:
    - KEV vulnerabilities (critical/high)
    - Asset ACR scores
    - Exposure indicators
    """
    print("=" * 60)
    print("BOD 26-04 Data Collection")
    print("=" * 60)

    # Step 1: Get KEV vulnerabilities
    kev_vulns = get_kev_vulnerabilities(api, severity="Critical")

    # Create lookup for KEV plugins
    kev_plugin_lookup = {v["plugin_id"]: v for v in kev_vulns}
    kev_plugin_ids = set(kev_plugin_lookup.keys())

    # Step 2: Get assets with ACR scores
    assets = get_assets_with_acr(api, limit=500)  # Sample 500 assets to find more KEV matches

    # Step 3: Match vulnerabilities to assets
    print(f"\nMatching vulnerabilities to assets...")
    results = []

    for i, asset in enumerate(assets):
        print(f"  Processing asset {i+1}/{len(assets)}: {asset['id']}")

        # Get vulnerabilities for this asset
        asset_kevs = get_asset_vulnerabilities(api, asset["id"], kev_plugin_ids)

        if asset_kevs:
            # Enrich with KEV details
            enriched_kevs = []
            for av in asset_kevs:
                plugin_id = av["plugin_id"]
                if plugin_id in kev_plugin_lookup:
                    enriched = {**av, **kev_plugin_lookup[plugin_id]}
                    enriched_kevs.append(enriched)

            results.append({
                "asset": asset,
                "kev_vulnerabilities": enriched_kevs,
                "kev_count": len(enriched_kevs)
            })

    # Step 4: Sort by priority
    # Priority: More KEV vulns, higher ACR, higher exposure
    results.sort(
        key=lambda x: (
            -x["kev_count"],
            -(x["asset"]["acr_score"] or 0),
            -(x["asset"]["exposure_score"] or 0)
        )
    )

    # Step 5: Generate report
    report = {
        "generated_at": datetime.now().isoformat(),
        "summary": {
            "total_kev_vulnerabilities": len(kev_vulns),
            "total_assets_analyzed": len(assets),
            "assets_with_kev_vulnerabilities": len(results)
        },
        "kev_vulnerabilities": kev_vulns,
        "assets_at_risk": results
    }

    # Save report
    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n{'=' * 60}")
    print("Report Summary")
    print(f"{'=' * 60}")
    print(f"Total KEV vulnerabilities: {len(kev_vulns)}")
    print(f"Assets analyzed: {len(assets)}")
    print(f"Assets with KEV vulnerabilities: {len(results)}")
    print(f"\nReport saved to: {output_file}")

    # Show top 5 highest priority assets
    if results:
        print(f"\nTop 5 Highest Priority Assets:")
        for i, result in enumerate(results[:5], 1):
            asset = result["asset"]
            ip = asset["ipv4"][0] if asset["ipv4"] else "N/A"
            print(f"{i}. {ip} - {result['kev_count']} KEV vulns, ACR={asset['acr_score']}, Exposure={asset['exposure_score']}")


def main():
    """Main function."""
    api = TenableAPI(BASE_URL, HEADERS)

    # Generate BOD 26-04 report
    generate_bod_26_04_report(api, output_file="/Users/cedson/Documents/GitHub/bod-26-04-risk-tiering/data/bod_26_04_report.json")


if __name__ == "__main__":
    main()
