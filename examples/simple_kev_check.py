#!/usr/bin/env python3
"""
Simple test to verify KEV attribute access.
"""

import json
import os
import requests

# Get credentials from environment variables - NEVER hardcode API keys
ACCESS_KEY = os.environ.get("TENABLE_ACCESS_KEY")
SECRET_KEY = os.environ.get("TENABLE_SECRET_KEY")
BASE_URL = "https://cloud.tenable.com"

if not ACCESS_KEY or not SECRET_KEY:
    raise ValueError(
        "Missing Tenable API credentials. Set TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY environment variables.\n"
        "Get your keys from: Tenable > Settings > My Account > API Keys"
    )

HEADERS = {
    "X-ApiKeys": f"accessKey={ACCESS_KEY};secretKey={SECRET_KEY}",
    "Accept": "application/json",
}

# Test with plugin 185887 which we know has KEV date
plugin_id = 185887

print(f"Checking plugin {plugin_id} for KEV data...\n")

response = requests.get(
    f"{BASE_URL}/plugins/plugin/{plugin_id}",
    headers=HEADERS
)

if response.status_code == 200:
    data = response.json()

    print(f"Plugin Name: {data.get('name')}")
    print(f"Family: {data.get('family_name')}")

    # Find KEV attribute
    for attr in data.get("attributes", []):
        if attr["attribute_name"] == "cisa-known-exploited":
            print(f"\n*** KEV DATE FOUND: {attr['attribute_value']} ***\n")
            break

    # Show other exploit-related attributes
    print("Exploit-related attributes:")
    for attr in data.get("attributes", []):
        name = attr["attribute_name"]
        if any(term in name for term in ["exploit", "cisa", "malware"]):
            print(f"  {name}: {attr['attribute_value']}")

else:
    print(f"Error: {response.status_code}")
    print(response.text)
