"""
test_cve_enrichment.py

Tests _parse_adp_container against synthetic CVE records built to match
the field names and example values CISA publishes in the Vulnrichment
README (CVE-2024-25522's "poc"/"yes"/"total" example, CVE-2024-4947's KEV
block, etc.) -- NOT against a live API response, which this sandbox can't
reach. See the "verify before relying on this in production" note at the
top of cve_enrichment.py: these tests prove the parser is internally
correct against the assumed schema, not that the assumed schema is
correct. Re-run equivalent tests against a real fetched record before
this ships.
"""

import sys
import os
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

from cve_enrichment import CveEnrichmentClient  # noqa: E402


def _client_with_temp_cache():
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    tmp.write("{}")
    tmp.close()
    return CveEnrichmentClient(cache_path=tmp.name)


def test_parses_automatable_and_technical_impact_from_options_array():
    # Shaped after CISA's own CVE-2024-25522 example in the Vulnrichment README:
    # "options": [{"Exploitation": "poc"}, {"Automatable": "yes"}, {"Technical Impact": "total"}]
    record = {
        "containers": {
            "cna": {},
            "adp": [
                {
                    "providerMetadata": {"shortName": "CISA-ADP"},
                    "metrics": [
                        {
                            "other": {
                                "type": "ssvc",
                                "content": {
                                    "options": [
                                        {"Exploitation": "poc"},
                                        {"Automatable": "yes"},
                                        {"Technical Impact": "total"},
                                    ]
                                },
                            }
                        }
                    ],
                }
            ],
        }
    }
    client = _client_with_temp_cache()
    result = client._parse_adp_container("CVE-2024-25522", record)
    assert result.automatable is True
    assert result.technical_impact == "total"
    assert result.in_kev is False
    assert result.source == "vulnrichment"


def test_parses_kev_block_and_date_added():
    # Shaped after CISA's CVE-2024-4947 example: a separate `other` block
    # with type "kev" and a content.dateAdded field.
    record = {
        "containers": {
            "adp": [
                {
                    "providerMetadata": {"shortName": "CISA-ADP"},
                    "metrics": [
                        {"other": {"type": "ssvc", "content": {"options": [
                            {"Automatable": "no"}, {"Technical Impact": "total"}
                        ]}}},
                        {"other": {"type": "kev", "content": {
                            "dateAdded": "2024-05-20",
                            "reference": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2024-4947"
                        }}},
                    ],
                }
            ]
        }
    }
    client = _client_with_temp_cache()
    result = client._parse_adp_container("CVE-2024-4947", record)
    assert result.in_kev is True
    assert result.kev_date_added.isoformat() == "2024-05-20"
    assert result.automatable is False
    assert result.technical_impact == "total"


def test_no_adp_container_returns_unavailable_not_a_crash():
    # A CVE where the originating CNA already provided complete data and
    # CISA's ADP made no assessment (per the README's CVE-2024-2905 example).
    record = {"containers": {"cna": {"some": "data"}, "adp": []}}
    client = _client_with_temp_cache()
    result = client._parse_adp_container("CVE-2024-2905", record)
    assert result.automatable is None
    assert result.technical_impact is None
    assert result.in_kev is False
    assert result.source == "unavailable"


def test_non_cisa_adp_container_is_ignored():
    # A record with an ADP container from a different authorized
    # publisher (e.g. a supplier ADP like Siemens' SADP) should not be
    # mistaken for CISA's assessment.
    record = {
        "containers": {
            "adp": [
                {
                    "providerMetadata": {"shortName": "Siemens-SADP"},
                    "metrics": [{"other": {"type": "ssvc", "content": {"options": [
                        {"Automatable": "yes"}
                    ]}}}],
                }
            ]
        }
    }
    client = _client_with_temp_cache()
    result = client._parse_adp_container("CVE-2025-2884", record)
    assert result.automatable is None  # ignored -- not from CISA
    assert result.source == "unavailable"


def test_malformed_kev_date_does_not_crash():
    record = {
        "containers": {
            "adp": [
                {
                    "providerMetadata": {"shortName": "CISA-ADP"},
                    "metrics": [{"other": {"type": "kev", "content": {"dateAdded": "not-a-date"}}}],
                }
            ]
        }
    }
    client = _client_with_temp_cache()
    result = client._parse_adp_container("CVE-9999-00000", record)
    assert result.in_kev is True
    assert result.kev_date_added is None  # malformed -- dropped, not crashed


def test_missing_containers_key_entirely_does_not_crash():
    client = _client_with_temp_cache()
    result = client._parse_adp_container("CVE-0000-00000", {})
    assert result.automatable is None
    assert result.source == "unavailable"


def test_parses_a_real_fetched_record_not_just_synthetic_data():
    """
    This is CVE-2024-34686's actual record, fetched from
    github.com/CVEProject/cvelistV5 during development (not paraphrased,
    not hand-constructed) -- the one real verification this module had
    been missing. It confirms three things at once: the CISA-ADP
    providerMetadata.shortName value really is "CISA-ADP" (not just the
    "CISA" guess used in the parser's filter), the options array really
    does contain single-key dicts for Exploitation/Automatable/Technical
    Impact under other.type == "ssvc", and the CVE Program Container
    (shortName "CVE") really does sit alongside the CISA-ADP container in
    the same adp[] list and must be excluded, not merged.
    """
    real_record = {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1",
        "cveMetadata": {
            "cveId": "CVE-2024-34686",
            "assignerOrgId": "e4686d1a-f260-4930-ac4c-2f5c992778dd",
            "state": "PUBLISHED",
            "assignerShortName": "sap",
            "dateReserved": "2024-05-07T05:46:11.657Z",
            "datePublished": "2024-06-11T02:11:49.630Z",
            "dateUpdated": "2024-08-02T02:59:22.207Z",
        },
        "containers": {
            "cna": {"title": "Cross-Site Scripting (XSS) vulnerability in SAP CRM (WebClient UI)"},
            "adp": [
                {
                    "affected": [{"vendor": "sap_se", "product": "sap_crm_webclient_ui"}],
                    "metrics": [
                        {
                            "other": {
                                "type": "ssvc",
                                "content": {
                                    "timestamp": "2024-06-11T13:30:24.401872Z",
                                    "id": "CVE-2024-34686",
                                    "options": [
                                        {"Exploitation": "none"},
                                        {"Automatable": "no"},
                                        {"Technical Impact": "partial"},
                                    ],
                                    "role": "CISA Coordinator",
                                    "version": "2.0.3",
                                },
                            }
                        }
                    ],
                    "title": "CISA ADP Vulnrichment",
                    "providerMetadata": {
                        "orgId": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                        "shortName": "CISA-ADP",
                        "dateUpdated": "2024-06-11T13:41:52.606Z",
                    },
                },
                {
                    "providerMetadata": {
                        "orgId": "af854a3a-2127-422b-91ae-364da2661108",
                        "shortName": "CVE",
                        "dateUpdated": "2024-08-02T02:59:22.207Z",
                    },
                    "title": "CVE Program Container",
                    "references": [{"url": "https://me.sap.com/notes/3465129", "tags": ["x_transferred"]}],
                },
            ],
        },
    }
    client = _client_with_temp_cache()
    result = client._parse_adp_container("CVE-2024-34686", real_record)
    assert result.automatable is False   # "no" in the real record
    assert result.technical_impact == "partial"
    assert result.in_kev is False  # this particular CVE has no KEV block -- correctly absent, not a parse failure
    assert result.source == "vulnrichment"


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
