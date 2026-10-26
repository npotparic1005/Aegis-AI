"""Offline tests for the new tools — parsing logic only, no network.

Run:  PYTHONPATH=. python tests/test_tools.py
"""

from app.tools.cve_lookup import CveLookupTool
from app.tools.nmap_tool import NmapTool
from app.tools.zap_tool import ZapTool
from app.tools.registry import build_default_registry


def test_registry_has_all_tools():
    reg = build_default_registry()
    names = set(reg.names())
    assert {"nmap", "cve_lookup", "zap"} <= names


def test_full_schema_includes_common_and_tool_specific_fields():
    schema = CveLookupTool().full_schema()
    props = schema["parameters"]["properties"]
    assert {"target", "rationale", "product", "version", "limit"} <= props.keys()
    assert {"target", "rationale", "product"} <= set(schema["parameters"]["required"])


def test_nmap_dedup_key_ignores_params():
    t = NmapTool()
    assert t.dedup_key("10.0.0.5", {"ports": [80]}) == t.dedup_key("10.0.0.5", {"ports": [443]})
    assert t.dedup_key("10.0.0.5", {}) != t.dedup_key("10.0.0.6", {})


def test_cve_dedup_key_keeps_target_evidence_separate():
    t = CveLookupTool()
    key_a = t.dedup_key("host-a", {"product": "nginx", "version": "1.2"})
    key_b = t.dedup_key("host-b", {"product": "nginx", "version": "1.2"})
    assert key_a != key_b


def test_skill_file_loaded_for_every_registered_tool():
    reg = build_default_registry()
    for tool in reg.all():
        assert tool.usage_notes, f"{tool.name} has no skills/{tool.name}.md content loaded"


def test_validate_params_catches_missing_required():
    t = CveLookupTool()
    assert t.validate_params({}) is not None
    assert t.validate_params({"product": "nginx"}) is None


def test_validate_params_catches_bad_enum():
    t = NmapTool()
    assert t.validate_params({"timing": "T9"}) is not None
    assert t.validate_params({"timing": "T4"}) is None


def test_grounding_check_rejects_unseen_product():
    t = CveLookupTool()
    error = t.grounding_check({"product": "Apache HTTP Server", "version": "2.4.41"}, [])
    assert error is not None


def test_grounding_check_accepts_exact_product_match():
    t = CveLookupTool()
    findings = [{"data": {"product": "Microsoft Windows RPC", "service": "msrpc"}}]
    assert t.grounding_check({"product": "Microsoft Windows RPC"}, findings) is None


def test_grounding_check_accepts_documented_product_alias():
    t = CveLookupTool()
    # A documented alias is accepted without allowing arbitrary word overlap.
    findings = [{"data": {"product": "Apache httpd", "service": "http"}}]
    assert t.grounding_check({"product": "Apache HTTP Server"}, findings) is None


def test_grounding_check_not_applicable_to_tools_without_override():
    # Default Tool.grounding_check is a no-op -- nmap/dns_lookup/etc. don't
    # assert a prior discovery, so there's nothing to cross-check.
    t = NmapTool()
    assert t.grounding_check({"ports": [80]}, []) is None


def test_target_applicable_rejects_target_outside_in_scope_domains():
    from app.tools.whois_lookup import WhoisTool

    t = WhoisTool()
    assert t.target_applicable("127.0.0.1", ["localhost"]) is not None
    assert t.target_applicable("example.com", ["localhost"]) is not None


def test_target_applicable_accepts_real_in_scope_domain():
    from app.tools.dns_lookup import DnsLookupTool

    t = DnsLookupTool()
    assert t.target_applicable("localhost", ["localhost"]) is None


def test_target_applicable_not_restricted_by_default():
    # nmap/cve_lookup/http_headers work against any authorized target --
    # only whois/dns_lookup restrict to a real in-scope domain.
    t = NmapTool()
    assert t.target_applicable("127.0.0.1", []) is None


def test_cve_dedup_key_normalizes_whitespace_and_case():
    # Regression: a model re-sending "VMware Authentication Daemon " (a
    # trailing space) or different casing for a product/version it
    # already checked must still be recognized as the same pair.
    t = CveLookupTool()
    key1 = t.dedup_key("127.0.0.1", {"product": "VMware Authentication Daemon", "version": "1.0"})
    key2 = t.dedup_key("127.0.0.1", {"product": "VMware Authentication Daemon ", "version": "1.0"})
    key3 = t.dedup_key("127.0.0.1", {"product": "vmware authentication daemon", "version": "1.0"})
    assert key1 == key2 == key3


def test_nmap_dedup_key_normalizes_target_whitespace_and_case():
    t = NmapTool()
    assert t.dedup_key("Example.COM", {}) == t.dedup_key(" example.com ", {})


def test_default_dedup_key_handles_list_valued_params():
    # Regression: dns_lookup's `types` param is a list, and the default
    # dedup_key used to build a tuple containing that raw list, which
    # crashed with "unhashable type: 'list'" the moment it hit a set.
    from app.tools.dns_lookup import DnsLookupTool

    t = DnsLookupTool()
    key = t.dedup_key("example.com", {"types": ["A", "MX"]})
    {key}  # must be hashable -- raises TypeError if not
    assert key == t.dedup_key("example.com", {"types": ["A", "MX"]})


def test_cve_parse_and_sort():
    sample = {
        "vulnerabilities": [
            {"cve": {
                "id": "CVE-2021-0001",
                "descriptions": [{"lang": "en", "value": "medium issue"}],
                "metrics": {"cvssMetricV31": [{"cvssData":
                            {"baseScore": 5.0, "baseSeverity": "MEDIUM"}}]},
            }},
            {"cve": {
                "id": "CVE-2021-9999",
                "descriptions": [{"lang": "en", "value": "critical issue"}],
                "metrics": {"cvssMetricV31": [{"cvssData":
                            {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
            }},
        ]
    }
    out = CveLookupTool._parse(sample, host="10.0.0.5")
    assert out[0]["cve"] == "CVE-2021-9999"      # critical sorted first
    assert out[0]["severity"] == "CRITICAL"
    assert out[1]["severity"] == "MEDIUM"


def test_cve_preview_no_side_effects():
    t = CveLookupTool()
    prev = t.command_preview("10.0.0.5", product="OpenSSH", version="7.2")
    assert "OpenSSH" in prev and "10.0.0.5" in prev


def test_zap_alert_dedup_and_sort():
    alerts = [
        {"alert": "XSS", "risk": "High", "url": "http://x/a", "confidence": "High"},
        {"alert": "XSS", "risk": "High", "url": "http://x/a", "confidence": "High"},  # dup
        {"alert": "Info leak", "risk": "Low", "url": "http://x/b", "confidence": "Low"},
    ]
    out = ZapTool._parse_alerts(alerts, host="x")
    assert len(out) == 2                # duplicate removed
    assert out[0]["severity"] == "High" # high sorted first


def test_zap_preview_active_flag():
    t = ZapTool()
    assert "ACTIVE" in t.command_preview("10.0.0.5", active=True)
    assert "ACTIVE" not in t.command_preview("10.0.0.5")


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"ok  {name}")
    print("all passed")
