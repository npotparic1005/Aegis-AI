"""Offline evidence regressions: saved Nmap XML and synthetic NVD responses.

No scanner, Ollama, or network requests are made. See fixtures/README.md.
"""

import copy
import json
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
from datetime import date
from pathlib import Path
from unittest.mock import Mock, patch

import requests

from app.agent.executor import Action, Executor
from app.config import Engagement, Scope
from app.cve_matching import classify_cve, exact_cpe_query, numeric_compare
from app.evidence import evidence_recap, planner_finding
from app.memory.audit import AuditLog
from app.memory.database import Database
from app.policy.validator import PolicyValidator
from app.reporting.report import generate_markdown
from app.tools.cve_lookup import CveLookupTool, NVD_ENDPOINT
from app.tools.http_headers import HttpHeadersTool
from app.tools.nmap_tool import NmapTool
from app.tools.registry import ToolRegistry


XML = (Path(__file__).parent / "fixtures/nmap_local_recon.xml").read_text()
OPENSSH_CPE = "cpe:/a:openbsd:openssh:10.3"


def condition(product="openssh", vendor="openbsd", version="*", **bounds):
    return {"vulnerable": True,
            "criteria": f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*", **bounds}


def record(*matches, description="Synthetic advisory.", number="0001", **extra):
    cve = {"id": f"CVE-2026-{number}", "descriptions": [{"lang": "en", "value": description}],
           "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH", "baseScore": 8.1}}]},
           **extra}
    if matches:
        cve["configurations"] = [{"nodes": [{"operator": "OR", "cpeMatch": list(matches)}]}]
    return cve


def response(*cves, total=None, status=200):
    data = {"vulnerabilities": [{"cve": cve} for cve in cves],
            "totalResults": len(cves) if total is None else total}
    return Mock(status_code=status, text=json.dumps(data), json=Mock(return_value=data))


class OfflineTests(unittest.TestCase):
    def setUp(self):
        for name in ("subprocess.run", "requests.sessions.Session.request",
                     "socket.gethostbyname", "socket.getaddrinfo"):
            guard = patch(name, side_effect=AssertionError(f"Unexpected external operation: {name}"))
            guard.start()
            self.addCleanup(guard.stop)
        for name in ("app.tools.cve_lookup.time.sleep", "app.tools.nmap_tool.shutil.which"):
            stub = patch(name, return_value="test-binary")
            stub.start()
            self.addCleanup(stub.stop)


class NmapEvidenceTests(OfflineTests):
    def test_saved_port_3001_is_an_unresolved_label_with_http_evidence(self):
        ports = {f["port"]: f for f in NmapTool._parse_xml(XML)}
        self.assertEqual(set(ports), {2222, 3001, 6379, 8080})
        web = ports[3001]
        self.assertEqual((web["service"], web["service_guess"], web["service_confidence"]),
                         ("unknown", "nessus", 3))
        self.assertEqual(web["identification"], "unresolved")
        self.assertEqual(web["product"], "")
        self.assertTrue(web["http_observed"])
        self.assertEqual(web["http_title"], "OWASP Juice Shop")
        self.assertIn("HTTP/1.1 200 OK", web["http_responses"])
        self.assertIn("port-table guess", web["summary"])
        self.assertGreater(len(web["service_fingerprint"]), len(web["fingerprint_excerpt"]))
        self.assertTrue(web["fingerprint_excerpt_truncated"])
        self.assertEqual(ports[2222]["cpes"], [OPENSSH_CPE])
        self.assertEqual(ports[2222]["service_method"], "probed")
        self.assertEqual(ports[2222]["service_confidence"], 10)

    def test_scripts_tunnel_and_full_outputs_survive_parsing(self):
        root = ET.fromstring(XML)
        port = root.find("./host/ports/port")
        port.find("service").set("tunnel", "ssl")
        ET.SubElement(port, "script", id="test-banner", output="a" * 2000)
        finding = NmapTool._parse_xml(ET.tostring(root, encoding="unicode"))[0]
        self.assertEqual(finding["tunnel"], "ssl")
        self.assertEqual(finding["extra_info"], "protocol 2.0")
        self.assertEqual(len(finding["scripts"][0]["output"]), 2000)
        view = planner_finding(finding)
        self.assertEqual(len(view["script_excerpts"][0]["output"]), 600)
        self.assertNotIn("service_fingerprint", view)
        self.assertEqual(len(finding["scripts"][0]["output"]), 2000)

    def test_invalid_or_incomplete_xml_is_not_a_successful_empty_scan(self):
        for output in ("", "<nmaprun>", "<html/>", "<nmaprun/>",
                       '<nmaprun><runstats><finished exit="error"/></runstats></nmaprun>'):
            with self.subTest(output=output), patch("subprocess.run", return_value=
                    subprocess.CompletedProcess([], 0, output, "")):
                result = NmapTool().run("127.0.0.1")
                self.assertFalse(result.success)
                self.assertEqual(result.error, "invalid_output")

    def test_nonzero_exit_fails_even_with_complete_xml(self):
        with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 1, XML, "error")):
            result = NmapTool().run("127.0.0.1")
        self.assertFalse(result.success)
        self.assertEqual(result.error, "exit_1")

    def test_completed_empty_scan_has_coverage_qualification(self):
        output = '<nmaprun><runstats><finished exit="success"/></runstats></nmaprun>'
        with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, output, "")):
            result = NmapTool().run("127.0.0.1")
        self.assertTrue(result.success)
        self.assertIn("unscanned ports are unknown", result.summary)


class CveMatchingTests(OfflineTests):
    def assess(self, cve, version="10.3", cpes=None):
        return classify_cve(cve, "OpenSSH", version, cpes or [])

    def test_numeric_ordering_and_unknown_vendor_versions(self):
        self.assertEqual(numeric_compare("10.10", "10.9"), 1)
        self.assertEqual(numeric_compare("10.3", "10.3.0"), 0)
        self.assertIsNone(numeric_compare("10.3p1", "10.3"))

    def test_boundaries_and_multiple_affected_branches(self):
        for bound, expected in (("versionEndExcluding", "excluded"),
                                ("versionEndIncluding", "candidate"),
                                ("versionStartExcluding", "excluded"),
                                ("versionStartIncluding", "candidate")):
            with self.subTest(bound=bound):
                self.assertEqual(self.assess(record(condition(**{bound: "10.3"})))["assessment"], expected)
        cve = record(condition(versionEndExcluding="10.1"),
                     condition(versionStartIncluding="10.3", versionEndExcluding="10.4"))
        self.assertEqual(self.assess(cve)["match_basis"], "product_version")

    def test_unknown_range_or_vendor_suffix_remains_unverified(self):
        for version in ("", "10.3p1", "10.0 - 10.3"):
            with self.subTest(version=version):
                verdict = self.assess(record(condition(versionEndExcluding="10.2")), version)
                self.assertEqual(verdict["assessment"], "candidate")
                self.assertEqual(verdict["match_basis"], "product_only")

    def test_description_bound_can_exclude_but_not_confirm(self):
        cve = record(description="OpenSSH before 10.3 allows a synthetic condition.")
        self.assertEqual(self.assess(cve)["match_basis"], "description_version_mismatch")
        self.assertEqual(self.assess(cve, "10.2")["match_basis"], "keyword_only")

    def test_description_with_disjoint_branches_is_not_excluded(self):
        cve = record(description="OpenSSH before 10.1 and versions 10.3 through 10.4 are affected.")
        self.assertEqual(self.assess(cve)["assessment"], "candidate")

    def test_wildcard_cpe_does_not_hide_explicit_description_limit(self):
        cve = record(condition(), description="OpenSSH through 10.0 is affected under specific conditions.")
        verdict = self.assess(cve, cpes=[OPENSSH_CPE])
        self.assertEqual(verdict["assessment"], "excluded")
        self.assertEqual(verdict["match_basis"], "description_version_mismatch")
        self.assertEqual(self.assess(cve, "10.0")["assessment"], "candidate")

    def test_description_does_not_override_explicit_or_complex_conditions(self):
        text = "OpenSSH through 10.0 is affected."
        explicit = record(condition(versionEndExcluding="10.4"), description=text)
        self.assertEqual(self.assess(explicit)["match_basis"], "product_version")
        suffixed = record(condition(versionEndExcluding="10.4p1"), description=text)
        self.assertEqual(self.assess(suffixed)["match_basis"], "product_only")
        branches = record(condition(), description="OpenSSH through 10.0 and 10.3 are affected.")
        self.assertEqual(self.assess(branches)["assessment"], "candidate")
        negated = record(condition(), description=text)
        negated["configurations"][0]["negate"] = True
        self.assertEqual(self.assess(negated)["match_basis"], "unverified_configuration")

    def test_product_cpe_overrides_keyword_mentions(self):
        cve = record(condition(product="mac_os_x", vendor="apple", version="10.3"),
                     description="An Apple operating system bundles OpenSSH.")
        self.assertEqual(self.assess(cve)["match_basis"], "product_mismatch")
        middleware = record(condition(product="express-session", vendor="expressjs", version="1.0"))
        self.assertEqual(classify_cve(middleware, "Express", "1.0", [])["assessment"], "excluded")

    def test_vendor_alias_and_complex_cpe_remain_unknown(self):
        cve = record(condition(vendor="another_vendor", version="10.3"))
        self.assertEqual(self.assess(cve, cpes=[OPENSSH_CPE])["assessment"], "candidate")
        cve = record({"vulnerable": True, "criteria": "cpe:2.3:a:vendor:escaped\\:name:*:*:*:*:*:*:*:*"})
        self.assertEqual(self.assess(cve)["match_basis"], "unverified_configuration")

    def test_platform_prerequisites_never_become_confirmed_vulnerabilities(self):
        cve = record(condition(version="10.3"), {**condition(product="platform"), "vulnerable": False})
        cve["configurations"][0]["operator"] = "AND"
        verdict = self.assess(cve)
        self.assertEqual(verdict["assessment"], "candidate")
        self.assertIn("prerequisites are not verified", verdict["reason"])
        cve["configurations"][0]["negate"] = True
        self.assertEqual(self.assess(cve)["match_basis"], "unverified_configuration")
        self.assertEqual(self.assess(record({**condition(), "vulnerable": False}))["assessment"], "candidate")

    def test_rejected_advisory_is_excluded(self):
        self.assertEqual(self.assess(record(vulnStatus="Rejected"))["match_basis"], "rejected_record")

    def test_exact_cpe_conversion_requires_unambiguous_application(self):
        self.assertEqual(exact_cpe_query([OPENSSH_CPE]),
                         "cpe:2.3:a:openbsd:openssh:10.3:*:*:*:*:*:*:*")
        for cpes in (["cpe:/o:linux:linux_kernel"], ["cpe:/a:openbsd:openssh"],
                     [OPENSSH_CPE, "cpe:/a:openbsd:openssh:10.2"]):
            self.assertIsNone(exact_cpe_query(cpes))


class CveLookupTests(OfflineTests):
    def test_exact_cpe_query_filters_candidates_and_records_coverage(self):
        possible = record(condition(version="10.3"), number="0001")
        excluded = record(condition(versionEndExcluding="10.3"), number="0002")
        with patch("requests.get", return_value=response(possible, excluded, total=30)) as get:
            result = CveLookupTool().run("127.0.0.1", product="OpenSSH", version="10.3",
                                        _evidence={"cpes": [OPENSSH_CPE]})
        self.assertTrue(result.success)
        params = get.call_args.kwargs["params"]
        self.assertIn("cpeName", params)
        self.assertIn("isVulnerable", params)
        self.assertNotIn("keywordSearch", params)
        lookup, candidate = result.findings
        self.assertEqual((lookup["candidate_count"], lookup["excluded_count"]), (1, 1))
        self.assertTrue(lookup["searches"][0]["truncated"])
        self.assertEqual(lookup["searches"][0]["reviewed"], 2)
        self.assertEqual(lookup["excluded_matches"][0]["cve"], excluded["id"])
        self.assertEqual(candidate["cve"], possible["id"])
        self.assertIn("unverified", candidate["summary"])
        self.assertEqual(candidate["configurations"], possible["configurations"])
        self.assertTrue(lookup["retrieved_at"])

    def test_cpe_empty_or_rejected_falls_back_once_and_preserves_zero_result(self):
        for first in (response(), response(status=400)):
            with self.subTest(status=first.status_code), patch("requests.get", side_effect=[first, response()]) as get:
                result = CveLookupTool().run("127.0.0.1", product="OpenSSH",
                                            _evidence={"cpes": [OPENSSH_CPE], "version": "10.3"})
            self.assertEqual(get.call_count, 2)
            self.assertEqual(get.call_args.kwargs["params"]["keywordSearch"], "openssh 10.3")
            self.assertTrue(result.success)
            self.assertEqual(len(result.findings), 1)
            self.assertEqual(len(result.findings[0]["searches"]), 2)
            self.assertEqual(result.findings[0]["candidate_count"], 0)
            self.assertIn("zero candidates does not establish absence", result.summary)

    def test_range_banner_is_not_queried_as_an_exact_version(self):
        tool = CveLookupTool()
        with patch("requests.get", return_value=response()) as get:
            tool.run("127.0.0.1", product="Redis key-value store", version="7.0 - 8.0")
        self.assertEqual(get.call_args.kwargs["params"]["keywordSearch"], "redis")
        self.assertIn("keyword='redis'", tool.command_preview("127.0.0.1", product="Redis key-value store", version="7.0 - 8.0"))

    def test_failures_are_not_zero_candidate_successes(self):
        malformed = Mock(status_code=200, text="bad", json=Mock(side_effect=ValueError("bad JSON")))
        invalid_record = response({})
        for resp, error in ((response(status=429), "http_429"), (malformed, "invalid_response"),
                            (invalid_record, "invalid_response"), (response(record(), total=0), "invalid_response")):
            with self.subTest(error=error), patch("requests.get", return_value=resp):
                result = CveLookupTool().run("127.0.0.1", product="OpenSSH")
            self.assertFalse(result.success)
            self.assertEqual(result.error, error)
            self.assertEqual(result.findings, [])
        with patch("requests.get", side_effect=requests.ConnectionError("offline")):
            self.assertEqual(CveLookupTool().run("127.0.0.1", product="OpenSSH").error, "request_failed")

    def test_grounding_uses_observations_from_the_requested_target(self):
        tool = CveLookupTool()
        findings = [{"data": f} for f in NmapTool._parse_xml(XML)]
        self.assertIsNone(tool.grounding_check({"product": "OpenSSH", "version": "10.3"}, findings, "127.0.0.1"))
        for params, target in (({"product": "OpenSSH", "version": "10.2"}, "127.0.0.1"),
                               ({"product": "OpenSSH"}, "127.0.0.2"),
                               ({"product": "nessus"}, "127.0.0.1"),
                               ({"product": "OWASP Juice Shop"}, "127.0.0.1")):
            self.assertIsNotNone(tool.grounding_check(params, findings, target))
        prior = [{"data": {"host": "127.0.0.1", "product": "Microsoft Windows RPC"}}]
        self.assertIsNotNone(tool.grounding_check({"product": "Microsoft IIS"}, prior, "127.0.0.1"))
        self.assertIsNotNone(tool.validate_params({"product": "OpenSSH", "_evidence": {"cpes": [OPENSSH_CPE]}}))

    def test_cve_records_cannot_ground_new_queries(self):
        tool = CveLookupTool()
        for kind in ("cve_lookup", "cve_candidate", "cve_excluded"):
            finding = {"kind": kind, "host": "127.0.0.1", "product": "OpenSSH", "cve": "CVE-2026-0001"}
            self.assertIsNotNone(tool.grounding_check({"product": "OpenSSH"}, [finding], "127.0.0.1"))

    def test_ambiguous_observed_versions_do_not_choose_one(self):
        services = NmapTool._parse_xml(XML)
        other = {**services[0], "version": "10.2", "cpes": ["cpe:/a:openbsd:openssh:10.2"]}
        context = CveLookupTool().execution_context("127.0.0.1", {"product": "OpenSSH"}, services + [other])
        self.assertEqual(context["_evidence"]["version"], "")
        self.assertEqual(context["_evidence"]["cpes"], [])


class HttpEvidenceTests(OfflineTests):
    def test_timeout_and_tls_failure_preserve_uncertainty(self):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("curl", 20)):
            result = HttpHeadersTool().run("127.0.0.1", port=3001)
        self.assertFalse(result.success)
        self.assertEqual(result.error, "timeout")
        self.assertIn("undetermined", result.summary)
        with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 35, "HTTP/1.1 200 Connection established\n", "TLS failed")):
            result = HttpHeadersTool().run("127.0.0.1", port=3001, scheme="https")
        self.assertFalse(result.success)
        self.assertEqual(result.error, "curl_exit_35")
        self.assertIn("does not establish absence", result.summary)

    def test_http_404_is_a_response_with_endpoint_provenance(self):
        with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, "HTTP/1.1 404 Not Found\nServer: demo\n", "")):
            result = HttpHeadersTool().run("127.0.0.1", port=3001)
        self.assertTrue(result.success)
        self.assertIn("404", result.summary)
        self.assertEqual(result.findings[0]["url"], "http://127.0.0.1:3001/")

    def test_empty_output_is_not_http_success(self):
        with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, "", "")):
            self.assertEqual(HttpHeadersTool().run("127.0.0.1").error, "invalid_output")


class EvidencePersistenceTests(OfflineTests):
    def test_executor_preserves_evidence_and_report_separates_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(":memory:")
            self.addCleanup(db.close)
            session = db.create_session("offline", "offline")
            scope = Scope(
                engagement=Engagement("test", "self", "lab", date(2000, 1, 1), date(2100, 1, 1)),
                in_scope_hosts=["127.0.0.1"], in_scope_domains=["lab.test"],
                out_of_scope_hosts=[], out_of_scope_domains=[], allowed_tools=["nmap", "cve_lookup"],
                max_concurrent_actions=1, allowed_ports=[], block_destructive=True,
            )
            registry = ToolRegistry()
            registry.register(NmapTool())
            registry.register(CveLookupTool())
            executor = Executor(registry, PolicyValidator(scope), db, AuditLog(f"{tmp}/audit.log"),
                                session.id, require_confirmation=False)
            with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, XML, "")):
                result = executor.execute(Action("nmap", "lab.test", {}, "Read saved XML"))
            self.assertTrue(result.success)
            possible = record(condition(version="10.3"), number="0001", description="Full description " + "x" * 1800)
            excluded = record(condition(versionEndExcluding="10.3"), number="0002")
            with patch("requests.get", return_value=response(possible, excluded)) as get:
                result = executor.execute(Action("cve_lookup", "lab.test", {"product": "OpenSSH"}, "Enrich observed version"))
                repeated = executor.execute(Action("cve_lookup", "lab.test", {"product": "OpenSSH", "version": "10.3"}, "Repeat"))
            self.assertTrue(result.success)
            self.assertEqual(repeated.error, "duplicate")
            self.assertEqual(get.call_count, 1)
            with patch("requests.get", return_value=response()):
                result = executor.execute(Action("cve_lookup", "lab.test", {"product": "Redis key-value store"}, "Empty lookup"))
            self.assertTrue(result.success)
            findings = db.get_findings(session.id)
            web = next(f["data"] for f in findings if f["data"].get("port") == 3001)
            self.assertEqual(web["target"], "lab.test")
            self.assertEqual(web["host"], "127.0.0.1")
            self.assertEqual(web["source_tool"], "nmap")
            self.assertEqual(web["service_fingerprint"], NmapTool._parse_xml(XML)[1]["service_fingerprint"])
            recap = evidence_recap(findings)
            self.assertEqual(len(recap["services_discovered"]), 4)
            self.assertEqual(len(recap["cve_lookups"]), 2)
            self.assertTrue(any(s["port"] == 3001 and s["identification"] == "unresolved" for s in recap["services_discovered"]))
            candidate = next(f["data"] for f in findings if f["data"].get("kind") == "cve_candidate")
            original = copy.deepcopy(candidate)
            view = planner_finding(candidate)
            self.assertNotIn("configurations", view)
            self.assertTrue(view["description_excerpt_truncated"])
            self.assertEqual(candidate, original)
            report = Path(generate_markdown(db, scope, session.id, tmp)).read_text()
            self.assertIn("Candidate [CVE-2026-0001]", report)
            self.assertIn("Excluded [CVE-2026-0002]", report)
            self.assertNotIn("Candidate [CVE-2026-0002]", report)
            self.assertIn(NVD_ENDPOINT, report)
            self.assertIn("zero candidates does not establish absence", report)
            self.assertIn("OWASP Juice Shop", report)
            self.assertIn(possible["descriptions"][0]["value"], report)


if __name__ == "__main__":
    unittest.main()
