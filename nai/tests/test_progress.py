"""Offline regressions for coverage, explicit stopping, and factual summaries."""

import copy
import json
import sqlite3
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest.mock import Mock, patch

from app.agent.executor import Action, Executor
from app.agent.loop import AgentLoop
from app.agent.progress import completion_error, completion_schema, investigation_state, render_inventory
from app.agent.intent import RunIntent
from app.config import Engagement, Scope
from app.llm.client import LLMError, PlanResponse, ToolCall
from app.memory.audit import AuditLog
from app.memory.database import Database
from app.policy.validator import PolicyValidator
from app.reporting.report import generate_markdown
from app.tools.base import ToolResult
from app.tools.cve_lookup import CveLookupTool
from app.tools.dns_lookup import DnsLookupTool
from app.tools.http_headers import HttpHeadersTool
from app.tools.nmap_tool import NmapTool
from app.tools.registry import ToolRegistry
from app.tools.whois_lookup import WhoisTool


FIXTURE = (Path(__file__).parent / "fixtures/nmap_local_recon.xml").read_text()


def call(name, **params):
    return PlanResponse([ToolCall("test-call", name, params)])


class ProgressTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Database(":memory:")
        self.addCleanup(self.db.close)
        self.session = self.db.create_session("test", "test")
        self.scope = Scope(
            engagement=Engagement("test", "self", "lab", date(2000, 1, 1), date(2100, 1, 1)),
            in_scope_hosts=["127.0.0.1", "127.0.0.2"], in_scope_domains=["example.test"],
            out_of_scope_hosts=[], out_of_scope_domains=[],
            allowed_tools=["nmap", "http_headers", "cve_lookup", "dns_lookup", "whois"],
            max_concurrent_actions=1, allowed_ports=[], block_destructive=True,
        )
        self.registry = ToolRegistry()
        for tool in (NmapTool(), HttpHeadersTool(), CveLookupTool(), DnsLookupTool(), WhoisTool()):
            tool.run = Mock(side_effect=AssertionError("Unexpected unconfigured tool execution"))
            self.registry.register(tool)
        self.registry.get("nmap").run.side_effect = lambda target, **params: ToolResult(
            "nmap", target, True, "4 open ports in the saved capture.", findings=NmapTool._parse_xml(FIXTURE))
        self.registry.get("http_headers").run.side_effect = lambda target, **params: ToolResult(
            "http_headers", target, True, "HTTP/1.1 200 OK", findings=[])
        self.registry.get("cve_lookup").run.side_effect = self.fake_lookup
        self.executor = Executor(self.registry, PolicyValidator(self.scope), self.db,
                                 AuditLog(f"{self.tmp.name}/audit.log"), self.session.id,
                                 require_confirmation=False)
        for name in ("subprocess.run", "requests.sessions.Session.request",
                     "socket.gethostbyname", "socket.getaddrinfo"):
            guard = patch(name, side_effect=AssertionError(f"Unexpected external operation: {name}"))
            guard.start()
            self.addCleanup(guard.stop)

    @staticmethod
    def fake_lookup(target, **params):
        evidence = params.get("_evidence", {})
        finding = {"kind": "cve_lookup", "host": target, "product": params["product"],
                   "version": params.get("version") or evidence.get("version", ""),
                   "observed_services": evidence.get("services", []), "candidate_count": 0, "excluded_count": 0,
                   "searches": [{"query": {"keywordSearch": params["product"]}, "status": 200,
                                 "reviewed": 0, "total_results": 0, "truncated": False}],
                   "summary": "Synthetic empty lookup; no vulnerability applicability verified.",
                   "coverage_note": "Bounded synthetic lookup", "source": "https://example.test/nvd",
                   "retrieved_at": "2026-09-16T00:00:00+00:00", "excluded_matches": []}
        return ToolResult("cve_lookup", target, True, finding["summary"], findings=[finding])

    def execute(self, tool, target="127.0.0.1", **params):
        return self.executor.execute(Action(tool, target, params))

    def state(self, targets=None):
        tools = [name for name in self.scope.allowed_tools
                 if self.executor.run_tools is None or name in self.executor.run_tools]
        return investigation_state(self.db.get_findings(self.session.id), self.db.get_actions(self.session.id),
                                   targets or ["127.0.0.1"], tools)

    def finish_current(self):
        return call("finish_recon", reason="objective_addressed",
                    deferred_checks=[item["id"] for item in self.state()["pending_checks"]])

    def run_script(self, responses, objective="Reconnaissance of 127.0.0.1", limit=15,
                   intent_tools=None, interpretation_responses=None):
        responses = iter(responses)
        interpretations = iter(interpretation_responses) if interpretation_responses is not None else None
        offered = []

        def plan(system, schemas, turns):
            if schemas[0]["name"] == "interpret_objective":
                if interpretations is not None:
                    response = next(interpretations)
                    if isinstance(response, Exception):
                        raise response
                    return response
                # Script the model's interpretation explicitly; never parse test prompts.
                names = [tool["name"] for tool in json.loads(turns[0].content)["available_tools"]]
                return call("interpret_objective", goal="Scripted reconnaissance goal",
                            allowed_tools=names if intent_tools is None else intent_tools,
                            restriction_reason="" if intent_tools is None else "Scripted user restriction")
            offered.append(copy.deepcopy(schemas))
            response = next(responses)
            if isinstance(response, Exception):
                raise response
            return response() if callable(response) else response

        llm = Mock()
        llm.plan.side_effect = plan
        loop = AgentLoop(llm, self.registry, self.executor, self.db, self.scope, self.session.id, limit)
        events = []
        result = loop.run(objective, lambda kind, payload: events.append((kind, payload)))
        return result, events, offered, llm

    def test_unperformed_failed_and_successful_checks_remain_distinct(self):
        self.execute("nmap")
        self.registry.get("cve_lookup").run.side_effect = lambda target, **params: ToolResult(
            "cve_lookup", target, False, "NVD unavailable", error="http_429")
        self.execute("cve_lookup", product="OpenSSH")
        self.execute("http_headers", port=3001)
        ports = {s["port"]: s for s in self.state()["services"]}
        self.assertEqual(ports[2222]["cve"]["status"], "failed")
        self.assertEqual(ports[3001]["http"]["status"], "checked")
        self.assertEqual(ports[8080]["http"]["status"], "not_assessed")
        self.assertEqual(ports[6379]["cve"]["status"], "not_assessed")
        summary = render_inventory(self.state())
        self.assertIn("lookup not performed", summary)
        self.assertIn("no successful lookup evidence", summary)
        self.assertNotIn("No known vulnerabilities", summary)

    def test_rejections_and_declines_do_not_count_as_checks(self):
        self.execute("nmap")
        self.executor.require_confirmation = True
        self.executor.confirm_fn = lambda *_: False
        self.assertIsNone(self.execute("cve_lookup", product="OpenSSH"))
        self.assertEqual(self.execute("cve_lookup", product="Invented").error, "ungrounded")
        ssh = self.state()["services"][0]
        self.assertEqual(ssh["cve"]["status"], "not_assessed")
        self.assertEqual(ssh["cve"]["action_ids"], [])

    def test_lookup_coverage_does_not_transfer_between_targets_or_versions(self):
        self.execute("nmap")
        original = NmapTool._parse_xml(FIXTURE)[0]
        for target, port, version in (("127.0.0.2", 2222, "10.3"), ("127.0.0.1", 2223, "10.2")):
            service = {**original, "target": target, "host": target, "port": port, "version": version}
            self.db.add_finding(self.session.id, None, target, "SSH", service)
        self.execute("cve_lookup", product="OpenSSH", version="10.3")
        states = {(s["target"], s["port"]): s["cve"]["status"] for s in self.state()["services"]}
        self.assertEqual(states[("127.0.0.1", 2222)], "checked")
        self.assertEqual(states[("127.0.0.1", 2223)], "not_assessed")
        self.assertEqual(states[("127.0.0.2", 2222)], "not_assessed")

    def test_empty_lookup_is_checked_but_never_a_clean_bill_of_health(self):
        self.execute("nmap")
        self.execute("cve_lookup", product="OpenSSH")
        state = self.state()
        self.assertEqual(state["services"][0]["cve"]["status"], "checked")
        self.assertIn("0 unverified candidate(s)", render_inventory(state))
        self.assertIn("do not establish absence", render_inventory(state))

    def test_success_without_structured_lookup_evidence_is_incomplete(self):
        self.execute("nmap")
        self.registry.get("cve_lookup").run.side_effect = lambda target, **params: ToolResult(
            "cve_lookup", target, True, "Lookup returned no structured evidence")
        self.execute("cve_lookup", product="OpenSSH")
        self.assertEqual(self.state()["services"][0]["cve"]["status"], "incomplete")
        self.assertIn("attempted, but structured lookup evidence is missing", render_inventory(self.state()))

    def test_http_failure_does_not_assess_other_ports(self):
        self.execute("nmap")
        self.registry.get("http_headers").run.side_effect = lambda target, **params: ToolResult(
            "http_headers", target, False, "TLS failed", error="curl_exit_35")
        self.execute("http_headers", port=3001, scheme="https")
        ports = {s["port"]: s for s in self.state()["services"]}
        self.assertEqual(ports[3001]["http"]["status"], "failed")
        self.assertEqual(ports[8080]["http"]["status"], "not_assessed")

    def test_ip_only_run_hides_domain_tools_but_executor_still_rejects_them(self):
        _, _, offered, _ = self.run_script([
            call("http_headers", target="127.0.0.1", port=8080), self.finish_current,
        ])
        names = {s["name"] for s in offered[0]}
        self.assertNotIn("dns_lookup", names)
        self.assertNotIn("whois", names)
        self.assertIn("nmap", names)
        self.assertEqual(self.execute("dns_lookup", types=["A"]).error, "tool_not_requested")
        # Target applicability remains an independent gate without intent permissions.
        self.executor.run_tools = None
        self.assertEqual(self.execute("dns_lookup", types=["A"]).error, "target_not_applicable")

    def test_mixed_target_schemas_limit_domain_tools_to_domains(self):
        schemas = self.registry.enabled_schemas(self.scope, ["127.0.0.1", "example.test"])
        targets = {s["name"]: s["parameters"]["properties"]["target"]["enum"] for s in schemas}
        self.assertEqual(targets["dns_lookup"], ["example.test"])
        self.assertEqual(targets["whois"], ["example.test"])
        self.assertEqual(targets["nmap"], ["127.0.0.1", "example.test"])
        # Building a scoped schema must not mutate future schemas.
        self.assertNotIn("enum", self.registry.get("dns_lookup").full_schema()["parameters"]["properties"]["target"])

    def test_session_nine_pattern_gets_review_and_can_continue(self):
        bogus = "No known vulnerabilities were found for Redis or nginx."
        result, events, _, llm = self.run_script([
            call("nmap", target="127.0.0.1", ports=[2222, 3001, 6379, 8080]),
            call("cve_lookup", product="OpenSSH", version="10.3"),
            call("http_headers", port=3001),
            PlanResponse(text=bogus),
            call("http_headers", port=8080),
            self.finish_current,
        ])
        self.assertTrue(result)
        self.assertEqual(self.registry.get("http_headers").run.call_count, 2)
        summary = events[-1][1]
        self.assertNotIn(bogus, summary)
        self.assertIn("Redis key-value store 8.10.1", summary)
        self.assertIn("lookup not performed", summary)
        self.assertIn("OWASP Juice Shop", summary)
        self.assertEqual(summary, self.db.get_conclusion(self.session.id)["summary"])
        history = llm.plan.call_args.args[2]
        reviews = [json.loads(t.content) for t in history if t.kind == "user" and t.content.startswith("{")]
        self.assertIn("completion_error", reviews[0])
        self.assertIn("127.0.0.1/tcp/8080/http", [x["id"] for x in reviews[0]["session_status"]["investigation"]["pending_checks"]])
        report = Path(generate_markdown(self.db, self.scope, self.session.id, self.tmp.name)).read_text()
        self.assertIn(summary, report)
        self.assertNotIn(bogus, report)

    def test_nmap_only_run_does_not_create_unrequested_followup_checks(self):
        result, _, _, _ = self.run_script([
            call("nmap", target="127.0.0.1", ports=[2222, 3001, 6379, 8080]), self.finish_current,
        ], objective="Only run Nmap on 127.0.0.1 to identify services.", intent_tools=["nmap"])
        self.assertTrue(result)
        self.registry.get("cve_lookup").run.assert_not_called()
        self.registry.get("http_headers").run.assert_not_called()
        conclusion = self.db.get_conclusion(self.session.id)
        self.assertEqual(conclusion["decision"]["deferred_checks"], [])
        self.assertNotIn("CVE", conclusion["summary"])
        self.assertNotIn("HTTP headers", conclusion["summary"])

    def test_http_can_be_first_and_only_investigative_tool(self):
        result, events, _, _ = self.run_script([
            call("http_headers", target="127.0.0.1", port=8080), self.finish_current,
        ], objective="Inspect headers on http://127.0.0.1:8080/")
        self.assertTrue(result)
        self.registry.get("nmap").run.assert_not_called()
        self.assertIn("127.0.0.1:8080/tcp: http", events[-1][1])

    def test_only_nmap_is_enforced_without_redundant_negative_instructions(self):
        result, events, offered, _ = self.run_script([
            call("nmap", target="127.0.0.1", ports=[2222, 3001, 6379, 8080]),
            call("cve_lookup", product="OpenSSH", version="10.3"),
            call("http_headers", port=3001),
            call("finish_recon"),
        ], objective="Use only Nmap to identify services on 127.0.0.1 ports 2222, 3001, 6379, and 8080.", intent_tools=["nmap"])
        self.assertTrue(result)
        self.assertEqual({s["name"] for s in offered[0]}, {"nmap", "finish_recon"})
        for schemas in offered[1:]:
            self.assertEqual({s["name"] for s in schemas}, {"finish_recon"})
        self.registry.get("cve_lookup").run.assert_not_called()
        self.registry.get("http_headers").run.assert_not_called()
        rejections = [r for kind, r in events if kind == "result" and r.error == "tool_not_requested"]
        self.assertEqual(len(rejections), 2)
        self.assertEqual(self.db.get_run_context(self.session.id)["intent"]["allowed_tools"], ["nmap"])
        self.assertNotIn("Checks left", events[-1][1])

    def test_http_only_can_finish_with_natural_reason_without_enum_retry(self):
        result, events, offered, llm = self.run_script([
            call("http_headers", target="127.0.0.1", port=3001),
            call("finish_recon", reason="HTTP headers collected successfully."),
        ], objective="Collect only the HTTP response headers from http://127.0.0.1:3001/.", intent_tools=["http_headers"])
        self.assertTrue(result)
        self.assertEqual(llm.plan.call_count, 3)  # Interpretation, HTTP, finish; no completion retry.
        self.assertEqual({s["name"] for s in offered[0]}, {"http_headers", "finish_recon"})
        self.assertFalse(any(kind == "warning" and "Closing prose" in value for kind, value in events))
        self.assertNotIn("CVE", events[-1][1])
        self.assertNotIn("Vulnerability", events[-1][1])
        self.assertNotIn("not assessed", events[-1][1])

    def test_http_interpretation_without_explanation_needs_no_retry(self):
        interpretation = call("interpret_objective", goal="Collect only HTTP response headers",
                              allowed_tools=["http_headers"], restriction_reason="")
        result, events, offered, llm = self.run_script([
            call("http_headers", target="127.0.0.1", port=3001), PlanResponse(text="Finished"),
        ], objective="Collect only HTTP response headers from http://127.0.0.1:3001/.",
           interpretation_responses=[interpretation])
        self.assertTrue(result)
        self.assertEqual(llm.plan.call_count, 3)
        self.assertFalse(any(kind == "warning" and "interpretation" in value for kind, value in events))
        self.assertTrue(all({s["name"] for s in schemas} == {"http_headers", "finish_recon"} for schemas in offered))
        recorded = self.db.get_run_context(self.session.id)["intent"]
        self.assertTrue(recorded["tool_choice_restricted"])
        self.assertEqual(recorded["restriction_reason"], "")
        report = Path(generate_markdown(self.db, self.scope, self.session.id, self.tmp.name)).read_text()
        self.assertNotIn("Tool choice remains open", report)
        self.assertIn("Explanation not supplied", report)

    def test_nmap_exhausted_target_is_not_offered_again(self):
        result, _, offered, llm = self.run_script([
            call("nmap", target="127.0.0.1", ports=[2222, 3001, 6379, 8080]), call("finish_recon"),
        ], intent_tools=["nmap"])
        self.assertTrue(result)
        self.assertEqual({s["name"] for s in offered[1]}, {"finish_recon"})
        self.assertEqual(self.registry.get("nmap").run.call_count, 1)
        history = llm.plan.call_args.args[2]
        result_context = json.loads(next(turn.content for turn in history if turn.kind == "tool_result"))
        self.assertEqual(result_context["session_status"]["currently_available_targets"], {})
        self.assertEqual(result_context["session_status"]["intent"]["allowed_tools"], ["nmap"])
        self.assertNotIn("deferred_checks", offered[1][0]["parameters"]["properties"])

    def test_nmap_other_targets_remain_available_until_executed(self):
        result, _, offered, _ = self.run_script([
            call("nmap", target="127.0.0.1"), call("nmap", target="127.0.0.2"), call("finish_recon"),
        ], objective="Use only Nmap on 127.0.0.1 and 127.0.0.2", intent_tools=["nmap"])
        self.assertTrue(result)
        first = next(s for s in offered[0] if s["name"] == "nmap")
        second = next(s for s in offered[1] if s["name"] == "nmap")
        self.assertEqual(first["parameters"]["properties"]["target"]["enum"], ["127.0.0.1", "127.0.0.2"])
        self.assertEqual(second["parameters"]["properties"]["target"]["enum"], ["127.0.0.2"])
        self.assertEqual({s["name"] for s in offered[2]}, {"finish_recon"})

    def test_rejected_or_declined_nmap_does_not_exhaust_target(self):
        self.assertEqual(self.execute("nmap", ports="invalid").error, "invalid_params")
        self.assertFalse(self.executor.target_exhausted("nmap", "127.0.0.1"))
        self.executor.require_confirmation = True
        self.executor.confirm_fn = lambda *_: False
        self.assertIsNone(self.execute("nmap"))
        self.assertFalse(self.executor.target_exhausted("nmap", "127.0.0.1"))
        self.executor.confirm_fn = lambda *_: True
        result, _, offered, _ = self.run_script([call("nmap", target="127.0.0.1"), call("finish_recon")],
                                               intent_tools=["nmap"])
        self.assertTrue(result)
        self.assertIn("nmap", {s["name"] for s in offered[0]})

    def test_failed_nmap_is_exhausted_but_is_not_reported_as_success(self):
        self.registry.get("nmap").run.side_effect = lambda target, **params: ToolResult(
            "nmap", target, False, "Synthetic timeout", error="timeout")
        result, events, offered, _ = self.run_script([
            call("nmap", target="127.0.0.1"), self.finish_current,
        ], intent_tools=["nmap"])
        self.assertFalse(result)
        self.assertEqual({s["name"] for s in offered[1]}, {"finish_recon"})
        self.assertIn("Failed executed actions", events[-1][1])
        self.assertIn("No successful tool result", events[-1][1])

    def test_session_21_invalid_parameters_still_rejected_and_empty_coverage_finishes(self):
        # Script the bad call even though it is no longer offered, to verify
        # the executor remains authoritative. The rejected finish IDs were not
        # stored in session 21; this nonempty list is a synthetic equivalent.
        result, events, offered, llm = self.run_script([
            call("nmap", target="127.0.0.1", ports=[2222, 3001, 6379, 8080]),
            call("nmap", target="127.0.0.1", http_headers=True, script_category="discovery",
                 ports=[3001], service_detection=False),
            call("finish_recon", deferred_checks=["unrequested-http-check"]),
        ], intent_tools=["nmap"])
        self.assertTrue(result)
        self.assertEqual(llm.plan.call_count, 4)
        errors = [value.error for kind, value in events if kind == "result" and value]
        self.assertIn("invalid_params", errors)
        self.assertNotIn("invalid_completion", errors)
        self.assertEqual(self.registry.get("nmap").run.call_count, 1)
        self.assertEqual({s["name"] for s in offered[-1]}, {"finish_recon"})
        conclusion = self.db.get_conclusion(self.session.id)
        self.assertEqual(conclusion["decision"]["deferred_checks"], [])
        self.assertEqual(conclusion["decision"]["ignored_deferred_checks"], ["unrequested-http-check"])
        self.assertNotIn("unrequested-http-check", conclusion["summary"])
        self.assertNotIn("CVE", conclusion["summary"])

    def test_narrow_run_accepts_plain_stop_without_publishing_model_claims(self):
        result, events, _, llm = self.run_script([
            call("http_headers", target="127.0.0.1", port=3001),
            PlanResponse(text="No vulnerabilities exist. Everything is safe."),
        ], objective="Collect only HTTP headers from http://127.0.0.1:3001/.", intent_tools=["http_headers"])
        self.assertTrue(result)
        self.assertEqual(llm.plan.call_count, 3)
        self.assertFalse(any(kind == "warning" and "Closing prose" in value for kind, value in events))
        self.assertNotIn("Everything is safe", events[-1][1])
        self.assertIn("HTTP headers: checked", events[-1][1])

    def test_restricted_run_still_needs_successful_results_before_plain_stop(self):
        result, events, _, _ = self.run_script([
            PlanResponse(text="Done"), PlanResponse(text="Done"), PlanResponse(text="Done"),
        ], objective="Use only Nmap on 127.0.0.1", intent_tools=["nmap"])
        self.assertFalse(result)
        self.registry.get("nmap").run.assert_not_called()
        self.assertIn("No successful tool result", events[-1][1])

    def test_explicitly_disabled_tools_are_not_reenabled_by_tool_restrictions(self):
        self.scope.allowed_tools = ["http_headers"]
        invalid = call("interpret_objective", goal="Use Nmap", allowed_tools=["nmap"],
                       restriction_reason="User requests only Nmap")
        result, _, _, llm = self.run_script([], objective="Use only Nmap on 127.0.0.1",
                                          interpretation_responses=[invalid] * 3)
        self.assertFalse(result)
        self.assertEqual(llm.plan.call_count, 3)
        self.assertEqual(llm.plan.call_args.args[1][0]["parameters"]["properties"]["allowed_tools"]["items"]["enum"],
                         ["http_headers"])
        self.registry.get("nmap").run.assert_not_called()

    def test_actual_checks_are_not_hidden_by_display_filter(self):
        self.execute("nmap")
        self.execute("cve_lookup", product="OpenSSH")
        state = investigation_state(self.db.get_findings(self.session.id), self.db.get_actions(self.session.id),
                                   ["127.0.0.1"], ["nmap"])
        self.assertIn("CVE enrichment: checked", render_inventory(state))
        self.assertNotIn("CVE enrichment: not assessed", render_inventory(state))

    def test_interpretation_receives_objective_and_is_preserved_for_planner_and_report(self):
        objective = "Just retrieve the web response metadata at http://127.0.0.1:3001/."
        interpretation = call("interpret_objective", goal="Collect response headers from port 3001",
                              allowed_tools=["http_headers"], restriction_reason="Only web response metadata was requested")
        result, events, _, llm = self.run_script([
            call("http_headers", target="127.0.0.1", port=3001), call("finish_recon"),
        ], objective=objective, interpretation_responses=[interpretation])
        self.assertTrue(result)
        first_call = llm.plan.call_args_list[0]
        context = json.loads(first_call.args[2][0].content)
        self.assertEqual(context["objective"], objective)
        self.assertEqual(context["validated_targets"][0]["port"], 3001)
        self.assertEqual({t["name"] for t in context["available_tools"]}, {"nmap", "http_headers", "cve_lookup"})
        self.assertTrue(all(t["description"] for t in context["available_tools"]))
        self.assertEqual([t["name"] for t in first_call.args[1]], ["interpret_objective"])
        saved = self.db.get_run_context(self.session.id)
        self.assertEqual(saved["objective"], objective)
        self.assertEqual(saved["intent"], {"source": "llm", "tool_choice_restricted": True,
                                           **interpretation.tool_calls[0].arguments})
        history = llm.plan.call_args_list[1].args[2]
        self.assertIn(json.dumps(saved["intent"]), history[0].content)
        self.assertIn(objective, history[0].content)
        self.assertLess([k for k, _ in events].index("intent"), [k for k, _ in events].index("plan"))
        report = Path(generate_markdown(self.db, self.scope, self.session.id, self.tmp.name)).read_text()
        self.assertIn("Objective and model interpretation", report)
        self.assertIn(objective, report)
        self.assertIn("Only web response metadata was requested", report)

    def test_tool_permissions_come_from_model_not_prompt_phrase_matching(self):
        # Deliberately wrong model interpretation: the app exposes it, rather than
        # secretly correcting it with a second natural-language parser. Semantic
        # accuracy of real model interpretations requires manual prompt runs.
        result, events, offered, _ = self.run_script([
            call("http_headers", target="127.0.0.1", port=3001), call("finish_recon"),
        ], objective="Use only Nmap on 127.0.0.1", intent_tools=["http_headers"])
        self.assertTrue(result)
        self.assertEqual({s["name"] for s in offered[0]}, {"http_headers", "finish_recon"})
        self.registry.get("nmap").run.assert_not_called()
        self.assertEqual(next(value for kind, value in events if kind == "intent")["allowed_tools"], ["http_headers"])

    def test_broad_interpretation_keeps_followups_available_after_first_tool(self):
        result, _, offered, _ = self.run_script([
            call("nmap", target="127.0.0.1"),
            call("http_headers", target="127.0.0.1", port=3001), self.finish_current,
        ], objective="Start with Nmap on 127.0.0.1 and investigate interesting services.")
        self.assertTrue(result)
        self.assertEqual({s["name"] for s in offered[0]}, {"nmap", "http_headers", "cve_lookup", "finish_recon"})
        for schemas in offered[1:]:
            self.assertEqual({s["name"] for s in schemas}, {"http_headers", "cve_lookup", "finish_recon"})
        self.registry.get("http_headers").run.assert_called_once()
        self.assertEqual(self.db.get_run_context(self.session.id)["intent"]["restriction_reason"], "")

    def test_model_can_exclude_one_tool_without_forcing_a_fixed_sequence(self):
        result, events, offered, _ = self.run_script([
            call("nmap", target="127.0.0.1"), call("http_headers", target="127.0.0.1", port=3001),
            self.finish_current,
        ], objective="Investigate 127.0.0.1 but skip advisory research.", intent_tools=["nmap", "http_headers"])
        self.assertTrue(result)
        self.assertTrue(all("cve_lookup" not in {s["name"] for s in schemas} for schemas in offered))
        self.assertNotIn("CVE", events[-1][1])
        self.assertIn("HTTP headers on 127.0.0.1:8080", events[-1][1])

    def test_invalid_interpretation_can_be_corrected_before_any_execution(self):
        invalid = call("interpret_objective", goal="Inspect headers", allowed_tools=["invented_tool"], restriction_reason="Only headers")
        valid = call("interpret_objective", goal="Inspect headers", allowed_tools=["http_headers"], restriction_reason="Only headers")
        result, events, _, llm = self.run_script([
            call("http_headers", target="127.0.0.1", port=3001), call("finish_recon"),
        ], interpretation_responses=[invalid, valid])
        self.assertTrue(result)
        self.assertEqual(llm.plan.call_count, 4)
        history = llm.plan.call_args_list[1].args[2]
        correction = json.loads(history[-1].content)
        self.assertIn("invented_tool", correction["interpretation_error"])
        self.assertIn("Nothing was executed", correction["instruction"])
        self.assertLess([k for k, _ in events].index("warning"), [k for k, _ in events].index("plan"))
        self.assertEqual(len(self.db.get_actions(self.session.id)), 1)

    def test_interpretation_stage_never_executes_premature_tool_calls(self):
        mixed = PlanResponse([
            ToolCall("intent", "interpret_objective", {"goal": "Inspect headers", "allowed_tools": ["http_headers"],
                                                        "restriction_reason": "Only headers"}),
            ToolCall("http", "http_headers", {"target": "127.0.0.1", "port": 3001}),
        ])
        result, events, offered, llm = self.run_script([], interpretation_responses=[
            mixed, call("nmap", target="127.0.0.1"), PlanResponse(text="Use HTTP headers"),
        ])
        self.assertFalse(result)
        self.assertEqual(llm.plan.call_count, 3)
        self.assertEqual(offered, [])
        self.assertEqual(self.db.get_actions(self.session.id), [])
        self.registry.get("nmap").run.assert_not_called()
        self.registry.get("http_headers").run.assert_not_called()
        self.assertEqual(self.executor.run_tools, frozenset())
        self.assertNotIn("intent", self.db.get_run_context(self.session.id))
        self.assertIn("no valid objective interpretation", events[-1][1])

    def test_interpretation_failure_has_no_unrestricted_fallback(self):
        malformed = call("interpret_objective", goal="Inspect")
        result, _, _, llm = self.run_script([], interpretation_responses=[malformed] * 3)
        self.assertFalse(result)
        self.assertEqual(llm.plan.call_count, 3)
        self.assertEqual(self.db.get_actions(self.session.id), [])
        self.assertFalse(self.db.get_conclusion(self.session.id)["normal_stop"])

    def test_interpretation_llm_failure_stops_without_execution(self):
        result, events, _, llm = self.run_script([], interpretation_responses=[LLMError("offline failure")])
        self.assertFalse(result)
        self.assertEqual(llm.plan.call_count, 1)
        self.assertEqual(self.db.get_actions(self.session.id), [])
        self.assertIn("LLM error during objective interpretation", events[-1][1])

    def test_impossible_request_can_produce_empty_permissions_without_substitution(self):
        interpretation = call("interpret_objective", goal="Use an unavailable tool",
                              allowed_tools=[], restriction_reason="The requested exclusive tool is unavailable")
        result, events, _, llm = self.run_script([], interpretation_responses=[interpretation])
        self.assertFalse(result)
        self.assertEqual(llm.plan.call_count, 1)
        self.assertEqual(self.executor.run_tools, frozenset())
        self.assertEqual(self.db.get_actions(self.session.id), [])
        self.assertIn("permits no available tools", events[-1][1])
        self.assertEqual(self.db.get_run_context(self.session.id)["intent"]["allowed_tools"], [])

    def test_no_applicable_tools_stops_before_interpretation(self):
        self.scope.allowed_tools = ["whois"]
        result, _, _, llm = self.run_script([])
        self.assertFalse(result)
        llm.plan.assert_not_called()

    def test_no_successful_tool_result_cannot_be_a_successful_run(self):
        result, events, _, _ = self.run_script([self.finish_current])
        self.assertFalse(result)
        self.assertIn("No successful tool result", events[-1][1])
        self.assertFalse(self.db.get_conclusion(self.session.id)["normal_stop"])

    def test_repeated_plain_text_stops_with_incomplete_factual_inventory(self):
        result, events, _, llm = self.run_script([PlanResponse(text="All safe") for _ in range(3)])
        self.assertFalse(result)
        self.assertEqual(llm.plan.call_count, 4)
        self.assertIn("without a valid completion decision", events[-1][1])
        self.assertNotIn("All safe", events[-1][1])

    def test_invalid_completion_requires_exact_pending_check_accounting(self):
        self.execute("nmap")
        state = self.state()
        expected = [x["id"] for x in state["pending_checks"]]
        self.assertIsNone(completion_error({"reason": "objective_addressed", "deferred_checks": expected}, state))
        for args in ({}, [], {"reason": [], "deferred_checks": expected},
                     {"reason": "objective_addressed", "deferred_checks": []},
                     {"reason": "objective_addressed", "deferred_checks": expected + [expected[0]]},
                     {"reason": "objective_addressed", "deferred_checks": expected + ["invented"]},
                     {"reason": "objective_addressed", "deferred_checks": expected, "summary": "All safe"}):
            with self.subTest(args=args):
                self.assertIsNotNone(completion_error(args, state))

    def test_omitted_pending_checks_can_be_corrected(self):
        result, events, _, _ = self.run_script([
            call("nmap", target="127.0.0.1"),
            call("finish_recon", reason="objective_addressed", deferred_checks=[]),
            self.finish_current,
        ])
        self.assertTrue(result)
        self.assertTrue(any(kind == "result" and value.error == "invalid_completion" for kind, value in events))

    def test_repeated_malformed_completion_is_bounded(self):
        result, _, _, llm = self.run_script([call("finish_recon", reason="nonsense") for _ in range(3)])
        self.assertFalse(result)
        self.assertEqual(llm.plan.call_count, 4)

    def test_finishing_alongside_a_tool_cannot_skip_its_result(self):
        result, _, _, _ = self.run_script([
            PlanResponse([ToolCall("finish", "finish_recon", {"reason": "objective_addressed", "deferred_checks": []}),
                          ToolCall("http", "http_headers", {"target": "127.0.0.1", "port": 8080})]),
            self.finish_current,
        ])
        self.assertTrue(result)
        self.registry.get("http_headers").run.assert_called_once()

    def test_iteration_limit_and_llm_error_preserve_partial_inventory(self):
        result, events, _, _ = self.run_script([call("nmap", target="127.0.0.1")], limit=1)
        self.assertFalse(result)
        self.assertIn("investigation incomplete", events[-1][1])
        self.assertEqual(len(self.db.get_conclusion(self.session.id)["investigation"]["services"]), 4)
        # A separate loop error also records the evidence rather than replacing it with prose.
        result, events, _, _ = self.run_script([LLMError("synthetic offline failure")])
        self.assertFalse(result)
        self.assertIn("LLM error", events[-1][1])
        self.assertIn("OpenSSH 10.3", events[-1][1])

    def test_truncation_and_candidate_counts_survive_closing_inventory(self):
        self.execute("nmap")
        lookup = self.fake_lookup("127.0.0.1", product="OpenSSH", version="10.3").findings[0]
        lookup.update(candidate_count=9, excluded_count=1)
        lookup["searches"][0].update(reviewed=10, total_results=14, truncated=True)
        self.db.add_finding(self.session.id, None, "127.0.0.1", lookup["summary"], lookup)
        summary = render_inventory(self.state())
        self.assertIn("9 unverified candidate(s), 1 excluded match(es); reviewed 10 of 14", summary)


class DatabaseMigrationTests(unittest.TestCase):
    def test_old_database_migrates_without_inventing_action_parameters(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = f"{tmp}/old.db"
            connection = sqlite3.connect(path)
            connection.executescript('''
                CREATE TABLE sessions(id INTEGER PRIMARY KEY, name TEXT, engagement TEXT, created_at TEXT, status TEXT);
                CREATE TABLE actions(id INTEGER PRIMARY KEY, session_id INTEGER, tool TEXT, target TEXT, command TEXT,
                    policy_ok INTEGER, policy_reason TEXT, executed INTEGER, created_at TEXT);
                INSERT INTO sessions VALUES(1, 'old', 'old', '2020', 'closed');
                INSERT INTO actions VALUES(1, 1, 'http_headers', '127.0.0.1', 'curl', 1, 'allowed', 1, '2020');
            ''')
            connection.close()
            for _ in range(2):
                db = Database(path)
                try:
                    self.assertIsNone(db.get_actions(1)[0]["params"])
                    self.assertIsNone(db.get_actions(1)[0]["success"])
                    self.assertEqual(db.get_conclusion(1), {})
                    self.assertEqual(db.get_run_context(1), {})
                    state = investigation_state([], db.get_actions(1), ["127.0.0.1"], ["http_headers"])
                    self.assertEqual(state["services"], [])
                    self.assertEqual(state["targets"][0]["status"], "unknown")
                finally:
                    db.close()


class IntentValidationTests(unittest.TestCase):
    tools = ["nmap", "http_headers", "cve_lookup", "custom_tool"]

    def test_structurally_invalid_interpretations_are_rejected(self):
        valid = {"goal": "Inspect the target", "allowed_tools": self.tools, "restriction_reason": ""}
        invalid = [None, [], {}, {**valid, "goal": " "}, {**valid, "goal": 123},
                   {**valid, "restriction_reason": None}, {**valid, "allowed_tools": "nmap"},
                   {**valid, "allowed_tools": [False]}, {**valid, "allowed_tools": [{}]},
                   {**valid, "allowed_tools": ["nmap", "nmap"]},
                   {**valid, "allowed_tools": ["invented"], "restriction_reason": "Use it"},
                   {**valid, "target": "another-host"}]
        for arguments in invalid:
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                RunIntent.from_arguments(arguments, self.tools)

    def test_new_tool_names_need_no_parser_aliases(self):
        intent = RunIntent.from_arguments({"goal": "Inspect using the custom tool", "allowed_tools": ["custom_tool"],
                                            "restriction_reason": "The user requested the custom tool only"}, self.tools)
        self.assertEqual(intent.allowed_tools, {"custom_tool"})

    def test_missing_explanation_does_not_broaden_or_reject_model_permissions(self):
        for names in (["nmap"], [], self.tools):
            with self.subTest(names=names):
                intent = RunIntent.from_arguments({"goal": "Inspect", "allowed_tools": names}, self.tools)
                self.assertEqual(intent.allowed_tools, set(names))
                self.assertEqual(intent.tool_choice_restricted, set(names) != set(self.tools))


class CompletionValidationTests(unittest.TestCase):
    def test_empty_coverage_does_not_request_deferrals_but_validates_types(self):
        state = {"pending_checks": []}
        schema = completion_schema(state)
        self.assertNotIn("deferred_checks", schema["parameters"]["properties"])
        self.assertEqual(schema["parameters"]["required"], [])
        self.assertIsNone(completion_error({}, state))
        for args in ({"deferred_checks": "invented"}, {"deferred_checks": [False]}, {"reason": {}},
                     {"summary": "Everything is safe"}):
            with self.subTest(args=args):
                self.assertIsNotNone(completion_error(args, state))


if __name__ == "__main__":
    unittest.main()
