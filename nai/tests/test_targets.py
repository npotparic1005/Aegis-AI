"""Offline regressions for objective targets and rejected-call recovery.

From the repository root:
  PYTHONPATH=nai nai/.venv/bin/python -m unittest discover -s nai/tests -p 'test_targets.py' -v

Planner responses and tool execution are mocked. No Ollama or scanner runs.
"""

import json
import subprocess
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest.mock import Mock, patch

from app.agent.executor import Action, Executor
from app.agent.loop import AgentLoop
from app.agent.targets import RunTargets, TargetError, parse_target
from app.config import Engagement, Scope
from app.llm.client import PlanResponse, ToolCall
from app.memory.audit import AuditLog
from app.memory.database import Database
from app.policy.validator import PolicyValidator
from app.tools.base import ToolResult
from app.tools.cve_lookup import CveLookupTool
from app.tools.http_headers import HttpHeadersTool
from app.tools.nmap_tool import NmapTool
from app.tools.registry import ToolRegistry


class TargetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Database(":memory:")
        self.addCleanup(self.db.close)
        self.session = self.db.create_session("test", "test")
        self.audit_path = Path(self.tmp.name) / "audit.log"
        self.scope = Scope(
            engagement=Engagement("test", "self", "test", date(2000, 1, 1), date(2100, 1, 1)),
            in_scope_hosts=["127.0.0.1", "127.0.0.2", "example.test"], in_scope_domains=[],
            out_of_scope_hosts=[], out_of_scope_domains=[],
            allowed_tools=["nmap", "cve_lookup", "http_headers"], max_concurrent_actions=1,
            allowed_ports=[], block_destructive=True,
        )
        self.validator = PolicyValidator(self.scope)
        self.registry = ToolRegistry()
        self.executed = []
        for tool in (NmapTool(), CveLookupTool(), HttpHeadersTool()):
            def fake_run(host, _name=tool.name, **params):
                self.executed.append((_name, host, params))
                return ToolResult(_name, host, True, "Mock tool response")
            tool.run = Mock(side_effect=fake_run)
            self.registry.register(tool)
        self.executor = Executor(
            self.registry, self.validator, self.db, AuditLog(str(self.audit_path)),
            self.session.id, require_confirmation=False,
            run_targets=self.targets("Reconnaissance of 127.0.0.1"),
        )
        # Fail the test if a regression accidentally reaches a real process,
        # HTTP request, or DNS resolver instead of the test doubles above.
        for name in ("subprocess.run", "requests.sessions.Session.request",
                     "socket.gethostbyname", "socket.getaddrinfo"):
            guard = patch(name, side_effect=AssertionError(f"Unexpected external operation: {name}"))
            guard.start()
            self.addCleanup(guard.stop)

    def targets(self, objective):
        return RunTargets.from_objective(objective, self.validator)

    def seed_product(self):
        self.db.add_finding(self.session.id, None, "127.0.0.1", "OpenSSH",
                            {"product": "OpenSSH", "version": "10.3"})

    def loop(self, responses):
        llm = Mock()
        responses = iter(responses)

        def plan(system, schemas, turns):
            if schemas[0]["name"] == "interpret_objective":
                context = json.loads(turns[0].content)
                return PlanResponse([ToolCall("intent", "interpret_objective", {
                    "goal": "Scripted reconnaissance goal",
                    "allowed_tools": [tool["name"] for tool in context["available_tools"]],
                    "restriction_reason": "",
                })])
            return next(responses)

        llm.plan.side_effect = plan
        loop = AgentLoop(llm, self.registry, self.executor, self.db, self.scope,
                         self.session.id, max_iterations=5)
        return loop, llm

    def test_four_port_objective_has_one_host(self):
        targets = self.targets("Reconnaissance of 127.0.0.1 on ports 2222, 3001, 6379, and 8080.")
        self.assertEqual(targets.hosts, ("127.0.0.1",))

    def test_sentence_punctuation_and_versions_are_not_extra_targets(self):
        targets = self.targets("Inspect 127.0.0.1. Check OpenSSH 10.3 and nginx 1.30.4.")
        self.assertEqual(targets.hosts, ("127.0.0.1",))

    def test_url_preserves_endpoint_and_normalizes_hostname(self):
        target = self.targets("Inspect https://EXAMPLE.TEST.:8443/admin?view=1#top").entries[0]
        self.assertEqual(target.host, "example.test")
        self.assertEqual((target.scheme, target.port, target.path), ("https", 8443, "/admin?view=1"))

    def test_url_path_is_not_parsed_as_another_target(self):
        targets = self.targets("Inspect http://127.0.0.1:8080/docs/scanme.nmap.org")
        self.assertEqual(targets.hosts, ("127.0.0.1",))

    def test_explicit_single_label_lab_hostname_is_supported(self):
        self.scope.in_scope_hosts.append("lab-server")
        self.assertEqual(self.targets("Inspect lab-server.").hosts, ("lab-server",))
        self.assertEqual(self.targets("Inspect lab-server:8080").entries[0].port, 8080)

    def test_bare_hostname_with_port_preserves_endpoint(self):
        target = self.targets("Inspect example.test:8443").entries[0]
        self.assertEqual((target.host, target.port), ("example.test", 8443))

    def test_missing_objective_target_never_uses_scope(self):
        for objective in ("Perform reconnaissance on ", "Inspect the lab"):
            with self.subTest(objective=objective), self.assertRaises(TargetError) as caught:
                self.targets(objective)
            self.assertEqual(caught.exception.code, "missing_target")

    def test_scanme_objective_is_refused_before_planner_or_tools(self):
        loop, llm = self.loop([])
        events = []
        completed = loop.run("Perform reconnaissance on http://scanme.nmap.org/",
                             lambda kind, payload: events.append((kind, payload)))
        self.assertFalse(completed)
        llm.plan.assert_not_called()
        self.assertEqual(self.executed, [])
        self.assertIn("scanme.nmap.org", events[-1][1])
        self.assertIn("No substitute target", events[-1][1])

    def test_one_unauthorized_target_refuses_the_entire_run(self):
        loop, llm = self.loop([])
        self.assertFalse(loop.run("Inspect 127.0.0.1 and scanme.nmap.org"))
        llm.plan.assert_not_called()
        self.assertEqual(self.executed, [])

    def test_missing_call_target_is_inherited_and_recorded(self):
        events = []
        result = self.executor.execute(Action("http_headers", None, {"port": 8080}),
                                       lambda kind, payload: events.append((kind, payload)))
        self.assertTrue(result.success)
        self.assertEqual(self.executed[0][1], "127.0.0.1")
        self.assertIn("Filled missing target", self.audit_path.read_text())
        self.assertTrue(any(kind == "warning" for kind, _ in events))
        self.assertEqual(self.db.get_actions(self.session.id)[0]["target"], "127.0.0.1")

    def test_empty_and_null_targets_are_repaired_but_wrong_types_are_not(self):
        for value in ("", "  ", None):
            with self.subTest(value=value):
                target, notes = self.executor.run_targets.resolve(value)
                self.assertEqual(target.host, "127.0.0.1")
                self.assertTrue(notes)
        for value in (0, False, [], {}):
            with self.subTest(value=value):
                result = self.executor.execute(Action("nmap", value, {}))
                self.assertEqual(result.error, "invalid_target")
        self.assertEqual(self.executed, [])

    def test_wrong_but_globally_allowed_host_is_rejected_then_retry_executes(self):
        self.seed_product()
        params = {"product": "OpenSSH", "version": "10.3"}
        bad = self.executor.execute(Action("cve_lookup", "127.0.0.2", params))
        self.assertEqual(bad.error, "target_mismatch")
        self.assertEqual(self.executor.done_keys_summary(), [])
        good = self.executor.execute(Action("cve_lookup", "127.0.0.1", params))
        self.assertTrue(good.success)
        self.assertEqual(len(self.executed), 1)

    def test_policy_rejection_does_not_consume_cve_identity(self):
        self.seed_product()
        self.scope.allowed_tools.remove("cve_lookup")
        action = Action("cve_lookup", "127.0.0.1", {"product": "OpenSSH", "version": "10.3"})
        self.assertEqual(self.executor.execute(action).error, "policy_denied")
        self.scope.allowed_tools.append("cve_lookup")
        self.assertTrue(self.executor.execute(action).success)
        self.assertEqual(len(self.executed), 1)

    def test_multitarget_run_requires_explicit_target_and_allows_correction(self):
        self.executor.run_targets = self.targets("Inspect 127.0.0.1 and 127.0.0.2")
        rejected = self.executor.execute(Action("nmap", "", {}))
        self.assertEqual(rejected.error, "missing_target")
        self.assertIn("127.0.0.2", rejected.summary)
        self.assertEqual(self.executed, [])
        self.assertTrue(self.executor.execute(Action("nmap", "127.0.0.2", {})).success)

    def test_invalid_port_parameter_can_be_corrected_before_preview(self):
        for ports in (8080, "8080", ["8080"], [True]):
            with self.subTest(ports=ports):
                rejected = self.executor.execute(Action("nmap", "127.0.0.1", {"ports": ports}))
                self.assertEqual(rejected.error, "invalid_params")
        self.assertEqual(self.executed, [])
        self.assertTrue(self.executor.execute(Action("nmap", "127.0.0.1", {"ports": [8080]})).success)
        self.assertEqual(self.executed[0][2]["ports"], [8080])

    def test_actual_execution_still_blocks_duplicate(self):
        action = Action("nmap", "127.0.0.1", {"ports": [8080]})
        self.assertTrue(self.executor.execute(action).success)
        self.assertEqual(self.executor.execute(action).error, "duplicate")
        self.assertEqual(len(self.executed), 1)

    def test_http_uses_url_defaults_without_overriding_explicit_parameters(self):
        self.executor.run_targets = self.targets("Inspect https://127.0.0.1:8443/admin?view=1")
        self.assertTrue(self.executor.execute(Action("http_headers", "", {})).success)
        self.assertEqual(self.executed[-1][2], {"scheme": "https", "port": 8443, "path": "/admin?view=1"})
        self.assertTrue(self.executor.execute(Action("http_headers", "127.0.0.1", {
            "scheme": "http", "port": 8080, "path": "/other",
        })).success)
        self.assertEqual(self.executed[-1][2], {"scheme": "http", "port": 8080, "path": "/other"})

    def test_url_in_tool_call_is_normalized_before_policy(self):
        result = self.executor.execute(Action("http_headers", "https://127.0.0.1:8443/a", {}))
        self.assertTrue(result.success)
        self.assertEqual(self.executed[-1], ("http_headers", "127.0.0.1",
                                            {"scheme": "https", "port": 8443, "path": "/a"}))

    def test_http_path_cannot_replace_url_authority(self):
        result = self.executor.execute(Action("http_headers", "127.0.0.1", {"path": "@example.test"}))
        self.assertEqual(result.error, "invalid_params")
        self.assertEqual(self.executed, [])

    def test_http_redirect_is_returned_without_automatic_following(self):
        tool = HttpHeadersTool()
        completed = subprocess.CompletedProcess([], 0, "HTTP/1.1 302 Found\nLocation: http://elsewhere.test/\n", "")
        with patch("shutil.which", return_value="curl"), patch("subprocess.run", return_value=completed) as run:
            result = tool.run("127.0.0.1", scheme="https")
        command = run.call_args.args[0]
        self.assertNotIn("-L", command)
        self.assertEqual(command[-1], "https://127.0.0.1:443/")
        self.assertTrue(any(f.get("header") == "Location" for f in result.findings))

    def test_planner_receives_target_error_and_recovers_on_next_turn(self):
        loop, llm = self.loop([
            PlanResponse([ToolCall("1", "http_headers", {"target": "127.0.0.2", "port": 8080})]),
            PlanResponse([ToolCall("2", "http_headers", {"port": 8080})]),
            PlanResponse(text="Done"),
            PlanResponse([ToolCall("finish", "finish_recon", {"reason": "objective_addressed", "deferred_checks": []})]),
        ])
        self.assertTrue(loop.run("Reconnaissance of 127.0.0.1 on port 8080"))
        self.assertEqual(self.executed, [("http_headers", "127.0.0.1", {"port": 8080})])
        history = llm.plan.call_args.args[2]
        outcomes = [json.loads(turn.content) for turn in history if turn.kind == "tool_result"]
        self.assertEqual(outcomes[0]["error"], "target_mismatch")
        self.assertEqual(outcomes[1]["target"], "127.0.0.1")
        for schema in llm.plan.call_args.args[1]:
            if schema["name"] == "finish_recon":
                continue
            self.assertEqual(schema["parameters"]["properties"]["target"]["enum"], ["127.0.0.1"])

    def test_nonobject_arguments_are_rejected_without_crashing_loop(self):
        loop, _ = self.loop([
            PlanResponse([ToolCall("1", "nmap", [])]),
            PlanResponse([ToolCall("2", "nmap", {"ports": [8080]})]),
            PlanResponse([ToolCall("finish", "finish_recon", {"reason": "objective_addressed", "deferred_checks": []})]),
        ])
        self.assertTrue(loop.run("Inspect 127.0.0.1"))
        self.assertEqual(len(self.executed), 1)

    def test_repeated_wrong_targets_stop_without_execution(self):
        loop, _ = self.loop([
            PlanResponse([ToolCall(str(i), "nmap", {"target": "127.0.0.2"})]) for i in range(3)
        ])
        self.assertFalse(loop.run("Inspect 127.0.0.1"))
        self.assertEqual(self.executed, [])

    def test_invalid_addresses_are_not_silently_normalized_to_a_host(self):
        for value in ("http://user@example.test/", "http://127.0.0.1:99999/", "127.0.0.1/24",
                      "127.0.0.1 --script=default", "http://127.0.0.1\\@example.test/"):
            with self.subTest(value=value), self.assertRaises(TargetError):
                parse_target(value)


if __name__ == "__main__":
    unittest.main()
