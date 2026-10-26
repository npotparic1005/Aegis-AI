"""Executor.

The only place tools actually run. Every execution path here is:

    proposed action
        -> run target normalization / membership check
        -> parameter validation + applicability / grounding checks
        -> duplicate check (generalized via tool.dedup_key())
        -> policy validation (fail closed)
        -> human confirmation (if enabled)
        -> mark attempted and run
        -> persist findings + result + audit

Nothing bypasses this. The agent loop's planner can *suggest*
anything; it only becomes real by going through execute(). Every
outcome -- including failures, policy denials, and duplicates -- is
persisted, so the planner can see *why* something didn't work on its
next turn instead of just seeing silence.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Callable

from app.agent.targets import RunTargets, TargetError, parse_target
from app.memory.audit import AuditLog
from app.memory.database import Database
from app.policy.validator import PolicyValidator
from app.tools.base import ToolResult
from app.tools.registry import ToolRegistry


@dataclass
class Action:
    tool: str
    target: str | None
    params: dict[str, Any]
    rationale: str = ""


# A confirm callback returns True to proceed. Injected so the CLI
# (or a future web UI) controls how the human is asked.
ConfirmFn = Callable[[str, str], bool]


class Executor:
    def __init__(
        self,
        registry: ToolRegistry,
        validator: PolicyValidator,
        db: Database,
        audit: AuditLog,
        session_id: int,
        require_confirmation: bool = True,
        confirm_fn: ConfirmFn | None = None,
        run_targets: RunTargets | None = None,
    ) -> None:
        self.registry = registry
        self.validator = validator
        self.db = db
        self.audit = audit
        self.session_id = session_id
        self.require_confirmation = require_confirmation
        self.confirm_fn = confirm_fn or (lambda _cmd, _why: True)
        self.run_targets = run_targets
        self.run_tools: frozenset[str] | None = None
        self._done_keys: set = set()

    def done_keys_summary(self) -> list[str]:
        """Human-readable identities of actions that reached tool.run().
        Fed back to the planner every turn so it doesn't have to infer
        "have I already done this?" purely from re-reading raw history."""
        return sorted(str(k) for k in self._done_keys)

    def target_exhausted(self, tool_name: str, target: str) -> bool:
        """Whether every further call of this tool on this target is a duplicate.

        Parameter-dependent tools remain available for different requests.
        Rejections and declined actions never enter _done_keys.
        """
        tool = self.registry.get(tool_name)
        return bool(tool and tool.single_run_per_target
                    and tool.dedup_key(target, {}) in self._done_keys)

    def _reject(self, action: Action, message: str, error: str) -> ToolResult:
        """Record a rejected proposal without consuming its execution identity."""
        target = action.target if isinstance(action.target, str) else repr(action.target)
        self.audit.note(f"Rejected {action.tool} target={target!r}: {message}")
        action_id = self.db.record_action(
            self.session_id, action.tool, target, "", False, message, executed=False,
            params=action.params if isinstance(action.params, dict) else None,
        )
        self.db.record_result(action_id, False, message, error)
        return ToolResult(action.tool, target, False, message, error=error)

    def execute(self, action: Action, on_event=lambda *_: None) -> ToolResult | None:
        tool = self.registry.get(action.tool)
        if tool is None:
            on_event("plan", action)
            return self._reject(action, f"Unknown tool '{action.tool}'.", "unknown_tool")

        if self.run_tools is not None and action.tool not in self.run_tools:
            on_event("plan", action)
            return self._reject(action, f"{action.tool} is not permitted for this run. "
                                f"Allowed by the recorded model interpretation: {sorted(self.run_tools)}.", "tool_not_requested")

        if not isinstance(action.params, dict):
            on_event("plan", action)
            return self._reject(action, "Tool parameters must be a JSON object.", "invalid_params")
        try:
            if self.run_targets is not None:
                target, notes = self.run_targets.resolve(action.target)
            else:
                # Explicit CLI actions (multiscan) have no model/objective from
                # which to inherit a target. Never fall back to global scope.
                target, notes = parse_target(action.target), []
        except TargetError as exc:
            on_event("plan", action)
            return self._reject(action, str(exc), exc.code)

        params = dict(action.params)
        for key, value in tool.target_defaults(target).items():
            if key not in params:
                params[key] = value
                notes.append(f"Filled {key}={value!r} from the target URL/address.")
        action = Action(action.tool, target.host, params, action.rationale)
        for note in notes:
            self.audit.note(f"Session {self.session_id}, {action.tool}: {note}")
            on_event("warning", note)
        on_event("plan", action)

        param_error = tool.validate_params(action.params)
        if param_error is not None:
            return self._reject(action, f"Invalid parameters: {param_error}", "invalid_params")

        target_error = tool.target_applicable(action.target, self.validator.scope.in_scope_domains)
        if target_error is not None:
            return self._reject(action, f"Rejected: {target_error}", "target_not_applicable")

        prior_findings = self.db.get_findings(self.session_id)
        grounding_error = tool.grounding_check(action.params, prior_findings, target=action.target)
        if grounding_error is not None:
            return self._reject(action, f"Rejected: {grounding_error}", "ungrounded")

        context = tool.execution_context(action.target, action.params, prior_findings)
        dedup_key = tool.dedup_key(action.target, {**action.params, **context})
        if dedup_key in self._done_keys:
            advice = ("This tool can run only once per target in this session; choose another available action or finish."
                      if tool.single_run_per_target else "Adjust parameters or choose another available action.")
            return self._reject(action,
                                f"This step already executed in this session. {advice}", "duplicate")

        command = tool.command_preview(action.target, **action.params, **context)

        # 1. POLICY GATE -- fail closed.
        decision = self.validator.validate_action(action.tool, action.target, command)
        self.audit.policy(decision.allowed, decision.reason, action.target, action.tool)
        action_id = self.db.record_action(
            self.session_id, action.tool, action.target, command,
            decision.allowed, decision.reason, executed=False,
            params={**action.params, **context},
        )
        if not decision.allowed:
            result = ToolResult(action.tool, action.target, False,
                                f"Blocked by policy: {decision.reason}", error="policy_denied")
            self.db.record_result(action_id, result.success, result.summary, result.error)
            return result

        # 2. HUMAN CONFIRMATION.
        if self.require_confirmation and not self.confirm_fn(command, action.rationale):
            self.audit.note(f"Human declined: {command}")
            self.db.record_result(action_id, False, "Declined by human.", "declined")
            return None

        # 3. RUN.
        self._done_keys.add(dedup_key)
        self.audit.action(action.tool, action.target, command)
        result = tool.run(action.target, **action.params, **context)

        # 4. PERSIST.
        self.db.conn.execute(
            "UPDATE actions SET executed = 1 WHERE id = ?", (action_id,)
        )
        self.db.conn.commit()
        self.db.record_result(action_id, result.success, result.summary, result.error)
        for finding in result.findings:
            # Preserve the requested hostname even when Nmap reports its IP.
            finding = {**finding, "target": action.target, "source_tool": action.tool}
            self.db.add_finding(
                self.session_id, action_id,
                host=finding.get("host", action.target),
                summary=self._describe(finding),
                data=finding,
            )
        return result

    def execute_parallel(self, actions: list[Action], max_workers: int = 2) -> list[ToolResult]:
        """Run several already-approved actions concurrently.

        Confirmation and policy still apply per-action inside execute().
        max_workers is capped by scope.max_concurrent_actions upstream.
        """
        results: list[ToolResult] = []
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(self.execute, a): a for a in actions}
            for fut in as_completed(futures):
                res = fut.result()
                if res is not None:
                    results.append(res)
        return results

    @staticmethod
    def _describe(finding: dict[str, Any]) -> str:
        # Preserve the tool's summary, including evidence qualifications.
        # Older/custom tools may still supply just the raw port fields.
        if "summary" in finding:
            return str(finding["summary"])
        if "port" in finding:
            svc = finding.get("service", "")
            ver = finding.get("version", "")
            return f"{finding.get('port')}/{finding.get('protocol')} {finding.get('state')} {svc} {ver}".strip()
        return str(finding)[:120]
