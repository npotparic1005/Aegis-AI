"""Policy / scope enforcement.

This is the gate. Every action the agent wants to take is checked
here BEFORE it runs. If a target is not explicitly in scope, if a
tool isn't allowed, if the engagement window has passed, or if an
action looks destructive, the validator refuses.

Design rule: fail closed. When in doubt, deny.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import date

import socket

from app.config import Scope


@dataclass
class Decision:
    """Result of a policy check."""

    allowed: bool
    reason: str

    def __bool__(self) -> bool:  # lets you write `if decision:`
        return self.allowed


# Substrings that suggest an action would modify/destroy the target
# rather than observe it. Used as a coarse guardrail; the real
# protection is the allowlist of tools + explicit human approval.
_DESTRUCTIVE_HINTS = (
    "delete", "drop", "shutdown", "reboot", "format", "wipe",
    "script=dos", "dos-", "flood", "destroy", "rm -rf",
)


class PolicyValidator:
    def __init__(self, scope: Scope) -> None:
        self.scope = scope
        self._networks = self._parse_networks(scope.in_scope_hosts)
        self._oos_networks = self._parse_networks(scope.out_of_scope_hosts)

    # ---- public API ---------------------------------------------------

    def check_engagement_window(self, today: date | None = None) -> Decision:
        today = today or date.today()
        eng = self.scope.engagement
        if today < eng.start_date:
            return Decision(False, f"Engagement starts {eng.start_date}; today is {today}.")
        if today > eng.end_date:
            return Decision(False, f"Engagement ended {eng.end_date}; authorization expired.")
        return Decision(True, "Within engagement window.")

    def is_target_authorized(self, target: str) -> Decision:
        """Is this IP / host / domain allowed?

        Order matters: explicit out-of-scope always wins over in-scope.
        """
        target = target.strip().lower()

        # 1. Explicit exclusions first — these override everything.
        if target in {d.lower() for d in self.scope.out_of_scope_domains}:
            return Decision(False, f"'{target}' is explicitly out of scope (domain).")
        if target in {h.lower() for h in self.scope.out_of_scope_hosts}:
            return Decision(False, f"'{target}' is explicitly out of scope (host).")
        if self._ip_in_networks(target, self._oos_networks):
            return Decision(False, f"'{target}' is explicitly out of scope (host).")

        # 2. In-scope domains (exact match).
        if target in {d.lower() for d in self.scope.in_scope_domains}:
            return Decision(True, f"'{target}' is an in-scope domain.")

        # 3. In-scope hosts — exact hostnames as well as IPs/CIDRs.
        if target in {h.lower() for h in self.scope.in_scope_hosts}:
            return Decision(True, f"'{target}' is an in-scope host.")
        if self._ip_in_networks(target, self._networks):
            return Decision(True, f"'{target}' falls inside an in-scope range.")

        # 4. If target is an IP that isn't directly in scope, check whether
        #    an allowed domain happens to resolve to it (same machine).
        if self._looks_like_ip(target):
            for domain in self.scope.in_scope_domains:
                try:
                    resolved = socket.gethostbyname(domain)
                except OSError:
                    continue
                if resolved == target:
                    return Decision(True, f"'{target}' resolves from in-scope domain '{domain}'.")

        return Decision(False, f"'{target}' is not in the authorized scope.")

    @staticmethod
    def _looks_like_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def is_tool_allowed(self, tool_name: str) -> Decision:
        if tool_name in self.scope.allowed_tools:
            return Decision(True, f"Tool '{tool_name}' is allowed.")
        return Decision(
            False,
            f"Tool '{tool_name}' is not in allowed_tools ({self.scope.allowed_tools}).",
        )

    def is_action_safe(self, command_preview: str) -> Decision:
        if not self.scope.block_destructive:
            return Decision(True, "Destructive-action blocking disabled by config.")
        low = command_preview.lower()
        for hint in _DESTRUCTIVE_HINTS:
            if hint in low:
                return Decision(False, f"Blocked: action matches destructive pattern '{hint}'.")
        return Decision(True, "No destructive pattern detected.")

    def ports_allowed(self, ports: list[int]) -> Decision:
        allowed = self.scope.allowed_ports
        if not allowed:
            return Decision(True, "No port restriction configured.")
        bad = [p for p in ports if p not in allowed]
        if bad:
            return Decision(False, f"Ports out of scope: {bad}. Allowed: {allowed}.")
        return Decision(True, "All requested ports are in scope.")

    def validate_action(self, tool_name: str, target: str, command_preview: str) -> Decision:
        """Full check combining every rule. Returns first failure."""
        for check in (
            self.check_engagement_window(),
            self.is_tool_allowed(tool_name),
            self.is_target_authorized(target),
            self.is_action_safe(command_preview),
        ):
            if not check.allowed:
                return check
        return Decision(True, "Action authorized by policy.")

    # ---- internals ----------------------------------------------------

    @staticmethod
    def _parse_networks(entries: list[str]) -> list[ipaddress._BaseNetwork]:
        nets: list[ipaddress._BaseNetwork] = []
        for entry in entries:
            try:
                nets.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                # Not an IP/CIDR (probably a hostname) — skip; handled elsewhere.
                continue
        return nets

    @staticmethod
    def _ip_in_networks(target: str, networks: list[ipaddress._BaseNetwork]) -> bool:
        try:
            ip = ipaddress.ip_address(target)
        except ValueError:
            return False
        return any(ip in net for net in networks)
