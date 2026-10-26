"""Append-only audit log.

Separate from the SQLite DB on purpose: a flat, human-readable,
timestamped trail you can hand to a client or keep for your own
records. Every policy decision and every executed action is logged.
"""

from __future__ import annotations

from datetime import datetime, timezone


class AuditLog:
    def __init__(self, path: str) -> None:
        self.path = path

    def write(self, event: str, detail: str) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        line = f"{ts}\t{event}\t{detail}\n"
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(line)

    def policy(self, allowed: bool, reason: str, target: str, tool: str) -> None:
        verdict = "ALLOW" if allowed else "DENY"
        self.write("POLICY", f"{verdict} tool={tool} target={target} :: {reason}")

    def action(self, tool: str, target: str, command: str) -> None:
        self.write("ACTION", f"tool={tool} target={target} cmd={command}")

    def note(self, text: str) -> None:
        self.write("NOTE", text)
