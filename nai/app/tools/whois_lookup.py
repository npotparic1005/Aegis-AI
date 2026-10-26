"""WHOIS lookup tool.

Retrieves registration info for a domain: registrar, creation/expiry
dates, name servers, registrant org. Read-only reconnaissance.

    pip install python-whois
"""

from __future__ import annotations

from typing import Any

from app.tools.base import Tool, ToolResult


class WhoisTool(Tool):
    name = "whois"
    description = "Look up WHOIS registration data for a domain (registrar, dates, name servers). Read-only."
    params_schema = {"properties": {}, "required": []}

    def target_applicable(self, target: str, in_scope_domains: list[str]) -> str | None:
        if target.strip().lower() not in {d.strip().lower() for d in in_scope_domains}:
            return (
                f"'{target}' is not one of this engagement's in-scope domains -- "
                f"whois only applies to a real in-scope domain, not an IP or a guessed name."
            )
        return None

    def command_preview(self, target: str, **params: Any) -> str:
        return f"whois {target}"

    def run(self, target: str, **params: Any) -> ToolResult:
        try:
            import whois
        except ImportError:
            return ToolResult(self.name, target, False,
                              "python-whois not installed (pip install python-whois).",
                              error="dependency_missing")

        try:
            data = whois.whois(target)
        except Exception as exc:
            return ToolResult(self.name, target, False,
                              f"WHOIS lookup failed: {exc}", error="lookup_failed")

        fields = {
            "registrar": data.get("registrar"),
            "creation_date": data.get("creation_date"),
            "expiration_date": data.get("expiration_date"),
            "name_servers": data.get("name_servers"),
            "org": data.get("org"),
            "country": data.get("country"),
        }
        findings = []
        for key, val in fields.items():
            if val:
                findings.append({
                    "host": target,
                    "field": key,
                    "value": str(val),
                    "summary": f"{key}: {val}",
                })

        summary = (f"WHOIS returned {len(findings)} field(s) for {target}."
                   if findings else f"No WHOIS data for {target}.")
        return ToolResult(self.name, target, True, summary, findings=findings)