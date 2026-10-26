"""DNS lookup tool.

Resolves common DNS record types for a domain (A, AAAA, MX, NS, TXT,
CNAME). Read-only reconnaissance — reveals infrastructure, mail servers,
and sometimes subdomains. Uses the system resolver via dnspython.

    pip install dnspython
"""

from __future__ import annotations

from typing import Any

from app.tools.base import Tool, ToolResult

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]


class DnsLookupTool(Tool):
    name = "dns_lookup"
    description = "Resolve DNS records for a domain (A, AAAA, MX, NS, TXT, CNAME). Read-only."
    params_schema = {
        "properties": {
            "types": {
                "type": "array",
                "items": {"type": "string"},
                "description": "DNS record types to resolve, e.g. ['A','MX']. Omit for the common set.",
            },
        },
        "required": [],
    }

    def target_applicable(self, target: str, in_scope_domains: list[str]) -> str | None:
        if target.strip().lower() not in {d.strip().lower() for d in in_scope_domains}:
            return (
                f"'{target}' is not one of this engagement's in-scope domains -- "
                f"dns_lookup only applies to a real in-scope domain, not an IP or a guessed name."
            )
        return None

    def command_preview(self, target: str, **params: Any) -> str:
        types = params.get("types") or RECORD_TYPES
        return f"dns lookup {target} ({', '.join(types)})"

    def run(self, target: str, **params: Any) -> ToolResult:
        try:
            import dns.resolver
        except ImportError:
            return ToolResult(self.name, target, False,
                              "dnspython not installed (pip install dnspython).",
                              error="dependency_missing")

        types = params.get("types") or RECORD_TYPES
        findings = []
        for rtype in types:
            try:
                answers = dns.resolver.resolve(target, rtype, lifetime=5)
                for rdata in answers:
                    val = str(rdata)
                    findings.append({
                        "host": target,
                        "record": rtype,
                        "value": val,
                        "summary": f"{rtype}: {val}",
                    })
            except Exception:
                # No record of this type, or lookup failed — skip quietly.
                continue

        summary = (f"{len(findings)} DNS record(s) for {target}."
                   if findings else f"No DNS records resolved for {target}.")
        return ToolResult(self.name, target, True, summary, findings=findings)