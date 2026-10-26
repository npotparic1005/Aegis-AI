"""HTTP header grabber via curl (external tool).

Runs the system `curl` to fetch HTTP response headers, the same way
Delegates to curl rather than doing the
request in Python — more robust against odd servers. Read-only:
sends one HEAD-style request and returns the headers. Never crashes;
a failed connection is returned as a finding, not an exception.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import Any

from app.tools.base import Tool, ToolResult


class HttpHeadersTool(Tool):
    name = "http_headers"
    description = "Fetch HTTP response headers using curl. Read-only."
    params_schema = {
        "properties": {
            "port": {"type": "integer", "minimum": 1, "maximum": 65535,
                     "description": "Port to connect to. Default 80 for HTTP, 443 for HTTPS."},
            "scheme": {
                "type": "string",
                "enum": ["http", "https"],
                "description": "Default 'http'.",
            },
            "path": {"type": "string", "description": "Request path. Default '/'."},
        },
        "required": [],
    }

    def target_defaults(self, target) -> dict[str, Any]:
        defaults = {}
        if target.scheme:
            defaults["scheme"] = target.scheme
        if target.port is not None:
            defaults["port"] = target.port
        if target.path:
            defaults["path"] = target.path
        return defaults

    def validate_params(self, params: dict[str, Any]) -> str | None:
        error = super().validate_params(params)
        if error:
            return error
        path = params.get("path", "/")
        if not path.startswith("/") or any(char.isspace() or ord(char) < 32 for char in path):
            return "'path' must start with '/' and contain no whitespace; supply the host in 'target'."
        return None

    def command_preview(self, target: str, **params: Any) -> str:
        scheme = params.get("scheme", "http")
        port = params.get("port", 443 if scheme == "https" else 80)
        path = params.get("path", "/")
        return f"curl -I {scheme}://{target}:{port}{path}"

    def run(self, target: str, **params: Any) -> ToolResult:
        curl = shutil.which("curl") or shutil.which("curl.exe")
        if curl is None:
            return ToolResult(self.name, target, False,
                              "curl not found on PATH.", error="binary_not_found")

        scheme = params.get("scheme", "http")
        port = int(params.get("port", 443 if scheme == "https" else 80))
        path = params.get("path", "/")
        url = f"{scheme}://{target}:{port}{path}"

        # -I: headers only, -s: silent, -S: still show errors,
        # -k: allow self-signed certs, --max-time: hard timeout.
        # Return redirects as evidence. Following them automatically could
        # contact another host without passing the run's target check.
        args = [curl, "-I", "-s", "-S", "-k", "--max-time", "15", url]

        try:
            proc = subprocess.run(args, capture_output=True, text=True, timeout=20)
        except subprocess.TimeoutExpired:
            note = "no HTTP response (timeout)"
            return ToolResult(self.name, target, False,
                              f"HTTP request timed out on {url}; service availability is undetermined.",
                              findings=[{"kind": "http_error", "host": target, "port": port, "url": url,
                                         "note": note, "summary": f"{url}: {note}"}], error="timeout")

        output = (proc.stdout or "") + (proc.stderr or "")
        if proc.returncode != 0:
            note = output.strip()[:200]
            return ToolResult(self.name, target, False,
                              f"HTTP request failed for {url} (curl: exit {proc.returncode}); "
                              "this does not establish absence of an HTTP service.",
                              findings=[{"kind": "http_error", "host": target, "port": port, "url": url,
                                         "note": note, "summary": f"{url}: request failed: {note}"}],
                              raw_output=output, error=f"curl_exit_{proc.returncode}")

        # Parse header lines into findings.
        findings = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if ":" in line and not line.startswith("HTTP/"):
                name, _, value = line.partition(":")
                findings.append({
                    "kind": "http_header",
                    "host": target,
                    "port": port,
                    "url": url,
                    "header": name.strip(),
                    "value": value.strip(),
                    "summary": f"{url} — {name.strip()}: {value.strip()}",
                })

        statuses = [line for line in proc.stdout.splitlines() if line.startswith("HTTP/")]
        if not statuses:
            return ToolResult(self.name, target, False, f"No HTTP status line in curl output for {url}.",
                              raw_output=output, error="invalid_output")
        summary = f"{statuses[-1].strip()} from {url}; {len(findings)} header(s)."
        return ToolResult(self.name, target, True, summary,
                          findings=findings, raw_output=proc.stdout)
