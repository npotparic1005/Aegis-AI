"""nmap wrapper.

Shells out to the standard `nmap` binary, asks for XML on stdout,
and parses it into structured findings the LLM can reason over.

This is a thin, transparent wrapper: it runs the same command you
could type by hand. No stealth/evasion flags are baked in — the
point is authorized service discovery, not avoiding detection.
"""

from __future__ import annotations

import shutil
import subprocess
import html
import re
import xml.etree.ElementTree as ET
from typing import Any

from app.tools.base import Tool, ToolResult


class NmapTool(Tool):
    name = "nmap"
    single_run_per_target = True
    description = "Network/port scanner. Discovers open ports and running services on an authorized host."
    params_schema = {
        "properties": {
            "ports": {
                "type": "array",
                "items": {"type": "integer"},
                "description": "Specific ports to scan. Omit to let nmap/top_ports pick the set.",
            },
            "top_ports": {
                "type": "integer",
                "description": "Scan nmap's N most common ports instead of a specific list. Ignored if 'ports' is given.",
            },
            "service_detection": {
                "type": "boolean",
                "description": "Run version detection (-sV). Default true.",
            },
            "os_detection": {
                "type": "boolean",
                "description": "Attempt OS fingerprinting (-O). Default false; needs raw-socket privileges.",
            },
            "protocol": {
                "type": "string",
                "enum": ["tcp", "udp"],
                "description": "Scan TCP (-sT, default) or UDP (-sU) ports.",
            },
            "timing": {
                "type": "string",
                "enum": ["T0", "T1", "T2", "T3", "T4", "T5"],
                "description": "nmap timing template, paranoid (T0) to insane (T5). Default is nmap's own (T3).",
            },
            "script_category": {
                "type": "string",
                "enum": ["default", "discovery", "version", "safe"],
                "description": (
                    "Run one of nmap's non-intrusive NSE script categories "
                    "(--script=<category>). Only these safe categories are "
                    "exposed; nmap's intrusive/vuln/exploit/dos categories "
                    "are deliberately not available through this tool."
                ),
            },
        },
        "required": [],
    }

    # Timeout so a hung scan can't stall the whole agent.
    DEFAULT_TIMEOUT = 300

    def dedup_key(self, target: str, params: dict[str, Any]) -> tuple:
        # A host is either scanned or it isn't -- params don't change that.
        # Normalize whitespace/case so a re-sent target isn't a "new" host.
        return (self.name, target.strip().lower())

    def command_preview(self, target: str, **params: Any) -> str:
        return " ".join(self._build_args(target, **params))

    def run(self, target: str, **params: Any) -> ToolResult:
        if shutil.which("nmap") is None:
            return ToolResult(
                tool=self.name,
                target=target,
                success=False,
                summary="nmap is not installed or not on PATH.",
                error="binary_not_found",
            )

        args = self._build_args(target, **params)
        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=params.get("timeout", self.DEFAULT_TIMEOUT),
                check=False,
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool=self.name,
                target=target,
                success=False,
                summary="nmap scan timed out.",
                error="timeout",
            )

        if proc.returncode != 0:
            return ToolResult(
                tool=self.name,
                target=target,
                success=False,
                summary="nmap exited with an error.",
                raw_output=proc.stdout + proc.stderr,
                error=f"exit_{proc.returncode}",
            )

        try:
            findings = self._parse_xml(proc.stdout)
        except (ET.ParseError, ValueError) as exc:
            return ToolResult(self.name, target, False,
                              f"Nmap output could not establish scan results: {exc}",
                              raw_output=proc.stdout + proc.stderr, error="invalid_output")
        open_ports = [f for f in findings if f.get("state") == "open"]
        summary = (
            f"{len(open_ports)} open port(s) found on {target}."
            if open_ports
            else f"No open ports reported in this completed scan of {target}; unscanned ports are unknown."
        )
        return ToolResult(
            tool=self.name,
            target=target,
            success=True,
            summary=summary,
            findings=findings,
            raw_output=proc.stdout,
        )

    # ---- internals ----------------------------------------------------

    def _build_args(self, target: str, **params: Any) -> list[str]:
        args = ["nmap", "-oX", "-"]  # XML to stdout

        if params.get("service_detection", True):
            args.append("-sV")  # service/version detection

        if params.get("os_detection"):
            args.append("-O")

        protocol = params.get("protocol")
        if protocol == "udp":
            args.append("-sU")
        elif protocol == "tcp":
            args.append("-sT")

        timing = params.get("timing")
        if timing:
            args.append(f"-{timing}")

        script_category = params.get("script_category")
        if script_category:
            args.append(f"--script={script_category}")

        ports = params.get("ports")
        top_ports = params.get("top_ports")
        if ports:
            args += ["-p", ",".join(str(int(p)) for p in ports)]
        elif top_ports:
            args += ["--top-ports", str(int(top_ports))]

        args.append(target)
        return args

    @staticmethod
    def _parse_xml(xml_text: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        root = ET.fromstring(xml_text)
        finished = root.find("./runstats/finished")
        if root.tag != "nmaprun" or finished is None or finished.get("exit") != "success":
            raise ValueError("missing successful Nmap completion record")

        for host in root.findall("host"):
            addr_el = host.find("address")
            addr = addr_el.get("addr") if addr_el is not None else "unknown"
            for port in host.findall("./ports/port"):
                state_el = port.find("state")
                service_el = port.find("service")
                method = service_el.get("method", "") if service_el is not None else ""
                reported = service_el.get("name", "") if service_el is not None else ""
                confidence = service_el.get("conf", "") if service_el is not None else ""
                confidence = int(confidence) if confidence.isdigit() else None
                identification = "probed" if method == "probed" else "unresolved"
                fingerprint = service_el.get("servicefp", "") if service_el is not None else ""
                finding = {
                        "kind": "service",
                        "source": "nmap",
                        "host": addr,
                        "port": int(port.get("portid", 0)),
                        "protocol": port.get("protocol", ""),
                        "state": state_el.get("state") if state_el is not None else "",
                        "service": reported if method == "probed" else "unknown",
                        "service_guess": reported if method != "probed" else "",
                        "service_method": method,
                        "service_confidence": confidence,
                        "identification": identification,
                        "product": service_el.get("product", "") if service_el is not None else "",
                        "version": service_el.get("version", "") if service_el is not None else "",
                        "extra_info": service_el.get("extrainfo", "") if service_el is not None else "",
                        "os_hint": service_el.get("ostype", "") if service_el is not None else "",
                        "tunnel": service_el.get("tunnel", "") if service_el is not None else "",
                        "cpes": [c.text for c in service_el.findall("cpe") if c.text]
                                if service_el is not None else [],
                        "service_fingerprint": fingerprint,
                        "scripts": [{"id": s.get("id", ""), "output": s.get("output", "")}
                                    for s in port.findall("script")],
                }
                finding.update(NmapTool._fingerprint_hints(fingerprint))
                details = f"{finding['port']}/{finding['protocol']} {finding['state']}: "
                if method == "probed":
                    details += " ".join(filter(None, [finding["product"] or reported, finding["version"]]))
                    details += f" (probed; service confidence {confidence if confidence is not None else 'unknown'}/10)"
                else:
                    label = "port-table guess" if method == "table" else "unverified label"
                    details += f"unresolved service ({label}: {reported or 'none'}; not confirmed)"
                if finding.get("http_observed"):
                    details += "; HTTP response observed"
                if finding.get("http_title"):
                    details += f"; page title: {finding['http_title']}"
                finding["summary"] = details
                findings.append(finding)
        return findings

    @staticmethod
    def _fingerprint_hints(fingerprint: str) -> dict[str, Any]:
        """Decode Nmap's escaped text without interpreting it as Python/regex code.

        The raw fingerprint remains evidence. These are observations extracted
        from its text, not a new product/version identification.
        """
        if not fingerprint:
            return {}
        decoded = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m[1], 16)), fingerprint)
        escapes = {"r": "\r", "n": "\n", "t": "\t"}
        decoded = re.sub(r"\\([rnt\\.\"'()*+?\[\]{}|^$])",
                         lambda m: escapes.get(m[1], m[1]), decoded)
        responses = list(dict.fromkeys(re.findall(r"HTTP/\d(?:\.\d)? [1-5]\d\d[^\r\n]{0,80}", decoded)))
        title = re.search(r"<title\b[^>]*>(.*?)</title>", decoded, re.I | re.S)
        out: dict[str, Any] = {"fingerprint_excerpt": decoded[:1500],
                               "fingerprint_excerpt_truncated": len(decoded) > 1500}
        if responses:
            out["http_observed"] = True
            out["http_responses"] = responses[:4]
        if title:
            out["http_title"] = " ".join(html.unescape(re.sub(r"<[^>]+>", "", title[1])).split())[:240]
        return out
