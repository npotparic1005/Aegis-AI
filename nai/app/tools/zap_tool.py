"""OWASP ZAP tool (Day 6–7).

Thin wrapper around OWASP ZAP — a mainstream, legitimate web-app
security scanner. Like the nmap wrapper, this does NOT implement any
attacks itself: it drives ZAP's own built-in scanner through ZAP's
API and collects the alerts ZAP reports.

Safety posture, by design:
  - Default is spider + PASSIVE scan only (observes traffic, sends
    nothing intrusive).
  - ACTIVE scan (which sends test requests) is OPT-IN via
    params={"active": true} — so you never launch it by accident. It
    still passes the policy gate + human confirmation like everything
    else.

Requires ZAP running with its API enabled, and the Python client:
    pip install zaproxy
    (start ZAP, note the API key from Tools > Options > API)
"""

from __future__ import annotations

import time
from typing import Any

from app.tools.base import Tool, ToolResult


class ZapTool(Tool):
    name = "zap"
    description = "OWASP ZAP web-app scanner. Drives ZAP's own scanner; does not implement attacks itself."
    params_schema = {
        "properties": {
            "active": {
                "type": "boolean",
                "description": "Send real test requests. Default false (spider+passive only).",
            },
            "max_wait": {
                "type": "integer",
                "description": "Max seconds to wait for spider/scan completion. Default 300.",
            },
            "zap_host": {
                "type": "string",
                "description": "ZAP API host. Default 127.0.0.1.",
            },
            "zap_port": {
                "type": "integer",
                "description": "ZAP API port. Default 8080.",
            },
            "api_key": {
                "type": "string",
                "description": "ZAP API key, if one is configured.",
            },
        },
        "required": [],
    }

    def command_preview(self, target: str, **params: Any) -> str:
        mode = "spider + passive + ACTIVE" if params.get("active") else "spider + passive"
        return f"zap {mode} scan of {target}"

    def run(self, target: str, **params: Any) -> ToolResult:
        try:
            from zapv2 import ZAPv2
        except ImportError:
            return ToolResult(self.name, target, False,
                              "zaproxy client not installed (pip install zaproxy).",
                              error="dependency_missing")

        zap_host = params.get("zap_host", "127.0.0.1")
        zap_port = int(params.get("zap_port", 8080))
        api_key = params.get("api_key", "")
        max_wait = int(params.get("max_wait", 300))
        do_active = bool(params.get("active", False))

        proxy = f"http://{zap_host}:{zap_port}"
        zap = ZAPv2(apikey=api_key, proxies={"http": proxy, "https": proxy})

        # Normalise target to a URL ZAP understands.
        url = target if target.startswith("http") else f"http://{target}"

        try:
            zap.urlopen(url)
            time.sleep(2)

            # 1. Spider: discover the site's URLs.
            spider_id = zap.spider.scan(url)
            self._wait(lambda: int(zap.spider.status(spider_id)), max_wait, "spider")

            # 2. Passive scan runs automatically as the spider crawls.
            self._wait(lambda: 0 if int(zap.pscan.records_to_scan) == 0 else 1,
                       max_wait, "passive")

            # 3. Active scan is opt-in only.
            if do_active:
                ascan_id = zap.ascan.scan(url)
                self._wait(lambda: int(zap.ascan.status(ascan_id)), max_wait, "active")

            alerts = zap.core.alerts(baseurl=url)
        except Exception as exc:  # ZAP client raises various errors
            return ToolResult(self.name, target, False,
                              f"ZAP scan error: {exc}", error="zap_error")

        findings = self._parse_alerts(alerts, host=target)
        highs = [f for f in findings if f.get("severity") in ("High", "Critical")]
        summary = (
            f"ZAP found {len(findings)} alert(s) on {target}"
            + (f" — {len(highs)} high." if highs else ".")
        )
        return ToolResult(self.name, target, True, summary, findings=findings)

    @staticmethod
    def _wait(status_fn, max_wait: int, label: str) -> None:
        """Poll a ZAP status function until done (100 / 0) or timeout."""
        waited = 0
        while waited < max_wait:
            try:
                val = status_fn()
            except Exception:
                return
            # spider/ascan report 0..100; our passive lambda reports 0 when done
            if val >= 100 or (label == "passive" and val == 0):
                return
            time.sleep(2)
            waited += 2

    @staticmethod
    def _parse_alerts(alerts: list[dict], host: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        seen = set()
        for a in alerts:
            key = (a.get("alert"), a.get("risk"), a.get("url"))
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "host": host,
                "alert": a.get("alert", ""),
                "severity": a.get("risk", ""),      # Informational/Low/Medium/High
                "confidence": a.get("confidence", ""),
                "url": a.get("url", ""),
                "summary": (a.get("alert", "") + " @ " + a.get("url", "")).strip(),
            })
        order = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
        out.sort(key=lambda f: order.get(f.get("severity", ""), 4))
        return out
