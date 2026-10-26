"""CVE candidate enrichment for observed services.

Read-only enrichment: given a product/service and version that nmap
discovered, ask the public NVD (National Vulnerability Database) API
which records match. CPE conditions filter candidates, but reconnaissance
does not verify vulnerability applicability or exploitation prerequisites.

NVD API is rate limited:
  - no key : ~5 requests / 30s
  - with key: ~50 requests / 30s   (set NVD_API_KEY env var)
Get a free key at https://nvd.nist.gov/developers/request-an-api-key
"""

from __future__ import annotations

import os
import time
import json
import re
from datetime import datetime, timezone
from typing import Any

from app.tools.base import Tool, ToolResult
from app.cve_matching import classify_cve, exact_cpe_query, product_name

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CveLookupTool(Tool):
    name = "cve_lookup"
    description = (
        "Find and filter CVE candidates for an observed product/version. Matches are not confirmed vulnerabilities. "
        "queries the public NVD database, does not touch the target."
    )
    params_schema = {
        "properties": {
            "product": {
                "type": "string",
                "description": "Product/service name, as reported by nmap.",
            },
            "version": {
                "type": "string",
                "description": "Version string, if known.",
            },
            "limit": {
                "type": "integer",
                "minimum": 1, "maximum": 50,
                "description": "Maximum NVD records to review per query (1-50). Default 10; results may be incomplete.",
            },
        },
        "required": ["product"],
    }

    def dedup_key(self, target: str, params: dict[str, Any]) -> tuple:
        # Evidence and applicability belong to a particular target.
        product = product_name(str(params.get("product") or ""))
        version = str(params.get("version") or params.get("_evidence", {}).get("version") or "").strip().lower()
        return (self.name, target.strip().lower(), product, version)

    @staticmethod
    def _matching_services(params, prior_findings, target=None):
        matches = []
        for finding in prior_findings:
            data = finding.get("data") if isinstance(finding.get("data"), dict) else finding
            if data.get("kind") in {"cve_candidate", "cve_lookup"} or "cve" in data:
                continue
            if data.get("state", "open") != "open" or data.get("identification") == "unresolved":
                continue
            if data.get("service_method") == "table":
                continue
            host = data.get("target") or data.get("host") or finding.get("host")
            if target is not None and host != target:
                continue
            if not data.get("product") or product_name(data["product"]) != product_name(params.get("product", "")):
                continue
            if params.get("version") and params["version"].strip() != str(data.get("version", "")).strip():
                continue
            matches.append(data)
        return matches

    def grounding_check(self, params, prior_findings, target=None) -> str | None:
        if self._matching_services(params, prior_findings, target):
            return None
        return ("No observed product/version on this target supports that lookup. Copy the product "
                "and version from a service finding; port-table guesses and CVE search results are not discovery evidence.")

    def execution_context(self, target, params, prior_findings) -> dict:
        matches = self._matching_services(params, prior_findings, target)
        # Do not choose a version when the caller omitted it and several were observed.
        versions = {str(m.get("version", "")) for m in matches}
        cpes = list(dict.fromkeys(cpe for m in matches for cpe in m.get("cpes", []))) if len(versions) == 1 else []
        return {"_evidence": {"cpes": cpes,
                              "version": next(iter(versions)) if len(versions) == 1 else "",
                              "services": [{key: m[key] for key in ("host", "target", "port", "product", "version", "cpes")
                                            if key in m} for m in matches]}}

    def command_preview(self, target: str, **params: Any) -> str:
        product = params.get("product", "")
        version = params.get("version") or params.get("_evidence", {}).get("version", "")
        cpe = exact_cpe_query(params.get("_evidence", {}).get("cpes", []))
        term = self._keyword(product, version)
        query = f"cpeName='{cpe}' (keyword fallback if empty/unsupported)" if cpe else f"keyword='{term}'"
        return f"nvd-lookup {query} ({product} on {target}; candidate enrichment, not vulnerability verification)"

    @staticmethod
    def _keyword(product: str, version: str) -> str:
        # A version range/banner is not an exact version to put into keywordSearch.
        exact_version = version if re.fullmatch(r"[\w.+-]+", version) else ""
        return f"{product_name(product)} {exact_version}".strip()

    def run(self, target: str, **params: Any) -> ToolResult:
        try:
            import requests
        except ImportError:
            return ToolResult(self.name, target, False,
                              "requests not installed (pip install requests).",
                              error="dependency_missing")

        product = (params.get("product") or "").strip()
        version = (params.get("version") or "").strip()
        limit = int(params.get("limit", 10))
        if not product:
            return ToolResult(self.name, target, False,
                              "No product given to look up.", error="no_product")

        evidence = params.get("_evidence", {})
        version = version or evidence.get("version", "")
        cpes = evidence.get("cpes", [])
        cpe = exact_cpe_query(cpes)
        keyword = self._keyword(product, version)
        headers = {}
        api_key = os.environ.get("NVD_API_KEY")
        if api_key:
            headers["apiKey"] = api_key

        searches = []
        query = {"cpeName": cpe, "isVulnerable": ""} if cpe else {"keywordSearch": keyword}
        # At most two requests: a structured CPE search, then a keyword fallback
        # if no records were returned or NVD did not accept the CPE name.
        while True:
            try:
                resp = requests.get(NVD_ENDPOINT, params={**query, "resultsPerPage": limit},
                                    headers=headers, timeout=30)
            except requests.RequestException as exc:
                return ToolResult(self.name, target, False, f"NVD request failed: {exc}", error="request_failed")
            time.sleep(6 if not api_key else 1)
            if resp.status_code == 400 and "cpeName" in query:
                searches.append({"query": query, "status": 400, "note": "CPE query rejected; trying keywords."})
                query = {"keywordSearch": keyword}
                continue
            if resp.status_code != 200:
                return ToolResult(self.name, target, False, f"NVD returned HTTP {resp.status_code}; lookup incomplete.",
                                  raw_output=resp.text, error=f"http_{resp.status_code}")
            try:
                data = resp.json()
                if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
                    raise ValueError("missing vulnerabilities array")
                total = int(data["totalResults"])
                reviewed = len(data["vulnerabilities"])
                if total < reviewed:
                    raise ValueError("inconsistent totalResults")
            except (ValueError, KeyError, TypeError) as exc:
                return ToolResult(self.name, target, False, f"Invalid NVD response: {exc}",
                                  raw_output=resp.text, error="invalid_response")
            searches.append({"query": query, "total_results": total, "reviewed": reviewed,
                             "truncated": total > reviewed, "status": 200})
            if "cpeName" in query and total == 0:
                query = {"keywordSearch": keyword}
                continue
            break

        try:
            assessed = self._parse(data, host=target, product=product, version=version, cpes=cpes)
        except (ValueError, TypeError, AttributeError, KeyError) as exc:
            return ToolResult(self.name, target, False, f"Invalid NVD record: {exc}",
                              raw_output=resp.text, error="invalid_response")
        candidates = [f for f in assessed if f["assessment"] == "candidate"]
        excluded = [f for f in assessed if f["assessment"] == "excluded"]
        summary = (f"CVE lookup for {product} {version}: {len(candidates)} unverified candidate(s), "
                   f"{len(excluded)} excluded match(es); reviewed {reviewed} of {total} records in the final query. "
                   "No vulnerability was confirmed; zero candidates does not establish absence of vulnerabilities.")
        lookup = {"kind": "cve_lookup", "host": target, "product": product, "version": version,
                  "summary": summary, "source": NVD_ENDPOINT,
                  "retrieved_at": datetime.now(timezone.utc).isoformat(), "searches": searches,
                  "candidate_count": len(candidates), "excluded_count": len(excluded),
                  "excluded_matches": excluded, "observed_services": evidence.get("services", []),
                  "coverage_note": "Bounded NVD searches; incomplete enrichment, aliases, unreviewed pages and "
                                   "unknown configuration can omit applicable CVEs. This is not a vulnerability assessment."}
        return ToolResult(self.name, target, True, summary, findings=[lookup, *candidates],
                          raw_output=json.dumps(data))

    @staticmethod
    def _parse(data: dict[str, Any], host: str, product: str = "", version: str = "",
               cpes: list[str] | None = None) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
                raise ValueError("missing or invalid CVE ID")
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            severity, score = CveLookupTool._severity(cve.get("metrics", {}))
            assessment = classify_cve(cve, product, version, cpes or [])
            status = "Candidate (unverified)" if assessment["assessment"] == "candidate" else "Excluded match"
            out.append({
                "kind": "cve_candidate" if assessment["assessment"] == "candidate" else "cve_excluded",
                "host": host,
                "product": product,
                "version": version,
                "cve": cve_id,
                "severity": severity,
                "cvss": score,
                **assessment,
                "description": desc,
                "configurations": cve.get("configurations", []),
                "source": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "summary": f"{status}: {cve_id} ({severity or 'unscored'}, {score}) — {assessment['reason']}",
            })
        # Sort worst-first.
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "": 4}
        out.sort(key=lambda f: order.get(f.get("severity", ""), 5))
        return out

    @staticmethod
    def _severity(metrics: dict[str, Any]) -> tuple[str, float]:
        # NVD nests CVSS under version-specific keys; try newest first.
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            arr = metrics.get(key)
            if arr:
                data = arr[0].get("cvssData", {})
                sev = data.get("baseSeverity") or arr[0].get("baseSeverity", "")
                return sev.upper(), float(data.get("baseScore", 0.0))
        return "", 0.0
