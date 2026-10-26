"""Compact planner views over complete stored reconnaissance evidence."""

from __future__ import annotations

#pravi skracene prikaze za model, prompt ostaje mali
def planner_finding(finding: dict) -> dict:
    view = {key: value for key, value in finding.items()
            if key not in {"service_fingerprint", "configurations", "excluded_matches", "scripts", "description"}}
    if "description" in finding:
        view["description_excerpt"] = finding["description"][:1200]
        view["description_excerpt_truncated"] = len(finding["description"]) > 1200
    if finding.get("scripts"):
        view["script_excerpts"] = [{"id": s["id"], "output": s["output"][:600]}
                                   for s in finding["scripts"][:6]]
        view["scripts_omitted"] = max(0, len(finding["scripts"]) - 6)
    if "excluded_matches" in finding:
        view["excluded_matches"] = [{key: f[key] for key in ("cve", "assessment", "reason")}
                                    for f in finding["excluded_matches"]]
    return view

#prolazi kroz nalaze sesije i pravi dva recnika, jedan za servise, drugi za cve pretrage koje su vec radjene
def evidence_recap(findings: list[dict]) -> dict:
    services, lookups = [], []
    seen = set()
    for finding in findings:
        data = finding.get("data", {})
        if data.get("kind") == "cve_lookup":
            lookups.append({key: data[key] for key in ("target", "host", "product", "version", "summary")
                            if key in data})
        if "port" not in data or data.get("state") != "open":
            continue
        key = (data.get("target", data.get("host")), data.get("host"), data["port"], data.get("protocol"))
        if key in seen:
            continue
        seen.add(key)
        services.append({field: data[field] for field in (
            "target", "host", "port", "protocol", "service", "service_guess", "product", "version",
            "service_method", "service_confidence", "identification", "http_observed", "http_title", "cpes",
        ) if field in data})
    return {"services_discovered": services, "cve_lookups": lookups}
