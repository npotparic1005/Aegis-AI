"""Derive reconnaissance coverage from stored observations and action outcomes.

These records describe work done and work left unassessed. They do not choose
tools, assert that a vulnerability applies, or impose a reconnaissance workflow.
"""

from __future__ import annotations

from app.cve_matching import product_name


def _host(data: dict) -> str:
    return data.get("target") or data.get("host", "")


def _port(params: dict) -> int:
    return params.get("port", 443 if params.get("scheme") == "https" else 80)


def _same_product(service: dict, data: dict) -> bool:
    return (bool(service.get("product")) and _host(data) == _host(service)
            and product_name(data.get("product", "")) == product_name(service["product"])
            and (not data.get("version") or data["version"] == service.get("version", "")))


def _cve_applies_to_service(service: dict, lookup: dict) -> bool:
    observations = lookup.get("observed_services", [])
    if observations:
        return any(_same_product(service, observation)
                   and observation.get("port") == service["port"] for observation in observations)
    return _same_product(service, lookup)


def investigation_state(findings: list[dict], actions: list[dict], targets: list[str],
                        available_tools: list[str]) -> dict:
    data = [f.get("data", f) for f in findings]
    services = {}
    for finding in data:
        if "port" in finding and finding.get("state") == "open":
            key = (_host(finding), finding.get("protocol", "tcp"), finding["port"])
            services[key] = {k: finding[k] for k in (
                "target", "host", "port", "protocol", "service", "product", "version",
                "identification", "service_guess", "http_observed", "http_title", "tunnel",
            ) if k in finding}

    # A successful HTTP-only run also has useful endpoint evidence, even when
    # the model never chose Nmap. Failed requests never create a discovered service.
    for finding in data:
        if finding.get("kind") in {"http_header", "http_response"} and finding.get("port"):
            key = (_host(finding), "tcp", finding["port"])
            services.setdefault(key, {"target": key[0], "host": finding.get("host", key[0]),
                                     "port": key[2], "protocol": "tcp", "service": "http",
                                     "identification": "protocol_observed", "http_observed": True})
    for action in actions:
        if action["tool"] == "http_headers" and action["executed"] and action.get("success") and action.get("params") is not None:
            key = (action["target"], "tcp", _port(action["params"]))
            services.setdefault(key, {"target": key[0], "host": key[0], "port": key[2], "protocol": "tcp",
                                     "service": "http", "identification": "protocol_observed", "http_observed": True})

    lookups = [f for f in data if f.get("kind") == "cve_lookup"]
    pending = []
    for (target, protocol, port), service in services.items():
        service["id"] = f"{target}/{protocol}/{port}"
        service["target"] = target
        service["protocol"] = protocol
        http_actions = [a for a in actions if a["tool"] == "http_headers" and a["target"] == target
                        and a["executed"] and a.get("params") is not None
                        and protocol == "tcp" and _port(a["params"]) == port]
        http_observations = [f for f in data if f.get("kind") in {"http_header", "http_response"}
                             and _host(f) == target and f.get("port") == port and protocol == "tcp"]
        http_ok = bool(http_observations) or any(a.get("success") for a in http_actions)
        http_failed = [a["id"] for a in http_actions if a.get("success") == 0]
        web_hint = service.get("http_observed") or "http" in service.get("service", "").lower()
        service["http"] = {
            "status": "checked" if http_ok else "failed" if http_failed else "not_assessed" if web_hint else "not_indicated",
            "action_ids": [a["id"] for a in http_actions], "failed_action_ids": http_failed,
        }
        if web_hint and not http_ok and "http_headers" in available_tools:
            pending.append({"id": service["id"] + "/http", "service_id": service["id"],
                            "check": "http_headers", "status": service["http"]["status"],
                            "detail": f"HTTP headers on {target}:{port}: {service['http']['status']}."})

        service_lookups = [lookup for lookup in lookups if _cve_applies_to_service(service, lookup)]
        cve_actions = []
        for action in actions:
            if action["tool"] != "cve_lookup" or not action["executed"] or action["target"] != target:
                continue
            params = action.get("params") or {}
            evidence = params.get("_evidence", {})
            query = {**params, "target": target, "version": params.get("version") or evidence.get("version", ""),
                     "observed_services": evidence.get("services", [])}
            if _cve_applies_to_service(service, query):
                cve_actions.append(action)
        cve_failed = [a["id"] for a in cve_actions if a.get("success") == 0]
        identified = bool(service.get("product")) and service.get("identification") != "unresolved"
        service["cve"] = {
            "status": ("checked" if service_lookups else "failed" if cve_failed else "incomplete" if cve_actions
                       else "not_assessed" if identified else "unavailable_product"),
            "action_ids": [a["id"] for a in cve_actions], "failed_action_ids": cve_failed,
            "lookups": [{key: lookup[key] for key in ("product", "version", "candidate_count", "excluded_count", "searches")
                         if key in lookup} for lookup in service_lookups],
        }
        if identified and not service_lookups and "cve_lookup" in available_tools:
            pending.append({"id": service["id"] + "/cve", "service_id": service["id"],
                            "check": "cve_lookup", "status": service["cve"]["status"],
                            "detail": f"Optional CVE enrichment for {service['product']} {service.get('version', '')} "
                                      f"on {target}:{port}: {service['cve']['status']}."})
        followups = [service["http"]["status"], service["cve"]["status"]]
        service["investigation_status"] = "checked" if "checked" in followups else "failed" if "failed" in followups else "discovered"

    target_states = []
    for target in targets:
        attempts = [a for a in actions if a["target"] == target and a["executed"]]
        successful = [a for a in attempts if a.get("success")]
        status = ("checked" if successful else "unknown" if any(a.get("success") is None for a in attempts)
                  else "failed" if attempts else "not_assessed")
        target_states.append({"target": target, "status": status, "successful_actions": len(successful)})
        if not successful:
            pending.append({"id": f"{target}/observation", "check": "target_observation", "status": status,
                            "detail": f"No successful tool result recorded for target {target}."})
    return {"targets": target_states, "services": list(services.values()), "pending_checks": pending,
            "available_tools": available_tools,
            "executed_actions": sum(bool(a["executed"]) for a in actions),
            "failed_actions": [{"id": a["id"], "tool": a["tool"], "target": a["target"], "error": a.get("error", "")}
                               for a in actions if a["executed"] and a.get("success") == 0],
            "note": "Checked means a recorded tool result. Pending checks may be deferred when unnecessary "
                    "for the objective. Tools excluded by the user do not create pending checks."}


def completion_schema(state: dict) -> dict:
    ids = [check["id"] for check in state["pending_checks"]]
    properties = {
        "reason": {"type": "string", "description": "Optional brief reason for stopping. Use 'blocked' if unable to continue."},
    }
    if ids:
        properties["deferred_checks"] = {
            "type": "array", "items": {"type": "string", "enum": ids},
            "uniqueItems": True, "minItems": len(ids), "maxItems": len(ids),
            "description": "Copy all current pending check IDs to defer them.",
        }
    return {
        "name": "finish_recon",
        "description": ("Finish reconnaissance without executing a scanner. The app renders a factual inventory. "
                        + ("Either continue with a useful tool or explicitly defer EVERY pending check. "
                           f"Deferral is allowed; CVE enrichment is optional. Current pending check IDs: {ids}"
                           if ids else "No recorded checks are pending. Call with {} to finish; no deferral list is needed.")),
        "parameters": {"type": "object", "properties": properties,
                       "required": ["deferred_checks"] if ids else [], "additionalProperties": False},
    }


def completion_error(arguments: dict, state: dict) -> str | None:
    if not isinstance(arguments, dict) or set(arguments) - {"reason", "deferred_checks"}:
        return "finish_recon accepts only reason and deferred_checks."
    if "reason" in arguments and not isinstance(arguments["reason"], str):
        return "reason must be text if supplied."
    deferred = arguments.get("deferred_checks", [])
    if not isinstance(deferred, list) or any(not isinstance(item, str) for item in deferred):
        return "deferred_checks must be an array of current pending check IDs."
    expected = {item["id"] for item in state["pending_checks"]}
    if not expected:
        # Stale/invented deferrals add no facts and cannot erase pending work.
        # The loop normalizes them to [] and records the ignored IDs separately.
        return None
    if set(deferred) != expected or len(deferred) != len(set(deferred)):
        return f"Account for every pending check exactly once, or continue investigating. Expected IDs: {sorted(expected)}."
    return None


def render_inventory(state: dict) -> str:
    tools = state.get("available_tools", ["http_headers", "cve_lookup"])
    lines = [f"Results — {state['executed_actions']} executed tool action(s):", ""]
    for target in state["targets"]:
        if target["status"] != "checked":
            lines.append(f"- Target {target['target']}: {target['status'].replace('_', ' ')}.")
    for service in state["services"]:
        identity = " ".join(filter(None, [service.get("product") or service.get("service", "unknown"), service.get("version")]))
        if service.get("identification") == "unresolved":
            identity = f"unresolved service (unverified label: {service.get('service_guess') or 'none'})"
        lines.append(f"- {service['target']}:{service['port']}/{service['protocol']}: {identity}.")
        if service.get("http_title"):
            lines.append(f"  Observed page title: {service['http_title']}.")
        http = service["http"]
        if http["status"] != "not_indicated" and ("http_headers" in tools or http["action_ids"] or http["status"] == "checked"):
            lines.append(f"  HTTP headers: {http['status'].replace('_', ' ')}.")
        cve = service["cve"]
        if "cve_lookup" not in tools and not cve["action_ids"] and not cve["lookups"]:
            continue
        if cve["status"] == "checked":
            for lookup in cve["lookups"]:
                searches = lookup.get("searches", [])
                final = searches[-1] if searches else {}
                lines.append(f"  CVE enrichment: checked; {lookup.get('candidate_count', 'unknown')} unverified candidate(s), "
                             f"{lookup.get('excluded_count', 'unknown')} excluded match(es); reviewed "
                             f"{final.get('reviewed', 'unknown')} of {final.get('total_results', 'unknown')} records in the final query.")
        elif cve["status"] == "unavailable_product":
            lines.append("  CVE enrichment: not assessed; no identified product to ground a lookup.")
        elif cve["status"] == "failed":
            lines.append("  CVE enrichment: failed; no successful lookup evidence recorded.")
        elif cve["status"] == "incomplete":
            lines.append("  CVE enrichment: attempted, but structured lookup evidence is missing.")
        else:
            lines.append("  CVE enrichment: not assessed (lookup not performed).")
    if not state["services"]:
        lines.append("No service inventory was established by the recorded results; this does not imply no services exist.")
    if state["pending_checks"]:
        lines.extend(["", "Checks left unassessed or incomplete:", ""])
        lines.extend(f"- {item['detail'].replace('not_assessed', 'not assessed')}" for item in state["pending_checks"])
    if state["failed_actions"]:
        lines.extend(["", "Failed executed actions:", ""])
        lines.extend(f"- {item['tool']} on {item['target']}: {item['error'] or 'unsuccessful'}." for item in state["failed_actions"])
    if "cve_lookup" in tools or any(s["cve"]["action_ids"] or s["cve"]["lookups"] for s in state["services"]):
        lines.extend(["", "Vulnerability applicability was not verified. Empty or unperformed lookups do not establish absence of vulnerabilities."])
    return "\n".join(lines)
