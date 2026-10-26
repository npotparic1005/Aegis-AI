"""Report generation.

Turns the session's stored findings and action trail into a clean
Markdown report. Kept dependency-free (plain Markdown) so it works
anywhere; convert to PDF later with e.g. pandoc or weasyprint.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

from app.config import Scope
from app.memory.database import Database


def generate_markdown(db: Database, scope: Scope, session_id: int, output_dir: str) -> str:
    findings = db.get_findings(session_id)
    actions = db.get_actions(session_id)
    eng = scope.engagement

    lines: list[str] = []
    lines.append(f"# Penetration Test Report — {eng.name}")
    lines.append("")
    lines.append(f"*Generated: {datetime.now(timezone.utc).isoformat()}*")
    lines.append("")
    lines.append("## Engagement")
    lines.append("")
    lines.append(f"- **Client:** {eng.client}")
    lines.append(f"- **Authorization:** {eng.authorization_ref}")
    lines.append(f"- **Window:** {eng.start_date} → {eng.end_date}")
    lines.append(f"- **In-scope hosts:** {', '.join(scope.in_scope_hosts) or '—'}")
    lines.append(f"- **In-scope domains:** {', '.join(scope.in_scope_domains) or '—'}")
    lines.append("")

    context = db.get_run_context(session_id)
    intent = context.get("intent")
    if intent:
        lines.extend(["## Objective and model interpretation", "",
                      f"- **User objective:** {context['objective']}",
                      f"- **Interpreted goal:** {intent['goal']}",
                      f"- **Tools permitted by this interpretation:** {', '.join(intent['allowed_tools']) or 'none'}",
                      f"- **Restriction:** {intent['restriction_reason'] or ('Explanation not supplied.' if intent.get('tool_choice_restricted', True) else 'Tool choice remains open.')}", ""])

    lines.append("## Summary")
    lines.append("")
    executed = [a for a in actions if a["executed"]]
    lines.append(f"- Actions executed: **{len(executed)}**")
    lines.append(f"- Findings recorded: **{len(findings)}**")
    lines.append("")

    conclusion = db.get_conclusion(session_id)
    if conclusion:
        lines.extend(["## Recorded conclusion", "", conclusion["summary"], ""])

    lines.append("## Findings")
    lines.append("")
    if not findings:
        lines.append("_No findings recorded._")
    else:
        lines.append("| Host | Detail |")
        lines.append("|------|--------|")
        for f in findings:
            detail = f["summary"].replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {f['host']} | {detail} |")
    lines.append("")

    lookups = [f["data"] for f in findings if f.get("data", {}).get("kind") == "cve_lookup"]
    if lookups:
        lines.extend(["## CVE lookup evidence", "",
                      "CVE candidates are unverified. Search matches, version matches and severity scores "
                      "do not confirm vulnerability applicability. Empty searches do not prove absence of vulnerabilities.", ""])
        for lookup in lookups:
            lines.extend([f"### {lookup['host']} — {lookup['product']} {lookup['version']}", "",
                          lookup["summary"], "", lookup["coverage_note"], "",
                          f"Source: {lookup['source']} (retrieved {lookup['retrieved_at']})", ""])
            for search in lookup["searches"]:
                lines.append(f"- Query: `{search['query']}`; HTTP {search['status']}; "
                             f"reviewed {search.get('reviewed', 'unknown')} of {search.get('total_results', 'unknown')} "
                             f"records; truncated: {search.get('truncated', 'unknown')}.")
            lines.append("")
            for excluded in lookup["excluded_matches"]:
                lines.append(f"- Excluded [{excluded['cve']}]({excluded['source']}): {excluded['reason']}")
            lines.append("")
        for f in findings:
            data = f.get("data", {})
            if data.get("kind") == "cve_candidate":
                lines.extend([f"### Candidate [{data['cve']}]({data['source']}) — unverified", "",
                              data["reason"], "", data["description"], ""])

    lines.append("## Action Log (audit)")
    lines.append("")
    lines.append("| Time | Tool | Target | Policy | Executed |")
    lines.append("|------|------|--------|--------|----------|")
    for a in actions:
        pol = "allow" if a["policy_ok"] else "DENY"
        ex = "yes" if a["executed"] else "no"
        lines.append(
            f"| {a['created_at']} | {a['tool']} | {a['target']} | {pol} | {ex} |"
        )
    lines.append("")

    os.makedirs(output_dir, exist_ok=True)
    filename = f"report_session_{session_id}.md"
    path = os.path.join(output_dir, filename)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return path
