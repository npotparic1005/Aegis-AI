"""PDF report generation (Day 9).

Builds a clean PDF from the same session data as the Markdown report,
using fpdf2 (lightweight, pure Python, no system deps):

    pip install fpdf2

If fpdf2 isn't installed, callers should fall back to the Markdown
report and convert it later (e.g. with pandoc).
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

from app.config import Scope
from app.memory.database import Database


def generate_pdf(db: Database, scope: Scope, session_id: int, output_dir: str) -> str:
    try:
        from fpdf import FPDF
    except ImportError as exc:
        raise RuntimeError("fpdf2 not installed (pip install fpdf2).") from exc

    findings = db.get_findings(session_id)
    actions = db.get_actions(session_id)
    eng = scope.engagement

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # ---- title ----
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 12, _ascii(f"Penetration Test Report — {eng.name}"), ln=True)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(120)
    pdf.cell(0, 6, f"Generated: {datetime.now(timezone.utc).isoformat()}", ln=True)
    pdf.set_text_color(0)
    pdf.ln(4)

    # ---- engagement ----
    _heading(pdf, "Engagement")
    for label, value in [
        ("Client", eng.client),
        ("Authorization", eng.authorization_ref),
        ("Window", f"{eng.start_date} to {eng.end_date}"),
        ("In-scope hosts", ", ".join(scope.in_scope_hosts) or "-"),
        ("In-scope domains", ", ".join(scope.in_scope_domains) or "-"),
    ]:
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(45, 6, _ascii(label))
        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(0, 6, _ascii(str(value)), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    # ---- summary ----
    executed = [a for a in actions if a["executed"]]
    _heading(pdf, "Summary")
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, f"Actions executed: {len(executed)}", ln=True)
    pdf.cell(0, 6, f"Findings recorded: {len(findings)}", ln=True)
    pdf.ln(2)

    # ---- findings ----
    _heading(pdf, "Findings")
    if not findings:
        pdf.set_font("Helvetica", "I", 10)
        pdf.cell(0, 6, "No findings recorded.", ln=True)
    else:
        _row(pdf, ["Host", "Detail"], header=True, widths=[45, 145])
        for f in findings:
            _row(pdf, [f["host"], f["summary"]], widths=[45, 145])
    pdf.ln(2)

    # ---- audit ----
    _heading(pdf, "Action Log (audit)")
    _row(pdf, ["Tool", "Target", "Policy", "Exec"], header=True,
         widths=[35, 70, 45, 40])
    for a in actions:
        _row(pdf, [
            a["tool"], a["target"],
            "allow" if a["policy_ok"] else "DENY",
            "yes" if a["executed"] else "no",
        ], widths=[35, 70, 45, 40])

    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, f"report_session_{session_id}.pdf")
    pdf.output(path)
    return path


# ---- small helpers -------------------------------------------------------

def _heading(pdf, text: str) -> None:
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_fill_color(240)
    pdf.cell(0, 8, _ascii(text), ln=True, fill=True)
    pdf.ln(1)


def _row(pdf, cells: list[str], widths: list[int], header: bool = False) -> None:
    pdf.set_font("Helvetica", "B" if header else "", 9)
    if header:
        pdf.set_fill_color(230)
    line_h = 6
    for text, w in zip(cells, widths):
        pdf.cell(w, line_h, _ascii(str(text))[: int(w / 1.9)], border=1,
                 fill=header)
    pdf.ln(line_h)


def _ascii(text: str) -> str:
    """fpdf core fonts are latin-1; drop anything they can't render."""
    return text.encode("latin-1", "replace").decode("latin-1")
