"""Aegis-AI — CLI entry point.

Usage:
    python -m app.main scan --objective "Map services on the lab host"
    python -m app.main scope          # print & validate current scope
    python -m app.main report --session 1

Human-in-the-loop by default: the agent proposes each action and
asks you to approve before anything runs.
"""

from __future__ import annotations

import argparse
import sys

from app.agent.executor import Action, Executor
from app.agent.loop import AgentLoop
from app.config import load_scope, load_settings
from app.llm.client import LLMClient
from app.memory.audit import AuditLog
from app.memory.database import Database
from app.policy.validator import PolicyValidator
from app.reporting.report import generate_markdown
from app.reporting.pdf import generate_pdf
from app.tools.registry import build_default_registry



def c(text: str, color: str) -> str:
    codes = {"red": 91, "green": 92, "yellow": 93, "blue": 94, "grey": 90, "bold": 1}
    return f"\033[{codes.get(color, 0)}m{text}\033[0m"


def confirm(command: str, rationale: str) -> bool:
    print()
    print(c("  Proposed action", "bold"))
    if rationale:
        print(c(f"   why: {rationale}", "grey"))
    print(c(f"   cmd: {command}", "blue"))
    ans = input(c("   run this? [y/N] ", "yellow")).strip().lower()
    return ans in {"y", "yes"}


def on_event(kind: str, payload) -> None:
    if kind == "targets":
        print(c(f"Targets for this run: {', '.join(payload)}", "blue"))
    elif kind == "interpreting":
        print(c("Interpreting objective…", "grey"))
    elif kind == "intent":
        print(c(f"Model interpretation: {payload['goal']}", "blue"))
        print(c(f"Tools permitted by this interpretation: {', '.join(payload['allowed_tools']) or 'none'}", "blue"))
        if payload['restriction_reason']:
            print(c(f"  Restriction: {payload['restriction_reason']}", "grey"))
        elif not payload['tool_choice_restricted']:
            print(c("  Tool choice remains open; actions will be selected from evidence.", "grey"))
    elif kind == "iteration":
        print(c(f"\n── iteration {payload} ──", "grey"))
    elif kind == "plan":
        print(c(f"  plan: {payload.tool} → {payload.target}", "bold"))
        if payload.rationale:
            print(c(f"   why: {payload.rationale}", "grey"))
        if payload.params:
            print(c(f"   params: {payload.params!r}", "grey"))
    elif kind == "result":
        if payload is None:
            print(c("  (skipped)", "grey"))
        elif payload.success:
            print(c(f"  ✓ {payload.summary}", "green"))
            for f in payload.findings:
                summary = f.get("summary", f)
                if summary != payload.summary:
                    print(c(f"      {summary}", "grey"))
        else:
            print(c(f"  ✗ {payload.summary}", "red"))
    elif kind == "warning":
        print(c(f"  ! {payload}", "yellow"))
    elif kind == "done":
        print(c(f"\n■ {payload}", "bold"))


# ---- commands -----------------------------------------------------------

def _write_reports(db, scope, session_id, output_dir, want_pdf: bool) -> None:
    md_path = generate_markdown(db, scope, session_id, output_dir)
    print(c(f"\nReport written: {md_path}", "green"))
    if want_pdf:
        try:
            pdf_path = generate_pdf(db, scope, session_id, output_dir)
            print(c(f"PDF written:    {pdf_path}", "green"))
        except RuntimeError as exc:
            print(c(f"PDF skipped: {exc}", "yellow"))


def cmd_scope(_args) -> int:
    scope = load_scope()
    validator = PolicyValidator(scope)
    print(c("Engagement:", "bold"), scope.engagement.name)
    print("  authorization:", scope.engagement.authorization_ref)
    print("  window:", scope.engagement.start_date, "→", scope.engagement.end_date)
    win = validator.check_engagement_window()
    print("  window valid:", c("yes", "green") if win else c("no", "red"), f"({win.reason})")
    print("  in-scope hosts:", scope.in_scope_hosts)
    print("  in-scope domains:", scope.in_scope_domains)
    print("  allowed tools:", scope.allowed_tools)
    return 0


def cmd_scan(args) -> int:
    scope = load_scope()
    settings = load_settings()

    validator = PolicyValidator(scope)
    win = validator.check_engagement_window()
    if not win:
        print(c(f"Refusing to run: {win.reason}", "red"))
        return 1

    registry = build_default_registry()
    llm = LLMClient(settings.llm)
    db = Database(settings.db_path)
    audit = AuditLog(settings.audit_log)

    session = db.create_session(name=args.objective, engagement=scope.engagement.name)
    audit.note(f"Session {session.id} started. Objective: {args.objective}")

    require_confirmation = settings.agent.require_confirmation and not args.yes
    if args.yes and settings.agent.require_confirmation:
        print(c("  ! --yes: auto-approving every proposed action for this run.", "yellow"))

    executor = Executor(
        registry=registry,
        validator=validator,
        db=db,
        audit=audit,
        session_id=session.id,
        require_confirmation=require_confirmation,
        confirm_fn=confirm,
    )
    loop = AgentLoop(
        llm=llm,
        registry=registry,
        executor=executor,
        db=db,
        scope=scope,
        session_id=session.id,
        max_iterations=settings.agent.max_iterations,
    )

    print(c(f"Aegis-AI session #{session.id} — {scope.engagement.name}", "bold"))
    print(c(f"Objective: {args.objective}", "grey"))

    completed = False
    try:
        completed = loop.run(args.objective, on_event=on_event)
    except KeyboardInterrupt:
        print(c("\nInterrupted by user.", "yellow"))

    db.close_session(session.id)
    _write_reports(db, scope, session.id, settings.output_dir, want_pdf=args.pdf)
    db.close()
    return 0 if completed else 1


def cmd_multiscan(args) -> int:
    """run nmap across every in-scope host in parallel.

    Each action still passes the policy gate + confirmation inside the
    executor — parallelism doesn't bypass any control.
    """
    scope = load_scope()
    settings = load_settings()
    validator = PolicyValidator(scope)
    if not validator.check_engagement_window():
        print(c("Refusing to run: outside engagement window.", "red"))
        return 1

    registry = build_default_registry()
    db = Database(settings.db_path)
    audit = AuditLog(settings.audit_log)
    session = db.create_session(name="multiscan", engagement=scope.engagement.name)

    require_confirmation = settings.agent.require_confirmation and not args.yes
    if args.yes and settings.agent.require_confirmation:
        print(c("  ! --yes: auto-approving every proposed action for this run.", "yellow"))

    executor = Executor(
        registry=registry, validator=validator, db=db, audit=audit,
        session_id=session.id,
        require_confirmation=require_confirmation,
        confirm_fn=confirm,
    )

    # Build one nmap action per in-scope host (skip CIDR ranges here).
    hosts = [h for h in scope.in_scope_hosts if "/" not in h]
    actions = [Action(tool="nmap", target=h, params={}, rationale="parallel sweep")
               for h in hosts]
    if not actions:
        print(c("No single-host targets in scope (CIDR ranges are skipped here).", "yellow"))
        return 0

    print(c(f"Parallel nmap over {len(actions)} host(s): {hosts}", "bold"))
    workers = min(scope.max_concurrent_actions, len(actions))
    results = executor.execute_parallel(actions, max_workers=workers)
    for r in results:
        tag = "green" if r and r.success else "red"
        print(c(f"  {r.target}: {r.summary}", tag))

    db.close_session(session.id)
    _write_reports(db, scope, session.id, settings.output_dir, want_pdf=args.pdf)
    db.close()
    return 0


def cmd_report(args) -> int:
    scope = load_scope()
    settings = load_settings()
    db = Database(settings.db_path)
    _write_reports(db, scope, args.session, settings.output_dir, want_pdf=args.pdf)
    db.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aegis", description="Authorized pentest orchestration agent.")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="Run the agent toward an objective.")
    s.add_argument("--objective", required=True, help="What you want the agent to accomplish.")
    s.add_argument("--pdf", action="store_true", help="Also write a PDF report.")
    s.add_argument("--yes", "-y", action="store_true",
                    help="Auto-approve every proposed action for this run (skip the y/N prompt). "
                         "Scoped to this run only -- settings.yaml's require_confirmation is untouched.")
    s.set_defaults(func=cmd_scan)

    m = sub.add_parser("multiscan", help="Parallel nmap over all in-scope hosts.")
    m.add_argument("--pdf", action="store_true", help="Also write a PDF report.")
    m.add_argument("--yes", "-y", action="store_true",
                    help="Auto-approve every proposed action for this run (skip the y/N prompt).")
    m.set_defaults(func=cmd_multiscan)

    sc = sub.add_parser("scope", help="Print and validate the current scope.")
    sc.set_defaults(func=cmd_scope)

    r = sub.add_parser("report", help="Regenerate a report for a session.")
    r.add_argument("--session", type=int, required=True)
    r.add_argument("--pdf", action="store_true", help="Also write a PDF report.")
    r.set_defaults(func=cmd_report)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
