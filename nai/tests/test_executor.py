"""Tests for the executor's finding-description logic and safeguards.

Run:  PYTHONPATH=. python tests/test_executor.py
"""

import tempfile
from datetime import date

from app.agent.executor import Action, Executor
from app.config import Engagement, Scope
from app.memory.audit import AuditLog
from app.memory.database import Database
from app.policy.validator import PolicyValidator
from app.tools.registry import discover_tools


def _make_executor(confirm: bool):
    """A real Executor wired to a throwaway DB, with confirm_fn fixed so
    tests never actually reach a tool's run() (no live network calls)."""
    tmp = tempfile.mkdtemp()
    db = Database(f"{tmp}/t.db")
    audit = AuditLog(f"{tmp}/audit.log")
    scope = Scope(
        engagement=Engagement(name="t", client="self", authorization_ref="lab",
                               start_date=date(2000, 1, 1), end_date=date(2100, 1, 1)),
        in_scope_hosts=["127.0.0.1"], in_scope_domains=[], out_of_scope_hosts=[],
        out_of_scope_domains=[], allowed_tools=["nmap", "cve_lookup"],
        max_concurrent_actions=1, allowed_ports=[], block_destructive=True,
    )
    session = db.create_session(name="t", engagement="t")
    executor = Executor(
        registry=discover_tools(), validator=PolicyValidator(scope), db=db, audit=audit,
        session_id=session.id, require_confirmation=True, confirm_fn=lambda cmd, why: confirm,
    )
    return executor, db, session


def test_cve_lookup_rejected_when_product_never_discovered():
    executor, _db, _session = _make_executor(confirm=False)
    action = Action(tool="cve_lookup", target="127.0.0.1",
                     params={"product": "Apache HTTP Server", "version": "2.4.41"},
                     rationale="test")
    result = executor.execute(action)
    assert result is not None and result.error == "ungrounded"


def test_cve_lookup_passes_grounding_after_matching_nmap_finding():
    executor, db, session = _make_executor(confirm=False)
    db.add_finding(session.id, None, host="127.0.0.1", summary="msrpc",
                    data={"product": "Microsoft Windows RPC", "service": "msrpc"})
    action = Action(tool="cve_lookup", target="127.0.0.1",
                     params={"product": "Microsoft Windows RPC"}, rationale="test")
    result = executor.execute(action)
    # confirm_fn declines -- proves this got PAST validate_params/grounding/
    # dedup/policy (those return a ToolResult, not None) without ever
    # reaching tool.run() (no live NVD call in a unit test).
    assert result is None


def test_describe_prefers_finding_summary():
    # cve_lookup / zap / dns_lookup / whois / http_headers all already
    # build a proper "summary" in their finding dicts -- use it instead
    # of falling through to a raw dict repr.
    finding = {"host": "10.0.0.5", "cve": "CVE-2020-1234", "summary": "Something bad"}
    assert Executor._describe(finding) == "Something bad"


def test_describe_falls_back_to_nmap_port_shape():
    finding = {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "version": "2.4.7"}
    assert Executor._describe(finding) == "80/tcp open http 2.4.7"


def test_describe_falls_back_to_raw_dict_when_neither_present():
    finding = {"host": "x", "weird_field": "value"}
    assert "weird_field" in Executor._describe(finding)


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"ok  {name}")
    print("all passed")
