"""Sanity tests for the policy gate — the security-critical part.

Run with:  python -m pytest tests/   (or just python tests/test_validator.py)
"""

from datetime import date

from app.config import Engagement, Scope
from app.policy.validator import PolicyValidator


def _scope() -> Scope:
    return Scope(
        engagement=Engagement(
            name="t", client="self", authorization_ref="lab",
            start_date=date(2000, 1, 1), end_date=date(2100, 1, 1),
        ),
        in_scope_hosts=["127.0.0.1", "10.10.10.0/24"],
        in_scope_domains=["localhost"],
        out_of_scope_hosts=["10.10.10.1"],
        out_of_scope_domains=["admin.localhost"],
        allowed_tools=["nmap"],
        max_concurrent_actions=2,
        allowed_ports=[],
        block_destructive=True,
    )


def test_in_scope_ip_allowed():
    v = PolicyValidator(_scope())
    assert v.is_target_authorized("127.0.0.1").allowed
    assert v.is_target_authorized("10.10.10.55").allowed


def test_out_of_scope_ip_denied():
    v = PolicyValidator(_scope())
    assert not v.is_target_authorized("8.8.8.8").allowed


def test_explicit_exclusion_wins():
    v = PolicyValidator(_scope())
    # 10.10.10.1 is inside the /24 but explicitly excluded
    assert not v.is_target_authorized("10.10.10.1").allowed


def test_tool_allowlist():
    v = PolicyValidator(_scope())
    assert v.is_tool_allowed("nmap").allowed
    assert not v.is_tool_allowed("sqlmap").allowed


def test_destructive_blocked():
    v = PolicyValidator(_scope())
    assert not v.is_action_safe("nmap --script=dos 127.0.0.1").allowed
    assert v.is_action_safe("nmap -sV 127.0.0.1").allowed


def test_exact_hostname_under_in_scope_hosts_is_allowed():
    # scope.yaml documents that in_scope.hosts accepts "exact hostnames"
    # in addition to IPs/CIDRs -- make sure that's actually honored.
    scope = _scope()
    scope.in_scope_hosts.append("scanme.nmap.org")
    v = PolicyValidator(scope)
    assert v.is_target_authorized("scanme.nmap.org").allowed


def test_exact_hostname_under_out_of_scope_hosts_is_denied():
    scope = _scope()
    scope.in_scope_hosts.append("scanme.nmap.org")
    scope.out_of_scope_hosts.append("scanme.nmap.org")
    v = PolicyValidator(scope)
    assert not v.is_target_authorized("scanme.nmap.org").allowed


def test_full_validate_action():
    v = PolicyValidator(_scope())
    ok = v.validate_action("nmap", "127.0.0.1", "nmap -sV 127.0.0.1")
    assert ok.allowed
    bad = v.validate_action("nmap", "8.8.8.8", "nmap -sV 8.8.8.8")
    assert not bad.allowed


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"ok  {name}")
    print("all passed")
