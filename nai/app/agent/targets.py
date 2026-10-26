"""Literal targets for one reconnaissance run, independent of tool selection.

Recognize explicit addresses in the objective without consulting the model or
resolving DNS. The engagement allowlist authorizes targets; it never supplies
a replacement for a target missing from the objective.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass
from urllib.parse import urlsplit

from app.policy.validator import PolicyValidator


class TargetError(ValueError):
    def __init__(self, message: str, code: str = "invalid_target") -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Target:
    host: str
    scheme: str | None = None
    port: int | None = None
    path: str | None = None

    def context(self) -> dict:
        return {key: value for key, value in asdict(self).items() if value is not None}


def parse_target(value: str) -> Target:
    """Separate an IPv4 address / hostname from optional HTTP URL details."""
    if not isinstance(value, str) or not value.strip():
        raise TargetError("Supply a non-empty host, IPv4 address, or HTTP(S) URL.")
    value = value.strip()
    if any(char.isspace() or ord(char) < 32 for char in value) or "\\" in value:
        raise TargetError("A target must be one address without whitespace or backslashes.")
    is_url = "://" in value
    try:
        parts = urlsplit(value if is_url else "//" + value)
        host = parts.hostname
        port = parts.port  # also validates malformed/out-of-range ports
    except ValueError as exc:
        raise TargetError(f"Invalid target {value!r}: {exc}") from exc
    if is_url and parts.scheme.lower() not in {"http", "https"}:
        raise TargetError("Only HTTP(S) URLs are supported; otherwise supply a host/IP.")
    if parts.username is not None or parts.password is not None:
        raise TargetError("Supply the target without URL credentials.")
    if not is_url and (parts.path or parts.query or parts.fragment):
        raise TargetError("Use an HTTP(S) URL for a path, or individual hosts instead of a range.")
    if not host:
        raise TargetError(f"No hostname in target {value!r}.")
    host = host.lower().rstrip(".")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if re.fullmatch(r"[\d.]+", host):
            raise TargetError(f"Invalid IPv4 address {host!r}.")
        labels = host.split(".")
        if len(host) > 253 or not all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in labels
        ):
            raise TargetError(f"Invalid hostname {host!r}.")
    else:
        if address.version != 4:
            raise TargetError("IPv6 targets are not supported by this reconnaissance workflow yet.")
        host = str(address)
    if port is not None and port < 1:
        raise TargetError("A target port must be between 1 and 65535.")
    if parts.netloc.endswith(":"):
        raise TargetError("Supply a number after the target's port separator.")
    path = None
    if is_url:
        path = (parts.path or "/") + ("?" + parts.query if parts.query else "")
    return Target(host, parts.scheme.lower() if is_url else None, port, path)


_URL = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s<>\"`]+", re.IGNORECASE)
_HOST = re.compile(
    r"(?<![\w@./:-])(?:localhost|(?:[a-z0-9][a-z0-9-]*\.)+[a-z0-9][a-z0-9-]*)"
    r"\.?(?::\d+)?(?:/\d+)?(?![\w./:-])",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class RunTargets:
    entries: tuple[Target, ...]

    @property
    def hosts(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(target.host for target in self.entries))

    @classmethod
    def from_objective(cls, objective: str, validator: PolicyValidator) -> RunTargets:
        candidates: list[tuple[int, str]] = []
        # Mask URLs so their hosts/path components are not counted a second time.
        remaining = objective
        for match in _URL.finditer(objective):
            candidates.append((match.start(), match.group().rstrip(".,;!?)']}")))
            remaining = remaining[:match.start()] + " " * len(match.group()) + remaining[match.end():]
        for match in _HOST.finditer(remaining):
            value = match.group()
            # A dotted software version such as 10.3 or 1.30.4 is not an IP.
            if re.fullmatch(r"\d+(?:\.\d+){1,2}", value.rstrip(".")):
                continue
            candidates.append((match.start(), value))
        # Recognize single-label lab hostnames only when literally named and
        # explicitly configured. Never infer one from "the lab" / "all targets".
        names = [*validator.scope.in_scope_hosts, *validator.scope.in_scope_domains]
        for name in names:
            if re.fullmatch(r"[a-zA-Z][a-zA-Z0-9-]*", name):
                pattern = rf"(?<![\w@./:-]){re.escape(name)}\.?(:\d+)?(?![\w./:-])"
                candidates.extend((m.start(), m.group()) for m in re.finditer(pattern, remaining, re.I))
        if not candidates:
            raise TargetError(
                "No explicit target found in the objective. Name a host, IPv4 address, "
                "or HTTP(S) URL, for example 'Reconnaissance of 127.0.0.1'. "
                "Targets are not inferred from scope.yaml.",
                "missing_target",
            )
        entries = tuple(dict.fromkeys(parse_target(value) for _, value in sorted(candidates)))
        for host in dict.fromkeys(target.host for target in entries):
            decision = validator.is_target_authorized(host)
            if not decision.allowed:
                raise TargetError(
                    f"Requested target {host!r} is not authorized: {decision.reason} "
                    "Check the objective and scope.yaml. No substitute target will be used.",
                    "policy_denied",
                )
        return cls(entries)

    def resolve(self, value: str | None) -> tuple[Target, list[str]]:
        notes = []
        if value is None or (isinstance(value, str) and not value.strip()):
            if len(self.hosts) != 1:
                raise TargetError(
                    f"Missing target: this run has multiple hosts {list(self.hosts)}. "
                    "Resubmit the tool call with one explicit target from this list.",
                    "missing_target",
                )
            value = self.hosts[0]
            notes.append(f"Filled missing target from the validated run target: {value}.")
        target = parse_target(value)
        if target.host not in self.hosts:
            raise TargetError(
                f"Target {target.host!r} was not requested for this run. "
                f"Use one of {list(self.hosts)}; global scope does not add targets to this run.",
                "target_mismatch",
            )
        if value != target.host:
            notes.append(f"Normalized target {value!r} to host {target.host!r}.")
        # Keep a unique objective URL as context when the call supplies just its
        # hostname. Multiple URLs on the same host require explicit parameters.
        if target.scheme is None and target.port is None:
            endpoints = [entry for entry in self.entries if entry.host == target.host
                         and (entry.scheme is not None or entry.port is not None)]
            if len(endpoints) == 1:
                target = endpoints[0]
        return target, notes
