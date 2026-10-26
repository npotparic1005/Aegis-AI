"""Configuration loading for Aegis-AI.

Loads scope.yaml and settings.yaml into typed objects so the rest
of the app never touches raw dicts. Fails loudly if the scope
file is missing or malformed — you should never run without an
explicit, valid scope.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import date
from typing import Any

import yaml

CONFIG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config")


@dataclass
class Engagement:
    name: str
    client: str
    authorization_ref: str
    start_date: date
    end_date: date


@dataclass
class Scope:
    engagement: Engagement
    in_scope_hosts: list[str]
    in_scope_domains: list[str]
    out_of_scope_hosts: list[str]
    out_of_scope_domains: list[str]
    allowed_tools: list[str]
    max_concurrent_actions: int
    allowed_ports: list[int]
    block_destructive: bool
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class LLMConfig:
    provider: str
    model: str
    base_url: str
    temperature: float
    max_tokens: int
    timeout: int


@dataclass
class AgentConfig:
    require_confirmation: bool
    max_iterations: int


@dataclass
class Settings:
    llm: LLMConfig
    agent: AgentConfig
    db_path: str
    audit_log: str
    output_dir: str


def _read_yaml(path: str) -> dict[str, Any]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Required config not found: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"Malformed config (expected a mapping): {path}")
    return data


def load_scope(path: str | None = None) -> Scope:
    path = path or os.path.join(CONFIG_DIR, "scope.yaml")
    data = _read_yaml(path)

    eng = data.get("engagement", {})
    try:
        engagement = Engagement(
            name=eng["name"],
            client=eng.get("client", "unknown"),
            authorization_ref=eng["authorization_ref"],
            start_date=_as_date(eng["start_date"]),
            end_date=_as_date(eng["end_date"]),
        )
    except KeyError as exc:
        raise ValueError(f"scope.yaml missing required engagement field: {exc}")

    in_scope = data.get("in_scope", {}) or {}
    oos = data.get("out_of_scope", {}) or {}
    constraints = data.get("constraints", {}) or {}

    return Scope(
        engagement=engagement,
        in_scope_hosts=list(in_scope.get("hosts", []) or []),
        in_scope_domains=list(in_scope.get("domains", []) or []),
        out_of_scope_hosts=list(oos.get("hosts", []) or []),
        out_of_scope_domains=list(oos.get("domains", []) or []),
        allowed_tools=list(data.get("allowed_tools", []) or []),
        max_concurrent_actions=int(constraints.get("max_concurrent_actions", 1)),
        allowed_ports=list(constraints.get("allowed_ports", []) or []),
        block_destructive=bool(constraints.get("block_destructive", True)),
        raw=data,
    )


def load_settings(path: str | None = None) -> Settings:
    path = path or os.path.join(CONFIG_DIR, "settings.yaml")
    data = _read_yaml(path)

    llm = data.get("llm", {})
    agent = data.get("agent", {})
    storage = data.get("storage", {})
    reporting = data.get("reporting", {})

    return Settings(
        llm=LLMConfig(
            provider=llm.get("provider", "anthropic"),
            model=llm.get("model", "claude-sonnet-4-5"),
            base_url=llm.get("base_url", "http://localhost:11434"),
            temperature=float(llm.get("temperature", 0.2)),
            max_tokens=int(llm.get("max_tokens", 1500)),
            timeout=int(llm.get("timeout", 600)),
        ),
        agent=AgentConfig(
            require_confirmation=bool(agent.get("require_confirmation", True)),
            max_iterations=int(agent.get("max_iterations", 25)),
        ),
        db_path=storage.get("db_path", "aegis.db"),
        audit_log=storage.get("audit_log", "audit.log"),
        output_dir=reporting.get("output_dir", "reports"),
    )


def _as_date(value: Any) -> date:
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value))
