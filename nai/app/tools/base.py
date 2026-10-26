"""Base contract every tool must satisfy.

A Tool wraps an external, standard security utility (nmap, ZAP,
etc.). The tool NEVER decides whether it may run -- that is the
executor's job, gated by the policy validator. A tool just knows
how to build a command, run it, normalise the output, describe its
own parameters, and say when two proposed calls are "the same step".

`params_schema` + `usage_notes` are the tool's self-description --
the "skill" data the LLM planner sees. Nothing tool-specific should
ever need to live in the agent loop; if the model needs to know
something about how to use a tool, it belongs here.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from app.agent.targets import Target

_SKILLS_DIR = os.path.join(os.path.dirname(__file__), "skills")


def _hashable(value: Any) -> Any:
    """Make a JSON-ish value (str/int/bool/list/dict/None) hashable and
    comparison-stable, so it can go into a dedup key. Array/object-valued
    params (e.g. dns_lookup's `types: [...]`) would otherwise crash `in a
    set`; string values are normalized (strip/lower) so a model resending
    "value " or "VALUE" isn't treated as a brand-new, distinct call."""
    if isinstance(value, list):
        return tuple(_hashable(v) for v in value)
    if isinstance(value, dict):
        return tuple(sorted((k, _hashable(v)) for k, v in value.items()))
    if isinstance(value, str):
        return value.strip().lower()
    return value


@dataclass
class ToolResult:
    tool: str
    target: str
    success: bool
    summary: str
    findings: list[dict[str, Any]] = field(default_factory=list)
    raw_output: str = ""
    error: str = ""


class Tool(ABC):
    #: Short unique name, referenced from scope.yaml allowed_tools and
    #: used as the tool-call function name.
    name: str = "base"
    #: One-line description of what the tool does.
    description: str = ""
    #: Filename under app/tools/skills/ holding this tool's "skill" --
    #: a markdown doc explaining when/how to use it, what each
    #: parameter means, and common failure modes. Defaults to
    #: "<name>.md" so a tool + its skill file is the entire extension
    #: point; override only if you want a different filename.
    skill_file: str = ""
    #: JSON-schema fragment for this tool's own parameters, as
    #: {"properties": {...}, "required": [...]}. `target` and
    #: `rationale` are added automatically by full_schema() -- don't
    #: repeat them here.
    params_schema: dict[str, Any] = {}
    #: True only when dedup_key depends on the target alone. Lets the planner
    #: stop offering targets whose execution slot has already been consumed.
    single_run_per_target: bool = False

    def __init__(self) -> None:
        self.usage_notes = self._load_skill(self.skill_file or f"{self.name}.md")

    @staticmethod
    def _load_skill(filename: str) -> str:
        try:
            with open(os.path.join(_SKILLS_DIR, filename), "r", encoding="utf-8") as fh:
                return fh.read().strip()
        except FileNotFoundError:
            return ""

    @abstractmethod
    def command_preview(self, target: str, **params: Any) -> str:
        """Return the exact command that WOULD run, as a string.

        Used for human confirmation and for the policy destructive-action
        check. Building this must have no side effects.
        """

    @abstractmethod
    def run(self, target: str, **params: Any) -> ToolResult:
        """Actually execute against an already-authorized target."""

    def dedup_key(self, target: str, params: dict[str, Any]) -> tuple:
        """Identity used to refuse re-proposing "the same step" in a session.

        Default: same tool + same target + same params. Override this
        when a tool's identity is coarser than that -- e.g. nmap only
        makes sense once per host regardless of which params were used.
        """
        return (self.name, _hashable(target), tuple(sorted((k, _hashable(v)) for k, v in params.items())))

    def target_defaults(self, target: Target) -> dict[str, Any]:
        """Optional URL details this tool can use when parameters are omitted."""
        return {}

    def validate_params(self, params: dict[str, Any]) -> str | None:
        """Check `params` against params_schema; return an error message,
        or None if they're fine.

        Not a substitute for the policy gate -- this catches missing fields,
        incorrect JSON types and out-of-enum values before a call ever
        reaches command_preview()/run(), since a tool-calling model can
        still occasionally return something that doesn't match its own
        declared schema.
        """
        if not isinstance(params, dict):
            return "Tool parameters must be a JSON object."
        properties = self.params_schema.get("properties", {})
        for req in self.params_schema.get("required", []):
            if req not in params:
                return f"Missing required parameter '{req}'."
        for key, value in params.items():
            spec = properties.get(key)
            if spec is None:
                return f"Unknown parameter '{key}'. Valid parameters: {list(properties)}."
            error = self._validate_value(key, value, spec)
            if error:
                return error
        return None

    @staticmethod
    def _validate_value(key: str, value: Any, spec: dict) -> str | None:
        types = {"string": str, "integer": int, "boolean": bool, "array": list, "object": dict}
        kind = spec.get("type")
        if kind in types and type(value) is not types[kind]:
            return f"'{key}' must be a JSON {kind}, got {value!r}."
        if "enum" in spec and value not in spec["enum"]:
            return f"'{key}' must be one of {spec['enum']}, got {value!r}."
        if kind == "integer":
            if "minimum" in spec and value < spec["minimum"]:
                return f"'{key}' must be at least {spec['minimum']}."
            if "maximum" in spec and value > spec["maximum"]:
                return f"'{key}' must be at most {spec['maximum']}."
        if kind == "array":
            for index, item in enumerate(value):
                error = Tool._validate_value(f"{key}[{index}]", item, spec.get("items", {}))
                if error:
                    return error
        return None

    def execution_context(self, target: str, params: dict[str, Any], prior_findings: list[dict[str, Any]]) -> dict:
        """Trusted recorded evidence for execution; never supplied by the model."""
        return {}

    def grounding_check(self, params: dict[str, Any], prior_findings: list[dict[str, Any]],
                        target: str | None = None) -> str | None:
        """Return an error message if this call ISN'T grounded in what's
        actually been discovered so far this session, or None if it's
        fine (including: this tool doesn't need grounding at all).

        Default: no requirement. Most tools (nmap, dns_lookup, whois,
        http_headers) operate directly on the target, not on a claimed
        prior discovery -- there's nothing to cross-check. Override this
        for a tool whose parameters assert that something should already
        be known (e.g. cve_lookup's `product`), so the model can't query
        it for a service that was never actually found.
        """
        return None

    def target_applicable(self, target: str, in_scope_domains: list[str]) -> str | None:
        """Return an error message if this tool doesn't apply to `target`
        at all, or None if it's fine (including: this tool has no
        target restriction).

        Default: no restriction -- most tools work against whatever
        host/domain they're pointed at. Override this for a tool that
        only makes sense against a real domain (whois, dns_lookup), so
        a call against a bare IP or a plausible-looking domain that was
        never actually the engagement's is rejected before it ever
        runs, rather than wasting a call the policy gate would reject
        anyway (or, worse, a fabricated domain that happens to slip
        past scope checks).
        """
        return None

    def full_schema(self) -> dict[str, Any]:
        """Provider-agnostic tool-call definition for the LLM planner.

        Shape: {"name", "description", "parameters": <json schema>}.
        Each LLMClient provider adapter translates this into its own
        wire format (Anthropic's input_schema, OpenAI/Ollama's
        function.parameters).
        """
        properties = {
            "target": {
                "type": "string",
                "description": "A host from this run's validated targets. Copy it exactly; always include this field.",
            },
            "rationale": {
                "type": "string",
                "description": "One short sentence: why this step, now.",
            },
        }
        properties.update(self.params_schema.get("properties", {}))
        required = ["target", "rationale", *self.params_schema.get("required", [])]
        return {
            "name": self.name,
            "description": f"{self.description} {self.usage_notes}".strip(),
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
                "additionalProperties": False,
            },
        }
