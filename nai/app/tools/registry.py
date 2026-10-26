"""Tool registry -- with real auto-discovery.

Every module under app/tools/ is imported once; any class that
subclasses Tool (and isn't the base itself) is instantiated and
registered under its `.name`. Adding a tool is exactly: drop a new
file in this package that defines a Tool subclass. Nothing else --
not this file, not the agent loop -- needs to change.

scope.yaml's `allowed_tools` then decides which of the *discovered*
tools are actually enabled for a given engagement: the LLM planner
only ever sees schemas for enabled tools, and the executor's policy
gate is the second, independent check that nothing else can run.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil

from app.config import Scope
from app.tools.base import Tool


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        if tool.name in self._tools:
            raise ValueError(f"Tool '{tool.name}' already registered.")
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def all(self) -> list[Tool]:
        return list(self._tools.values())

    def names(self) -> list[str]:
        return list(self._tools.keys())

    def enabled(self, scope: Scope) -> list[Tool]:
        """Tools this engagement's scope.yaml has switched on."""
        return [t for t in self._tools.values() if t.name in scope.allowed_tools]

    def enabled_schemas(self, scope: Scope, targets: list[str] | None = None) -> list[dict]:
        """Limit each schema to applicable run targets; execution still validates."""
        schemas = []
        for tool in self.enabled(scope):
            applicable = None if targets is None else [
                host for host in targets if tool.target_applicable(host, scope.in_scope_domains) is None]
            if applicable == []:
                continue
            schema = tool.full_schema()
            if applicable is not None:
                schema["parameters"]["properties"]["target"]["enum"] = applicable
            schemas.append(schema)
        return schemas


def discover_tools() -> ToolRegistry:
    """Import every module in app.tools and register any Tool subclass found."""
    import app.tools as tools_pkg

    registry = ToolRegistry()
    for _, module_name, _ in pkgutil.iter_modules(tools_pkg.__path__):
        if module_name in ("base", "registry"):
            continue
        module = importlib.import_module(f"app.tools.{module_name}")
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, Tool)
                and obj is not Tool
                and obj.__module__ == module.__name__
            ):
                registry.register(obj())
    return registry


def build_default_registry() -> ToolRegistry:
    """Back-compat name for discover_tools()."""
    return discover_tools()
