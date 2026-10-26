"""Provider-agnostic LLM client -- native tool-calling only.

Every supported provider (Anthropic, OpenAI, Ollama) is driven through
its own function/tool-calling contract instead of prompting the model
to emit ad-hoc JSON that we then have to parse out of prose. This
assumes the configured model was actually trained for tool use --
Claude and GPT models always are, and so are common open-weight models
served through Ollama (Qwen2.5, Llama 3.1+, Mistral Nemo, Command-R,
...). Point this at a model that doesn't support tool calling and it
will simply never call a tool.

The wire format for tool calls differs per provider, so `Turn` /
`ToolCall` are a small provider-agnostic representation of the
conversation. Each `_xxx_plan` method translates that generic history
into its own provider's shape and back. The client has NO knowledge of
pentest logic, scope, or which actions are allowed -- that lives in
the policy layer. Keeping this dumb keeps the security boundary clean.

  ANTHROPIC_API_KEY   for provider: anthropic
  OPENAI_API_KEY      for provider: openai
  (ollama needs no key; it talks to base_url)
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, field
from typing import Any

from app.config import LLMConfig


class LLMError(RuntimeError):
    pass


@dataclass
class ToolCall:
    call_id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class PlanResponse:
    tool_calls: list[ToolCall] = field(default_factory=list)
    text: str = ""


@dataclass
class Turn:
    """One entry in the planning conversation.

    kind is one of:
      "user"           -- context/objective text
      "assistant_call"  -- a tool call the model made
      "tool_result"      -- what running that call produced
    """

    kind: str
    content: str = ""
    call_id: str = ""
    name: str = ""
    arguments: dict[str, Any] = field(default_factory=dict)


class LLMClient:
    def __init__(self, cfg: LLMConfig) -> None:
        self.cfg = cfg
        self.provider = cfg.provider.lower()

    def plan(self, system: str, tools: list[dict[str, Any]], turns: list[Turn]) -> PlanResponse:
        """Ask the model for the next tool call(s), given the full history so far.

        `tools` are provider-agnostic definitions from Tool.full_schema():
        {"name", "description", "parameters": <json schema>}.
        """
        if self.provider == "anthropic":
            return self._anthropic_plan(system, tools, turns)
        if self.provider == "openai":
            return self._openai_plan(system, tools, turns)
        if self.provider == "ollama":
            return self._ollama_plan(system, tools, turns)
        raise LLMError(f"Unknown provider: {self.provider}")

    def complete(self, system: str, user: str) -> str:
        """Plain text completion, no tools -- used for the closing risk analysis."""
        if self.provider == "anthropic":
            return self._anthropic_text(system, user)
        if self.provider == "openai":
            return self._openai_text(system, user)
        if self.provider == "ollama":
            return self._ollama_text(system, user)
        raise LLMError(f"Unknown provider: {self.provider}")

    def analyze_findings(self, objective: str, findings: list) -> str:
        """Read every finding and write a human-language risk analysis."""
        system = (
            "You are a senior penetration tester writing the analysis section "
            "of a report. Given raw findings from an authorized scan, write a "
            "clear, professional risk analysis: what was found, which findings "
            "matter most and why, security implications, and concrete "
            "remediation recommendations. Group by severity. Be concise and "
            "factual. Write in prose, not JSON."
        )
        user = (
            f"Engagement objective: {objective}\n\n"
            f"Findings:\n{json.dumps(findings, indent=2, default=str)}\n\n"
            "Write the risk analysis."
        )
        try:
            return self.complete(system, user)
        except Exception as exc:
            short = str(exc).split(chr(10))[0][:120]
            return f"(AI analysis unavailable: {short})"

    # ---- Anthropic ------------------------------------------------------

    def _anthropic_client(self):
        try:
            import anthropic
        except ImportError as exc:
            raise LLMError("pip install anthropic") from exc
        key = os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise LLMError("ANTHROPIC_API_KEY not set.")
        return anthropic.Anthropic(api_key=key, timeout=float(self.cfg.timeout))

    def _anthropic_plan(self, system: str, tools: list[dict], turns: list[Turn]) -> PlanResponse:
        client = self._anthropic_client()
        messages: list[dict[str, Any]] = []
        for t in turns:
            if t.kind == "user":
                messages.append({"role": "user", "content": t.content})
            elif t.kind == "assistant_call":
                messages.append({
                    "role": "assistant",
                    "content": [{"type": "tool_use", "id": t.call_id, "name": t.name, "input": t.arguments}],
                })
            elif t.kind == "tool_result":
                messages.append({
                    "role": "user",
                    "content": [{"type": "tool_result", "tool_use_id": t.call_id, "content": t.content}],
                })

        anth_tools = [
            {"name": tool["name"], "description": tool["description"], "input_schema": tool["parameters"]}
            for tool in tools
        ]
        try:
            msg = client.messages.create(
                model=self.cfg.model,
                max_tokens=self.cfg.max_tokens,
                temperature=self.cfg.temperature,
                system=system,
                tools=anth_tools,
                messages=messages,
            )
        except Exception as exc:
            raise LLMError(f"Anthropic request failed: {exc}") from exc

        calls: list[ToolCall] = []
        text_parts: list[str] = []
        for block in msg.content:
            if block.type == "tool_use":
                calls.append(ToolCall(call_id=block.id, name=block.name, arguments=block.input or {}))
            elif block.type == "text":
                text_parts.append(block.text)
        return PlanResponse(tool_calls=calls, text="".join(text_parts))

    def _anthropic_text(self, system: str, user: str) -> str:
        client = self._anthropic_client()
        msg = client.messages.create(
            model=self.cfg.model,
            max_tokens=self.cfg.max_tokens,
            temperature=self.cfg.temperature,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(block.text for block in msg.content if block.type == "text")

    # ---- OpenAI -----------------------------------------------------------

    def _openai_client(self):
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise LLMError("pip install openai") from exc
        key = os.environ.get("OPENAI_API_KEY")
        if not key:
            raise LLMError("OPENAI_API_KEY not set.")
        return OpenAI(api_key=key, timeout=float(self.cfg.timeout))

    def _openai_plan(self, system: str, tools: list[dict], turns: list[Turn]) -> PlanResponse:
        client = self._openai_client()
        messages: list[dict[str, Any]] = [{"role": "system", "content": system}]
        for t in turns:
            if t.kind == "user":
                messages.append({"role": "user", "content": t.content})
            elif t.kind == "assistant_call":
                messages.append({
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [{
                        "id": t.call_id,
                        "type": "function",
                        "function": {"name": t.name, "arguments": json.dumps(t.arguments)},
                    }],
                })
            elif t.kind == "tool_result":
                messages.append({"role": "tool", "tool_call_id": t.call_id, "content": t.content})

        oa_tools = [
            {
                "type": "function",
                "function": {
                    "name": tool["name"],
                    "description": tool["description"],
                    "parameters": tool["parameters"],
                },
            }
            for tool in tools
        ]
        try:
            resp = client.chat.completions.create(
                model=self.cfg.model,
                temperature=self.cfg.temperature,
                max_tokens=self.cfg.max_tokens,
                messages=messages,
                tools=oa_tools,
            )
        except Exception as exc:
            raise LLMError(f"OpenAI request failed: {exc}") from exc

        message = resp.choices[0].message
        calls: list[ToolCall] = []
        for tc in (message.tool_calls or []):
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError as exc:
                raise LLMError(f"Bad tool-call arguments from OpenAI: {exc}") from exc
            calls.append(ToolCall(call_id=tc.id, name=tc.function.name, arguments=args))
        return PlanResponse(tool_calls=calls, text=message.content or "")

    def _openai_text(self, system: str, user: str) -> str:
        client = self._openai_client()
        resp = client.chat.completions.create(
            model=self.cfg.model,
            temperature=self.cfg.temperature,
            max_tokens=self.cfg.max_tokens,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
        )
        return resp.choices[0].message.content or ""

    # ---- Ollama -------------------------------------------------------------

    def _ollama_plan(self, system: str, tools: list[dict], turns: list[Turn]) -> PlanResponse:
        try:
            import requests
        except ImportError as exc:
            raise LLMError("pip install requests") from exc

        messages: list[dict[str, Any]] = [{"role": "system", "content": system}]
        for t in turns:
            if t.kind == "user":
                messages.append({"role": "user", "content": t.content})
            elif t.kind == "assistant_call":
                messages.append({
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [{"function": {"name": t.name, "arguments": t.arguments}}],
                })
            elif t.kind == "tool_result":
                messages.append({"role": "tool", "content": t.content})

        oa_tools = [
            {
                "type": "function",
                "function": {
                    "name": tool["name"],
                    "description": tool["description"],
                    "parameters": tool["parameters"],
                },
            }
            for tool in tools
        ]
        url = self.cfg.base_url.rstrip("/") + "/api/chat"
        try:
            resp = requests.post(
                url,
                json={
                    "model": self.cfg.model,
                    "stream": False,
                    "options": {"temperature": self.cfg.temperature},
                    "messages": messages,
                    "tools": oa_tools,
                },
                timeout=self.cfg.timeout,
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise LLMError(f"Ollama request failed: {exc}") from exc

        message = resp.json().get("message", {})
        calls: list[ToolCall] = []
        for tc in (message.get("tool_calls") or []):
            fn = tc.get("function", {})
            raw_args = fn.get("arguments", {})
            if isinstance(raw_args, str):
                try:
                    raw_args = json.loads(raw_args or "{}")
                except json.JSONDecodeError as exc:
                    raise LLMError(f"Bad tool-call arguments from Ollama: {exc}") from exc
            calls.append(ToolCall(call_id=str(uuid.uuid4()), name=fn.get("name", ""), arguments=raw_args or {}))
        return PlanResponse(tool_calls=calls, text=message.get("content", "") or "")

    def _ollama_text(self, system: str, user: str) -> str:
        import requests

        url = self.cfg.base_url.rstrip("/") + "/api/chat"
        resp = requests.post(
            url,
            json={
                "model": self.cfg.model,
                "stream": False,
                "options": {"temperature": self.cfg.temperature},
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            },
            timeout=self.cfg.timeout,
        )
        resp.raise_for_status()
        return resp.json().get("message", {}).get("content", "")
