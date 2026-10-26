# Aegis-AI

An authorized penetration-testing orchestration agent. An LLM acts as the
reasoning "brain" that decides the next step; standard security tools
(`nmap`, and later `ZAP`, etc.) do the actual work. Every action passes through
a scope/policy gate and — by default — a human approval prompt before it runs.

The current development focus is reconnaissance: the local LLM selects the
initial tools from the user's objective, then chooses follow-ups from their
results. The app tracks checks per service and builds the closing inventory from
recorded evidence. Before execution the LLM records its interpretation of the
goal and any tool restrictions; the app displays, validates and enforces that
interpretation. Prompt meaning is not parsed with phrase-matching rules. Explicit
requests such as `Use only Nmap` should restrict the whole run; broader objectives
should keep tool choice open for model-selected follow-ups. Relevant optional
checks can be deferred. Start with the [local run guide](RUNNING.md) for macOS and Windows.


---

## Design principles

1. **Scope is law.** `config/scope.yaml` is the single source of truth for what
   may be touched — and which tools are even switched on. Every action is
   validated against it. Fail closed.
2. **Human-in-the-loop.** The agent proposes; you approve. Autonomy is opt-in.
3. **The LLM only reasons.** It cannot run anything, invent tools, or reach
   out-of-scope targets — the executor and policy layer enforce that no matter
   what the model returns.
4. **Tools describe themselves.** Nothing tool-specific is hardcoded into the
   agent's prompt. Each tool carries its own JSON-schema parameters and usage
   notes (`app/tools/base.py`); the agent only ever sees the schemas of the
   tools `scope.yaml` enabled, via the model provider's native tool-calling —
   not hand-parsed JSON.
5. **Everything is audited.** Every decision and action is logged (`audit.log`
   + SQLite) — including *why* a step failed, not just whether it ran.

---

## Architecture

```
config/scope.yaml ──► app/policy/validator.py   (the gate: is this allowed?)
                            ▲
app/agent/loop.py ──► app/agent/executor.py ──► app/tools/registry.py
 (tool-calling loop)     (gate + confirm + run)      │  (auto-discovers every
        │                                            │   Tool subclass)
        ▼                                            ├─ app/tools/nmap_tool.py
app/llm/client.py                                    └─ app/tools/*.py …
   (anthropic/openai/ollama —                     app/memory/database.py (state)
    native tool-calling)                          app/reporting/report.py
```

Flow per step: **model calls a tool → policy check → human confirm → run →
result fed back to the model → repeat** until the model stops calling tools.
The model sees the whole conversation natively, so it can react to a failed
or rejected step and try something different on the next turn — this assumes
the configured model is actually trained for tool/function calling (Claude
and GPT models always are; for local models via Ollama, pick one that is,
e.g. Qwen2.5, Llama 3.1+, or Mistral Nemo).

---

## Local setup

From the repository root (the directory containing `aegis.py`):

```bash
python3.13 -m venv nai/.venv
nai/.venv/bin/python -m pip install -r nai/requirements.txt

# install the external scanner
sudo apt install nmap        # or: brew install nmap

# install and start Ollama (https://ollama.com), then download the model:
ollama pull qwen2.5:7b
```

The default `config/settings.yaml` runs inference locally through Ollama with
`qwen2.5:7b`. CVE enrichment contacts NVD; DNS and WHOIS may also use external
services. The [run guide](RUNNING.md) includes Windows setup, the four-service
Docker target, and instructions for capturing a baseline run.

> Want a cloud model instead? Set `provider` to `anthropic` or `openai`
> in `settings.yaml` and export the matching API key
> (`ANTHROPIC_API_KEY` / `OPENAI_API_KEY`).

## Configure your engagement

Edit `config/scope.yaml` so it mirrors your **written authorization**. Only put
targets you own or are explicitly permitted to test. A good practice lab:
DVWA, a VulnHub VM, or a HackTheBox machine you've started.

## Run

```bash
python3 aegis.py lab up -d --wait                           # start local targets
python3 aegis.py scope                                     # print & validate scope
python3 aegis.py scan --objective "Map services on 127.0.0.1"
python3 aegis.py scan --objective "..." --pdf                # also write PDF
python3 aegis.py scan --objective "..." --yes                # auto-approve this run
python3 aegis.py report --session 1 --pdf                    # regenerate a report
python3 aegis.py lab down --volumes                         # remove demo targets
```

On Windows replace `python3` with `py`. The launcher uses `nai/.venv` directly;
activation is not required. Local reports go to `nai/reports/local/`.

The agent proposes each step and waits for your `y/N` before running, unless
you pass `--yes` -- which skips the prompt for that run only, without
touching `require_confirmation` in `settings.yaml`.

---

## Roadmap — all implemented

- [x] Skeleton: agent loop, executor, registry, nmap, SQLite
- [x] Policy layer + scope.yaml + audit logging
- [x] Session management
- [x] CVE lookup tool (NVD API) — read-only enrichment of discovered versions
- [x] OWASP ZAP tool — spider + passive by default, active opt-in
- [x] Parallel execution (`multiscan`) — still gated per-action
- [x] Reporting → Markdown **and** PDF (`--pdf`)

### Tools that ship

| Tool         | What it does                                   | Enabled by default |
|--------------|------------------------------------------------|--------------------|
| `nmap`       | Port/service discovery                         | yes                |
| `cve_lookup` | Unverified CVE candidates for an observed service (NVD) | yes (read-only) |
| `zap`        | Web-app scan (spider/passive/active)           | no — enable per engagement |

Enable a tool by adding its name under `allowed_tools` in `scope.yaml`.
`zap` is left off by default so you turn it on deliberately.

### Adding your own tool

1. Subclass `Tool` in `app/tools/your_tool.py` (implement `command_preview` + `run`,
   and set `params_schema` — the JSON-schema of its parameters, so the model
   always gets a typed, enumerable set of options rather than free-form flags).
2. Write `app/tools/skills/your_tool.md` — the tool's "skill": a markdown doc
   explaining when to use it, what each parameter means, and common failure
   modes. It's picked up automatically by filename (`<tool name>.md`) and
   folded into what the model sees; no registration needed.
3. Add its name to `allowed_tools` in `scope.yaml`.

That's genuinely it — `app/tools/registry.py` scans every file in `app/tools/`
and registers any `Tool` subclass it finds, so there's no registry to hand-edit.

---

