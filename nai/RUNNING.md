# Running the local reconnaissance demo

The local LLM selects tools from your objective and chooses follow-ups from
their results. The launcher does not choose tools or change agent behavior.

## One-time setup

Use Python 3.13, Nmap, Ollama, and Docker Desktop. The agent and Ollama run on
your computer; Docker runs the target services. Python packages cover DNS,
WHOIS, CVE lookup, and PDF reporting. ZAP stays disabled.

On macOS, from the repository root:

```bash
brew install nmap
python3.13 -m venv nai/.venv
nai/.venv/bin/python -m pip install -r nai/requirements.txt
```

Install [Ollama](https://docs.ollama.com/macos) if it is not already installed.
Open Ollama, or leave `ollama serve` running in a separate terminal. Download
the configured model once:

```bash
ollama pull qwen2.5:7b
```

On Windows, install Python 3.13, the [Nmap Windows package](https://nmap.org/download.html#windows)
(including Npcap), [Ollama](https://ollama.com/download/windows), and Docker
Desktop using Linux containers. Ensure `nmap` and `curl.exe` are on PATH.
Open a new PowerShell window after installation, then run from the repository root:

```powershell
py -3.13 -m venv nai/.venv
.\nai\.venv\Scripts\python.exe -m pip install -r nai/requirements.txt
ollama pull qwen2.5:7b
```

Each teammate creates their own `.venv`; do not copy it between machines.
Keep the same model tag and target images for comparable runs. The active
model is configured in `nai/config/settings.yaml`.

## Everyday commands

Open Docker Desktop and Ollama. From the repository root:

```bash
python3 aegis.py lab up -d --wait
python3 aegis.py lab ps
python3 aegis.py scope
python3 aegis.py scan --objective "Perform reconnaissance of 127.0.0.1 on ports 2222, 3001, 6379, and 8080. Identify the services and gather relevant details."
```

On Windows, replace `python3` with `py`. No virtual-environment activation is
needed. The launcher always uses `nai/.venv` and runs the app from `nai/`, so
its database and reports stay in the same place.

The first `lab up` downloads the images. Later starts reuse them. The target
images are pinned to multi-architecture digests so Intel and Apple Silicon
machines use the same image releases without forcing x86 emulation.

The agent proposes commands for approval by default. `--yes` uses the app's
existing automatic-approval option for that run. Use `scan` initially;
`multiscan` has a known SQLite/threading issue that this setup does not fix.

## Target services

| Service | Address | Useful observations |
|---|---|---|
| Nginx | http://127.0.0.1:8080 | HTTP service, server version, headers |
| OpenSSH | 127.0.0.1:2222 | SSH service and banner; login is not needed for recon |
| Redis | 127.0.0.1:6379 | A distinct non-HTTP service and version |
| Juice Shop | http://127.0.0.1:3001 | A second web service, deliberately vulnerable application |

All published ports bind to `127.0.0.1`; the containers have no mounts of your
project, home directory, or Docker socket. Other localhost services on your
computer are not part of this demo. Start with the four explicit ports above.
The current app does not enforce `allowed_ports`, so keep command approval
enabled when exploring broader prompts. CVE lookups now distinguish unverified
candidates from excluded matches; reconnaissance does not confirm vulnerabilities.

`nai/config/scope.yaml` contains only localhost targets for this demo.
Public-domain DNS/WHOIS behavior needs a separate suitable target. CVE
enrichment contacts NVD on the internet; model inference remains local.

## How a run selects its target

Name the intended host(s) explicitly in the objective. The app recognizes
IPv4 addresses, DNS names, HTTP(S) URLs, and explicitly configured single-label
lab hostnames. It checks every recognized host against `scope.yaml` before
asking the LLM to select a tool, and prints `Targets for this run: ...`.
The global allowlist does not supply missing targets or substitute another host.

For example, `http://scanme.nmap.org/` is recognized as host `scanme.nmap.org`.
With the current demo scope, that request is refused before any tool or model
call. The refusal exits with status 1 and writes the explanation to `nai/audit.log`.
Do not expect that objective to scan localhost.

The LLM continues to select initial tools and follow-ups. Every proposed host
must belong to the validated targets for that run. Hostnames are normalized
for case and a trailing dot, but IP addresses and DNS names are not treated as
interchangeable aliases: a request for `127.0.0.1` does not add `localhost`.
HTTP URL scheme, port, path and query are retained as context; omitted HTTP
parameters use those details when there is one unambiguous endpoint for the host.
Explicit model parameters remain visible in the
proposed action. HTTP redirects are reported without automatically following them.

If a tool call omits its target and the run has one validated host, the executor
fills it and records a notice in the terminal and audit log. With multiple hosts,
it returns an error asking the model to choose one explicitly. Rejected calls
do not consume the duplicate-execution check, so a corrected call can run.

Target extraction recognizes literal addresses; it is not a general natural-language
scope parser. Keep intended targets explicit and avoid mixing them with unrelated
domain examples in the objective. CIDR ranges and IPv6 reconnaissance are not
supported by this target parser; use individual IPv4 addresses or hostnames.
Port restrictions and full vulnerability verification remain separate, unfinished work.

## How reconnaissance evidence is handled

Nmap findings retain the identification method, confidence, CPE identifiers,
raw service fingerprint and port script output. A port-table name such as
`nessus` on port 3001 is an unverified guess. HTTP responses and a page title
inside an unidentified fingerprint remain observations the LLM can investigate.
They do not automatically become a product/version identification.

CVE lookup uses an observed application CPE when available, with at most one
keyword fallback if that query is empty or rejected. Otherwise it uses product
keywords, including an exact observed version when available. Each successful
lookup stores its queries, retrieval time, source, reviewed/total counts and
excluded matches, including when it returns zero candidates.

Simple CPE product identities and dotted numeric version bounds can exclude
unrelated products and out-of-range versions. A narrow description fallback
can exclude an explicit single upper bound such as `OpenSSH before 10.3` for
observed version 10.3. This also applies when the product CPE contains only a
wildcard version with no version bounds; explicit or complex CPE version
conditions are not overridden by prose. Ambiguous descriptions, vendor aliases, version suffixes
and complex conditions remain unverified. A matching product/version is still
only a candidate: platform, configuration and component prerequisites are not
verified. Searches are bounded (10 records by default, maximum 50 per query),
so zero candidates never means that a service has no vulnerabilities.

The planner receives bounded excerpts; full parsed fingerprints, script output,
advisory descriptions and CPE conditions remain in the session database.
The Markdown report includes CVE sources, coverage and exclusion reasons.
The legacy PDF report still uses abbreviated finding rows; use Markdown for
the detailed CVE evidence. Historical session reports are not rewritten.

Malformed/incomplete Nmap output and failed HTTP requests are errors. A timeout
or TLS failure does not establish that an HTTP service is absent.

## Investigation status and stopping

The LLM still selects the first tool and every follow-up. Each tool schema now
lists only applicable run targets. For an IP-only objective, DNS and WHOIS are
not offered; the executor still independently rejects inappropriate calls.

Before investigation, the LLM interprets the objective in a separate native
`interpret_objective` call. It records the requested goal, the tools permitted
throughout the run, and an optional explanation of any narrowed selection.
The terminal and Markdown report display this model interpretation; it is also
saved with the original objective in the session database and audit log.

An omitted or blank explanation does not cause a retry or broaden permissions;
the model's tool list is the actual decision. Python validates the response
structure and tool names, then enforces the model's
recorded permissions. It does not infer restrictions from phrases or tool-name
aliases in the prompt. The model should interpret `Use only Nmap ...` as permitting
only Nmap and `Collect only the HTTP response headers ...` as permitting only the
HTTP headers tool. Excluded tools are neither offered nor executable and do not
appear as unfinished work. Engagement scope remains an independent limit.

For broad objectives the model is instructed to keep all available tools permitted;
this is not a fixed execution plan. `Start with Nmap and investigate its findings`
should allow useful follow-ups. Merely permitting a tool does not require using it.

This adds one model call before the investigative iterations. Malformed
interpretations receive up to two correction opportunities, with no tool execution.
Repeated invalid responses or a model error stop the run without an unrestricted
fallback. An interpretation permitting no available tools also stops without
execution. Validation cannot prove the interpretation matches the user's meaning:
review the displayed interpretation during manual prompt tests. There is no extra
approval prompt for this step; existing action confirmation settings still apply.

Offered actions are refreshed after each turn. The current Nmap wrapper permits
one execution per host, so hosts already attempted are removed from its target
list; after all have been attempted, Nmap is no longer offered. Failed executions
also consume this existing slot; rejected and declined proposals do not. Tools
whose requests vary by parameters, such as HTTP headers on different ports,
remain available. Run permissions and coverage records are preserved separately,
so unavailable actions never turn incomplete checks into successful checks.

After each result, the planner sees a per-service record of HTTP checks and
CVE enrichment: checked, failed, incomplete, or not assessed. Open services
remain visible even when unidentified. A successful HTTP request on port 3001
does not mark port 8080 checked, and a CVE lookup for one host/version does not
cover a different host/version. A rejected or declined proposal does not count
as a performed check. These statuses describe tool coverage, not a full assessment.

To stop with pending checks, the model calls the internal `finish_recon` control
with the IDs of the checks it chooses to defer. This runs no external tool. The
reason is optional free text; it no longer requires a particular enum value.
When there are no pending checks, `finish_recon` needs no arguments and its schema
does not request a deferral list. If the model still supplies a list of check IDs,
the app ignores that list for completion, retaining it in the audit and saved
decision. It adds no findings or pending work. When checks do remain, every ID
must still be accounted for exactly once. A plain
closing response can also stop a run with no pending checks and at least one
successful tool action. Its prose is not published as a factual conclusion.

The model may instead select another useful investigative action. CVE enrichment
is optional. Tools excluded by the recorded interpretation need neither execution
nor a deferral decision, and there is no fixed scan sequence.

Plain closing prose while checks remain, and incomplete finish decisions, receive up to two correction
opportunities without new execution. Repeated invalid decisions, model errors,
repeated rejected actions, and the iteration limit stop with a recorded partial
inventory. A normal stop returns exit status 0 when at least one tool
succeeded; this does not certify that every possible check or the natural-language
objective was fulfilled. A blocked decision or a run with no successful tools
returns status 1 (the optional reason `blocked` signals the former). Pending checks cover observed HTTP/product evidence and targets
without successful results; they are not a full objective or port-coverage parser.

The terminal's closing inventory is generated from stored evidence, including
relevant unperformed checks and bounded CVE lookup counts. A Nmap-only inventory
shows discovered services without unrelated HTTP/CVE checklist entries; an
HTTP-only inventory omits CVE warnings. Actual recorded checks remain visible
even if the available tool list changes. Free-form model conclusions
are not published as findings. The same conclusion is stored with the session
and included in its Markdown report. Existing databases gain action-parameter,
run-context and conclusion columns automatically; old sessions are retained.

## Offline and manual checks

From the repository root, run the offline regression checks first. They use a
temporary audit file, an in-memory database, scripted planner responses, and
mocked tool execution. They do not start Ollama, Nmap, curl, or containers:

```bash
PYTHONPATH=nai nai/.venv/bin/python -m unittest discover -s nai/tests -p 'test_targets.py' -v
PYTHONPATH=nai nai/.venv/bin/python -m unittest discover -s nai/tests -p 'test_evidence.py' -v
PYTHONPATH=nai nai/.venv/bin/python -m unittest discover -s nai/tests -p 'test_progress.py' -v
```

The evidence checks replay the saved four-port Nmap capture and synthetic NVD
responses. They cover unknown-service fingerprints, affected-version boundaries,
unrelated products, query failures and empty results, storage, and Markdown reports.
See `tests/fixtures/README.md` for fixture provenance.
The progress checks use scripted planner responses to replay premature stopping,
continue useful follow-ups, finish with explicit deferrals, preserve failed checks,
validate and enforce scripted model interpretations, accept simple stopping responses, filter
target-specific schemas, and migrate an old temporary database.

The existing offline checks can also be run individually:

```bash
PYTHONPATH=nai nai/.venv/bin/python nai/tests/test_executor.py
PYTHONPATH=nai nai/.venv/bin/python nai/tests/test_tools.py
PYTHONPATH=nai nai/.venv/bin/python nai/tests/test_validator.py
```

In PowerShell, set `$env:PYTHONPATH = 'nai'` and use
`.\nai\.venv\Scripts\python.exe` instead of `nai/.venv/bin/python`.

Then check the current localhost-only scope with the previously failing objective:

```bash
python3 aegis.py scan --objective "Perform reconnaissance on http://scanme.nmap.org/" --yes
```

Expected: a refusal naming `scanme.nmap.org`, with no iteration or tool execution.
An exit status of 1 is expected for this check. Finally, with the demo containers
and Ollama running, repeat the four-port run:

```bash
python3 aegis.py scan --objective "Reconnaissance of 127.0.0.1 on ports 2222, 3001, 6379, and 8080." --yes
```

Expected: `Targets for this run: 127.0.0.1`, no execution against another host,
and an explicit notice if a missing tool-call target is filled. The sequence of
tools remains model-selected, so it can differ between runs.

For evidence quality, check that port 3001 stays in the inventory and that any
`nessus` label is qualified as a guess. An available HTTP fingerprint should
include its observed page title. CVE results should distinguish candidates from
excluded matches and show coverage limits. Whether the model chooses the useful
HTTP follow-up and reliably uses the explicit finish control is part of this
manual run; the offline tests cannot establish the live model's choices. The
closing inventory itself must report unperformed CVE lookups as not assessed.

To check that tool choice remains driven by the prompt, also try these separately:

```bash
python3 aegis.py scan --objective "Use only Nmap to identify services on 127.0.0.1 ports 2222, 3001, 6379, and 8080." --yes
python3 aegis.py scan --objective "Collect only the HTTP response headers from http://127.0.0.1:3001/." --yes
```

Expected: the displayed model interpretation permits only `nmap` for the first
request and only `http_headers` for the second. Once recorded, only those tools
are offered and can execute. Excluded checks do not appear as unfinished work,
and a normal closing response after the result does not trigger a finish-reason
enum error. Also repeat the broad four-port objective above: its interpretation
should keep tool choice open. These manual checks evaluate the model's understanding;
scripted offline tests only verify validation, enforcement and recovery.

## Verify before an agent run

```bash
ollama list
python3 aegis.py lab ps
nmap -sT -sV -p 2222,3001,6379,8080 127.0.0.1
curl -I http://127.0.0.1:8080
curl -I http://127.0.0.1:3001
```

In Windows PowerShell use `curl.exe` instead of `curl`. The direct Nmap scan
is a manual reference check, not a fixed first step in the agent workflow.

If a port is occupied, `lab up` will report a bind error. Stop the conflicting
service or change that port's host-side mapping in `nai/compose.yaml`, then
use the new port in your objective. Inspect startup problems with:

```bash
python3 aegis.py lab logs --tail 60
```

## Save a baseline run

The Markdown report preserves the recorded conclusion. Capture terminal output
as well to retain tool rationales and correction messages. From the repository root on macOS:

```bash
mkdir -p nai/logs
set -o pipefail
python3 aegis.py scan --objective "Perform reconnaissance of 127.0.0.1 on ports 2222, 3001, 6379, and 8080. Identify the services and gather relevant details." 2>&1 | tee "nai/logs/baseline-$(date +%Y%m%d-%H%M%S).log"
```

In PowerShell:

```powershell
New-Item -ItemType Directory -Force nai/logs | Out-Null
py aegis.py scan --objective "Perform reconnaissance of 127.0.0.1 on ports 2222, 3001, 6379, and 8080. Identify the services and gather relevant details." 2>&1 | Tee-Object -FilePath "nai/logs/baseline-$(Get-Date -Format yyyyMMdd-HHmmss).log"
```

Reports are written under `nai/reports/local/`, with session data in `nai/aegis.db`
and audit events in `nai/audit.log`. Terminal captures under `nai/logs/` are
ignored by Git. The `reports/local` output directory keeps new reports separate
from historical reports that may have the same session number.

## Stop or restart

```bash
python3 aegis.py lab stop
python3 aegis.py lab up -d --wait
```

To remove just this demo's containers, network, and disposable volumes:

```bash
python3 aegis.py lab down --volumes
```

Images remain cached. The app's database, logs, and reports are outside the
containers and are retained. Closing a terminal does not stop detached target
containers. There is no automatic restart policy; bring them up when needed.
