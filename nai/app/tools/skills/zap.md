## When to use this

For a target that's an actual web application, not just an open web port --
use this when the objective is about testing a site's own logic/pages, not
just discovering that a web server exists (that's what `http_headers` is
for). Requires a running ZAP instance with its API reachable; if the
connection fails, that's an environment problem, not a reason to retry with
different scan parameters.

## Choosing parameters

- `active`: leave this false unless the engagement scope explicitly calls
  for active testing. Spider + passive (the default) only observes traffic
  as it crawls the site and never sends anything a normal browser wouldn't --
  it's safe against a target you don't have explicit permission to actively
  probe. `active=true` sends real test requests (the same category of thing
  an actual attack would send) and should be treated as a distinct,
  deliberate escalation, not a default.
- `max_wait`: the default (300s) is enough for a small site. Raise it for a
  larger one rather than assuming a timeout means the scan failed.
- `zap_host` / `zap_port` / `api_key`: only change these if ZAP isn't
  running on the default local address, or has an API key configured.

## After it runs

Findings are already sorted worst-first (High/Medium/Low/Informational).
There's no built-in dedup-by-target here the way nmap/cve_lookup have it --
use judgement about whether re-scanning the same site adds anything before
doing it again.
