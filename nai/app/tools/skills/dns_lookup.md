## When to use this

Only for a domain target, not a bare IP -- DNS records are looked up by
name, so this has nothing to resolve against an IP. Good early step for a
domain objective, before or alongside `whois`, to map out the domain's
infrastructure before touching the host itself.

This is enforced, not just a suggestion: a call against a target that isn't
one of this engagement's actual in-scope domains is rejected outright,
before it ever runs. If the objective's target is a bare IP with no
in-scope domain associated with it, don't call this tool at all.

## Choosing parameters

- `types`: omit it for the common set (A, AAAA, MX, NS, TXT, CNAME), which
  covers most reconnaissance needs in one call. Only narrow it to specific
  types if the objective is about one thing in particular (e.g. just mail
  infrastructure -> `["MX"]`).

## Reading the result

- A/AAAA records give you the IP(s) to actually target with nmap/http_headers.
- MX records reveal the mail infrastructure (often a different provider
  entirely from the web host).
- NS records show who runs DNS for the domain -- useful context, not
  something to act on directly.
- TXT records occasionally reveal SPF/DKIM/verification strings worth
  noting in a report, but rarely something to act on.
- No records of a given type is a normal, valid result (e.g. no MX means no
  mail service) -- not a failure to retry.
