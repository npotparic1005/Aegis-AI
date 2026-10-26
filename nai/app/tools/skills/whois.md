## When to use this

Only for a domain target, not a bare IP. This returns *who registered the
domain and when*, not anything about the services running on it -- it's a
complement to `dns_lookup`/`nmap`, not a substitute. Good for engagement
context (registrar, org, creation/expiry dates) rather than for finding
anything to act on technically.

This is enforced, not just a suggestion: a call against a target that isn't
one of this engagement's actual in-scope domains is rejected outright,
before it ever runs. If the objective's target is a bare IP with no
in-scope domain associated with it, don't call this tool at all.

## Parameters

None -- it's a single, fixed lookup.

## Reading the result

Missing fields are common and not a failure: many registrars redact
registrant details (privacy protection), so an empty `org`/`country` field
just means that data isn't public, not that the lookup failed. A creation
date close to "today" for an otherwise established-looking site can be
worth flagging in a report; a long-registered domain generally isn't.
