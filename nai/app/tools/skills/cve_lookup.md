## When to use this

Use this for optional CVE enrichment after a tool has observed a product on
the requested target. This is a candidate lookup, not a vulnerability scanner.
An unknown service or a port-table guess is not evidence of an installed product.

## Choosing parameters

- `product`: copy an observed product. Only a small set of explicit aliases is
  supported; sharing a word with another product does not establish identity.
- `version`: copy the observed version when available. Do not invent one or
  convert a reported range into a particular version. Without a precise version,
  results remain less specific.
- `limit`: maximum NVD records reviewed per query (default 10, maximum 50).
  It is not a count of all applicable CVEs. Inspect the reported coverage.

The executor supplies observed CPE identifiers from recorded evidence; do not
invent a CPE or send internal evidence parameters. A precise application CPE
uses NVD's CPE query. An empty/rejected CPE query falls back to keywords, with
both queries recorded. If a precise CPE is unavailable, only keywords are used.

## After it runs

- `cve_lookup`: query/coverage information, candidate counts, and excluded
  matches. It is not itself a vulnerability finding.
- `cve_candidate`: an **unverified candidate**. `product_version` means a
  vulnerable CPE product/version condition matches, but the target's platform,
  configuration, installed components and exploit prerequisites remain unchecked.
  `product_only`, `keyword_only` and `unverified_configuration` are weaker evidence.
- Excluded matches have a reason, such as a different product or an observed
  version outside the affected range. Never list them as vulnerabilities or candidates.

In particular, “OpenSSH before 10.3” does not establish a vulnerability in 10.3.
An advisory for an Express middleware package does not establish that the package
is installed just because Express was detected. A severity score describes the
advisory, not confidence that it applies here.

Zero candidates means these bounded searches produced no candidates, not that
the service has no known vulnerabilities. Preserve truncated-result and coverage
notes. Calls are deduplicated per target/product/version after execution.
