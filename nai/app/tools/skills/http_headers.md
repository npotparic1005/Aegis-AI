## When to use this

Use this to inspect a web URL named in the objective, or after discovery
identifies a likely HTTP/HTTPS service. It can be the first tool when the
user specifically requests HTTP headers; an Nmap scan is not a prerequisite.

## Choosing parameters

- `scheme`: use the objective URL's scheme when provided. Otherwise try
  `http` first unless nmap already told you the port is TLS.
  If `http` times out, retry once with `scheme=https` on the same
  port/target before giving up on it -- that's a legitimate, different call
  (not a duplicate), since it changes the actual request being made.
- `port`: use the objective URL's port or the port reported by discovery.
  Without an explicit port, the defaults are 80 for HTTP and 443 for HTTPS.
- `path`: leave as `/` unless the objective specifically points at another
  path.

## Reading the result

Redirects are returned without being followed automatically. Inspect the
`Location` header and propose a separate follow-up only if its host belongs
to this run's validated targets. Do not expand the run to a redirect's host.

A timeout or TLS/connection error is a failed request, not evidence that no
HTTP service exists or that a firewall caused it. Record the error and keep
availability unresolved. A valid HTTP error response (such as 404) still proves
that an HTTP server responded. Look at the
`Server`/`X-Powered-By` headers for anything worth a `cve_lookup` call with
that product/version, and note any *missing* security headers
(Content-Security-Policy, Strict-Transport-Security, X-Frame-Options) as a
finding in their own right.
