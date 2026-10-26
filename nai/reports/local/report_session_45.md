# Penetration Test Report — Local Recon Demo

*Generated: 2026-10-09T06:30:12.621716+00:00*

## Engagement

- **Client:** self
- **Authorization:** personal-lab-owned-hardware
- **Window:** 2025-01-01 → 2030-12-31
- **In-scope hosts:** 127.0.0.1, scanme.nmap.org
- **In-scope domains:** localhost

## Objective and model interpretation

- **User objective:** Perform reconnaissance of 127.0.0.1 on ports 2222, 3001, and 8080. Identify the services and gather relevant details.
- **Interpreted goal:** Perform reconnaissance of 127.0.0.1 on ports 2222, 3001, and 8080. Identify the services and gather relevant details.
- **Tools permitted by this interpretation:** cve_lookup, http_headers, nmap
- **Restriction:** Tool choice remains open.

## Summary

- Actions executed: **5**
- Findings recorded: **37**

## Recorded conclusion

Agent kept proposing rejected actions (duplicate/out-of-scope/invalid); stopping.

Results — 5 executed tool action(s):

- 127.0.0.1:2222/tcp: OpenSSH 10.3.
  CVE enrichment: checked; 9 unverified candidate(s), 1 excluded match(es); reviewed 10 of 14 records in the final query.
- 127.0.0.1:3001/tcp: unresolved service (unverified label: nessus).
  HTTP headers: checked.
  CVE enrichment: not assessed; no identified product to ground a lookup.
- 127.0.0.1:8080/tcp: nginx 1.30.4.
  HTTP headers: checked.
  CVE enrichment: checked; 0 unverified candidate(s), 0 excluded match(es); reviewed 0 of 0 records in the final query.

Vulnerability applicability was not verified. Empty or unperformed lookups do not establish absence of vulnerabilities.

## Findings

| Host | Detail |
|------|--------|
| 127.0.0.1 | 2222/tcp open: OpenSSH 10.3 (probed; service confidence 10/10) |
| 127.0.0.1 | 3001/tcp open: unresolved service (port-table guess: nessus; not confirmed); HTTP response observed |
| 127.0.0.1 | 8080/tcp open: nginx 1.30.4 (probed; service confidence 10/10) |
| 127.0.0.1 | http://127.0.0.1:8080/ — Server: nginx/1.30.4 |
| 127.0.0.1 | http://127.0.0.1:8080/ — Date: Thu, 08 Oct 2026 13:37:52 GMT |
| 127.0.0.1 | http://127.0.0.1:8080/ — Content-Type: text/html |
| 127.0.0.1 | http://127.0.0.1:8080/ — Content-Length: 896 |
| 127.0.0.1 | http://127.0.0.1:8080/ — Last-Modified: Wed, 15 Jul 2026 18:38:41 GMT |
| 127.0.0.1 | http://127.0.0.1:8080/ — Connection: keep-alive |
| 127.0.0.1 | http://127.0.0.1:8080/ — ETag: "6a57d3b1-380" |
| 127.0.0.1 | http://127.0.0.1:8080/ — Accept-Ranges: bytes |
| 127.0.0.1 | CVE lookup for OpenSSH 10.3: 9 unverified candidate(s), 1 excluded match(es); reviewed 10 of 14 records in the final query. No vulnerability was confirmed; zero candidates does not establish absence of vulnerabilities. |
| 127.0.0.1 | Candidate (unverified): CVE-2008-3844 (HIGH, 9.3) — Product identity matches, but the observed version or CPE conditions cannot establish version applicability. |
| 127.0.0.1 | Candidate (unverified): CVE-2007-2768 (MEDIUM, 4.3) — Product identity matches, but the observed version or CPE conditions cannot establish version applicability. |
| 127.0.0.1 | Candidate (unverified): CVE-2026-59995 (MEDIUM, 4.2) — A vulnerable CPE product/version condition matches. Platform, configuration, component role and exploit prerequisites are not verified. |
| 127.0.0.1 | Candidate (unverified): CVE-2026-59996 (MEDIUM, 4.2) — A vulnerable CPE product/version condition matches. Platform, configuration, component role and exploit prerequisites are not verified. |
| 127.0.0.1 | Candidate (unverified): CVE-2026-59997 (MEDIUM, 4.2) — A vulnerable CPE product/version condition matches. Platform, configuration, component role and exploit prerequisites are not verified. |
| 127.0.0.1 | Candidate (unverified): CVE-2026-59998 (MEDIUM, 4.8) — A vulnerable CPE product/version condition matches. Platform, configuration, component role and exploit prerequisites are not verified. |
| 127.0.0.1 | Candidate (unverified): CVE-2026-59999 (MEDIUM, 5.9) — A vulnerable CPE product/version condition matches. Platform, configuration, component role and exploit prerequisites are not verified. |
| 127.0.0.1 | Candidate (unverified): CVE-2026-60001 (MEDIUM, 6.5) — A vulnerable CPE product/version condition matches. Platform, configuration, component role and exploit prerequisites are not verified. |
| 127.0.0.1 | Candidate (unverified): CVE-2026-60000 (LOW, 3.7) — A vulnerable CPE product/version condition matches. Platform, configuration, component role and exploit prerequisites are not verified. |
| 127.0.0.1 | http://127.0.0.1:3001/ — Access-Control-Allow-Origin: * |
| 127.0.0.1 | http://127.0.0.1:3001/ — X-Content-Type-Options: nosniff |
| 127.0.0.1 | http://127.0.0.1:3001/ — X-Frame-Options: SAMEORIGIN |
| 127.0.0.1 | http://127.0.0.1:3001/ — Feature-Policy: payment 'self' |
| 127.0.0.1 | http://127.0.0.1:3001/ — X-Recruiting: /#/jobs |
| 127.0.0.1 | http://127.0.0.1:3001/ — Accept-Ranges: bytes |
| 127.0.0.1 | http://127.0.0.1:3001/ — Cache-Control: public, max-age=0 |
| 127.0.0.1 | http://127.0.0.1:3001/ — Last-Modified: Thu, 08 Oct 2026 13:11:28 GMT |
| 127.0.0.1 | http://127.0.0.1:3001/ — ETag: W/"24b1-1a11ba3e5e7" |
| 127.0.0.1 | http://127.0.0.1:3001/ — Content-Type: text/html; charset=UTF-8 |
| 127.0.0.1 | http://127.0.0.1:3001/ — Content-Length: 9393 |
| 127.0.0.1 | http://127.0.0.1:3001/ — Vary: Accept-Encoding |
| 127.0.0.1 | http://127.0.0.1:3001/ — Date: Thu, 08 Oct 2026 13:50:46 GMT |
| 127.0.0.1 | http://127.0.0.1:3001/ — Connection: keep-alive |
| 127.0.0.1 | http://127.0.0.1:3001/ — Keep-Alive: timeout=5 |
| 127.0.0.1 | CVE lookup for nginx 1.30.4: 0 unverified candidate(s), 0 excluded match(es); reviewed 0 of 0 records in the final query. No vulnerability was confirmed; zero candidates does not establish absence of vulnerabilities. |

## CVE lookup evidence

CVE candidates are unverified. Search matches, version matches and severity scores do not confirm vulnerability applicability. Empty searches do not prove absence of vulnerabilities.

### 127.0.0.1 — OpenSSH 10.3

CVE lookup for OpenSSH 10.3: 9 unverified candidate(s), 1 excluded match(es); reviewed 10 of 14 records in the final query. No vulnerability was confirmed; zero candidates does not establish absence of vulnerabilities.

Bounded NVD searches; incomplete enrichment, aliases, unreviewed pages and unknown configuration can omit applicable CVEs. This is not a vulnerability assessment.

Source: https://services.nvd.nist.gov/rest/json/cves/2.0 (retrieved 2026-10-08T13:43:06.228554+00:00)

- Query: `{'cpeName': 'cpe:2.3:a:openbsd:openssh:10.3:*:*:*:*:*:*:*', 'isVulnerable': ''}`; HTTP 200; reviewed 10 of 14 records; truncated: True.

- Excluded [CVE-2023-51767](https://nvd.nist.gov/vuln/detail/CVE-2023-51767): Description specifies OpenSSH through 10.0; observed version is 10.3.

### 127.0.0.1 — nginx 1.30.4

CVE lookup for nginx 1.30.4: 0 unverified candidate(s), 0 excluded match(es); reviewed 0 of 0 records in the final query. No vulnerability was confirmed; zero candidates does not establish absence of vulnerabilities.

Bounded NVD searches; incomplete enrichment, aliases, unreviewed pages and unknown configuration can omit applicable CVEs. This is not a vulnerability assessment.

Source: https://services.nvd.nist.gov/rest/json/cves/2.0 (retrieved 2026-10-08T13:58:56.935439+00:00)

- Query: `{'cpeName': 'cpe:2.3:a:igor_sysoev:nginx:1.30.4:*:*:*:*:*:*:*', 'isVulnerable': ''}`; HTTP 200; reviewed 0 of 0 records; truncated: False.
- Query: `{'keywordSearch': 'nginx 1.30.4'}`; HTTP 200; reviewed 0 of 0 records; truncated: False.


### Candidate [CVE-2008-3844](https://nvd.nist.gov/vuln/detail/CVE-2008-3844) — unverified

Product identity matches, but the observed version or CPE conditions cannot establish version applicability.

Certain Red Hat Enterprise Linux (RHEL) 4 and 5 packages for OpenSSH, as signed in August 2008 using a legitimate Red Hat GPG key, contain an externally introduced modification (Trojan Horse) that allows the package authors to have an unknown impact.  NOTE: since the malicious packages were not distributed from any official Red Hat sources, the scope of this issue is restricted to users who may have obtained these packages through unofficial distribution points.  As of 20080827, no unofficial distributions of this software are known.

### Candidate [CVE-2007-2768](https://nvd.nist.gov/vuln/detail/CVE-2007-2768) — unverified

Product identity matches, but the observed version or CPE conditions cannot establish version applicability.

OpenSSH, when using OPIE (One-Time Passwords in Everything) for PAM, allows remote attackers to determine the existence of certain user accounts, which displays a different response if the user account exists and is configured to use one-time passwords (OTP), a similar issue to CVE-2007-2243.

### Candidate [CVE-2026-59995](https://nvd.nist.gov/vuln/detail/CVE-2026-59995) — unverified

A vulnerable CPE product/version condition matches. Platform, configuration, component role and exploit prerequisites are not verified.

sftp in OpenSSH before 10.4 does not properly constrain the location of downloaded files when "sftp server:/path ." is used with an attacker-controlled server.

### Candidate [CVE-2026-59996](https://nvd.nist.gov/vuln/detail/CVE-2026-59996) — unverified

A vulnerable CPE product/version condition matches. Platform, configuration, component role and exploit prerequisites are not verified.

scp in OpenSSH before 10.4 may place a file in the parent directory of an intended directory when the copy occurs between two remote destinations.

### Candidate [CVE-2026-59997](https://nvd.nist.gov/vuln/detail/CVE-2026-59997) — unverified

A vulnerable CPE product/version condition matches. Platform, configuration, component role and exploit prerequisites are not verified.

internal-sftp in sshd in OpenSSH before 10.4 recognizes only the first 9 command-line arguments, which can be important if a later command-line argument would have helped to ensure the intended security properties of an SFTP connection.

### Candidate [CVE-2026-59998](https://nvd.nist.gov/vuln/detail/CVE-2026-59998) — unverified

A vulnerable CPE product/version condition matches. Platform, configuration, component role and exploit prerequisites are not verified.

sshd in OpenSSH before 10.4 has an undocumented security-relevant behavior: GSSAPIStrictAcceptorCheck has no value if the server is in Windows Active Directory.

### Candidate [CVE-2026-59999](https://nvd.nist.gov/vuln/detail/CVE-2026-59999) — unverified

A vulnerable CPE product/version condition matches. Platform, configuration, component role and exploit prerequisites are not verified.

In sshd in OpenSSH before 10.4, DisableForwarding=yes was supposed to take precedence over PermitTunnel=yes, but did not.

### Candidate [CVE-2026-60001](https://nvd.nist.gov/vuln/detail/CVE-2026-60001) — unverified

A vulnerable CPE product/version condition matches. Platform, configuration, component role and exploit prerequisites are not verified.

sshd in OpenSSH before 10.4 does not always honor the minimum authentication delay.

### Candidate [CVE-2026-60000](https://nvd.nist.gov/vuln/detail/CVE-2026-60000) — unverified

A vulnerable CPE product/version condition matches. Platform, configuration, component role and exploit prerequisites are not verified.

sshd in OpenSSH before 10.4 allows remote attackers to cause a denial of service (resource consumption from excessive authentication attempts) because MaxAuthTries was mishandled for GSSAPIAuthentication.

## Action Log (audit)

| Time | Tool | Target | Policy | Executed |
|------|------|--------|--------|----------|
| 2026-10-08T13:31:39.009130+00:00 | nmap | 127.0.0.1 | allow | yes |
| 2026-10-08T13:34:14.036919+00:00 | cve_lookup | 127.0.0.1 | DENY | no |
| 2026-10-08T13:37:52.176125+00:00 | http_headers | 127.0.0.1 | allow | yes |
| 2026-10-08T13:42:58.578922+00:00 | cve_lookup | 127.0.0.1 | allow | yes |
| 2026-10-08T13:50:45.979749+00:00 | http_headers | 127.0.0.1 | allow | yes |
| 2026-10-08T13:57:07.848359+00:00 | http_headers | 127.0.0.1 | DENY | no |
| 2026-10-08T13:58:43.083145+00:00 | cve_lookup | 127.0.0.1 | allow | yes |
| 2026-10-08T18:16:17.305393+00:00 | http_headers | 127.0.0.1 | DENY | no |
| 2026-10-09T06:28:30.004015+00:00 | cve_lookup | 127.0.0.1 | DENY | no |
| 2026-10-09T06:30:12.580321+00:00 | http_headers | 127.0.0.1 | DENY | no |
