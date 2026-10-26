# Penetration Test Report — Local Recon Demo

*Generated: 2026-10-07T20:04:51.006339+00:00*

## Engagement

- **Client:** self
- **Authorization:** personal-lab-owned-hardware
- **Window:** 2025-01-01 → 2030-12-31
- **In-scope hosts:** 127.0.0.1
- **In-scope domains:** localhost

## Objective and model interpretation

- **User objective:** Map services on 127.0.0.1
- **Interpreted goal:** Map services on 127.0.0.1
- **Tools permitted by this interpretation:** cve_lookup, http_headers, nmap
- **Restriction:** Tool choice remains open.

## Summary

- Actions executed: **4**
- Findings recorded: **7**

## Findings

| Host | Detail |
|------|--------|
| 127.0.0.1 | 135/tcp open: Microsoft Windows RPC (probed; service confidence 10/10) |
| 127.0.0.1 | 445/tcp open: unresolved service (port-table guess: microsoft-ds; not confirmed) |
| 127.0.0.1 | 902/tcp open: VMware Authentication Daemon 1.10 (probed; service confidence 10/10) |
| 127.0.0.1 | 912/tcp open: VMware Authentication Daemon 1.0 (probed; service confidence 10/10) |
| 127.0.0.1 | http://127.0.0.1:902/: request failed: 220 VMware Authentication Daemon Version 1.10: SSL Required, ServerDaemonProtocol:SOAP, MKSDisplayProtocol:VNC , , NFCSSL supported/t,  curl: (1) Received HTTP/0.9 when not allowed |
| 127.0.0.1 | http://127.0.0.1:912/: request failed: 220 VMware Authentication Daemon Version 1.0, ServerDaemonProtocol:SOAP, MKSDisplayProtocol:VNC , , ,  curl: (1) Received HTTP/0.9 when not allowed |
| 127.0.0.1 | CVE lookup for VMware Authentication Daemon 1.0: 0 unverified candidate(s), 2 excluded match(es); reviewed 2 of 2 records in the final query. No vulnerability was confirmed; zero candidates does not establish absence of vulnerabilities. |

## CVE lookup evidence

CVE candidates are unverified. Search matches, version matches and severity scores do not confirm vulnerability applicability. Empty searches do not prove absence of vulnerabilities.

### 127.0.0.1 — VMware Authentication Daemon 1.0

CVE lookup for VMware Authentication Daemon 1.0: 0 unverified candidate(s), 2 excluded match(es); reviewed 2 of 2 records in the final query. No vulnerability was confirmed; zero candidates does not establish absence of vulnerabilities.

Bounded NVD searches; incomplete enrichment, aliases, unreviewed pages and unknown configuration can omit applicable CVEs. This is not a vulnerability assessment.

Source: https://services.nvd.nist.gov/rest/json/cves/2.0 (retrieved 2026-10-07T19:50:54.064169+00:00)

- Query: `{'keywordSearch': 'vmware authentication daemon 1.0'}`; HTTP 200; reviewed 2 of 2 records; truncated: False.

- Excluded [CVE-2009-3707](https://nvd.nist.gov/vuln/detail/CVE-2009-3707): Returned vulnerable CPE products do not match the observed application.
- Excluded [CVE-2009-4811](https://nvd.nist.gov/vuln/detail/CVE-2009-4811): Returned vulnerable CPE products do not match the observed application.

## Action Log (audit)

| Time | Tool | Target | Policy | Executed |
|------|------|--------|--------|----------|
| 2026-10-07T19:41:09.863107+00:00 | nmap | 127.0.0.1 | allow | yes |
| 2026-10-07T19:44:32.191530+00:00 | cve_lookup | 127.0.0.1 | DENY | no |
| 2026-10-07T19:44:32.216747+00:00 | http_headers | 127.0.0.1 | allow | yes |
| 2026-10-07T19:45:36.924987+00:00 | http_headers | 127.0.0.1 | allow | yes |
| 2026-10-07T19:49:32.445921+00:00 | cve_lookup | 127.0.0.1 | allow | yes |
| 2026-10-07T19:52:42.999323+00:00 | http_headers | 127.0.0.1 | DENY | no |
| 2026-10-07T19:56:54.507241+00:00 | cve_lookup | 127.0.0.1 | allow | no |
