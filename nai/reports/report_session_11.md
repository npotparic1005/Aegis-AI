# Penetration Test Report — Local Lab — DVWA

*Generated: 2026-09-01T12:11:16.178622+00:00*

## Engagement

- **Client:** self
- **Authorization:** personal-lab-owned-hardware
- **Window:** 2025-01-01 → 2030-12-31
- **In-scope hosts:** 127.0.0.1, 10.10.10.0/24
- **In-scope domains:** localhost, dvwa.local

## Summary

- Actions executed: **3**
- Findings recorded: **6**

## Findings

| Host | Detail |
|------|--------|
| 127.0.0.1 | 135/tcp open msrpc |
| 127.0.0.1 | 445/tcp open microsoft-ds |
| 127.0.0.1 | 902/tcp open vmware-auth 1.10 |
| 127.0.0.1 | 912/tcp open vmware-auth 1.0 |
| 127.0.0.1 | {'host': '127.0.0.1', 'cve': 'CVE-2009-3707', 'severity': 'MEDIUM', 'cvss': 5.0, 'summary': 'VMware Authentication Daemo |
| 127.0.0.1 | {'host': '127.0.0.1', 'cve': 'CVE-2009-4811', 'severity': 'MEDIUM', 'cvss': 5.0, 'summary': 'VMware Authentication Daemo |

## Action Log (audit)

| Time | Tool | Target | Policy | Executed |
|------|------|--------|--------|----------|
| 2026-09-01T12:07:19.898067+00:00 | nmap | 127.0.0.1 | allow | yes |
| 2026-09-01T12:08:23.812024+00:00 | cve_lookup | 127.0.0.1 | allow | yes |
| 2026-09-01T12:09:53.121691+00:00 | cve_lookup | 127.0.0.1 | allow | yes |
