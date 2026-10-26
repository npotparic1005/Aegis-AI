# Penetration Test Report — Local Lab — DVWA

*Generated: 2026-09-11T07:09:31.549820+00:00*

## Engagement

- **Client:** self
- **Authorization:** personal-lab-owned-hardware
- **Window:** 2025-01-01 → 2030-12-31
- **In-scope hosts:** 127.0.0.1, scanme.nmap.org
- **In-scope domains:** 0.0.0.0/0, localhost, scanme.nmap.org

## Summary

- Actions executed: **4**
- Findings recorded: **7**

## Findings

| Host | Detail |
|------|--------|
| 127.0.0.1 | 135/tcp open msrpc |
| 127.0.0.1 | 445/tcp open microsoft-ds |
| 127.0.0.1 | 902/tcp open vmware-auth 1.10 |
| 127.0.0.1 | 912/tcp open vmware-auth 1.0 |
| 127.0.0.1 | {'host': '127.0.0.1', 'header': '220 VMware Authentication Daemon Version 1.10', 'value': 'SSL Required, ServerDaemonPro |
| 127.0.0.1 | {'host': '127.0.0.1', 'cve': 'CVE-2009-3707', 'severity': 'MEDIUM', 'cvss': 5.0, 'summary': 'VMware Authentication Daemo |
| 127.0.0.1 | {'host': '127.0.0.1', 'cve': 'CVE-2009-4811', 'severity': 'MEDIUM', 'cvss': 5.0, 'summary': 'VMware Authentication Daemo |

## Action Log (audit)

| Time | Tool | Target | Policy | Executed |
|------|------|--------|--------|----------|
| 2026-09-11T06:59:00.750365+00:00 | nmap | 127.0.0.1 | allow | yes |
| 2026-09-11T07:01:46.370484+00:00 | cve_lookup | 127.0.0.1 | allow | yes |
| 2026-09-11T07:03:26.988111+00:00 | http_headers | 127.0.0.1 | allow | yes |
| 2026-09-11T07:04:08.859392+00:00 | cve_lookup | 127.0.0.1 | allow | yes |
