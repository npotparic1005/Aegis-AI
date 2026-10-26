# Penetration Test Report — Local Lab — DVWA

*Generated: 2026-09-12T18:45:49.975203+00:00*

## Engagement

- **Client:** self
- **Authorization:** personal-lab-owned-hardware
- **Window:** 2025-01-01 → 2030-12-31
- **In-scope hosts:** 127.0.0.1, scanme.nmap.org
- **In-scope domains:** localhost

## Summary

- Actions executed: **4**
- Findings recorded: **15**

## Findings

| Host | Detail |
|------|--------|
| 127.0.0.1 | 135/tcp open msrpc |
| 127.0.0.1 | 445/tcp open microsoft-ds |
| 127.0.0.1 | 902/tcp open vmware-auth 1.10 |
| 127.0.0.1 | 912/tcp open vmware-auth 1.0 |
| 127.0.0.1 | {'host': '127.0.0.1', 'cve': 'CVE-2003-0003', 'severity': 'HIGH', 'cvss': 7.5, 'summary': 'Buffer overflow in the RPC Lo |
| 127.0.0.1 | {'host': '127.0.0.1', 'cve': 'CVE-2003-0352', 'severity': 'HIGH', 'cvss': 7.5, 'summary': 'Buffer overflow in a certain  |
| 127.0.0.1 | {'host': '127.0.0.1', 'cve': 'CVE-2004-0569', 'severity': 'HIGH', 'cvss': 7.5, 'summary': 'The RPC Runtime Library for M |
| 127.0.0.1 | {'host': '127.0.0.1', 'cve': 'CVE-2001-0509', 'severity': 'MEDIUM', 'cvss': 5.0, 'summary': 'Vulnerabilities in RPC serv |
| 127.0.0.1 | {'host': '127.0.0.1', 'cve': 'CVE-2002-1140', 'severity': 'MEDIUM', 'cvss': 5.0, 'summary': 'The Sun Microsystems RPC li |
| 127.0.0.1 | {'host': '127.0.0.1', 'cve': 'CVE-2002-1141', 'severity': 'MEDIUM', 'cvss': 5.0, 'summary': 'An input validation error i |
| 127.0.0.1 | {'host': '127.0.0.1', 'cve': 'CVE-2003-0807', 'severity': 'MEDIUM', 'cvss': 5.0, 'summary': 'Buffer overflow in the COM  |
| 127.0.0.1 | {'host': '127.0.0.1', 'cve': 'CVE-2004-0116', 'severity': 'MEDIUM', 'cvss': 5.0, 'summary': 'An Activation function in t |
| 127.0.0.1 | {'host': '127.0.0.1', 'cve': 'CVE-2000-0771', 'severity': 'LOW', 'cvss': 2.1, 'summary': 'Microsoft Windows 2000 allows  |
| 127.0.0.1 | {'host': '127.0.0.1', 'cve': 'CVE-2004-0124', 'severity': 'LOW', 'cvss': 2.6, 'summary': 'The DCOM RPC interface for Mic |
| 127.0.0.1 | {'host': '127.0.0.1', 'note': 'curl: (7) Failed to connect to 127.0.0.1:80 after 2024 ms: Could not connect to server',  |

## Action Log (audit)

| Time | Tool | Target | Policy | Executed |
|------|------|--------|--------|----------|
| 2026-09-12T18:26:45.354859+00:00 | nmap | 127.0.0.1 | allow | yes |
| 2026-09-12T18:27:35.528032+00:00 | cve_lookup | 127.0.0.1 | allow | yes |
| 2026-09-12T18:33:50.231912+00:00 | cve_lookup | 127.0.0.1 | allow | yes |
| 2026-09-12T18:39:50.521028+00:00 | dns_lookup | example.com | DENY | no |
| 2026-09-12T18:41:14.804917+00:00 | whois | example.com | DENY | no |
| 2026-09-12T18:44:24.506186+00:00 | http_headers | 127.0.0.1 | allow | yes |
