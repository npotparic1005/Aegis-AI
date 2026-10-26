# Penetration Test Report — Local Lab — DVWA

*Generated: 2026-09-12T18:04:58.683847+00:00*

## Engagement

- **Client:** self
- **Authorization:** personal-lab-owned-hardware
- **Window:** 2025-01-01 → 2030-12-31
- **In-scope hosts:** 127.0.0.1, scanme.nmap.org
- **In-scope domains:** localhost

## Summary

- Actions executed: **2**
- Findings recorded: **13**

## Findings

| Host | Detail |
|------|--------|
| 45.33.32.156 | 19/tcp filtered chargen |
| 45.33.32.156 | 22/tcp open ssh 6.6.1p1 Ubuntu 2ubuntu2.13 |
| 45.33.32.156 | 25/tcp filtered smtp |
| 45.33.32.156 | 80/tcp open http 2.4.7 |
| 45.33.32.156 | 113/tcp filtered ident |
| 45.33.32.156 | 135/tcp filtered msrpc |
| 45.33.32.156 | 139/tcp filtered netbios-ssn |
| 45.33.32.156 | 515/tcp filtered printer |
| 45.33.32.156 | 1025/tcp filtered NFS-or-IIS |
| 45.33.32.156 | 6129/tcp filtered |
| 45.33.32.156 | 9929/tcp open nping-echo |
| 45.33.32.156 | 31337/tcp open tcpwrapped |
| scanme.nmap.org | {'host': 'scanme.nmap.org', 'note': 'curl: (28) Operation timed out after 15013 milliseconds with 0 bytes received'} |

## Action Log (audit)

| Time | Tool | Target | Policy | Executed |
|------|------|--------|--------|----------|
| 2026-09-12T17:58:56.480821+00:00 | nmap | scanme.nmap.org | allow | yes |
| 2026-09-12T18:00:41.473612+00:00 | http_headers | scanme.nmap.org | allow | yes |
