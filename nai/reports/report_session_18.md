# Penetration Test Report — Local Lab — DVWA

*Generated: 2026-09-02T08:11:44.785938+00:00*

## Engagement

- **Client:** self
- **Authorization:** personal-lab-owned-hardware
- **Window:** 2025-01-01 → 2030-12-31
- **In-scope hosts:** 127.0.0.1, scanme.nmap.org
- **In-scope domains:** 0.0.0.0/0, localhost, scanme.nmap.org

## Summary

- Actions executed: **1**
- Findings recorded: **7**

## Findings

| Host | Detail |
|------|--------|
| 45.33.32.156 | 22/tcp open ssh 6.6.1p1 Ubuntu 2ubuntu2.13 |
| 45.33.32.156 | 80/tcp open http 2.4.7 |
| 45.33.32.156 | 646/tcp filtered ldp |
| 45.33.32.156 | 2000/tcp open tcpwrapped |
| 45.33.32.156 | 5060/tcp open tcpwrapped |
| 45.33.32.156 | 9929/tcp open nping-echo |
| 45.33.32.156 | 31337/tcp open tcpwrapped |

## Action Log (audit)

| Time | Tool | Target | Policy | Executed |
|------|------|--------|--------|----------|
| 2026-09-02T08:08:13.005508+00:00 | nmap | scanme.nmap.org | allow | yes |
| 2026-09-02T08:10:31.997512+00:00 | http_headers | 45.33.32.156 | DENY | no |
| 2026-09-02T08:10:57.792848+00:00 | cve_lookup | 45.33.32.156 | DENY | no |
| 2026-09-02T08:11:22.343958+00:00 | http_headers | 45.33.32.156 | DENY | no |
