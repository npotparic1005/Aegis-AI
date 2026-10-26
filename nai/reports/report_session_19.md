# Penetration Test Report — Local Lab — DVWA

*Generated: 2026-09-02T09:11:06.785100+00:00*

## Engagement

- **Client:** self
- **Authorization:** personal-lab-owned-hardware
- **Window:** 2025-01-01 → 2030-12-31
- **In-scope hosts:** 127.0.0.1, scanme.nmap.org
- **In-scope domains:** 0.0.0.0/0, localhost, scanme.nmap.org

## Summary

- Actions executed: **4**
- Findings recorded: **10**

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
| 45.33.32.156 | {'host': '45.33.32.156', 'cve': 'CVE-2021-44224', 'severity': 'HIGH', 'cvss': 8.2, 'summary': 'A crafted URI sent to htt |
| 45.33.32.156 | {'host': '45.33.32.156', 'header': 'Server', 'value': 'Apache/2.4.7 (Ubuntu)', 'summary': 'Server: Apache/2.4.7 (Ubuntu) |
| 45.33.32.156 | {'host': '45.33.32.156', 'header': 'Content-Type', 'value': 'text/html', 'summary': 'Content-Type: text/html'} |

## Action Log (audit)

| Time | Tool | Target | Policy | Executed |
|------|------|--------|--------|----------|
| 2026-09-02T09:02:52.503433+00:00 | nmap | scanme.nmap.org | allow | yes |
| 2026-09-02T09:04:56.676548+00:00 | http_headers | 45.33.32.156 | allow | yes |
| 2026-09-02T09:06:37.593983+00:00 | zap | 45.33.32.156 | DENY | no |
| 2026-09-02T09:06:59.043989+00:00 | cve_lookup | 45.33.32.156 | allow | yes |
| 2026-09-02T09:08:36.068683+00:00 | http_headers | 45.33.32.156 | allow | yes |
| 2026-09-02T09:10:45.851109+00:00 | zap | 45.33.32.156 | DENY | no |
