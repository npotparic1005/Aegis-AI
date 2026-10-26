# Penetration Test Report — Local Lab — DVWA

*Generated: 2026-09-02T10:22:42.573844+00:00*

## Engagement

- **Client:** self
- **Authorization:** personal-lab-owned-hardware
- **Window:** 2025-01-01 → 2030-12-31
- **In-scope hosts:** 127.0.0.1, scanme.nmap.org
- **In-scope domains:** 0.0.0.0/0, localhost, scanme.nmap.org

## Summary

- Actions executed: **2**
- Findings recorded: **12**

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
| 45.33.32.156 | {'host': '45.33.32.156', 'header': 'Date', 'value': 'Wed, 02 Sep 2026 10:20:27 GMT', 'summary': 'Date: Wed, 02 Sep 2026  |
| 45.33.32.156 | {'host': '45.33.32.156', 'header': 'Server', 'value': 'Apache/2.4.7 (Ubuntu)', 'summary': 'Server: Apache/2.4.7 (Ubuntu) |
| 45.33.32.156 | {'host': '45.33.32.156', 'header': 'Accept-Ranges', 'value': 'bytes', 'summary': 'Accept-Ranges: bytes'} |
| 45.33.32.156 | {'host': '45.33.32.156', 'header': 'Vary', 'value': 'Accept-Encoding', 'summary': 'Vary: Accept-Encoding'} |
| 45.33.32.156 | {'host': '45.33.32.156', 'header': 'Content-Type', 'value': 'text/html', 'summary': 'Content-Type: text/html'} |

## Action Log (audit)

| Time | Tool | Target | Policy | Executed |
|------|------|--------|--------|----------|
| 2026-09-02T10:17:37.052648+00:00 | nmap | scanme.nmap.org | allow | yes |
| 2026-09-02T10:20:21.041802+00:00 | http_headers | 45.33.32.156 | allow | yes |
| 2026-09-02T10:21:55.825716+00:00 | zap | 45.33.32.156 | DENY | no |
| 2026-09-02T10:22:19.505061+00:00 | zap | 45.33.32.156 | DENY | no |
