# Security Policy

## Reporting

Do not open a public issue for a vulnerability that could expose captured
credentials, event databases, API keys, source telemetry, or deployed
listeners. Use a
[private GitHub security advisory](https://github.com/Kousiksamanta1/Honeypot-Sentinel/security/advisories/new)
with sanitized reproduction steps and the expected impact.

## Deployment Guidance

- Run listeners only on systems and networks you are authorized to monitor.
- Keep the Flask dashboard bound to a trusted interface or protected by a
  reverse proxy with authentication.
- Protect `.env`, SQLite databases, and log files with restrictive permissions.
- Configure retention and notices according to applicable privacy and
  monitoring laws.
- Treat all captured input as hostile.

