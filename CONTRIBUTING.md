# Contributing

Thanks for helping improve Honeypot Sentinel.

## Lab Safety

- Develop and test in an isolated environment you control.
- Use synthetic source addresses, credentials, commands, and event data.
- Never commit captured credentials, public IP telemetry, database files,
  deployment secrets, or production logs.
- Do not expose the dashboard publicly without authentication and network
  controls.

## Development Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Run the test suite:

```bash
python -m unittest discover -s tests -v
```

## Pull Requests

- Keep each change focused and explain its monitoring value.
- Add tests for persistence, profiling, thresholds, enrichment, or API changes.
- Preserve bounded network operations and graceful shutdown behavior.
- Update deployment and privacy guidance when data collection changes.

By contributing, you agree that your contribution is licensed under the MIT
License.

