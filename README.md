# MCP Drift Watch

**Know when your AI agent's MCP connections change.**

A tiny, open-source, **offline, read-only** MCP configuration drift detector. Save a fingerprint baseline, compare it with your current MCP configuration, and generate a standalone HTML report. No API keys, third-party services, or database needed.

## Quick start

Python 3.10+ required.

```bash
git clone https://github.com/Sunnylincc/MCP-Drift-Watch.git
cd MCP-Drift-Watch
python mcp_drift_watch.py snapshot examples/initial.json -o baseline.json
python mcp_drift_watch.py check examples/changed.json -b baseline.json -o drift.html --json changes.json
```

Open `drift.html` in a browser to view the results.

For your own configuration:

```bash
python mcp_drift_watch.py snapshot /path/to/mcp.json -o my-baseline.json
# Later, after the config changes:
python mcp_drift_watch.py check /path/to/mcp.json -b my-baseline.json -o my-drift.html
```

Optional installation:

```bash
python -m pip install .
mcp-drift snapshot examples/initial.json -o baseline.json
mcp-drift check examples/changed.json -b baseline.json
```

## What it detects

- Servers added or removed
- Changed local launch command or remote MCP URL
- Changed command arguments
- Changed environment settings and request headers
- Other configuration metadata changes
- High / medium / informational severity annotations
- HTML and optional JSON report outputs

The snapshot saves **SHA-256 fingerprints** for each tracked field, not raw command arguments, credentials, URLs, or environment values. This makes it suitable for local baselines, but remember that **hashes can still reveal information** if original values are guessable. Do not publicly post baselines or reports without review.

## Automation / CI

`--fail-on high` returns exit code 2 when high-severity changes are detected. `--fail-on any` returns 2 on any drift. Default is `--fail-on none` (successful check exits 0 even with changes).

Exit code 1 indicates an input or execution error. You can use these exit codes in local scripts or CI.

## What it does NOT do

- Does not launch MCP servers or execute commands
- Does not connect to remote services or read their tool definitions
- Does not monitor running processes
- Does not prove an attack, vulnerability, or actual permission escalation
- Does not inspect secrets inside environment values

MCP tool-schema or behavior drift is **not** included in v0.1. The comparison is based only on locally supplied configuration content.

## Tests

```bash
python -m unittest discover -s tests -v
```

## Contributions

PRs welcome! Please include tests and no real secrets. Read [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE).
