"""Offline MCP configuration drift detection. Never executes servers or connects to them."""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import sys
from pathlib import Path
from typing import Any

MAX_BYTES = 2_000_000
VERSION = 1
FIELDS = ("connection", "arguments", "environment", "metadata")


def read_json(path: Path) -> Any:
    if path.stat().st_size > MAX_BYTES:
        raise ValueError("File exceeds the 2 MB limit")
    return json.loads(path.read_text(encoding="utf-8"))


def server_entries(config: Any) -> dict[str, dict]:
    if not isinstance(config, dict):
        raise ValueError("Config root must be an object")
    key = next((k for k in ("mcpServers", "servers") if k in config), None)
    if key is None or not isinstance(config[key], dict):
        raise ValueError("Expected an object named 'mcpServers' or 'servers'")
    for name, entry in config[key].items():
        if not isinstance(entry, dict):
            raise ValueError(f"Server entry {name!r} must be an object")
    return config[key]


def digest(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def describe(entry: dict) -> dict[str, str]:
    # Only hashes go into the saved snapshot; secrets and sensitive arguments stay local.
    connection = {k: entry[k] for k in ("command", "url", "type") if k in entry}
    environment = {k: entry[k] for k in ("env", "headers") if k in entry}
    metadata = {k: v for k, v in entry.items() if k not in {"command", "url", "type", "args", "env", "headers"}}
    return {
        "connection": digest(connection),
        "arguments": digest(entry.get("args")),
        "environment": digest(environment),
        "metadata": digest(metadata),
    }


def snapshot(config: Any) -> dict:
    return {
        "format": "mcp-drift-watch",
        "version": VERSION,
        "notice": "Contains SHA-256 fingerprints; treat as sensitive metadata and do not publish blindly.",
        "servers": {name: describe(value) for name, value in sorted(server_entries(config).items())},
    }


def compare(baseline: Any, current: Any) -> list[dict[str, str]]:
    if not isinstance(baseline, dict) or baseline.get("format") != "mcp-drift-watch" or baseline.get("version") != VERSION:
        raise ValueError("Invalid baseline format or version")
    old = baseline.get("servers")
    if not isinstance(old, dict) or any(not isinstance(v, dict) or any(not isinstance(v.get(f), str) or len(v[f]) != 64 for f in FIELDS) for v in old.values()):
        raise ValueError("Malformed snapshot data")
    new = snapshot(current)["servers"]
    changes = []
    for name in sorted(set(old) | set(new)):
        if name not in old:
            changes.append({"server": name, "change": "added", "severity": "high", "detail": "New MCP server added. Review its source and scope before trusting it."})
        elif name not in new:
            changes.append({"server": name, "change": "removed", "severity": "info", "detail": "MCP server removed."})
        else:
            for field in FIELDS:
                if old[name][field] != new[name][field]:
                    severity = "high" if field in ("connection", "environment") else "medium"
                    changes.append({"server": name, "change": field, "severity": severity, "detail": {
                        "connection": "Launch command, transport, or remote URL changed.",
                        "arguments": "Server launch arguments changed.",
                        "environment": "Environment settings or request headers changed.",
                        "metadata": "Other server configuration properties changed.",
                    }[field]})
    return changes


def make_report(changes: list[dict[str, str]]) -> dict:
    return {
        "tool": "MCP Drift Watch",
        "note": "Static configuration diff only; runtime MCP tool definitions are not inspected.",
        "changed": bool(changes),
        "summary": {level: sum(c["severity"] == level for c in changes) for level in ("high", "medium", "info")},
        "changes": changes,
    }


def render_html(report: dict) -> str:
    escape = lambda s: html.escape(str(s), quote=True)
    cards = "".join(
        '<article><div class="top"><strong>' + escape(c["server"]) + '</strong><span class="tag ' +
        escape(c["severity"]) + '">' + escape(c["severity"]) + '</span></div><p><b>' +
        escape(c["change"].replace("_", " ").title()) + '</b> · ' + escape(c["detail"]) + '</p></article>'
        for c in report["changes"]
    )
    if not cards:
        cards = '<article><strong>No configuration drift detected.</strong><p>The selected snapshot matches this config for the tracked fields.</p></article>'
    stats = report["summary"]
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>MCP Drift Watch</title>
<style>
:root{{color-scheme:dark;font-family:system-ui,-apple-system,sans-serif}}*{{box-sizing:border-box}}
body{{margin:0;background:#0b1421;color:#edf4f8}}main{{max-width:900px;margin:auto;padding:50px 22px}}
small{{color:#72dbbb;letter-spacing:.16em;font-weight:700;text-transform:uppercase}}
h1{{font-size:clamp(30px,5vw,54px);margin:8px 0}}.muted{{color:#afc2d1}}
.metrics{{display:flex;gap:12px;flex-wrap:wrap;margin:30px 0}}.metric{{background:#182b3a;border:1px solid #2a4a58;border-radius:12px;padding:18px;flex:1;min-width:130px}}
.metric b{{display:block;font-size:29px}}article{{background:#15273a;border:1px solid #345164;border-radius:14px;padding:20px;margin:14px 0;overflow-wrap:anywhere}}
.top{{display:flex;align-items:center;justify-content:space-between;gap:12px}}.tag{{font-size:11px;text-transform:uppercase;padding:4px 8px;border-radius:6px;background:#29546c}}
.tag.high{{background:#9a4150}}.tag.medium{{background:#856333}}p{{color:#bdd0dc;line-height:1.5}}
aside{{padding:15px;background:#203c38;border-radius:10px;color:#c8ebe0;font-size:13px}}
</style></head><body><main><small>Offline · Read-only · Open source</small><h1>MCP Drift Watch</h1>
<p class="muted">Know when your AI agent's MCP connections change.</p>
<div class="metrics"><div class="metric"><b>{stats["high"]}</b>High</div><div class="metric"><b>{stats["medium"]}</b>Medium</div><div class="metric"><b>{stats["info"]}</b>Info</div></div>
<aside>Static configuration differences only. Changes are not proof of an attack. MCP runtime tool definitions are not evaluated.</aside>
<h2>Configuration changes</h2>{cards}<p class="muted">Report generated locally. Credential values and command arguments are intentionally omitted.</p></main></body></html>"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline MCP configuration drift checker.")
    sub = parser.add_subparsers(dest="action", required=True)
    snap = sub.add_parser("snapshot", help="Create a local fingerprint baseline")
    snap.add_argument("config", type=Path)
    snap.add_argument("-o", "--output", type=Path, default=Path("mcp-baseline.json"))
    check = sub.add_parser("check", help="Compare current config with a baseline")
    check.add_argument("config", type=Path)
    check.add_argument("-b", "--baseline", type=Path, default=Path("mcp-baseline.json"))
    check.add_argument("-o", "--output", type=Path, default=Path("mcp-drift-report.html"))
    check.add_argument("--json", dest="json_output", type=Path)
    check.add_argument("--fail-on", choices=("none", "high", "any"), default="none")
    args = parser.parse_args(argv)
    try:
        current = read_json(args.config)
        if args.action == "snapshot":
            result = snapshot(current)
            args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            print(f"Created baseline for {len(result['servers'])} MCP server(s): {args.output}")
            return 0
        baseline = read_json(args.baseline)
        report = make_report(compare(baseline, current))
        args.output.write_text(render_html(report), encoding="utf-8")
        if args.json_output:
            args.json_output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"Detected {len(report['changes'])} change(s). Report: {args.output}")
        if args.fail_on == "any" and report["changed"]:
            return 2
        if args.fail_on == "high" and report["summary"]["high"]:
            return 2
        return 0
    except (OSError, ValueError, UnicodeError, TypeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
