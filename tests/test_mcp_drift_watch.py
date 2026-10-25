import json
import tempfile
import unittest
from pathlib import Path

from mcp_drift_watch import snapshot, compare, make_report, render_html, main


class DriftTests(unittest.TestCase):
    def test_unchanged_and_reordered(self):
        one = {"mcpServers": {"a": {"command": "node", "env": {"X": "secret"}, "args": ["test"]}}}
        self.assertEqual(compare(snapshot(one), one), [])
        self.assertEqual(compare(snapshot(one), {"mcpServers": {"a": {"args": ["test"], "env": {"X": "secret"}, "command": "node"}}}), [])

    def test_change_severity(self):
        old = snapshot({"mcpServers": {"a": {"command": "node", "args": ["one"]}}})
        changed = {"mcpServers": {"a": {"command": "bash", "args": ["two"], "env": {"TOKEN": "example"}}}}
        changes = compare(old, changed)
        self.assertEqual({c["change"] for c in changes}, {"connection", "arguments", "environment"})
        self.assertEqual(sum(c["severity"] == "high" for c in changes), 2)

    def test_add_remove(self):
        old = snapshot({"mcpServers": {"removed": {"command": "python"}}})
        changes = compare(old, {"servers": {"added": {"url": "https://example.org"}}})
        self.assertEqual({c["change"] for c in changes}, {"added", "removed"})

    def test_no_sensitive_values_or_markup(self):
        secret = "NEVER_PRINT_SECRET_194"
        name = "<img src=x onerror=alert(1)>"
        config = {"mcpServers": {name: {"command": "node", "args": [secret], "env": {"API_KEY": secret}, "url": "https://example.com/?token=" + secret}}}
        baseline = snapshot(config)
        self.assertNotIn(secret, json.dumps(baseline))
        report = make_report(compare(snapshot({"mcpServers": {}}), config))
        html = render_html(report)
        self.assertNotIn(secret, html)
        self.assertNotIn(name, html)
        self.assertIn("&lt;img", html)

    def test_baseline_validation(self):
        with self.assertRaises(ValueError):
            compare({"format": "wrong"}, {"mcpServers": {}})
        with self.assertRaises(ValueError):
            snapshot({"other": {}})

    def test_cli_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            cfg = d / "config.json"
            cfg.write_text('{"mcpServers":{"a":{"command":"node"}}}', encoding="utf-8")
            baseline = d / "baseline.json"
            page = d / "report.html"
            report = d / "report.json"
            self.assertEqual(main(["snapshot", str(cfg), "-o", str(baseline)]), 0)
            self.assertEqual(main(["check", str(cfg), "-b", str(baseline), "-o", str(page), "--json", str(report), "--fail-on", "any"]), 0)
            self.assertTrue(page.exists())
            cfg.write_text('{"mcpServers":{"a":{"command":"bash"}}}', encoding="utf-8")
            self.assertEqual(main(["check", str(cfg), "-b", str(baseline), "-o", str(page), "--fail-on", "high"]), 2)
            self.assertIn("connection", page.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
