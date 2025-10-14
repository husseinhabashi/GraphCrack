#!/usr/bin/env python3
"""
Report Generator for GraphQL Crack Engine
Generates color-coded HTML + JSON reports with risk scoring summary
and also outputs the HTML directly to the terminal.
"""

import json
from pathlib import Path
from typing import Dict, Any
from datetime import datetime, timezone


class ReportGenerator:
    def __init__(self, results: Dict[str, Any]):
        self.results = results
        self.results["meta"]["finished_at"] = datetime.now(timezone.utc).isoformat()

    def generate_html_report(self, outfile: str) -> str:
        out_path = Path(outfile)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        # Save JSON report
        json_path = out_path.with_suffix(".json")
        with open(json_path, "w", encoding="utf-8") as jf:
            json.dump(self.results, jf, indent=2, ensure_ascii=False)
        print(f"[+] Raw JSON report saved: {json_path}")

        meta = self.results.get("meta", {})
        vulns = self.results.get("vulnerabilities", [])
        findings = self.results.get("findings", [])
        risk_score = meta.get("risk_score", 0)
        risk_label = meta.get("risk_label", "N/A")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>GraphQL Crack Report – {meta.get('target','Unknown Target')}</title>
<style>
body {{
  font-family: monospace;
  background: #0d1117;
  color: #e6edf3;
  padding: 30px;
}}
h1, h2, h3 {{
  color: #58a6ff;
}}
pre {{
  background: #161b22;
  padding: 10px;
  border-radius: 6px;
  overflow-x: auto;
}}
.card {{
  background: #161b22;
  padding: 12px;
  border-radius: 6px;
  margin-bottom: 10px;
  border-left: 5px solid #30363d;
}}
.severity-critical {{ border-color: #f85149; }}
.severity-high {{ border-color: #d29922; }}
.severity-medium {{ border-color: #58a6ff; }}
.severity-low {{ border-color: #3fb950; }}
.severity-info {{ border-color: #8b949e; }}
.risk-summary {{
  background: #161b22;
  border-left: 5px solid #58a6ff;
  padding: 12px;
  border-radius: 6px;
  margin-bottom: 16px;
}}
.risk-critical {{ color: #f85149; }}
.risk-high {{ color: #d29922; }}
.risk-medium {{ color: #58a6ff; }}
.risk-low {{ color: #3fb950; }}
.risk-info {{ color: #8b949e; }}
</style>
</head>
<body>

<h1>GraphQL Crack Report</h1>
<p><b>Target:</b> {meta.get('target','N/A')}<br>
<b>Mode:</b> {meta.get('mode','N/A')}<br>
<b>Started:</b> {meta.get('started_at','N/A')}<br>
<b>Finished:</b> {meta.get('finished_at','N/A')}</p>

<div class="risk-summary">
  <b>Overall Risk Score:</b> {risk_score}/100<br>
  <b>Overall Risk Level:</b> <span class="risk-{risk_label.lower()}">{risk_label}</span><br>
  <b>Total Vulnerabilities:</b> {len(vulns)}<br>
  <b>Total Findings:</b> {len(findings)}
</div>

<h2>Vulnerabilities</h2>
{"".join(self._render_vuln(v) for v in vulns) or "<p>No vulnerabilities found.</p>"}

<h2>Findings</h2>
{"".join(self._render_finding(f) for f in findings) or "<p>No findings available.</p>"}

<h2>Raw JSON Results</h2>
<pre>{json.dumps(self.results, indent=2, ensure_ascii=False)}</pre>

</body>
</html>
"""

        # Write HTML file
        with open(out_path, "w", encoding="utf-8") as hf:
            hf.write(html)

        # Output the HTML to the terminal (preview)
        print("\n" + "─" * 80)
        print(f"[+] HTML report generated: {out_path}")
        print("─" * 80)
        print(html)
        print("─" * 80)
        print(f"[*] End of HTML output preview for: {out_path}\n")

        return str(out_path)

    def _render_vuln(self, v: Dict[str, Any]) -> str:
        sev = str(v.get("risk_label") or v.get("severity", "info")).lower()
        return f"""
<div class="card severity-{sev}">
  <b>{v.get('type','unknown')}</b><br>
  {v.get('description','')}<br>
  <small>
    Severity: {v.get('severity','N/A')} |
    Risk Score: {v.get('risk_score',0)} |
    Label: {v.get('risk_label','N/A')} |
    Exploitability: {v.get('exploitability','N/A')} |
    Exposure: {v.get('exposure','N/A')}
  </small>
</div>"""

    def _render_finding(self, f: Dict[str, Any]) -> str:
        return f"""
<div class="card">
  <b>{f.get('type','unknown')}</b><br>
  {f.get('description','')}
</div>"""