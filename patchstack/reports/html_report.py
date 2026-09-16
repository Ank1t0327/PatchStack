import os
from typing import Any
from patchstack.reports.base import BaseReportExporter


class HTMLReportExporter(BaseReportExporter):
    """
    Generates a standalone, dark-themed HTML Security Assessment Report.
    """

    def export(self, scan_result: Any, output_path: str) -> str:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

        recon_info = scan_result.recon
        server_tech = recon_info.fingerprint.server if recon_info else "Unknown"
        framework_tech = recon_info.fingerprint.framework if recon_info else "Unknown"

        # Severity metrics counts
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in scan_result.findings:
            sev = f.severity.value.capitalize()
            if sev in counts:
                counts[sev] += 1

        rows_html = ""
        for i, f in enumerate(scan_result.findings, 1):
            sev_class = f.severity.value.lower()
            rows_html += f"""
            <tr class="finding-row {sev_class}">
                <td>{i}</td>
                <td><span class="badge {sev_class}">{f.severity.value}</span></td>
                <td><strong>{f.title}</strong><br><small class="text-muted">{f.id}</small></td>
                <td><code>{f.endpoint}</code></td>
                <td><code>{f.parameter or 'N/A'}</code></td>
                <td><span class="badge badge-cwe">{f.cwe}</span><br><small>{f.owasp_category}</small></td>
                <td><pre>{f.evidence}</pre></td>
                <td>{f.remediation}</td>
            </tr>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>PatchStack Security Report - {scan_result.target_url}</title>
    <style>
        :root {{
            --bg-color: #0d1117;
            --card-bg: #161b22;
            --border-color: #30363d;
            --text-color: #c9d1d9;
            --accent-color: #58a6ff;
            --critical-color: #f85149;
            --high-color: #ff7b72;
            --medium-color: #d29922;
            --low-color: #3fb950;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 20px 40px;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0;
            color: var(--accent-color);
            font-size: 28px;
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .metric-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}
        .metric-card h3 {{
            margin: 0 0 10px 0;
            font-size: 14px;
            text-transform: uppercase;
            color: #8b949e;
        }}
        .metric-card .value {{
            font-size: 32px;
            font-weight: bold;
        }}
        .risk-score {{ color: var(--critical-color); }}
        .count-critical {{ color: var(--critical-color); }}
        .count-high {{ color: var(--high-color); }}
        .count-medium {{ color: var(--medium-color); }}
        .count-low {{ color: var(--low-color); }}

        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow: hidden;
            margin-top: 20px;
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
            font-size: 14px;
        }}
        th {{
            background-color: #21262d;
            color: #f0f6fc;
        }}
        .badge {{
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 12px;
            text-transform: uppercase;
        }}
        .badge.critical {{ background: rgba(248, 81, 73, 0.2); color: var(--critical-color); border: 1px solid var(--critical-color); }}
        .badge.high {{ background: rgba(255, 123, 114, 0.2); color: var(--high-color); border: 1px solid var(--high-color); }}
        .badge.medium {{ background: rgba(210, 153, 34, 0.2); color: var(--medium-color); border: 1px solid var(--medium-color); }}
        .badge.low {{ background: rgba(63, 185, 80, 0.2); color: var(--low-color); border: 1px solid var(--low-color); }}
        .badge-cwe {{ background: #1f6beb; color: #ffffff; }}
        pre {{
            margin: 0;
            white-space: pre-wrap;
            font-family: monospace;
            font-size: 12px;
            background: #0d1117;
            padding: 8px;
            border-radius: 4px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>🛡️ PatchStack Security Assessment Report</h1>
            <p>Target: <code>{scan_result.target_url}</code> | Server: {server_tech} ({framework_tech})</p>
        </div>
    </div>

    <div class="metrics-grid">
        <div class="metric-card">
            <h3>Overall Risk Score</h3>
            <div class="value risk-score">{scan_result.risk_score}/10</div>
        </div>
        <div class="metric-card">
            <h3>Critical</h3>
            <div class="value count-critical">{counts['Critical']}</div>
        </div>
        <div class="metric-card">
            <h3>High</h3>
            <div class="value count-high">{counts['High']}</div>
        </div>
        <div class="metric-card">
            <h3>Medium</h3>
            <div class="value count-medium">{counts['Medium']}</div>
        </div>
        <div class="metric-card">
            <h3>Low</h3>
            <div class="value count-low">{counts['Low']}</div>
        </div>
    </div>

    <h2>Vulnerability Findings ({scan_result.total_findings})</h2>
    <table>
        <thead>
            <tr>
                <th>#</th>
                <th>Severity</th>
                <th>Vulnerability Title</th>
                <th>Endpoint</th>
                <th>Parameter</th>
                <th>CWE / OWASP</th>
                <th>Evidence</th>
                <th>Remediation</th>
            </tr>
        </thead>
        <tbody>
            {rows_html if rows_html else '<tr><td colspan="8" style="text-align:center;">No vulnerability findings reported.</td></tr>'}
        </tbody>
    </table>
</body>
</html>
"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        return output_path
