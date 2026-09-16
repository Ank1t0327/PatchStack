import argparse
from flask import Flask, jsonify, render_template_string, make_response
from patchstack.storage.db import ScanDatabaseManager


def create_dashboard_app(db_path: str = "patchstack.db") -> Flask:
    app = Flask(__name__)
    db_manager = ScanDatabaseManager(db_path)

    DASHBOARD_HTML = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>PatchStack Security Dashboard</title>
        <style>
            body { font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 20px; }
            .terminal-card {
                border: 2px solid #30363d;
                border-radius: 6px;
                background: #161b22;
                max-width: 650px;
                margin: 20px auto;
                box-shadow: 0 4px 12px rgba(0,0,0,0.5);
            }
            .title-bar {
                background: #21262d;
                padding: 10px 15px;
                border-bottom: 2px solid #30363d;
                font-weight: bold;
                color: #58a6ff;
            }
            .section { padding: 15px; border-bottom: 1px solid #30363d; }
            .row { display: flex; justify-content: space-between; margin: 6px 0; }
            .crit { color: #f85149; font-weight: bold; }
            .high { color: #ff7b72; font-weight: bold; }
            .med { color: #d29922; }
            .low { color: #3fb950; }
            table { width: 100%; border-collapse: collapse; margin-top: 10px; }
            th, td { text-align: left; padding: 6px; border-bottom: 1px solid #21262d; }
            th { color: #8b949e; }
        </style>
    </head>
    <body>
        <div class="terminal-card">
            <div class="title-bar">┌─────────────────────────────────┐<br>│ PATCHSTACK SECURITY DASHBOARD   │<br>└─────────────────────────────────┘</div>
            {% if scan %}
            <div class="section">
                <div class="row"><span>Target URL</span><span><strong>{{ scan.target_url }}</strong></span></div>
                <div class="row"><span>Risk Score</span><span class="crit"><strong>{{ scan.risk_score }}/10</strong></span></div>
                <div class="row"><span>Total Findings</span><span>{{ scan.total_findings }}</span></div>
            </div>
            <div class="section">
                <div class="row"><span class="crit">Critical</span><span class="crit">{{ counts.Critical }}</span></div>
                <div class="row"><span class="high">High</span><span class="high">{{ counts.High }}</span></div>
                <div class="row"><span class="med">Medium</span><span class="med">{{ counts.Medium }}</span></div>
                <div class="row"><span class="low">Low</span><span class="low">{{ counts.Low }}</span></div>
            </div>
            <div class="section">
                <div style="font-weight:bold; margin-bottom:8px; color:#58a6ff;">Vulnerabilities Inventory</div>
                <table>
                    <thead>
                        <tr><th>Finding Title</th><th>Severity</th><th>CWE</th></tr>
                    </thead>
                    <tbody>
                        {% for f in findings %}
                        <tr>
                            <td>{{ f.title }}</td>
                            <td><span class="{{ f.severity.lower() }}">{{ f.severity }}</span></td>
                            <td>{{ f.cwe }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% else %}
            <div class="section">No scan history recorded in database. Run <code>patchstack --audit</code> to initiate scan.</div>
            {% endif %}
        </div>
    </body>
    </html>
    """

    @app.route("/", methods=["GET"])
    def index():
        scan = db_manager.get_latest_scan()
        if not scan:
            return render_template_string(DASHBOARD_HTML, scan=None)

        details = scan.get("details", {})
        findings = details.get("findings", [])

        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in findings:
            sev = f.get("severity", "").capitalize()
            if sev in counts:
                counts[sev] += 1

        return render_template_string(DASHBOARD_HTML, scan=scan, counts=counts, findings=findings)

    @app.route("/api/v1/scan/latest", methods=["GET"])
    def api_latest():
        scan = db_manager.get_latest_scan()
        if not scan:
            return jsonify({"error": "No scan data available"}), 404
        return jsonify(scan)

    return app


def main():
    parser = argparse.ArgumentParser(description="PatchStack Dashboard Server")
    parser.add_argument("--port", type=int, default=8080, help="Port to run dashboard on (default: 8080)")
    parser.add_argument("--db", type=str, default="patchstack.db", help="Path to SQLite scan database")
    args = parser.parse_args()

    app = create_dashboard_app(args.db)
    print(f"[*] Starting PatchStack Dashboard on http://127.0.0.1:{args.port}")
    app.run(host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
