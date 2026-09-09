import pytest
from patchstack.recon.parser import HTMLReconParser
from patchstack.recon.fingerprint import TechnologyFingerprinter
from patchstack.recon.engine import ReconEngine
from patchstack.scanner.http_client import HTTPResponseTelemetry
from patchstack.target_app.app import create_app


def test_html_recon_parser():
    sample_html = """
    <html>
        <body>
            <a href="/about">About Us</a>
            <a href="https://external.com/page">External</a>
            <form action="/login" method="POST">
                <input type="text" name="user" required>
                <input type="password" name="pass" required>
                <button type="submit">Submit</button>
            </form>
        </body>
    </html>
    """
    links, forms, scripts, meta = HTMLReconParser.parse_html(sample_html, "http://127.0.0.1:5000")

    assert "http://127.0.0.1:5000/about" in links
    assert "https://external.com/page" in links
    assert len(forms) == 1
    assert forms[0].action == "http://127.0.0.1:5000/login"
    assert forms[0].method == "POST"
    assert len(forms[0].fields) == 2
    assert forms[0].fields[0].name == "user"
    assert forms[0].fields[0].required is True


def test_technology_fingerprinter():
    telemetry = HTTPResponseTelemetry(
        url="http://127.0.0.1:5000",
        status_code=200,
        headers={"Server": "Flask/3.0.0 (Werkzeug/3.0.1 Python/3.10)", "X-Powered-By": "PatchStack-TargetApp/1.0"},
        body="<html><body>Werkzeug</body></html>",
        elapsed_ms=10.0,
        cookies={"session": "test_session_id_123"},
    )
    fp = TechnologyFingerprinter.analyze(telemetry)

    assert fp.framework == "Flask"
    assert fp.programming_language == "Python"
    assert "Flask" in fp.technologies
    assert "Python" in fp.technologies


def test_recon_engine_against_target_app(monkeypatch):
    app = create_app()
    client = app.test_client()

    engine = ReconEngine()

    def mock_get(url, **kwargs):
        parsed_path = url.replace("http://127.0.0.1:5000", "") or "/"
        res = client.get(parsed_path)
        return HTTPResponseTelemetry(
            url=url,
            status_code=res.status_code,
            headers=dict(res.headers),
            body=res.get_data(as_text=True),
            elapsed_ms=5.0,
            cookies={"patchstack_visitor": "guest_session_v1"},
        )

    monkeypatch.setattr(engine.http_client, "get", mock_get)

    recon_res = engine.run("http://127.0.0.1:5000", max_depth=2)

    assert recon_res.total_endpoints >= 5
    assert recon_res.total_forms >= 3
    assert recon_res.fingerprint.framework == "Flask"
