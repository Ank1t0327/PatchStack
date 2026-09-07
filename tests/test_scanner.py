import pytest
from patchstack.config import Config
from patchstack.scanner.engine import ScannerEngine
from patchstack.target_app.app import create_app


@pytest.fixture
def test_server():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def test_scanner_headers_detection(monkeypatch):
    # Test scanner engine with mock server response
    app = create_app()
    client = app.test_client()

    config = Config()
    engine = ScannerEngine(config)

    # Mock HTTPClient request to hit test client
    def mock_get(url, **kwargs):
        res = client.get("/")
        from patchstack.scanner.http_client import HTTPResponseTelemetry
        return HTTPResponseTelemetry(
            url=url,
            status_code=res.status_code,
            headers=dict(res.headers),
            body=res.get_data(as_text=True),
            elapsed_ms=12.5,
        )

    monkeypatch.setattr(engine.http_client, "get", mock_get)
    result = engine.run("http://127.0.0.1:5000")

    assert result.total_findings > 0
    missing_ids = [f.id for f in result.findings]
    assert "MISSING_HEADER_CONTENT_SECURITY_POLICY" in missing_ids
