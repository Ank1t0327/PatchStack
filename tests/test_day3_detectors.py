import pytest
from patchstack.detectors.headers import SecurityHeadersDetector
from patchstack.detectors.cookies import CookieSecurityDetector
from patchstack.detectors.info_disclosure import ServerInfoDisclosureDetector
from patchstack.detectors.methods import DangerousMethodsDetector
from patchstack.detectors.cors import CORSConfigDetector
from patchstack.scanner.http_client import HTTPResponseTelemetry
from patchstack.target_app.app import create_app


@pytest.fixture
def target_client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def test_security_headers_detector(monkeypatch, target_client):
    detector = SecurityHeadersDetector()

    def mock_get(url, **kwargs):
        res = target_client.get("/")
        return HTTPResponseTelemetry(
            url=url,
            status_code=res.status_code,
            headers=dict(res.headers),
            body=res.get_data(as_text=True),
            elapsed_ms=5.0,
        )

    class MockHTTPClient:
        def get(self, url, **kwargs):
            return mock_get(url, **kwargs)

    findings = detector.scan(MockHTTPClient(), "http://127.0.0.1:5000")
    finding_ids = [f.id for f in findings]

    assert "MISSING_CONTENT_SECURITY_POLICY" in finding_ids
    assert "MISSING_X_FRAME_OPTIONS" in finding_ids
    assert "MISSING_STRICT_TRANSPORT_SECURITY" in finding_ids


def test_cookie_security_detector(target_client):
    detector = CookieSecurityDetector()

    class MockHTTPClient:
        def get(self, url, **kwargs):
            res = target_client.get("/api/v1/insecure-cookie")
            # Convert multidict headers to list of tuples or raw dictionary
            headers = [("Set-Cookie", "auth_token=secret12345; Path=/")]
            return HTTPResponseTelemetry(
                url=url,
                status_code=res.status_code,
                headers=dict(headers),
                body=res.get_data(as_text=True),
                elapsed_ms=5.0,
            )

    findings = detector.scan(MockHTTPClient(), "http://127.0.0.1:5000")
    finding_ids = [f.id for f in findings]

    assert "COOKIE_MISSING_HTTPONLY" in finding_ids
    assert "COOKIE_MISSING_SECURE" in finding_ids
    assert "COOKIE_WEAK_SAMESITE" in finding_ids


def test_info_disclosure_detector(target_client):
    detector = ServerInfoDisclosureDetector()

    class MockHTTPClient:
        def get(self, url, **kwargs):
            res = target_client.get("/api/v1/info-leak")
            return HTTPResponseTelemetry(
                url=url,
                status_code=res.status_code,
                headers=dict(res.headers),
                body=res.get_data(as_text=True),
                elapsed_ms=5.0,
            )

    findings = detector.scan(MockHTTPClient(), "http://127.0.0.1:5000")
    finding_ids = [f.id for f in findings]

    assert "SERVER_INFO_DISCLOSURE_SERVER_HEADER" in finding_ids
    assert "SERVER_INFO_DISCLOSURE_X_POWERED_BY" in finding_ids


def test_dangerous_methods_detector(target_client):
    detector = DangerousMethodsDetector()

    class MockHTTPClient:
        def request(self, method, url, **kwargs):
            if method == "OPTIONS":
                res = target_client.options("/api/v1/debug-methods")
            elif method == "TRACE":
                res = target_client.trace("/api/v1/debug-methods")
            else:
                res = target_client.get("/api/v1/debug-methods")
            return HTTPResponseTelemetry(
                url=url,
                status_code=res.status_code,
                headers=dict(res.headers),
                body=res.get_data(as_text=True),
                elapsed_ms=5.0,
            )

    findings = detector.scan(MockHTTPClient(), "http://127.0.0.1:5000")
    finding_ids = [f.id for f in findings]

    assert "DANGEROUS_METHOD_TRACE_ENABLED" in finding_ids


def test_cors_config_detector(target_client):
    detector = CORSConfigDetector()

    class MockHTTPClient:
        def get(self, url, **kwargs):
            origin = kwargs.get("headers", {}).get("Origin", "")
            res = target_client.get("/api/v1/cors-vulnerable", headers={"Origin": origin})
            return HTTPResponseTelemetry(
                url=url,
                status_code=res.status_code,
                headers=dict(res.headers),
                body=res.get_data(as_text=True),
                elapsed_ms=5.0,
            )

    findings = detector.scan(MockHTTPClient(), "http://127.0.0.1:5000")
    finding_ids = [f.id for f in findings]

    assert "CORS_ARBITRARY_ORIGIN_REFLECTED_WITH_CREDENTIALS" in finding_ids
