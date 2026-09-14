import pytest
from patchstack.detectors.sqli import SQLInjectionDetector
from patchstack.detectors.xss import XSSDetector
from patchstack.detectors.idor import IDORAccessControlDetector
from patchstack.scanner.http_client import HTTPResponseTelemetry
from patchstack.target_app.app import create_app


@pytest.fixture
def target_client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def test_sqli_detector_vulnerable_endpoint(target_client):
    detector = SQLInjectionDetector()

    class MockHTTPClient:
        def get(self, url, **kwargs):
            parsed_path = url.replace("http://127.0.0.1:5000", "")
            res = target_client.get(parsed_path)
            return HTTPResponseTelemetry(
                url=url,
                status_code=res.status_code,
                headers=dict(res.headers),
                body=res.get_data(as_text=True),
                elapsed_ms=5.0,
            )

    findings = detector.scan(MockHTTPClient(), "http://127.0.0.1:5000/api/v1/sqli/user-vulnerable?id=101")
    assert len(findings) > 0
    assert "SQLI_ERROR_BASED" in [f.id for f in findings]


def test_sqli_detector_secure_endpoint(target_client):
    detector = SQLInjectionDetector()

    class MockHTTPClient:
        def get(self, url, **kwargs):
            parsed_path = url.replace("http://127.0.0.1:5000", "")
            res = target_client.get(parsed_path)
            return HTTPResponseTelemetry(
                url=url,
                status_code=res.status_code,
                headers=dict(res.headers),
                body=res.get_data(as_text=True),
                elapsed_ms=5.0,
            )

    findings = detector.scan(MockHTTPClient(), "http://127.0.0.1:5000/api/v1/sqli/user-secure?id=101")
    assert len(findings) == 0


def test_xss_detector_vulnerable_endpoint(target_client):
    detector = XSSDetector()

    class MockHTTPClient:
        def get(self, url, **kwargs):
            parsed_path = url.replace("http://127.0.0.1:5000", "")
            res = target_client.get(parsed_path)
            return HTTPResponseTelemetry(
                url=url,
                status_code=res.status_code,
                headers=dict(res.headers),
                body=res.get_data(as_text=True),
                elapsed_ms=5.0,
            )

    findings = detector.scan(MockHTTPClient(), "http://127.0.0.1:5000/api/v1/xss/search-vulnerable?q=test")
    assert len(findings) > 0
    assert "XSS_REFLECTED" in [f.id for f in findings]


def test_xss_detector_secure_endpoint(target_client):
    detector = XSSDetector()

    class MockHTTPClient:
        def get(self, url, **kwargs):
            parsed_path = url.replace("http://127.0.0.1:5000", "")
            res = target_client.get(parsed_path)
            return HTTPResponseTelemetry(
                url=url,
                status_code=res.status_code,
                headers=dict(res.headers),
                body=res.get_data(as_text=True),
                elapsed_ms=5.0,
            )

    findings = detector.scan(MockHTTPClient(), "http://127.0.0.1:5000/api/v1/xss/search-secure?q=test")
    assert len(findings) == 0


def test_idor_detector_vulnerable_endpoint(target_client):
    detector = IDORAccessControlDetector()

    class MockHTTPClient:
        def request(self, method, url, **kwargs):
            if "login-vulnerable" in url:
                res = target_client.post("/api/v1/auth/login-vulnerable", json={"username": "user101", "password": "Password101!"})
            else:
                parsed_path = url.replace("http://127.0.0.1:5000", "")
                res = target_client.get(parsed_path, headers=kwargs.get("headers", {}))
            return HTTPResponseTelemetry(
                url=url,
                status_code=res.status_code,
                headers=dict(res.headers),
                body=res.get_data(as_text=True),
                elapsed_ms=5.0,
            )

        def get(self, url, **kwargs):
            return self.request("GET", url, **kwargs)

    findings = detector.scan(MockHTTPClient(), "http://127.0.0.1:5000/api/v1/idor/user-vulnerable")
    assert len(findings) > 0
    assert "IDOR_HORIZONTAL_PRIVILEGE_ESCALATION" in [f.id for f in findings]
