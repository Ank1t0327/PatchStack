import pytest
from patchstack.config import ScannerConfig
from patchstack.scanner.http_client import HTTPClient, HTTPResponseTelemetry
from patchstack.detectors.sqli import SQLInjectionDetector
from patchstack.detectors.xss import XSSDetector
from patchstack.detectors.idor import IDORAccessControlDetector
from patchstack.detectors.auth import AuthSessionDetector
from patchstack.detectors.headers import SecurityHeadersDetector
from patchstack.detectors.cookies import CookieSecurityDetector
from patchstack.target_app.app import create_app


@pytest.fixture
def target_client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def test_false_positives_on_patched_application(target_client):
    """
    Verifies that detectors report 0 findings against secure/patched endpoints (No False Positives).
    """
    class MockHTTPClient:
        def get(self, url, **kwargs):
            parsed_path = url.replace("http://127.0.0.1:5000", "") or "/"
            res = target_client.get(parsed_path, headers=kwargs.get("headers", {}))
            return HTTPResponseTelemetry(
                url=url,
                status_code=res.status_code,
                headers=dict(res.headers),
                body=res.get_data(as_text=True),
                elapsed_ms=4.0,
            )

        def request(self, method, url, **kwargs):
            payload = kwargs.get("json", {})
            parsed_path = url.replace("http://127.0.0.1:5000", "") or "/"
            res = target_client.post(parsed_path, json=payload, headers=kwargs.get("headers", {}))
            return HTTPResponseTelemetry(
                url=url,
                status_code=res.status_code,
                headers=dict(res.headers),
                body=res.get_data(as_text=True),
                elapsed_ms=4.0,
            )

    client = MockHTTPClient()

    # Patched SQLi Endpoint
    sqli_findings = SQLInjectionDetector().scan(client, "http://127.0.0.1:5000/api/v1/sqli/user-secure?id=101")
    assert len(sqli_findings) == 0

    # Patched XSS Endpoint
    xss_findings = XSSDetector().scan(client, "http://127.0.0.1:5000/api/v1/xss/search-secure?q=security")
    assert len(xss_findings) == 0

    # Patched Auth Endpoint
    auth_findings = AuthSessionDetector().scan(client, "http://127.0.0.1:5000/api/v1/auth/login-secure")
    assert len(auth_findings) == 0


def test_invalid_urls_and_unreachable_hosts():
    """
    Tests scanner resilience against unreachable hosts and invalid URLs without crashing.
    """
    config = ScannerConfig(target_url="http://invalid-non-existent-domain-999.local", timeout=1)
    client = HTTPClient(config)

    # Verify graceful unreachable check
    reachable = client.verify_target_reachable("http://invalid-non-existent-domain-999.local")
    assert reachable is False

    # Perform request on unreachable host
    res = client.get("http://invalid-non-existent-domain-999.local")
    assert res is None


def test_timeouts_and_connection_errors():
    """
    Ensures HTTP client handles timeouts gracefully.
    """
    config = ScannerConfig(target_url="http://127.0.0.1:59999", timeout=1)
    client = HTTPClient(config)

    res = client.get("http://127.0.0.1:59999")
    assert res is None


def test_unexpected_http_500_and_binary_responses(target_client):
    """
    Verifies detectors handle HTTP 500 errors and binary responses safely.
    """
    class Mock500HTTPClient:
        def get(self, url, **kwargs):
            return HTTPResponseTelemetry(
                url=url,
                status_code=500,
                headers={"Content-Type": "application/octet-stream"},
                body="\x00\x01\x02\x03\x04\x05",
                elapsed_ms=10.0,
            )

        def request(self, method, url, **kwargs):
            return self.get(url, **kwargs)

    client = Mock500HTTPClient()

    # Detectors should execute without throwing unhandled exceptions
    sqli_res = SQLInjectionDetector().scan(client, "http://127.0.0.1:5000/api/v1/test")
    xss_res = XSSDetector().scan(client, "http://127.0.0.1:5000/api/v1/test")
    headers_res = SecurityHeadersDetector().scan(client, "http://127.0.0.1:5000/api/v1/test")

    assert isinstance(sqli_res, list)
    assert isinstance(xss_res, list)
    assert isinstance(headers_res, list)


def test_authentication_failures_handling(target_client):
    """
    Ensures detectors handle HTTP 401 Unauthorized / 403 Forbidden responses safely.
    """
    class MockAuthFailHTTPClient:
        def get(self, url, **kwargs):
            return HTTPResponseTelemetry(
                url=url,
                status_code=401,
                headers={"Content-Type": "application/json"},
                body='{"error": "Unauthorized access"}',
                elapsed_ms=5.0,
            )

        def request(self, method, url, **kwargs):
            return self.get(url, **kwargs)

    client = MockAuthFailHTTPClient()
    idor_findings = IDORAccessControlDetector().scan(client, "http://127.0.0.1:5000/api/user/102")
    assert isinstance(idor_findings, list)
    assert len(idor_findings) == 0
