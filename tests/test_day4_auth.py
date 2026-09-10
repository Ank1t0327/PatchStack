import pytest
from patchstack.target_app.auth import VulnerableAuthManager, SecureAuthManager
from patchstack.detectors.auth import AuthSessionDetector
from patchstack.scanner.http_client import HTTPResponseTelemetry
from patchstack.target_app.app import create_app


@pytest.fixture
def target_client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def test_vulnerable_auth_manager():
    auth = VulnerableAuthManager()
    ok_inv, msg_inv, _, _ = auth.login("nonexistent", "pass")
    assert not ok_inv
    assert msg_inv == "User not found"

    ok_wrong, msg_wrong, _, _ = auth.login("admin", "wrongpass")
    assert not ok_wrong
    assert msg_wrong == "Incorrect password"

    ok_succ, msg_succ, data1, cookie1 = auth.login("admin", "AdminPassword123!")
    assert ok_succ
    assert "SESSION-1001" in data1["session_id"]

    _, _, data2, _ = auth.login("admin", "AdminPassword123!")
    assert "SESSION-1002" in data2["session_id"]


def test_secure_auth_manager():
    auth = SecureAuthManager()
    ok_inv, msg_inv, _, _ = auth.login("nonexistent", "pass")
    ok_wrong, msg_wrong, _, _ = auth.login("admin", "wrongpass")

    # Both return generic error message
    assert msg_inv == "Invalid username or password"
    assert msg_wrong == "Invalid username or password"

    # Lockout test after 5 failed attempts
    for _ in range(3):
        auth.login("admin", "wrongpass")

    ok_locked, msg_locked, _, _ = auth.login("admin", "wrongpass")
    assert not ok_locked
    assert "locked" in msg_locked.lower()


def test_auth_session_detector_vulnerable_endpoint(target_client):
    detector = AuthSessionDetector()

    class MockHTTPClient:
        def request(self, method, url, **kwargs):
            payload = kwargs.get("json", {})
            res = target_client.post("/api/v1/auth/login-vulnerable", json=payload)
            headers = dict(res.headers)
            if "Set-Cookie" in res.headers:
                headers["Set-Cookie"] = res.headers["Set-Cookie"]
            return HTTPResponseTelemetry(
                url=url,
                status_code=res.status_code,
                headers=headers,
                body=res.get_data(as_text=True),
                elapsed_ms=5.0,
            )

    findings = detector.scan(MockHTTPClient(), "http://127.0.0.1:5000/api/v1/auth/login-vulnerable")
    finding_ids = [f.id for f in findings]

    assert "AUTH_USERNAME_ENUMERATION" in finding_ids
    assert "AUTH_PREDICTABLE_SESSION_ID" in finding_ids
    assert "AUTH_MISSING_RATE_LIMITING" in finding_ids
    assert "AUTH_INSECURE_SESSION_COOKIE" in finding_ids


def test_auth_session_detector_secure_endpoint(target_client):
    detector = AuthSessionDetector()

    class MockHTTPClient:
        def request(self, method, url, **kwargs):
            payload = kwargs.get("json", {})
            res = target_client.post("/api/v1/auth/login-secure", json=payload)
            headers = dict(res.headers)
            if "Set-Cookie" in res.headers:
                headers["Set-Cookie"] = res.headers["Set-Cookie"]
            return HTTPResponseTelemetry(
                url=url,
                status_code=res.status_code,
                headers=headers,
                body=res.get_data(as_text=True),
                elapsed_ms=5.0,
            )

    findings = detector.scan(MockHTTPClient(), "http://127.0.0.1:5000/api/v1/auth/login-secure")
    assert len(findings) == 0
