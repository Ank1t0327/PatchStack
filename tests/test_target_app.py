import pytest
from patchstack.target_app.app import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_index_route(client):
    rv = client.get("/")
    assert rv.status_code == 200
    json_data = rv.get_json()
    assert json_data["status"] == "running"
    assert "PatchStack" in json_data["name"]


def test_health_route(client):
    rv = client.get("/health")
    assert rv.status_code == 200
    json_data = rv.get_json()
    assert json_data["status"] == "healthy"


def test_headers_test_route(client):
    rv = client.get("/api/v1/headers-test", headers={"Origin": "http://attacker.com"})
    assert rv.status_code == 200
    assert rv.headers.get("Access-Control-Allow-Origin") == "http://attacker.com"
