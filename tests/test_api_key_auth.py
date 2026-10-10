import pytest
from backend.app.config import settings

def test_ingestion_unauthenticated_when_api_key_unset(client, monkeypatch):
    """When API_KEY is unset, sensor ingestion allows open local development."""
    monkeypatch.setattr(settings, "API_KEY", None)

    event_payload = {
        "event_id": "test-open-dev-01",
        "source_ip": "198.51.100.10",
        "event_type": "auth_attempt",
        "payload": "dev open test"
    }

    # /api/events succeeds without X-API-Key
    res = client.post("/api/events", json=event_payload)
    assert res.status_code == 201
    assert res.json()["event_id"] == "test-open-dev-01"

    # /api/v1/events succeeds without X-API-Key
    res_v1 = client.post("/api/v1/events", json={**event_payload, "event_id": "test-open-dev-02"})
    assert res_v1.status_code == 201

def test_ingestion_requires_key_when_configured(client, monkeypatch):
    """When API_KEY is set, missing header returns 401, wrong key returns 403, valid key returns 201."""
    test_secret = "sensor-production-secret-987"
    monkeypatch.setattr(settings, "API_KEY", test_secret)

    payload = {
        "event_id": "test-auth-event-01",
        "source_ip": "198.51.100.15",
        "event_type": "command_execution",
        "payload": "whoami"
    }

    # 1. Missing header -> HTTP 401 Unauthorized
    res_missing = client.post("/api/events", json=payload)
    assert res_missing.status_code == 401
    assert "missing X-API-Key" in res_missing.json()["detail"]
    assert test_secret not in str(res_missing.json())

    # 2. Invalid header -> HTTP 403 Forbidden
    res_invalid = client.post("/api/events", json=payload, headers={"X-API-Key": "wrong-secret"})
    assert res_invalid.status_code == 403
    assert "invalid API key" in res_invalid.json()["detail"]
    assert test_secret not in str(res_invalid.json())

    # 3. Valid header -> HTTP 201 Created
    res_valid = client.post("/api/events", json=payload, headers={"X-API-Key": test_secret})
    assert res_valid.status_code == 201
    assert res_valid.json()["event_id"] == "test-auth-event-01"

def test_api_key_protection_cannot_be_bypassed_via_route_aliases(client, monkeypatch):
    """Verify that neither /api/v1/events nor bulk ingestion can bypass X-API-Key verification."""
    test_secret = "sensor-production-secret-987"
    monkeypatch.setattr(settings, "API_KEY", test_secret)

    single_payload = {
        "event_id": "test-bypass-01",
        "source_ip": "198.51.100.20",
        "event_type": "auth_attempt"
    }
    bulk_payload = {
        "events": [
            {
                "event_id": "test-bypass-bulk-01",
                "source_ip": "198.51.100.21",
                "event_type": "port_scan"
            }
        ]
    }

    # /api/v1/events alias missing key
    assert client.post("/api/v1/events", json=single_payload).status_code == 401
    assert client.post("/api/v1/events", json=single_payload, headers={"X-API-Key": "bad"}).status_code == 403
    assert client.post("/api/v1/events", json=single_payload, headers={"X-API-Key": test_secret}).status_code == 201

    # /api/events/bulk missing key
    assert client.post("/api/events/bulk", json=bulk_payload).status_code == 401
    assert client.post("/api/events/bulk", json=bulk_payload, headers={"X-API-Key": "bad"}).status_code == 403
    assert client.post("/api/events/bulk", json=bulk_payload, headers={"X-API-Key": test_secret}).status_code == 201

    # /api/v1/events/bulk alias missing key
    bulk_payload_2 = {"events": [{**single_payload, "event_id": "test-bypass-bulk-02"}]}
    assert client.post("/api/v1/events/bulk", json=bulk_payload_2).status_code == 401
    assert client.post("/api/v1/events/bulk", json=bulk_payload_2, headers={"X-API-Key": "bad"}).status_code == 403
    assert client.post("/api/v1/events/bulk", json=bulk_payload_2, headers={"X-API-Key": test_secret}).status_code == 201
