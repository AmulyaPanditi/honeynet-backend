def test_explainable_alert_detection_and_lifecycle(client):
    """Verify alert generation, explainability details, deduplication, and status update."""
    ip_target = "198.51.100.99"

    # Ingest 3 consecutive auth failures
    for i in range(3):
        res = client.post("/api/events", json={
            "event_id": f"evt-fail-iso-{i}",
            "source_ip": ip_target,
            "event_type": "auth_failure",
            "username": "root",
            "payload": f"Failed password attempt {i}"
        })
        assert res.status_code == 201

    # Trigger detection
    res_detect = client.post("/api/alerts/detect")
    assert res_detect.status_code == 200
    d_data = res_detect.json()
    assert d_data["new_alerts_created"] >= 1

    # Fetch alerts for target IP
    res_alerts = client.get(f"/api/alerts?source_ip={ip_target}")
    assert res_alerts.status_code == 200
    alerts = res_alerts.json()
    assert len(alerts) >= 1
    target_alert = alerts[0]

    assert target_alert["detection_rule_id"] == "ALERT_RULE_AUTH_BRUTE_FORCE"
    assert "Observed Evidence" in target_alert["explanation"]
    assert target_alert["severity_rationale"] is not None

    alert_id = target_alert["alert_id"]

    # Deduplication test: running detect again should produce 0 new alerts
    res_detect2 = client.post("/api/alerts/detect")
    assert res_detect2.status_code == 200
    assert res_detect2.json()["new_alerts_created"] == 0

    # Status update: update to INVESTIGATING
    res_patch = client.patch(f"/api/alerts/{alert_id}", json={"status": "INVESTIGATING"})
    assert res_patch.status_code == 200
    assert res_patch.json()["status"] == "INVESTIGATING"
    assert res_patch.json()["is_resolved"] is False

    # Status update: update to RESOLVED
    res_patch2 = client.patch(f"/api/alerts/{alert_id}", json={"status": "RESOLVED"})
    assert res_patch2.status_code == 200
    assert res_patch2.json()["status"] == "RESOLVED"
    assert res_patch2.json()["is_resolved"] is True

    # Error handling
    assert client.get("/api/alerts/non-existent-alt-999").status_code == 404
    assert client.patch(f"/api/alerts/{alert_id}", json={"status": "INVALID_STATUS"}).status_code == 400
