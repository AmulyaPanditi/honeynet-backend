from datetime import datetime, timezone, timedelta

def test_explicit_session_correlation_and_timeline(client):
    """Verify session creation from explicit session IDs and chronological timeline ordering."""
    sess_id = "test-sess-iso-01"
    base_time = datetime.now(timezone.utc)

    # Ingest 3 events chronologically
    for i in range(3):
        t = (base_time + timedelta(seconds=i * 20)).isoformat()
        res = client.post("/api/events", json={
            "event_id": f"evt-sess-iso-{i}",
            "session_id": sess_id,
            "timestamp": t,
            "source_ip": "198.51.100.33",
            "event_type": "command_execution",
            "payload": f"step-{i}"
        })
        assert res.status_code == 201

    # Fetch session
    res_sess = client.get(f"/api/sessions/{sess_id}")
    assert res_sess.status_code == 200
    s_data = res_sess.json()
    assert s_data["session_id"] == sess_id
    assert s_data["event_count"] == 3

    # Fetch timeline
    res_tl = client.get(f"/api/sessions/{sess_id}/timeline")
    assert res_tl.status_code == 200
    tl_data = res_tl.json()
    assert len(tl_data["timeline"]) == 3
    # Check strictly non-decreasing offset_seconds
    offsets = [item["offset_seconds"] for item in tl_data["timeline"]]
    assert offsets == sorted(offsets)

def test_correlation_engine_run(client):
    """Verify manual execution of correlation engine."""
    res = client.post("/api/correlation/run?window_minutes=30")
    assert res.status_code == 200
    assert "events_processed" in res.json()
    assert "correlated_sessions" in res.json()
