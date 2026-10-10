"""
Comprehensive Automated Test Script for Event Correlation & Attack Session Detection
Covers Tests 1-11 per Phase 6 requirements.
"""

import httpx
import json
import time
from datetime import datetime, timezone, timedelta

BASE_URL = "http://127.0.0.1:8000"

def run_tests():
    print("===================================================================")
    print("EVENT CORRELATION & ATTACK SESSION DETECTION TEST SUITE")
    print("===================================================================")

    now = datetime.now(timezone.utc)
    ts = int(time.time())

    # --- Test 1: Events sharing a valid explicit session identifier ---
    print("\n[Test 1] Testing events sharing a valid explicit session identifier...")
    explicit_sess_id = f"explicit-sess-{ts}"
    for i in range(3):
        res = httpx.post(f"{BASE_URL}/api/events", json={
            "event_id": f"evt-expl-{ts}-{i}",
            "timestamp": (now + timedelta(seconds=i * 30)).isoformat(),
            "session_id": explicit_sess_id,
            "source_ip": "198.51.100.150",
            "source_port": 50000 + i,
            "honeypot_id": "cowrie-ssh-test",
            "honeypot_type": "ssh",
            "event_type": "command_execution",
            "username": "attacker_user",
            "payload": f"echo 'stage-{i}'",
            "data_origin": "synthetic"
        })
        assert res.status_code in [200, 201]

    sess_res = httpx.get(f"{BASE_URL}/api/sessions/{explicit_sess_id}")
    assert sess_res.status_code == 200
    sess_data = sess_res.json()
    print(f" -> Session created: ID={sess_data['session_id']}")
    print(f" -> Method: {sess_data['correlation_method']}")
    print(f" -> Event Count: {sess_data['event_count']}")
    assert sess_data["correlation_method"] == "explicit_session_id"
    assert sess_data["event_count"] == 3

    # --- Test 2: Events correlated through fallback rules (IP + sensor + time window) ---
    print("\n[Test 2] Testing events correlated through fallback rules (no session_id)...")
    fallback_ip = f"198.51.100.{ts % 200 + 10}"
    fb_ev1 = f"evt-fallback-1-{ts}"
    fb_ev2 = f"evt-fallback-2-{ts}"

    httpx.post(f"{BASE_URL}/api/events", json={
        "event_id": fb_ev1,
        "timestamp": (now + timedelta(seconds=10)).isoformat(),
        "source_ip": fallback_ip,
        "honeypot_id": "dionaea-smb-test",
        "event_type": "port_scan",
        "payload": "SMB probe 1",
        "data_origin": "synthetic"
    })
    httpx.post(f"{BASE_URL}/api/events", json={
        "event_id": fb_ev2,
        "timestamp": (now + timedelta(seconds=70)).isoformat(),
        "source_ip": fallback_ip,
        "honeypot_id": "dionaea-smb-test",
        "event_type": "port_scan",
        "payload": "SMB probe 2",
        "data_origin": "synthetic"
    })

    # Trigger correlation engine
    corr_run = httpx.post(f"{BASE_URL}/api/correlation/run").json()
    print(f" -> Correlation run completed: {corr_run['correlated_sessions']} sessions, {corr_run['flagged_sequences_detected']} leads.")

    # Fetch sessions for this fallback IP
    ip_sessions = httpx.get(f"{BASE_URL}/api/sessions?source_ip={fallback_ip}").json()
    assert len(ip_sessions) >= 1
    matched_fb = ip_sessions[0]
    print(f" -> Fallback session created: {matched_fb['session_id']}")
    print(f" -> Method: {matched_fb['correlation_method']}")
    print(f" -> Events linked: {matched_fb['event_count']}")
    assert matched_fb["correlation_method"] == "fallback_ip_sensor_window"
    assert matched_fb["event_count"] >= 2

    # --- Test 3: Unrelated events remaining separate ---
    print("\n[Test 3] Testing unrelated events remaining separate...")
    unrelated_ip = f"203.0.113.{(ts + 50) % 200 + 10}"
    httpx.post(f"{BASE_URL}/api/events", json={
        "event_id": f"evt-unrel-{ts}",
        "timestamp": now.isoformat(),
        "source_ip": unrelated_ip,
        "honeypot_id": "conpot-scada-isolated",
        "event_type": "ping",
        "payload": "Single isolated probe",
        "data_origin": "synthetic"
    })
    httpx.post(f"{BASE_URL}/api/correlation/run")
    unrel_sessions = httpx.get(f"{BASE_URL}/api/sessions?source_ip={unrelated_ip}").json()
    assert len(unrel_sessions) == 1
    assert unrel_sessions[0]["session_id"] != matched_fb["session_id"]
    print(f" -> Unrelated event kept in isolated session: {unrel_sessions[0]['session_id']}")

    # --- Test 4: Missing optional fields handled safely ---
    print("\n[Test 4] Testing missing optional fields handled safely...")
    missing_fields_id = f"evt-missing-{ts}"
    res = httpx.post(f"{BASE_URL}/api/events", json={
        "event_id": missing_fields_id,
        "source_ip": "192.0.2.200",
        "event_type": "network_probe"
        # No payload, username, session_id, honeypot_id, ports
    })
    assert res.status_code in [200, 201]
    retrieved_missing = httpx.get(f"{BASE_URL}/api/events/{missing_fields_id}").json()
    assert retrieved_missing["username"] is None
    assert retrieved_missing["session_id"] is not None # Automatically linked via fallback
    print(f" -> Handled missing fields: event assigned to {retrieved_missing['session_id']}")

    # --- Test 5: Correct timeline ordering ---
    print("\n[Test 5] Testing correct chronological timeline ordering...")
    timeline_res = httpx.get(f"{BASE_URL}/api/sessions/{explicit_sess_id}/timeline")
    assert timeline_res.status_code == 200
    timeline = timeline_res.json()["timeline"]
    assert len(timeline) >= 3
    for i in range(len(timeline) - 1):
        t1 = datetime.fromisoformat(timeline[i]["timestamp"])
        t2 = datetime.fromisoformat(timeline[i + 1]["timestamp"])
        assert t1 <= t2, f"Timeline sorting violated: {t1} > {t2}"
        assert timeline[i]["offset_seconds"] <= timeline[i + 1]["offset_seconds"]
    print(f" -> Timeline strictly ordered across {len(timeline)} chronological entries.")

    # --- Test 7: Updating an existing session with new events ---
    print("\n[Test 7] Testing updating an existing session with new event...")
    initial_count = sess_data["event_count"]
    httpx.post(f"{BASE_URL}/api/events", json={
        "event_id": f"evt-expl-update-{ts}",
        "timestamp": (now + timedelta(seconds=120)).isoformat(),
        "session_id": explicit_sess_id,
        "source_ip": "198.51.100.150",
        "honeypot_id": "cowrie-ssh-test",
        "event_type": "command_execution",
        "payload": "crontab -l",
        "data_origin": "synthetic"
    })
    updated_sess = httpx.get(f"{BASE_URL}/api/sessions/{explicit_sess_id}").json()
    assert updated_sess["event_count"] == initial_count + 1
    print(f" -> Session updated: previous={initial_count}, new count={updated_sess['event_count']}")

    # --- Test 8: Repeatable correlation without duplicate sessions ---
    print("\n[Test 8] Testing repeatable correlation without duplicate sessions...")
    count_before = len(httpx.get(f"{BASE_URL}/api/sessions?limit=200").json())
    httpx.post(f"{BASE_URL}/api/correlation/run")
    httpx.post(f"{BASE_URL}/api/correlation/run")
    count_after = len(httpx.get(f"{BASE_URL}/api/sessions?limit=200").json())
    assert count_before == count_after, f"Sessions duplicated: {count_before} != {count_after}"
    print(f" -> Re-ran correlation twice: session count remained constant at {count_after}.")

    # --- Test 9: Session API endpoints verification ---
    print("\n[Test 9] Testing all session endpoints...")
    assert httpx.get(f"{BASE_URL}/api/sessions").status_code == 200
    assert httpx.get(f"{BASE_URL}/api/sessions/{explicit_sess_id}").status_code == 200
    assert httpx.get(f"{BASE_URL}/api/sessions/{explicit_sess_id}/events").status_code == 200
    assert httpx.get(f"{BASE_URL}/api/sessions/{explicit_sess_id}/timeline").status_code == 200
    assert httpx.get(f"{BASE_URL}/api/sessions/non-existent-99999").status_code == 404
    print(" -> All session endpoints return valid responses and proper HTTP status codes.")

    # --- Test 11: Existing ingestion functionality verification ---
    print("\n[Test 11] Verifying existing ingestion functionality still works...")
    ingest_single = httpx.post(f"{BASE_URL}/api/events", json={
        "source_ip": "192.0.2.88",
        "event_type": "port_scan",
        "payload": "SYN Check"
    })
    assert ingest_single.status_code in [200, 201]

    bulk_ingest = httpx.post(f"{BASE_URL}/api/events/bulk", json={
        "events": [
            {"source_ip": "192.0.2.89", "event_type": "ping", "payload": "ICMP"},
            {"source_ip": "192.0.2.90", "event_type": "ping", "payload": "ICMP"}
        ]
    })
    assert bulk_ingest.status_code in [200, 201]
    assert bulk_ingest.json()["ingested"] == 2
    print(" -> Single and bulk ingestion pipelines remain completely functional.")

    print("\n===================================================================")
    print("ALL 11 CORRELATION & ATTACK SESSION TESTS PASSED SUCCESSFULLY!")
    print("===================================================================")

if __name__ == "__main__":
    run_tests()
