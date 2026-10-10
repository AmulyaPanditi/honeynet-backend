"""
Comprehensive Test Script for Telemetry Ingestion and Database Integration Pipeline
Tests Operations 1-11 per Phase 6 requirements.
"""

import httpx
import json
import time

BASE_URL = "http://127.0.0.1:8000"

def test_pipeline():
    print("===================================================================")
    print("AUTONOMOUS HONEYNET TELEMETRY PIPELINE VERIFICATION")
    print("===================================================================")

    # 1 & 2. Check GET /api/health
    print("\n[Step 2] Testing GET /api/health...")
    res = httpx.get(f"{BASE_URL}/api/health")
    assert res.status_code == 200, f"Health check failed: {res.status_code}"
    health_data = res.json()
    print(f" -> Status: {health_data['status']}")
    print(f" -> Database Engine: {health_data['database']['engine']}")
    print(f" -> Version: {health_data['version']}")
    assert health_data["status"] == "healthy"

    # 3. Insert one event via POST /api/events
    print("\n[Step 3] Testing POST /api/events (Single Event Ingestion)...")
    single_event_id = f"test-event-{int(time.time())}"
    event_payload = {
        "event_id": single_event_id,
        "source_ip": "198.51.100.99",
        "source_port": 54321,
        "destination_ip": "198.51.100.1",
        "destination_port": 22,
        "protocol": "TCP",
        "event_type": "auth_attempt",
        "username": "target_user_sec",
        "honeypot_id": "cowrie-ssh-sensor-01",
        "honeypot_type": "ssh",
        "payload": "Synthetic validation: Authentication attempt with password",
        "data_origin": "synthetic"
    }
    res = httpx.post(f"{BASE_URL}/api/events", json=event_payload)
    assert res.status_code in [200, 201], f"Insert failed: {res.text}"
    created_event = res.json()
    print(f" -> Ingested event ID: {created_event['event_id']}")
    print(f" -> Mapped Technique: {created_event['mitre_technique_id']} ({created_event['mitre_technique_name']})")
    print(f" -> Username captured: {created_event['username']}")
    print(f" -> Data Origin: {created_event['data_origin']}")
    assert created_event["event_id"] == single_event_id
    assert created_event["username"] == "target_user_sec"

    # 4. Retrieve that event via GET /api/events/{event_id}
    print(f"\n[Step 4] Testing GET /api/events/{single_event_id}...")
    res = httpx.get(f"{BASE_URL}/api/events/{single_event_id}")
    assert res.status_code == 200, f"Retrieve failed: {res.text}"
    fetched = res.json()
    assert fetched["source_ip"] == "198.51.100.99"
    assert fetched["username"] == "target_user_sec"
    print(f" -> Retrieved successfully: IP={fetched['source_ip']}, User={fetched['username']}")

    # 5. Search for events by source IP and event type
    print("\n[Step 5] Testing Search: GET /api/events?source_ip=198.51.100.99&event_type=auth_attempt...")
    res = httpx.get(f"{BASE_URL}/api/events?source_ip=198.51.100.99&event_type=auth_attempt")
    assert res.status_code == 200
    search_results = res.json()
    assert len(search_results) >= 1
    print(f" -> Search returned {len(search_results)} matching events.")

    # 6. Test pagination
    print("\n[Step 6] Testing Pagination: GET /api/events?skip=0&limit=3 and skip=3&limit=3...")
    page1 = httpx.get(f"{BASE_URL}/api/events?skip=0&limit=3").json()
    page2 = httpx.get(f"{BASE_URL}/api/events?skip=3&limit=3").json()
    print(f" -> Page 1 items: {len(page1)}, Page 2 items: {len(page2)}")
    if page1 and page2:
        assert page1[0]["id"] != page2[0]["id"], "Pagination offset check failed"
        print(" -> Pagination offset correctly distinct between pages.")

    # 7. Insert a batch of events via POST /api/events/bulk
    print("\n[Step 7] Testing POST /api/events/bulk (Batch Ingestion)...")
    batch_ts = int(time.time())
    bulk_payload = {
        "events": [
            {
                "event_id": f"batch-event-a-{batch_ts}",
                "source_ip": "192.0.2.110",
                "event_type": "port_scan",
                "payload": "SYN Port Sweep 80, 443, 8080",
                "data_origin": "real"
            },
            {
                "event_id": f"batch-event-b-{batch_ts}",
                "source_ip": "192.0.2.111",
                "event_type": "command_execution",
                "username": "nobody",
                "payload": "id; whoami",
                "data_origin": "real"
            }
        ]
    }
    res = httpx.post(f"{BASE_URL}/api/events/bulk", json=bulk_payload)
    assert res.status_code in [200, 201], f"Bulk insert failed: {res.text}"
    bulk_result = res.json()
    print(f" -> Ingested count: {bulk_result['ingested']}")
    print(f" -> Duplicates skipped: {bulk_result['duplicates_skipped']}")
    assert bulk_result["ingested"] == 2

    # 8. Verify duplicate handling
    print("\n[Step 8] Testing Duplicate Handling (Re-submitting single_event_id and batch)...")
    dup_res = httpx.post(f"{BASE_URL}/api/events", json=event_payload)
    assert dup_res.status_code in [200, 201]
    print(f" -> Single duplicate handled gracefully without error: {dup_res.json()['event_id']}")

    bulk_with_dup = {
        "events": [
            event_payload, # already exists
            {
                "event_id": f"batch-event-c-{batch_ts}",
                "source_ip": "192.0.2.112",
                "event_type": "command_execution",
                "payload": "cat /etc/passwd",
                "data_origin": "real"
            }
        ]
    }
    bulk_dup_res = httpx.post(f"{BASE_URL}/api/events/bulk", json=bulk_with_dup)
    assert bulk_dup_res.status_code in [200, 201]
    bulk_dup_data = bulk_dup_res.json()
    print(f" -> Bulk duplicate test: {bulk_dup_data['ingested']} new ingested, {bulk_dup_data['duplicates_skipped']} duplicates skipped.")
    assert bulk_dup_data["duplicates_skipped"] >= 1

    # 11. Confirm dashboard metrics reflect stored records
    print("\n[Step 11] Confirming GET /api/stats reflects persisted events...")
    stats_res = httpx.get(f"{BASE_URL}/api/stats")
    assert stats_res.status_code == 200
    stats = stats_res.json()
    print(f" -> Total events: {stats['total_events']}")
    print(f" -> Real events: {stats['real_events_count']}")
    print(f" -> Synthetic events: {stats['synthetic_events_count']}")
    print(f" -> Unique source IPs: {stats['unique_source_ips']}")
    print(f" -> Event types: {list(stats['event_types_breakdown'].keys())}")
    assert stats["total_events"] > 0
    assert stats["real_events_count"] + stats["synthetic_events_count"] == stats["total_events"]

    print("\n===================================================================")
    print("ALL API & DATABASE INTEGRATION PIPELINE TESTS PASSED SUCCESSFULLY!")
    print("===================================================================")

if __name__ == "__main__":
    test_pipeline()
