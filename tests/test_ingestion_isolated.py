import os
from pathlib import Path
from app.config import DEFAULT_SQLITE_PATH

def test_ingestion_and_duplicate_suppression(client):
    """Verify single and bulk event ingestion with safe duplicate suppression."""
    # Capture disk honeynet.db size before test
    disk_db_exists = DEFAULT_SQLITE_PATH.exists()
    disk_db_mtime = DEFAULT_SQLITE_PATH.stat().st_mtime if disk_db_exists else 0

    event_data = {
        "event_id": "isolated-test-evt-01",
        "source_ip": "198.51.100.77",
        "event_type": "command_execution",
        "username": "root",
        "payload": "cat /etc/passwd",
        "honeypot_type": "ssh",
        "data_origin": "synthetic"
    }

    # 1. Single ingestion
    res = client.post("/api/events", json=event_data)
    assert res.status_code == 201
    assert res.json()["event_id"] == "isolated-test-evt-01"

    # 2. Duplicate ingestion does not throw database error
    res_dup = client.post("/api/events", json=event_data)
    assert res_dup.status_code == 201
    assert res_dup.json()["event_id"] == "isolated-test-evt-01"

    # 3. Bulk ingestion
    bulk_data = {
        "events": [
            event_data,  # duplicate
            {
                "event_id": "isolated-test-evt-02",
                "source_ip": "198.51.100.78",
                "event_type": "auth_failure",
                "username": "admin",
                "payload": "failed pass"
            }
        ]
    }
    res_bulk = client.post("/api/events/bulk", json=bulk_data)
    assert res_bulk.status_code == 201
    b_json = res_bulk.json()
    assert b_json["duplicates_skipped"] == 1
    assert b_json["ingested"] == 1

    # 4. Search and pagination
    res_search = client.get("/api/events?search=passwd")
    assert res_search.status_code == 200
    assert len(res_search.json()) >= 1

    res_page = client.get("/api/events?skip=0&limit=1")
    assert res_page.status_code == 200
    assert len(res_page.json()) == 1

    # 5. Verify the active development disk honeynet.db was NOT modified
    if disk_db_exists:
        assert DEFAULT_SQLITE_PATH.stat().st_mtime == disk_db_mtime, \
            "Isolated test must NOT write or modify the development database on disk!"
