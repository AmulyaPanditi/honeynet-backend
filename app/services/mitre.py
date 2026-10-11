import re
from typing import Dict, Any, Optional, List, Tuple
from sqlalchemy.orm import Session
from datetime import datetime, timezone
import uuid

from app.services.mitre_catalog import (
    load_mitre_catalog,
    get_technique_from_catalog,
    TechniqueCatalogItem
)
from app.models.mitre import TechniqueMappingDB
from app.models.telemetry import TelemetryEventDB
from app.models.session import InvestigationSessionDB

# Populate MITRE_TECHNIQUES dict dynamically from catalog for full backward compatibility
def get_mitre_techniques_dict() -> Dict[str, Dict[str, Any]]:
    catalog = load_mitre_catalog()
    result = {}
    for tid, item in catalog.items():
        result[tid] = {
            "id": item.technique_id,
            "name": item.name,
            "tactic": item.tactics[0] if item.tactics else "General",
            "tactics": item.tactics,
            "description": item.description,
            "applicable_event_evidence": item.applicable_event_evidence,
            "data_source_requirements": item.data_source_requirements,
            "mapping_rule_id": item.mapping_rule_id
        }
    return result

MITRE_TECHNIQUES = get_mitre_techniques_dict()

# Transparent Rule Identifiers
RULE_USER_DISCOVERY = "RULE_USER_DISCOVERY"
RULE_SYSINFO_DISCOVERY = "RULE_SYSINFO_DISCOVERY"
RULE_UNIX_SHELL = "RULE_UNIX_SHELL"
RULE_POWERSHELL = "RULE_POWERSHELL"
RULE_INGRESS_TRANSFER = "RULE_INGRESS_TRANSFER"
RULE_CRON_PERSISTENCE = "RULE_CRON_PERSISTENCE"
RULE_INDICATOR_REMOVAL = "RULE_INDICATOR_REMOVAL"
RULE_FILE_DIR_DISCOVERY = "RULE_FILE_DIR_DISCOVERY"
RULE_REMOTE_SYSTEM_DISCOVERY = "RULE_REMOTE_SYSTEM_DISCOVERY"
RULE_NETWORK_SCAN = "RULE_NETWORK_SCAN"
RULE_VALID_ACCOUNTS = "RULE_VALID_ACCOUNTS"
RULE_EXPLOIT_PAYLOAD = "RULE_EXPLOIT_PAYLOAD"
RULE_AUTH_BRUTE_FORCE = "RULE_AUTH_BRUTE_FORCE"
RULE_PASSWORD_GUESSING = "RULE_PASSWORD_GUESSING"
RULE_UNMAPPED = "RULE_UNMAPPED"

def evaluate_event_evidence(
    event_type: str,
    payload: Optional[str] = None,
    username: Optional[str] = None,
    destination_port: Optional[int] = None,
    honeypot_type: Optional[str] = None
) -> Dict[str, Any]:
    """
    Evaluates raw telemetry evidence against authoritative MITRE ATT&CK mapping rules.
    Strictly adheres to evidence-based requirements:
    - Never defaults to an exploit technique if no evidence exists.
    - Never infers a technique solely from an IP address or generic label.
    - An isolated authentication failure returns 'insufficient_evidence' (cannot confirm brute force without sequence).
    - Distinguishes observed behavior, rule-supported technique mapping, and unmapped/insufficient evidence.
    """
    payload_str = (payload or "").strip()
    payload_lower = payload_str.lower()
    event_type_lower = (event_type or "").lower().strip()
    catalog = load_mitre_catalog()

    # 1. Ingress Tool Transfer (T1105) - Command & Control
    # Evidence: External download utilities with target URLs or IPs
    if any(k in payload_lower for k in ["curl ", "wget ", "ftp ", "tftp ", "certutil -urlcache", "bitsadmin "]):
        t = catalog.get("T1105")
        matched = next(k.strip() for k in ["curl", "wget", "ftp", "tftp", "certutil", "bitsadmin"] if k in payload_lower)
        return {
            "technique_id": "T1105",
            "name": t.name if t else "Ingress Tool Transfer",
            "tactic": "Command and Control",
            "mapping_rule": RULE_INGRESS_TRANSFER,
            "explanation": f"Payload contained external retrieval utility '{matched}' downloading artifacts into the decoy.",
            "mapping_status": "supported",
            "evidence_strength": "high",
            "confidence": 0.95,
            "severity": "high",
            "supporting_event_fields": {"payload": payload_str, "matched_utility": matched}
        }

    # 2. Persistence via Cron (T1053.003) - Persistence
    # Evidence: Direct manipulation of cron tables or recurring job configs
    if any(k in payload_lower for k in ["crontab", "/etc/cron", "systemctl enable"]):
        t = catalog.get("T1053.003")
        return {
            "technique_id": "T1053.003",
            "name": t.name if t else "Scheduled Task/Job: Cron",
            "tactic": "Persistence",
            "mapping_rule": RULE_CRON_PERSISTENCE,
            "explanation": "Payload inspected or modified cron job schedules for recurring persistence.",
            "mapping_status": "supported",
            "evidence_strength": "high",
            "confidence": 0.92,
            "severity": "critical",
            "supporting_event_fields": {"payload": payload_str}
        }

    # 3. Indicator Removal / File Deletion (T1070.004) - Defense Evasion
    # Evidence: Artifact scrubbing or shell history purging commands
    if any(k in payload_lower for k in ["rm -rf", "history -c", "truncate -s 0", "unset histfile", "shred "]):
        t = catalog.get("T1070.004")
        return {
            "technique_id": "T1070.004",
            "name": t.name if t else "Indicator Removal: File Deletion",
            "tactic": "Defense Evasion",
            "mapping_rule": RULE_INDICATOR_REMOVAL,
            "explanation": "Payload executed trace removal commands targeting filesystem artifacts or shell history.",
            "mapping_status": "supported",
            "evidence_strength": "high",
            "confidence": 0.90,
            "severity": "high",
            "supporting_event_fields": {"payload": payload_str}
        }

    # 4. System Owner / User Discovery (T1033) - Discovery
    # Evidence: User discovery commands enumerating active accounts, sessions, or IDs
    user_cmds = ["whoami", "id", "cat /etc/passwd", "last", "logname", "users"]
    # Check for whole-word or delimited presence
    if any(re.search(rf"\b{re.escape(cmd)}\b", payload_lower) for cmd in user_cmds):
        t = catalog.get("T1033")
        matched = next(cmd for cmd in user_cmds if re.search(rf"\b{re.escape(cmd)}\b", payload_lower))
        return {
            "technique_id": "T1033",
            "name": t.name if t else "System Owner/User Discovery",
            "tactic": "Discovery",
            "mapping_rule": RULE_USER_DISCOVERY,
            "explanation": f"Payload executed user discovery command '{matched}' to enumerate account identity.",
            "mapping_status": "supported",
            "evidence_strength": "high",
            "confidence": 0.88,
            "severity": "low",
            "supporting_event_fields": {"payload": payload_str, "discovered_command": matched}
        }

    # 5. System Information Discovery (T1082) - Discovery
    # Evidence: OS version, architecture, or hardware queries
    sysinfo_cmds = ["uname -a", "uname", "cat /etc/os-release", "cat /proc/cpuinfo", "lscpu", "systeminfo", "cat /proc/version"]
    if any(cmd in payload_lower for cmd in sysinfo_cmds):
        t = catalog.get("T1082")
        matched = next(cmd for cmd in sysinfo_cmds if cmd in payload_lower)
        return {
            "technique_id": "T1082",
            "name": t.name if t else "System Information Discovery",
            "tactic": "Discovery",
            "mapping_rule": RULE_SYSINFO_DISCOVERY,
            "explanation": f"Payload executed host discovery command '{matched}' querying operating system specifications.",
            "mapping_status": "supported",
            "evidence_strength": "high",
            "confidence": 0.88,
            "severity": "low",
            "supporting_event_fields": {"payload": payload_str, "discovered_command": matched}
        }

    # 6. File and Directory Discovery (T1083) - Discovery
    if any(k in payload_lower for k in ["ls -", "find /", "dir /s", "locate "]):
        t = catalog.get("T1083")
        return {
            "technique_id": "T1083",
            "name": t.name if t else "File and Directory Discovery",
            "tactic": "Discovery",
            "mapping_rule": RULE_FILE_DIR_DISCOVERY,
            "explanation": "Payload executed directory listing or file location searches on target host.",
            "mapping_status": "supported",
            "evidence_strength": "medium",
            "confidence": 0.80,
            "severity": "low",
            "supporting_event_fields": {"payload": payload_str}
        }

    # 7. Remote System Discovery (T1018) - Discovery
    if any(k in payload_lower for k in ["arp -a", "net view", "ip neigh"]):
        t = catalog.get("T1018")
        return {
            "technique_id": "T1018",
            "name": t.name if t else "Remote System Discovery",
            "tactic": "Discovery",
            "mapping_rule": RULE_REMOTE_SYSTEM_DISCOVERY,
            "explanation": "Payload executed discovery commands querying adjacent network hosts or neighbors.",
            "mapping_status": "supported",
            "evidence_strength": "medium",
            "confidence": 0.80,
            "severity": "low",
            "supporting_event_fields": {"payload": payload_str}
        }

    # 8. PowerShell Interpreter (T1059.001) - Execution
    if "powershell" in payload_lower or "invoke-expression" in payload_lower or "invoke-webrequest" in payload_lower:
        t = catalog.get("T1059.001")
        return {
            "technique_id": "T1059.001",
            "name": t.name if t else "Command and Scripting Interpreter: PowerShell",
            "tactic": "Execution",
            "mapping_rule": RULE_POWERSHELL,
            "explanation": "Payload contains PowerShell invocation or cmdlet execution.",
            "mapping_status": "supported",
            "evidence_strength": "high",
            "confidence": 0.90,
            "severity": "medium",
            "supporting_event_fields": {"payload": payload_str}
        }

    # 9. Exploit Public-Facing Application (T1190) - Initial Access
    # Concrete payload evidence: SQL injection, path traversal, Log4j JNDI, or known CVE signatures
    exploit_indicators = ["' or '1'='1", "union select", "../", "..\\", "${jndi:", "cve-", "/etc/passwd"]
    if any(ind in payload_lower for ind in exploit_indicators) and ("http" in (honeypot_type or "").lower() or destination_port in [80, 443, 8080, 8000]):
        t = catalog.get("T1190")
        matched = next(ind for ind in exploit_indicators if ind in payload_lower)
        return {
            "technique_id": "T1190",
            "name": t.name if t else "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "mapping_rule": RULE_EXPLOIT_PAYLOAD,
            "explanation": f"Inbound application payload exhibited exploit signature: '{matched}'.",
            "mapping_status": "supported",
            "evidence_strength": "high",
            "confidence": 0.92,
            "severity": "high",
            "supporting_event_fields": {"payload": payload_str, "matched_pattern": matched}
        }

    # 10. Network Service Discovery (T1046) - Discovery
    if event_type_lower in ["port_scan", "network_scan", "syn_scan"] or "scan" in payload_lower:
        t = catalog.get("T1046")
        return {
            "technique_id": "T1046",
            "name": t.name if t else "Network Service Discovery",
            "tactic": "Discovery",
            "mapping_rule": RULE_NETWORK_SCAN,
            "explanation": "Observed port or network scanning activity against honeynet listeners.",
            "mapping_status": "supported",
            "evidence_strength": "high",
            "confidence": 0.85,
            "severity": "low",
            "supporting_event_fields": {"event_type": event_type, "payload": payload_str}
        }

    # 11. Valid Accounts (T1078) - Initial Access
    # Evidence: Explicit successful authentication
    if event_type_lower in ["login_success", "auth_success"] or "login successful" in payload_lower:
        t = catalog.get("T1078")
        return {
            "technique_id": "T1078",
            "name": t.name if t else "Valid Accounts",
            "tactic": "Initial Access",
            "mapping_rule": RULE_VALID_ACCOUNTS,
            "explanation": f"Observed successful authentication into decoy using valid credentials for account '{username or 'unknown'}'.",
            "mapping_status": "supported",
            "evidence_strength": "medium",
            "confidence": 0.80,
            "severity": "medium",
            "supporting_event_fields": {"username": username, "event_type": event_type}
        }

    # 12. General Command Execution / Unix Shell (T1059.004) - Execution
    # Only if payload is present and represents arbitrary command execution
    if (event_type_lower == "command_execution" or any(k in payload_lower for k in ["sh ", "bash", "/bin/sh", "/bin/bash"])) and payload_str:
        t = catalog.get("T1059.004")
        return {
            "technique_id": "T1059.004",
            "name": t.name if t else "Command and Scripting Interpreter: Unix Shell",
            "tactic": "Execution",
            "mapping_rule": RULE_UNIX_SHELL,
            "explanation": f"Observed interactive command or shell script invocation: '{payload_str[:80]}'.",
            "mapping_status": "supported",
            "evidence_strength": "medium",
            "confidence": 0.82,
            "severity": "medium",
            "supporting_event_fields": {"payload": payload_str, "event_type": event_type}
        }

    # 13. Authentication attempts & Brute Force handling (T1110.001) - Credential Access
    # Crucial rule: Do NOT map every single failed login to a confirmed brute force technique!
    if "auth" in event_type_lower or "login" in event_type_lower:
        # Check if the payload indicates explicit brute force tool or password spray dictionary
        if any(tool in payload_lower for tool in ["hydra", "medusa", "passwords.txt", "wordlist", "bruteforce"]):
            t = catalog.get("T1110.001")
            return {
                "technique_id": "T1110.001",
                "name": t.name if t else "Password Guessing",
                "tactic": "Credential Access",
                "mapping_rule": RULE_AUTH_BRUTE_FORCE,
                "explanation": "Authentication payload contains automated brute force tool or wordlist signature.",
                "mapping_status": "supported",
                "evidence_strength": "high",
                "confidence": 0.90,
                "severity": "high",
                "supporting_event_fields": {"payload": payload_str, "username": username}
            }
        else:
            # Single isolated failed login without sequence evidence: Mark as INSUFFICIENT EVIDENCE
            t = catalog.get("T1110.001")
            return {
                "technique_id": "T1110.001",
                "name": t.name if t else "Password Guessing",
                "tactic": "Credential Access",
                "mapping_rule": RULE_PASSWORD_GUESSING,
                "explanation": "Isolated authentication failure; insufficient evidence to establish brute force without repeated attempts or credential spray evidence.",
                "mapping_status": "insufficient_evidence",
                "evidence_strength": "low",
                "confidence": 0.35,
                "severity": "low",
                "supporting_event_fields": {"event_type": event_type, "username": username}
            }

    # 14. Unmapped Events (Ping, generic probe, connection closed, etc.)
    # Strictly do NOT default to T1190 or fabricate a mapping!
    return {
        "technique_id": None,
        "name": "Unmapped",
        "tactic": "None",
        "mapping_rule": RULE_UNMAPPED,
        "explanation": "No telemetry evidence matches known MITRE ATT&CK techniques.",
        "mapping_status": "unmapped",
        "evidence_strength": "none",
        "confidence": 0.0,
        "severity": "low",
        "supporting_event_fields": {"event_type": event_type, "payload": payload_str}
    }

def map_telemetry_to_mitre(
    event_type: str,
    payload: Optional[str] = None,
    destination_port: int = 0,
    honeypot_type: str = "",
    username: Optional[str] = None
) -> Dict[str, Any]:
    """
    Evidence-based evaluation function.
    Maintains compatibility with caller expectations while returning rigorous evidence-based mappings.
    """
    evidence = evaluate_event_evidence(
        event_type=event_type,
        payload=payload,
        username=username,
        destination_port=destination_port,
        honeypot_type=honeypot_type
    )

    if evidence["mapping_status"] == "supported":
        return {
            "technique_id": evidence["technique_id"],
            "name": evidence["name"],
            "tactic": evidence["tactic"],
            "confidence": evidence["confidence"],
            "severity": evidence["severity"],
            "mapping_rule": evidence["mapping_rule"],
            "explanation": evidence["explanation"],
            "evidence_strength": evidence["evidence_strength"],
            "mapping_status": evidence["mapping_status"]
        }
    else:
        # For unmapped or insufficient evidence, return None for technique_id
        return {
            "technique_id": None,
            "name": None,
            "tactic": None,
            "confidence": evidence["confidence"],
            "severity": evidence["severity"],
            "mapping_rule": evidence["mapping_rule"],
            "explanation": evidence["explanation"],
            "evidence_strength": evidence["evidence_strength"],
            "mapping_status": evidence["mapping_status"]
        }

def persist_event_technique_mapping(
    event: TelemetryEventDB,
    db: Session
) -> Optional[TechniqueMappingDB]:
    """
    Evaluates and records an event-level MITRE ATT&CK mapping in the database.
    Only records supported or explicit insufficient_evidence mappings.
    """
    evidence = evaluate_event_evidence(
        event_type=event.event_type,
        payload=event.payload,
        username=event.username,
        destination_port=event.destination_port,
        honeypot_type=event.honeypot_type
    )

    # Check if a mapping already exists for this event
    existing = db.query(TechniqueMappingDB).filter(
        TechniqueMappingDB.event_id == event.event_id,
        TechniqueMappingDB.scope == "event"
    ).first()

    if evidence["mapping_status"] == "supported":
        if existing:
            existing.technique_id = evidence["technique_id"]
            existing.technique_name = evidence["name"]
            existing.tactic = evidence["tactic"]
            existing.supporting_event_ids = [event.event_id]
            existing.supporting_event_fields = evidence["supporting_event_fields"]
            existing.mapping_rule = evidence["mapping_rule"]
            existing.explanation = evidence["explanation"]
            existing.mapping_status = evidence["mapping_status"]
            existing.evidence_strength = evidence["evidence_strength"]
            db.commit()
            return existing
        else:
            mapping = TechniqueMappingDB(
                technique_id=evidence["technique_id"],
                technique_name=evidence["name"],
                tactic=evidence["tactic"],
                scope="event",
                event_id=event.event_id,
                session_id=event.session_id,
                supporting_event_ids=[event.event_id],
                supporting_event_fields=evidence["supporting_event_fields"],
                mapping_rule=evidence["mapping_rule"],
                explanation=evidence["explanation"],
                mapping_status=evidence["mapping_status"],
                evidence_strength=evidence["evidence_strength"]
            )
            db.add(mapping)
            db.commit()
            db.refresh(mapping)
            return mapping
    else:
        # If existing mapping is no longer supported, remove it
        if existing:
            db.delete(existing)
            db.commit()
        return None

def analyze_session_techniques(
    session: InvestigationSessionDB,
    db: Session
) -> List[Dict[str, Any]]:
    """
    Aggregates evidence-backed technique mappings at the session level.
    Requirements:
    - Retains event IDs supporting each mapping.
    - Avoids duplicate mappings for the same evidence.
    - Handles multi-event brute force detection (>= 2 auth failures in session promotes to T1110.001 supported).
    - Stores session-level records in technique_mappings with scope='session'.
    - Updates session.associated_mitre_techniques.
    """
    catalog = load_mitre_catalog()

    # Retrieve all events for this session ordered chronologically
    events = db.query(TelemetryEventDB).filter(
        (TelemetryEventDB.session_id == session.session_id) |
        (TelemetryEventDB.event_id.in_(session.associated_event_ids or []))
    ).order_by(TelemetryEventDB.timestamp.asc()).all()

    if not events:
        session.associated_mitre_techniques = []
        db.commit()
        return []

    # Map techniques observed across events: technique_id -> aggregate info
    technique_aggregates: Dict[str, Dict[str, Any]] = {}
    auth_failures: List[TelemetryEventDB] = []

    for evt in events:
        ev_eval = evaluate_event_evidence(
            event_type=evt.event_type,
            payload=evt.payload,
            username=evt.username,
            destination_port=evt.destination_port,
            honeypot_type=evt.honeypot_type
        )

        # Track authentication failures for session-level brute force analysis
        ev_type_lower = (evt.event_type or "").lower()
        if "fail" in ev_type_lower or ("auth" in ev_type_lower and ev_type_lower != "auth_success"):
            auth_failures.append(evt)

        if ev_eval["mapping_status"] == "supported" and ev_eval["technique_id"]:
            tid = ev_eval["technique_id"]
            if tid not in technique_aggregates:
                technique_aggregates[tid] = {
                    "technique_id": tid,
                    "name": ev_eval["name"],
                    "tactic": ev_eval["tactic"],
                    "supporting_event_ids": [evt.event_id],
                    "supporting_event_fields": ev_eval["supporting_event_fields"],
                    "mapping_rule": ev_eval["mapping_rule"],
                    "explanation": ev_eval["explanation"],
                    "mapping_status": "supported",
                    "evidence_strength": ev_eval["evidence_strength"],
                    "event_count": 1
                }
            else:
                if evt.event_id not in technique_aggregates[tid]["supporting_event_ids"]:
                    technique_aggregates[tid]["supporting_event_ids"].append(evt.event_id)
                technique_aggregates[tid]["event_count"] += 1
                # Increase strength if multiple events support it
                if technique_aggregates[tid]["event_count"] >= 2:
                    technique_aggregates[tid]["evidence_strength"] = "high"

    # Multi-event Brute Force Rule at Session Level:
    # If >= 2 authentication failures occurred in the session, create/update T1110.001 supported mapping!
    if len(auth_failures) >= 2:
        tid = "T1110.001"
        t_cat = catalog.get(tid)
        fail_ids = [f.event_id for f in auth_failures]
        usernames = list(set(f.username for f in auth_failures if f.username))
        technique_aggregates[tid] = {
            "technique_id": tid,
            "name": t_cat.name if t_cat else "Password Guessing",
            "tactic": "Credential Access",
            "supporting_event_ids": fail_ids,
            "supporting_event_fields": {
                "failure_count": len(auth_failures),
                "targeted_usernames": usernames
            },
            "mapping_rule": RULE_AUTH_BRUTE_FORCE,
            "explanation": f"Observed {len(auth_failures)} authentication failures in session targeting {len(usernames) or 1} user(s). Evidence supports password guessing.",
            "mapping_status": "supported",
            "evidence_strength": "high",
            "event_count": len(auth_failures)
        }

    session_techniques = list(technique_aggregates.values())

    # Update session JSON field
    session.associated_mitre_techniques = session_techniques

    # Synchronize persistent TechniqueMappingDB records for this session
    # Remove old session mappings
    db.query(TechniqueMappingDB).filter(
        TechniqueMappingDB.session_id == session.session_id,
        TechniqueMappingDB.scope == "session"
    ).delete()

    for item in session_techniques:
        mapping_db = TechniqueMappingDB(
            technique_id=item["technique_id"],
            technique_name=item["name"],
            tactic=item["tactic"],
            scope="session",
            session_id=session.session_id,
            supporting_event_ids=item["supporting_event_ids"],
            supporting_event_fields=item["supporting_event_fields"],
            mapping_rule=item["mapping_rule"],
            explanation=item["explanation"],
            mapping_status=item["mapping_status"],
            evidence_strength=item["evidence_strength"]
        )
        db.add(mapping_db)

    db.commit()
    db.refresh(session)
    return session_techniques

def run_mitre_analysis(db: Session) -> Dict[str, Any]:
    """
    Executes a comprehensive, evidence-based MITRE ATT&CK re-analysis pass
    across all telemetry events and investigation sessions in the database.
    - Synchronizes telemetry_events table columns (clears default T1190 or unmapped).
    - Records event-level TechniqueMappingDB records.
    - Aggregates session-level techniques and records session TechniqueMappingDB records.
    """
    events = db.query(TelemetryEventDB).all()
    sessions = db.query(InvestigationSessionDB).all()

    evaluated_events = len(events)
    mapped_events_count = 0
    unmapped_events_count = 0

    # 1. Process Event-Level Mappings
    for evt in events:
        evidence = evaluate_event_evidence(
            event_type=evt.event_type,
            payload=evt.payload,
            username=evt.username,
            destination_port=evt.destination_port,
            honeypot_type=evt.honeypot_type
        )

        if evidence["mapping_status"] == "supported":
            evt.mitre_technique_id = evidence["technique_id"]
            evt.mitre_technique_name = evidence["name"]
            evt.mitre_tactic = evidence["tactic"]
            evt.confidence_score = evidence["confidence"]
            evt.severity = evidence["severity"]
            mapped_events_count += 1
        else:
            evt.mitre_technique_id = None
            evt.mitre_technique_name = None
            evt.mitre_tactic = None
            evt.confidence_score = 0.0
            unmapped_events_count += 1

        persist_event_technique_mapping(evt, db)

    db.commit()

    # 2. Process Session-Level Mappings
    total_session_techniques = 0
    for sess in sessions:
        res = analyze_session_techniques(sess, db)
        total_session_techniques += len(res)

    return {
        "evaluated_events": evaluated_events,
        "mapped_events": mapped_events_count,
        "unmapped_events": unmapped_events_count,
        "evaluated_sessions": len(sessions),
        "session_techniques_mapped": total_session_techniques,
        "message": f"Successfully evaluated {evaluated_events} events ({mapped_events_count} evidence-backed, {unmapped_events_count} unmapped) across {len(sessions)} sessions."
    }
