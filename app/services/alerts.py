from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime, timezone
import uuid
import json
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.models.telemetry import TelemetryEventDB
from app.models.session import InvestigationSessionDB
from app.models.alert import AlertDB, AlertDetectResponse
from app.services.mitre import MITRE_TECHNIQUES

# Detection Rule Definitions
RULE_AUTH_BRUTE_FORCE = "ALERT_RULE_AUTH_BRUTE_FORCE"
RULE_AUTH_BREACH = "ALERT_RULE_AUTH_BREACH"
RULE_DISCOVERY_CONCENTRATION = "ALERT_RULE_DISCOVERY_CONCENTRATION"
RULE_POST_AUTH_EXECUTION = "ALERT_RULE_POST_AUTH_EXECUTION"
RULE_CRON_PERSISTENCE = "ALERT_RULE_CRON_PERSISTENCE"
RULE_INGRESS_TOOL_TRANSFER = "ALERT_RULE_INGRESS_TOOL_TRANSFER"
RULE_INDICATOR_REMOVAL = "ALERT_RULE_INDICATOR_REMOVAL"

DISCOVERY_TECHNIQUES = {"T1082", "T1087", "T1046", "T1083", "T1018", "T1016", "T1049"}
DISCOVERY_KEYWORDS = ["uname", "id", "whoami", "cat /etc/passwd", "cat /etc/shadow", "ps", "netstat", "ifconfig", "ip a", "lsof", "w", "last"]

def cluster_threat_actor(events: List[TelemetryEventDB], source_ip: str) -> str:
    """
    Cluster threat actors into behavioral profiles based on observed TTPs.
    """
    payloads = " ".join([(e.payload or "") for e in events]).lower()
    
    if "curl" in payloads and ("mips" in payloads or "arm" in payloads or "sh" in payloads):
        return "Mirai-IoT-Botnet"
    if "powershell" in payloads or "cmd.exe" in payloads:
        return "Empire-Living-Off-The-Land"
    if "whoami" in payloads and "crontab" in payloads:
        return "APT-C2-Intruder"
    if len(events) >= 3 and all(e.event_type in ["auth_attempt", "auth_failure", "login_failed"] for e in events):
        return "Hydra-Brute-Force-Actor"
    if any(e.event_type == "port_scan" for e in events):
        return "ZMap-Masscan-Recon-Scanner"
    
    clean_ip = source_ip.replace(".", "-").replace(":", "-")[:12]
    return f"Threat-Cluster-{clean_ip}"

def _is_auth_failure(event: TelemetryEventDB) -> bool:
    et = (event.event_type or "").lower()
    payload = (event.payload or "").lower()
    if et in ["auth_failure", "login_failed"]:
        return True
    if et == "auth_attempt":
        if "failed" in payload or "invalid" in payload or "failure" in payload:
            return True
        # If payload is just username/password without explicit success, treat as failure
        if "success" not in payload and "accepted" not in payload:
            return True
    return False

def _is_auth_success(event: TelemetryEventDB) -> bool:
    et = (event.event_type or "").lower()
    payload = (event.payload or "").lower()
    if et in ["auth_success", "session_start", "login_success"]:
        return True
    if "accepted password" in payload or "successful login" in payload:
        return True
    return False

def _upsert_alert(
    db: Session,
    fingerprint: str,
    rule_id: str,
    title: str,
    description: str,
    severity: str,
    severity_rationale: str,
    explanation: str,
    source_ip: str,
    session_id: Optional[str],
    related_event_ids: List[str],
    related_technique_ids: List[str],
    supporting_evidence: Dict[str, Any],
    primary_technique_id: Optional[str] = None,
    threat_actor_cluster: Optional[str] = None,
    data_origin: str = "real"
) -> Tuple[AlertDB, bool]:
    """
    Creates or updates an alert with strict fingerprint deduplication.
    Returns (alert, is_new).
    """
    existing_alert = db.query(AlertDB).filter(AlertDB.fingerprint == fingerprint).first()
    
    if existing_alert:
        # Merge new event IDs preserving order and uniqueness
        curr_ids = list(existing_alert.related_event_ids or [])
        updated_ids = list(dict.fromkeys(curr_ids + related_event_ids))
        
        curr_techs = list(existing_alert.related_technique_ids or [])
        updated_techs = list(dict.fromkeys(curr_techs + related_technique_ids))
        
        existing_alert.related_event_ids = updated_ids
        existing_alert.related_technique_ids = updated_techs
        existing_alert.supporting_evidence = supporting_evidence
        existing_alert.explanation = explanation
        existing_alert.severity_rationale = severity_rationale
        existing_alert.title = title
        existing_alert.description = description
        if primary_technique_id:
            existing_alert.primary_technique_id = primary_technique_id
        if threat_actor_cluster:
            existing_alert.threat_actor_cluster = threat_actor_cluster
        existing_alert.timestamp = datetime.now(timezone.utc)
        
        db.commit()
        db.refresh(existing_alert)
        return existing_alert, False
    else:
        new_alert = AlertDB(
            alert_id=f"alt-{uuid.uuid4().hex[:12]}",
            timestamp=datetime.now(timezone.utc),
            session_id=session_id,
            source_ip=source_ip,
            title=title,
            description=description,
            severity=severity,
            status="NEW",
            is_resolved=False,
            detection_rule_id=rule_id,
            fingerprint=fingerprint,
            related_event_ids=related_event_ids,
            related_technique_ids=related_technique_ids,
            supporting_evidence=supporting_evidence,
            explanation=explanation,
            severity_rationale=severity_rationale,
            primary_technique_id=primary_technique_id,
            threat_actor_cluster=threat_actor_cluster or f"Threat-Cluster-{source_ip.replace('.', '-')[:12]}",
            data_origin=data_origin
        )
        db.add(new_alert)
        db.commit()
        db.refresh(new_alert)
        return new_alert, True

def evaluate_session_for_alerts(session_record: InvestigationSessionDB, events: List[TelemetryEventDB], db: Session) -> List[Tuple[AlertDB, bool]]:
    """
    Evaluates a correlated attack session against all explainable detection rules.
    Returns list of (AlertDB, is_new).
    """
    results: List[Tuple[AlertDB, bool]] = []
    if not events:
        return results

    # Sort events chronologically
    sorted_events = sorted(events, key=lambda e: e.timestamp or datetime.min)
    source_ip = session_record.source_ip or (sorted_events[0].source_ip if sorted_events else "unknown")
    cluster_name = cluster_threat_actor(sorted_events, source_ip)
    data_origin = "synthetic" if any(e.data_origin == "synthetic" for e in sorted_events) else "real"
    
    # 1. Evaluate Repeated Authentication Failures (Rule 1)
    # Important: Do NOT flag isolated failed login (< 3 attempts)
    auth_failures = [e for e in sorted_events if _is_auth_failure(e)]
    if len(auth_failures) >= 3:
        failed_ids = [e.event_id for e in auth_failures]
        usernames_tried = list(set(e.username for e in auth_failures if e.username))
        timestamps = [e.timestamp.isoformat() if e.timestamp else "" for e in auth_failures]
        honeypot_ids = list(set(e.honeypot_id for e in auth_failures if e.honeypot_id))
        
        severity = "high" if len(auth_failures) >= 5 else "medium"
        rationale = (
            f"Severity assigned as '{severity.upper()}': {len(auth_failures)} repeated authentication failures "
            f"were observed against honeypot accounts ({', '.join(usernames_tried) or 'unknown'}). "
            f"Repeated failures exceeding the threshold (>=3) indicate automated credential testing rather than a benign typo."
        )
        explanation = (
            f"Observed Evidence: {len(auth_failures)} consecutive authentication failure events from IP {source_ip} "
            f"between {timestamps[0]} and {timestamps[-1]}. Rule Matched: {RULE_AUTH_BRUTE_FORCE}. "
            f"Why Matched: Telemetry recorded {len(auth_failures)} failed login attempts exceeding the detection threshold (min 3). "
            f"Investigative Hypothesis: Systematic credential guessing or dictionary attack against target services."
        )
        evidence = {
            "failure_count": len(auth_failures),
            "usernames_attempted": usernames_tried,
            "honeypots_targeted": honeypot_ids,
            "event_ids": failed_ids,
            "first_attempt": timestamps[0] if timestamps else None,
            "last_attempt": timestamps[-1] if timestamps else None
        }
        
        fingerprint = f"{RULE_AUTH_BRUTE_FORCE}:{session_record.session_id or source_ip}"
        alert, is_new = _upsert_alert(
            db=db,
            fingerprint=fingerprint,
            rule_id=RULE_AUTH_BRUTE_FORCE,
            title=f"Brute Force Credential Spraying ({len(auth_failures)} Failures)",
            description=f"Multiple consecutive authentication failures observed from adversary IP {source_ip}.",
            severity=severity,
            severity_rationale=rationale,
            explanation=explanation,
            source_ip=source_ip,
            session_id=session_record.session_id,
            related_event_ids=failed_ids,
            related_technique_ids=["T1110.001", "T1110"],
            supporting_evidence=evidence,
            primary_technique_id="T1110.001",
            threat_actor_cluster=cluster_name,
            data_origin=data_origin
        )
        results.append((alert, is_new))

    # 2. Evaluate Auth Failure Followed by Success (Rule 2 - Auth Breach)
    auth_successes = [e for e in sorted_events if _is_auth_success(e)]
    if auth_failures and auth_successes:
        first_success = auth_successes[0]
        # Verify chronological order: at least one failure occurred before success
        prior_failures = [f for f in auth_failures if (f.timestamp or datetime.min) <= (first_success.timestamp or datetime.max)]
        if prior_failures:
            breach_event_ids = [f.event_id for f in prior_failures] + [first_success.event_id]
            severity = "critical"
            rationale = (
                "Severity assigned as 'CRITICAL': One or more authentication failures were immediately followed "
                "by a successful login within the same session. This progression indicates compromised credentials "
                "granting unauthorized access to the honeypot."
            )
            explanation = (
                f"Observed Evidence: {len(prior_failures)} failed authentication attempt(s) followed by successful authentication "
                f"for account '{first_success.username or 'root'}' at {first_success.timestamp.isoformat() if first_success.timestamp else 'unknown'}. "
                f"Rule Matched: {RULE_AUTH_BREACH}. Why Matched: Failed authentication attempts directly preceded a valid session login. "
                f"Investigative Hypothesis: The threat actor successfully guessed or obtained valid credentials."
            )
            evidence = {
                "prior_failure_count": len(prior_failures),
                "successful_login_event_id": first_success.event_id,
                "successful_username": first_success.username,
                "login_timestamp": first_success.timestamp.isoformat() if first_success.timestamp else None,
                "destination_port": first_success.destination_port
            }
            fingerprint = f"{RULE_AUTH_BREACH}:{session_record.session_id or source_ip}"
            alert, is_new = _upsert_alert(
                db=db,
                fingerprint=fingerprint,
                rule_id=RULE_AUTH_BREACH,
                title=f"Authentication Breach: Successful Login Following Failures",
                description=f"Adversary from {source_ip} successfully gained authentication access following prior failed attempts.",
                severity=severity,
                severity_rationale=rationale,
                explanation=explanation,
                source_ip=source_ip,
                session_id=session_record.session_id,
                related_event_ids=breach_event_ids,
                related_technique_ids=["T1078", "T1110"],
                supporting_evidence=evidence,
                primary_technique_id="T1078",
                threat_actor_cluster=cluster_name,
                data_origin=data_origin
            )
            results.append((alert, is_new))

    # 3. Evaluate Discovery-related Behavior (Rule 3)
    discovery_events = []
    observed_discovery_techs = set()
    for e in sorted_events:
        tech = e.mitre_technique_id
        payload = (e.payload or "").lower()
        if tech in DISCOVERY_TECHNIQUES:
            discovery_events.append(e)
            observed_discovery_techs.add(tech)
        elif any(k in payload for k in DISCOVERY_KEYWORDS) and e.event_type in ["command_exec", "interactive_command", "network_scan"]:
            discovery_events.append(e)
            if tech:
                observed_discovery_techs.add(tech)
            else:
                observed_discovery_techs.add("T1082")

    if len(observed_discovery_techs) >= 2 or len(discovery_events) >= 3:
        disc_ids = [e.event_id for e in discovery_events]
        primary_disc = sorted(list(observed_discovery_techs))[0] if observed_discovery_techs else "T1082"
        severity = "medium"
        rationale = (
            f"Severity assigned as 'MEDIUM': Adversary conducted multi-faceted discovery reconnaissance ({len(discovery_events)} events) "
            f"spanning techniques {', '.join(sorted(list(observed_discovery_techs)))}. Reconnaissance indicates situational discovery without immediate destruction."
        )
        explanation = (
            f"Observed Evidence: {len(discovery_events)} discovery commands executed across {len(observed_discovery_techs)} MITRE techniques. "
            f"Rule Matched: {RULE_DISCOVERY_CONCENTRATION}. Why Matched: Discovery activity concentrated within correlated session {session_record.session_id}. "
            f"Investigative Hypothesis: Attacker is profiling system architecture, users, and network topology prior to lateral movement or staging."
        )
        evidence = {
            "discovery_commands_count": len(discovery_events),
            "techniques_observed": sorted(list(observed_discovery_techs)),
            "commands_executed": [e.payload for e in discovery_events if e.payload][:5],
            "event_ids": disc_ids
        }
        fingerprint = f"{RULE_DISCOVERY_CONCENTRATION}:{session_record.session_id or source_ip}"
        alert, is_new = _upsert_alert(
            db=db,
            fingerprint=fingerprint,
            rule_id=RULE_DISCOVERY_CONCENTRATION,
            title=f"Discovery Reconnaissance Concentration ({len(observed_discovery_techs)} Techniques)",
            description=f"Systematic post-access or pre-attack reconnaissance commands observed from {source_ip}.",
            severity=severity,
            severity_rationale=rationale,
            explanation=explanation,
            source_ip=source_ip,
            session_id=session_record.session_id,
            related_event_ids=disc_ids,
            related_technique_ids=sorted(list(observed_discovery_techs)),
            supporting_evidence=evidence,
            primary_technique_id=primary_disc,
            threat_actor_cluster=cluster_name,
            data_origin=data_origin
        )
        results.append((alert, is_new))

    # 4. Evaluate Multiple Suspicious Events / Post-Auth Command Execution (Rule 4)
    # Condition: Auth event present followed by interactive shell commands
    command_events = [e for e in sorted_events if e.event_type in ["command_exec", "interactive_command"]]
    if auth_successes and command_events:
        post_auth_commands = [c for c in command_events if (c.timestamp or datetime.min) >= (auth_successes[0].timestamp or datetime.min)]
        if post_auth_commands:
            chain_ids = [auth_successes[0].event_id] + [c.event_id for c in post_auth_commands]
            severity = "high"
            rationale = (
                "Severity assigned as 'HIGH': Confirmed execution of interactive commands following established session authentication. "
                "Interactive command execution within a honeynet represents active hands-on-keyboard adversary activity."
            )
            explanation = (
                f"Observed Evidence: {len(post_auth_commands)} interactive shell commands recorded following login '{auth_successes[0].username}'. "
                f"Rule Matched: {RULE_POST_AUTH_EXECUTION}. Why Matched: Post-authentication execution sequence confirmed in session {session_record.session_id}. "
                f"Investigative Hypothesis: Hands-on-keyboard adversary or automated post-exploitation script interacting with the shell environment."
            )
            evidence = {
                "auth_event_id": auth_successes[0].event_id,
                "executed_commands": [c.payload for c in post_auth_commands if c.payload][:5],
                "command_count": len(post_auth_commands),
                "event_ids": chain_ids
            }
            fingerprint = f"{RULE_POST_AUTH_EXECUTION}:{session_record.session_id or source_ip}"
            alert, is_new = _upsert_alert(
                db=db,
                fingerprint=fingerprint,
                rule_id=RULE_POST_AUTH_EXECUTION,
                title=f"Post-Authentication Interactive Command Execution ({len(post_auth_commands)} Commands)",
                description=f"Actor from {source_ip} authenticated and executed interactive shell commands on the honeypot.",
                severity=severity,
                severity_rationale=rationale,
                explanation=explanation,
                source_ip=source_ip,
                session_id=session_record.session_id,
                related_event_ids=chain_ids,
                related_technique_ids=["T1059.004", "T1078"],
                supporting_evidence=evidence,
                primary_technique_id="T1059.004",
                threat_actor_cluster=cluster_name,
                data_origin=data_origin
            )
            results.append((alert, is_new))

    # 5. Evaluate Specific Technique-backed Patterns (Rules 5, 6, 7)
    for e in sorted_events:
        payload = (e.payload or "").lower()
        
        # Rule 5: Cron Persistence (T1053.003)
        if e.mitre_technique_id == "T1053.003" or "crontab" in payload or "/etc/cron" in payload:
            severity = "critical"
            rationale = (
                "Severity assigned as 'CRITICAL': Persistence modification detected. Modifying cron jobs allows the actor "
                "to maintain survival across session teardowns and system reboots."
            )
            explanation = (
                f"Observed Evidence: Execution of scheduled task / cron command: '{e.payload}'. "
                f"Rule Matched: {RULE_CRON_PERSISTENCE}. Why Matched: Direct invocation of cron scheduling mechanisms. "
                f"Investigative Hypothesis: Adversary is securing persistent backdoor execution."
            )
            evidence = {
                "event_id": e.event_id,
                "payload": e.payload,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None
            }
            fingerprint = f"{RULE_CRON_PERSISTENCE}:{session_record.session_id or source_ip}"
            alert, is_new = _upsert_alert(
                db=db,
                fingerprint=fingerprint,
                rule_id=RULE_CRON_PERSISTENCE,
                title=f"Persistence Mechanism: Cron Modification Detected",
                description=f"Attacker scheduled a persistent task or cron job from source IP {source_ip}.",
                severity=severity,
                severity_rationale=rationale,
                explanation=explanation,
                source_ip=source_ip,
                session_id=session_record.session_id,
                related_event_ids=[e.event_id],
                related_technique_ids=["T1053.003"],
                supporting_evidence=evidence,
                primary_technique_id="T1053.003",
                threat_actor_cluster=cluster_name,
                data_origin=data_origin
            )
            results.append((alert, is_new))

        # Rule 6: Ingress Tool Transfer (T1105)
        if e.mitre_technique_id == "T1105" or (("curl " in payload or "wget " in payload or "tftp " in payload) and ("http" in payload or "ftp" in payload or ".sh" in payload or ".bin" in payload)):
            severity = "high"
            rationale = (
                "Severity assigned as 'HIGH': Network transfer tool invoked to download external files. "
                "Staging tools or malware binaries onto the honeynet indicates secondary payload execution."
            )
            explanation = (
                f"Observed Evidence: External payload download command: '{e.payload}'. "
                f"Rule Matched: {RULE_INGRESS_TOOL_TRANSFER}. Why Matched: Ingress tool transfer command captured in shell stream. "
                f"Investigative Hypothesis: Adversary is staging malware implants or lateral movement scripts."
            )
            evidence = {
                "event_id": e.event_id,
                "payload": e.payload,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None
            }
            fingerprint = f"{RULE_INGRESS_TOOL_TRANSFER}:{session_record.session_id or source_ip}"
            alert, is_new = _upsert_alert(
                db=db,
                fingerprint=fingerprint,
                rule_id=RULE_INGRESS_TOOL_TRANSFER,
                title=f"Ingress Tool Transfer: Staging Remote Payload",
                description=f"External file retrieval command executed by {source_ip}.",
                severity=severity,
                severity_rationale=rationale,
                explanation=explanation,
                source_ip=source_ip,
                session_id=session_record.session_id,
                related_event_ids=[e.event_id],
                related_technique_ids=["T1105"],
                supporting_evidence=evidence,
                primary_technique_id="T1105",
                threat_actor_cluster=cluster_name,
                data_origin=data_origin
            )
            results.append((alert, is_new))

        # Rule 7: Indicator Removal (T1070.004)
        if e.mitre_technique_id == "T1070.004" or ("history -c" in payload or "rm -rf" in payload or "> /var/log" in payload or "unset histfile" in payload):
            severity = "high"
            rationale = (
                "Severity assigned as 'HIGH': Anti-forensics command observed. Defense evasion by clearing command logs "
                "or removing traces indicates deliberate efforts to obscure intrusion footprints."
            )
            explanation = (
                f"Observed Evidence: Log or history wipe command executed: '{e.payload}'. "
                f"Rule Matched: {RULE_INDICATOR_REMOVAL}. Why Matched: Anti-forensics / indicator removal command captured. "
                f"Investigative Hypothesis: Attacker is actively trying to evade forensic timeline reconstruction."
            )
            evidence = {
                "event_id": e.event_id,
                "payload": e.payload,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None
            }
            fingerprint = f"{RULE_INDICATOR_REMOVAL}:{session_record.session_id or source_ip}"
            alert, is_new = _upsert_alert(
                db=db,
                fingerprint=fingerprint,
                rule_id=RULE_INDICATOR_REMOVAL,
                title=f"Defense Evasion: Indicator Removal / Anti-Forensics",
                description=f"Adversary from {source_ip} executed commands to erase command history or audit logs.",
                severity=severity,
                severity_rationale=rationale,
                explanation=explanation,
                source_ip=source_ip,
                session_id=session_record.session_id,
                related_event_ids=[e.event_id],
                related_technique_ids=["T1070.004"],
                supporting_evidence=evidence,
                primary_technique_id="T1070.004",
                threat_actor_cluster=cluster_name,
                data_origin=data_origin
            )
            results.append((alert, is_new))

    return results

def detect_explainable_alerts(db: Session) -> AlertDetectResponse:
    """
    Main detection service: Evaluates all sessions and unassigned events,
    generating or updating explainable security alerts with deduplication.
    """
    sessions = db.query(InvestigationSessionDB).all()
    all_events = db.query(TelemetryEventDB).all()
    
    events_by_session: Dict[str, List[TelemetryEventDB]] = {}
    unassigned_by_ip: Dict[str, List[TelemetryEventDB]] = {}
    
    for ev in all_events:
        if ev.session_id:
            events_by_session.setdefault(ev.session_id, []).append(ev)
        else:
            unassigned_by_ip.setdefault(ev.source_ip, []).append(ev)
            
    new_alerts_count = 0
    updated_alerts_count = 0
    
    # 1. Process correlated sessions
    for sess in sessions:
        sess_events = events_by_session.get(sess.session_id, [])
        alert_results = evaluate_session_for_alerts(sess, sess_events, db)
        for _, is_new in alert_results:
            if is_new:
                new_alerts_count += 1
            else:
                updated_alerts_count += 1
                
    # 2. Process unassigned events grouped by source IP (synthetic sessions for evaluation)
    for ip, ip_events in unassigned_by_ip.items():
        pseudo_session = InvestigationSessionDB(
            session_id=None,
            source_ip=ip,
            honeypot_id=ip_events[0].honeypot_id if ip_events else None
        )
        alert_results = evaluate_session_for_alerts(pseudo_session, ip_events, db)
        for _, is_new in alert_results:
            if is_new:
                new_alerts_count += 1
            else:
                updated_alerts_count += 1

    total_active = db.query(AlertDB).filter(AlertDB.is_resolved == False).count()
    
    return AlertDetectResponse(
        evaluated_sessions=len(sessions),
        evaluated_events=len(all_events),
        new_alerts_created=new_alerts_count,
        existing_alerts_updated=updated_alerts_count,
        total_active_alerts=total_active,
        message=f"Detection run complete: evaluated {len(sessions)} sessions and {len(all_events)} events. Created {new_alerts_count} new alerts, updated {updated_alerts_count} existing alerts."
    )

def check_and_create_alert(event: TelemetryEventDB, db: Session) -> Optional[AlertDB]:
    """
    Evaluates newly ingested telemetry event for real-time alert generation or update.
    Reuses the unified explainable detection logic and fingerprint deduplication.
    """
    # Fetch events associated with this session or source_ip
    if event.session_id:
        events = db.query(TelemetryEventDB).filter(TelemetryEventDB.session_id == event.session_id).all()
        session_rec = db.query(InvestigationSessionDB).filter(InvestigationSessionDB.session_id == event.session_id).first()
        if not session_rec:
            session_rec = InvestigationSessionDB(session_id=event.session_id, source_ip=event.source_ip, honeypot_id=event.honeypot_id)
    else:
        events = db.query(TelemetryEventDB).filter(TelemetryEventDB.source_ip == event.source_ip).all()
        session_rec = InvestigationSessionDB(session_id=None, source_ip=event.source_ip, honeypot_id=event.honeypot_id)

    # Ensure current event is in the list
    if not any(e.event_id == event.event_id for e in events):
        events.append(event)
        
    results = evaluate_session_for_alerts(session_rec, events, db)
    if results:
        # Return the most relevant/highest severity alert produced
        return results[0][0]
    return None
