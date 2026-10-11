"""
MITRE ATT&CK Mapping Verification Service
Project: Autonomous Honeynet Telemetry & Threat Actor MITRE ATT&CK Causal Graph Profiler.

Evaluates candidate ATT&CK mappings against authoritative catalog data and actual telemetry evidence.
Assigns explicit, documented verification statuses:
- SUPPORTED: Telemetry contains concrete evidence satisfying the documented technique criteria.
- NEEDS_MORE_EVIDENCE: Plausible technique hypothesis, but telemetry lacks sufficient sequence or payload context.
- REJECTED: Technique ID is invalid, tactic association conflicts, or evidence contradicts the technique.
"""

from enum import Enum
from typing import Optional, List, Dict, Any, Union
from pydantic import BaseModel, Field, ConfigDict

from app.services.mitre_catalog import (
    load_mitre_catalog,
    get_technique_from_catalog,
    TechniqueCatalogItem
)

class VerificationStatus(str, Enum):
    SUPPORTED = "SUPPORTED"
    NEEDS_MORE_EVIDENCE = "NEEDS_MORE_EVIDENCE"
    REJECTED = "REJECTED"

class ObservationType(str, Enum):
    DIRECT_OBSERVATION = "direct_observation"
    INFERRED_BEHAVIOR = "inferred_behavior"

class TechniqueVerificationResult(BaseModel):
    candidate_technique_id: str = Field(..., description="Proposed MITRE ATT&CK technique identifier")
    official_technique_name: Optional[str] = Field(None, description="Official technique name from catalog")
    associated_tactics: List[str] = Field(default_factory=list, description="Official ATT&CK tactics")
    is_sub_technique: bool = Field(False, description="Whether this is a sub-technique (contains dot notation)")
    parent_technique_id: Optional[str] = Field(None, description="Parent technique ID if sub-technique")
    supporting_event_ids: List[str] = Field(default_factory=list, description="IDs of events providing evidence")
    observed_behavior: str = Field(..., description="Observed telemetry behavior category or activity")
    supporting_evidence: Dict[str, Any] = Field(default_factory=dict, description="Concrete payload or event fields")
    verification_status: VerificationStatus = Field(..., description="SUPPORTED, NEEDS_MORE_EVIDENCE, or REJECTED")
    observation_type: ObservationType = Field(ObservationType.DIRECT_OBSERVATION, description="Direct or inferred")
    mapping_rationale: str = Field(..., description="Clear explanation of the verification outcome")
    missing_evidence: List[str] = Field(default_factory=list, description="Specific evidence missing for full support")
    alternative_explanations: List[str] = Field(default_factory=list, description="Plausible non-malicious or alternative explanations")
    limitations: str = Field(..., description="Documented investigative limitations of the telemetry observation")

    model_config = ConfigDict(use_enum_values=True)

def verify_technique_mapping(
    candidate_technique_id: str,
    event_type: str,
    payload: Optional[str] = None,
    username: Optional[str] = None,
    supporting_event_ids: Optional[List[str]] = None,
    event_count: int = 1,
    claimed_tactic: Optional[str] = None
) -> TechniqueVerificationResult:
    """
    Evaluates whether a candidate MITRE ATT&CK technique mapping is justified by actual evidence.
    - Validates against authoritative catalog.
    - Checks parent/sub-technique hierarchy.
    - Verifies evidence strength and distinguishes direct observation from inference.
    - Never fabricates calibrated probabilities.
    """
    catalog = load_mitre_catalog()
    t_id_clean = (candidate_technique_id or "").strip().upper()
    event_ids = supporting_event_ids or []
    payload_str = (payload or "").strip()
    payload_lower = payload_str.lower()
    event_type_lower = (event_type or "").lower().strip()

    is_sub = "." in t_id_clean
    parent_id = t_id_clean.split(".")[0] if is_sub else None

    # Step 1: Catalog Validation
    cat_item: Optional[TechniqueCatalogItem] = catalog.get(t_id_clean)
    if not cat_item:
        return TechniqueVerificationResult(
            candidate_technique_id=t_id_clean,
            official_technique_name=None,
            associated_tactics=[],
            is_sub_technique=is_sub,
            parent_technique_id=parent_id,
            supporting_event_ids=event_ids,
            observed_behavior=event_type,
            supporting_evidence={"payload": payload_str[:100] if payload_str else None},
            verification_status=VerificationStatus.REJECTED,
            observation_type=ObservationType.INFERRED_BEHAVIOR,
            mapping_rationale=f"Technique ID '{t_id_clean}' does not exist in the authoritative MITRE ATT&CK catalog.",
            missing_evidence=["Valid technique identifier in catalog."],
            alternative_explanations=["Typographical error in rule definition or unsupported custom ID."],
            limitations="Uncataloged technique cannot be mapped to MITRE knowledge base."
        )

    # Step 2: Tactic Validation if claimed
    if claimed_tactic and claimed_tactic not in cat_item.tactics:
        return TechniqueVerificationResult(
            candidate_technique_id=t_id_clean,
            official_technique_name=cat_item.name,
            associated_tactics=cat_item.tactics,
            is_sub_technique=is_sub,
            parent_technique_id=parent_id,
            supporting_event_ids=event_ids,
            observed_behavior=event_type,
            supporting_evidence={"claimed_tactic": claimed_tactic, "valid_tactics": cat_item.tactics},
            verification_status=VerificationStatus.REJECTED,
            observation_type=ObservationType.INFERRED_BEHAVIOR,
            mapping_rationale=(
                f"Claimed tactic '{claimed_tactic}' is invalid for {t_id_clean} ({cat_item.name}). "
                f"Authoritative tactics are: {', '.join(cat_item.tactics)}."
            ),
            missing_evidence=["Valid tactic correlation."],
            alternative_explanations=["Mismatched tactic metadata in detection rule."],
            limitations="Tactical objective must conform to official MITRE matrix taxonomy."
        )

    # Step 3: Evidence Evaluation by Technique
    # --- T1110 / T1110.001 Brute Force / Password Guessing ---
    if t_id_clean in ["T1110", "T1110.001"]:
        # If payload contains automated brute force tool or password spray dictionary
        has_tool = any(tool in payload_lower for tool in ["hydra", "medusa", "passwords.txt", "wordlist", "bruteforce"])
        if has_tool:
            return TechniqueVerificationResult(
                candidate_technique_id=t_id_clean,
                official_technique_name=cat_item.name,
                associated_tactics=cat_item.tactics,
                is_sub_technique=is_sub,
                parent_technique_id=parent_id,
                supporting_event_ids=event_ids,
                observed_behavior="Automated Credential Guessing",
                supporting_evidence={"payload": payload_str, "username": username},
                verification_status=VerificationStatus.SUPPORTED,
                observation_type=ObservationType.DIRECT_OBSERVATION,
                mapping_rationale="Payload exhibits explicit automated password guessing tool or dictionary signature.",
                missing_evidence=[],
                alternative_explanations=["Security audit or authorized penetration testing."],
                limitations="Confirms tool signature in honeynet listener; cannot verify credential validity on production systems."
            )
        elif event_count >= 2:
            return TechniqueVerificationResult(
                candidate_technique_id=t_id_clean,
                official_technique_name=cat_item.name,
                associated_tactics=cat_item.tactics,
                is_sub_technique=is_sub,
                parent_technique_id=parent_id,
                supporting_event_ids=event_ids,
                observed_behavior="Repeated Authentication Failures",
                supporting_evidence={"failure_count": event_count, "username": username},
                verification_status=VerificationStatus.SUPPORTED,
                observation_type=ObservationType.DIRECT_OBSERVATION,
                mapping_rationale=f"Observed sequence of {event_count} authentication failures within session window.",
                missing_evidence=[],
                alternative_explanations=["User repeatedly mistyped password or misconfigured SSH key agent."],
                limitations="Telemetry records repeated failures; does not confirm attacker intent without broader context."
            )
        else:
            # Single isolated failed login
            return TechniqueVerificationResult(
                candidate_technique_id=t_id_clean,
                official_technique_name=cat_item.name,
                associated_tactics=cat_item.tactics,
                is_sub_technique=is_sub,
                parent_technique_id=parent_id,
                supporting_event_ids=event_ids,
                observed_behavior="Isolated Authentication Failure",
                supporting_evidence={"event_type": event_type, "username": username},
                verification_status=VerificationStatus.NEEDS_MORE_EVIDENCE,
                observation_type=ObservationType.INFERRED_BEHAVIOR,
                mapping_rationale="Single isolated authentication failure does not substantiate automated brute force or password guessing.",
                missing_evidence=[
                    "Multiple authentication retries across short duration.",
                    "Automated brute-force tool identifier or dictionary payload."
                ],
                alternative_explanations=["Single benign login typo", "Stale saved credentials in legitimate client"],
                limitations="Single failure event cannot establish automated credential attack sequence."
            )

    # --- T1078 Valid Accounts ---
    if t_id_clean == "T1078":
        if "success" in event_type_lower or any(k in payload_lower for k in ["accepted password", "successful login"]):
            return TechniqueVerificationResult(
                candidate_technique_id=t_id_clean,
                official_technique_name=cat_item.name,
                associated_tactics=cat_item.tactics,
                is_sub_technique=is_sub,
                parent_technique_id=parent_id,
                supporting_event_ids=event_ids,
                observed_behavior="Successful Decoy Authentication",
                supporting_evidence={"event_type": event_type, "username": username},
                verification_status=VerificationStatus.SUPPORTED,
                observation_type=ObservationType.DIRECT_OBSERVATION,
                mapping_rationale=f"Observed accepted credentials for account '{username or 'unknown'}' establishing honeynet session.",
                missing_evidence=[],
                alternative_explanations=["Authorized decoy testing by security administrator."],
                limitations="Valid login confirms credential acceptance; does not verify account acquisition vector."
            )
        else:
            return TechniqueVerificationResult(
                candidate_technique_id=t_id_clean,
                official_technique_name=cat_item.name,
                associated_tactics=cat_item.tactics,
                is_sub_technique=is_sub,
                parent_technique_id=parent_id,
                supporting_event_ids=event_ids,
                observed_behavior=event_type,
                supporting_evidence={"event_type": event_type, "payload": payload_str[:100] if payload_str else None},
                verification_status=VerificationStatus.REJECTED,
                observation_type=ObservationType.INFERRED_BEHAVIOR,
                mapping_rationale="Event does not indicate successful authentication into a valid account.",
                missing_evidence=["Accepted authentication confirmation event."],
                alternative_explanations=["Failed authentication attempt or unauthenticated probe."],
                limitations="T1078 requires observed successful account utilization."
            )

    # --- T1033 System Owner / User Discovery ---
    if t_id_clean == "T1033":
        user_disc_cmds = ["whoami", "id", "cat /etc/passwd", "last", "logname", "users", "who", "net user"]
        has_disc = any(cmd in payload_lower for cmd in user_disc_cmds)
        if has_disc:
            matched_cmd = next(cmd for cmd in user_disc_cmds if cmd in payload_lower)
            return TechniqueVerificationResult(
                candidate_technique_id=t_id_clean,
                official_technique_name=cat_item.name,
                associated_tactics=cat_item.tactics,
                is_sub_technique=is_sub,
                parent_technique_id=parent_id,
                supporting_event_ids=event_ids,
                observed_behavior="User Identity Enumeration",
                supporting_evidence={"matched_command": matched_cmd, "payload": payload_str},
                verification_status=VerificationStatus.SUPPORTED,
                observation_type=ObservationType.DIRECT_OBSERVATION,
                mapping_rationale=f"Observed direct command execution querying user account identity: '{matched_cmd}'.",
                missing_evidence=[],
                alternative_explanations=["Standard administrative session setup or shell prompt verification."],
                limitations="Decoy shell captured command string; does not verify command output fidelity."
            )
        else:
            return TechniqueVerificationResult(
                candidate_technique_id=t_id_clean,
                official_technique_name=cat_item.name,
                associated_tactics=cat_item.tactics,
                is_sub_technique=is_sub,
                parent_technique_id=parent_id,
                supporting_event_ids=event_ids,
                observed_behavior=event_type,
                supporting_evidence={"payload": payload_str[:100] if payload_str else None},
                verification_status=VerificationStatus.REJECTED,
                observation_type=ObservationType.INFERRED_BEHAVIOR,
                mapping_rationale="Payload lacks commands querying user identity or account configuration.",
                missing_evidence=["Execution of user enumeration utilities: whoami, id, cat /etc/passwd."],
                alternative_explanations=["Non-identity command execution."],
                limitations="T1033 requires concrete user discovery commands."
            )

    # --- T1082 System Information Discovery ---
    if t_id_clean == "T1082":
        sys_cmds = ["uname", "hostname", "systeminfo", "lscpu", "cat /etc/os-release", "cat /proc/cpuinfo"]
        has_sys = any(cmd in payload_lower for cmd in sys_cmds)
        if has_sys:
            matched_cmd = next(cmd for cmd in sys_cmds if cmd in payload_lower)
            return TechniqueVerificationResult(
                candidate_technique_id=t_id_clean,
                official_technique_name=cat_item.name,
                associated_tactics=cat_item.tactics,
                is_sub_technique=is_sub,
                parent_technique_id=parent_id,
                supporting_event_ids=event_ids,
                observed_behavior="System Architecture Enumeration",
                supporting_evidence={"matched_command": matched_cmd, "payload": payload_str},
                verification_status=VerificationStatus.SUPPORTED,
                observation_type=ObservationType.DIRECT_OBSERVATION,
                mapping_rationale=f"Observed command execution querying host hardware and kernel details: '{matched_cmd}'.",
                missing_evidence=[],
                alternative_explanations=["Automated environment check in login profile script."],
                limitations="Decoy shell captured host query string; does not prove successful kernel compromise."
            )
        else:
            return TechniqueVerificationResult(
                candidate_technique_id=t_id_clean,
                official_technique_name=cat_item.name,
                associated_tactics=cat_item.tactics,
                is_sub_technique=is_sub,
                parent_technique_id=parent_id,
                supporting_event_ids=event_ids,
                observed_behavior=event_type,
                supporting_evidence={"payload": payload_str[:100] if payload_str else None},
                verification_status=VerificationStatus.REJECTED,
                observation_type=ObservationType.INFERRED_BEHAVIOR,
                mapping_rationale="Payload lacks commands querying operating system or hardware architecture.",
                missing_evidence=["Host enumeration commands: uname, hostname, /etc/os-release."],
                alternative_explanations=["Unrelated shell commands."],
                limitations="T1082 requires observable system discovery commands."
            )

    # --- T1105 Ingress Tool Transfer ---
    if t_id_clean == "T1105":
        transfer_tools = ["curl", "wget", "tftp", "ftpget", "certutil", "bitsadmin"]
        has_tool = any(tool in payload_lower for tool in transfer_tools)
        if has_tool:
            matched_tool = next(tool for tool in transfer_tools if tool in payload_lower)
            return TechniqueVerificationResult(
                candidate_technique_id=t_id_clean,
                official_technique_name=cat_item.name,
                associated_tactics=cat_item.tactics,
                is_sub_technique=is_sub,
                parent_technique_id=parent_id,
                supporting_event_ids=event_ids,
                observed_behavior="External Artifact Retrieval Attempt",
                supporting_evidence={"matched_utility": matched_tool, "payload": payload_str},
                verification_status=VerificationStatus.SUPPORTED,
                observation_type=ObservationType.DIRECT_OBSERVATION,
                mapping_rationale=f"Observed transfer utility '{matched_tool}' attempting to download external payload.",
                missing_evidence=[],
                alternative_explanations=["Administrative package download or configuration script fetch."],
                limitations="Decoy egress containment blocks outbound download; payload execution cannot be verified."
            )
        else:
            return TechniqueVerificationResult(
                candidate_technique_id=t_id_clean,
                official_technique_name=cat_item.name,
                associated_tactics=cat_item.tactics,
                is_sub_technique=is_sub,
                parent_technique_id=parent_id,
                supporting_event_ids=event_ids,
                observed_behavior=event_type,
                supporting_evidence={"payload": payload_str[:100] if payload_str else None},
                verification_status=VerificationStatus.REJECTED,
                observation_type=ObservationType.INFERRED_BEHAVIOR,
                mapping_rationale="Payload lacks external file transfer utilities or download syntax.",
                missing_evidence=["Transfer utility invocation: curl, wget, tftp, ftp, certutil."],
                alternative_explanations=["Normal terminal operations."],
                limitations="T1105 requires observed ingress tool transfer commands."
            )

    # --- T1053.003 Scheduled Task/Job: Cron ---
    if t_id_clean == "T1053.003":
        cron_indicators = ["crontab", "/etc/cron", "systemctl enable"]
        has_cron = any(ind in payload_lower for ind in cron_indicators)
        if has_cron:
            matched_ind = next(ind for ind in cron_indicators if ind in payload_lower)
            return TechniqueVerificationResult(
                candidate_technique_id=t_id_clean,
                official_technique_name=cat_item.name,
                associated_tactics=cat_item.tactics,
                is_sub_technique=is_sub,
                parent_technique_id=parent_id,
                supporting_event_ids=event_ids,
                observed_behavior="Recurring Job Schedule Manipulation",
                supporting_evidence={"matched_indicator": matched_ind, "payload": payload_str},
                verification_status=VerificationStatus.SUPPORTED,
                observation_type=ObservationType.DIRECT_OBSERVATION,
                mapping_rationale=f"Observed inspection or modification of recurring cron schedules: '{matched_ind}'.",
                missing_evidence=[],
                alternative_explanations=["Routine sysadmin crontab inspection or maintenance job."],
                limitations="Decoy shell captured crontab manipulation; persistence survival depends on filesystem state."
            )
        else:
            return TechniqueVerificationResult(
                candidate_technique_id=t_id_clean,
                official_technique_name=cat_item.name,
                associated_tactics=cat_item.tactics,
                is_sub_technique=is_sub,
                parent_technique_id=parent_id,
                supporting_event_ids=event_ids,
                observed_behavior=event_type,
                supporting_evidence={"payload": payload_str[:100] if payload_str else None},
                verification_status=VerificationStatus.REJECTED,
                observation_type=ObservationType.INFERRED_BEHAVIOR,
                mapping_rationale="Payload lacks cron or scheduled task modification commands.",
                missing_evidence=["Crontab commands or /etc/cron directory manipulation."],
                alternative_explanations=["Non-persistence commands."],
                limitations="T1053.003 requires cron configuration evidence."
            )

    # --- T1070.004 Indicator Removal: File Deletion ---
    if t_id_clean == "T1070.004":
        removal_indicators = ["history -c", "rm -rf", "unset histfile", "truncate -s 0", "shred "]
        has_removal = any(ind in payload_lower for ind in removal_indicators)
        if has_removal:
            matched_ind = next(ind for ind in removal_indicators if ind in payload_lower)
            return TechniqueVerificationResult(
                candidate_technique_id=t_id_clean,
                official_technique_name=cat_item.name,
                associated_tactics=cat_item.tactics,
                is_sub_technique=is_sub,
                parent_technique_id=parent_id,
                supporting_event_ids=event_ids,
                observed_behavior="Defense Evasion Artifact Erasure",
                supporting_evidence={"matched_indicator": matched_ind, "payload": payload_str},
                verification_status=VerificationStatus.SUPPORTED,
                observation_type=ObservationType.DIRECT_OBSERVATION,
                mapping_rationale=f"Observed defense evasion command purging traces or logs: '{matched_ind}'.",
                missing_evidence=[],
                alternative_explanations=["Automated session cleanup script or directory purge."],
                limitations="Centralized sensor streaming preserves logs off-host despite local deletion attempt."
            )
        else:
            return TechniqueVerificationResult(
                candidate_technique_id=t_id_clean,
                official_technique_name=cat_item.name,
                associated_tactics=cat_item.tactics,
                is_sub_technique=is_sub,
                parent_technique_id=parent_id,
                supporting_event_ids=event_ids,
                observed_behavior=event_type,
                supporting_evidence={"payload": payload_str[:100] if payload_str else None},
                verification_status=VerificationStatus.REJECTED,
                observation_type=ObservationType.INFERRED_BEHAVIOR,
                mapping_rationale="Payload lacks defense evasion or artifact removal commands.",
                missing_evidence=["History purging or recursive file deletion commands."],
                alternative_explanations=["Non-evasion commands."],
                limitations="T1070.004 requires trace deletion evidence."
            )

    # --- T1046 Network Service Discovery ---
    if t_id_clean == "T1046":
        is_scan = "scan" in event_type_lower or "port_scan" in event_type_lower or any(k in payload_lower for k in ["nmap", "masscan", "zmap", "ifconfig", "ip addr", "netstat"])
        if is_scan:
            return TechniqueVerificationResult(
                candidate_technique_id=t_id_clean,
                official_technique_name=cat_item.name,
                associated_tactics=cat_item.tactics,
                is_sub_technique=is_sub,
                parent_technique_id=parent_id,
                supporting_event_ids=event_ids,
                observed_behavior="Network Service Discovery",
                supporting_evidence={"event_type": event_type, "payload": payload_str[:100] if payload_str else None},
                verification_status=VerificationStatus.SUPPORTED,
                observation_type=ObservationType.DIRECT_OBSERVATION,
                mapping_rationale="Observed port scan or network service enumeration against honeynet listener.",
                missing_evidence=[],
                alternative_explanations=["External internet measurement research scanner (e.g. Shadowserver, Censys)."],
                limitations="Telemetry reflects decoys exposed interfaces; cannot assess internal lateral scan depth."
            )
        else:
            return TechniqueVerificationResult(
                candidate_technique_id=t_id_clean,
                official_technique_name=cat_item.name,
                associated_tactics=cat_item.tactics,
                is_sub_technique=is_sub,
                parent_technique_id=parent_id,
                supporting_event_ids=event_ids,
                observed_behavior=event_type,
                supporting_evidence={"payload": payload_str[:100] if payload_str else None},
                verification_status=VerificationStatus.NEEDS_MORE_EVIDENCE,
                observation_type=ObservationType.INFERRED_BEHAVIOR,
                mapping_rationale="Observed traffic lacks multi-port scanning or service probe signatures.",
                missing_evidence=["Multi-port sweep or explicit scanning utility payload."],
                alternative_explanations=["Single-port application connection attempt."],
                limitations="Isolated network packets do not confirm systematic network service discovery."
            )

    # --- T1018 Remote System Discovery ---
    if t_id_clean == "T1018":
        remote_cmds = ["arp -a", "ping ", "net view", "ip neigh"]
        has_remote = any(cmd in payload_lower for cmd in remote_cmds)
        if has_remote:
            matched_cmd = next(cmd for cmd in remote_cmds if cmd in payload_lower)
            return TechniqueVerificationResult(
                candidate_technique_id=t_id_clean,
                official_technique_name=cat_item.name,
                associated_tactics=cat_item.tactics,
                is_sub_technique=is_sub,
                parent_technique_id=parent_id,
                supporting_event_ids=event_ids,
                observed_behavior="Remote Network Host Enumeration",
                supporting_evidence={"matched_command": matched_cmd, "payload": payload_str},
                verification_status=VerificationStatus.SUPPORTED,
                observation_type=ObservationType.DIRECT_OBSERVATION,
                mapping_rationale=f"Observed network discovery querying adjacent hosts or neighbors: '{matched_cmd}'.",
                missing_evidence=[],
                alternative_explanations=["Diagnostic network connectivity test."],
                limitations="Decoy network isolation prevents actual remote host discovery output."
            )
        else:
            return TechniqueVerificationResult(
                candidate_technique_id=t_id_clean,
                official_technique_name=cat_item.name,
                associated_tactics=cat_item.tactics,
                is_sub_technique=is_sub,
                parent_technique_id=parent_id,
                supporting_event_ids=event_ids,
                observed_behavior=event_type,
                supporting_evidence={"payload": payload_str[:100] if payload_str else None},
                verification_status=VerificationStatus.REJECTED,
                observation_type=ObservationType.INFERRED_BEHAVIOR,
                mapping_rationale="Payload lacks remote host enumeration commands (arp, ping, ip neigh).",
                missing_evidence=["Remote host discovery commands."],
                alternative_explanations=["Unrelated shell commands."],
                limitations="T1018 requires remote neighbor queries."
            )

    # --- T1190 Exploit Public-Facing Application ---
    if t_id_clean == "T1190":
        exploit_indicators = ["' or '1'='1", "union select", "../", "..\\", "${jndi:", "cve-", "/etc/passwd"]
        has_exploit = any(ind in payload_lower for ind in exploit_indicators)
        if has_exploit:
            matched_exp = next(ind for ind in exploit_indicators if ind in payload_lower)
            return TechniqueVerificationResult(
                candidate_technique_id=t_id_clean,
                official_technique_name=cat_item.name,
                associated_tactics=cat_item.tactics,
                is_sub_technique=is_sub,
                parent_technique_id=parent_id,
                supporting_event_ids=event_ids,
                observed_behavior="Application Exploit Payload Attempt",
                supporting_evidence={"matched_pattern": matched_exp, "payload": payload_str},
                verification_status=VerificationStatus.SUPPORTED,
                observation_type=ObservationType.DIRECT_OBSERVATION,
                mapping_rationale=f"Inbound application payload exhibited concrete exploit signature: '{matched_exp}'.",
                missing_evidence=[],
                alternative_explanations=["Automated vulnerability scanning or web application security assessment."],
                limitations="Decoy captures malicious request string; does not indicate successful code execution in honeypot."
            )
        else:
            return TechniqueVerificationResult(
                candidate_technique_id=t_id_clean,
                official_technique_name=cat_item.name,
                associated_tactics=cat_item.tactics,
                is_sub_technique=is_sub,
                parent_technique_id=parent_id,
                supporting_event_ids=event_ids,
                observed_behavior=event_type,
                supporting_evidence={"payload": payload_str[:100] if payload_str else None},
                verification_status=VerificationStatus.REJECTED,
                observation_type=ObservationType.INFERRED_BEHAVIOR,
                mapping_rationale="Payload lacks exploit syntax, CVE signatures, or path traversal expressions.",
                missing_evidence=["Concrete exploit payload signatures (SQLi, JNDI, path traversal)."],
                alternative_explanations=["Generic network connection probe."],
                limitations="T1190 strictly requires observed exploit syntax."
            )

    # --- Default Fallback for other valid catalog techniques ---
    return TechniqueVerificationResult(
        candidate_technique_id=t_id_clean,
        official_technique_name=cat_item.name,
        associated_tactics=cat_item.tactics,
        is_sub_technique=is_sub,
        parent_technique_id=parent_id,
        supporting_event_ids=event_ids,
        observed_behavior=event_type,
        supporting_evidence={"payload": payload_str[:100] if payload_str else None},
        verification_status=VerificationStatus.NEEDS_MORE_EVIDENCE,
        observation_type=ObservationType.INFERRED_BEHAVIOR,
        mapping_rationale=f"Candidate technique {t_id_clean} ({cat_item.name}) requires specific telemetry evidence: {cat_item.applicable_event_evidence}.",
        missing_evidence=[f"Telemetry fulfilling: {cat_item.applicable_event_evidence}"],
        alternative_explanations=["Uncorrelated event activity."],
        limitations="Evidence does not meet documented threshold for confirmed mapping."
    )
