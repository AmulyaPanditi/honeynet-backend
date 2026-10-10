"""
Event Analysis Service
Project: Autonomous Honeynet Telemetry & Threat Actor MITRE ATT&CK Causal Graph Profiler.

Provides evidence-based, deterministic, explainable behavioral analysis of incoming
telemetry events without creating duplicate database records or alerts.

Supports explicit behavioral categories:
- AUTH_FAILURE
- AUTH_SUCCESS
- USER_DISCOVERY
- SYSTEM_INFO_DISCOVERY
- NETWORK_DISCOVERY
- FILE_RETRIEVAL_TRANSFER
- PERSISTENCE_MECHANISM
- INDICATOR_REMOVAL
- UNCLASSIFIED
"""

import re
from enum import Enum
from typing import Optional, List, Dict, Any, Union
from pydantic import BaseModel, Field, ConfigDict

from backend.app.models.telemetry import TelemetryEventDB, TelemetryEventCreate
from backend.app.services.mitre_catalog import load_mitre_catalog

class BehaviorCategory(str, Enum):
    AUTH_FAILURE = "AUTH_FAILURE"
    AUTH_SUCCESS = "AUTH_SUCCESS"
    USER_DISCOVERY = "USER_DISCOVERY"
    SYSTEM_INFO_DISCOVERY = "SYSTEM_INFO_DISCOVERY"
    NETWORK_DISCOVERY = "NETWORK_DISCOVERY"
    FILE_RETRIEVAL_TRANSFER = "FILE_RETRIEVAL_TRANSFER"
    PERSISTENCE_MECHANISM = "PERSISTENCE_MECHANISM"
    INDICATOR_REMOVAL = "INDICATOR_REMOVAL"
    UNCLASSIFIED = "UNCLASSIFIED"

# Deterministic Rule Identifiers
RULE_BEHAVIOR_AUTH_FAILURE = "RULE_BEHAVIOR_AUTH_FAILURE"
RULE_BEHAVIOR_AUTH_SUCCESS = "RULE_BEHAVIOR_AUTH_SUCCESS"
RULE_BEHAVIOR_USER_DISCOVERY = "RULE_BEHAVIOR_USER_DISCOVERY"
RULE_BEHAVIOR_SYSINFO_DISCOVERY = "RULE_BEHAVIOR_SYSINFO_DISCOVERY"
RULE_BEHAVIOR_NETWORK_DISCOVERY = "RULE_BEHAVIOR_NETWORK_DISCOVERY"
RULE_BEHAVIOR_FILE_RETRIEVAL = "RULE_BEHAVIOR_FILE_RETRIEVAL"
RULE_BEHAVIOR_PERSISTENCE = "RULE_BEHAVIOR_PERSISTENCE"
RULE_BEHAVIOR_INDICATOR_REMOVAL = "RULE_BEHAVIOR_INDICATOR_REMOVAL"
RULE_BEHAVIOR_UNCLASSIFIED = "RULE_BEHAVIOR_UNCLASSIFIED"

# Structured Explainable Output Schema
class EventAnalysisResult(BaseModel):
    event_id: Optional[str] = Field(None, description="Unique event identifier from telemetry record")
    observed_event_type: str = Field(..., description="Observed event type from telemetry")
    observed_behavior_category: BehaviorCategory = Field(..., description="Categorized behavioral classification")
    matched_rule_id: str = Field(..., description="Deterministic rule identifier used for matching")
    concise_explanation: str = Field(..., description="Clear explanation of why this classification was made")
    supporting_evidence: Dict[str, Any] = Field(default_factory=dict, description="Extracted telemetry attributes supporting this classification")
    candidate_mitre_technique_ids: List[str] = Field(default_factory=list, description="Candidate MITRE ATT&CK technique IDs verified in catalog")
    mapping_limitations: str = Field(..., description="Investigation caveats and limitations of the observation")
    data_origin: str = Field("real", description="Origin of telemetry: 'real' or 'synthetic'")
    source_ip: Optional[str] = Field(None, description="Preserved observer or attacker source IP")
    honeypot_id: Optional[str] = Field(None, description="Preserved sensor or honeypot identifier")

    model_config = ConfigDict(use_enum_values=True)

# Bounded, deterministic regex rules for untrusted payload extraction
# Avoid broad substring matching (e.g., 'curling_iron', 'secure_login', 'whoamiman', 'uname_test')
# Never evaluate or execute payloads in any shell
_REGEX_USER_DISCOVERY = re.compile(
    r'(?:^|[;&|\s`$()/])(?:whoami|logname|users|who|last)(?:\s+-[a-zA-Z]+|\s+[a-zA-Z0-9_.-]+|\s*$)|'
    r'\b(?:^|[;&|\s`$()/])id(?:\s+-[a-zA-Z]+|\s+[a-zA-Z0-9_.-]+|\s*$)|'
    r'\bcat\s+(?:[^\s|;&]*/)?etc/passwd\b|'
    r'\b(?:net\s+user|query\s+user)\b',
    re.IGNORECASE
)

_REGEX_SYSINFO_DISCOVERY = re.compile(
    r'(?:^|[;&|\s`$()/])(?:uname|hostname|systeminfo|lscpu)\b|'
    r'\bcat\s+(?:[^\s|;&]*/)?(?:etc/os-release|proc/cpuinfo|proc/version|etc/issue)\b',
    re.IGNORECASE
)

_REGEX_NETWORK_DISCOVERY = re.compile(
    r'(?:^|[;&|\s`$()/])(?:ifconfig|netstat|route|arp)\b|'
    r'\bip\s+(?:addr|a|route|link|neigh)\b|'
    r'\bping\s+-[a-zA-Z0-9]+|'
    r'\b(?:nmap|masscan|zmap)\b',
    re.IGNORECASE
)

_REGEX_FILE_RETRIEVAL = re.compile(
    r'(?:^|[;&|\s`$()/])(?:curl|wget|tftp|ftpget)\b|'
    r'\b(?:certutil\s+-urlcache|bitsadmin\s+/transfer)\b',
    re.IGNORECASE
)

_REGEX_PERSISTENCE = re.compile(
    r'(?:^|[;&|\s`$()/])crontab\b|'
    r'/etc/cron(?:\.(?:d|daily|hourly|weekly|monthly)|tab)\b|'
    r'\bsystemctl\s+enable\b',
    re.IGNORECASE
)

_REGEX_INDICATOR_REMOVAL = re.compile(
    r'\bhistory\s+-c\b|'
    r'\brm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r|--recursive|\s+-rf)\b|'
    r'\bunset\s+histfile\b|'
    r'\bexport\s+histfile=/dev/null\b|'
    r'\btruncate\s+-s\s*0\b|'
    r'\bshred\b',
    re.IGNORECASE
)

_REGEX_AUTH_SUCCESS_PAYLOAD = re.compile(
    r'\b(?:accepted\s+password|successful\s+login|login\s+successful|authentication\s+succeeded|auth\s+success)\b',
    re.IGNORECASE
)

_REGEX_AUTH_FAILURE_PAYLOAD = re.compile(
    r'\b(?:fail|failed|failure|invalid|incorrect|denied|rejected|bad\s+password|wrong\s+password)\b',
    re.IGNORECASE
)

def _normalize_event_input(event: Union[TelemetryEventDB, TelemetryEventCreate, Dict[str, Any], Any]) -> Dict[str, Any]:
    """
    Safely normalizes input event from SQLAlchemy models, Pydantic schemas, or dictionaries.
    Treats all fields as untrusted and avoids arbitrary code execution.
    """
    if isinstance(event, dict):
        event_id = event.get("event_id")
        event_type = str(event.get("event_type") or "unknown").strip()
        raw_payload = event.get("payload") or event.get("raw_details")
        username = event.get("username")
        data_origin = event.get("data_origin") or "real"
        source_ip = event.get("source_ip")
        honeypot_id = event.get("honeypot_id")
        destination_port = event.get("destination_port")
        honeypot_type = event.get("honeypot_type")
    else:
        event_id = getattr(event, "event_id", None)
        event_type = str(getattr(event, "event_type", "unknown") or "unknown").strip()
        raw_payload = getattr(event, "payload", None) or getattr(event, "raw_details", None)
        username = getattr(event, "username", None)
        data_origin = getattr(event, "data_origin", "real") or "real"
        source_ip = getattr(event, "source_ip", None)
        honeypot_id = getattr(event, "honeypot_id", None)
        destination_port = getattr(event, "destination_port", None)
        honeypot_type = getattr(event, "honeypot_type", None)

    # Safely convert payload to string if present, handle malformed or non-string inputs
    if raw_payload is None:
        payload_str = ""
    elif isinstance(raw_payload, str):
        payload_str = raw_payload.strip()
    else:
        payload_str = str(raw_payload).strip()

    origin_norm = "synthetic" if str(data_origin).lower() == "synthetic" else "real"

    return {
        "event_id": str(event_id) if event_id is not None else None,
        "event_type": event_type,
        "payload": payload_str,
        "username": str(username) if username is not None else None,
        "data_origin": origin_norm,
        "source_ip": str(source_ip) if source_ip is not None else None,
        "honeypot_id": str(honeypot_id) if honeypot_id is not None else None,
        "destination_port": destination_port,
        "honeypot_type": str(honeypot_type) if honeypot_type is not None else None
    }

def _validate_techniques(candidates: List[str]) -> List[str]:
    """
    Validates candidate MITRE ATT&CK technique IDs against the authoritative catalog.
    Only returns technique IDs actively defined in the catalog.
    """
    try:
        catalog = load_mitre_catalog()
        return [tid for tid in candidates if tid in catalog]
    except Exception:
        # Fallback to empty list if catalog cannot be loaded to avoid fabricating techniques
        return []

def analyze_telemetry_event(
    event: Union[TelemetryEventDB, TelemetryEventCreate, Dict[str, Any], Any]
) -> EventAnalysisResult:
    """
    Interprets telemetry using explicit, explainable behavioral rules.
    - Deterministic matching rules.
    - Treats payload as untrusted text.
    - Validates candidate MITRE technique IDs against catalog.
    - Does NOT insert or modify any database records.
    - Does NOT emit duplicate alerts.
    """
    norm = _normalize_event_input(event)
    event_id = norm["event_id"]
    event_type = norm["event_type"]
    event_type_lower = event_type.lower()
    payload = norm["payload"]
    username = norm["username"]
    data_origin = norm["data_origin"]
    source_ip = norm["source_ip"]
    honeypot_id = norm["honeypot_id"]

    # 1. Evaluate Authentication Events
    is_auth_event = any(k in event_type_lower for k in ["auth", "login", "session_start"])

    if is_auth_event:
        # Check Authentication Success first
        if event_type_lower in ["auth_success", "login_success", "session_start"] or (
            payload and _REGEX_AUTH_SUCCESS_PAYLOAD.search(payload)
        ):
            target_user = username or "unknown"
            return EventAnalysisResult(
                event_id=event_id,
                observed_event_type=event_type,
                observed_behavior_category=BehaviorCategory.AUTH_SUCCESS,
                matched_rule_id=RULE_BEHAVIOR_AUTH_SUCCESS,
                concise_explanation=(
                    f"Observed successful authentication into decoy honeynet establishing session for account '{target_user}'."
                ),
                supporting_evidence={
                    "event_type": event_type,
                    "username": username,
                    "source_ip": source_ip,
                    "payload_snippet": payload[:100] if payload else None
                },
                candidate_mitre_technique_ids=_validate_techniques(["T1078"]),
                mapping_limitations=(
                    "Valid account observation verifies credential acceptance; account origin or compromise vector "
                    "cannot be determined without identity provider audit logs."
                ),
                data_origin=data_origin,
                source_ip=source_ip,
                honeypot_id=honeypot_id
            )

        # Check Authentication Failure
        if event_type_lower in ["auth_failure", "login_failed", "authentication_failure"] or (
            event_type_lower in ["auth_attempt", "login_attempt"] and (
                not payload or _REGEX_AUTH_FAILURE_PAYLOAD.search(payload) or not _REGEX_AUTH_SUCCESS_PAYLOAD.search(payload)
            )
        ):
            target_user = username or "unknown"
            return EventAnalysisResult(
                event_id=event_id,
                observed_event_type=event_type,
                observed_behavior_category=BehaviorCategory.AUTH_FAILURE,
                matched_rule_id=RULE_BEHAVIOR_AUTH_FAILURE,
                concise_explanation=(
                    f"Observed failed authentication attempt for account '{target_user}' against decoy listener."
                ),
                supporting_evidence={
                    "event_type": event_type,
                    "username": username,
                    "source_ip": source_ip,
                    "payload_snippet": payload[:100] if payload else None
                },
                candidate_mitre_technique_ids=_validate_techniques(["T1110.001"]),
                mapping_limitations=(
                    "Telemetry captures an isolated login failure. Without sequence analysis across multiple attempts "
                    "or session aggregation, cannot definitively confirm automated brute force (T1110.001)."
                ),
                data_origin=data_origin,
                source_ip=source_ip,
                honeypot_id=honeypot_id
            )

    # 2. Evaluate Command and Payload Evidence Safely
    # Only evaluate bounded patterns if payload is non-empty string
    if payload:
        # H. Indicator Removal
        m_ir = _REGEX_INDICATOR_REMOVAL.search(payload)
        if m_ir:
            matched_term = m_ir.group(0).strip()
            return EventAnalysisResult(
                event_id=event_id,
                observed_event_type=event_type,
                observed_behavior_category=BehaviorCategory.INDICATOR_REMOVAL,
                matched_rule_id=RULE_BEHAVIOR_INDICATOR_REMOVAL,
                concise_explanation=(
                    f"Observed defense evasion command attempting trace removal or log purging: '{matched_term}'."
                ),
                supporting_evidence={
                    "matched_pattern": matched_term,
                    "payload": payload,
                    "source_ip": source_ip
                },
                candidate_mitre_technique_ids=_validate_techniques(["T1070.004"]),
                mapping_limitations=(
                    "Captured command line in honeynet shell. Centralized telemetry streaming captures events "
                    "off-host, ensuring observation survives local trace deletion."
                ),
                data_origin=data_origin,
                source_ip=source_ip,
                honeypot_id=honeypot_id
            )

        # G. Persistence Mechanism
        m_pers = _REGEX_PERSISTENCE.search(payload)
        if m_pers:
            matched_term = m_pers.group(0).strip()
            return EventAnalysisResult(
                event_id=event_id,
                observed_event_type=event_type,
                observed_behavior_category=BehaviorCategory.PERSISTENCE_MECHANISM,
                matched_rule_id=RULE_BEHAVIOR_PERSISTENCE,
                concise_explanation=(
                    f"Observed scheduled task or cron persistence manipulation: '{matched_term}'."
                ),
                supporting_evidence={
                    "matched_pattern": matched_term,
                    "payload": payload,
                    "source_ip": source_ip
                },
                candidate_mitre_technique_ids=_validate_techniques(["T1053.003"]),
                mapping_limitations=(
                    "Captured command modifying scheduled jobs. Decoy persistence survival across restart depends "
                    "on virtualization and filesystem emulation state."
                ),
                data_origin=data_origin,
                source_ip=source_ip,
                honeypot_id=honeypot_id
            )

        # F. File Retrieval / Ingress Tool Transfer
        m_file = _REGEX_FILE_RETRIEVAL.search(payload)
        if m_file:
            matched_term = m_file.group(0).strip()
            return EventAnalysisResult(
                event_id=event_id,
                observed_event_type=event_type,
                observed_behavior_category=BehaviorCategory.FILE_RETRIEVAL_TRANSFER,
                matched_rule_id=RULE_BEHAVIOR_FILE_RETRIEVAL,
                concise_explanation=(
                    f"Observed external file retrieval utility invocation attempting tool download: '{matched_term}'."
                ),
                supporting_evidence={
                    "matched_tool": matched_term,
                    "payload": payload,
                    "source_ip": source_ip
                },
                candidate_mitre_technique_ids=_validate_techniques(["T1105"]),
                mapping_limitations=(
                    "Decoy captured transfer utility invocation. Network egress containment blocks external download; "
                    "payload staging cannot be completed without uncontained network routing."
                ),
                data_origin=data_origin,
                source_ip=source_ip,
                honeypot_id=honeypot_id
            )

        # D. System Information Discovery
        m_sys = _REGEX_SYSINFO_DISCOVERY.search(payload)
        if m_sys:
            matched_term = m_sys.group(0).strip()
            return EventAnalysisResult(
                event_id=event_id,
                observed_event_type=event_type,
                observed_behavior_category=BehaviorCategory.SYSTEM_INFO_DISCOVERY,
                matched_rule_id=RULE_BEHAVIOR_SYSINFO_DISCOVERY,
                concise_explanation=(
                    f"Observed host discovery command enumerating operating system or kernel specifications: '{matched_term}'."
                ),
                supporting_evidence={
                    "matched_command": matched_term,
                    "payload": payload,
                    "source_ip": source_ip
                },
                candidate_mitre_technique_ids=_validate_techniques(["T1082"]),
                mapping_limitations=(
                    "Decoy shell captured host enumeration command string. Does not verify OS command execution "
                    "success or decoy response fidelity."
                ),
                data_origin=data_origin,
                source_ip=source_ip,
                honeypot_id=honeypot_id
            )

        # C. User Discovery
        m_user = _REGEX_USER_DISCOVERY.search(payload)
        if m_user:
            matched_term = m_user.group(0).strip()
            return EventAnalysisResult(
                event_id=event_id,
                observed_event_type=event_type,
                observed_behavior_category=BehaviorCategory.USER_DISCOVERY,
                matched_rule_id=RULE_BEHAVIOR_USER_DISCOVERY,
                concise_explanation=(
                    f"Observed user discovery command querying active identity or account privileges: '{matched_term}'."
                ),
                supporting_evidence={
                    "matched_command": matched_term,
                    "payload": payload,
                    "source_ip": source_ip
                },
                candidate_mitre_technique_ids=_validate_techniques(["T1033"]),
                mapping_limitations=(
                    "Decoy shell captured user enumeration command string. Telemetry does not verify whether command output "
                    "satisfied adversary or if low-interaction decoy simulated user accounts."
                ),
                data_origin=data_origin,
                source_ip=source_ip,
                honeypot_id=honeypot_id
            )

        # E. Network Discovery via Payload
        m_net = _REGEX_NETWORK_DISCOVERY.search(payload)
        if m_net:
            matched_term = m_net.group(0).strip()
            # Determine if candidate technique is remote discovery (T1018) or service discovery (T1046)
            tech = "T1018" if any(k in matched_term.lower() for k in ["arp", "ping", "neigh"]) else "T1046"
            return EventAnalysisResult(
                event_id=event_id,
                observed_event_type=event_type,
                observed_behavior_category=BehaviorCategory.NETWORK_DISCOVERY,
                matched_rule_id=RULE_BEHAVIOR_NETWORK_DISCOVERY,
                concise_explanation=(
                    f"Observed network discovery command querying interfaces or network neighbors: '{matched_term}'."
                ),
                supporting_evidence={
                    "matched_command": matched_term,
                    "payload": payload,
                    "source_ip": source_ip
                },
                candidate_mitre_technique_ids=_validate_techniques([tech]),
                mapping_limitations=(
                    "Decoy listener observed network query. Internal subnet routing visibility is limited by honeynet topology."
                ),
                data_origin=data_origin,
                source_ip=source_ip,
                honeypot_id=honeypot_id
            )

    # 3. Evaluate Network Discovery via Event Type (e.g., Port Scan)
    if event_type_lower in ["port_scan", "network_scan", "syn_scan"]:
        return EventAnalysisResult(
            event_id=event_id,
            observed_event_type=event_type,
            observed_behavior_category=BehaviorCategory.NETWORK_DISCOVERY,
            matched_rule_id=RULE_BEHAVIOR_NETWORK_DISCOVERY,
            concise_explanation="Observed network service scanning or port probe against honeynet decoy listener.",
            supporting_evidence={
                "event_type": event_type,
                "source_ip": source_ip,
                "payload": payload or None
            },
            candidate_mitre_technique_ids=_validate_techniques(["T1046"]),
            mapping_limitations=(
                "Network scan observed on decoy ingress. Port scan breadth and probe velocity depend on sensor listener coverage."
            ),
            data_origin=data_origin,
            source_ip=source_ip,
            honeypot_id=honeypot_id
        )

    # 4. Unknown or Unclassified Activity
    # Crucial rule: Do not classify every unknown event as malicious. Never invent techniques.
    return EventAnalysisResult(
        event_id=event_id,
        observed_event_type=event_type,
        observed_behavior_category=BehaviorCategory.UNCLASSIFIED,
        matched_rule_id=RULE_BEHAVIOR_UNCLASSIFIED,
        concise_explanation=(
            "Observed event type and payload do not match defined behavioral heuristics or attack signatures."
        ),
        supporting_evidence={
            "event_type": event_type,
            "payload_snippet": payload[:100] if payload else None,
            "source_ip": source_ip
        },
        candidate_mitre_technique_ids=[],  # Strictly empty list; no invented techniques
        mapping_limitations=(
            "No deterministic behavior pattern identified; event retained as baseline telemetry without malicious attribution."
        ),
        data_origin=data_origin,
        source_ip=source_ip,
        honeypot_id=honeypot_id
    )

def analyze_events_batch(
    events: List[Union[TelemetryEventDB, TelemetryEventCreate, Dict[str, Any], Any]]
) -> List[EventAnalysisResult]:
    """
    Performs batch analysis across multiple telemetry records.
    Produces structured analysis results without inserting duplicate database records.
    """
    return [analyze_telemetry_event(e) for e in events]
