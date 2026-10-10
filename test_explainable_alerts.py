import os
import sys
import json
import time
import uuid
import unittest
import urllib.request
import urllib.error
import sqlite3

BASE_URL = "http://127.0.0.1:8000"
DB_PATH = "honeynet.db"

def api_get(endpoint: str):
    url = f"{BASE_URL}{endpoint}"
    req = urllib.request.Request(url, headers={"User-Agent": "AlertTester/1.0"})
    with urllib.request.urlopen(req) as resp:
        return resp.status, json.loads(resp.read().decode())

def api_post(endpoint: str, data: dict = None):
    url = f"{BASE_URL}{endpoint}"
    body = json.dumps(data or {}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json", "User-Agent": "AlertTester/1.0"}, method="POST")
    with urllib.request.urlopen(req) as resp:
        return resp.status, json.loads(resp.read().decode())

def api_patch(endpoint: str, data: dict):
    url = f"{BASE_URL}{endpoint}"
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json", "User-Agent": "AlertTester/1.0"}, method="PATCH")
    with urllib.request.urlopen(req) as resp:
        return resp.status, json.loads(resp.read().decode())

class TestExplainableSecurityAlerts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Verify server health
        status, health = api_get("/api/health")
        assert status == 200, "Backend must be healthy"

    def test_01_synthetic_event_sequence_triggers_expected_rules(self):
        """1. A known synthetic event sequence triggers the expected rule."""
        tag = int(time.time())
        # Sequence A: 3 auth failures -> ALERT_RULE_AUTH_BRUTE_FORCE
        ip_brute = f"198.51.100.{tag % 200 + 10}"
        events_brute = [
            {
                "event_id": f"syn-fail-1-{tag}",
                "source_ip": ip_brute,
                "event_type": "auth_failure",
                "username": "root",
                "payload": "Failed password for root",
                "destination_port": 22,
                "data_origin": "synthetic",
                "severity": "medium"
            },
            {
                "event_id": f"syn-fail-2-{tag}",
                "source_ip": ip_brute,
                "event_type": "auth_failure",
                "username": "admin",
                "payload": "Failed password for admin",
                "destination_port": 22,
                "data_origin": "synthetic",
                "severity": "medium"
            },
            {
                "event_id": f"syn-fail-3-{tag}",
                "source_ip": ip_brute,
                "event_type": "auth_failure",
                "username": "support",
                "payload": "Failed password for support",
                "destination_port": 22,
                "data_origin": "synthetic",
                "severity": "medium"
            }
        ]
        api_post("/api/events/bulk", {"events": events_brute})

        # Sequence B: Failures followed by successful login -> ALERT_RULE_AUTH_BREACH
        ip_breach = f"198.51.100.{(tag + 1) % 200 + 10}"
        sess_breach = f"syn-breach-sess-{tag}"
        events_breach = [
            {
                "event_id": f"syn-breach-f1-{tag}",
                "session_id": sess_breach,
                "source_ip": ip_breach,
                "event_type": "auth_failure",
                "username": "ubuntu",
                "payload": "Failed password for ubuntu",
                "destination_port": 22,
                "data_origin": "synthetic",
                "severity": "medium"
            },
            {
                "event_id": f"syn-breach-succ-{tag}",
                "session_id": sess_breach,
                "source_ip": ip_breach,
                "event_type": "auth_success",
                "username": "ubuntu",
                "payload": "Accepted password for ubuntu",
                "destination_port": 22,
                "data_origin": "synthetic",
                "severity": "high"
            }
        ]
        api_post("/api/events/bulk", {"events": events_breach})

        # Run correlation and alert detection
        api_post("/api/correlation/run")
        status, detect_res = api_post("/api/alerts/detect")
        self.assertEqual(status, 200)

        # Verify ALERT_RULE_AUTH_BRUTE_FORCE was generated for ip_brute
        _, alerts_brute = api_get(f"/api/alerts?source_ip={ip_brute}")
        rule_brute_matches = [a for a in alerts_brute if a.get("detection_rule_id") == "ALERT_RULE_AUTH_BRUTE_FORCE"]
        self.assertTrue(len(rule_brute_matches) >= 1, "Expected ALERT_RULE_AUTH_BRUTE_FORCE for 3 consecutive failures")

        # Verify ALERT_RULE_AUTH_BREACH was generated for ip_breach
        _, alerts_breach = api_get(f"/api/alerts?source_ip={ip_breach}")
        rule_breach_matches = [a for a in alerts_breach if a.get("detection_rule_id") == "ALERT_RULE_AUTH_BREACH"]
        self.assertTrue(len(rule_breach_matches) >= 1, "Expected ALERT_RULE_AUTH_BREACH for failure followed by success")
        self.assertEqual(rule_breach_matches[0]["severity"], "critical")

    def test_02_unrelated_event_does_not_trigger_rule(self):
        """2. An unrelated event does not trigger that rule (isolated failed login != brute force)."""
        tag = int(time.time()) + 1000
        isolated_ip = f"192.0.2.{tag % 200 + 10}"
        
        # Single isolated failed login (below threshold of 3)
        api_post("/api/events", {
            "event_id": f"syn-isolated-fail-{tag}",
            "source_ip": isolated_ip,
            "event_type": "auth_failure",
            "username": "testuser",
            "payload": "Failed password for testuser",
            "destination_port": 22,
            "data_origin": "synthetic",
            "severity": "low"
        })

        # Run alert detection
        api_post("/api/alerts/detect")

        # Verify NO brute force alert is generated for isolated failure
        _, alerts = api_get(f"/api/alerts?source_ip={isolated_ip}")
        brute_force_alerts = [a for a in alerts if a.get("detection_rule_id") == "ALERT_RULE_AUTH_BRUTE_FORCE"]
        self.assertEqual(len(brute_force_alerts), 0, "Isolated single failed login must NOT trigger ALERT_RULE_AUTH_BRUTE_FORCE")

    def test_03_alert_evidence_references_existing_event_ids(self):
        """3. Alert evidence references existing event IDs."""
        status, alerts = api_get("/api/alerts?limit=20")
        self.assertEqual(status, 200)

        # Check in database that referenced event IDs genuinely exist
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        explainable_alerts = [a for a in alerts if a.get("detection_rule_id") and a.get("related_event_ids")]
        self.assertTrue(len(explainable_alerts) > 0, "Should have explainable alerts with related_event_ids")

        for alert in explainable_alerts[:5]:
            for ev_id in alert["related_event_ids"]:
                cursor.execute("SELECT id FROM telemetry_events WHERE event_id = ?", (ev_id,))
                row = cursor.fetchone()
                self.assertIsNotNone(row, f"Referenced event ID {ev_id} must exist in telemetry_events database table")
        conn.close()

    def test_04_technique_mappings_are_evidence_backed(self):
        """4. Technique mappings are evidence-backed."""
        status, alerts = api_get("/api/alerts?limit=20")
        self.assertEqual(status, 200)

        for alert in alerts:
            if alert.get("detection_rule_id") == "ALERT_RULE_AUTH_BRUTE_FORCE":
                self.assertIn("T1110.001", alert.get("related_technique_ids", []))
            elif alert.get("detection_rule_id") == "ALERT_RULE_AUTH_BREACH":
                self.assertIn("T1078", alert.get("related_technique_ids", []))
            elif alert.get("detection_rule_id") == "ALERT_RULE_CRON_PERSISTENCE":
                self.assertIn("T1053.003", alert.get("related_technique_ids", []))
            elif alert.get("detection_rule_id") == "ALERT_RULE_INGRESS_TOOL_TRANSFER":
                self.assertIn("T1105", alert.get("related_technique_ids", []))

    def test_05_repeated_detection_does_not_create_duplicate_alerts(self):
        """5. Repeated detection does not create duplicate alerts."""
        # Initial run
        _, res1 = api_post("/api/alerts/detect")
        count_before = res1["total_active_alerts"]

        # Run immediately again
        _, res2 = api_post("/api/alerts/detect")
        self.assertEqual(res2["new_alerts_created"], 0, "Second detection pass should create 0 new alerts")
        self.assertEqual(res2["total_active_alerts"], count_before, "Active alerts count must remain unchanged")

    def test_06_alert_status_updates_persist(self):
        """6. Alert status updates persist."""
        _, alerts = api_get("/api/alerts?limit=1")
        self.assertTrue(len(alerts) > 0, "Need at least one alert to test update")
        target_alert = alerts[0]
        alert_id = target_alert["alert_id"]

        # Update to INVESTIGATING
        status_code, updated1 = api_patch(f"/api/alerts/{alert_id}", {"status": "INVESTIGATING"})
        self.assertEqual(status_code, 200)
        self.assertEqual(updated1["status"], "INVESTIGATING")
        self.assertFalse(updated1["is_resolved"])

        # Fetch independently
        _, fetched1 = api_get(f"/api/alerts/{alert_id}")
        self.assertEqual(fetched1["status"], "INVESTIGATING")

        # Update to RESOLVED
        status_code, updated2 = api_patch(f"/api/alerts/{alert_id}", {"status": "RESOLVED"})
        self.assertEqual(status_code, 200)
        self.assertEqual(updated2["status"], "RESOLVED")
        self.assertTrue(updated2["is_resolved"])

        # Fetch independently
        _, fetched2 = api_get(f"/api/alerts/{alert_id}")
        self.assertEqual(fetched2["status"], "RESOLVED")
        self.assertTrue(fetched2["is_resolved"])

    def test_07_severity_and_status_filters_work(self):
        """7. Severity and status filters work."""
        # Severity filter: critical
        status_code, crit_alerts = api_get("/api/alerts?severity=critical")
        self.assertEqual(status_code, 200)
        for a in crit_alerts:
            self.assertEqual(a["severity"].lower(), "critical")

        # Status filter: RESOLVED
        status_code, res_alerts = api_get("/api/alerts?status=RESOLVED")
        self.assertEqual(status_code, 200)
        for a in res_alerts:
            self.assertEqual(a["status"], "RESOLVED")

        # Status filter: NEW
        status_code, new_alerts = api_get("/api/alerts?status=NEW")
        self.assertEqual(status_code, 200)
        for a in new_alerts:
            self.assertEqual(a["status"], "NEW")

    def test_08_alert_details_return_correct_evidence(self):
        """8. Alert details return correct evidence."""
        _, alerts = api_get("/api/alerts?limit=10")
        explainable = next((a for a in alerts if a.get("explanation")), None)
        self.assertIsNotNone(explainable, "Should find at least one alert with an explanation")

        status_code, detail = api_get(f"/api/alerts/{explainable['alert_id']}")
        self.assertEqual(status_code, 200)
        self.assertIn("Observed Evidence", detail["explanation"])
        self.assertIn("Rule Matched", detail["explanation"])
        self.assertIsNotNone(detail["severity_rationale"])
        self.assertIsInstance(detail["supporting_evidence"], dict)

    def test_09_dashboard_metrics_match_database_records(self):
        """9. Dashboard metrics match database records."""
        status_code, metrics = api_get("/api/alerts/metrics")
        self.assertEqual(status_code, 200)

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM alerts")
        db_total = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM alerts WHERE status = 'NEW'")
        db_new = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM alerts WHERE status = 'RESOLVED' OR is_resolved = 1")
        db_resolved = cursor.fetchone()[0]

        conn.close()

        self.assertEqual(metrics["total_alerts"], db_total)
        self.assertEqual(metrics["new_alerts"], db_new)
        self.assertEqual(metrics["resolved_alerts"], db_resolved)

    def test_10_api_validation_and_error_handling(self):
        """10. API request validation and error handling."""
        # Non-existent alert returns 404
        try:
            api_get("/api/alerts/non-existent-id-99999")
            self.fail("Expected 404 for non-existent alert")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 404)

        # Invalid status in PATCH returns 400
        try:
            _, alerts = api_get("/api/alerts?limit=1")
            api_patch(f"/api/alerts/{alerts[0]['alert_id']}", {"status": "INVALID_STATUS"})
            self.fail("Expected 400 for invalid alert status")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 400)

    def test_11_existing_regressions_still_pass(self):
        """11. Existing ingestion, correlation, MITRE mapping, and graph endpoints still function."""
        # Ingestion
        s, ev = api_get("/api/events?limit=5")
        self.assertEqual(s, 200)

        # Sessions
        s, sess = api_get("/api/sessions?limit=5")
        self.assertEqual(s, 200)

        # MITRE Catalog & Matrix
        s, techs = api_get("/api/techniques?limit=5")
        self.assertEqual(s, 200)

        # Graph
        s, graph = api_get("/api/graph?limit=5")
        self.assertEqual(s, 200)
        self.assertIn("nodes", graph)
        self.assertIn("edges", graph)

if __name__ == "__main__":
    unittest.main()
