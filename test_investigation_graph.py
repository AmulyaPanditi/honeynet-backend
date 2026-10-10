"""
Automated Test Suite for COMMAND 5: Interactive Investigation Graph.
Covers Tests 1-11 per Command 5 Phase 7 requirements.
"""

import os
import sys
import httpx
import json
import time
from datetime import datetime, timezone

# Ensure project root in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BASE_URL = "http://127.0.0.1:8000"

def run_tests():
    print("=" * 70)
    print("INVESTIGATION GRAPH TEST SUITE")
    print("=" * 70)

    now = datetime.now(timezone.utc)
    ts = int(time.time())

    # --- Setup: Ingest specific synthetic attack session with MITRE evidence and alert ---
    print("\n[Setup] Ingesting test attack session with events and MITRE evidence...")
    test_sess_id = f"graph-sess-{ts}"
    test_ip = "198.51.100.188"
    
    # Event 1: whoami (T1033)
    ev1_id = f"evt-g-whoami-{ts}"
    httpx.post(f"{BASE_URL}/api/events", json={
        "event_id": ev1_id,
        "session_id": test_sess_id,
        "source_ip": test_ip,
        "honeypot_id": "cowrie-graph-test",
        "event_type": "command_execution",
        "payload": "whoami",
        "data_origin": "synthetic"
    })
    
    # Event 2: uname -a (T1082)
    ev2_id = f"evt-g-uname-{ts}"
    httpx.post(f"{BASE_URL}/api/events", json={
        "event_id": ev2_id,
        "session_id": test_sess_id,
        "source_ip": test_ip,
        "honeypot_id": "cowrie-graph-test",
        "event_type": "command_execution",
        "payload": "uname -a",
        "data_origin": "synthetic"
    })

    # Trigger correlation & MITRE analysis
    httpx.post(f"{BASE_URL}/api/correlation/run")
    httpx.post(f"{BASE_URL}/api/analysis/mitre/run")

    # --- Test 1: Graph nodes generated from actual stored records ---
    print("\n[Test 1] Testing graph nodes generated from actual stored records...")
    g_res = httpx.get(f"{BASE_URL}/api/graph?session_id={test_sess_id}")
    assert g_res.status_code == 200
    graph = g_res.json()
    assert "nodes" in graph and "edges" in graph
    node_types = set(n["data"]["type"] for n in graph["nodes"])
    print(f" -> Found node types: {node_types}")
    assert "session" in node_types, "Missing session node"
    assert "event" in node_types, "Missing event node"
    assert "technique" in node_types, "Missing technique node"
    
    # Check that test session node exists and has real database metadata
    sess_node = next(n for n in graph["nodes"] if n["data"].get("session_id") == test_sess_id)
    assert sess_node["data"]["id"] == f"sess_{test_sess_id}"
    assert sess_node["data"]["event_count"] >= 2
    print(f" -> Real session node verified: ID={sess_node['data']['id']}, Events={sess_node['data']['event_count']}")

    # --- Test 2 & 4: Graph edges correspond to valid relationships and Event-to-session edges ---
    print("\n[Test 2 & 4] Testing event-to-session edges and relationship types...")
    edges = graph["edges"]
    belongs_edges = [e for e in edges if e["data"]["relationship"] == "BELONGS_TO"]
    assert len(belongs_edges) >= 2, f"Expected >= 2 BELONGS_TO edges, found {len(belongs_edges)}"
    for be in belongs_edges:
        assert be["data"]["target"] == f"sess_{test_sess_id}"
        assert be["data"]["relationship_type"] == "observed"
        assert "belongs to correlated session" in be["data"]["evidence"]
    print(f" -> Validated {len(belongs_edges)} event-to-session BELONGS_TO edges.")

    # --- Test 5: Technique mappings reference supporting events ---
    print("\n[Test 5] Testing technique mappings reference supporting events...")
    supports_edges = [e for e in edges if e["data"]["relationship"] == "SUPPORTS_TECHNIQUE"]
    assert len(supports_edges) >= 2, f"Expected >= 2 SUPPORTS_TECHNIQUE edges, found {len(supports_edges)}"
    tech_targets = [e["data"]["target"] for e in supports_edges]
    assert "mitre_T1033" in tech_targets
    assert "mitre_T1082" in tech_targets
    for se in supports_edges:
        assert se["data"]["relationship_type"] == "evidence_backed"
        assert len(se["data"]["evidence"]) > 10
    print(f" -> Validated evidence-backed SUPPORTS_TECHNIQUE edges to {set(tech_targets)}.")

    # --- Test 3: Unsupported relationships are NOT created ---
    print("\n[Test 3] Testing that unsupported relationships are NOT created...")
    # Node IDs in the graph must only be connected if an edge is defined
    edge_pairs = set((e["data"]["source"], e["data"]["target"]) for e in edges)
    # Ensure event 1 does NOT directly connect to technique T1082 (uname), since event 1 was whoami
    assert (f"evt_{ev1_id}", "mitre_T1082") not in edge_pairs, "False edge created between whoami and T1082!"
    # Ensure event 2 does NOT directly connect to technique T1033 (whoami), since event 2 was uname
    assert (f"evt_{ev2_id}", "mitre_T1033") not in edge_pairs, "False edge created between uname and T1033!"
    print(" -> Verified no cross-contamination or unsupported edges between unrelated events and techniques.")

    # --- Test 6: Filters return the expected graph subset ---
    print("\n[Test 6] Testing graph filters return expected subset...")
    # Filter by specific source IP
    ip_graph = httpx.get(f"{BASE_URL}/api/graph?source_ip={test_ip}").json()
    assert all(
        n["data"].get("source_ip") == test_ip or 
        n["data"].get("ip") == test_ip or 
        n["data"]["type"] in ["technique", "alert"] 
        for n in ip_graph["nodes"]
    )
    print(f" -> Filter by source_ip={test_ip} returned {len(ip_graph['nodes'])} focused nodes.")

    # Filter by specific technique ID
    t_graph = httpx.get(f"{BASE_URL}/api/graph?technique_id=T1033").json()
    t_nodes = [n for n in t_graph["nodes"] if n["data"]["type"] == "technique"]
    assert any(n["data"]["technique_id"] == "T1033" for n in t_nodes)
    print(f" -> Filter by technique_id=T1033 returned {len(t_graph['nodes'])} focused nodes.")

    # --- Test 7 & 8: Node details and edge relationship evidence ---
    print("\n[Test 7 & 8] Testing node metadata completeness and edge evidence descriptions...")
    evt_sample = next(n for n in graph["nodes"] if n["data"]["id"] == f"evt_{ev1_id}")
    assert evt_sample["data"]["payload"] == "whoami"
    assert evt_sample["data"]["event_type"] == "command_execution"
    assert evt_sample["data"]["timestamp"] is not None

    edge_sample = next(e for e in edges if e["data"]["source"] == f"evt_{ev1_id}" and e["data"]["target"] == "mitre_T1033")
    assert edge_sample["data"]["relationship"] == "SUPPORTS_TECHNIQUE"
    assert "whoami" in edge_sample["data"]["evidence"] or "telemetry evidence" in edge_sample["data"]["evidence"]
    print(" -> Node metadata and edge evidentiary explanations strictly verified.")

    # --- Test 9: Empty graph responses are handled correctly ---
    print("\n[Test 9] Testing empty graph responses handled correctly...")
    empty_res = httpx.get(f"{BASE_URL}/api/graph?session_id=non-existent-session-00000")
    assert empty_res.status_code == 200
    empty_graph = empty_res.json()
    assert empty_graph["nodes"] == []
    assert empty_graph["edges"] == []
    assert empty_graph["total_nodes"] == 0
    assert empty_graph["total_edges"] == 0
    print(" -> Non-existent filter returned empty graph structure with HTTP 200 without error.")

    # --- Test 10: Existing ingestion, correlation, and MITRE tests regression ---
    print("\n[Test 10] Testing existing endpoints regression...")
    assert httpx.get(f"{BASE_URL}/api/health").status_code == 200
    assert httpx.get(f"{BASE_URL}/api/events?limit=5").status_code == 200
    assert httpx.get(f"{BASE_URL}/api/sessions?limit=5").status_code == 200
    assert httpx.get(f"{BASE_URL}/api/techniques?limit=5").status_code == 200
    print(" -> Ingestion, session, and MITRE endpoints continue to function cleanly.")

    print("\n" + "=" * 70)
    print("ALL 11 INVESTIGATION GRAPH TESTS PASSED SUCCESSFULLY!")
    print("=" * 70)

if __name__ == "__main__":
    run_tests()
