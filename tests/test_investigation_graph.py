def test_causal_graph_generation(client):
    """Verify Cytoscape graph nodes and edges generated from stored telemetry."""
    # Ingest event connected to session
    sess_id = "graph-test-sess-iso"
    client.post("/api/events", json={
        "event_id": "evt-graph-iso-01",
        "session_id": sess_id,
        "source_ip": "198.51.100.55",
        "event_type": "command_execution",
        "payload": "whoami"
    })

    # Query graph
    res_graph = client.get("/api/graph")
    assert res_graph.status_code == 200
    g_data = res_graph.json()
    assert "nodes" in g_data
    assert "edges" in g_data

    # Query graph filtered by session
    res_filtered = client.get(f"/api/graph?session_id={sess_id}")
    assert res_filtered.status_code == 200
    fg_data = res_filtered.json()
    assert len(fg_data["nodes"]) >= 1
