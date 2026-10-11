import os
from pathlib import Path
from app.config import resolve_database_url, PROJECT_ROOT, DEFAULT_SQLITE_PATH

def test_health_endpoint(client):
    """Health check endpoint returns HTTP 200 and connected database status."""
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert data["database"]["status"] == "connected"
    assert "engine" in data["database"]

def test_sqlite_deterministic_path_resolution():
    """Verify that relative SQLite URLs resolve deterministically to project root."""
    # 1. Default when unset
    default_url = resolve_database_url(None)
    assert default_url == f"sqlite:///{DEFAULT_SQLITE_PATH.as_posix()}"
    assert Path(default_url.replace("sqlite:///", "")).is_absolute()

    # 2. Relative string './honeynet.db' resolves to project root
    rel_url = resolve_database_url("sqlite:///./honeynet.db")
    assert rel_url == f"sqlite:///{DEFAULT_SQLITE_PATH.as_posix()}"

    # 3. Relative string 'honeynet.db' resolves to project root
    plain_url = resolve_database_url("sqlite:///honeynet.db")
    assert plain_url == f"sqlite:///{DEFAULT_SQLITE_PATH.as_posix()}"

    # 4. In-memory SQLite is preserved
    mem_url = resolve_database_url("sqlite:///:memory:")
    assert mem_url == "sqlite:///:memory:"

    # 5. PostgreSQL URLs are preserved without modification
    pg_url = "postgresql://user:secret@postgres.internal:5432/honeynet_db"
    assert resolve_database_url(pg_url) == pg_url
