import os
from pathlib import Path
from typing import List, Optional
from pydantic_settings import BaseSettings

# Deterministic Project Base Directory (c:/Users/Amuly/OneDrive/Desktop/hackathon)
# Calculated from this file: backend/app/config.py -> parent.parent.parent is project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_SQLITE_PATH = PROJECT_ROOT / "honeynet.db"

def resolve_database_url(raw_url: Optional[str]) -> str:
    """
    Ensures SQLite URLs resolve deterministically to a stable absolute location
    regardless of which directory the backend process is launched from.
    Preserves explicitly configured PostgreSQL URLs, absolute SQLite paths, or in-memory databases.
    """
    if not raw_url:
        return f"sqlite:///{DEFAULT_SQLITE_PATH.as_posix()}"
    
    # Handle relative SQLite paths like sqlite:///./honeynet.db or sqlite:///honeynet.db
    if raw_url.startswith("sqlite:///") and not raw_url.startswith("sqlite:///:memory:"):
        path_part = raw_url[len("sqlite:///"):]
        # If path is relative (no drive letter on Windows and not absolute)
        if not os.path.isabs(path_part) and not (len(path_part) > 1 and path_part[1] == ":"):
            clean_rel = path_part.lstrip("./").lstrip(".\\")
            resolved = (PROJECT_ROOT / clean_rel).resolve()
            return f"sqlite:///{resolved.as_posix()}"
            
    return raw_url

class Settings(BaseSettings):
    PROJECT_NAME: str = "Autonomous Honeynet Telemetry & MITRE ATT&CK Causal Profiler"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Database
    DATABASE_URL: str = resolve_database_url(os.getenv("DATABASE_URL", None))
    
    # Optional Sensor Authentication Key (if set, requires X-API-Key header on ingestion)
    API_KEY: Optional[str] = os.getenv("API_KEY", None)

    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000"
    ]

    class Config:
        case_sensitive = True
        env_file = ".env"
        extra = "ignore"

settings = Settings()
