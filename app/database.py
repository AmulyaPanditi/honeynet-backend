import logging
from sqlalchemy import create_engine, text, inspect
from sqlalchemy.orm import declarative_base, sessionmaker
from app.config import settings

logger = logging.getLogger("honeynet.database")

# Clean database abstraction supporting both PostgreSQL and development SQLite fallback
DATABASE_URL = settings.DATABASE_URL

# Handle potential Heroku/Render postgres:// prefix
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

is_sqlite = DATABASE_URL.startswith("sqlite")

connect_args = {"check_same_thread": False} if is_sqlite else {}

from pathlib import Path

if is_sqlite:
    if not DATABASE_URL.startswith("sqlite:///:memory:"):
        db_path_str = DATABASE_URL.replace("sqlite:///", "")
        # Remove potential leading slash on windows paths
        db_path = Path(db_path_str)
        if db_path.parent:
            db_path.parent.mkdir(parents=True, exist_ok=True)
    logger.info(f"Operating with SQLite database at: {DATABASE_URL}")
    engine = create_engine(DATABASE_URL, connect_args=connect_args)
else:
    logger.info("Connecting to persistent PostgreSQL database.")
    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True,
        pool_recycle=300
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    import app.models.telemetry
    import app.models.alert
    import app.models.session
    import app.models.mitre
    Base.metadata.create_all(bind=engine)
    
    # Safe schema migration for added columns
    try:
        with engine.connect() as conn:
            inspector = inspect(engine)
            tables = inspector.get_table_names()
            if "telemetry_events" in tables:
                telemetry_cols = [c["name"] for c in inspector.get_columns("telemetry_events")]
                if "username" not in telemetry_cols:
                    logger.info("Adding 'username' column to telemetry_events table...")
                    conn.execute(text("ALTER TABLE telemetry_events ADD COLUMN username VARCHAR(64)"))
                    conn.commit()
                if "data_origin" not in telemetry_cols:
                    logger.info("Adding 'data_origin' column to telemetry_events table...")
                    conn.execute(text("ALTER TABLE telemetry_events ADD COLUMN data_origin VARCHAR(16) DEFAULT 'real'"))
                    conn.commit()

            if "alerts" in tables:
                alert_cols = [c["name"] for c in inspector.get_columns("alerts")]
                columns_to_add = [
                    ("status", "VARCHAR(32) DEFAULT 'NEW'"),
                    ("detection_rule_id", "VARCHAR(64)"),
                    ("related_event_ids", "TEXT DEFAULT '[]'"),
                    ("related_technique_ids", "TEXT DEFAULT '[]'"),
                    ("supporting_evidence", "TEXT DEFAULT '{}'"),
                    ("explanation", "TEXT"),
                    ("severity_rationale", "TEXT"),
                    ("fingerprint", "VARCHAR(128)"),
                    ("data_origin", "VARCHAR(16) DEFAULT 'real'"),
                ]
                for col_name, col_type in columns_to_add:
                    if col_name not in alert_cols:
                        logger.info(f"Adding '{col_name}' column to alerts table...")
                        conn.execute(text(f"ALTER TABLE alerts ADD COLUMN {col_name} {col_type}"))
                        conn.commit()
    except Exception as e:
        logger.warning(f"Schema migration check notice: {e}")

