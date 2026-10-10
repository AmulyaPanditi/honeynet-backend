import sys
from pathlib import Path

# Ensure project root is in sys.path so 'backend.app' is always resolvable
_project_root = str(Path(__file__).resolve().parent.parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.app.config import settings
from backend.app.database import init_db

from backend.app.api.health import router as health_router
from backend.app.api.events import router as events_router
from backend.app.api.sessions import router as sessions_router
from backend.app.api.dashboard import router as dashboard_router
from backend.app.api.telemetry import router as telemetry_router
from backend.app.api.alerts import router as alerts_router
from backend.app.api.mitre import router as mitre_router
from backend.app.api.graph import router as graph_router
from backend.app.api.profiles import router as profiles_router

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("honeynet.app")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database tables and migrations on startup
    logger.info("Initializing database schema and running migrations...")
    init_db()
    logger.info("Database schema initialized. Running clean without automatic fake event generation.")
    yield
    logger.info("Shutting down honeynet backend.")

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Autonomous Honeynet Telemetry Ingestion, Causal Graph Reconstruction, and MITRE ATT&CK Profiling Engine.",
    lifespan=lifespan
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global error handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception at {request.url.path}: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"error": "InternalServerError", "message": str(exc), "path": request.url.path}
    )

# Direct /api route prefix to satisfy exact API convention requirements
# (GET /api/health, GET /api/events, POST /api/events, POST /api/events/bulk, GET /api/stats, GET /api/sessions, etc.)
app.include_router(health_router, prefix="/api")
app.include_router(events_router, prefix="/api")
app.include_router(sessions_router, prefix="/api")
app.include_router(mitre_router, prefix="/api")
app.include_router(graph_router, prefix="/api")
app.include_router(alerts_router, prefix="/api")
app.include_router(profiles_router, prefix="/api")

# Also include health check at root /health and /api/v1/health
app.include_router(health_router, prefix=settings.API_V1_STR)
app.include_router(health_router)

# Versioned /api/v1 routes for existing frontend compatibility
app.include_router(events_router, prefix=settings.API_V1_STR)
app.include_router(sessions_router, prefix=settings.API_V1_STR)
app.include_router(dashboard_router, prefix=settings.API_V1_STR)
app.include_router(telemetry_router, prefix=settings.API_V1_STR)
app.include_router(alerts_router, prefix=settings.API_V1_STR)
app.include_router(mitre_router, prefix=settings.API_V1_STR)
app.include_router(graph_router, prefix=settings.API_V1_STR)
app.include_router(profiles_router, prefix=settings.API_V1_STR)

@app.get("/")
def root():
    return {
        "project": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "docs_url": "/docs",
        "health_url": "/api/health",
        "events_url": "/api/events",
        "sessions_url": "/api/sessions",
        "stats_url": "/api/stats"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=True)
