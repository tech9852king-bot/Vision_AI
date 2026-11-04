# VantaVisionAI Funding Prototype

> Enterprise-grade Computer Vision Threat Monitoring & Automated Incident Orchestration Platform.
> Combines zero-cloud-bandwidth browser-side TensorFlow.js MobileNet V2 object detection, lightweight IoU centroid tracking, a 7-layer guarded Brain command interface, grounded security Copilot, and FastAPI/SQLite backend.

---

## 🏛 1. Executive Summary & Architecture Map

VantaVisionAI solves the heavy bandwidth and privacy costs of cloud video streaming by running **local, in-browser WebGL object detection**. Raw video frames never leave client memory; only deduplicated, structured JSON metadata is dispatched to the backend policy engine.

```
                           [ CLIENT BROWSER ]
       +-------------------------------------------------------+
       | MediaStream (Webcam / Synthetic Test Feed / Video)    |
       |                          │                            |
       |                          ▼                            |
       |            TensorFlow.js COCO-SSD (MobileNet V2)      |
       |                          │                            |
       |                          ▼                            |
       |         Lightweight IoU & Centroid Tracker            |
       |     (Assigns persistent IDs e.g. #TRK-101; prevents    |
       |       event spamming; deduplicates ingestion)         |
       +--------------------------┬----------------------------+
                                  │ POST /api/v1/events (Metadata only)
                                  ▼
                    [ FASTAPI / DOCKER BACKEND ]
       +-------------------------------------------------------+
       | Real-Time Policy Engine                               |
       |  - Evaluates target class, zones & schedules          |
       |  - Automated incident escalation & severity ranking   |
       +--------------------------┬----------------------------+
                                  │
                                  ▼
       +-------------------------------------------------------+
       | SQLite Persistent Storage & Multi-Tenant Isolation    |
       |  - Events · Incidents · Policies · Audit Trails       |
       +--------------------------┬----------------------------+
                                  │
                                  ▼
       +-------------------------------------------------------+
       | Controlled Brain CLI & Grounded Security Copilot      |
       |  - 7-Layer Architecture: Router -> Context ->         |
       |    Evidence -> Reasoning -> Action Guard ->           |
       |    Audit -> Fallback                                  |
       +-------------------------------------------------------+
```

---

## 🔍 2. Hardware Disclosure & Environmental Integrity

- **Simulated Provider Integrity**: The system transparently reports `provider: "SIMULATED"` and `real_camera_configured: false`. In cloud sandbox or headless environments without physical camera hardware, this eliminates false promises and preserves investor and technical trust.
- **In-Browser Synthetic Surveillance Feed**: Provides a deterministic, real canvas `MediaStream` (`canvas.captureStream(15)`) with moving objects (person, vehicle, luggage). This enables genuine TensorFlow.js MobileNet V2 object detection and tracking without requiring a physical camera device.
- **Watchdog Auto-Reconnection**: Scanner features a 6-second stream stall detector with exponential backoff and cancel controls, ensuring uninterrupted surveillance operations without manual page refresh.

---

## 🛡 3. The 7-Layer Controlled Brain Command Architecture

The Brain (`POST /api/v1/brain`) is an allowlisted command controller, NOT an unconstrained chatbot. Every command passes through 7 distinct defense layers:

1. **Intent Router**: Normalizes and maps requests strictly to 11 allowlisted operational commands.
2. **Context Builder**: Isolates tenant scope using `X-Tenant-ID`.
3. **Evidence Layer**: Reads verified telemetry directly from SQLite storage.
4. **Reasoning Layer**: Applies deterministic logic; no hallucinations.
5. **Action Guard**: Rejects SQL injection, shell commands, or unallowlisted actions with HTTP 400.
6. **Audit Layer**: Records every attempt (success or blocked) into the immutable audit trail.
7. **Fallback Layer**: Structured error response with approved operational syntax.

### Approved Allowlisted Commands

| Command | Category | Functionality |
|---|---|---|
| `help` | Syntax | Complete operational syntax guide and allowed flags |
| `status` | System | Healthcheck, camera provider mode, and system parameters |
| `capabilities` | Architecture | Verified operational capabilities and active AI modules |
| `summary` | Metrics | Aggregated counts of detections, incidents, and policies |
| `incidents` | Security | Queries open security incidents, severity levels, and policies |
| `policies` | Security | Inspects automated detection rules and operational thresholds |
| `cameras` | Telemetry | Inspects registered video inputs and physical vs simulated status |
| `events` | Telemetry | Lists recent detection events filtered by tenant |
| `diagnostics` | Hardware | Camera pipeline diagnostics and scheduler telemetry |
| `audit` | Compliance | Inspects recent cryptographic audit trail records |
| `troubleshoot` | Operations | Step-by-step diagnostic guidance for camera, permission, or policy issues |

---

## 🤖 4. Grounded Security Copilot

The Copilot (`POST /api/v1/copilot`) provides verified operational analysis grounded in real database records. Every response adheres to a strict 5-part structure:

- **Finding**: Direct, quantitative answer to the security inquiry.
- **Evidence**: Explicit list of database records corroborating the finding.
- **Interpretation**: Contextual analysis of the threat posture.
- **Recommended Steps**: Concrete operational next actions for the security operator.
- **Limitations**: Transparent boundaries on data coverage and simulated hardware.

---

## 🚀 5. Quickstart & Deployment

### Option A: Docker Compose (Production Target, Port 8000)

```bash
# Build and start containerized FastAPI backend & frontend
docker compose up --build
```

- **Service**: `vanta-funding`
- **Container**: `vanta-funding-prototype`
- **URL**: `http://localhost:8000`
- **Healthcheck**: `http://localhost:8000/health`

### Option B: Local Node.js Preview Server (Port 3000)

```bash
# Install dependencies (if needed)
npm install

# Start zero-dependency preview server
npm run dev
# Live at http://localhost:3000
```

### Option C: Python FastAPI Direct

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## 🧪 6. Automated Testing & Verification

Run the full dual-stack test suite (20 Node.js API integration tests + 14 Python unit tests = 34 total assertions):

```bash
npm test
```

Expected output:
```text
[TEST SUITE] Executing VantaVisionAI REST Endpoints Integration Suite...
  ✓ [PASS] GET /health returns 200 with status ok
  ✓ [PASS] GET /ready returns 200 and declares SIMULATED provider
  ✓ [PASS] GET /api/v1/system returns app_name and subsystem telemetry
  ✓ [PASS] GET /api/v1/summary returns metrics object
  ✓ [PASS] POST /api/v1/demo/run creates simulation event & incident
  ✓ [PASS] POST /api/v1/events creates new event
  ✓ [PASS] GET /api/v1/events lists recorded events
  ✓ [PASS] DELETE /api/v1/events/:id removes created event
  ✓ [PASS] GET /api/v1/incidents returns array of incidents
  ✓ [PASS] POST /api/v1/incidents/:id/resolve marks incident as RESOLVED
  ✓ [PASS] GET /api/v1/policies returns 4 active security policies
  ✓ [PASS] POST /api/v1/brain accepts allowlisted command "help"
  ✓ [PASS] POST /api/v1/brain handles "diagnostics"
  ✓ [PASS] POST /api/v1/brain handles "tools" command
  ✓ [PASS] POST /api/v1/brain rejects unallowlisted injection with 400
  ✓ [PASS] GET /api/v1/brain/tools returns approved tool registry
  ✓ [PASS] POST /api/v1/brain/tools/get_system_status executes approved tool
  ✓ [PASS] POST /api/v1/brain/tools/resolve_incident rejects missing params with 400
  ✓ [PASS] POST /api/v1/copilot returns 5-part grounded response structure
  ✓ [PASS] GET /api/v1/audit returns immutable audit records
[TEST SUITE] Integration Complete: 20/20 assertions passed.
..............
----------------------------------------------------------------------
Ran 14 tests in 0.050s
OK
```

---

## 📡 7. API Contract Reference

| Method | Endpoint | Description | Sample Request |
|---|---|---|---|
| `GET` | `/` | Web application single-page interface | - |
| `GET` | `/health` | Service health status | - |
| `GET` | `/ready` | Database & hardware provider status | - |
| `GET` | `/api/v1/system` | System architecture & subsystem metrics | - |
| `GET` | `/api/v1/summary` | Aggregated dashboard KPI counters | - |
| `GET` | `/api/v1/events` | List all recorded detection events | - |
| `POST` | `/api/v1/events` | Ingest detection event & trigger policies | `{"camera_id":"CAM-01","class_name":"person","confidence":0.94}` |
| `DELETE` | `/api/v1/events/{id}` | Delete detection event | - |
| `GET` | `/api/v1/incidents` | List active & resolved security incidents | - |
| `POST` | `/api/v1/incidents/{id}/resolve` | Mark security incident as RESOLVED | - |
| `GET` | `/api/v1/policies` | Retrieve active automated detection rules | - |
| `PUT` | `/api/v1/policies/{id}/toggle` | Enable or disable detection policy | `{"enabled": false}` |
| `POST` | `/api/v1/copilot` | Ask grounded natural language security question | `{"query": "Summarize open incidents"}` |
| `GET` | `/api/v1/audit` | Inspect tamper-evident audit trail | - |
| `POST` | `/api/v1/demo/run` | Execute end-to-end intrusion simulation | `{"scenario": "intrusion"}` |
| `POST` | `/api/v1/brain` | Execute allowlisted Brain command | `{"command": "status", "args": {}}` |
| `GET` | `/api/v1/brain/tools` | Enumerate approved operational tools | - |
| `POST` | `/api/v1/brain/tools/{name}` | Execute approved operational tool | `{"parameters": {}}` |
| `GET` | `/api/v1/audit/dossier` | Cryptographic forensic dossier with verified hash chain | - |

---

## 🦅 8. Tactical & Defense Operational Modules

1. **Cross-Camera Geo-Spatial Re-Identification (Re-ID) Continuity**:
   - `ObjectTracker` incorporates a rolling 5-second `reIdBuffer` memory.
   - When tracked targets momentarily occlude or reappear after camera source switching, the system performs aspect ratio and bounding-box size similarity matching (>= 80% threshold).
   - Preserves track continuity (`#TRK-xxx`) and logs `REID_CONTINUITY_MATCH` events in `STATE.sceneEventsLog`.

2. **Autonomous Tactical UAV / Drone Dispatch Subsystem**:
   - Registered 15th approved Brain operational tool: `dispatch_tactical_drone`.
   - Supports tactical profiles: `PERIMETER_RECON`, `TARGET_LOCK`, and `THERMAL_OVERWATCH`.
   - Real-time audit recording (`BRAIN_TOOL_DISPATCH_TACTICAL_DRONE`) and instant WebSocket telemetry push (`UAV_DISPATCHED`).
   - Integrated with Aleana Voice Assistant for hands-free spoken dispatch commands ("dispatch drone", "launch drone", "drone bhejo").

3. **Cryptographic Forensic Dossier & Ledger Verification**:
   - Generates immutable forensic dossiers at `/api/v1/audit/dossier` linking open/resolved incidents, detection events, active security policies, and SHA-256 hash-chained audit blocks.
   - Front-end operators can export tamper-evident signed JSON dossiers with one-click verification against `GENESIS_BLOCK_0000`.

---

## 📋 9. Compliance & Security Architecture

- **Multi-Tenant Isolation**: Enforced via `X-Tenant-ID` HTTP header across all endpoints.
- **Action Guard & Injection Protection**: Disallows SQL statements, shell execution, or non-whitelisted intents.
- **Audit Immutability**: All CRUD, policy, and Brain actions generate structured audit records with cryptographic SHA-256 ledger chaining.
- **Zero-Pill Discipline & Accessibility**: WCAG AA color contrast, responsive layout across desktop and mobile, and zero-pill typographic metadata hierarchy.
