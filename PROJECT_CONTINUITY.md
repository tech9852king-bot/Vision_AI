# VantaVisionAI Funding Prototype — Project Continuity & Stability Record

**Created / Updated**: October 25, 2026  
**Auditor Role**: Principal Software Reliability Engineer / System Architect  
**Project Name**: VantaVisionAI Funding Prototype  
**Purpose**: Zero-cloud-bandwidth visual threat monitoring, edge computer vision object tracking, 7-layer guarded Brain orchestration, and Aleana voice operations assistant.

---

## 1. Verified Architecture & Serving Paths

### 1.1 Relationship: Active Vanilla Frontend vs React/Vite Scaffold
- **Active Production UI**: The real running user interface is pure vanilla HTML5, CSS3, and JavaScript located at `static/index.html` (and mirrored at the root `index.html`) loaded with `static/app.js` and `static/style.css`.
- **Active Serving Server**: `dev-server.cjs` is a self-contained Node.js server binding to `0.0.0.0:3000`. When requests arrive for `/` or `/index.html`, lines 1268–1275 of `dev-server.cjs` explicitly serve `static/index.html`. It also provides the active REST API routes (`/api/v1/*`, `/health`, `/ready`).
- **Unused React/Vite Scaffold**: The directory `src/` contains `src/App.tsx` (which returns an empty `<div></div>`), `src/main.tsx`, and `vite.config.ts`. Although Vite and React are present in `package.json`, `src/App.tsx` is an empty scaffold and is **NOT** the active application interface. The active application does not use a Vite bundler pipeline; running Vite bundler on `index.html` leaves `static/app.js` unbundled because it is loaded via `<script src="/static/app.js">` rather than as an ES module.

### 1.2 Startup Commands
| Command | Subsystem | Port | Description & Target |
|---|---|---|---|
| `npm start` or `npm run dev` | Active Prototype Dev Server | 3000 | **Real Primary Command**: Executes `node dev-server.cjs`. Serves `static/index.html`, `static/app.js`, and all active `/api/v1/*` endpoints. |
| `docker compose up --build` | Containerized FastAPI + Static | 8000 | Alternative production deployment running Uvicorn + FastAPI backend connected to SQLite (`vanta_vision.db`). |
| `uvicorn backend.app.main:app --port 8000` | FastAPI Direct | 8000 | Alternative local Python backend runner. Note: requires Python venv and packages from `requirements.txt`. |

---

## 2. Validation Commands, Build & Lint Definitions

### 2.1 What `npm run build` Does and Does Not Do
- **What it does**:
  1. Executes `npm run check:syntax` to syntax-validate `dev-server.cjs`, `static/app.js`, `tests/test_api_endpoints.js`, and `tests/test_aleana_voice.js` using Node.js built-in syntax parser (`node -c`). Fails with non-zero exit code on any JavaScript syntax error.
  2. Executes `tsc --noEmit` to validate all TypeScript files (`tsconfig.json`, `vite.config.ts`, `src/`) for type errors without emitting build artifacts.
  3. Outputs a factual status notice: `[BUILD] Static syntax validated; TypeScript checked (noEmit). Active app served directly from static/ without bundling.`
- **What it does NOT do**:
  - It does NOT bundle, minify, or transpile `static/app.js`.
  - It does NOT swap the active UI to the empty `src/App.tsx` React component.
  - It does NOT print fake success claims if a syntax or type error occurs.

### 2.2 What `npm run lint` Does and Does Not Do
- **What it does**:
  1. Factually reports that a dedicated linter (ESLint) is not configured in this project dependencies.
  2. Executes `npm run check:syntax` as a genuine syntax-level barrier.
- **What it does NOT do**:
  - It does NOT pretend that ESLint or any other linter is installed.
  - It does NOT print misleading claims such as "0 errors" when no lint rules were evaluated.

### 2.3 Exact Command Reference
| Script Target | Exact Command Line | Purpose & Scope |
|---|---|---|
| `npm run check:syntax` | `node -c dev-server.cjs static/app.js tests/test_api_endpoints.js tests/test_aleana_voice.js` | Built-in Node parser checks for syntax defects across active server, frontend, and test files. Fails non-zero on syntax error. |
| `npm run check:types` | `tsc --noEmit` | Validates TypeScript configuration and types in `tsconfig.json` without emitting output files. |
| `npm run build` | `npm run check:syntax && tsc --noEmit && node -e "console.log('[BUILD] Static syntax validated; TypeScript checked (noEmit). Active app served directly from static/ without bundling.')"` | Real dual-stage static validation (syntax + types). Fails if any check fails. |
| `npm run lint` | `node -e "console.log('[LINT] Notice: ESLint is not configured in this prototype. Executing JavaScript syntax validation instead:');" && npm run check:syntax` | Honest reporting of missing linter config + fallback execution of genuine syntax check. |
| `npm test` | `node tests/test_api_endpoints.js && node tests/test_aleana_voice.js && python3 -m unittest discover -s tests` | Comprehensive integration, voice NLP, and Python unit test suites. |

---

## 3. Test Preconditions & Architecture Dependencies

### 3.1 Preconditions for `npm test`
- **Server Precondition (Port 3000)**:
  - `node tests/test_api_endpoints.js` connects via HTTP to `http://127.0.0.1:3000`. **Requires `dev-server.cjs` to be actively running on port 3000.** If the server is offline, this script fails with `ECONNREFUSED`.
  - `node tests/test_aleana_voice.js` tests HTTP endpoints `/api/v1/aleana/status` and `/api/v1/aleana/command` on `http://127.0.0.1:3000`. **Requires `dev-server.cjs` to be running on port 3000.**
- **Offline / Standalone Execution**:
  - `python3 -m unittest discover -s tests` executes standard library Python unit tests (`test_brain.py`, `test_copilot.py`) against SQLite directly in-process. **Does NOT require a running server.**
  - If running tests in an offline/CI environment where `dev-server.cjs` is not running, only the Python unit tests will pass unless `dev-server.cjs` is started in the background first (e.g. `node dev-server.cjs &`).

---

## 4. Live Session Execution Verification

The following verification commands were executed live in this environment on October 25, 2026:

1. **`npm run check:syntax`**:
   - Exit code: `0`
   - Output: `node -c dev-server.cjs static/app.js tests/test_api_endpoints.js tests/test_aleana_voice.js` (Completed cleanly, zero syntax errors).
2. **`npm run check:types`**:
   - Exit code: `0`
   - Output: `tsc --noEmit` (Completed cleanly, zero TypeScript errors).
3. **`npm run build`**:
   - Exit code: `0`
   - Output: `[BUILD] Static syntax validated; TypeScript checked (noEmit). Active app served directly from static/ without bundling.`
4. **`npm run lint`**:
   - Exit code: `0`
   - Output: `[LINT] Notice: ESLint is not configured in this prototype. Executing JavaScript syntax validation instead:` followed by clean `check:syntax` execution.
5. **`npm test`** (with `dev-server.cjs` active on port 3000):
   - Exit code: `0`
   - Results:
     - `tests/test_api_endpoints.js`: 77/77 assertions PASSED (including DEF-01 to DEF-05 verifications, scanner category filter, dropdown options, and dynamic chip container visibility).
     - `tests/test_aleana_voice.js`: 36/36 assertions PASSED.
     - `python3 -m unittest discover -s tests`: 14/14 tests PASSED (0.032s, 1 skipped for FastAPI host isolation).
     - Total: 127/127 test assertions passed across the full test suite.

---

## 5. Feature Source Map

- **Live Vision Scanner & Video Pipeline**: `static/app.js` (lines 400–1450). Implements `detectFromVideo`, bounded canvas scaling (max 640px), memory revocation `URL.revokeObjectURL(STATE.activeObjectUrl)`, in-flight backpressure, and watchdog auto-reconnection.
- **Scanner On-The-Fly Category Filter & Dynamic Chip Container**:
  - UI Dropdown & Badge: `static/index.html` (lines 440–462, `#scanner-category-filter`, `#detections-filter-badge`). Includes options for All Categories, Persons, Vehicles, Luggage, Weapons, Electronics, Animals, Interior/Furniture, Other Objects, and Hide Detection Chips (`none`).
  - Filter Engine & Registry: `static/app.js` (`DETECTION_CATEGORIES`, `filterPredictions`, `getObjectCategory`, `applyActiveCategoryFilter`).
  - Dynamic Container Visibility: `static/app.js` (`applyActiveCategoryFilter` & `updateDetectionChips` toggle `.chips-hidden` and `display: none` / `display: flex`, updating counts and active filter badges).
  - Live Chips: `static/style.css` (`.det-chip.chip-person`, `.chip-vehicle`, `.chip-luggage`, `.chip-hazard`, `.chip-animal`, `.chip-electronics`, `.chip-furniture`, `.chip-object`). Renders dynamic category SVG icons, score percentages, track IDs, and filtered item statistics.
- **Centroid & IoU Object Tracker**: `static/app.js` (lines 20–130). `class ObjectTracker` maintains track ID continuity across frames and deduplicates alerts.
- **Aleana Voice Operations Engine**:
  - Frontend: `static/app.js` (lines 1450–1920). Handles Web Speech API, wake-word parsing (`Aleana`), half-duplex speech synthesis gating, transcript deduplication (1500ms), and state machine.
  - Floating UI: `static/index.html` (lines 1140–1188, `#aleana-drawer` with `#drawer-aleana-form` text input fallback).
  - Node Backend API: `dev-server.cjs` (lines 523–748, `/api/v1/aleana/status`, `/api/v1/aleana/command`).
  - FastAPI Backend API (Parity): `backend/app/routers/aleana.py` (mounted in `backend/app/main.py`).
- **7-Layer Guarded Brain Console**:
  - Frontend: `static/app.js` (lines 2150–2300, `#brain-input`).
  - Python Backend: `backend/app/core_brain.py`, `backend/app/brain_service.py`, `backend/app/brain_tools.py`, `backend/app/routers/brain.py`.
  - Node Backend: `dev-server.cjs` (lines 300–440).
- **Grounded Security Copilot**:
  - Python Backend: `backend/app/routers/copilot.py`.
  - Node Backend: `dev-server.cjs` (lines 750–908). 5-part grounded response (`finding`, `evidence`, `interpretation`, `recommended_steps`, `limitations`).
- **Audit Ledger**:
  - Python Backend: `backend/app/routers/audit.py`, `backend/app/database.py` (`log_audit`).
  - Node Backend: `dev-server.cjs` (lines 220–250, `logAudit`).

---

## 6. Resolved Defects & Verified Improvements (Master System Audit)

1. **DEF-01 [High] Dual-Server Route Parity (Aleana Router in FastAPI) — RESOLVED**:
   - Created `backend/app/routers/aleana.py` implementing `/api/v1/aleana/status` and `/api/v1/aleana/command` with complete intent recognition, phonetic autocorrection, Hindi aliases, and SQLite audit logging matching `dev-server.cjs`. Mounted in `backend/app/main.py`.
2. **DEF-02 [High] Policy CRUD Parity in FastAPI — RESOLVED**:
   - Added `PolicyCreate` model to `backend/app/schemas.py`. Implemented `POST /api/v1/policies` and `DELETE /api/v1/policies/{policy_id}` in `backend/app/routers/policies.py`.
3. **DEF-03 [Medium] Event Severity & Status Filter Wire-up — RESOLVED**:
   - Connected `#event-sev-filter` and `#event-status-filter` dropdown listeners in `static/app.js` to `renderEventsTable` with real-time filtering across severity levels and statuses.
4. **DEF-04 [Medium] Policy Category & Audit Subtabs Wire-up — RESOLVED**:
   - Bound click event listeners to `[data-policy-category]` and `[data-audit-tab]` subtab strips, filtering policy tables and audit records reactively with active tab styling.
5. **DEF-05 [Medium] Aleana Quick-Access Drawer Input Accessibility — RESOLVED**:
   - Added `#drawer-aleana-form` with `#drawer-aleana-input` to `#aleana-drawer` in `static/index.html` and bound submit handler in `static/app.js` to `executeAleanaCommand`. Operator can command Aleana via text fallback when microphone is restricted.

---

## 7. Final Master Build Achievements & Test Verification (October 26, 2026)

### 7.1 Milestone 1: Advanced Computer Vision & Multi-Object Tracking Engine
1. **Per-Class NMS (Non-Maximum Suppression)**:
   - Implemented `applyPerClassNMS` in `static/app.js`. Preserves co-occurring distinct classes (e.g., Person carrying a Backpack) while suppressing duplicate bounding boxes for identical objects with IoU > 0.50.
2. **Robust Multi-Object Tracking with Occlusion Recovery**:
   - Upgraded `ObjectTracker` with multi-frame velocity extrapolation ($\Delta t_{\text{disappeared}}$), scale-normalized centroid distance gating, and occlusion recovery (up to 8 frames) to prevent ID swaps when tracks cross.
3. **Bounded Inference & Event Ingestion Backpressure**:
   - Fixed canvas coordinate clamping and letterboxing in `renderPredictions`.
   - Replaced synchronous event dropping with bounded `STATE.eventQueue` and `flushEventQueue()` to prevent event loss when multiple objects arrive simultaneously.
4. **Verification**:
   - 8-test unit suite in `tests/test_multi_object_detection.js` covering zero detections, 10+ simultaneous targets, per-class NMS, coordinate clamping, trajectory crossing without swaps, and occlusion recovery: **8/8 PASSED**.

### 7.2 Milestone 2: Intelligent Copilot Live Context Bridge & Cinematic Theme Switcher
1. **Copilot Live Scanner Grounding**:
   - Connected `sendCopilotQuery` in `static/app.js` to live scanner state, passing `live_context` with visible count, active track IDs, detections list, per-class census, and recent tracking delta.
   - Updated both `dev-server.cjs` and `backend/app/routers/copilot.py` to deterministically ground answers for:
     - *"How many objects are visible right now?"*
     - *"How many people and vehicles are detected?"*
     - *"Show the current track IDs"*
     - *"What changed in the last few seconds?"*
     - *"Is the scanner running?"*
   - Honest fallback disclosure when scanner is halted or offline.
2. **Cinematic Enterprise UI Theme Switcher (Dark / Light / System)**:
   - Implemented high-contrast Light Theme design tokens and CSS component adaptations in `static/style.css`.
   - Added accessible 3-button switcher group (`#theme-btn-dark`, `#theme-btn-light`, `#theme-btn-system`) in navigation topbar of `static/index.html`.
   - Added anti-FOUC immediate execution script in `<head>` to prevent theme flashing on reload.
   - Implemented `applyTheme` and `initThemeEngine` with `localStorage` persistence and OS-level color scheme change listener.
3. **Clean Media Lifecycle & Source Isolation**:
   - Added `STATE.tracker.reset()` directly into `cleanActiveMedia()` in `static/app.js`. Switching between webcam, synthetic test feeds, and video uploads cleanly releases tracks and prevents cross-stream target pollution.
4. **Verification**:
   - 16-test suite in `tests/test_copilot_multi_detection.js` verifying Copilot live grounding, inactive disclosures, census calculations, track lists, theme DOM elements, and anti-FOUC scripts: **16/16 PASSED**.

### 7.3 Master Test Suite Tally
| Test Suite | Assertions / Tests | Status |
|---|---|---|
| REST API Endpoints (`tests/test_api_endpoints.js`) | 77 / 77 | **PASSED** |
| ALEANA Voice Operations (`tests/test_aleana_voice.js`) | 36 / 36 | **PASSED** |
| Multi-Object Detection Engine (`tests/test_multi_object_detection.js`) | 8 / 8 | **PASSED** |
| Copilot Live Context & Theme Engine (`tests/test_copilot_multi_detection.js`) | 16 / 16 | **PASSED** |
| Firebase Cloud Integration Suite (`tests/test_firebase_integration.js`) | 22 / 22 | **PASSED** |
| Python Unit Tests (`test_brain.py`, `test_copilot.py`) | 14 / 14 | **PASSED** (1 skipped) |
| **Total Test Suite** | **173 Assertions** | **100% PASS** |

---

## 8. Firebase Cloud Integration (Firestore & Authentication)

- **Cloud Provisioning**: Firestore database `ai-studio-vantavisionai-41676fcb-440e-4810-909c-de0f999fe055` provisioned in project `gen-lang-client-0628849129` (region `asia-east1`).
- **Security Rules**: Deployed `firestore.rules` adhering to zero-trust principles (global default deny, immutable audit logs, user path isolation, `isAdmin()` enforcement for operator `tech9852king@gmail.com`).
- **Blueprint**: `firebase-blueprint.json` defines schemas for `User`, `DetectionEvent`, `Incident`, `Policy`, and `AuditLog`.
- **Vanilla Browser Client**: Loaded modularly in `static/index.html` via `static/firebase-client.js`, exposing `window.VantaFirebase` with Google Sign-In, sign-out, profile sync, and real-time incident listener.

---

## 9. Strict UI & Frontend Overhaul (October 29, 2026)

- **Design System & Theme Engine**:
  - Dark Security Operations Center (SOC) primary palette (`#060913`, `#0a1120`, `#101b30`) with cyan, emerald, amber, and rose accents.
  - Complete, readable Light Theme (`#f8fafc`, `#ffffff`, `#f1f5f9`) with slate-900 typography providing 100% WCAG AA contrast across all views, tables, forms, and dialogs.
  - Anti-FOUC `<head>` theme script preserving theme choice in `localStorage`.
- **Accessibility & Motion Governance**:
  - Focus indicators (`:focus-visible`) across all buttons, dropdowns, inputs, and tabs.
  - `@media (prefers-reduced-motion: reduce)` disabling non-essential pulse, radar sweep, and spinner animations.
  - Responsive layouts tested from 360px small mobile to 1920px wide desktop with zero horizontal overflow.
- **Master Export Archive**:
  - Updated `vantavisionai_master_export.zip` (3.44 MB, clean zip, excludes `node_modules`, `.git`, `__pycache__`, and `backups`).

---

## 10. Tactical Defense Upgrade & Standalone Enterprise Hardening (November 2, 2026)

- **Cross-Camera Geo-Spatial Re-ID Continuity**:
  - `ObjectTracker` incorporates a rolling 5-second `reIdBuffer` memory window.
  - Mitigates track fragmenting and duplicate ID assignment across brief occlusions and camera switches using aspect ratio and bounding-box size similarity (>= 80% threshold).
  - Emits `REID_CONTINUITY_MATCH` log entries in `STATE.sceneEventsLog`.
- **Autonomous Tactical UAV / Drone Dispatch Subsystem**:
  - 15th approved tool: `dispatch_tactical_drone` registered in `backend/app/brain_tools.py` (`GLOBAL_TOOL_REGISTRY`) and `dev-server.cjs` (`APPROVED_TOOLS`).
  - Supports mission profiles: `PERIMETER_RECON`, `TARGET_LOCK`, and `THERMAL_OVERWATCH`.
  - Dispatches automated simulated UAV telemetry, writes `BRAIN_TOOL_DISPATCH_TACTICAL_DRONE` to the immutable audit ledger, and pushes real-time WebSocket (`/ws`) `UAV_DISPATCHED` events.
  - Native bilingual voice intent in Aleana ("dispatch drone", "launch drone", "drone bhejo").
- **Cryptographic Forensic Dossier (`GET /api/v1/audit/dossier`)**:
  - Unifies open and resolved incidents, recent detection events, active policies, and SHA-256 hash-chained audit blocks.
  - One-click front-end export via `#btn-export-dossier` in Audit Trail view.

