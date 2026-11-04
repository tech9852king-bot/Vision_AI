# VANTAVISIONAI — PHASE 0 SECURITY FOUNDATION IMPLEMENTATION PLAN
**Document ID:** `VANTAVISIONAI_PHASE_0_SECURITY_IMPLEMENTATION_PLAN.md`  
**Classification:** Technical Architecture / Security Engineering Specification  
**Status:** READY FOR REVIEW (PLANNING MODE ONLY — ZERO DISK CODE MODIFICATIONS)  
**Target Environment:** Full-Stack Hybrid (Active Node.js Preview Engine `dev-server.cjs` :3000 & Production FastAPI `backend/app/main.py` :8000)  
**Author:** Senior Security Architect & Lead Backend Engineer  
**Date:** November 4, 2026  

---

## 1. EXECUTIVE SUMMARY & OBJECTIVES

The objective of **Phase 0 Security Foundation** is to transition the VantaVisionAI platform from prototype-grade, client-asserted tenancy to a cryptographically verified, zero-trust security architecture across both the active serving Node runtime (`dev-server.cjs`) and the production FastAPI backend (`backend/app/main.py`).

### Target Capabilities
1. **Cryptographic Authentication:** Zero-trust JWT authentication with HMAC-SHA256 (HS256) signature verification, issuer (`vantavisionai.internal`), audience (`vantavisionai.api`), expiry checking, and constant-time signature comparison.
2. **Server-Derived Tenant Identity:** Deprecate client-controlled `X-Tenant-ID` for actor identification. The authenticated actor identity (`sub`), assigned tenant (`tenant_id`), and role (`role`: `VIEWER`, `OPERATOR`, `ADMIN`) are extracted exclusively from cryptographically verified tokens.
3. **Role-Based REST Authorization (RBAC):** Hierarchical permission enforcement across read-only queries (`VIEWER`), mutating operations (`OPERATOR`), and administrative functions (`ADMIN`), with explicit public exemptions strictly bounded to `/health` and `/ready`.
4. **WebSocket Authentication & Tenancy Handshake:** Connection-time token validation via `protocols` subprotocol (`token.<jwt>`) or query parameter (`?token=<jwt>`), rejecting unauthorized handshakes with WebSocket close code `4401` / `4403`.
5. **Tenant-Isolated Real-Time Broadcasts:** Partitioned client registries (`Map<string, Set<WebSocket>>`), guaranteeing that telemetry, alerts, and detection events emitted on Tenant A are physically impossible to leak to Tenant B connections.
6. **Backward-Compatible Local Prototyping:** Safe developer fallbacks when running without external auth providers, allowing the existing test suite (172+ assertions) to pass 100% via test-scoped synthetic keys.

---

## 2. SOURCE OF TRUTH & RE-INSPECTION EVIDENCE

A comprehensive line-by-line inspection of current source code was conducted:

| Module / Path | Current State & Behavior | Security Defect Identified | CWE Reference |
| :--- | :--- | :--- | :--- |
| `dev-server.cjs:526-529` | `const tenantId = req.headers['x-tenant-id'] \|\| 'default';` | **Client-Controlled Tenancy:** Any untrusted client can manipulate `X-Tenant-ID` to impersonate another tenant. | CWE-639 (BOLA) |
| `dev-server.cjs:527-528` | `const actor = authHeader ? 'authenticated_user' : 'security_operator';` | **Header-Presence Check:** Checks if `Authorization` header exists without decoding or signature verification. | CWE-306 / CWE-287 |
| `dev-server.cjs:474-511` | `telemetryWss.clients.forEach(client => client.send(message));` | **Global Broadcast Leakage:** All events for all tenants are broadcast to every connected client socket. | CWE-200 (Info Disclosure) |
| `backend/app/routers/brain.py:24-28` | `get_tenant_id()` extracts header `X-Tenant-ID` and sanitizes regex. | **Trusting Client Input:** Relies entirely on client-supplied header for database partition key. | CWE-639 (BOLA) |
| `backend/app/database.py` | Tables `events`, `incidents`, `policies`, `audit_logs` use column `tenant_id TEXT`. | Data model supports tenancy, but queries rely on unsanctioned header value. | CWE-284 |
| `backend/app/brain_tools.py` | `ToolPermission` enums exist (`READ`, `OPERATOR`, `ADMIN`), but actor role is hardcoded string. | No cryptographically attested role validation before executing operational tools. | CWE-863 |
| `tests/test_api_endpoints.js` | Uses `'X-Tenant-ID': 'default'` in HTTP helper without `Authorization` bearer token. | Test assertions currently rely on unauthenticated endpoints. | Test Invariant Risk |

---

## 3. THREAT MODEL & SECURITY ATTACK VECTORS

```
                    ┌────────────────────────────────────────────────────────┐
                    │               ATTACK SURFACE & THREAT MODEL            │
                    └────────────────────────────────────────────────────────┘

  [ Attacker A ] ───( X-Tenant-ID: "tenant_defense_gov" )───► [ REST Endpoints ] ───► [ LEAKED INCIDENTS ]
       ▲                                                           │                      (CWE-639 BOLA)
       │                                                           ▼
       └────────────( Connects to ws://host/ws )──────────────► [ WebSocket ] ─────► [ CROSS-TENANT TELEMETRY ]
                                                               (No Auth/Tenant Filter)   (CWE-200 Broadcast)
```

1. **Threat 1: Cross-Tenant Data Exfiltration (BOLA / IDOR):** An attacker on tenant `tenant_civilian` passes `X-Tenant-ID: tenant_defense` and calls `GET /api/v1/incidents` or `GET /api/v1/audit/dossier`, reading classified security incident history.
2. **Threat 2: Cross-Tenant Event Manipulation:** An attacker posts synthetic intrusion events or deletes legitimate events for other tenants by forging the `X-Tenant-ID` header.
3. **Threat 3: Cross-Tenant WebSocket Eavesdropping:** A client opens a raw WebSocket connection to `/ws`. When any tenant experiences an intrusion, `broadcastRealtimeTelemetry` sends the full JSON packet to every active connection.
4. **Threat 4: Privilege Escalation on Mutating Brain Tools:** An unprivileged user triggers mutating operational tools (e.g., `resolve_incident`, `toggle_policy`, `execute_playbook`) because `actor` is assigned based solely on header presence.

---

## 4. PHASE 0 AUTHENTICATION & TENANT ISOLATION ARCHITECTURE

```
                               ┌─────────────────────────────────────────┐
                               │       PHASE 0 SECURITY FOUNDATION       │
                               └─────────────────────────────────────────┘
                                                    │
                 ┌──────────────────────────────────┴──────────────────────────────────┐
                 ▼                                                                     ▼
    [ Node.js Active Server :3000 ]                                       [ FastAPI Backend :8000 ]
     `dev-server.cjs`                                                      `backend/app/`
     ├─ Crypto Auth Guard (HS256)                                          ├─ FastAPI Depends(verify_jwt_auth)
     ├─ Server-Derived Tenancy                                             ├─ SecurityScopes RBAC
     ├─ Partitioned WebSocket Map                                          ├─ Cryptographic Verification
     │  `Map<tenantId, Set<WebSocket>>`                                    │  (PyJWT / cryptography)
     └─ Constant-Time Signature Verify                                     └─ Strict SQLite Tenant Bindings
```

### 4.1 Token Specification
- **Algorithm:** `HS256` (HMAC with SHA-256).
- **Issuer (`iss`):** `vantavisionai.internal`
- **Audience (`aud`):** `vantavisionai.api`
- **Subject (`sub`):** Unique operator ID (e.g., `usr_operator_001`)
- **Tenant ID (`tenant_id`):** Cryptographically bound tenant partition (e.g., `tenant_defense`, `default`)
- **Role (`role`):** Role designation (`VIEWER`, `OPERATOR`, `ADMIN`)
- **Expiry (`exp`):** Unix timestamp (default: 8 hours for operational shifts)
- **Issued At (`iat`):** Unix timestamp

### 4.2 Key Management & Safe Credential Rotation
- Primary signing key read from environment variable `VANTA_JWT_SECRET`.
- Secondary verification key supported via `VANTA_JWT_PREVIOUS_SECRET` to enable zero-downtime rotation.
- In prototype/test mode, if `VANTA_JWT_SECRET` is unset, a deterministic fallback test secret is generated and logged with high-visibility security warnings, preventing hardcoded secrets in source code while maintaining local test execution.

---

## 5. FILE-BY-FILE IMPLEMENTATION SPECIFICATION

### Target File 1: `backend/app/auth.py` (New Module)

#### 1. Existing Behavior
File does not exist. Authentication and tenant resolution are ad-hoc across router functions.

#### 2. Security Defect
No centralized cryptographic token parser or RBAC dependency for FastAPI.

#### 3. Required Change
Create `backend/app/auth.py` providing:
- `verify_jwt_token(token: str) -> AuthContext`
- `get_current_actor(security_scopes: SecurityScopes, authorization: Optional[str] = Header(None)) -> AuthContext`
- Constant-time signature check.
- `AuthContext` model containing `actor_id`, `tenant_id`, `role`, and `scopes`.

#### 4. Exact Implementation Location
New file `/backend/app/auth.py`.

#### 5. Dependencies
`pydantic`, `hashlib`, `hmac`, `base64`, `json`, `os`, `time`. Zero external binary dependencies; utilizes Python standard library for zero-footprint compatibility.

#### 6. Regression Risk
None on existing unit tests as long as a synthetic testing mode is provided for legacy automated test suites.

#### 7. Backup Procedure
New file, no backup required.

#### 8. Unit Tests
Add `test_auth_token_validation()`, `test_expired_token()`, `test_signature_mismatch()`, `test_role_enforcement()`.

#### 9. Integration Tests
Assert `HTTP 401` on `/api/v1/events` without token; assert `HTTP 200` with valid synthetic token.

#### 10. Acceptance Criteria
Valid token decodes actor and tenant; invalid signature returns `HTTP 401 Unauthorized`.

#### 11. Rollback Procedure
Delete `backend/app/auth.py`.

---

### Target File 2: `dev-server.cjs`

#### 1. Existing Behavior
Lines 526–529 derive `tenantId` directly from `req.headers['x-tenant-id'] || 'default'`. Lines 476–488 broadcast telemetry to all connected WebSocket clients globally.

#### 2. Security Defect
CWE-639 (BOLA) and CWE-200 (Cross-tenant telemetry exposure).

#### 3. Required Change
1. Implement native Node `verifyJwtToken(authHeader)` using standard `crypto` module (`crypto.createHmac('sha256', secret)`).
2. Check token on all `/api/v1/*` routes except `/health` and `/ready`.
3. Extract `tenantId = authContext.tenant_id` and `actor = authContext.actor_id`.
4. Refactor `telemetryWss` to maintain a partitioned map:
   ```javascript
   const tenantClientMap = new Map(); // tenantId -> Set<WebSocket>
   ```
5. In `broadcastRealtimeTelemetry(eventType, payload, tenantId)`, push packets **only** to `tenantClientMap.get(tenantId)`.
6. Authenticate WebSocket upgrade handshakes on `/ws` using token passed via `Sec-WebSocket-Protocol` (`token.<jwt>`) or URL query param `?token=<jwt>`.

#### 4. Exact Implementation Location
- Lines 474–511: WebSocket server connection logic and broadcast handler.
- Lines 513–530: Server request pipeline, auth extraction, and route guard dispatch.

#### 5. Dependencies
Native Node.js `crypto`, `url`, `ws`.

#### 6. Regression Risk
Existing tests in `tests/test_api_endpoints.js` make requests without tokens.  
*Mitigation:* Introduce a dual-mode test bypass: if `process.env.NODE_ENV === 'test'` and no token is supplied, bind to `tenant_id: 'default'` and `role: 'ADMIN'` with a logged audit notice, or update test helper to generate a valid test JWT signed by the test secret.

#### 7. Backup Procedure
Create snapshot backup copy `dev-server.cjs.phase0.bak` prior to modification.

#### 8. Unit Tests
Unit test signature verification, expired token rejection, and malformed header parsing.

#### 9. Integration Tests
Test suite in `tests/test_api_endpoints.js` updated to verify:
- Anonymous request rejected with 401.
- Valid JWT accepted with 200.
- Tampered JWT rejected with 401.
- Cross-tenant spoofing rejected.

#### 10. Acceptance Criteria
- Anonymous requests to `/api/v1/*` return 401.
- `broadcastRealtimeTelemetry` delivers messages only to the matching tenant's sockets.

#### 11. Rollback Procedure
Restore `dev-server.cjs` from `dev-server.cjs.phase0.bak`.

---

### Target File 3: `backend/app/routers/brain.py`

#### 1. Existing Behavior
Lines 24–28 define `get_tenant_id(x_tenant_id: Optional[str] = Header(None))` which blindly trusts the client header.

#### 2. Security Defect
CWE-639 (BOLA). Client can pass any arbitrary tenant ID string.

#### 3. Required Change
Replace `get_tenant_id` with `get_verified_auth_context(auth_ctx: AuthContext = Depends(verify_jwt_auth))`.  
Derive `tenant_id` strictly from `auth_ctx.tenant_id`.

#### 4. Exact Implementation Location
Lines 24–45 in `backend/app/routers/brain.py`.

#### 5. Dependencies
`backend.app.auth.verify_jwt_auth`, `backend.app.auth.AuthContext`.

#### 6. Regression Risk
Breaking Python `unittest` suite (`tests/test_brain.py`).  
*Mitigation:* Provide default test token generator for unit tests.

#### 7. Backup Procedure
Backup `backend/app/routers/brain.py` to `backend/app/routers/brain.py.phase0.bak`.

#### 8. Unit Tests
Assert `BrainService.process_command` receives server-validated tenant.

#### 9. Integration Tests
Verify unauthorized commands receive 401; cross-tenant commands cannot mutate foreign tenant state.

#### 10. Acceptance Criteria
No endpoint consumes unverified `X-Tenant-ID`.

#### 11. Rollback Procedure
Restore from `brain.py.phase0.bak`.

---

### Target File 4: `backend/app/routers/events.py`

#### 1. Existing Behavior
`list_events` and `create_event` depend on `get_tenant_id` from `brain.py`.

#### 2. Security Defect
Events can be injected or read across tenant boundaries by changing `X-Tenant-ID`.

#### 3. Required Change
Bind queries to `auth_ctx.tenant_id`. Check `auth_ctx.role` in `create_event` (`OPERATOR` or `ADMIN` required).

#### 4. Exact Implementation Location
Lines 14–60 in `backend/app/routers/events.py`.

#### 5. Dependencies
`backend.app.auth`.

#### 6. Regression Risk
Low. Existing database query parameters (`WHERE tenant_id = ?`) remain unchanged, but the value is securely sourced.

#### 7. Backup Procedure
Backup to `backend/app/routers/events.py.phase0.bak`.

#### 8. Unit Tests
Test cross-tenant event creation isolation.

#### 9. Integration Tests
Test that Tenant B cannot see events inserted by Tenant A.

#### 10. Acceptance Criteria
Database queries strictly parameterized with authenticated tenant ID.

#### 11. Rollback Procedure
Restore from backup file.

---

### Target File 5: `backend/app/routers/incidents.py`

#### 1. Existing Behavior
`resolve_incident` verifies `WHERE id = ? AND tenant_id = ?`, but `tenant_id` is derived from unverified header.

#### 2. Security Defect
An unauthenticated user can resolve incidents of another tenant by spoofing the header.

#### 3. Required Change
Bind `tenant_id` to `auth_ctx.tenant_id`. Require `auth_ctx.role in ['OPERATOR', 'ADMIN']` to resolve incidents.

#### 4. Exact Implementation Location
Lines 10–72 in `backend/app/routers/incidents.py`.

#### 5. Dependencies
`backend.app.auth`.

#### 6. Regression Risk
Zero risk to business logic; reinforces authorization check.

#### 7. Backup Procedure
Backup to `backend/app/routers/incidents.py.phase0.bak`.

#### 8. Unit Tests
Attempt to resolve incident with `VIEWER` role; verify rejection with 403 Forbidden.

#### 9. Integration Tests
Attempt cross-tenant resolution; verify 404 or 403.

#### 10. Acceptance Criteria
Resolution requires verified `OPERATOR` or `ADMIN` role on the owning tenant.

#### 11. Rollback Procedure
Restore from backup file.

---

### Target File 6: `backend/app/routers/policies.py`

#### 1. Existing Behavior
`create_policy`, `toggle_policy`, and `delete_policy` use client-supplied `tenant_id`.

#### 2. Security Defect
Unauthenticated users can toggle, disable, or delete critical security policies.

#### 3. Required Change
Bind to `auth_ctx.tenant_id`. Require `ADMIN` role for policy creation and deletion; require `OPERATOR` or `ADMIN` for toggle.

#### 4. Exact Implementation Location
Lines 10–120 in `backend/app/routers/policies.py`.

#### 5. Dependencies
`backend.app.auth`.

#### 6. Regression Risk
Low.

#### 7. Backup Procedure
Backup to `backend/app/routers/policies.py.phase0.bak`.

#### 8. Unit Tests
Verify role matrix (`VIEWER` cannot toggle policies).

#### 9. Integration Tests
Verify policies created under Tenant A do not appear in Tenant B policy lists.

#### 10. Acceptance Criteria
Mutations restricted to authorized roles.

#### 11. Rollback Procedure
Restore from backup file.

---

### Target File 7: `backend/app/routers/copilot.py`

#### 1. Existing Behavior
Telemetry context aggregation queries (`SELECT COUNT(*) FROM events WHERE tenant_id = ?`) rely on client header.

#### 2. Security Defect
Copilot intelligence reports can be generated against foreign tenant data by spoofing header.

#### 3. Required Change
Extract `tenant_id` from `auth_ctx.tenant_id`. Ground all SQL queries exclusively in the authenticated tenant.

#### 4. Exact Implementation Location
Lines 20–60 in `backend/app/routers/copilot.py`.

#### 5. Dependencies
`backend.app.auth`.

#### 6. Regression Risk
Zero risk to LLM or deterministic fallback logic.

#### 7. Backup Procedure
Backup to `backend/app/routers/copilot.py.phase0.bak`.

#### 8. Unit Tests
Verify Copilot context queries restrict to authenticated tenant.

#### 9. Integration Tests
Assert Copilot response does not contain incident details from foreign tenants.

#### 10. Acceptance Criteria
Copilot evidence and findings reflect solely the verified tenant.

#### 11. Rollback Procedure
Restore from backup file.

---

### Target File 8: `static/app.js`

#### 1. Existing Behavior
`STATE.tenantId = 'default'`. All `fetch` calls attach `headers: { 'X-Tenant-ID': STATE.tenantId }`. `initTelemetryWebSocket()` connects to `ws://${location.host}/ws` with no token.

#### 2. Security Defect
Client assumes it can pick any tenant ID; transmits unauthenticated WebSocket connections.

#### 3. Required Change
1. Implement client-side `AUTH_MANAGER` storing active session token (`localStorage.getItem('vanta_auth_token')` or default session token).
2. Attach `Authorization: Bearer <token>` to all `fetch` requests via a central `secureFetch()` wrapper.
3. Update `initTelemetryWebSocket()` to pass token in connection URL or `protocols`:
   ```javascript
   const ws = new WebSocket(`${wsUrl}?token=${encodeURIComponent(AUTH_MANAGER.getToken())}`);
   ```
4. Handle `401 Unauthorized` responses by prompting for re-authentication or switching to test credentials.

#### 4. Exact Implementation Location
- Lines 120–150 (State and Auth initialization).
- Lines 5724–5782 (`initTelemetryWebSocket`).
- All API fetch helpers (`fetchEvents`, `fetchIncidents`, `fetchSummary`, `fetchAuditLogs`).

#### 5. Dependencies
Standard browser Web APIs (`localStorage`, `fetch`, `WebSocket`).

#### 6. Regression Risk
Breaking UI when server enforces authentication.  
*Mitigation:* Pre-seed a default development demo token on boot so the UI runs seamlessly out-of-the-box in prototype mode.

#### 7. Backup Procedure
Backup `static/app.js` to `static/app.js.phase0.bak`.

#### 8. Unit Tests
Validate token storage and `secureFetch` header attachment.

#### 9. Integration Tests
Verify scanner detections and voice commands successfully transmit bearer token.

#### 10. Acceptance Criteria
WebSocket connects with token; HTTP requests include Authorization header; UI updates live.

#### 11. Rollback Procedure
Restore from `static/app.js.phase0.bak`.

---

## 6. COMPREHENSIVE TEST PLAN & ACCEPTANCE MATRIX

The test suite will execute synthetic tests against temporary in-memory sessions without altering persistent production records.

| Test ID | Scenario | Input / Action | Expected Result | Acceptance Threshold |
| :--- | :--- | :--- | :--- | :--- |
| **SEC-01** | Missing Credentials | `GET /api/v1/events` without `Authorization` header | HTTP 401 Unauthorized | Response status == 401, error code == `AUTH_REQUIRED` |
| **SEC-02** | Invalid Signature | `GET /api/v1/incidents` with forged HMAC signature | HTTP 401 Unauthorized | Response status == 401, error code == `INVALID_TOKEN` |
| **SEC-03** | Expired Token | `GET /api/v1/system` with `exp` in the past | HTTP 401 Unauthorized | Response status == 401, error code == `TOKEN_EXPIRED` |
| **SEC-04** | Invalid Issuer / Audience | Token with `iss: malicious.site` | HTTP 401 Unauthorized | Response status == 401, error code == `INVALID_ISSUER` |
| **SEC-05** | Role Restriction | `POST /api/v1/policies` with `role: VIEWER` token | HTTP 403 Forbidden | Response status == 403, error code == `INSUFFICIENT_PERMISSIONS` |
| **SEC-06** | Tenant Spoofing Bypass | Token issued for `tenant_alpha` sent with `X-Tenant-ID: tenant_beta` | System ignores header, serves `tenant_alpha` only | Returned records strictly match `tenant_alpha` |
| **SEC-07** | Cross-Tenant REST | Operator A queries Incident #inc_beta belonging to Tenant B | HTTP 404 Not Found or 403 Forbidden | Zero cross-tenant data returned |
| **SEC-08** | Unauthenticated WebSocket | Client connects to `ws://localhost:3000/ws` without token | WebSocket closed by server with code 4401 | Connection immediately terminated |
| **SEC-09** | Tenant WebSocket Broadcast | Event generated on Tenant A; client connected as Tenant B | Packet received ONLY by Tenant A client | Tenant B client receives 0 messages |
| **SEC-10** | Existing Scanner Continuity | Live webcam or test feed running object detection | Bounding boxes render; local events recorded | 10–14 FPS local inference maintained |
| **SEC-11** | Existing Brain Parity | Execute allowlisted commands (`help`, `status`, `summary`) | Commands succeed under verified tenant | All 15 tools operate under verified RBAC |
| **SEC-12** | Test Suite Invariant Gate | Execute `npm test` across all 172+ assertions | 100% tests pass | 0 failures, 0 regressions |

---

## 7. BACKWARD COMPATIBILITY & TEST INVARIANT PRESERVATION

To guarantee that not a single test in `npm test` fails during or after Phase 0 rollout:
1. **Automated Test Token Injector:** The test harness helper in `tests/test_api_endpoints.js` will be augmented with a local JWT signing utility using the shared test secret (`TEST_SECRET_KEY_FOR_LOCAL_DEV_ONLY`).
2. **Exempt Public Endpoints:** `/health` and `/ready` remain public and exempt from token checks to satisfy container health checks and uptime probes.
3. **Graceful Fallback Mode:** In development mode (`ENVIRONMENT=prototype`), if an unauthenticated request originates from `127.0.0.1` and `ENABLE_DEV_ANONYMOUS_FALLBACK=true`, the server assigns the default prototype operator context (`tenant_id: default`, `role: ADMIN`) with a high-priority audit warning log:
   ```json
   {
     "action": "AUTH_DEV_FALLBACK_USED",
     "actor": "anonymous_local_dev",
     "status": "WARNING",
     "details": "Unauthenticated local request permitted under prototype fallback mode."
   }
   ```
   This ensures developer agility while enforcing strict token validation whenever `NODE_ENV === 'production'`.

---

## 8. SUMMARY OF TARGET FILES TO MODIFY

Upon user approval of this plan, the following files will be modified in place:

1. `/backend/app/auth.py` *(New File — Centralized JWT & RBAC Engine)*
2. `/dev-server.cjs` *(Active Node Serving Server — Auth Guard, Token Parser, Partitioned WS)*
3. `/backend/app/routers/brain.py` *(FastAPI Brain Router — Server-derived tenant dependency)*
4. `/backend/app/routers/events.py` *(FastAPI Events Router — RBAC & Tenant Binding)*
5. `/backend/app/routers/incidents.py` *(FastAPI Incidents Router — Role check & Tenant Binding)*
6. `/backend/app/routers/policies.py` *(FastAPI Policies Router — Role check & Tenant Binding)*
7. `/backend/app/routers/copilot.py` *(FastAPI Copilot Router — Tenant Context Binding)*
8. `/backend/app/routers/audit.py` *(FastAPI Audit Router — Authenticated Forensic Dossier)*
9. `/backend/app/routers/demo.py` *(FastAPI Demo Router — Role & Tenant Binding)*
10. `/static/app.js` *(Frontend Client — Secure Fetch Wrapper & Authenticated WebSocket)*
11. `/tests/test_api_endpoints.js` *(Integration Test Suite — Authenticated Request Harness)*

---

## 9. EXACT VERIFICATION CRITERIA

Before declaring Phase 0 complete, the following four verification gates must be satisfied:

1. **Gate 1: Syntax & Compilation**
   - `npm run check:syntax` exits with status `0`.
   - `npm run check:types` (`tsc --noEmit`) reports `0 errors`.
2. **Gate 2: Security Assertions**
   - 12 new automated security tests (SEC-01 through SEC-12) pass with 100% compliance.
   - Cross-tenant requests produce zero leaked records.
   - Cross-tenant WebSocket broadcasts deliver zero cross-tenant messages.
3. **Gate 3: Legacy Test Invariant**
   - `npm test` executes all existing test suites (`test_api_endpoints.js`, `test_aleana_voice.js`, `test_multi_object_detection.js`, `test_copilot_multi_detection.js`, `test_firebase_integration.js`, and `test_brain.py`) with **172/172 assertions passing (100%)**.
4. **Gate 4: Twin-File Hash Parity**
   - `sha256sum index.html static/index.html` matches identically.
   - `sha256sum static/style.css static/styles.css` matches identically.

---

### STOP CONDITION ENFORCEMENT
*Planning mode active. Zero files modified. Zero database mutations executed. Awaiting user approval to proceed with Phase 0 implementation.*
