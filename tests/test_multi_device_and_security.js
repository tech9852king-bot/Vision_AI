/**
 * VantaVisionAI — Multi-Device Fleet, Zero-Trust JWT, Polygon Zones & 9-Layer Brain Test Suite
 */
const http = require('http');
const fs = require('fs');
const path = require('path');

global.window = {
  addEventListener: () => {},
  removeEventListener: () => {},
  localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
  location: { protocol: 'http:', host: '127.0.0.1:3000', origin: 'http://127.0.0.1:3000' }
};
const dummyElem = {
  id: 'mock',
  style: {},
  classList: { add: () => {}, remove: () => {}, toggle: () => {} },
  addEventListener: () => {},
  removeEventListener: () => {},
  querySelectorAll: () => [],
  getContext: () => ({
    clearRect: () => {},
    fillRect: () => {},
    strokeRect: () => {},
    beginPath: () => {},
    moveTo: () => {},
    lineTo: () => {},
    stroke: () => {},
    fill: () => {},
    fillText: () => {},
    setLineDash: () => {},
    arc: () => {}
  })
};
global.document = {
  getElementById: (id) => ({ ...dummyElem, id }),
  createElement: () => ({ ...dummyElem }),
  querySelector: () => ({ ...dummyElem }),
  querySelectorAll: () => [],
  addEventListener: () => {},
  documentElement: { setAttribute: () => {} }
};

const { isPointInPolygon, STATE, setDashboardAutoRefresh } = require('../static/app.js');

const PORT = 3000;
let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`  ✅ PASS: ${message}`);
    passed++;
  } else {
    console.error(`  ❌ FAIL: ${message}`);
    failed++;
  }
}

function request(method, reqPath, body = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const reqHeaders = {
      'Content-Type': 'application/json',
      ...headers
    };
    if (payload) {
      reqHeaders['Content-Length'] = Buffer.byteLength(payload);
    }

    const req = http.request(
      { hostname: '127.0.0.1', port: PORT, path: reqPath, method, headers: reqHeaders },
      (res) => {
        let raw = '';
        res.on('data', (chunk) => (raw += chunk));
        res.on('end', () => {
          let json = null;
          try {
            json = JSON.parse(raw);
          } catch (_) {}
          resolve({ status: res.statusCode, headers: res.headers, raw, json });
        });
      }
    );
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function runTests() {
  console.log('\n============================================================');
  console.log(' VantaVisionAI — Multi-Device, Security & Polygon Zone Tests');
  console.log('============================================================\n');

  // 1. Dockerfile, .dockerignore, PWA files existence
  console.log('--- 1. Container & PWA Artifact Integrity ---');
  const rootDir = path.join(__dirname, '..');
  assert(fs.existsSync(path.join(rootDir, 'Dockerfile')), 'Root Dockerfile exists for docker-compose build');
  assert(fs.existsSync(path.join(rootDir, '.dockerignore')), 'Root .dockerignore exists');
  assert(fs.existsSync(path.join(rootDir, 'static', 'manifest.json')), 'static/manifest.json exists');
  assert(fs.existsSync(path.join(rootDir, 'static', 'sw.js')), 'static/sw.js exists');

  const manifestRes = await request('GET', '/manifest.json');
  assert(manifestRes.status === 200 && manifestRes.json?.name?.includes('VantaVisionAI'), 'GET /manifest.json returns 200 with valid PWA manifest');

  const swRes = await request('GET', '/sw.js');
  assert(swRes.status === 200 && swRes.raw.includes('vantavisionai-pwa'), 'GET /sw.js returns 200 with Service Worker script');

  // 2. Zero-Trust HS256 JWT Session & Tamper Rejection
  console.log('\n--- 2. Zero-Trust HS256 JWT Authentication ---');
  const sessionRes = await request('GET', '/api/v1/auth/session', null, { 'X-Tenant-ID': 'default' });
  assert(sessionRes.status === 200 && typeof sessionRes.json?.token === 'string', 'GET /api/v1/auth/session issues signed HS256 JWT');
  const validJwt = sessionRes.json.token;

  const tamperedJwt = validJwt.slice(0, -4) + 'XXXX';
  const tamperedBrainRes = await request(
    'POST',
    '/api/v1/brain/execute',
    { command: 'status' },
    { Authorization: `Bearer ${tamperedJwt}` }
  );
  assert(tamperedBrainRes.status === 401, 'Tampered Bearer JWT is rejected with 401 Unauthorized');

  // 3. Multi-Device Inventory, Single-Use QR Pairing, Heartbeat & Revocation
  console.log('\n--- 3. Multi-Device Onboarding & Single-Use Pairing ---');
  const devicesRes = await request('GET', '/api/v1/devices', null, { Authorization: `Bearer ${validJwt}` });
  assert(devicesRes.status === 200 && Array.isArray(devicesRes.json?.items) && devicesRes.json.items.length >= 3, 'GET /api/v1/devices returns seeded multi-device fleet');

  const pairCreateRes = await request(
    'POST',
    '/api/v1/devices/pairing/create',
    { role: 'mobile_camera', ttl_seconds: 300 },
    { Authorization: `Bearer ${validJwt}` }
  );
  assert(pairCreateRes.status === 201 && typeof pairCreateRes.json?.pairing_code === 'string', 'POST /api/v1/devices/pairing/create generates single-use pairing code');
  const pairingCode = pairCreateRes.json.pairing_code;

  const pairClaimRes = await request('POST', '/api/v1/devices/pairing/claim', {
    pairing_code: pairingCode,
    name: 'Test Patrol iPhone 16 Pro',
    facing_mode: 'environment'
  });
  assert(pairClaimRes.status === 200 && pairClaimRes.json?.device?.device_id, 'POST /api/v1/devices/pairing/claim pairs new mobile camera device and issues device JWT');
  const pairedDeviceId = pairClaimRes.json.device.device_id;

  const replayClaimRes = await request('POST', '/api/v1/devices/pairing/claim', {
    pairing_code: pairingCode,
    name: 'Replay Attacker Device'
  });
  assert(replayClaimRes.status === 409, 'Replaying a claimed single-use pairing code returns 409 Conflict');

  const hbRes = await request(
    'POST',
    `/api/v1/devices/${pairedDeviceId}/heartbeat`,
    { status: 'ONLINE', fps: 28.5, latency_ms: 14.2, battery_pct: 91 },
    { Authorization: `Bearer ${validJwt}` }
  );
  assert(hbRes.status === 200 && hbRes.json?.device?.fps === 28.5, 'POST /api/v1/devices/:id/heartbeat updates device telemetry');

  const revokeRes = await request(
    'POST',
    `/api/v1/devices/${pairedDeviceId}/revoke`,
    {},
    { Authorization: `Bearer ${validJwt}` }
  );
  assert(revokeRes.status === 200 && revokeRes.json?.status === 'REVOKED', 'POST /api/v1/devices/:id/revoke revokes device access');

  // 4. Idempotent Event Ingestion & Provenance Fields
  console.log('\n--- 4. Idempotent Event Ingestion & Provenance ---');
  const uniqueEventId = `evt-test-idemp-${Date.now()}`;
  const evPayload = {
    event_id: uniqueEventId,
    camera_id: 'CAM-01-ENTRANCE',
    device_id: 'DEV-EDGE-ALPHA',
    track_id: 'TRK-701',
    zone_id: 'ZONE-ENTRANCE-01',
    class_name: 'person',
    confidence: 0.91,
    bbox: [120, 80, 90, 180],
    detection_model: 'COCO-SSD-MobileNetV2',
    processing_device: 'edge_camera_node',
    processing_latency_ms: 16.4
  };
  const evRes1 = await request('POST', '/api/v1/events', evPayload, { Authorization: `Bearer ${validJwt}` });
  const evRes2 = await request('POST', '/api/v1/events', evPayload, { Authorization: `Bearer ${validJwt}` });
  assert(
    [200, 201].includes(evRes1.status) &&
    [200, 201].includes(evRes2.status) &&
    evRes1.json?.id === evRes2.json?.id,
    'POST /api/v1/events deduplicates identical event_id idempotently'
  );
  assert(evRes1.json?.device_id === 'DEV-EDGE-ALPHA' && evRes1.json?.zone_id === 'ZONE-ENTRANCE-01', 'Event response preserves device_id and zone_id provenance');

  // 5. Polygon Zone Intelligence & Ray-Casting Math
  console.log('\n--- 5. Spatial Polygon Zone Intelligence & Correlations ---');
  const testPoly = [
    { x: 0.2, y: 0.2 },
    { x: 0.8, y: 0.2 },
    { x: 0.8, y: 0.8 },
    { x: 0.2, y: 0.8 }
  ];
  assert(isPointInPolygon({ x: 0.5, y: 0.5 }, testPoly) === true, 'isPointInPolygon returns true for interior point');
  assert(isPointInPolygon({ x: 0.05, y: 0.05 }, testPoly) === false, 'isPointInPolygon returns false for exterior point');

  const zonesRes = await request('GET', '/api/v1/zones', null, { Authorization: `Bearer ${validJwt}` });
  assert(zonesRes.status === 200 && Array.isArray(zonesRes.json?.items) && zonesRes.json.items.length >= 3, 'GET /api/v1/zones returns spatial polygon zones');

  const createZoneRes = await request(
    'POST',
    '/api/v1/zones',
    {
      name: 'Test Server Rack Polygon',
      camera_id: 'CAM-02-LOBBY',
      zone_type: 'restricted',
      polygon: testPoly,
      target_classes: ['person'],
      dwell_threshold_sec: 10,
      severity: 'CRITICAL'
    },
    { Authorization: `Bearer ${validJwt}` }
  );
  assert(createZoneRes.status === 201 && createZoneRes.json?.zone_id, 'POST /api/v1/zones creates new polygon zone');

  const delZoneRes = await request('DELETE', `/api/v1/zones/${createZoneRes.json.zone_id}`, null, { Authorization: `Bearer ${validJwt}` });
  assert(delZoneRes.status === 200 && delZoneRes.json?.deleted === true, 'DELETE /api/v1/zones/:id removes polygon zone');

  const corrRes = await request('GET', '/api/v1/correlations', null, { Authorization: `Bearer ${validJwt}` });
  assert(corrRes.status === 200 && Array.isArray(corrRes.json?.correlations), 'GET /api/v1/correlations returns cross-camera correlation list');

  // 6. 9-Layer Brain Execution & New Allowlisted Commands
  console.log('\n--- 6. 9-Layer Vanta Brain & Multi-Device Tooling ---');
  for (const cmd of ['devices', 'zones', 'correlations']) {
    const bRes = await request('POST', '/api/v1/brain/execute', { command: cmd }, { Authorization: `Bearer ${validJwt}` });
    assert(
      bRes.status === 200 &&
      bRes.json?.status === 'SUCCESS' &&
      Array.isArray(bRes.json?.pipeline_trace) &&
      bRes.json.pipeline_trace.length === 9 &&
      Array.isArray(bRes.json?.verified_facts),
      `Brain command "${cmd}" executes across all 9 layers with structured verified_facts`
    );
  }

  // 7. Dashboard Header Auto-Refresh Toggle Switch
  console.log('\n--- 7. Dashboard Header Auto-Refresh Toggle Switch ---');
  const htmlContent = fs.readFileSync(path.join(rootDir, 'static', 'index.html'), 'utf8');
  assert(
    htmlContent.includes('id="dashboard-auto-refresh-toggle"') &&
    htmlContent.includes('id="dashboard-auto-refresh-label"'),
    'Dashboard header includes #dashboard-auto-refresh-toggle switch and label'
  );
  assert(setDashboardAutoRefresh(false, false) === false && STATE.dashboardAutoRefresh === false, 'setDashboardAutoRefresh(false) disables automatic KPI & recent events polling');
  assert(setDashboardAutoRefresh(true, false) === true && STATE.dashboardAutoRefresh === true, 'setDashboardAutoRefresh(true) re-enables automatic KPI & recent events polling');

  // 8. 25-Tool Vanta Brain Registry Introspection & Execution
  console.log('\n--- 8. 25-Tool Vanta Brain Registry & Tool Execution ---');
  const toolsRes = await request('GET', '/api/v1/brain/tools', null, { Authorization: `Bearer ${validJwt}` });
  assert(
    toolsRes.status === 200 && Array.isArray(toolsRes.json?.tools) && toolsRes.json.tools.length >= 25,
    `GET /api/v1/brain/tools returns complete approved registry (${toolsRes.json?.tools?.length || 0} tools >= 25)`
  );

  const twinToolRes = await request(
    'POST',
    '/api/v1/brain/tools/synthesize_spatial_twin',
    { args: { include_zones: true } },
    { Authorization: `Bearer ${validJwt}` }
  );
  assert(
    twinToolRes.status === 200 && twinToolRes.json?.data?.twin_version === '2.0-NEXUS',
    'POST /api/v1/brain/tools/synthesize_spatial_twin executes 2D tactical spatial layout'
  );

  const forensicToolRes = await request(
    'POST',
    '/api/v1/brain/tools/replay_forensic_timeline',
    { args: { limit: 10 } },
    { Authorization: `Bearer ${validJwt}` }
  );
  assert(
    forensicToolRes.status === 200 && forensicToolRes.json?.data?.scrubbing_mode === 'CIRCULAR_BUFFER_SYNCHRONIZED',
    'POST /api/v1/brain/tools/replay_forensic_timeline extracts historical telemetry'
  );

  // 9. Digital Twin & Forensic Time-Machine Buffering
  console.log('\n--- 9. Digital Twin & Forensic Time-Machine Replay ---');
  assert(
    htmlContent.includes('id="digital-twin-canvas"') &&
    htmlContent.includes('id="forensic-replay-canvas"') &&
    htmlContent.includes('id="forensic-timeline-slider"'),
    'HTML templates include #digital-twin-canvas, #forensic-replay-canvas, and #forensic-timeline-slider'
  );
  const appModule = require(path.join(rootDir, 'static', 'app.js'));
  assert(typeof appModule.recordForensicFrame === 'function', 'app.js exports recordForensicFrame function');
  appModule.recordForensicFrame([
    { trackId: 999, class: 'person', score: 0.95, bbox: [50, 50, 100, 200], category: 'person' }
  ]);
  assert(
    Array.isArray(appModule.STATE.forensicBuffer) && appModule.STATE.forensicBuffer.length > 0,
    'recordForensicFrame appends frame to circular telemetry buffer'
  );

  console.log(`\n============================================================`);
  console.log(` Results: ${passed} Passed, ${failed} Failed`);
  console.log(`============================================================\n`);

  if (failed > 0) {
    process.exit(1);
  }
  process.exit(0);
}

runTests().catch((err) => {
  console.error('Fatal test runner error:', err);
  process.exit(1);
});
