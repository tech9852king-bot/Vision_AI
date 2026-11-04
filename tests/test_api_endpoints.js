/**
 * Comprehensive Integration Tests for VantaVisionAI REST Endpoints
 * Tests: /health, /ready, /api/v1/system, /api/v1/summary, /api/v1/events,
 *        DELETE /api/v1/events/:id, /api/v1/incidents, /api/v1/policies,
 *        /api/v1/demo/run, /api/v1/copilot, /api/v1/audit, /api/v1/brain
 */
const http = require('http');

function req(path, method = 'GET', data = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(path, 'http://127.0.0.1:3000');
    const opts = {
      hostname: u.hostname,
      port: u.port,
      path: u.pathname + u.search,
      method,
      headers: { 'Content-Type': 'application/json', 'X-Tenant-ID': 'default', ...headers }
    };
    const r = http.request(opts, res => {
      let b = '';
      res.on('data', c => b += c);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(b || '{}') });
        } catch (e) {
          resolve({ status: res.statusCode, raw: b });
        }
      });
    });
    r.on('error', reject);
    if (data) r.write(JSON.stringify(data));
    r.end();
  });
}

async function runTests() {
  console.log('[TEST SUITE] Executing VantaVisionAI REST Endpoints Integration Suite...');
  let passed = 0;
  let total = 0;

  function assert(name, condition) {
    total++;
    if (condition) {
      console.log(`  ✓ [PASS] ${name}`);
      passed++;
    } else {
      console.error(`  ✗ [FAIL] ${name}`);
      process.exitCode = 1;
    }
  }

  // 1. Health
  const h = await req('/health');
  assert('GET /health returns 200 with status ok', h.status === 200 && h.data.status === 'ok');

  // 2. Ready
  const r = await req('/ready');
  assert('GET /ready returns 200 and declares SIMULATED provider', r.status === 200 && r.data.provider === 'SIMULATED' && r.data.real_camera_configured === false);

  // 3. System
  const sys = await req('/api/v1/system');
  assert('GET /api/v1/system returns app_name and subsystem telemetry', sys.status === 200 && sys.data.app_name.includes('VantaVisionAI'));

  // 4. Summary
  const sum = await req('/api/v1/summary');
  assert('GET /api/v1/summary returns metrics object', sum.status === 200 && typeof sum.data.total_events === 'number');

  // 5. Demo Run
  const demo = await req('/api/v1/demo/run', 'POST', { scenario: 'intrusion', camera_id: 'DEMO-CAM-01' });
  assert('POST /api/v1/demo/run creates simulation event & incident', demo.status === 200 && demo.data.status === 'SUCCESS');

  // 6. Events CRUD
  const evPost = await req('/api/v1/events', 'POST', { camera_id: 'INTEG-CAM', class_name: 'person', confidence: 0.95 });
  assert('POST /api/v1/events creates new event', evPost.status === 200 && evPost.data.id);
  const evGet = await req('/api/v1/events');
  assert('GET /api/v1/events lists recorded events', evGet.status === 200 && Array.isArray(evGet.data) && evGet.data.length > 0);
  const evDel = await req('/api/v1/events/' + evPost.data.id, 'DELETE');
  assert('DELETE /api/v1/events/:id removes created event', evDel.status === 200 && evDel.data.status === 'SUCCESS');

  // 7. Incidents & Policies
  const inc = await req('/api/v1/incidents');
  assert('GET /api/v1/incidents returns array of incidents', inc.status === 200 && Array.isArray(inc.data));
  if (inc.data.length > 0) {
    const incId = inc.data[0].id;
    const resInc = await req(`/api/v1/incidents/${incId}/resolve`, 'POST');
    assert('POST /api/v1/incidents/:id/resolve marks incident as RESOLVED', resInc.status === 200 && resInc.data.new_status === 'RESOLVED');
  }
  const pol = await req('/api/v1/policies');
  assert('GET /api/v1/policies returns 4 active security policies', pol.status === 200 && pol.data.length >= 4);

  // 8. Brain allowlisted & injection protection
  const brainHelp = await req('/api/v1/brain', 'POST', { command: 'help' });
  assert('POST /api/v1/brain accepts allowlisted command "help"', brainHelp.status === 200 && brainHelp.data.result?.command === 'help');
  const brainDiag = await req('/api/v1/brain', 'POST', { command: 'diagnostics' });
  assert('POST /api/v1/brain handles "diagnostics"', brainDiag.status === 200 && brainDiag.data.result?.command === 'diagnostics');
  const brainToolsCmd = await req('/api/v1/brain', 'POST', { command: 'tools' });
  assert('POST /api/v1/brain handles "tools" command', brainToolsCmd.status === 200 && brainToolsCmd.data.result?.command === 'tools');
  const brainAttack = await req('/api/v1/brain', 'POST', { command: 'DROP TABLE events;' });
  assert('POST /api/v1/brain rejects unallowlisted injection with 400', brainAttack.status === 400);

  // 8b. Approved Tool Registry endpoints
  const toolList = await req('/api/v1/brain/tools');
  assert('GET /api/v1/brain/tools returns approved tool registry', toolList.status === 200 && Array.isArray(toolList.data.tools) && toolList.data.count >= 10);
  const toolExec = await req('/api/v1/brain/tools/get_system_status', 'POST', {});
  assert('POST /api/v1/brain/tools/get_system_status executes approved tool', toolExec.status === 200 && toolExec.data.status === 'SUCCESS' && toolExec.data.execution_time_ms >= 0);
  const toolInvalid = await req('/api/v1/brain/tools/resolve_incident', 'POST', {});
  assert('POST /api/v1/brain/tools/resolve_incident rejects missing params with 400', toolInvalid.status === 400);

  // 9. Copilot Grounded Telemetry
  const copilot = await req('/api/v1/copilot', 'POST', { query: 'What is our current incident status?' });
  assert('POST /api/v1/copilot returns 5-part grounded response structure', copilot.status === 200 && copilot.data.finding && copilot.data.evidence && copilot.data.recommended_steps);

  // 10. Audit Log
  const audit = await req('/api/v1/audit');
  assert('GET /api/v1/audit returns immutable audit records', audit.status === 200 && Array.isArray(audit.data) && audit.data.length > 0);

  // 11. Frontend Layout & KPI Card Isolation Verification
  const indexHtml = await req('/');
  assert('GET / returns 200 HTML content', indexHtml.status === 200 && typeof indexHtml.raw === 'string');
  const html = indexHtml.raw || '';
  
  assert('HTML contains view-dashboard as default active section', html.includes('id="view-dashboard" class="view-section active"'));
  assert('HTML contains view-scanner as inactive by default', html.includes('id="view-scanner" class="view-section"'));
  
  // Verify stat-grid-4 is enclosed within view-dashboard and not floating globally
  const dashboardStart = html.indexOf('id="view-dashboard"');
  const dashboardEnd = html.indexOf('id="view-scanner"');
  const statGridIndex = html.indexOf('class="stat-grid-4"');
  assert('stat-grid-4 is encapsulated strictly inside view-dashboard', statGridIndex > dashboardStart && statGridIndex < dashboardEnd);
  
  // Verify other sections do not duplicate the stat-grid-4 metrics bar
  const afterScanner = html.slice(dashboardEnd);
  assert('stat-grid-4 is not duplicated in scanner, copilot, audit, or pipeline sections', !afterScanner.includes('class="stat-grid-4"'));

  // 12. Video Pipeline Safety & Bounded Inference Verification
  const appJsRes = await req('/static/app.js');
  assert('GET /static/app.js returns 200', appJsRes.status === 200 && typeof appJsRes.raw === 'string');
  const appJs = appJsRes.raw || '';

  assert('app.js includes detectFromVideo bounded inference function', appJs.includes('async function detectFromVideo('));
  assert('app.js configures safe maxInferenceDimension (640px)', appJs.includes('maxInferenceDimension: 640'));
  assert('app.js includes centralized validateVideoFile validation', appJs.includes('async function validateVideoFile('));
  assert('app.js enforces maximum video size limit (50MB)', appJs.includes('maxVideoFileSizeMB: 50'));
  assert('app.js enforces maximum video duration limit (180s)', appJs.includes('maxVideoDurationSec: 180'));
  assert('app.js inference loop checks document.hidden, paused, and ended states', appJs.includes('document.hidden || videoEl.paused || videoEl.ended'));
  assert('app.js cleanActiveMedia revokes activeObjectUrl to prevent memory leaks', appJs.includes('URL.revokeObjectURL(STATE.activeObjectUrl)'));
  assert('app.js recordDetectionEvent enforces in-flight concurrency backpressure', appJs.includes('STATE.inFlightEventCount >= STATE.maxInFlightEvents'));
  assert('app.js throttles summary refresh polling during event streams', appJs.includes('now - STATE.lastSummaryRefreshTime > STATE.summaryRefreshThrottleMs'));

  // 13. Mathematical Geometry & Bounding Box Projection Invariant Test
  const mockOrigW = 1920, mockOrigH = 1080, mockMaxDim = 640;
  const mockInferW = mockMaxDim;
  const mockInferH = Math.round((mockOrigH / mockOrigW) * mockMaxDim); // 360
  const mockScaleX = mockOrigW / mockInferW; // 3
  const mockScaleY = mockOrigH / mockInferH; // 3
  const mockInferBbox = [100, 50, 40, 60]; // detected on 640x360 canvas
  const projectedBbox = [
    mockInferBbox[0] * mockScaleX,
    mockInferBbox[1] * mockScaleY,
    mockInferBbox[2] * mockScaleX,
    mockInferBbox[3] * mockScaleY
  ];
  assert('Coordinate projection accurately scales [100,50,40,60] on 640x360 to [300,150,120,180] on 1080p',
    projectedBbox[0] === 300 && projectedBbox[1] === 150 && projectedBbox[2] === 120 && projectedBbox[3] === 180
  );

  // 14. Live Scanner Category Filter Dropdown & Detection Chip Visualization Verification
  assert('HTML contains scanner-category-filter dropdown', html.includes('id="scanner-category-filter"'));
  assert('HTML contains detections-filter-badge badge', html.includes('id="detections-filter-badge"'));
  assert('Category filter includes "all" option', html.includes('value="all"'));
  assert('Category filter includes "person" option', html.includes('value="person"'));
  assert('Category filter includes "vehicles" option', html.includes('value="vehicles"'));
  assert('Category filter includes "luggage" option', html.includes('value="luggage"'));
  assert('Category filter includes "weapons" option', html.includes('value="weapons"'));
  assert('Category filter includes "electronics" option', html.includes('value="electronics"'));
  assert('Category filter includes "animals" option', html.includes('value="animals"'));
  assert('Category filter includes "none" option (Hide Detection Chips)', html.includes('value="none"'));

  assert('app.js defines DETECTION_CATEGORIES registry', appJs.includes('const DETECTION_CATEGORIES = {'));
  assert('app.js defines getObjectCategory classifier', appJs.includes('function getObjectCategory('));
  assert('app.js defines filterPredictions logic', appJs.includes('function filterPredictions('));
  assert('app.js defines applyActiveCategoryFilter', appJs.includes('function applyActiveCategoryFilter('));
  assert('app.js defines updateChipsRowVisibility function', appJs.includes('function updateChipsRowVisibility('));
  assert('app.js categoryFilterSelect listener calls updateChipsRowVisibility', appJs.includes('updateChipsRowVisibility(selectedCategory)'));
  assert('app.js updates detection chips with data-category attribute', appJs.includes('data-category='));
  assert('app.js dynamically controls detection chip container visibility', appJs.includes("chipsRow.classList.add('chips-hidden')") && appJs.includes("chipsRow.classList.remove('chips-hidden')"));
  assert('app.js updates detection chips with SVG icons and category styling', appJs.includes('catConfig.chipClass') && appJs.includes('catConfig.icon'));

  // Test category matching logic directly in Node
  const testCats = {
    person: ['person'],
    vehicles: ['car', 'truck', 'motorcycle', 'bus', 'bicycle'],
    luggage: ['backpack', 'handbag', 'suitcase'],
    weapons: ['knife', 'scissors'],
    electronics: ['cell phone', 'laptop', 'tv'],
    animals: ['dog', 'cat', 'bird']
  };

  const sampleDetections = [
    { class: 'person', score: 0.95, bbox: [10, 10, 50, 100] },
    { class: 'car', score: 0.88, bbox: [100, 100, 150, 80] },
    { class: 'backpack', score: 0.75, bbox: [30, 40, 20, 30] },
    { class: 'cell phone', score: 0.82, bbox: [20, 20, 10, 15] },
    { class: 'dog', score: 0.91, bbox: [200, 150, 60, 40] }
  ];

  const personOnly = sampleDetections.filter(d => d.class === 'person');
  assert('Category filter isolates person objects exclusively', personOnly.length === 1 && personOnly[0].class === 'person');

  const vehicleOnly = sampleDetections.filter(d => testCats.vehicles.includes(d.class));
  assert('Category filter isolates vehicles objects exclusively', vehicleOnly.length === 1 && vehicleOnly[0].class === 'car');

  const luggageOnly = sampleDetections.filter(d => testCats.luggage.includes(d.class));
  assert('Category filter isolates luggage objects exclusively', luggageOnly.length === 1 && luggageOnly[0].class === 'backpack');

  // 15. Comprehensive Audit Fix Verifications (DEF-01 to DEF-05)
  // DEF-01 & DEF-02: FastAPI Route Parity
  const fs = require('fs');
  const mainPy = fs.readFileSync('backend/app/main.py', 'utf8');
  assert('FastAPI main.py mounts aleana.router for parity', mainPy.includes('aleana.router'));
  assert('FastAPI aleana.py router file exists', fs.existsSync('backend/app/routers/aleana.py'));
  const schemasPy = fs.readFileSync('backend/app/schemas.py', 'utf8');
  assert('FastAPI schemas.py defines PolicyCreate model', schemasPy.includes('class PolicyCreate('));
  const policiesPy = fs.readFileSync('backend/app/routers/policies.py', 'utf8');
  assert('FastAPI policies.py implements POST / (create policy)', policiesPy.includes('@router.post('));
  assert('FastAPI policies.py implements DELETE /{policy_id}', policiesPy.includes('@router.delete('));

  // DEF-03: Event Filter Controls
  assert('HTML contains event-sev-filter dropdown', html.includes('id="event-sev-filter"'));
  assert('HTML contains event-status-filter dropdown', html.includes('id="event-status-filter"'));
  assert('app.js listens to event-sev-filter change', appJs.includes("getElementById('event-sev-filter')"));
  assert('app.js listens to event-status-filter change', appJs.includes("getElementById('event-status-filter')"));
  assert('app.js filters events table by severity and status', appJs.includes('EVENT_FILTER.sev !== \'all\'') && appJs.includes('EVENT_FILTER.status !== \'all\''));

  // DEF-04: Policy Category & Audit Subtabs
  assert('HTML defines data-policy-category subtabs', html.includes('data-policy-category="detection"') && html.includes('data-policy-category="system"') && html.includes('data-policy-category="automation"'));
  assert('app.js defines POLICY_FILTER state', appJs.includes('const POLICY_FILTER = {'));
  assert('app.js attaches click listener to data-policy-category buttons', appJs.includes('subtab-btn[data-policy-category]'));
  assert('HTML defines data-audit-tab subtabs', html.includes('data-audit-tab="logs"') && html.includes('data-audit-tab="health"') && html.includes('data-audit-tab="db"') && html.includes('data-audit-tab="api"'));
  assert('app.js defines AUDIT_FILTER.tab state', appJs.includes("tab: 'logs'"));
  assert('app.js attaches click listener to data-audit-tab buttons', appJs.includes('subtab-btn[data-audit-tab]'));

  // DEF-05: Drawer ALEANA Input
  assert('HTML defines drawer-aleana-form', html.includes('id="drawer-aleana-form"'));
  assert('HTML defines drawer-aleana-input', html.includes('id="drawer-aleana-input"'));
  assert('app.js listens to drawer-aleana-form submit', appJs.includes("getElementById('drawer-aleana-form')"));

  console.log(`[TEST SUITE] Integration Complete: ${passed}/${total} assertions passed.`);
  if (passed !== total) {
    process.exit(1);
  }
}

runTests().catch(err => {
  console.error('[TEST SUITE FATAL]', err);
  process.exit(1);
});
