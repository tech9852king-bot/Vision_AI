/**
 * VantaVisionAI - Milestone 2 Verification Suite
 * Tests:
 * 1. Live Multi-Object Scanner Copilot Grounding (visible count, track IDs, people & vehicles, delta, scanner state)
 * 2. Inactive scanner honest fallback answers
 * 3. Cinematic Enterprise UI Theme Switcher (Dark / Light / System, anti-FOUC script, CSS tokens)
 * 4. Clean source lifecycle with tracker reset on media cleanup
 */
const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 3000;
let passed = 0;
let total = 0;

function assert(description, condition) {
  total++;
  if (condition) {
    passed++;
    console.log(`  ✓ [PASS] ${description}`);
  } else {
    console.error(`  ✗ [FAIL] ${description}`);
    process.exitCode = 1;
  }
}

function req(endpoint, method = 'GET', body = null) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const options = {
      hostname: '127.0.0.1',
      port: PORT,
      path: endpoint,
      method,
      headers: {
        'Content-Type': 'application/json',
        'X-Tenant-ID': 'test-tenant'
      }
    };
    if (payload) {
      options.headers['Content-Length'] = Buffer.byteLength(payload);
    }

    const request = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try {
          resolve({ status: res.status, statusCode: res.statusCode, data: JSON.parse(data), raw: data });
        } catch (e) {
          resolve({ status: res.status, statusCode: res.statusCode, raw: data });
        }
      });
    });

    request.on('error', reject);
    if (payload) request.write(payload);
    request.end();
  });
}

async function runSuite() {
  console.log('[TEST SUITE] Executing Milestone 2: Copilot Live Context & Theme Suite...');

  // 1. Copilot Live Multi-Object Query: "How many objects are visible right now?"
  const mockLiveActive = {
    is_scanning: true,
    active_source: 'Webcam (Integrated Camera)',
    visible_count: 3,
    active_track_ids: [101, 102, 103],
    class_counts: { person: 2, backpack: 1 },
    detections: [
      { trackId: 101, class: 'person', score: 94, speed: 1.2, bbox: [50, 60, 100, 220] },
      { trackId: 102, class: 'person', score: 88, speed: 0.8, bbox: [220, 80, 90, 210] },
      { trackId: 103, class: 'backpack', score: 82, speed: 1.2, bbox: [70, 120, 40, 50] }
    ],
    recent_history: [
      { trackId: 101, class: 'person', score: 94, firstSeen: '10:00:00 AM', lastSeen: '10:00:05 AM' },
      { trackId: 102, class: 'person', score: 88, firstSeen: '10:00:01 AM', lastSeen: '10:00:05 AM' },
      { trackId: 103, class: 'backpack', score: 82, firstSeen: '10:00:02 AM', lastSeen: '10:00:05 AM' }
    ]
  };

  const resObjects = await req('/api/v1/copilot', 'POST', {
    query: 'How many objects are visible right now?',
    live_context: mockLiveActive
  });
  assert('Copilot reports 3 visible objects with active track IDs in finding',
    resObjects.statusCode === 200 &&
    resObjects.data.finding &&
    resObjects.data.finding.includes('3 object(s) currently visible') &&
    resObjects.data.finding.includes('#101') &&
    resObjects.data.finding.includes('#102') &&
    resObjects.data.finding.includes('#103')
  );
  assert('Copilot evidence includes detailed tracks for all 3 detections',
    resObjects.data.evidence &&
    resObjects.data.evidence.length === 3 &&
    resObjects.data.evidence[0].includes('Track #101 [PERSON]')
  );

  // 2. Inactive Scanner Honest Grounding
  const mockLiveInactive = {
    is_scanning: false,
    active_source: 'None',
    visible_count: 0,
    active_track_ids: [],
    class_counts: {},
    detections: [],
    recent_history: []
  };

  const resInactive = await req('/api/v1/copilot', 'POST', {
    query: 'How many objects are visible right now?',
    live_context: mockLiveInactive
  });
  assert('Copilot honestly declares scanner is INACTIVE when scanning is stopped',
    resInactive.statusCode === 200 &&
    resInactive.data.finding &&
    resInactive.data.finding.includes('INACTIVE') &&
    resInactive.data.finding.includes('0 objects')
  );

  // 3. Multi-class Census: "How many people and vehicles are detected?"
  const mockCensus = {
    is_scanning: true,
    active_source: 'Simulated Surveillance Stream (Main Entrance)',
    visible_count: 4,
    active_track_ids: [201, 202, 203, 204],
    class_counts: { person: 2, car: 1, truck: 1 },
    detections: [
      { trackId: 201, class: 'person', score: 92, bbox: [100, 100, 40, 100] },
      { trackId: 202, class: 'person', score: 89, bbox: [200, 100, 40, 100] },
      { trackId: 203, class: 'car', score: 95, bbox: [350, 150, 120, 80] },
      { trackId: 204, class: 'truck', score: 90, bbox: [500, 140, 130, 90] }
    ]
  };

  const resCensus = await req('/api/v1/copilot', 'POST', {
    query: 'How many people and vehicles are detected?',
    live_context: mockCensus
  });
  assert('Copilot census reports accurate breakdown: 2 persons and 2 vehicles',
    resCensus.statusCode === 200 &&
    resCensus.data.finding &&
    resCensus.data.finding.includes('2 person(s)') &&
    resCensus.data.finding.includes('2 vehicle(s)')
  );

  // 4. Track IDs query
  const resTracks = await req('/api/v1/copilot', 'POST', {
    query: 'Show the current track IDs',
    live_context: mockCensus
  });
  assert('Copilot reports exact active track IDs [#201, #202, #203, #204]',
    resTracks.statusCode === 200 &&
    resTracks.data.finding &&
    resTracks.data.finding.includes('#201') &&
    resTracks.data.finding.includes('#204')
  );

  // 5. Tracking delta query: "What changed in the last few seconds?"
  const resDelta = await req('/api/v1/copilot', 'POST', {
    query: 'What changed in the last few seconds?',
    live_context: mockLiveActive
  });
  assert('Copilot reports tracking delta from rolling history',
    resDelta.statusCode === 200 &&
    resDelta.data.finding &&
    resDelta.data.finding.includes('Tracking Delta: 3 distinct target(s)')
  );

  // 6. Scanner running query: "Is the scanner running?"
  const resRunning = await req('/api/v1/copilot', 'POST', {
    query: 'Is the scanner running?',
    live_context: mockLiveActive
  });
  assert('Copilot answers scanner status as RUNNING with source',
    resRunning.statusCode === 200 &&
    resRunning.data.finding &&
    resRunning.data.finding.includes('RUNNING')
  );

  // 7. HTML Theme Switcher Structure & Anti-FOUC Script
  const htmlContent = fs.readFileSync(path.join(__dirname, '../static/index.html'), 'utf8');
  assert('HTML contains theme-switcher-container group in topbar',
    htmlContent.includes('id="theme-switcher-container"')
  );
  assert('HTML contains Dark, Light, and System theme buttons',
    htmlContent.includes('id="theme-btn-dark"') &&
    htmlContent.includes('id="theme-btn-light"') &&
    htmlContent.includes('id="theme-btn-system"')
  );
  assert('HTML contains anti-FOUC theme script in <head>',
    htmlContent.includes("localStorage.getItem('vanta-theme')") &&
    htmlContent.includes("document.documentElement.setAttribute('data-theme'")
  );

  // 8. CSS Light Theme & Palette Tokens
  const cssContent = fs.readFileSync(path.join(__dirname, '../static/style.css'), 'utf8');
  assert('style.css defines html[data-theme="light"] high-contrast palette',
    cssContent.includes('html[data-theme="light"]') &&
    cssContent.includes('--bg-primary: #f8fafc;') &&
    cssContent.includes('--text-main: #0f172a;')
  );
  assert('style.css defines .theme-switcher-group and .theme-btn styling',
    cssContent.includes('.theme-switcher-group') &&
    cssContent.includes('.theme-btn')
  );

  // 9. app.js Theme Engine & Lifecycle
  const appJsContent = fs.readFileSync(path.join(__dirname, '../static/app.js'), 'utf8');
  assert('app.js defines applyTheme function',
    appJsContent.includes('function applyTheme(choice, persist = true)')
  );
  assert('app.js defines initThemeEngine function',
    appJsContent.includes('function initThemeEngine()')
  );
  assert('app.js cleanActiveMedia resets tracker to avoid cross-feed contamination',
    appJsContent.includes('STATE.tracker.reset()')
  );
  assert('app.js sendCopilotQuery attaches live_context object',
    appJsContent.includes('live_context: liveContext') &&
    appJsContent.includes('visible_count:') &&
    appJsContent.includes('active_track_ids:')
  );

  console.log(`[MILESTONE 2 SUITE] Complete: ${passed}/${total} assertions passed.`);
  if (passed !== total) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

runSuite().catch(err => {
  console.error('[TEST SUITE] Fatal error:', err);
  process.exit(1);
});
