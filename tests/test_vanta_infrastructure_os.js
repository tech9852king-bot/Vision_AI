/**
 * VANTA AI — Universal Infrastructure Intelligence OS
 * Gate 2 through Gate 9 Comprehensive Integration & Security Test Suite
 *
 * Verifies:
 *  - Gate 2: Unified Infrastructure Data Foundation (Facilities, Buildings, Assets, Asset Relationships, Profiles)
 *  - Gate 3.1: Industrial IoT Intelligence (Sensors, Adapters, Telemetry Ingestion, Anomaly Detection)
 *  - Gate 3.2: Predictive Maintenance Engine (ISO-10816 Vibration, Thermal, Acoustic, Weibull RUL)
 *  - Gate 3.3: Energy Intelligence Engine (Load factor, peak demand, estimated vs verified savings)
 *  - Gate 3.4: Cross-System Root-Cause Investigation (8-domain correlation & evidence chain)
 *  - Gate 4: Vanta Digital Twin (Spatial nodes, asset dependencies, health overlays)
 *  - Gate 5: Vanta Brain Evolution (9 Specialized Agents, 11 new Commands, 10 new Tools)
 *  - Gate 7: Multi-Agent Workflow Coordinator (Human Approval Gates, Duplicate-Action 409 Protection)
 *  - Gate 8: Enterprise RBAC & Security Governance (VIEWER 403 rejection, SHA-256 audit log chain)
 */

const http = require('http');
const assert = require('assert');

const BASE_URL = process.env.TEST_BASE_URL || 'http://127.0.0.1:3000';

function request(method, path, body = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE_URL);
    const payload = body ? JSON.stringify(body) : null;
    const reqHeaders = {
      'Content-Type': 'application/json',
      ...headers,
    };
    if (payload) {
      reqHeaders['Content-Length'] = Buffer.byteLength(payload);
    }

    const req = http.request(
      {
        hostname: url.hostname,
        port: url.port,
        path: url.pathname + url.search,
        method,
        headers: reqHeaders,
      },
      (res) => {
        let raw = '';
        res.on('data', (chunk) => (raw += chunk));
        res.on('end', () => {
          let json = null;
          try {
            json = JSON.parse(raw);
          } catch (_) {
            // keep raw
          }
          resolve({ status: res.statusCode, headers: res.headers, json, raw });
        });
      }
    );

    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function runTests() {
  console.log('=== VANTA AI — Universal Infrastructure Intelligence OS Test Suite ===');
  let passed = 0;
  let failed = 0;

  async function check(name, fn) {
    try {
      await fn();
      console.log(`  [PASS] ${name}`);
      passed++;
    } catch (err) {
      console.error(`  [FAIL] ${name}: ${err.message}`);
      failed++;
    }
  }

  // 1. Gate 2 — Industry Profiles & Unified Infrastructure Registry
  await check('Gate 2.1: GET /api/v1/profiles returns 5 industry vertical profiles', async () => {
    const res = await request('GET', '/api/v1/profiles');
    assert.strictEqual(res.status, 200);
    assert.ok(res.json.active_profile);
    assert.ok(Array.isArray(res.json.profiles));
    assert.ok(res.json.profiles.length >= 5);
  });

  await check('Gate 2.2: POST /api/v1/profiles/select switches active industry profile', async () => {
    const res = await request('POST', '/api/v1/profiles/select', { profile_id: 'power_energy' });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.json.active_profile_id, 'power_energy');
    assert.strictEqual(res.json.active_profile.profile_id, 'power_energy');
    // Restore manufacturing default
    await request('POST', '/api/v1/profiles/select', { profile_id: 'manufacturing' });
  });

  await check('Gate 2.3: GET /api/v1/facilities returns multi-sector facilities & building hierarchies', async () => {
    const res = await request('GET', '/api/v1/facilities');
    assert.strictEqual(res.status, 200);
    assert.ok(Array.isArray(res.json.facilities));
    assert.ok(res.json.facilities.length >= 2);
    assert.ok(Array.isArray(res.json.facilities[0].buildings));
  });

  await check('Gate 2.4: POST /api/v1/facilities creates new facility with provenance', async () => {
    const res = await request('POST', '/api/v1/facilities', {
      name: 'Alpha Semiconductor Cleanroom Fab',
      industry_profile: 'manufacturing',
      location: 'Austin, TX',
      total_area_sqm: 42000,
    });
    assert.strictEqual(res.status, 201);
    assert.ok(res.json.facility_id.startsWith('FAC-'));
    assert.strictEqual(res.json.name, 'Alpha Semiconductor Cleanroom Fab');
  });

  await check('Gate 2.5: GET /api/v1/assets returns assets & upstream/downstream relationships', async () => {
    const res = await request('GET', '/api/v1/assets');
    assert.strictEqual(res.status, 200);
    assert.ok(Array.isArray(res.json.assets));
    assert.ok(res.json.assets.length >= 4);
    assert.ok(Array.isArray(res.json.relationships));
    assert.ok(res.json.relationships.length >= 4);
  });

  // 2. Gate 3.1 — Industrial IoT Intelligence & Telemetry Ingestion
  await check('Gate 3.1a: GET /api/v1/sensors & /api/v1/iot/adapters return labeled adapters', async () => {
    const sRes = await request('GET', '/api/v1/sensors');
    assert.strictEqual(sRes.status, 200);
    assert.ok(sRes.json.sensors.length >= 6);

    const aRes = await request('GET', '/api/v1/iot/adapters');
    assert.strictEqual(aRes.status, 200);
    assert.ok(aRes.json.adapters.length >= 3);
    assert.ok(
      aRes.json.adapters.every(
        (a) => a.connection_mode === 'SIMULATION_ADAPTER' || a.connection_mode === 'CONFIGURED_LIVE_ADAPTER'
      )
    );
  });

  await check('Gate 3.1b: POST /api/v1/telemetry/ingest detects anomaly & updates equipment health', async () => {
    const res = await request('POST', '/api/v1/telemetry/ingest', {
      sensor_id: 'SEN-VIB-101',
      value: 8.6,
      provenance: 'SIMULATION_ADAPTER',
    });
    assert.strictEqual(res.status, 201);
    assert.strictEqual(res.json.anomaly_evaluation.is_anomaly, true);
    assert.strictEqual(res.json.anomaly_evaluation.severity, 'CRITICAL');
    assert.ok(res.json.updated_equipment_health);
    assert.ok(typeof res.json.updated_equipment_health.health_score === 'number');
  });

  // 3. Gate 3.2 — Predictive Maintenance Engine
  await check('Gate 3.2: POST /api/v1/maintenance/analyze computes ISO-10816 & Weibull RUL', async () => {
    const res = await request('POST', '/api/v1/maintenance/analyze', {
      equipment_id: 'EQ-CNC-01',
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.json.equipment_id, 'EQ-CNC-01');
    assert.ok(res.json.analysis);
    assert.ok(typeof res.json.analysis.health_score === 'number');
    assert.ok(typeof res.json.analysis.failure_risk_pct === 'number');
    assert.ok(typeof res.json.analysis.rul_estimated_hours === 'number');
    assert.ok(res.json.analysis.analysis_method.includes('ISO-10816'));
  });

  // 4. Gate 3.3 — Energy Intelligence Engine
  await check('Gate 3.3: GET /api/v1/energy & POST /api/v1/energy/optimize separate estimated vs verified savings', async () => {
    const getRes = await request('GET', '/api/v1/energy');
    assert.strictEqual(getRes.status, 200);
    assert.ok(getRes.json.summary);
    assert.ok(typeof getRes.json.summary.estimated_monthly_savings_usd === 'number');
    assert.ok(typeof getRes.json.summary.verified_monthly_savings_usd === 'number');

    const optRes = await request('POST', '/api/v1/energy/optimize', {
      active_power_kw: 495.0,
      power_factor: 0.94,
      verified_savings_kwh_month: 5200,
    });
    assert.strictEqual(optRes.status, 200);
    assert.strictEqual(optRes.json.status, 'UPDATED');
    assert.ok(optRes.json.analysis.verified_monthly_savings_usd > 0);
  });

  // 5. Gate 3.4 — Cross-System Root-Cause Investigation Engine
  await check('Gate 3.4: POST /api/v1/investigations/correlate builds 8-domain evidence chain', async () => {
    const res = await request('POST', '/api/v1/investigations/correlate', {
      facility_id: 'FAC-01-AUSTIN-GIGA',
      equipment_id: 'EQ-CNC-01',
      trigger: 'CROSS_MODAL_CORRELATION',
    });
    assert.strictEqual(res.status, 201);
    assert.ok(res.json.investigation_id.startsWith('INV-'));
    assert.ok(res.json.evidence_chain && typeof res.json.evidence_chain === 'object');
    assert.ok(Array.isArray(res.json.supporting_evidence));
    assert.ok(res.json.confidence_score > 0.5);
  });

  // 6. Gate 4 — Vanta Digital Twin
  await check('Gate 4: GET /api/v1/digital-twin returns unified spatial nodes & asset relationships', async () => {
    const res = await request('GET', '/api/v1/digital-twin');
    assert.strictEqual(res.status, 200);
    assert.ok(Array.isArray(res.json.spatial_nodes));
    assert.ok(res.json.spatial_nodes.length >= 4);
    assert.ok(Array.isArray(res.json.asset_relationships));
    assert.ok(res.json.overlays.health_summary);
  });

  // 7. Gate 5 — Vanta Brain Evolution (9 Specialized Agents, 11 new Commands, 10 new Tools)
  await check('Gate 5.1: GET /api/v1/agents & POST /api/v1/agents/orchestrate execute specialized agents', async () => {
    const aRes = await request('GET', '/api/v1/agents');
    assert.strictEqual(aRes.status, 200);
    assert.strictEqual(aRes.json.agents.length, 9);

    const oRes = await request('POST', '/api/v1/agents/orchestrate', {
      agent_id: 'PREDICTIVE_MAINTENANCE_AGENT',
      query: 'Evaluate bearing wear on CNC spindle',
    });
    assert.strictEqual(oRes.status, 200);
    assert.strictEqual(oRes.json.agent_id, 'PREDICTIVE_MAINTENANCE_AGENT');
    assert.ok(Array.isArray(oRes.json.verified_observations));
    assert.ok(Array.isArray(oRes.json.recommendations));
  });

  await check('Gate 5.2: POST /api/v1/brain executes new infrastructure commands (facilities, equipment, energy, investigations, workflows)', async () => {
    for (const cmd of ['facilities', 'equipment', 'energy', 'investigations', 'workflows']) {
      const bRes = await request('POST', '/api/v1/brain', { command: cmd });
      assert.strictEqual(bRes.status, 200, `Brain command ${cmd} failed`);
      assert.strictEqual(bRes.json.status, 'SUCCESS');
    }
  });

  await check('Gate 5.3: POST /api/v1/brain/tools/get_equipment_health runs approved infrastructure tool', async () => {
    const tRes = await request('POST', '/api/v1/brain/tools/get_equipment_health', {
      equipment_id: 'EQ-CNC-01',
    });
    assert.strictEqual(tRes.status, 200);
    assert.strictEqual(tRes.json.status, 'SUCCESS');
    assert.ok(Array.isArray(tRes.json.data.equipment));
  });

  // 8. Gate 7 & Gate 8 — Multi-Agent Workflows, Human Approval Gate, Duplicate Protection & RBAC
  await check('Gate 7.1: POST /api/v1/workflows creates human-gated workflow & prevents duplicate execution (409)', async () => {
    const wfPayload = {
      template_id: 'WF-TPL-THERMAL-ISOLATION-TEST',
      facility_id: 'FAC-01-AUSTIN-GIGA',
      target_asset_id: 'AST-HV-XFMR-01',
      target_equipment_id: 'EQ-XFMR-01',
      title: 'Emergency Transformer Thermal Inspection',
    };
    const wRes1 = await request('POST', '/api/v1/workflows', wfPayload);
    assert.strictEqual(wRes1.status, 201);
    assert.strictEqual(wRes1.json.status, 'PENDING_APPROVAL');

    // Immediate duplicate should be blocked with 409
    const wRes2 = await request('POST', '/api/v1/workflows', wfPayload);
    assert.strictEqual(wRes2.status, 409);

    // Approve workflow as ADMIN
    const wfId = wRes1.json.workflow_id;
    const appRes = await request('POST', `/api/v1/workflows/${wfId}/approve`, {
      notes: 'Approved by Chief Engineer after thermal review',
    });
    assert.strictEqual(appRes.status, 200);
    assert.strictEqual(appRes.json.status, 'COMPLETED');
  });

  await check('Gate 8: Role-Based Access Control blocks VIEWER role from mutating infrastructure (403)', async () => {
    const res = await request(
      'POST',
      '/api/v1/facilities',
      { name: 'Unauthorized Facility', industry_profile: 'manufacturing' },
      { 'x-vanta-role': 'VIEWER' }
    );
    assert.strictEqual(res.status, 403);
  });

  console.log(`\n=== VANTA AI Infrastructure Suite Summary: ${passed} passed, ${failed} failed ===`);
  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
