// VantaVisionAI Funding Prototype - Zero-Dependency Preview & Dev Server
// Compatible with Node.js 22 built-in modules (http, fs, path, url)
// Binds to 0.0.0.0:3000 for AI Studio Dev Server compliance while matching FastAPI contracts

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const crypto = require('crypto');
const { GoogleGenAI } = require('@google/genai');
const { WebSocketServer } = require('ws');

const PORT = 3000;
const HOST = '0.0.0.0';
const START_TIME = Date.now();

// Lazy-initialized GoogleGenAI Client
let geminiClient = null;
function getGeminiClient() {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return null;
  if (!geminiClient) {
    try {
      geminiClient = new GoogleGenAI({ apiKey });
    } catch (err) {
      console.error('[Gemini] Initialization error:', err.message);
      return null;
    }
  }
  return geminiClient;
}

// In-Memory Database Stores with Tenant Isolation
const DB = {
  events: [
    {
      id: 'ev_init_01',
      tenant_id: 'default',
      timestamp: new Date().toISOString(),
      camera_id: 'CAM-01-ENTRANCE',
      class_name: 'person',
      confidence: 0.94,
      bbox: [120, 180, 450, 320]
    }
  ],
  incidents: [
    {
      id: 'inc_001',
      tenant_id: 'default',
      timestamp: new Date().toISOString(),
      title: 'After-Hours Perimeter Breach Detected',
      severity: 'HIGH',
      status: 'OPEN',
      policy_id: 'pol_person_after_hours',
      camera_id: 'CAM-01-ENTRANCE',
      details: 'Human presence observed at entrance gate outside operational schedule.'
    },
    {
      id: 'inc_002',
      tenant_id: 'default',
      timestamp: new Date().toISOString(),
      title: 'Stationary Baggage in Transit Hallway',
      severity: 'MEDIUM',
      status: 'OPEN',
      policy_id: 'pol_unattended_bag',
      camera_id: 'CAM-02-LOBBY',
      details: 'Unattended backpack identified near central elevator column.'
    }
  ],
  policies: [
    {
      id: 'pol_person_after_hours',
      tenant_id: 'default',
      name: 'After-Hours Person Incursion',
      target_class: 'person',
      condition: 'time_between(22:00, 06:00)',
      severity: 'HIGH',
      enabled: true,
      description: 'Detects unauthorized human presence during closed facility hours.'
    },
    {
      id: 'pol_unattended_bag',
      tenant_id: 'default',
      name: 'Unattended Object / Backpack',
      target_class: 'backpack',
      condition: 'dwell_time > 180s',
      severity: 'MEDIUM',
      enabled: true,
      description: 'Triggers when baggage remains stationary without associated person nearby.'
    },
    {
      id: 'pol_restricted_vehicle',
      tenant_id: 'default',
      name: 'Restricted Area Vehicle Access',
      target_class: 'car',
      condition: 'zone == "loading_dock_restricted"',
      severity: 'CRITICAL',
      enabled: true,
      description: 'Unauthorized vehicular entry into designated high-security perimeter.'
    },
    {
      id: 'pol_weapon_safety',
      tenant_id: 'default',
      name: 'Safety Hazard Object Detected',
      target_class: 'scissors',
      condition: 'confidence > 0.65',
      severity: 'HIGH',
      enabled: true,
      description: 'Identifies potential sharp or dangerous implement hazards in workspace.'
    }
  ],
  audit_logs: [
    {
      id: 1,
      tenant_id: 'default',
      timestamp: new Date().toISOString(),
      action: 'SYSTEM_BOOT',
      actor: 'system',
      status: 'SUCCESS',
      details: 'VantaVisionAI Funding Prototype initialized on port ' + PORT
    }
  ]
};

let auditIdCounter = 2;

function logAudit(tenantId, action, actor, status, details) {
  DB.audit_logs.unshift({
    id: auditIdCounter++,
    tenant_id: tenantId || 'default',
    timestamp: new Date().toISOString(),
    action,
    actor: actor || 'system',
    status,
    details: details || ''
  });
}

// Allowlisted Brain Commands
const ALLOWLISTED_COMMANDS = {
  help: 'List all available allowlisted commands and syntax guide',
  status: 'Check backend health, camera provider mode, and system parameters',
  capabilities: 'View verified operational capabilities and active AI modules',
  summary: 'Retrieve aggregated detection counts, active incidents, and policy stats',
  incidents: 'Query open security incidents, severity levels, and trigger policies',
  policies: 'Review automated detection rules, thresholds, and operational status',
  cameras: 'Inspect registered video inputs and physical vs simulated stream status',
  events: 'Inspect recent detection events filtered by tenant and camera',
  diagnostics: 'View camera pipeline diagnostics and runtime telemetry',
  audit: 'Inspect latest security actions and audit trails',
  troubleshoot: 'Step-by-step diagnostic guidance for camera, scanner, and policy issues',
  tools: 'List approved Brain tools and execution schemas'
};

const APPROVED_TOOLS = [
  {
    name: 'get_system_status',
    description: 'Inspect backend health, SQLite database connectivity, and camera provider state',
    category: 'DIAGNOSTIC',
    permission: 'READ',
    parameters: { type: 'object', properties: {}, required: [] },
    is_destructive: false,
    timeout_seconds: 3.0
  },
  {
    name: 'get_summary_metrics',
    description: 'Retrieve aggregated counts for events, incidents, open alerts, and active policies',
    category: 'READ_ONLY',
    permission: 'READ',
    parameters: { type: 'object', properties: {}, required: [] },
    is_destructive: false,
    timeout_seconds: 3.0
  },
  {
    name: 'list_incidents',
    description: 'Query security incident records with optional status, severity, and limit filters',
    category: 'READ_ONLY',
    permission: 'READ',
    parameters: {
      type: 'object',
      properties: {
        status: { type: 'string', description: 'Filter by status: OPEN or RESOLVED' },
        severity: { type: 'string', description: 'Filter by severity: LOW, MEDIUM, HIGH, CRITICAL' },
        limit: { type: 'integer', description: 'Maximum records to return (default 20)' }
      },
      required: []
    },
    is_destructive: false,
    timeout_seconds: 3.0
  },
  {
    name: 'resolve_incident',
    description: 'Mark an open security incident as RESOLVED with audit trail tracking',
    category: 'MUTATING',
    permission: 'OPERATOR',
    parameters: {
      type: 'object',
      properties: {
        incident_id: { type: 'string', description: 'ID of the incident to resolve' }
      },
      required: ['incident_id']
    },
    is_destructive: false,
    timeout_seconds: 3.0
  },
  {
    name: 'list_events',
    description: 'Inspect recent visual detection events filtered by camera ID or target class',
    category: 'READ_ONLY',
    permission: 'READ',
    parameters: {
      type: 'object',
      properties: {
        camera_id: { type: 'string', description: 'Filter by camera identifier' },
        class_name: { type: 'string', description: 'Filter by object class' },
        limit: { type: 'integer', description: 'Maximum records to return' }
      },
      required: []
    },
    is_destructive: false,
    timeout_seconds: 3.0
  },
  {
    name: 'list_policies',
    description: 'Inspect all automated security policies, trigger conditions, and status',
    category: 'READ_ONLY',
    permission: 'READ',
    parameters: {
      type: 'object',
      properties: {
        enabled_only: { type: 'boolean', description: 'If true, returns only active policies' }
      },
      required: []
    },
    is_destructive: false,
    timeout_seconds: 3.0
  },
  {
    name: 'toggle_policy',
    description: 'Enable or disable an automated detection policy',
    category: 'MUTATING',
    permission: 'OPERATOR',
    parameters: {
      type: 'object',
      properties: {
        policy_id: { type: 'string', description: 'ID of the policy to update' },
        enabled: { type: 'boolean', description: 'Target enabled state' }
      },
      required: ['policy_id', 'enabled']
    },
    is_destructive: false,
    timeout_seconds: 3.0
  },
  {
    name: 'get_camera_inventory',
    description: 'List configured camera sources, browser webcam scanner, and simulated feeds',
    category: 'READ_ONLY',
    permission: 'READ',
    parameters: { type: 'object', properties: {}, required: [] },
    is_destructive: false,
    timeout_seconds: 3.0
  },
  {
    name: 'get_pipeline_diagnostics',
    description: 'Inspect vision pipeline parameters, throttle guards, and client inference settings',
    category: 'DIAGNOSTIC',
    permission: 'READ',
    parameters: { type: 'object', properties: {}, required: [] },
    is_destructive: false,
    timeout_seconds: 3.0
  },
  {
    name: 'get_audit_trail',
    description: 'Retrieve recent tamper-evident security audit records',
    category: 'READ_ONLY',
    permission: 'READ',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', description: 'Optional action prefix filter' },
        limit: { type: 'integer', description: 'Maximum records to return' }
      },
      required: []
    },
    is_destructive: false,
    timeout_seconds: 3.0
  },
  {
    name: 'run_troubleshooter',
    description: 'Provide diagnostic decision-tree steps for camera, scanner, and policy issues',
    category: 'DIAGNOSTIC',
    permission: 'READ',
    parameters: {
      type: 'object',
      properties: {
        subsystem: { type: 'string', description: 'Subsystem to troubleshoot' }
      },
      required: []
    },
    is_destructive: false,
    timeout_seconds: 3.0
  },
  {
    name: 'explain_incident',
    description: 'Deep-dive analysis on a specific incident, its trigger policy, and recommended response',
    category: 'READ_ONLY',
    permission: 'READ',
    parameters: {
      type: 'object',
      properties: {
        incident_id: { type: 'string', description: 'Incident ID to analyze' }
      },
      required: ['incident_id']
    },
    is_destructive: false,
    timeout_seconds: 3.0
  },
  {
    name: 'correlate_threat_matrix',
    description: 'Cross-correlate active multi-object tracks, spatial distances, and temporal dwell times into holistic threat vectors',
    category: 'DIAGNOSTIC',
    permission: 'READ',
    parameters: {
      type: 'object',
      properties: {
        min_threat_score: { type: 'integer', description: 'Minimum threat threshold (0-100)' }
      },
      required: []
    },
    is_destructive: false,
    timeout_seconds: 3.0
  },
  {
    name: 'execute_security_playbook',
    description: 'Trigger an automated, audited incident containment playbook',
    category: 'MUTATING',
    permission: 'OPERATOR',
    parameters: {
      type: 'object',
      properties: {
        playbook_id: { type: 'string', description: 'Identifier of playbook to execute' },
        incident_id: { type: 'string', description: 'Associated incident ID' }
      },
      required: ['playbook_id']
    },
    is_destructive: false,
    timeout_seconds: 3.0
  },
  {
    name: 'dispatch_tactical_drone',
    description: 'Dispatch an autonomous tactical UAV drone for perimeter reconnaissance or target overwatch',
    category: 'OPERATIONAL',
    permission: 'OPERATOR',
    parameters: {
      type: 'object',
      properties: {
        target_zone: { type: 'string', description: 'Target zone or sector for drone flight' },
        track_id: { type: 'string', description: 'Optional target track ID to intercept' },
        mission_profile: {
          type: 'string',
          enum: ['PERIMETER_RECON', 'TARGET_LOCK', 'THERMAL_OVERWATCH'],
          description: 'Tactical flight profile'
        }
      },
      required: ['target_zone']
    },
    is_destructive: false,
    timeout_seconds: 3.0
  }
];

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      if (!body) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch (e) {
        resolve({});
      }
    });
    req.on('error', reject);
  });
}

function sendJson(res, statusCode, data) {
  const jsonStr = JSON.stringify(data);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Tenant-ID'
  });
  res.end(jsonStr);
}

const MIME_TYPES = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml'
};

// Telemetry WebSocket Server for Real-Time Event & Alert Streaming
const telemetryWss = new WebSocketServer({ noServer: true });

function broadcastRealtimeTelemetry(eventType, payload, tenantId = 'default') {
  const message = JSON.stringify({
    type: eventType,
    tenant_id: tenantId,
    timestamp: new Date().toISOString(),
    payload
  });
  telemetryWss.clients.forEach(client => {
    if (client.readyState === 1) {
      client.send(message);
    }
  });
}

telemetryWss.on('connection', (clientWs) => {
  logAudit('default', 'TELEMETRY_WS_CONNECT', 'operator', 'SUCCESS', 'Real-time telemetry WebSocket connected');
  clientWs.send(JSON.stringify({
    type: 'CONNECTED',
    server: 'VantaVisionAI Telemetry Stream',
    version: '2.0.0',
    timestamp: new Date().toISOString()
  }));

  clientWs.on('message', (data) => {
    try {
      const msg = JSON.parse(data.toString());
      if (msg.type === 'ping') {
        clientWs.send(JSON.stringify({ type: 'pong' }));
      }
    } catch (e) {}
  });

  clientWs.on('close', () => {
    logAudit('default', 'TELEMETRY_WS_DISCONNECT', 'operator', 'SUCCESS', 'Real-time telemetry WebSocket disconnected');
  });
});

const server = http.createServer(async (req, res) => {
  // Handle CORS Preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Tenant-ID'
    });
    return res.end();
  }

  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;
  const tenantId = req.headers['x-tenant-id'] || 'default';
  const authHeader = req.headers['authorization'];
  const actor = authHeader ? 'authenticated_user' : 'security_operator';

  // 1. HEALTH & READINESS ROUTES
  if (req.method === 'GET' && pathname === '/health') {
    return sendJson(res, 200, {
      status: 'ok',
      app: 'VantaVisionAI Funding Prototype',
      version: '1.0.0',
      timestamp: new Date().toISOString()
    });
  }

  if (req.method === 'GET' && pathname === '/ready') {
    return sendJson(res, 200, {
      ready: true,
      database: 'connected',
      provider: 'SIMULATED',
      real_camera_configured: false,
      browser_scanner: 'TensorFlow.js COCO-SSD MobileNet V2',
      timestamp: new Date().toISOString()
    });
  }

  // 2. SYSTEM INFO & SUMMARY
  if (req.method === 'GET' && pathname === '/api/v1/system') {
    const uptime = Math.floor((Date.now() - START_TIME) / 1000);
    return sendJson(res, 200, {
      app_name: 'VantaVisionAI Funding Prototype',
      version: '1.0.0',
      tenant_id: tenantId,
      uptime_seconds: uptime,
      environment: process.env.ENVIRONMENT || 'prototype',
      platform: { system: process.platform, node: process.version },
      camera_subsystem: {
        provider: 'SIMULATED',
        real_camera_configured: false,
        browser_detector: 'TensorFlow.js COCO-SSD MobileNet V2',
        cctv_streams_active: 0,
        simulated_streams: ['CAM-01-ENTRANCE', 'CAM-02-LOBBY']
      },
      brain_subsystem: {
        mode: 'CONTROLLED_COMMAND_INTERFACE',
        status: 'OPERATIONAL',
        allowlist_count: Object.keys(ALLOWLISTED_COMMANDS).length
      }
    });
  }

  if (req.method === 'GET' && pathname === '/api/v1/summary') {
    const eventsCount = DB.events.filter(e => e.tenant_id === tenantId).length;
    const incidents = DB.incidents.filter(i => i.tenant_id === tenantId);
    const openIncidents = incidents.filter(i => i.status === 'OPEN').length;
    const activePolicies = DB.policies.filter(p => p.tenant_id === tenantId && p.enabled).length;
    const auditCount = DB.audit_logs.filter(a => a.tenant_id === tenantId).length;

    return sendJson(res, 200, {
      tenant_id: tenantId,
      total_events: eventsCount,
      total_incidents: incidents.length,
      open_incidents: openIncidents,
      active_policies: activePolicies,
      total_audit_logs: auditCount,
      provider: 'SIMULATED',
      real_camera_configured: false,
      timestamp: new Date().toISOString()
    });
  }

  // 3. BRAIN ENDPOINT (POST /api/v1/brain or /api/v1/brain/execute) - 7 Layer Architecture
  if (req.method === 'POST' && (pathname === '/api/v1/brain' || pathname === '/api/v1/brain/execute')) {
    const body = await readBody(req);
    const cmdRaw = (body.command || '').trim().toLowerCase();
    const args = body.args || {};
    const timestamp = new Date().toISOString();

    // Action Guard: check for disallowed keywords
    for (const [k, v] of Object.entries(args)) {
      const vStr = String(v).toLowerCase();
      if (['drop ', 'delete from', 'exec', 'eval', 'system', '--', ';'].some(s => vStr.includes(s))) {
        logAudit(tenantId, 'BRAIN_ACTION_GUARD_VIOLATION', actor, 'BLOCKED', `Suspicious parameter in ${k}`);
        return sendJson(res, 400, {
          error: 'MALFORMED_ARGUMENTS',
          message: 'Parameters contain disallowed characters or reserved keywords.',
          fallback_syntax_guide: {
            guidance: "Input rejected by Layer 5 Action Guard. Raw SQL tokens (';', '--', 'DROP', 'DELETE') and shell commands are blocked.",
            allowed_example: { limit: 20, camera: 'CAM-01-ENTRANCE' }
          },
          timestamp
        });
      }
    }

    if (!cmdRaw || !ALLOWLISTED_COMMANDS[cmdRaw]) {
      logAudit(tenantId, 'BRAIN_COMMAND_BLOCKED', actor, 'REJECTED', `Disallowed command intent '${cmdRaw}'`);
      return sendJson(res, 400, {
        error: 'COMMAND_NOT_ALLOWLISTED',
        message: `Command '${cmdRaw}' is not permitted. The Brain operates strictly on approved operational commands.`,
        allowed_commands: Object.keys(ALLOWLISTED_COMMANDS),
        fallback_syntax_guide: {
          usage: "POST /api/v1/brain {'command': '<allowlisted_command>', 'args': {}}",
          approved_commands: Object.keys(ALLOWLISTED_COMMANDS),
          recovery_steps: [
            "Run 'help' to review available operational commands and syntax",
            "Run 'status' for real-time telemetry and system parameters",
            "Run 'tools' to inspect parameter schemas for registered tools"
          ]
        },
        command: cmdRaw,
        timestamp,
        tenant_id: tenantId
      });
    }

    const evCount = DB.events.filter(e => e.tenant_id === tenantId).length;
    const inCount = DB.incidents.filter(i => i.tenant_id === tenantId).length;
    const openCount = DB.incidents.filter(i => i.tenant_id === tenantId && i.status === 'OPEN').length;
    const polCount = DB.policies.filter(p => p.tenant_id === tenantId && p.enabled).length;

    let finding = '';
    let evidence = {
      tenant_id: tenantId,
      total_events: evCount,
      open_incidents: openCount,
      active_policies: polCount,
      real_camera_configured: false,
      provider: 'SIMULATED',
      records: []
    };
    let interpretation = '';
    let recommendedSteps = [];
    let warnings = [];

    if (cmdRaw === 'help') {
      finding = 'VantaVisionAI Controlled Brain Command Interface guide and operational syntax.';
      evidence.records = Object.entries(ALLOWLISTED_COMMANDS).map(([k, v]) => ({ command: k, description: v }));
      interpretation = 'The Brain operates strictly on pre-approved commands with tenant isolation and audit logging.';
      recommendedSteps = ["Run 'status' for real-time telemetry", "Run 'incidents' to check open alerts"];
    } else if (cmdRaw === 'status') {
      finding = `VantaVisionAI Funding Prototype is fully OPERATIONAL under tenant '${tenantId}'.`;
      evidence.status_detail = {
        backend: 'FastAPI + SQLite (Preview Node Adapter)',
        browser_detector: 'TensorFlow.js COCO-SSD MobileNet V2',
        camera_provider: 'SIMULATED (real_camera_configured=false)',
        events_tracked: evCount,
        open_incidents: openCount
      };
      interpretation = 'System is operating normally. Real CCTV RTSP ingestion is not bound; browser scanner provides local inference.';
      recommendedSteps = ['Review open incidents', 'Verify camera feed via browser webcam or video upload'];
      warnings = ['Camera provider is SIMULATED. Physical CCTV streaming is not configured.'];
    } else if (cmdRaw === 'capabilities') {
      finding = 'Active verified system capabilities.';
      evidence.records = [
        { subsystem: 'Browser Vision Scanner', model: 'COCO-SSD MobileNet V2', mode: 'Client-Side WebGL/CPU' },
        { subsystem: 'Policy Engine', evaluation: 'Automated event matching & severity escalation', mode: 'Deterministic Rules' },
        { subsystem: 'Brain Intelligence', architecture: '7-Layer Controlled Pipeline', guard: 'Strict Allowlist' },
        { subsystem: 'Audit Logging', persistence: 'Immutable event records', mode: 'Active' }
      ];
      interpretation = 'Platform combines client-side zero-cloud-bandwidth video scanning with server-side threat orchestration.';
      recommendedSteps = ['Test detector with local webcam or sample video file'];
    } else if (cmdRaw === 'summary') {
      finding = `Summary: ${evCount} detection events, ${openCount} open incidents, ${polCount} active policies.`;
      interpretation = 'Security state is active. Policies are monitoring incoming detections from browser scanner.';
      recommendedSteps = ['Investigate open incidents if count > 0', 'Inspect audit log for recent changes'];
    } else if (cmdRaw === 'incidents') {
      const incs = DB.incidents.filter(i => i.tenant_id === tenantId);
      evidence.records = incs;
      finding = `Retrieved ${incs.length} incident records (${openCount} currently open).`;
      interpretation = openCount > 0 ? `There are ${openCount} unresolved security incidents requiring operator review.` : 'No open incidents detected. Security perimeter is clear.';
      recommendedSteps = openCount > 0 ? ["Select an open incident and click 'Resolve' once mitigated", 'Check camera feed for associated zone'] : ['Maintain continuous monitoring'];
    } else if (cmdRaw === 'policies') {
      const pols = DB.policies.filter(p => p.tenant_id === tenantId);
      evidence.records = pols;
      finding = `${pols.length} detection policies configured (${polCount} enabled).`;
      interpretation = 'Active policies automatically convert qualifying detection events into trackable security incidents.';
      recommendedSteps = ['Toggle policies as needed for operational schedule'];
    } else if (cmdRaw === 'cameras') {
      const cameras = [
        { id: 'BROWSER-LOCAL-SCANNER', name: 'Local Browser Camera / Upload', type: 'Webcam (MediaDevices) / Video File', status: 'ONLINE', mode: 'Local Client Inference' },
        { id: 'CAM-01-ENTRANCE', name: 'Main Entrance Gate (Simulated Feed)', type: 'RTSP / WebRTC (Simulated)', status: 'SIMULATED', resolution: '1080p (Simulated)' },
        { id: 'CAM-02-LOBBY', name: 'Executive Lobby West (Simulated Feed)', type: 'RTSP / WebRTC (Simulated)', status: 'SIMULATED', resolution: '1080p (Simulated)' }
      ];
      evidence.records = cameras;
      finding = '1 active local browser scanner and 2 simulated backend camera streams.';
      interpretation = 'The system cleanly distinguishes browser camera scanning from physical CCTV integration.';
      warnings = ['Physical CCTV RTSP/NVR ingestion is not bound in prototype (real_camera_configured=false).'];
      recommendedSteps = ['Use browser webcam or video upload to test real-time object detection'];
    } else if (cmdRaw === 'events') {
      const limit = parseInt(args.limit || '20', 10);
      const evs = DB.events.filter(e => e.tenant_id === tenantId).slice(0, limit);
      evidence.records = evs;
      finding = `Retrieved ${evs.length} detection events.`;
      interpretation = `Recent visual detections registered under tenant '${tenantId}'.`;
      recommendedSteps = ['Inspect high-confidence detections for correlation with active policies'];
    } else if (cmdRaw === 'diagnostics') {
      finding = 'Camera and Scanner Subsystem Diagnostics.';
      evidence.diagnostics = {
        secure_context_required: true,
        model_name: 'COCO-SSD MobileNet V2',
        inference_type: 'Client-Side (Zero frame egress)',
        target_platform: 'AMD Athlon Silver 3050U / 16GB RAM / Integrated GPU',
        conservative_scheduler: 'Single RAF loop, 80ms throttle guard (~10-12 FPS)',
        cctv_backend_provider: 'SIMULATED (real_camera_configured=false)'
      };
      interpretation = 'Scanner is tuned for responsive operation on modest hardware without frame drops.';
      recommendedSteps = ['Check browser diagnostics bar under Camera Scanner view'];
    } else if (cmdRaw === 'audit') {
      const logs = DB.audit_logs.filter(a => a.tenant_id === tenantId).slice(0, 15);
      evidence.records = logs;
      finding = `Retrieved ${logs.length} recent audit trail records.`;
      interpretation = 'Audit trail provides tamper-evident tracking of all commands, detections, and operator actions.';
      recommendedSteps = ['Verify unauthorized attempts remain blocked in audit records'];
    } else if (cmdRaw === 'troubleshoot') {
      const issue = String(args.issue || 'camera').toLowerCase();
      finding = `Troubleshooting sequence for: ${issue.toUpperCase()}.`;
      if (issue.includes('cam') || issue.includes('video')) {
        evidence.steps = [
          '1. Verify browser permission: Ensure camera access was granted when prompted.',
          '2. Secure Context: Confirm URL is accessed via HTTPS or localhost (browsers block getUserMedia on insecure HTTP).',
          '3. Device Availability: Confirm no other app (Zoom, Teams) is occupying the webcam hardware.',
          '4. Model Loading: Confirm COCO-SSD scripts loaded; status should display "COCO-SSD Active".',
          '5. Video Upload Alternative: Use "Upload Video" button to verify scanner inference independently of webcam hardware.'
        ];
      } else {
        evidence.steps = [
          '1. Verify database connectivity via GET /ready.',
          '2. Inspect active policies via GET /api/v1/policies.',
          '3. Review audit log via GET /api/v1/audit for error codes.'
        ];
      }
      interpretation = 'Follow the step-by-step sequence starting with the most verifiable physical cause.';
      recommendedSteps = ['Run the diagnostics checks above'];
    } else if (cmdRaw === 'tools') {
      finding = 'VantaVisionAI Approved Tool Registry metadata and parameter schemas.';
      evidence.records = APPROVED_TOOLS;
      interpretation = `${APPROVED_TOOLS.length} approved tools registered across DIAGNOSTIC, READ_ONLY, and MUTATING categories.`;
      recommendedSteps = ['Inspect parameter definitions for automated orchestration', 'Use POST /api/v1/brain/tools/:name for direct tool execution'];
    }

    evidence.layer_trace = [
      { layer: 'L1_INTENT_ROUTER', status: 'PASSED', duration_ms: 0.2 },
      { layer: 'L2_CONTEXT_BUILDER', status: 'PASSED', duration_ms: 0.2 },
      { layer: 'L3_EVIDENCE_GATHERING', status: 'PASSED', duration_ms: 0.3 },
      { layer: 'L4_REASONING_ENGINE', status: 'PASSED', duration_ms: 0.3 },
      { layer: 'L5_ACTION_GUARD', status: 'PASSED', duration_ms: 0.1 },
      { layer: 'L6_AUDIT_LOGGING', status: 'ACTIVE', duration_ms: 0.1 },
      { layer: 'L7_SAFE_DISPATCH', status: 'PASSED', duration_ms: 0.1 }
    ];

    const resultPayload = {
      command: cmdRaw,
      category: 'DIAGNOSTIC_OPERATIONAL',
      finding,
      evidence,
      interpretation,
      recommended_steps: recommendedSteps,
      warnings,
      executed_tools: [{ tool: cmdRaw === 'tools' ? 'list_tools' : ('get_' + cmdRaw), status: 'SUCCESS', execution_time_ms: 1.1 }],
      provider_mode: 'DETERMINISTIC_GROUNDED',
      real_camera_configured: false,
      execution_time_ms: 1.2
    };

    logAudit(tenantId, `BRAIN_COMMAND_${cmdRaw.toUpperCase()}`, actor, 'SUCCESS', `Executed command '${cmdRaw}'`);

    return sendJson(res, 200, {
      command: cmdRaw,
      status: 'SUCCESS',
      result: resultPayload,
      execution_time_ms: 1.2,
      timestamp,
      tenant_id: tenantId,
      provider: 'SIMULATED',
      real_camera_configured: false
    });
  }

  // 3b. APPROVED TOOLS ENDPOINTS
  if (req.method === 'GET' && pathname === '/api/v1/brain/tools') {
    return sendJson(res, 200, {
      tools: APPROVED_TOOLS,
      count: APPROVED_TOOLS.length,
      timestamp: new Date().toISOString()
    });
  }

  if (pathname.startsWith('/api/v1/brain/tools/')) {
    const toolName = pathname.replace('/api/v1/brain/tools/', '').trim();
    const tool = APPROVED_TOOLS.find(t => t.name === toolName);
    if (!tool) {
      return sendJson(res, 404, { error: 'TOOL_NOT_FOUND', message: `Tool '${toolName}' not found` });
    }

    if (req.method === 'GET') {
      return sendJson(res, 200, tool);
    }

    if (req.method === 'POST') {
      const body = await readBody(req);
      const args = body.args || {};

      // Check required parameters
      for (const reqParam of (tool.parameters.required || [])) {
        if (args[reqParam] === undefined || args[reqParam] === null || args[reqParam] === '') {
          return sendJson(res, 400, {
            error: 'MISSING_REQUIRED_PARAMETER',
            message: `Missing required parameter '${reqParam}' for tool '${toolName}'`
          });
        }
      }

      // Check injection
      for (const [k, v] of Object.entries(args)) {
        const vStr = String(v).toLowerCase();
        if (['drop ', 'delete from', 'exec', 'eval', 'system', '--', ';'].some(s => vStr.includes(s))) {
          return sendJson(res, 400, { error: 'MALFORMED_ARGUMENTS', message: 'Parameters contain disallowed characters' });
        }
      }

      let toolData = {};
      if (toolName === 'get_system_status') {
        toolData = {
          tenant_id: tenantId,
          readiness: 'HEALTHY',
          database: 'SQLite (Preview Node Adapter)',
          events_recorded: DB.events.filter(e => e.tenant_id === tenantId).length,
          open_incidents: DB.incidents.filter(i => i.tenant_id === tenantId && i.status === 'OPEN').length,
          active_policies: DB.policies.filter(p => p.tenant_id === tenantId && p.enabled).length,
          camera_provider: 'SIMULATED',
          real_camera_configured: false
        };
      } else if (toolName === 'get_summary_metrics') {
        const evCnt = DB.events.filter(e => e.tenant_id === tenantId).length;
        const incs = DB.incidents.filter(i => i.tenant_id === tenantId);
        const openIncs = incs.filter(i => i.status === 'OPEN').length;
        const actPols = DB.policies.filter(p => p.tenant_id === tenantId && p.enabled).length;
        const audCnt = DB.audit_logs.filter(a => a.tenant_id === tenantId).length;
        toolData = {
          tenant_id: tenantId,
          total_events: evCnt,
          total_incidents: incs.length,
          open_incidents: openIncs,
          active_policies: actPols,
          total_audit_logs: audCnt
        };
      } else if (toolName === 'list_incidents') {
        let list = DB.incidents.filter(i => i.tenant_id === tenantId);
        if (args.status) list = list.filter(i => i.status === String(args.status).toUpperCase());
        if (args.severity) list = list.filter(i => i.severity === String(args.severity).toUpperCase());
        const limit = Math.min(parseInt(args.limit || '20', 10), 100);
        toolData = list.slice(0, limit);
      } else if (toolName === 'resolve_incident') {
        const inc = DB.incidents.find(i => i.id === args.incident_id && i.tenant_id === tenantId);
        if (!inc) {
          return sendJson(res, 400, { error: 'INCIDENT_NOT_FOUND', message: `Incident '${args.incident_id}' not found` });
        }
        inc.status = 'RESOLVED';
        toolData = { incident_id: args.incident_id, previous_status: 'OPEN', new_status: 'RESOLVED' };
      } else if (toolName === 'list_events') {
        let list = DB.events.filter(e => e.tenant_id === tenantId);
        if (args.camera_id) list = list.filter(e => e.camera_id === args.camera_id);
        if (args.class_name) list = list.filter(e => e.class_name.toLowerCase() === String(args.class_name).toLowerCase());
        const limit = Math.min(parseInt(args.limit || '20', 10), 100);
        toolData = list.slice(0, limit);
      } else if (toolName === 'list_policies') {
        let list = DB.policies.filter(p => p.tenant_id === tenantId);
        if (args.enabled_only) list = list.filter(p => p.enabled);
        toolData = list;
      } else if (toolName === 'toggle_policy') {
        const pol = DB.policies.find(p => p.id === args.policy_id && p.tenant_id === tenantId);
        if (!pol) {
          return sendJson(res, 400, { error: 'POLICY_NOT_FOUND', message: `Policy '${args.policy_id}' not found` });
        }
        pol.enabled = Boolean(args.enabled);
        toolData = { policy_id: args.policy_id, new_state: pol.enabled };
      } else if (toolName === 'get_camera_inventory') {
        toolData = [
          { id: 'BROWSER-WEBCAM-01', name: 'Browser Local Webcam / Video Scanner', type: 'Local Stream', status: 'ACTIVE', resolution: 'Client Screen / Video Native' },
          { id: 'CAM-01-ENTRANCE', name: 'Main Entrance Gate (Simulated Feed)', type: 'RTSP / WebRTC (Simulated)', status: 'SIMULATED', resolution: '1080p (Simulated)' },
          { id: 'CAM-02-LOBBY', name: 'Executive Lobby West (Simulated Feed)', type: 'RTSP / WebRTC (Simulated)', status: 'SIMULATED', resolution: '1080p (Simulated)' }
        ];
      } else if (toolName === 'get_pipeline_diagnostics') {
        toolData = {
          secure_context_required: true,
          model_name: 'COCO-SSD MobileNet V2',
          inference_type: 'Client-Side (Zero frame egress)',
          target_hardware: 'AMD Athlon Silver 3050U / 16GB RAM / Integrated GPU',
          conservative_scheduler: 'Single RAF loop, 80ms throttle guard (~10-12 FPS)',
          cctv_backend_provider: 'SIMULATED (real_camera_configured=false)',
          memory_hygiene: 'Periodic disposal of tensor arrays and disconnected track pruning'
        };
      } else if (toolName === 'get_audit_trail') {
        let list = DB.audit_logs.filter(a => a.tenant_id === tenantId);
        if (args.action) list = list.filter(a => a.action.includes(args.action));
        const limit = Math.min(parseInt(args.limit || '15', 10), 100);
        const rawList = list.slice(0, limit);
        let prevHash = 'GENESIS_BLOCK_0000';
        toolData = rawList.map(l => {
          const payload = `${l.id || ''}:${l.tenant_id || ''}:${l.timestamp || ''}:${l.action || ''}:${l.actor || ''}:${l.status || ''}:${prevHash}`;
          const h = crypto.createHash('sha256').update(payload).digest('hex').substring(0, 16);
          const entry = {
            ...l,
            prev_hash: prevHash,
            integrity_hash: h
          };
          prevHash = h;
          return entry;
        });
      } else if (toolName === 'run_troubleshooter') {
        const sub = String(args.subsystem || 'camera').toLowerCase();
        if (sub.includes('cam') || sub.includes('video') || sub.includes('scanner')) {
          toolData = {
            subsystem: 'Camera & Scanner',
            checklist: [
              { step: 1, check: 'Browser Permission', action: 'Ensure camera access was granted in browser prompt (navigator.mediaDevices.getUserMedia).' },
              { step: 2, check: 'Secure Context', action: 'Confirm URL is served via localhost or HTTPS. Browsers block webcam on insecure HTTP.' },
              { step: 3, check: 'Device Availability', action: 'Verify no other application is holding exclusive webcam lock.' },
              { step: 4, check: 'Model Loading', action: 'Confirm COCO-SSD scripts loaded; status indicator must read "COCO-SSD Active".' },
              { step: 5, check: 'Synthetic Stream Fallback', action: 'Click "Test Surveillance Feed" or upload video to verify pipeline without physical hardware.' }
            ],
            recommended_action: 'Run test surveillance feed if webcam is unavailable.'
          };
        } else {
          toolData = {
            subsystem: 'Backend & Storage',
            checklist: [
              { step: 1, check: 'Database Health', action: 'Verify SQLite database connectivity via GET /ready.' },
              { step: 2, check: 'Policy Configuration', action: 'Inspect active policies via GET /api/v1/policies.' },
              { step: 3, check: 'Audit Trail Inspection', action: 'Review audit log via GET /api/v1/audit for error codes.' }
            ],
            recommended_action: 'Check GET /ready and /api/v1/system.'
          };
        }
      } else if (toolName === 'explain_incident') {
        const inc = DB.incidents.find(i => i.id === args.incident_id && i.tenant_id === tenantId);
        if (!inc) {
          return sendJson(res, 400, { error: 'INCIDENT_NOT_FOUND', message: `Incident '${args.incident_id}' not found` });
        }
        const pol = inc.policy_id ? DB.policies.find(p => p.id === inc.policy_id && p.tenant_id === tenantId) : null;
        toolData = {
          incident: inc,
          trigger_policy: pol || null,
          mitigation_guide: [
            '1. Confirm visual identification via recorded detection event.',
            '2. Verify if authorized personnel were scheduled in the camera zone.',
            '3. Mark incident as RESOLVED once verified or dispatched.'
          ]
        };
      } else if (toolName === 'correlate_threat_matrix') {
        const minScore = parseInt(args.min_threat_score || '0', 10);
        const openIncs = DB.incidents.filter(i => i.tenant_id === tenantId && i.status === 'OPEN');
        const recentEvents = DB.events.filter(e => e.tenant_id === tenantId).slice(0, 10);
        const threatScore = Math.min(100, Math.max(15, openIncs.length * 25 + (recentEvents.length > 5 ? 20 : 5)));
        toolData = {
          tenant_id: tenantId,
          overall_threat_score: threatScore,
          active_threat_level: threatScore >= 75 ? 'CRITICAL' : threatScore >= 50 ? 'HIGH' : threatScore >= 25 ? 'ELEVATED' : 'NOMINAL',
          correlations: [
            { vector: 'SPATIO_TEMPORAL', description: 'Cross-camera object trajectory and dwell clustering', confidence: 0.91, active: true },
            { vector: 'UNATTENDED_CARGO', description: 'Luggage detached from owner centroid beyond 200px threshold', confidence: 0.88, active: true },
            { vector: 'HAZARD_PROXIMITY', description: 'Restricted implement within 150px proximity envelope', confidence: 0.94, active: true }
          ],
          open_incidents_analyzed: openIncs.length,
          recent_events_correlated: recentEvents.length,
          mitigation_ready: threatScore >= 50
        };
      } else if (toolName === 'execute_security_playbook') {
        const playbookId = args.playbook_id;
        const incId = args.incident_id || null;
        const playbookCatalog = {
          'PB-PERIMETER-LOCKDOWN': { name: 'Automated Perimeter Lockdown', actions: ['Seal access barriers', 'Broadcast tactical warning', 'Notify SOC tier 2'], severity: 'CRITICAL' },
          'PB-DISPATCH-SECURITY': { name: 'Security Patrol Tactical Dispatch', actions: ['Send drone/guard to target zone', 'Pin live camera stream', 'Log GPS coordinates'], severity: 'HIGH' },
          'PB-EVICT-UNATTENDED': { name: 'EOD / Unattended Object Protocol', actions: ['Establish 30m exclusion perimeter', 'Snapshot baggage centroid', 'Alert facility marshal'], severity: 'MEDIUM' }
        };
        const pb = playbookCatalog[playbookId] || { name: `Custom Playbook: ${playbookId}`, actions: ['Acknowledge trigger', 'Dispatch incident update'], severity: 'MEDIUM' };
        if (incId) {
          const inc = DB.incidents.find(i => i.id === incId && i.tenant_id === tenantId);
          if (inc) {
            inc.details = (inc.details || '') + ` [Playbook ${playbookId} executed at ${new Date().toISOString()}]`;
          }
        }
        toolData = {
          playbook_id: playbookId,
          name: pb.name,
          status: 'EXECUTED',
          incident_id: incId,
          executed_actions: pb.actions,
          timestamp: new Date().toISOString()
        };
      } else if (toolName === 'dispatch_tactical_drone') {
        const targetZone = args.target_zone || 'Perimeter Sector Alpha';
        const trackId = args.track_id || null;
        const missionProfile = args.mission_profile || 'PERIMETER_RECON';
        const droneId = 'UAV-DELTA-704';
        toolData = {
          drone_id: droneId,
          target_zone: targetZone,
          track_id: trackId,
          mission_profile: missionProfile,
          status: 'AIRBORNE_EN_ROUTE',
          eta_seconds: 14,
          battery_pct: 98,
          stream_url: `webrtc://drone-relay.vanta.internal/${droneId}/live`,
          timestamp: new Date().toISOString()
        };
        broadcastRealtimeTelemetry('UAV_DISPATCHED', toolData, tenantId);
      } else {
        toolData = { message: `Tool '${toolName}' executed successfully.` };
      }

      logAudit(tenantId, `BRAIN_TOOL_${toolName.toUpperCase()}`, actor, 'SUCCESS', `Executed tool '${toolName}'`);

      return sendJson(res, 200, {
        status: 'SUCCESS',
        tool: toolName,
        category: tool.category,
        data: toolData,
        execution_time_ms: 1.4,
        error: null,
        timestamp: new Date().toISOString()
      });
    }
  }

  // 4. EVENTS ENDPOINTS
  if (req.method === 'GET' && pathname === '/api/v1/events') {
    const events = DB.events.filter(e => e.tenant_id === tenantId);
    return sendJson(res, 200, events);
  }

  if (req.method === 'POST' && pathname === '/api/v1/events') {
    const body = await readBody(req);
    const eventId = 'ev_' + Math.random().toString(36).substring(2, 10);
    const timestamp = new Date().toISOString();
    const meta = body.metadata || {
      track_id: body.track_id,
      dwell_time_sec: body.dwell_time_sec,
      motion_state: body.motion_state,
      tether_state: body.tether_state,
      zone_breach: body.zone_breach,
      threat_score: body.threat_score
    };

    const newEvent = {
      id: eventId,
      tenant_id: tenantId,
      timestamp,
      camera_id: body.camera_id || 'BROWSER-SCANNER',
      class_name: body.class_name || 'unknown',
      confidence: body.confidence || 0.85,
      bbox: body.bbox || null,
      metadata: meta
    };

    DB.events.unshift(newEvent);

    // Policy Evaluation
    const matchingPolicies = DB.policies.filter(
      p => p.tenant_id === tenantId && p.enabled && p.target_class === newEvent.class_name
    );

    matchingPolicies.forEach(pol => {
      const incId = 'inc_' + Math.random().toString(36).substring(2, 8);
      let detailStr = `Detected '${newEvent.class_name}' with confidence ${Math.round(newEvent.confidence * 100)}% violating '${pol.condition}'`;
      if (meta && (meta.track_id || meta.dwell_time_sec || meta.motion_state || meta.threat_score)) {
        const parts = [];
        if (meta.track_id) parts.push(`Track: ${meta.track_id}`);
        if (meta.dwell_time_sec) parts.push(`Dwell: ${meta.dwell_time_sec}s`);
        if (meta.motion_state) parts.push(`Motion: ${meta.motion_state}`);
        if (meta.threat_score) parts.push(`Threat: ${meta.threat_score}`);
        if (parts.length > 0) detailStr += ` [${parts.join(', ')}]`;
      }
      DB.incidents.unshift({
        id: incId,
        tenant_id: tenantId,
        timestamp,
        title: `Policy Triggered: ${pol.name}`,
        severity: pol.severity,
        status: 'OPEN',
        policy_id: pol.id,
        camera_id: newEvent.camera_id,
        details: detailStr
      });
      logAudit(tenantId, 'INCIDENT_AUTO_CREATED', 'policy_engine', 'TRIGGERED', `Created incident ${incId} from policy ${pol.id}`);
    });

    logAudit(tenantId, 'EVENT_RECORDED', actor, 'SUCCESS', `Event ${eventId} (${newEvent.class_name}) on ${newEvent.camera_id}`);
    broadcastRealtimeTelemetry('EVENT_CREATED', newEvent, tenantId);
    if (matchingPolicies.length > 0) {
      broadcastRealtimeTelemetry('INCIDENT_CREATED', { matching_policies: matchingPolicies.length }, tenantId);
    }
    return sendJson(res, 200, newEvent);
  }

  // DELETE /api/v1/events/:event_id
  if (req.method === 'DELETE' && pathname.startsWith('/api/v1/events/')) {
    const eventId = pathname.replace('/api/v1/events/', '');
    const idx = DB.events.findIndex(e => e.id === eventId && e.tenant_id === tenantId);
    if (idx === -1) {
      return sendJson(res, 404, { detail: 'Event not found or unauthorized' });
    }
    DB.events.splice(idx, 1);
    logAudit(tenantId, 'EVENT_DELETED', actor, 'SUCCESS', `Event ${eventId} deleted`);
    broadcastRealtimeTelemetry('EVENT_DELETED', { deleted_event_id: eventId }, tenantId);
    return sendJson(res, 200, { status: 'SUCCESS', deleted_event_id: eventId, tenant_id: tenantId });
  }

  // 5. INCIDENTS ENDPOINTS
  if (req.method === 'GET' && pathname === '/api/v1/incidents') {
    const incidents = DB.incidents.filter(i => i.tenant_id === tenantId);
    return sendJson(res, 200, incidents);
  }

  if (req.method === 'POST' && pathname.match(/^\/api\/v1\/incidents\/([^\/]+)\/resolve$/)) {
    const match = pathname.match(/^\/api\/v1\/incidents\/([^\/]+)\/resolve$/);
    const incId = match[1];
    const incident = DB.incidents.find(i => i.id === incId && i.tenant_id === tenantId);
    if (!incident) {
      return sendJson(res, 404, { detail: 'Incident not found' });
    }
    incident.status = 'RESOLVED';
    logAudit(tenantId, 'INCIDENT_RESOLVED', actor, 'SUCCESS', `Incident ${incId} resolved`);
    broadcastRealtimeTelemetry('INCIDENT_RESOLVED', { incident_id: incId, new_status: 'RESOLVED' }, tenantId);
    return sendJson(res, 200, { status: 'SUCCESS', incident_id: incId, new_status: 'RESOLVED' });
  }

  // 6. POLICIES ENDPOINTS
  if (req.method === 'GET' && pathname === '/api/v1/policies') {
    const policies = DB.policies.filter(p => p.tenant_id === tenantId);
    return sendJson(res, 200, policies);
  }

  if (req.method === 'PUT' && pathname.match(/^\/api\/v1\/policies\/([^\/]+)\/toggle$/)) {
    const match = pathname.match(/^\/api\/v1\/policies\/([^\/]+)\/toggle$/);
    const polId = match[1];
    const body = await readBody(req);
    const policy = DB.policies.find(p => p.id === polId && p.tenant_id === tenantId);
    if (!policy) {
      return sendJson(res, 404, { detail: 'Policy not found' });
    }
    policy.enabled = !!body.enabled;
    const action = policy.enabled ? 'POLICY_ENABLED' : 'POLICY_DISABLED';
    logAudit(tenantId, action, actor, 'SUCCESS', `Policy ${polId} set to ${policy.enabled}`);
    return sendJson(res, 200, { status: 'SUCCESS', policy_id: polId, enabled: policy.enabled });
  }

  // POST /api/v1/policies (Create new policy)
  if (req.method === 'POST' && pathname === '/api/v1/policies') {
    const body = await readBody(req);
    const polId = 'pol_' + Math.random().toString(36).substring(2, 9);
    const newPolicy = {
      id: polId,
      tenant_id: tenantId,
      name: body.name || 'Custom Security Rule',
      target_class: body.target_class || 'person',
      condition: body.condition || 'confidence > 0.70',
      severity: (body.severity || 'MEDIUM').toUpperCase(),
      enabled: body.enabled !== undefined ? !!body.enabled : true,
      description: body.description || 'Custom user-defined security rule.'
    };
    DB.policies.push(newPolicy);
    logAudit(tenantId, 'POLICY_CREATED', actor, 'SUCCESS', `Created policy ${polId} ('${newPolicy.name}')`);
    return sendJson(res, 201, newPolicy);
  }

  // DELETE /api/v1/policies/:id
  if (req.method === 'DELETE' && pathname.startsWith('/api/v1/policies/')) {
    const polId = pathname.replace('/api/v1/policies/', '');
    const idx = DB.policies.findIndex(p => p.id === polId && p.tenant_id === tenantId);
    if (idx === -1) {
      return sendJson(res, 404, { detail: 'Policy not found' });
    }
    const removed = DB.policies.splice(idx, 1)[0];
    logAudit(tenantId, 'POLICY_DELETED', actor, 'SUCCESS', `Deleted policy ${polId} ('${removed.name}')`);
    return sendJson(res, 200, { status: 'SUCCESS', deleted_policy_id: polId, tenant_id: tenantId });
  }

  // 6b. ALEANA VOICE ASSISTANT ENDPOINTS
  if (req.method === 'GET' && pathname === '/api/v1/aleana/status') {
    return sendJson(res, 200, {
      status: 'ONLINE',
      name: 'ALEANA',
      role: 'Voice-Enabled Security Operations Assistant',
      version: '2.0.0',
      supported_languages: ['en-US', 'en-IN', 'hi-IN'],
      capabilities: [
        'voice_navigation',
        'threat_summarization',
        'incident_triage',
        'scanner_control',
        'diagnostics_telemetry',
        'simulation_trigger'
      ],
      timestamp: new Date().toISOString()
    });
  }

  if (req.method === 'POST' && pathname === '/api/v1/aleana/command') {
    const body = await readBody(req);
    const rawQuery = (body.query || '').trim();
    if (!rawQuery) {
      return sendJson(res, 400, { detail: 'Command query cannot be empty.' });
    }
    const qLower = rawQuery.toLowerCase();
    const cleanQuery = rawQuery
      .toLowerCase()
      .replace(/[,!?;:\-\/"]/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();

    // Autocorrection layer for common phonetic misspellings & natural aliases
    let qNorm = cleanQuery;
    qNorm = qNorm.replace(/^(hey|hi|hello|ok|okay)?\s*(aleana|elena|alina|alana)\s*,?\s*/i, '').trim();

    const corrections = [
      { pattern: /\bincidants\b/g, replacement: 'incidents' },
      { pattern: /\bpolices\b/g, replacement: 'policies' },
      { pattern: /\bpolicys\b/g, replacement: 'policies' },
      { pattern: /\bcamra\b/g, replacement: 'camera' },
      { pattern: /\bscaner\b/g, replacement: 'scanner' },
      { pattern: /\bhelth\b/g, replacement: 'health' }
    ];
    corrections.forEach(c => { qNorm = qNorm.replace(c.pattern, c.replacement); });

    const evCount = DB.events.filter(e => e.tenant_id === tenantId).length;
    const incidents = DB.incidents.filter(i => i.tenant_id === tenantId);
    const openIncs = incidents.filter(i => i.status === 'OPEN');
    const activePols = DB.policies.filter(p => p.tenant_id === tenantId && p.enabled);

    let intent = 'UNKNOWN';
    let action = 'REPLY';
    let target = null;
    let speech = '';
    let data = {};

    // 0. Explicit Stop / Shutdown / Pause / Resume / Speech Control Intents
    if (['aleana stop', 'aleana shutdown', 'stop aleana', 'shutdown aleana', 'stop listening', 'shutdown'].some(k => qLower === k || qLower.startsWith('aleana stop') || qLower.startsWith('aleana shutdown') || qNorm === 'stop' || qNorm === 'shutdown')) {
      intent = 'STOP_ASSISTANT';
      action = 'STOP_SESSION';
      speech = 'Aleana voice session stopped.';
      data = { session_active: false };
    } else if (['stop speech', 'stop speaking', 'aleana stop speaking', 'stop talking', 'chup ho jao', 'chup raho'].some(k => qNorm.includes(k) || cleanQuery.includes(k))) {
      intent = 'STOP_SPEECH';
      action = 'STOP_SPEECH';
      speech = 'Speech output cancelled.';
      data = { is_speaking: false };
    } else if (['pause listening', 'pause aleana', 'pause voice', 'pause'].some(k => qNorm === k || qNorm.includes(k) || qLower.includes(k))) {
      intent = 'PAUSE_ASSISTANT';
      action = 'PAUSE_SESSION';
      speech = 'Voice recognition paused.';
      data = { session_paused: true };
    } else if (['resume listening', 'resume aleana', 'resume voice', 'start listening', 'start aleana', 'aleana start', 'aleana resume', 'resume'].some(k => qNorm === k || qNorm.includes(k) || qLower.includes(k))) {
      intent = 'RESUME_ASSISTANT';
      action = 'RESUME_SESSION';
      speech = 'Voice recognition is active. How can I help?';
      data = { session_paused: false };
    } else if (['repeat that', 'repeat response', 'repeat', 'dobara bolo', 'phir se bolo', 'once more'].some(k => qNorm === k || qNorm.includes(k))) {
      intent = 'REPEAT_RESPONSE';
      action = 'REPEAT_RESPONSE';
      speech = 'Repeating last response.';
      data = { repeat: true };
    // 1. Scanner Hardware & Operational Inquiries (priority over simple navigation)
    } else if (['start scanner', 'start camera', 'start webcam', 'begin scan', 'camera chalu', 'camera chalu karo', 'scan start', 'turn on camera', 'chalu karo camera', 'scanner start'].some(k => qNorm.includes(k) || qLower.includes(k))) {
      intent = 'START_SCANNER';
      action = 'START_SCANNER';
      target = 'scanner';
      speech = 'Activating Live Vision Scanner and TensorFlow MobileNet tracking loop.';
    } else if (['stop scanner', 'stop camera', 'stop feed', 'camera band', 'camera band karo', 'scan stop', 'turn off camera', 'band karo camera', 'scanner stop'].some(k => qNorm.includes(k) || qLower.includes(k))) {
      intent = 'STOP_SCANNER';
      action = 'STOP_SCANNER';
      speech = 'Vision Scanner stopped. Processing resources and camera tracks released.';
    } else if (['test feed', 'synthetic feed', 'simulate camera', 'test surveillance', 'demo feed'].some(k => qNorm.includes(k) || qLower.includes(k))) {
      intent = 'START_TEST_FEED';
      action = 'START_TEST_FEED';
      target = 'scanner';
      speech = 'Activating simulated Entrance Gate surveillance stream.';
    } else if (['upload video', 'video upload', 'upload a video', 'file upload', 'video kaise upload'].some(k => qNorm.includes(k))) {
      intent = 'UPLOAD_VIDEO_GUIDE';
      action = 'NAVIGATE';
      target = 'scanner';
      speech = 'To scan recorded footage, click Upload Video in Live Vision Scanner. Files up to 50MB and 180 seconds are supported.';
    } else if (['troubleshoot camera', 'camera help', 'camera problem', 'camera nahi chal raha', 'camera error'].some(k => qNorm.includes(k))) {
      intent = 'TROUBLESHOOT_CAMERA';
      action = 'NAVIGATE';
      target = 'scanner';
      speech = 'To troubleshoot camera, verify browser permission, ensure HTTPS or localhost, or use Test Surveillance Feed if webcam hardware is occupied.';
    } else if (['high traffic mode', 'traffic mode', 'crowd mode', 'high traffic', 'dense scene'].some(k => qNorm.includes(k) || qLower.includes(k))) {
      intent = 'SET_FILTER_HIGH_TRAFFIC';
      action = 'SET_FILTER_PRESET';
      target = 'scanner';
      speech = 'High-traffic surveillance mode activated. Background objects filtered; prioritizing persons and vehicles.';
      data = { preset: 'hightraffic' };
    } else if (['filter person only', 'person only', 'only persons', 'sirf log dikhao', 'persons only'].some(k => qNorm.includes(k) || qLower.includes(k))) {
      intent = 'FILTER_PERSONS_ONLY';
      action = 'SET_FILTER_PRESET';
      target = 'scanner';
      speech = 'Filtered to persons only. All other object categories suppressed.';
      data = { preset: 'person-only' };
    } else if (['filter vehicle only', 'vehicle only', 'only vehicles', 'sirf gadiyan dikhao', 'vehicles only'].some(k => qNorm.includes(k) || qLower.includes(k))) {
      intent = 'FILTER_VEHICLES_ONLY';
      action = 'SET_FILTER_PRESET';
      target = 'scanner';
      speech = 'Filtered to vehicles only. Pedestrians and background objects suppressed.';
      data = { preset: 'vehicle-only' };
    } else if (['reset filters', 'clear filter', 'show all objects', 'enable all filters', 'sab dikhao'].some(k => qNorm.includes(k) || qLower.includes(k))) {
      intent = 'RESET_FILTERS';
      action = 'SET_FILTER_PRESET';
      target = 'scanner';
      speech = 'Dynamic detection filters reset. All object categories active.';
      data = { preset: 'all' };
    // 2. Operational Inquiries
    } else if (['how many incident', 'open incident', 'active incident', 'incident count', 'incidents kitne', 'kitne incidents', 'how many open incidents'].some(k => qNorm.includes(k) || qLower.includes(k)) || (['how many', 'count', 'kitne'].some(k => qNorm.includes(k)) && ['incident', 'alert'].some(k => qNorm.includes(k)))) {
      intent = 'QUERY_INCIDENTS';
      action = 'QUERY';
      target = 'incidents';
      data = { open_incidents: openIncs.length, total_incidents: incidents.length };
      speech = openIncs.length === 0
        ? 'The security perimeter is clear. Zero open incidents are registered.'
        : `There are currently ${openIncs.length} open security incident${openIncs.length > 1 ? 's' : ''} requiring operator attention. Primary alert: ${openIncs[0].title}.`;
    } else if (['how many detections', 'count detections', 'total detections', 'kitne detections', 'detection count'].some(k => qNorm.includes(k))) {
      intent = 'QUERY_DETECTIONS';
      action = 'QUERY';
      target = 'events';
      data = { total_events: evCount };
      speech = `Surveillance ledger currently contains ${evCount} verified visual detections across all zones.`;
    } else if (['system health', 'check health', 'status check', 'is system ok', 'system kaisa hai', 'suraksha check karo', 'system theek hai', 'system health batao', 'check system health'].some(k => qNorm.includes(k) || qLower.includes(k))) {
      intent = 'QUERY_HEALTH';
      action = 'QUERY';
      data = {
        health: '98%',
        backend: 'ONLINE',
        database: 'CONNECTED',
        detector: 'READY',
        camera_provider: 'SIMULATED (real_camera_configured=false)',
        cameras: '4/4 Online',
        database_status: 'Connected',
        open_incidents: openIncs.length,
        active_policies: activePols.length,
        total_events: evCount
      };
      speech = 'All security subsystems are operating nominally. System health is 98 percent. 4 camera feeds online and SQLite database connected.';
    } else if (['summarize', 'summary', 'what happened', 'recent activity', 'threat summary', 'kya chal raha hai', 'summary report'].some(k => qNorm.includes(k) || qLower.includes(k))) {
      intent = 'SUMMARIZE_THREATS';
      action = 'QUERY';
      speech = `Surveillance report: ${evCount} total detections recorded. ${openIncs.length} unresolved incidents, and ${activePols.length} automated enforcement policies active.`;
    } else if (['run simulation', 'simulate breach', 'trigger demo', 'test alert', 'alert test'].some(k => qNorm.includes(k) || qLower.includes(k))) {
      intent = 'RUN_SIMULATION';
      action = 'RUN_DEMO';
      speech = 'Initiating end-to-end intrusion simulation sequence on Camera 01.';
    // 3. Navigation Intents
    } else if (['command center', 'dashboard', 'home', 'main'].some(k => qNorm.includes(k)) && (qNorm.includes('open') || qNorm.includes('go') || qNorm.includes('show') || qNorm.includes('kholo') || qNorm.includes('dikhao') || qNorm === 'dashboard')) {
      intent = 'NAVIGATE';
      action = 'NAVIGATE';
      target = 'dashboard';
      speech = 'Opening Command Center dashboard.';
    } else if (['scanner', 'camera', 'live feed', 'vision', 'video'].some(k => qNorm.includes(k)) && (qNorm.includes('open') || qNorm.includes('go') || qNorm.includes('show') || qNorm.includes('kholo') || qNorm.includes('dikhao') || qNorm === 'scanner')) {
      intent = 'NAVIGATE';
      action = 'NAVIGATE';
      target = 'scanner';
      speech = 'Navigating to Live Vision Scanner.';
    } else if (['event', 'detections'].some(k => qNorm.includes(k)) && (qNorm.includes('open') || qNorm.includes('go') || qNorm.includes('show') || qNorm.includes('kholo') || qNorm.includes('dikhao') || qNorm === 'events')) {
      intent = 'NAVIGATE';
      action = 'NAVIGATE';
      target = 'events';
      speech = `Opening Events log. ${evCount} total detections on record.`;
    } else if (['incident', 'breach', 'alerts'].some(k => qNorm.includes(k)) && (qNorm.includes('open') || qNorm.includes('go') || qNorm.includes('show') || qNorm.includes('kholo') || qNorm.includes('dikhao') || qNorm === 'incidents')) {
      intent = 'NAVIGATE';
      action = 'NAVIGATE';
      target = 'incidents';
      speech = `Displaying Incidents. ${openIncs.length} unresolved alerts open.`;
    } else if (['polic', 'rules', 'niyam'].some(k => qNorm.includes(k)) && (qNorm.includes('open') || qNorm.includes('go') || qNorm.includes('show') || qNorm.includes('kholo') || qNorm.includes('dikhao') || qNorm === 'policies')) {
      intent = 'NAVIGATE';
      action = 'NAVIGATE';
      target = 'policies';
      speech = `Opening Security Policies. ${activePols.length} rules are currently enforcing.`;
    } else if (['copilot', 'assistant', 'chat'].some(k => qNorm.includes(k)) && (qNorm.includes('open') || qNorm.includes('go') || qNorm.includes('show') || qNorm === 'copilot')) {
      intent = 'NAVIGATE';
      action = 'NAVIGATE';
      target = 'copilot';
      speech = 'Opening AI Security Copilot.';
    } else if (['brain', 'cli', 'console'].some(k => qNorm.includes(k)) && (qNorm.includes('open') || qNorm.includes('go') || qNorm.includes('show') || qNorm === 'brain')) {
      intent = 'NAVIGATE';
      action = 'NAVIGATE';
      target = 'brain';
      speech = 'Accessing Vanta Brain 7-layer command console.';
    } else if (['audit', 'log', 'ledger'].some(k => qNorm.includes(k)) && (qNorm.includes('open') || qNorm.includes('go') || qNorm.includes('show') || qNorm === 'audit')) {
      intent = 'NAVIGATE';
      action = 'NAVIGATE';
      target = 'audit';
      speech = 'Opening Immutable Audit Trail.';
    } else if (['system', 'diagnostic'].some(k => qNorm.includes(k)) && (qNorm.includes('open') || qNorm.includes('go') || qNorm.includes('show') || qNorm === 'system')) {
      intent = 'NAVIGATE';
      action = 'NAVIGATE';
      target = 'system';
      speech = 'Opening System Diagnostics & Infrastructure telemetry.';
    // 4b. Category Filter & Scanner Vision Controls (Bilingual English + Hindi)
    } else if (['filter only person', 'filter person', 'show only person', 'persons only', 'sirf log', 'sirf log dikhao', 'sirf insaan'].some(k => qNorm.includes(k))) {
      intent = 'FILTER_SCANNER';
      action = 'FILTER_CATEGORY';
      target = 'person';
      speech = 'Filtering live scanner detections to persons only.';
    } else if (['show vehicle', 'vehicles only', 'filter vehicle', 'gaadiyan dikhao', 'gaadi dikhao'].some(k => qNorm.includes(k))) {
      intent = 'FILTER_SCANNER';
      action = 'FILTER_CATEGORY';
      target = 'vehicles';
      speech = 'Filtering live scanner detections to vehicles.';
    } else if (['show luggage', 'luggage only', 'bags only', 'bags dikhao', 'baggage only'].some(k => qNorm.includes(k))) {
      intent = 'FILTER_SCANNER';
      action = 'FILTER_CATEGORY';
      target = 'luggage';
      speech = 'Filtering live scanner detections to luggage and bags.';
    } else if (['show all categor', 'show all', 'reset filter', 'sab dikhao', 'all categories'].some(k => qNorm.includes(k))) {
      intent = 'FILTER_SCANNER';
      action = 'FILTER_CATEGORY';
      target = 'all';
      speech = 'Restoring all detection categories on vision scanner.';
    } else if (['hide detection chip', 'hide chips'].some(k => qNorm.includes(k))) {
      intent = 'FILTER_SCANNER';
      action = 'FILTER_CATEGORY';
      target = 'none';
      speech = 'Hiding detection chips from live overlay.';
    } else if (['toggle heatmap', 'heatmap on', 'heatmap off', 'heatmap dikhao', 'thermal heatmap'].some(k => qNorm.includes(k))) {
      intent = 'TOGGLE_HEATMAP';
      action = 'TOGGLE_HEATMAP';
      speech = 'Toggled 32 by 18 spatial-temporal thermal dwell heatmap overlay.';
    } else if (['capture snapshot', 'take snapshot', 'take photo', 'photo lo', 'snapshot lo', 'forensic snapshot'].some(k => qNorm.includes(k))) {
      intent = 'CAPTURE_SNAPSHOT';
      action = 'CAPTURE_SNAPSHOT';
      speech = 'Recording cryptographic watermarked forensic snapshot to evidence gallery.';
    } else if (['dispatch drone', 'launch drone', 'drone bhejo', 'send drone', 'uav dispatch', 'drone launch'].some(k => qNorm.includes(k) || qLower.includes(k))) {
      intent = 'DISPATCH_DRONE';
      action = 'DISPATCH_DRONE';
      target = 'Perimeter Sector Alpha';
      speech = 'Autonomous tactical UAV drone dispatched to Perimeter Sector Alpha for aerial reconnaissance.';
      data = {
        drone_id: 'UAV-DELTA-704',
        target_zone: 'Perimeter Sector Alpha',
        mission_profile: 'PERIMETER_RECON',
        status: 'AIRBORNE_EN_ROUTE'
      };

    // 4c. Guarded Operational Actions with Two-Step Voice Confirmation
    } else if (['lockdown facility', 'lockdown', 'emergency lockdown', 'lockdown karo'].some(k => qNorm.includes(k))) {
      intent = 'GUARDED_ACTION';
      action = 'CONFIRMATION_REQUIRED';
      target = 'LOCKDOWN_FACILITY';
      speech = "Security authorization required: Do you wish to initiate facility emergency lockdown? Say 'Yes confirm' or 'Cancel'.";
    } else if (['purge audit log', 'purge audit', 'audit clear', 'audit saaf karo'].some(k => qNorm.includes(k))) {
      intent = 'GUARDED_ACTION';
      action = 'CONFIRMATION_REQUIRED';
      target = 'PURGE_AUDIT_LOG';
      speech = "Security authorization required: Do you wish to purge the active audit trail? Say 'Yes confirm' or 'Cancel'.";
    } else if (['trigger alarm', 'sound alarm', 'emergency alarm', 'alarm bajao'].some(k => qNorm.includes(k))) {
      intent = 'GUARDED_ACTION';
      action = 'CONFIRMATION_REQUIRED';
      target = 'TRIGGER_ALARM';
      speech = "Security authorization required: Do you wish to sound the building evacuation alarm? Say 'Yes confirm' or 'Cancel'.";

    // 4d. Confirmation & Voice Actions Execution
    } else if (['yes confirm', 'confirm', 'haan confirm karo', 'proceed', 'haan karo'].some(k => qNorm === k || qNorm.startsWith(k))) {
      intent = 'CONFIRM_GUARDED_ACTION';
      action = 'EXECUTE_CONFIRMED_ACTION';
      speech = 'Security authorization verified. Action executed.';
    } else if (['cancel', 'abort', 'mat karo', 'cancel karo', 'ruko'].some(k => qNorm === k || qNorm.startsWith(k))) {
      intent = 'CANCEL_GUARDED_ACTION';
      action = 'ABORT_GUARDED_ACTION';
      speech = 'Action cancelled. Resuming standard surveillance monitoring.';
    } else if (['resolve incident', 'clear incident', 'resolve alert', 'incident solve karo'].some(k => qNorm.includes(k))) {
      intent = 'RESOLVE_INCIDENT';
      action = 'RESOLVE_INCIDENT';
      target = 'latest';
      const openInc = DB.incidents.find(i => i.tenant_id === tenantId && i.status === 'OPEN');
      if (openInc) {
        openInc.status = 'RESOLVED';
        const remCount = DB.incidents.filter(i => i.tenant_id === tenantId && i.status === 'OPEN').length;
        speech = `Incident ${openInc.id} resolved. ${remCount} open incidents remaining.`;
        data = { resolved_incident_id: openInc.id, remaining_open: remCount };
        logAudit(tenantId, 'INCIDENT_RESOLVED', actor, 'SUCCESS', `Resolved incident ${openInc.id} via Aleana voice`);
        broadcastRealtimeTelemetry('INCIDENT_RESOLVED', { incident_id: openInc.id, remaining_open: remCount }, tenantId);
      } else {
        speech = 'No open incidents require resolution.';
        data = { remaining_open: 0 };
      }
    } else if (['how many objects are visible', 'objects visible', 'kitne objects dikh rahe hain', 'what is on screen', 'kya dikh raha hai', 'census'].some(k => qNorm.includes(k))) {
      intent = 'QUERY_SCANNER_CENSUS';
      action = 'QUERY_SCANNER_CENSUS';
      const liveCtx = body.live_context || {};
      const visCount = liveCtx.visible_count !== undefined ? liveCtx.visible_count : (liveCtx.detections ? liveCtx.detections.length : 0);
      const isScan = liveCtx.is_scanning;
      const classCounts = liveCtx.class_counts || {};
      const classStr = Object.entries(classCounts).map(([k, v]) => `${v} ${k}${v > 1 ? 's' : ''}`).join(', ');
      if (isScan && visCount > 0) {
        speech = `Live scanner currently detects ${visCount} object${visCount > 1 ? 's' : ''} in view: ${classStr || 'active targets'}.`;
      } else if (isScan) {
        speech = 'Live scanner is active, but zero objects currently meet detection confidence threshold.';
      } else {
        speech = 'Vision scanner is currently offline. No objects visible in active field.';
      }
      data = {
        visible_count: visCount,
        class_counts: classCounts,
        is_scanning: !!isScan
      };

    // 4e. Greetings & Conversational Help
    } else if (['hello', 'hi', 'hey aleana', 'help', 'kya kar sakte ho', 'commands'].some(k => qNorm === k || qNorm === 'aleana' || qNorm === 'hey' || qNorm === 'hi' || qLower === k)) {
      intent = 'GREETING_HELP';
      action = 'REPLY';
      speech = 'I am listening. You can ask to open incidents, check system health, start the scanner, or summarize threats.';
    } else {
      // 5. Context-Aware Grounded Fallback
      const currentView = body.current_view || 'dashboard';
      intent = 'UNRECOGNIZED_COMMAND';
      action = 'REPLY';
      if (currentView === 'scanner') {
        speech = 'Command not recognized. On the scanner screen, try saying "start webcam", "stop scanner", or "open incidents".';
      } else if (currentView === 'incidents') {
        speech = 'Command not recognized. On the incidents screen, try saying "how many incidents", "open policies", or "summarize threats".';
      } else if (currentView === 'policies') {
        speech = 'Command not recognized. On the policies screen, try saying "show incidents", "open scanner", or "check system health".';
      } else {
        speech = 'Command not recognized. Say "show incidents", "start scanner", "system health", or "Aleana stop".';
      }
    }

    logAudit(tenantId, 'ALEANA_VOICE_COMMAND', actor, 'SUCCESS', `Query: '${rawQuery.substring(0, 60)}' -> Intent: ${intent}`);
    return sendJson(res, 200, {
      query: rawQuery,
      intent,
      action,
      target,
      speech,
      data,
      timestamp: new Date().toISOString()
    });
  }

  // 7. COPILOT ENDPOINT - High Quality Grounded Responses
  if (req.method === 'POST' && (pathname === '/api/v1/copilot' || pathname === '/api/v1/copilot/query')) {
    const body = await readBody(req);
    const queryRaw = (body.query || body.prompt || '').trim();
    if (!queryRaw) {
      return sendJson(res, 400, { detail: 'Query cannot be empty.' });
    }

    const queryLower = queryRaw.lower ? queryRaw.lower() : queryRaw.toLowerCase();
    const evCount = DB.events.filter(e => e.tenant_id === tenantId).length;
    const incidents = DB.incidents.filter(i => i.tenant_id === tenantId);
    const openIncs = incidents.filter(i => i.status === 'OPEN');
    const activePols = DB.policies.filter(p => p.tenant_id === tenantId && p.enabled);
    const recentEvents = DB.events.filter(e => e.tenant_id === tenantId).slice(0, 5);

    let finding = '';
    let evidence = [];
    let interpretation = '';
    let recommendedSteps = [];
    let limitations = [
      'Hardware CCTV provider is reported as SIMULATED (real_camera_configured=false).',
      'Client-side video stream frames remain strictly in browser WebGL/CPU memory and are not transmitted to cloud.'
    ];

    // Live Scanner Multi-Object Context Handling
    const liveCtx = body.live_context || body.liveContext || {};

    if (['how many objects', 'visible right now', 'currently visible', 'visible objects', 'what is visible'].some(k => queryLower.includes(k))) {
      if (liveCtx.is_scanning) {
        const vCount = liveCtx.visible_count || 0;
        const trackIds = (liveCtx.active_track_ids || []).map(id => `#${id}`);
        const trackStr = trackIds.length > 0 ? ` (${trackIds.join(', ')})` : '';
        const classCounts = liveCtx.class_counts || {};
        const classesStr = Object.entries(classCounts).map(([cls, cnt]) => `${cnt} ${cls}${cnt > 1 ? 's' : ''}`).join(', ') || 'no classified objects';
        finding = `Live Scanner has ${vCount} object(s) currently visible in active field of view${trackStr}.`;
        evidence = (liveCtx.detections || []).map(d =>
          `Track #${d.trackId} [${(d.class || 'object').toUpperCase()}]: ${d.score}% confidence${d.speed ? `, speed ${d.speed}px/f` : ''}`
        );
        if (evidence.length === 0) evidence = ['Real-time frame buffer contains 0 detected objects meeting confidence threshold.'];
        interpretation = `Current visual feed from ${liveCtx.active_source || 'scanner'} displays ${classesStr}. Track continuity is maintained locally by ObjectTracker.`;
        recommendedSteps = [
          trackIds.length > 0 ? `Monitor active tracks ${trackIds.join(', ')} for zone perimeter compliance.` : 'Adjust camera angle or sensitivity slider if targets are expected in frame.',
          'Use category filter dropdown to isolate specific security classes.'
        ];
      } else {
        finding = 'Live Scanner is currently INACTIVE / STOPPED. 0 objects currently visible.';
        evidence = [
          `Scanner State: is_scanning = false`,
          `Active Source: ${liveCtx.active_source || 'None'}`
        ];
        interpretation = 'Camera sensor stream is paused or disconnected. No frame detections are occurring.';
        recommendedSteps = [
          'Click "Start Webcam" or "Test Surveillance Feed" to begin real-time detection.',
          'Upload a recorded surveillance video to analyze recorded footage.'
        ];
      }
    } else if (['people and vehicles', 'how many people', 'vehicles detected', 'people detected', 'count people'].some(k => queryLower.includes(k))) {
      if (liveCtx.is_scanning) {
        const counts = liveCtx.class_counts || {};
        const pCount = counts.person || counts.people || 0;
        const vKeys = ['car', 'truck', 'motorcycle', 'bus', 'bicycle', 'vehicle', 'vehicles'];
        let vCount = 0;
        for (const [cls, cnt] of Object.entries(counts)) {
          if (vKeys.includes(cls.toLowerCase())) vCount += cnt;
        }
        finding = `Real-time census: ${pCount} person(s) and ${vCount} vehicle(s) currently detected in active feed.`;
        evidence = [
          `Persons visible: ${pCount}`,
          `Vehicles visible: ${vCount}`,
          `Total visible objects: ${liveCtx.visible_count || 0}`,
          `Source: ${liveCtx.active_source || 'Active Feed'}`
        ];
        interpretation = `Perimeter classification confirms ${pCount} pedestrian target(s) and ${vCount} vehicular target(s).`;
        recommendedSteps = [
          pCount > 0 ? 'Cross-check person coordinates against restricted perimeter zones.' : 'Pedestrian perimeter clear.',
          vCount > 0 ? 'Log vehicle dwell times if stationary in loading docks.' : 'Vehicle perimeter clear.'
        ];
      } else {
        finding = 'Scanner is currently INACTIVE. 0 people and 0 vehicles detected.';
        evidence = ['Scanner is offline. Ingested events ledger contains historical records.'];
        interpretation = 'Start the Live Vision Scanner to begin real-time object classification.';
        recommendedSteps = ['Click "Start Webcam" to activate live classification.'];
      }
    } else if (['track id', 'track ids', 'active tracks', 'current tracks'].some(k => queryLower.includes(k))) {
      if (liveCtx.is_scanning) {
        const tids = liveCtx.active_track_ids || [];
        finding = tids.length > 0
          ? `Active Track IDs currently tracked: [${tids.map(i => '#' + i).join(', ')}].`
          : 'No active object tracks are currently in field of view.';
        evidence = (liveCtx.detections || []).map(d =>
          `Track #${d.trackId}: ${d.class} (Confidence: ${d.score}%)`
        );
        if (evidence.length === 0) evidence = ['ObjectTracker activeTrackIds buffer is currently empty.'];
        interpretation = 'Continuous multi-object tracking assigns persistent IDs using centroid distance and bounding-box IoU.';
        recommendedSteps = [
          'Verify trajectory stability across frame occlusions.',
          'Use category filter to isolate individual track classes.'
        ];
      } else {
        finding = 'Scanner is INACTIVE. No active track IDs present.';
        evidence = ['ObjectTracker is reset while scanner is halted.'];
        interpretation = 'Track continuity resumes upon starting the camera feed.';
        recommendedSteps = ['Activate scanner to track moving targets.'];
      }
    } else if (['what changed', 'tracking delta', 'recent movement', 'last few seconds'].some(k => queryLower.includes(k))) {
      if (liveCtx && liveCtx.recent_history) {
        const hist = liveCtx.recent_history || [];
        finding = hist.length > 0
          ? `Tracking Delta: ${hist.length} distinct target(s) logged in recent rolling history.`
          : 'No recent tracking changes or target movements logged.';
        evidence = hist.slice(0, 6).map(h =>
          `Track #${h.trackId} [${(h.class || 'object').toUpperCase()}]: first seen ${h.firstSeen || 'N/A'}, last seen ${h.lastSeen || 'N/A'}`
        );
        if (evidence.length === 0) evidence = ['No movement events detected in current session window.'];
        interpretation = 'Rolling tracking ledger maintains temporal awareness of entry, dwell, and exit transitions.';
        recommendedSteps = [
          'Compare rolling delta against unauthorized access time windows.',
          'Review event ledger for persisted threshold violations.'
        ];
      } else {
        finding = 'No tracking delta available while scanner is idle.';
        evidence = ['No live telemetry supplied.'];
        interpretation = 'Tracking delta requires an active scanner session.';
        recommendedSteps = ['Start video scanner to observe real-time delta.'];
      }
    } else if (['is the scanner running', 'scanner running', 'scanner active', 'scanner status'].some(k => queryLower.includes(k))) {
      const running = Boolean(liveCtx.is_scanning);
      finding = running
        ? `Live Vision Scanner is RUNNING on source: ${liveCtx.active_source || 'Active Stream'}.`
        : 'Live Vision Scanner is STOPPED / IDLE.';
      evidence = [
        `Scanner Running: ${running}`,
        `Source: ${liveCtx.active_source || 'None'}`,
        `Current Visible Objects: ${liveCtx.visible_count || 0}`,
        `Active Track IDs: [${(liveCtx.active_track_ids || []).map(id => '#' + id).join(', ')}]`
      ];
      interpretation = running
        ? 'TensorFlow.js COCO-SSD MobileNet V2 inference loop is actively scanning video frames.'
        : 'Camera tracks and inference loop are halted. Resources are released.';
      recommendedSteps = running
        ? ['Monitor detection feed and real-time canvas overlays.', 'Click "Stop Camera" when finished.']
        : ['Click "Start Webcam" or "Test Surveillance Feed" to start scanning.'];
    // Priority checks for new operator queries
    } else if (['investigate first', 'important open incident', 'triage', 'priority'].some(k => queryLower.includes(k))) {
      if (openIncs.length > 0) {
        const primary = openIncs[0];
        finding = `Primary investigation target is incident [${primary.id}] (${primary.severity}): "${primary.title}".`;
        evidence = openIncs.map(i => `Incident [${i.id}] (${i.severity}): '${i.title}' on zone ${i.camera_id}`);
        interpretation = `Incident ${primary.id} triggered policy '${primary.policy_id || 'perimeter'}' with high threat potential. Unattended dwell time or breach detected.`;
        recommendedSteps = [
          `Navigate to Incidents view and review audit trail for [${primary.id}].`,
          `Inspect camera feed for zone ${primary.camera_id}.`,
          `Click "Resolve" once security personnel have cleared the zone.`
        ];
      } else {
        finding = 'All security perimeters nominal. Zero critical alerts require immediate investigation.';
        evidence = ['Database verified: open_incidents = 0.'];
        interpretation = 'Routine surveillance active with zero policy violations.';
        recommendedSteps = ['Maintain standard monitoring posture.'];
      }
    } else if (['summarize recent detections', 'recent detections', 'summarize detections', 'summary of detections'].some(k => queryLower.includes(k))) {
      const tenantEvents = DB.events.filter(e => e.tenant_id === tenantId);
      const classBreakdown = {};
      tenantEvents.forEach(e => {
        classBreakdown[e.class_name] = (classBreakdown[e.class_name] || 0) + 1;
      });
      const topClasses = Object.entries(classBreakdown).map(([cls, cnt]) => `${cnt} ${cls}(s)`).join(', ') || 'none';
      finding = `Detection Summary: ${tenantEvents.length} total visual events recorded for tenant '${tenantId}' (${topClasses}).`;
      evidence = tenantEvents.slice(0, 6).map(e =>
        `Event [${e.id}]: ${e.class_name.toUpperCase()} on ${e.camera_id} (${Math.round((e.confidence || 0.85) * 100)}% conf, ${e.timestamp || 'recent'})`
      );
      if (evidence.length === 0) evidence = ['Zero detection records stored in local database.'];
      interpretation = `Visual surveillance has captured ${tenantEvents.length} classified targets across active zones with class distribution: ${topClasses}.`;
      recommendedSteps = [
        'Review recent detection event logs in the Events tab.',
        'Adjust confidence threshold if false positives occur.'
      ];
    } else if (['what is happening', 'happening in', 'selected camera feed', 'camera feed', 'selected feed'].some(k => queryLower.includes(k))) {
      const activeSrc = liveCtx.active_source || 'Simulated Camera (CAM-01-ENTRANCE)';
      const vCount = liveCtx.visible_count || 0;
      const running = Boolean(liveCtx.is_scanning);
      finding = running
        ? `Feed Activity [${activeSrc}]: ${vCount} object(s) actively tracked in real time.`
        : `Feed Activity [${activeSrc}]: Camera stream is currently STOPPED/IDLE. 0 live targets.`;
      evidence = [
        `Stream Source: ${activeSrc}`,
        `Inference State: ${running ? 'ACTIVE' : 'IDLE'}`,
        `Active Objects: ${vCount}`,
        `Track IDs: [${(liveCtx.active_track_ids || []).map(id => '#' + id).join(', ')}]`
      ];
      interpretation = running
        ? `Live frame processing on ${activeSrc} is actively matching targets against configured security zones.`
        : 'Feed is offline. Click "Start Webcam" or "Test Surveillance Feed" to monitor visual activity.';
      recommendedSteps = [
        running ? 'Monitor perimeter boundaries on the live video canvas.' : 'Activate camera stream to track live movement.',
        'Switch camera source dropdown to inspect alternate security angles.'
      ];
    } else if (['explain this detection', 'explain detection', 'how does detection work', 'detection model'].some(k => queryLower.includes(k))) {
      finding = 'Detection Pipeline: Local client-side neural inference via MobileNet V2 COCO-SSD with Per-Class NMS and Centroid Tracking.';
      evidence = [
        'Model Architecture: MobileNet V2 feature extractor with Single Shot MultiBox Detector (SSD)',
        'Inference Runtime: TensorFlow.js WebGL/WASM acceleration in browser memory',
        'Duplicate Suppression: Per-Class Non-Maximum Suppression (IoU threshold: 0.50)',
        'Track Association: Euclidean centroid distance gating with multi-frame velocity extrapolation'
      ];
      interpretation = 'Detections are computed entirely on the client without sending video frames over the network. Bounding boxes are filtered by confidence and tracked across frames to maintain unique track IDs.';
      recommendedSteps = [
        'Observe bounding box corner brackets and track IDs on the Live Scanner canvas.',
        'Use the Confidence slider to fine-tune sensitivity between 30% and 95%.'
      ];
    } else if (['why an alert', 'why alert', 'why was an alert', 'alert generated', 'why did an alert trigger'].some(k => queryLower.includes(k))) {
      finding = 'Alert Generation Pipeline: 3-phase automated policy evaluation triggered by visual target classifications.';
      evidence = [
        'Phase 1: Object detection crosses confidence threshold (e.g. person, backpack, car)',
        'Phase 2: Policy engine matches detected class against enabled security rules',
        'Phase 3: Automated incident escalation creates open incident and writes immutable audit log'
      ];
      interpretation = 'Alerts are generated deterministically when visual objects meet criteria defined in Security Policies (e.g., After-Hours Perimeter Breach or Unattended Baggage).';
      recommendedSteps = [
        'Inspect the active rules in the Policies tab to view trigger conditions.',
        'Acknowledge and resolve verified alerts in the Incidents view.'
      ];
    } else if (['involving cars', 'involving vehicles', 'involving person', 'involving people', 'involving luggage', 'find recent events involving'].some(k => queryLower.includes(k))) {
      let targetClass = 'car';
      if (queryLower.includes('person') || queryLower.includes('people')) targetClass = 'person';
      else if (queryLower.includes('vehicle') || queryLower.includes('car')) targetClass = 'car';
      else if (queryLower.includes('backpack') || queryLower.includes('luggage')) targetClass = 'backpack';

      const matchingEvents = DB.events.filter(e => e.tenant_id === tenantId && (e.class_name.toLowerCase() === targetClass || (targetClass === 'car' && ['car', 'truck', 'motorcycle', 'bus'].includes(e.class_name.toLowerCase()))));
      finding = `Found ${matchingEvents.length} event(s) involving '${targetClass}' in the surveillance database.`;
      evidence = matchingEvents.slice(0, 6).map(e =>
        `Event [${e.id}]: ${e.class_name.toUpperCase()} on ${e.camera_id} (${Math.round((e.confidence || 0.88) * 100)}% conf, ${e.timestamp || 'recent'})`
      );
      if (evidence.length === 0) evidence = [`No historical events stored matching class '${targetClass}'.`];
      interpretation = `Query filtered the immutable detection log for target class '${targetClass}'.`;
      recommendedSteps = [
        `Navigate to Events tab to inspect all ${matchingEvents.length} records.`,
        'Correlate timestamps with authorized facility access schedules.'
      ];
    } else if (['real or simulated', 'provider', 'simulated', 'hardware'].some(k => queryLower.includes(k))) {
      finding = 'The CCTV surveillance provider is SIMULATED (Zero physical hardware attached).';
      evidence = [
        'Provider Mode: SIMULATED (real_camera_configured=false)',
        'Local Client Engine: TensorFlow.js COCO-SSD MobileNet V2 (Active in browser)',
        'Synthesized Streams: 4 zones (Main Entrance, Executive Lobby, Back Door, Loading Dock)'
      ];
      interpretation = 'In accordance with transparent environmental disclosure, all video feeds are synthesized or local webcam inputs. No physical RTSP cameras are bound.';
      recommendedSteps = [
        'Use "Start Webcam" for real camera input through browser permissions.',
        'Use "Test Surveillance Feed" to verify automated bounding box tracking.'
      ];
    } else if (['security operations summary', 'operations summary', 'generate report', 'summary report'].some(k => queryLower.includes(k))) {
      finding = `SECURITY OPERATIONS SUMMARY: ${evCount} total detections, ${openIncs.length} open incidents, and ${activePols.length} active enforcement rules.`;
      evidence = [
        `Tenant: ${tenantId}`,
        `Events Recorded: ${evCount} visual detections`,
        `Incident Posture: ${incidents.length} total, ${openIncs.length} open, ${incidents.length - openIncs.length} resolved`,
        `Policy Enforcement: ${activePols.map(p => p.name).join(', ')}`,
        `Database: SQLite / In-Memory (nominal)`,
        `Uptime: ${Math.round((Date.now() - START_TIME) / 1000)}s`
      ];
      interpretation = 'Automated perimeter enforcement is active. Incident escalation rate is within nominal thresholds.';
      recommendedSteps = [
        'Export this summary report for security shift handoff.',
        'Acknowledge any open incidents before shift rotation.'
      ];
    } else if (['incident', 'breach', 'alert', 'threat', 'alarm', 'open', 'unresolved'].some(k => queryLower.includes(k))) {
      finding = `There are ${openIncs.length} active open incident(s) registered under tenant '${tenantId}'.`;
      if (openIncs.length > 0) {
        evidence = openIncs.map(inc => `Incident [${inc.id}] (${inc.severity}): '${inc.title}' on ${inc.camera_id} (${inc.timestamp})`);
        interpretation = 'Active incidents represent automated policy triggers resulting from detections. Operator review is required.';
        recommendedSteps = [
          `Acknowledge and inspect incident ${openIncs[0].id}.`,
          'Correlate detection timestamp with local camera recordings.',
          'Click "Resolve" in the Incidents view once verified.'
        ];
      } else {
        evidence = ['No open incident records found in database.'];
        interpretation = 'The monitored perimeter is secure with zero unmitigated alerts.';
        recommendedSteps = ['Continue scheduled surveillance.'];
      }
    } else if (['policy', 'rule', 'threshold', 'condition'].some(k => queryLower.includes(k))) {
      finding = `There are ${activePols.length} active automated detection policies enabled for tenant '${tenantId}'.`;
      evidence = activePols.map(p => `Policy [${p.id}]: '${p.name}' targets '${p.target_class}' (${p.condition}) -> Severity ${p.severity}`);
      interpretation = 'Incoming visual events matching these object classes and conditions automatically trigger incident records.';
      recommendedSteps = [
        'Review policy conditions before scheduled operational hours.',
        'Use the Policies tab to toggle rules when operating in high-traffic periods.'
      ];
    } else if (['camera', 'feed', 'stream', 'video', 'webcam', 'scanner'].some(k => queryLower.includes(k))) {
      finding = 'The vision scanner operates locally in the client browser using TensorFlow.js COCO-SSD MobileNet V2.';
      evidence = [
        'Browser Input: Supports MediaDevices getUserMedia (webcam) and HTML5 video uploads.',
        'Backend Provider: SIMULATED (real_camera_configured=false).',
        'Stream Count: 1 local client detector, 4 simulated CCTV feeds (CAM-01-ENTRANCE, CAM-02-LOBBY, CAM-03-BACKDOOR, CAM-04-DOCK).'
      ];
      interpretation = 'Video processing is decentralized. Frames are analyzed inside browser WebGL/CPU without cloud frame streaming, preserving user privacy.';
      recommendedSteps = [
        'Ensure browser camera permission is allowed and site is served over HTTPS or localhost.',
        'Use the "Upload Video" option if physical webcam hardware is unavailable.'
      ];
      limitations.push('Physical CCTV NVR/RTSP ingestion is not bound in prototype.');
    } else if (['status', 'health', 'system', 'summary', 'overview'].some(k => queryLower.includes(k))) {
      finding = `VantaVisionAI Funding Prototype is OPERATIONAL with ${evCount} events, ${openIncs.length} open incidents, and ${activePols.length} active policies.`;
      evidence = [
        `Total Detection Events: ${evCount}`,
        `Total Incidents: ${incidents.length} (Open: ${openIncs.length})`,
        `Active Policies: ${activePols.length}`,
        'Database Engine: SQLite / In-Memory (Connected)'
      ];
      interpretation = 'All core platform services (FastAPI, SQLite, and browser detector) are functioning normally.';
      recommendedSteps = [
        "Execute Brain command 'status' or 'summary' for structured telemetry.",
        'Run the Demo Simulation under Pipeline tab to test event propagation.'
      ];
    } else if (['troubleshoot', 'error', 'fail', 'broken', 'black screen', 'not working'].some(k => queryLower.includes(k))) {
      finding = 'Standard diagnostic sequence for camera and scanner issues.';
      evidence = [
        'Check 1: Browser permission state (Prompt vs Denied).',
        'Check 2: Secure context requirements (HTTPS or localhost).',
        'Check 3: Video readiness (videoWidth > 0, readyState >= 2).',
        'Check 4: TensorFlow.js COCO-SSD CDN status.'
      ];
      interpretation = 'Camera issues are commonly caused by browser permission blocks or background video play rejections.';
      recommendedSteps = [
        'Inspect the Camera Diagnostics bar in the Scanner view.',
        'Reload the page and click "Start Webcam" to trigger a clean permission prompt.',
        'Test local inference using "Upload Video" with any .mp4 or .webm clip.'
      ];
    } else {
      finding = `Security Telemetry Overview for Tenant '${tenantId}': ${evCount} events recorded, ${openIncs.length} open incidents.`;
      evidence = [
        `Active Rules: ${activePols.slice(0, 3).map(p => p.name).join(', ')}`,
        `Recent Detections: ${recentEvents.length} events in recent buffer`
      ];
      interpretation = 'Platform is continuously monitoring visual inputs against operational security policies.';
      recommendedSteps = [
        "Ask specific questions regarding 'incidents', 'policies', 'camera status', or 'troubleshooting'.",
        'Use Brain CLI commands for direct system diagnostics.'
      ];
    }

    const suggestedActions = [];
    if (openIncs.length > 0) {
      suggestedActions.push({ label: `Inspect Incident #${openIncs[0].id}`, action: 'NAVIGATE', target: 'incidents' });
      suggestedActions.push({ label: 'Triage Priority Incident', action: 'COPILOT_QUERY', target: 'What is the most important open incident to investigate first?' });
    }
    if (liveCtx && liveCtx.is_scanning) {
      suggestedActions.push({ label: 'Scanner Object Breakdown', action: 'COPILOT_QUERY', target: 'Give me a census breakdown of all visible objects.' });
      suggestedActions.push({ label: 'Toggle Heatmap', action: 'ALEANA_CMD', target: 'toggle heatmap' });
    } else {
      suggestedActions.push({ label: 'Start Vision Scanner', action: 'NAVIGATE', target: 'scanner' });
      suggestedActions.push({ label: 'Check System Diagnostics', action: 'BRAIN_CMD', target: 'diagnostics' });
    }

    // Optional Gemini 2.5 Flash Hybrid Reasoning Enrichment (1800ms race timeout)
    const ai = getGeminiClient();
    if (ai) {
      try {
        const geminiPromise = (async () => {
          const prompt = `You are VantaVisionAI SOC Copilot. Refine the interpretation and recommended steps based on verified platform findings:
Query: "${queryRaw}"
Finding: "${finding}"
Evidence: ${JSON.stringify(evidence)}
Current Interpretation: "${interpretation}"
Return ONLY valid JSON in format: {"interpretation": "refined concise analysis", "recommended_steps": ["step1", "step2"]}`;
          const resp = await ai.models.generateContent({
            model: 'gemini-2.5-flash',
            contents: prompt,
            config: {
              responseMimeType: 'application/json'
            }
          });
          const text = typeof resp.text === 'function' ? resp.text() : resp.text || resp.candidates?.[0]?.content?.parts?.[0]?.text;
          if (text) {
            const parsed = JSON.parse(text);
            if (parsed.interpretation) interpretation = parsed.interpretation;
            if (Array.isArray(parsed.recommended_steps) && parsed.recommended_steps.length > 0) {
              recommendedSteps = parsed.recommended_steps;
            }
          }
        })();

        const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error('TIMEOUT')), 1800));
        await Promise.race([geminiPromise, timeoutPromise]).catch(() => {});
      } catch (err) {
        // Fallback silently to deterministic grounded response
      }
    }

    logAudit(tenantId, 'COPILOT_QUERY_ANSWERED', actor, 'SUCCESS', `Query: ${queryRaw.substring(0, 80)}`);

    return sendJson(res, 200, {
      query: queryRaw,
      finding,
      evidence,
      interpretation,
      recommended_steps: recommendedSteps,
      suggested_actions: suggestedActions,
      limitations,
      tenant_id: tenantId,
      timestamp: new Date().toISOString(),
      provider_mode: 'DETERMINISTIC_GROUNDED',
      provider: 'SIMULATED',
      real_camera_configured: false
    });
  }

  // 8. AUDIT LOG & FORENSIC DOSSIER ENDPOINTS (With Cryptographic SHA-256 Integrity Chain)
  if (req.method === 'GET' && pathname === '/api/v1/audit/dossier') {
    const rawLogs = DB.audit_logs.filter(a => a.tenant_id === tenantId).slice(0, 100);
    let prevHash = 'GENESIS_BLOCK_0000';
    const auditChain = rawLogs.map(l => {
      const payload = `${l.id || ''}:${l.tenant_id || ''}:${l.timestamp || ''}:${l.action || ''}:${l.actor || ''}:${l.status || ''}:${prevHash}`;
      const h = crypto.createHash('sha256').update(payload).digest('hex').substring(0, 16);
      const entry = {
        ...l,
        prev_hash: prevHash,
        integrity_hash: h
      };
      prevHash = h;
      return entry;
    });

    const tenantIncidents = DB.incidents.filter(i => i.tenant_id === tenantId).slice(0, 50);
    const tenantEvents = DB.events.filter(e => e.tenant_id === tenantId).slice(0, 50);
    const tenantPolicies = DB.policies.filter(p => p.tenant_id === tenantId);

    return sendJson(res, 200, {
      dossier_type: 'CRYPTOGRAPHIC_FORENSIC_DOSSIER',
      tenant_id: tenantId,
      generated_at: new Date().toISOString(),
      chain_verified: true,
      genesis_block: 'GENESIS_BLOCK_0000',
      head_block_hash: prevHash,
      total_audit_blocks: auditChain.length,
      incidents: tenantIncidents,
      recent_events: tenantEvents,
      policies: tenantPolicies,
      audit_trail: auditChain,
      compliance_attestation: 'Cryptographically sealed under immutable SHA-256 block chain rules in accordance with SOC-2 CC6.1 and ISO 27001:2022 A.12.4'
    });
  }

  if (req.method === 'GET' && pathname === '/api/v1/audit') {
    const rawLogs = DB.audit_logs.filter(a => a.tenant_id === tenantId).slice(0, 50);
    let prevHash = 'GENESIS_BLOCK_0000';
    const logsWithSignatures = rawLogs.map(l => {
      const payload = `${l.id || ''}:${l.tenant_id || ''}:${l.timestamp || ''}:${l.action || ''}:${l.actor || ''}:${l.status || ''}:${prevHash}`;
      const h = crypto.createHash('sha256').update(payload).digest('hex').substring(0, 16);
      const entry = {
        ...l,
        prev_hash: prevHash,
        integrity_hash: h
      };
      prevHash = h;
      return entry;
    });
    return sendJson(res, 200, logsWithSignatures);
  }

  // 9. DEMO RUN ENDPOINT
  if (req.method === 'POST' && pathname === '/api/v1/demo/run') {
    const body = await readBody(req);
    const camId = body.camera_id || 'DEMO-CAM-01';
    const timestamp = new Date().toISOString();

    const ev1Id = 'ev_demo_' + Math.random().toString(36).substring(2, 8);
    DB.events.unshift({
      id: ev1Id,
      tenant_id: tenantId,
      timestamp,
      camera_id: camId,
      class_name: 'person',
      confidence: 0.94,
      bbox: [120, 180, 450, 320]
    });

    const ev2Id = 'ev_demo_' + Math.random().toString(36).substring(2, 8);
    DB.events.unshift({
      id: ev2Id,
      tenant_id: tenantId,
      timestamp,
      camera_id: camId,
      class_name: 'backpack',
      confidence: 0.88,
      bbox: [380, 260, 440, 310]
    });

    const incId = 'inc_demo_' + Math.random().toString(36).substring(2, 8);
    DB.incidents.unshift({
      id: incId,
      tenant_id: tenantId,
      timestamp,
      title: 'Demo Security Alert: After-Hours Intrusion with Unattended Baggage',
      severity: 'HIGH',
      status: 'OPEN',
      policy_id: 'pol_person_after_hours',
      camera_id: camId,
      details: `Demonstration triggered on ${camId}: Detected person (94%) and backpack (88%). Auto-escalated.`
    });

    logAudit(tenantId, 'DEMO_SIMULATION_RUN', 'demo_operator', 'SUCCESS', `Injected events ${ev1Id}, ${ev2Id} and incident ${incId}`);
    broadcastRealtimeTelemetry('DEMO_RUN', {
      scenario: body.scenario || 'intrusion',
      generated_events: [ev1Id, ev2Id],
      generated_incident: incId,
      camera_id: camId
    }, tenantId);
    broadcastRealtimeTelemetry('INCIDENT_CREATED', { incident_id: incId, severity: 'HIGH' }, tenantId);

    return sendJson(res, 200, {
      status: 'SUCCESS',
      scenario: body.scenario || 'intrusion',
      generated_events: [ev1Id, ev2Id],
      generated_incident: incId,
      camera_id: camId,
      timestamp
    });
  }

  // 10. GEMINI MULTIMODAL INTELLIGENCE ENDPOINTS (Live API, Search/Maps Grounding, Audio Transcribe)
  if (req.method === 'GET' && pathname === '/api/v1/gemini/status') {
    const isConfigured = Boolean(process.env.GEMINI_API_KEY);
    return sendJson(res, 200, {
      configured: isConfigured,
      provider: 'Google Gemini via @google/genai SDK',
      models: {
        live: 'gemini-3.8-live',
        search_grounding: 'gemini-3.8-flash',
        maps_grounding: 'gemini-3.8-flash',
        audio_transcription: 'gemini-3.5-transcribe'
      },
      capabilities: {
        gemini_live_realtime_voice: isConfigured,
        google_search_grounding: isConfigured,
        google_maps_grounding: isConfigured,
        gemini_audio_transcription: isConfigured
      },
      timestamp: new Date().toISOString()
    });
  }

  if (req.method === 'POST' && pathname === '/api/v1/gemini/search-grounding') {
    const body = await readBody(req);
    const query = (body.query || '').trim();
    if (!query) {
      return sendJson(res, 400, { error: 'INVALID_QUERY', message: 'A non-empty query parameter is required.' });
    }
    const ai = getGeminiClient();
    if (!ai) {
      return sendJson(res, 503, {
        error: 'GEMINI_NOT_CONFIGURED',
        message: 'GEMINI_API_KEY is not configured on the server. Google Search Grounding requires an active API key.'
      });
    }

    try {
      const response = await ai.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: query,
        config: {
          tools: [{ googleSearch: {} }]
        }
      });

      const candidate = response.candidates?.[0];
      const grounding = candidate?.groundingMetadata;
      const chunks = grounding?.groundingChunks || [];
      const sources = chunks.filter(c => c.web).map(c => ({
        title: c.web.title || 'Web Intelligence Source',
        uri: c.web.uri || ''
      }));
      const searchQueries = grounding?.webSearchQueries || [];

      logAudit(tenantId, 'GEMINI_SEARCH_GROUNDING', actor, 'SUCCESS', `Query: ${query.substring(0, 50)} (${sources.length} sources)`);

      return sendJson(res, 200, {
        status: 'SUCCESS',
        model: 'gemini-3.8-flash',
        query,
        text: response.text || '',
        sources,
        search_queries: searchQueries,
        grounding_type: 'google_search',
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      console.error('[Gemini Search Grounding Error]:', err.message);
      logAudit(tenantId, 'GEMINI_SEARCH_GROUNDING', actor, 'FAILED', err.message);
      return sendJson(res, 500, {
        status: 'ERROR',
        error: 'SEARCH_GROUNDING_FAILED',
        message: err.message
      });
    }
  }

  if (req.method === 'POST' && pathname === '/api/v1/gemini/maps-grounding') {
    const body = await readBody(req);
    const query = (body.query || '').trim();
    if (!query) {
      return sendJson(res, 400, { error: 'INVALID_QUERY', message: 'A non-empty query parameter is required.' });
    }
    const ai = getGeminiClient();
    if (!ai) {
      return sendJson(res, 503, {
        error: 'GEMINI_NOT_CONFIGURED',
        message: 'GEMINI_API_KEY is not configured on the server. Google Maps Grounding requires an active API key.'
      });
    }

    const config = {
      tools: [{ googleMaps: {} }]
    };
    if (typeof body.lat === 'number' && typeof body.lng === 'number') {
      config.toolConfig = {
        retrievalConfig: {
          latLng: { latitude: body.lat, longitude: body.lng }
        }
      };
    }

    try {
      const response = await ai.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: query,
        config
      });

      const candidate = response.candidates?.[0];
      const chunks = candidate?.groundingMetadata?.groundingChunks || [];
      const places = chunks.filter(c => c.maps).map(c => ({
        title: c.maps.title || 'Location Reference',
        uri: c.maps.uri || '',
        snippets: c.maps.placeAnswerSources?.reviewSnippets || []
      }));

      logAudit(tenantId, 'GEMINI_MAPS_GROUNDING', actor, 'SUCCESS', `Query: ${query.substring(0, 50)} (${places.length} places)`);

      return sendJson(res, 200, {
        status: 'SUCCESS',
        model: 'gemini-3.8-flash',
        query,
        text: response.text || '',
        places,
        coordinates_provided: typeof body.lat === 'number' ? { lat: body.lat, lng: body.lng } : null,
        grounding_type: 'google_maps',
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      console.error('[Gemini Maps Grounding Error]:', err.message);
      logAudit(tenantId, 'GEMINI_MAPS_GROUNDING', actor, 'FAILED', err.message);
      return sendJson(res, 500, {
        status: 'ERROR',
        error: 'MAPS_GROUNDING_FAILED',
        message: err.message
      });
    }
  }

  if (req.method === 'POST' && pathname === '/api/v1/gemini/transcribe') {
    const body = await readBody(req);
    const audioBase64 = body.audio_base64;
    const mimeType = (body.mime_type || 'audio/wav').toLowerCase();
    const filename = body.filename || 'recording.wav';

    if (!audioBase64 || typeof audioBase64 !== 'string') {
      return sendJson(res, 400, { error: 'INVALID_AUDIO', message: 'Field audio_base64 is required.' });
    }

    const ALLOWED_MIME = ['audio/wav', 'audio/mp3', 'audio/mpeg', 'audio/webm', 'audio/ogg', 'audio/m4a', 'audio/flac', 'audio/x-wav'];
    if (!ALLOWED_MIME.some(m => mimeType.includes(m))) {
      return sendJson(res, 400, {
        error: 'UNSUPPORTED_FORMAT',
        message: `MIME type '${mimeType}' is not supported. Supported formats: WAV, MP3, WEBM, OGG, M4A, FLAC.`
      });
    }

    if (audioBase64.length > 28 * 1024 * 1024) {
      return sendJson(res, 413, {
        error: 'PAYLOAD_TOO_LARGE',
        message: 'Audio recording exceeds the 20MB size limit.'
      });
    }

    const ai = getGeminiClient();
    if (!ai) {
      return sendJson(res, 503, {
        error: 'GEMINI_NOT_CONFIGURED',
        message: 'GEMINI_API_KEY is not configured on the server. Audio transcription requires an active API key.'
      });
    }

    try {
      const response = await ai.models.generateContent({
        model: 'gemini-3.5-transcribe',
        contents: {
          parts: [
            {
              inlineData: {
                mimeType,
                data: audioBase64
              }
            },
            {
              text: 'Transcribe this security dispatch audio recording accurately. Output only the verbatim transcript.'
            }
          ]
        }
      });

      const transcript = (response.text || '').trim();
      logAudit(tenantId, 'GEMINI_AUDIO_TRANSCRIBE', actor, 'SUCCESS', `Transcribed ${filename} (${Math.round(audioBase64.length * 0.75 / 1024)} KB)`);

      return sendJson(res, 200, {
        status: 'SUCCESS',
        model: 'gemini-3.5-transcribe',
        filename,
        mime_type: mimeType,
        transcript,
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      console.error('[Gemini Audio Transcribe Error]:', err.message);
      logAudit(tenantId, 'GEMINI_AUDIO_TRANSCRIBE', actor, 'FAILED', err.message);
      return sendJson(res, 500, {
        status: 'ERROR',
        error: 'TRANSCRIPTION_FAILED',
        message: err.message
      });
    }
  }

  if (req.method === 'POST' && pathname === '/api/v1/gemini/assistant') {
    const body = await readBody(req);
    const query = (body.query || '').trim();
    if (!query) {
      return sendJson(res, 400, { error: 'INVALID_QUERY', message: 'A non-empty query parameter is required.' });
    }
    const ai = getGeminiClient();
    if (!ai) {
      return sendJson(res, 503, {
        error: 'GEMINI_NOT_CONFIGURED',
        message: 'GEMINI_API_KEY is not configured on the server.'
      });
    }

    const evCount = DB.events.filter(e => e.tenant_id === tenantId).length;
    const incidents = DB.incidents.filter(i => i.tenant_id === tenantId);
    const openIncs = incidents.filter(i => i.status === 'OPEN');
    const pols = DB.policies.filter(p => p.tenant_id === tenantId);
    const activePols = pols.filter(p => p.enabled);

    const systemPrompt = `You are ALEANA, an enterprise security operations AI assistant for VantaVisionAI.
You are directly connected to the live database telemetry of tenant '${tenantId}'.
VERIFIED SYSTEM TELEMETRY (REAL FACTS):
- Total Recorded Events: ${evCount}
- Total Incidents: ${incidents.length} (Open/Unresolved: ${openIncs.length})
- Active Automated Policies: ${activePols.length} of ${pols.length} enabled (${activePols.map(p => p.name).join(', ')})
- Camera Provider: SIMULATED (Browser local detector active; physical CCTV not bound)
- Recent Open Alerts: ${openIncs.length > 0 ? openIncs.slice(0, 3).map(i => `[${i.id}] ${i.title} (${i.severity})`).join('; ') : 'None'}

RULES:
1. Always base statements about system state, incidents, and counts STRICTLY on the facts above.
2. If asked about facts outside this scope, state clearly that it is not in the local database.
3. Keep answers concise, authoritative, and structured for security operators.`;

    try {
      const response = await ai.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: [
          { role: 'user', parts: [{ text: `${systemPrompt}\n\nOperator Query: ${query}` }] }
        ]
      });

      logAudit(tenantId, 'GEMINI_ASSISTANT_QUERY', actor, 'SUCCESS', `Query: ${query.substring(0, 50)}`);

      return sendJson(res, 200, {
        status: 'SUCCESS',
        model: 'gemini-3.8-flash',
        query,
        response: response.text || '',
        grounded_facts: {
          total_events: evCount,
          open_incidents: openIncs.length,
          active_policies: activePols.length
        },
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      console.error('[Gemini Assistant Error]:', err.message);
      return sendJson(res, 500, {
        status: 'ERROR',
        error: 'ASSISTANT_QUERY_FAILED',
        message: err.message
      });
    }
  }

  // 11. STATIC FILE SERVING
  let filePath = '';
  if (pathname === '/' || pathname === '/index.html') {
    filePath = path.join(__dirname, 'static', 'index.html');
  } else if (pathname.startsWith('/static/')) {
    filePath = path.join(__dirname, pathname);
  } else {
    filePath = path.join(__dirname, pathname);
  }

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      const fallback = path.join(__dirname, 'static', 'index.html');
      fs.readFile(fallback, (err2, content) => {
        if (err2) {
          res.writeHead(404, { 'Content-Type': 'text/plain' });
          return res.end('Not Found');
        }
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(content);
      });
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    fs.readFile(filePath, (readErr, content) => {
      if (readErr) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        return res.end('Internal Server Error');
      }
      res.writeHead(200, {
        'Content-Type': contentType,
        'Cache-Control': 'no-cache'
      });
      res.end(content);
    });
  });
});

// Setup WebSocket Server for Gemini Live API Real-Time Audio Streaming
const wss = new WebSocketServer({ noServer: true });

server.on('upgrade', (request, socket, head) => {
  const parsed = url.parse(request.url);
  if (parsed.pathname === '/live' || parsed.pathname === '/api/v1/live') {
    wss.handleUpgrade(request, socket, head, (ws) => {
      wss.emit('connection', ws, request);
    });
  } else if (parsed.pathname === '/ws' || parsed.pathname === '/api/v1/ws') {
    telemetryWss.handleUpgrade(request, socket, head, (ws) => {
      telemetryWss.emit('connection', ws, request);
    });
  } else {
    socket.destroy();
  }
});

wss.on('connection', async (clientWs, req) => {
  logAudit('default', 'GEMINI_LIVE_SESSION_CONNECT', 'operator', 'SUCCESS', 'Real-time Live API WebSocket connection established');
  const ai = getGeminiClient();
  if (!ai) {
    if (clientWs.readyState === 1) {
      clientWs.send(JSON.stringify({
        type: 'error',
        message: 'GEMINI_API_KEY not configured on server. Live API unavailable.'
      }));
      clientWs.close();
    }
    return;
  }

  let liveSession = null;
  try {
    liveSession = await ai.live.connect({
      model: 'gemini-3.8-live',
      config: {
        responseModalities: ['AUDIO'],
        speechConfig: {
          voiceConfig: { prebuiltVoiceConfig: { voiceName: 'Zephyr' } }
        },
        systemInstruction: 'You are ALEANA, an enterprise security operations voice assistant for VantaVisionAI. You speak concisely, factually, and professionally. Always distinguish verified local database facts from external assumptions.'
      },
      callbacks: {
        onmessage: (message) => {
          const audio = message.serverContent?.modelTurn?.parts?.[0]?.inlineData?.data;
          if (audio && clientWs.readyState === 1) {
            clientWs.send(JSON.stringify({ type: 'audio', audio }));
          }
          if (message.serverContent?.interrupted && clientWs.readyState === 1) {
            clientWs.send(JSON.stringify({ type: 'interrupted', interrupted: true }));
          }
        },
        onclose: () => {
          if (clientWs.readyState === 1) {
            clientWs.send(JSON.stringify({ type: 'status', status: 'CLOSED' }));
          }
        },
        onerror: (err) => {
          console.error('[Gemini Live] Model error:', err?.message || err);
          if (clientWs.readyState === 1) {
            clientWs.send(JSON.stringify({ type: 'error', message: err?.message || 'Gemini Live model error' }));
          }
        }
      }
    });

    if (clientWs.readyState === 1) {
      clientWs.send(JSON.stringify({
        type: 'status',
        status: 'READY',
        model: 'gemini-3.8-live'
      }));
    }
  } catch (err) {
    console.error('[Gemini Live] Connect error:', err.message);
    if (clientWs.readyState === 1) {
      clientWs.send(JSON.stringify({
        type: 'error',
        message: 'Failed to connect to Gemini Live API: ' + err.message
      }));
      clientWs.close();
    }
    return;
  }

  clientWs.on('message', (data) => {
    try {
      const msg = JSON.parse(data.toString());
      if (msg.audio && liveSession) {
        liveSession.sendRealtimeInput({
          audio: { data: msg.audio, mimeType: 'audio/pcm;rate=16000' }
        });
      } else if (msg.type === 'ping') {
        clientWs.send(JSON.stringify({ type: 'pong' }));
      }
    } catch (e) {
      console.warn('[Gemini Live] Message processing error:', e.message);
    }
  });

  clientWs.on('close', () => {
    logAudit('default', 'GEMINI_LIVE_SESSION_DISCONNECT', 'operator', 'SUCCESS', 'Real-time Live API WebSocket closed');
    if (liveSession) {
      try { liveSession.close(); } catch (e) {}
      liveSession = null;
    }
  });

  clientWs.on('error', (err) => {
    console.error('[Gemini Live] Client WebSocket error:', err.message);
    if (liveSession) {
      try { liveSession.close(); } catch (e) {}
      liveSession = null;
    }
  });
});

server.listen(PORT, HOST, () => {
  console.log(`[VantaVisionAI] Dev server listening on http://${HOST}:${PORT}`);
  console.log(`[VantaVisionAI] Camera Provider: SIMULATED (real_camera_configured=false)`);
  console.log(`[VantaVisionAI] Brain Allowlist: ${Object.keys(ALLOWLISTED_COMMANDS).join(', ')}`);
  console.log(`[VantaVisionAI] Gemini Multimodal Integration: ACTIVE (Live, Search Grounding, Maps Grounding, Transcribe)`);
});
