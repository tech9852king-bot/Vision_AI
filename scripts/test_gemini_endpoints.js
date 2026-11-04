/**
 * Integration Test for Gemini Multimodal Intelligence Endpoints
 */
const http = require('http');
const { WebSocket } = require('ws');

function req(path, method = 'GET', data = null) {
  return new Promise((resolve, reject) => {
    const opts = {
      hostname: '127.0.0.1',
      port: 3000,
      path,
      method,
      headers: {
        'Content-Type': 'application/json',
        'X-Tenant-ID': 'default'
      }
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

async function run() {
  console.log('[TEST] Checking Gemini Multimodal Endpoints...');

  // 1. Status
  const statusRes = await req('/api/v1/gemini/status');
  console.log('Status endpoint status:', statusRes.status);
  console.log('Status data:', JSON.stringify(statusRes.data, null, 2));

  // 2. Assistant query
  const assistRes = await req('/api/v1/gemini/assistant', 'POST', {
    query: 'What is the current incident count and are policies active?'
  });
  console.log('Assistant status:', assistRes.status, 'data:', JSON.stringify(assistRes.data));

  // 3. Search grounding
  const searchRes = await req('/api/v1/gemini/search-grounding', 'POST', {
    query: 'What are standard physical security guidelines for data centers?'
  });
  console.log('Search grounding status:', searchRes.status, 'data:', JSON.stringify(searchRes.data));

  // 4. Maps grounding
  const mapsRes = await req('/api/v1/gemini/maps-grounding', 'POST', {
    query: 'Emergency hospitals near San Francisco',
    lat: 37.7749,
    lng: -122.4194
  });
  console.log('Maps grounding status:', mapsRes.status, 'data:', JSON.stringify(mapsRes.data));

  // 5. Transcribe validation (with small dummy wav header)
  const dummyWavBase64 = 'UklGRiQAAABXQVZFZm10IBAAAAABAAEARKwAAIhYAQACABAAZGF0YQAAAAA=';
  const transRes = await req('/api/v1/gemini/transcribe', 'POST', {
    audio_base64: dummyWavBase64,
    mime_type: 'audio/wav',
    filename: 'test_dispatch.wav'
  });
  console.log('Transcribe status:', transRes.status);
  console.log('Transcribe data:', JSON.stringify(transRes.data, null, 2));

  // 6. WebSocket Live Endpoint upgrade test
  const wsTest = await new Promise((resolve) => {
    try {
      const ws = new WebSocket('ws://127.0.0.1:3000/live');
      ws.on('open', () => {
        ws.send(JSON.stringify({ type: 'ping' }));
      });
      ws.on('message', (msg) => {
        try {
          const parsed = JSON.parse(msg.toString());
          resolve({ ok: true, msg: parsed });
        } catch (e) {
          resolve({ ok: true, raw: msg.toString() });
        }
        ws.close();
      });
      ws.on('error', (err) => {
        resolve({ ok: false, error: err.message });
      });
      setTimeout(() => resolve({ ok: false, error: 'timeout' }), 4000);
    } catch (e) {
      resolve({ ok: false, error: e.message });
    }
  });
  console.log('Live WS test result:', wsTest);

  console.log('[TEST] Multimodal verification finished.');
}

run().catch(console.error);
