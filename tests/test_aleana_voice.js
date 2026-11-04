/**
 * Test Suite for Aleana Voice Assistant Endpoints & NLP Intent Routing
 */
const http = require('http');

function post(path, body) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: '127.0.0.1',
      port: 3000,
      path,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Tenant-ID': 'default' }
    }, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(d) }); }
        catch (e) { resolve({ status: res.statusCode, raw: d }); }
      });
    });
    req.on('error', reject);
    req.write(JSON.stringify(body));
    req.end();
  });
}

function get(path) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: '127.0.0.1',
      port: 3000,
      path,
      method: 'GET',
      headers: { 'Content-Type': 'application/json', 'X-Tenant-ID': 'default' }
    }, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(d) }); }
        catch (e) { resolve({ status: res.statusCode, raw: d }); }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

async function runAleanaTests() {
  console.log('[TEST SUITE] Executing Aleana Voice Assistant Test Suite...');
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

  // 1. Aleana Status
  const statusRes = await get('/api/v1/aleana/status');
  assert('GET /api/v1/aleana/status returns 200 and declares ONLINE', statusRes.status === 200 && statusRes.data.status === 'ONLINE' && statusRes.data.name === 'ALEANA');

  // 2. Incident Query Intent
  const qInc = await post('/api/v1/aleana/command', { query: 'Aleana, how many open incidents are there?' });
  assert('POST /api/v1/aleana/command recognizes QUERY_INCIDENTS intent', qInc.status === 200 && qInc.data.intent === 'QUERY_INCIDENTS' && typeof qInc.data.speech === 'string');

  // 3. Navigation Intent
  const qNav = await post('/api/v1/aleana/command', { query: 'open policies' });
  assert('POST /api/v1/aleana/command recognizes NAVIGATE to policies', qNav.status === 200 && qNav.data.action === 'NAVIGATE' && qNav.data.target === 'policies');

  // 4. Scanner Hardware Control Intent
  const qCam = await post('/api/v1/aleana/command', { query: 'start camera' });
  assert('POST /api/v1/aleana/command recognizes START_SCANNER action', qCam.status === 200 && qCam.data.action === 'START_SCANNER');

  // 5. System Health Check Intent
  const qHealth = await post('/api/v1/aleana/command', { query: 'check system health' });
  assert('POST /api/v1/aleana/command recognizes QUERY_HEALTH intent', qHealth.status === 200 && qHealth.data.intent === 'QUERY_HEALTH' && qHealth.data.data.health === '98%');

  // 6. Multilingual Hindi / Hinglish Voice Support
  const qHindi = await post('/api/v1/aleana/command', { query: 'scanner kholo' });
  assert('POST /api/v1/aleana/command handles Hindi command "scanner kholo"', qHindi.status === 200 && qHindi.data.action === 'NAVIGATE' && qHindi.data.target === 'scanner');

  // 7. Explicit Stop Intent
  const qStop = await post('/api/v1/aleana/command', { query: 'aleana stop' });
  assert('POST /api/v1/aleana/command recognizes STOP_ASSISTANT intent', qStop.status === 200 && qStop.data.intent === 'STOP_ASSISTANT' && qStop.data.action === 'STOP_SESSION');

  // 8. Explicit Pause Intent
  const qPause = await post('/api/v1/aleana/command', { query: 'pause listening' });
  assert('POST /api/v1/aleana/command recognizes PAUSE_ASSISTANT intent', qPause.status === 200 && qPause.data.intent === 'PAUSE_ASSISTANT' && qPause.data.action === 'PAUSE_SESSION');

  // 9. Explicit Start / Resume Intent
  const qStart = await post('/api/v1/aleana/command', { query: 'aleana start' });
  assert('POST /api/v1/aleana/command recognizes RESUME_ASSISTANT intent', qStart.status === 200 && qStart.data.intent === 'RESUME_ASSISTANT');

  // 10. Non-repetitive fallback
  const qUnknown = await post('/api/v1/aleana/command', { query: 'xyz unknown phrase 987' });
  assert('POST /api/v1/aleana/command does not repeat intro on unrecognized command', qUnknown.status === 200 && qUnknown.data.speech.includes('Command not recognized'));

  // 10b. Safe Autocorrection Layer: "show incidants" -> incidents
  const qAutoInc = await post('/api/v1/aleana/command', { query: 'show incidants' });
  assert('Autocorrection maps misspelling "show incidants" to incidents', qAutoInc.status === 200 && (qAutoInc.data.target === 'incidents' || qAutoInc.data.intent === 'QUERY_INCIDENTS'));

  // 10c. Safe Autocorrection Layer: "open polices" -> NAVIGATE to policies
  const qAutoPol = await post('/api/v1/aleana/command', { query: 'open polices' });
  assert('Autocorrection maps misspelling "open polices" to policies view', qAutoPol.status === 200 && qAutoPol.data.action === 'NAVIGATE' && qAutoPol.data.target === 'policies');

  // 10d. Hindi / Hinglish Aliases: "camera chalu karo" -> START_SCANNER
  const qChalu = await post('/api/v1/aleana/command', { query: 'camera chalu karo' });
  assert('Hindi alias "camera chalu karo" triggers START_SCANNER', qChalu.status === 200 && qChalu.data.action === 'START_SCANNER');

  // 10e. Hindi / Hinglish Aliases: "camera band karo" -> STOP_SCANNER
  const qBand = await post('/api/v1/aleana/command', { query: 'camera band karo' });
  assert('Hindi alias "camera band karo" triggers STOP_SCANNER', qBand.status === 200 && qBand.data.action === 'STOP_SCANNER');

  // 10f. Hindi / Hinglish Aliases: "kya chal raha hai" -> SUMMARIZE_THREATS
  const qKya = await post('/api/v1/aleana/command', { query: 'kya chal raha hai' });
  assert('Hindi alias "kya chal raha hai" triggers SUMMARIZE_THREATS', qKya.status === 200 && qKya.data.intent === 'SUMMARIZE_THREATS');

  // 10g. Context-Aware Grounded Fallback
  const qScannerFallback = await post('/api/v1/aleana/command', { query: 'random unhandled word', current_view: 'scanner' });
  assert('Contextual fallback on scanner view suggests scanner-specific commands', qScannerFallback.status === 200 && qScannerFallback.data.speech.includes('scanner screen'));

  // 10h. Stop Speech Control Intent
  const qStopSpeech = await post('/api/v1/aleana/command', { query: 'stop speech' });
  assert('Speech cancellation intent "stop speech" returns STOP_SPEECH action', qStopSpeech.status === 200 && qStopSpeech.data.action === 'STOP_SPEECH');

  // =========================================================================
  // B. DETERMINISTIC MOCK VOICE CONTROLLER UNIT SUITE (Priority 5 Verification)
  // =========================================================================

  function normalizeTranscript(raw) {
    if (!raw) return '';
    return String(raw).toLowerCase().replace(/[,!?;:\-\/"]/g, ' ').replace(/\s+/g, ' ').trim();
  }

  function parseWakeAndCommand(rawText) {
    const norm = normalizeTranscript(rawText);
    if (!norm) return { hasWake: false, command: '', isWakeOnly: false };
    const wakeRegex = /\b(aleana|elena|alina|alana)\b/i;
    const hasWake = wakeRegex.test(norm);
    if (!hasWake) return { hasWake: false, command: norm, isWakeOnly: false };
    let command = norm.replace(/\b(hey|hi|hello|ok|okay)?\s*(aleana|elena|alina|alana)\s*(please)?\b/gi, '').trim();
    return { hasWake: true, command, isWakeOnly: command.length === 0 };
  }

  class MockController {
    constructor() {
      this.state = 'IDLE';
      this.sessionActive = false;
      this.isPaused = false;
      this.userStopped = true;
      this.isSpeaking = false;
      this.sessionId = 0;
      this.sessionHasGreeted = false;
      this.waitingForCommandAfterWake = false;
      this.greetingsSpoken = 0;
      this.commandsExecuted = [];
      this.recognitionRunning = false;
      this.restartsCount = 0;
      this.lastExecutedQuery = '';
      this.lastExecutedTime = 0;
    }

    startSession() {
      this.sessionId++;
      this.sessionHasGreeted = false;
      this.userStopped = false;
      this.isPaused = false;
      this.sessionActive = true;
      this.waitingForCommandAfterWake = false;
      this.recognitionRunning = true;
      this.onStart();
    }

    onStart() {
      if (!this.sessionHasGreeted) {
        this.sessionHasGreeted = true;
        this.greetingsSpoken++;
        this.speak('Aleana online. How can I help?');
      } else {
        this.state = 'LISTENING';
      }
    }

    speak(text) {
      this.isSpeaking = true;
      this.state = 'SPEAKING';
      // Half-duplex: abort recognition during speech
      this.recognitionRunning = false;
    }

    onSpeechEnd() {
      this.isSpeaking = false;
      if (this.sessionActive && !this.userStopped && !this.isPaused) {
        this.recognitionRunning = true;
        this.state = 'LISTENING';
      } else if (this.isPaused) {
        this.state = 'PAUSED';
      } else {
        this.state = 'IDLE';
      }
    }

    onEnd(unexpected = true) {
      this.recognitionRunning = false;
      if (this.isSpeaking) return;
      if (this.sessionActive && !this.userStopped && !this.isPaused) {
        this.restartsCount++;
        this.recognitionRunning = true;
        this.onStart(); // recovers
      } else if (this.isPaused) {
        this.state = 'PAUSED';
      } else {
        this.state = 'IDLE';
      }
    }

    pauseSession() {
      this.isPaused = true;
      this.recognitionRunning = false;
      this.state = 'PAUSED';
    }

    resumeSession() {
      this.isPaused = false;
      this.sessionActive = true;
      this.recognitionRunning = true;
      this.state = 'LISTENING';
    }

    stopSession() {
      this.sessionActive = false;
      this.userStopped = true;
      this.isPaused = false;
      this.sessionHasGreeted = false;
      this.recognitionRunning = false;
      this.state = 'IDLE';
    }

    handleTranscript(rawText, nowTime = 1000) {
      const norm = normalizeTranscript(rawText);
      const isStopPhrase = /^(aleana\s+)?(stop|shutdown|turn off|stop listening)(\s+aleana)?$/i.test(norm) ||
                           ['aleana stop', 'aleana shutdown', 'stop aleana', 'shutdown aleana', 'stop listening', 'shutdown'].includes(norm);
      const isHardwareOrSpeechStop = norm.includes('scanner') || norm.includes('camera') || norm.includes('feed') || norm.includes('speech');

      if (isStopPhrase && !isHardwareOrSpeechStop) {
        this.stopSession();
        return { action: 'STOPPED' };
      }

      if (['stop speech', 'stop speaking', 'aleana stop speaking', 'stop talking', 'chup ho jao'].some(k => norm.includes(k))) {
        this.isSpeaking = false;
        if (this.sessionActive && !this.userStopped && !this.isPaused) {
          this.state = 'LISTENING';
          this.recognitionRunning = true;
        }
        return { action: 'SPEECH_STOPPED' };
      }

      if (['pause listening', 'pause aleana'].some(k => norm.includes(k))) {
        this.pauseSession();
        return { action: 'PAUSED' };
      }
      if (['resume listening', 'resume aleana', 'start listening', 'start aleana', 'aleana start', 'aleana resume'].some(k => norm.includes(k))) {
        if (this.isPaused) this.resumeSession();
        return { action: 'RESUMED' };
      }

      const parsed = parseWakeAndCommand(rawText);
      let targetCommand = parsed.command;
      if (this.waitingForCommandAfterWake) {
        this.waitingForCommandAfterWake = false;
        targetCommand = parsed.command || norm;
      }

      if (parsed.hasWake && parsed.isWakeOnly) {
        this.waitingForCommandAfterWake = true;
        this.state = 'WAKE_DETECTED';
        return { action: 'WAKE_DETECTED' };
      }

      if (targetCommand) {
        if (targetCommand === this.lastExecutedQuery && (nowTime - this.lastExecutedTime) < 1500) {
          return { action: 'DEDUPLICATED' };
        }
        this.lastExecutedQuery = targetCommand;
        this.lastExecutedTime = nowTime;
        this.commandsExecuted.push(targetCommand);
        this.state = 'PROCESSING';
        return { action: 'EXECUTED', command: targetCommand };
      }

      return { action: 'IGNORED' };
    }
  }

  // 11. First session start produces exactly one greeting
  const mock = new MockController();
  mock.startSession();
  assert('First session start produces exactly one greeting', mock.greetingsSpoken === 1 && mock.state === 'SPEAKING');
  mock.onSpeechEnd();
  assert('Speech end transitions to LISTENING without greeting again', mock.state === 'LISTENING' && mock.greetingsSpoken === 1);

  // 12. Multiple commands do not repeat introduction
  mock.handleTranscript('show incidents', 2000);
  mock.onSpeechEnd();
  mock.handleTranscript('check system health', 4000);
  mock.onSpeechEnd();
  assert('Multiple commands do not repeat introduction', mock.greetingsSpoken === 1 && mock.commandsExecuted.length === 2);

  // 13. Unexpected onend recovery does not repeat the greeting
  mock.onEnd(true);
  assert('Unexpected onend recovery does not repeat greeting', mock.greetingsSpoken === 1 && mock.recognitionRunning === true && mock.state === 'LISTENING');

  // 14. "Aleana" alone enters WAKE_DETECTED state
  const wakeRes = mock.handleTranscript('Aleana', 6000);
  assert('"Aleana" alone activates WAKE_DETECTED state', wakeRes.action === 'WAKE_DETECTED' && mock.state === 'WAKE_DETECTED' && mock.waitingForCommandAfterWake === true);

  // 15. Follow-up command executes from wake state
  const followRes = mock.handleTranscript('show incidents', 7000);
  assert('Follow-up command executes from wake waiting state', followRes.action === 'EXECUTED' && followRes.command === 'show incidents' && mock.waitingForCommandAfterWake === false);

  // 16. "Aleana, open scanner" routes correct command
  const directCmd = mock.handleTranscript('Aleana, open scanner', 9000);
  assert('"Aleana, open scanner" parses wake word and routes command', directCmd.action === 'EXECUTED' && directCmd.command === 'open scanner');

  // 17. "Aleana stop" stops recognition and prevents restart
  mock.handleTranscript('Aleana stop', 11000);
  assert('"Aleana stop" stops recognition and session', mock.sessionActive === false && mock.userStopped === true && mock.recognitionRunning === false && mock.state === 'IDLE');
  mock.onEnd(false);
  assert('onEnd after Stop does not restart recognition', mock.recognitionRunning === false && mock.state === 'IDLE');

  // 18. "Aleana shutdown" stops recognition
  mock.startSession();
  mock.onSpeechEnd();
  mock.handleTranscript('Aleana shutdown', 13000);
  assert('"Aleana shutdown" halts voice session', mock.sessionActive === false && mock.userStopped === true);

  // 19. Pause vs Stop have distinct semantics
  mock.startSession();
  mock.onSpeechEnd();
  mock.handleTranscript('pause listening', 15000);
  assert('Pause listening sets isPaused=true while preserving sessionActive', mock.isPaused === true && mock.sessionActive === true && mock.state === 'PAUSED');
  mock.handleTranscript('resume listening', 16000);
  assert('Resume listening clears isPaused and sets LISTENING without re-greeting', mock.isPaused === false && mock.state === 'LISTENING' && mock.greetingsSpoken === 3);

  // 20. Duplicate interim/final transcripts do not execute commands twice
  mock.lastExecutedQuery = '';
  mock.lastExecutedTime = 0;
  const exec1 = mock.handleTranscript('open policies', 20000);
  const exec2 = mock.handleTranscript('open policies', 20300); // 300ms later
  assert('Duplicate rapid transcripts within 1500ms are deduplicated', exec1.action === 'EXECUTED' && exec2.action === 'DEDUPLICATED');

  // 21. Stop command does not misinterpret "stop scanner" as session shutdown
  mock.startSession();
  mock.onSpeechEnd();
  const scanStop = mock.handleTranscript('stop scanner', 25000);
  assert('"stop scanner" is routed as scanner hardware command, not voice session shutdown', scanStop.action === 'EXECUTED' && scanStop.command === 'stop scanner' && mock.sessionActive === true);

  // 22. "Stop speech" cancels speech output without terminating the active voice session
  mock.speak('Active speech synthesis playback');
  assert('Speech is actively running before cancel', mock.isSpeaking === true);
  const stopSpeechRes = mock.handleTranscript('stop speech', 30000);
  assert('"stop speech" cancels speech without stopping session', stopSpeechRes.action === 'SPEECH_STOPPED' && mock.isSpeaking === false && mock.sessionActive === true && mock.state === 'LISTENING');

  // 23. Multi-object tracker preserves distinct IDs and prevents cross-assignment
  const fs = require('fs');
  const appJsCode = fs.readFileSync('static/app.js', 'utf8');
  assert('app.js defines ObjectTracker class', appJsCode.includes('class ObjectTracker'));

  const trackerStart = appJsCode.indexOf('class ObjectTracker {');
  const trackerEnd = appJsCode.indexOf('// =========================================================================\n// 2. GLOBAL APPLICATION STATE');
  if (trackerStart !== -1 && trackerEnd !== -1) {
    const trackerCode = appJsCode.slice(trackerStart, trackerEnd).trim();
    const fn = new Function(`${trackerCode}; return ObjectTracker;`);
    const TestTracker = fn();
    const tracker = new TestTracker();

    // Frame 1: Two persons at [100, 100, 50, 100] and [300, 100, 50, 100]
    const f1 = tracker.update([
      { class: 'person', bbox: [100, 100, 50, 100], score: 0.92 },
      { class: 'person', bbox: [300, 100, 50, 100], score: 0.88 }
    ]);
    const id1 = f1[0].trackId;
    const id2 = f1[1].trackId;
    assert('Tracker assigns distinct IDs for simultaneous same-class objects', id1 !== id2 && f1.length === 2);

    // Frame 2: Objects moved slightly
    const f2 = tracker.update([
      { class: 'person', bbox: [106, 102, 50, 100], score: 0.93 },
      { class: 'person', bbox: [304, 98, 50, 100], score: 0.89 }
    ]);
    assert('Tracker preserves 1-to-1 track continuity across motion frames without swapping', f2[0].trackId === id1 && f2[1].trackId === id2);
  }

  console.log(`[ALEANA SUITE] Complete: ${passed}/${total} assertions passed.`);
  if (passed !== total) process.exit(1);
}

runAleanaTests().catch(err => {
  console.error('[ALEANA SUITE FATAL]', err);
  process.exit(1);
});
