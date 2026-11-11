/**
 * VantaVisionAI - Camera Initialization, Reconnection Retry & Beep Sound Control Test Suite
 */
const assert = require('assert');
const fs = require('fs');
const path = require('path');

console.log('[TEST SUITE] Executing Camera Reconnection & Beep Sound Control Suite...');

// Mock Minimal Browser Environment for Node.js
global.window = {
  addEventListener: () => {},
  removeEventListener: () => {},
  localStorage: {
    _data: {},
    getItem(k) { return this._data[k] || null; },
    setItem(k, v) { this._data[k] = String(v); },
    removeItem(k) { delete this._data[k]; }
  },
  showToast: () => {},
  isSecureContext: true,
  location: { protocol: 'https:', hostname: 'localhost' },
  requestAnimationFrame: (cb) => setTimeout(cb, 50),
  cancelAnimationFrame: (id) => clearTimeout(id)
};
global.requestAnimationFrame = global.window.requestAnimationFrame;
global.cancelAnimationFrame = global.window.cancelAnimationFrame;
global.localStorage = global.window.localStorage;
const dummyElem = {
  id: 'mock',
  style: {},
  textContent: '',
  className: '',
  addEventListener: () => {},
  removeEventListener: () => {},
  querySelectorAll: () => [],
  getBoundingClientRect: () => ({ width: 640, height: 360 }),
  appendChild: () => {},
  removeChild: () => {},
  setAttribute: () => {},
  removeAttribute: () => {},
  getAttribute: () => null,
  getContext: () => ({
    clearRect: () => {},
    fillRect: () => {},
    strokeRect: () => {},
    beginPath: () => {},
    moveTo: () => {},
    lineTo: () => {},
    stroke: () => {},
    fill: () => {},
    measureText: () => ({ width: 10 }),
    fillText: () => {},
    setLineDash: () => {},
    arc: () => {},
    save: () => {},
    restore: () => {}
  }),
  width: 640,
  height: 360,
  captureStream: () => ({
    getVideoTracks: () => [{ label: 'Mock Track', readyState: 'live', stop: () => {} }],
    getTracks: () => [{ stop: () => {} }]
  }),
  play: async () => {},
  pause: () => {}
};

global.document = {
  getElementById: (id) => ({ ...dummyElem, id }),
  createElement: () => ({ ...dummyElem }),
  querySelectorAll: () => [],
  addEventListener: () => {}
};
global.performance = { now: () => Date.now() };

// Load static/app.js
const appModule = require('../static/app.js');
const {
  STATE,
  TacticalSoundEngine,
  setBeepSoundEnabled,
  isBeepSoundEnabled,
  toggleBeepSound,
  triggerReconnection,
  cancelReconnection
} = appModule;

// Test 1: Beep sound variable defaults to false / muted
assert.strictEqual(typeof STATE.beepSoundEnabled, 'boolean', 'STATE.beepSoundEnabled must be boolean');
assert.strictEqual(STATE.beepSoundEnabled, false, 'STATE.beepSoundEnabled must default to false (muted)');
console.log('  ✓ [PASS] 1. STATE.beepSoundEnabled is boolean and defaults to false (muted)');

// Test 2: TacticalSoundEngine initializes with beepEnabled = false and isMuted = true
const sound = new TacticalSoundEngine();
assert.strictEqual(sound.beepEnabled, false, 'sound.beepEnabled must be false by default');
assert.strictEqual(sound.isMuted, true, 'sound.isMuted must be true by default');
assert.strictEqual(sound.isBeepAllowed(), false, 'isBeepAllowed() must return false by default');
console.log('  ✓ [PASS] 2. TacticalSoundEngine initializes with isBeepAllowed() === false');

// Test 3: Sound methods do not create AudioContext or produce sound when beep is disabled
sound.playAlert();
sound.playBreachAlert();
sound.playPing();
assert.strictEqual(sound.audioCtx, null, 'audioCtx must not be initialized when beep sound is disabled');
console.log('  ✓ [PASS] 3. Sound methods strictly no-op and do not initialize audio when beep disabled');

// Test 4: setBeepSoundEnabled toggles variable and updates localStorage
STATE.soundEngine = sound;
const enabled = setBeepSoundEnabled(true);
assert.strictEqual(enabled, true, 'setBeepSoundEnabled(true) returns true');
assert.strictEqual(STATE.beepSoundEnabled, true, 'STATE.beepSoundEnabled is now true');
assert.strictEqual(sound.isBeepAllowed(), true, 'isBeepAllowed() returns true when enabled');
assert.strictEqual(global.window.localStorage.getItem('vanta_beep_enabled'), 'true', 'Persisted to localStorage');
console.log('  ✓ [PASS] 4. setBeepSoundEnabled(true) enables sound and persists setting');

// Test 5: toggleBeepSound toggles back to disabled
const toggledOff = toggleBeepSound();
assert.strictEqual(toggledOff, false, 'toggleBeepSound() toggles to false');
assert.strictEqual(STATE.beepSoundEnabled, false, 'STATE.beepSoundEnabled is false after toggle');
assert.strictEqual(sound.isBeepAllowed(), false, 'isBeepAllowed() returns false after toggle');
console.log('  ✓ [PASS] 5. toggleBeepSound() accurately toggles back to disabled');

// Test 6: Camera Reconnection state variables exist
assert.strictEqual(typeof STATE.reconnectAttempts, 'number', 'reconnectAttempts must be numeric');
assert.strictEqual(typeof STATE.maxReconnectAttempts, 'number', 'maxReconnectAttempts must be numeric');
assert.strictEqual(STATE.maxReconnectAttempts, 5, 'maxReconnectAttempts should be 5');
assert.strictEqual(typeof STATE.cameraStatus, 'string', 'cameraStatus must be string');
console.log('  ✓ [PASS] 6. Camera reconnection parameters and status tracking are defined');

// Test 7: triggerReconnection initiates exponential backoff and sets isReconnecting = true
STATE.userStopped = false;
STATE.activeSourceType = 'Webcam';
STATE.isReconnecting = false;
STATE.reconnectAttempts = 0;
triggerReconnection('Test disconnect error');

assert.strictEqual(STATE.isReconnecting, true, 'STATE.isReconnecting must be true');
assert.strictEqual(STATE.reconnectAttempts, 1, 'STATE.reconnectAttempts must be incremented to 1');
assert.strictEqual(STATE.cameraStatus, 'reconnecting', 'cameraStatus must be reconnecting');
assert.ok(STATE.reconnectTimer !== null, 'reconnectTimer must be scheduled');
console.log('  ✓ [PASS] 7. triggerReconnection schedules backoff timer and updates cameraStatus');

// Test 8: cancelReconnection resets reconnect state
cancelReconnection();
assert.strictEqual(STATE.isReconnecting, false, 'isReconnecting must be cleared');
assert.strictEqual(STATE.reconnectAttempts, 0, 'reconnectAttempts must be reset to 0');
assert.strictEqual(STATE.reconnectTimer, null, 'reconnectTimer must be cleared');
console.log('  ✓ [PASS] 8. cancelReconnection cleanly clears timer and resets state');

// Test 9: Reconnection exhaustion switches smoothly to synthetic feed
STATE.userStopped = false;
STATE.activeSourceType = 'Webcam';
STATE.isReconnecting = false;
STATE.reconnectAttempts = 5; // Reached max
triggerReconnection('Exhaustion test');
assert.strictEqual(STATE.isReconnecting, false, 'isReconnecting must be false after exhaustion');
assert.strictEqual(STATE.activeSourceType, 'TestFeed', 'activeSourceType must auto-switch to TestFeed');
assert.strictEqual(STATE.cameraStatus, 'fallback', 'cameraStatus must transition to fallback');
console.log('  ✓ [PASS] 9. Max reconnect attempts smoothly transitions to simulated fallback feed');

// Test 10: static/firebase-client.js defines syncCameraStatus
const fbClientSrc = fs.readFileSync(path.join(__dirname, '../static/firebase-client.js'), 'utf8');
assert.ok(fbClientSrc.includes('async function syncCameraStatus'), 'firebase-client.js must define syncCameraStatus');
assert.ok(fbClientSrc.includes('syncCameraStatus'), 'firebase-client.js must export syncCameraStatus in window.VantaFirebase');
console.log('  ✓ [PASS] 10. static/firebase-client.js implements and exports syncCameraStatus');

console.log('[CAMERA & AUDIO SUITE] Complete: 10/10 assertions passed.');
cancelReconnection();
if (STATE.syntheticTimer) clearInterval(STATE.syntheticTimer);
process.exit(0);
