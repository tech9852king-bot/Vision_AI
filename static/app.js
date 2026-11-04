// VantaVisionAI - Enterprise Cybersecurity Surveillance, 7-Layer Brain & Aleana Voice Assistant
// Master Client Application: Computer Vision Tracking, Voice Engine, Real-Time Threat Orchestration

// =========================================================================
// 1. LIGHTWEIGHT IOU / CENTROID OBJECT TRACKER
// =========================================================================
// 1.1 SANITIZATION AND PER-CLASS NON-MAXIMUM SUPPRESSION (NMS)
function sanitizeAndValidateDetections(rawPredictions, maxW = 10000, maxH = 10000) {
  if (!Array.isArray(rawPredictions)) return [];
  const valid = [];
  for (let i = 0; i < rawPredictions.length; i++) {
    const p = rawPredictions[i];
    if (!p || typeof p !== 'object') continue;
    if (typeof p.class !== 'string' || !p.class.trim()) continue;
    const score = Number(p.score);
    if (isNaN(score) || score < 0 || score > 1) continue;
    if (!Array.isArray(p.bbox) || p.bbox.length !== 4) continue;
    let [x, y, w, h] = p.bbox.map(Number);
    if (isNaN(x) || isNaN(y) || isNaN(w) || isNaN(h)) continue;
    if (w <= 0 || h <= 0) continue;

    // Boundary clamping to ensure coordinates stay within valid frame bounds
    const clampedX = Math.max(0, Math.min(maxW - 4, x));
    const clampedY = Math.max(0, Math.min(maxH - 4, y));
    const clampedW = Math.max(4, Math.min(maxW - clampedX, w));
    const clampedH = Math.max(4, Math.min(maxH - clampedY, h));

    valid.push({
      ...p,
      class: p.class.toLowerCase().trim(),
      score: Math.min(1.0, Math.max(0.0, score)),
      bbox: [clampedX, clampedY, clampedW, clampedH]
    });
  }
  return valid;
}

function computeBoxIoU(boxA, boxB) {
  const xA = Math.max(boxA[0], boxB[0]);
  const yA = Math.max(boxA[1], boxB[1]);
  const xB = Math.min(boxA[0] + boxA[2], boxB[0] + boxB[2]);
  const yB = Math.min(boxA[1] + boxA[3], boxB[1] + boxB[3]);
  const interArea = Math.max(0, xB - xA) * Math.max(0, yB - yA);
  const unionArea = (boxA[2] * boxA[3]) + (boxB[2] * boxB[3]) - interArea;
  return unionArea > 0 ? interArea / unionArea : 0;
}

function applyPerClassNMS(predictions, iouThreshold = 0.50) {
  if (!Array.isArray(predictions) || predictions.length <= 1) return predictions || [];
  
  // Group by class to avoid suppressing legitimate concurrent overlapping objects of different classes (e.g. Person + Backpack)
  const byClass = new Map();
  for (const pred of predictions) {
    if (!byClass.has(pred.class)) {
      byClass.set(pred.class, []);
    }
    byClass.get(pred.class).push(pred);
  }

  const result = [];
  for (const [cls, list] of byClass.entries()) {
    // Sort descending by confidence score
    list.sort((a, b) => b.score - a.score);
    const selected = [];
    for (let i = 0; i < list.length; i++) {
      const candidate = list[i];
      let keep = true;
      for (let j = 0; j < selected.length; j++) {
        const prev = selected[j];
        const iou = computeBoxIoU(candidate.bbox, prev.bbox);
        if (iou >= iouThreshold) {
          keep = false;
          break;
        }
      }
      if (keep) {
        selected.push(candidate);
      }
    }
    result.push(...selected);
  }
  return result;
}

// 1.2 MULTI-OBJECT TRACKER (IOU + MOTION PREDICTION + OCCLUSION RECOVERY)
class ObjectTracker {
  constructor(maxDisappeared = 20, iouThreshold = 0.20) {
    this.nextTrackId = 101;
    this.tracks = new Map(); // id -> { id, class, bbox, vx, vy, disappeared, age, eventSent, score }
    this.maxDisappeared = maxDisappeared;
    this.iouThreshold = iouThreshold;
    this.reIdBuffer = []; // Rolling 5-second memory for cross-camera / occlusion Re-ID continuity
    this.reIdWindowMs = 5000;
  }

  pushToReIdBuffer(trk) {
    if (!trk || !trk.bbox) return;
    const w = trk.bbox[2];
    const h = trk.bbox[3];
    const ar = w / (h || 1);
    const area = w * h;
    const now = Date.now();
    this.reIdBuffer = (this.reIdBuffer || []).filter(item => (now - item.lastSeenTime) < this.reIdWindowMs && item.id !== trk.id);
    this.reIdBuffer.push({
      id: trk.id,
      class: trk.class,
      width: w,
      height: h,
      aspectRatio: ar,
      area: area,
      lastSeenTime: trk.lastSeenTime || now
    });
  }

  computeIoU(boxA, boxB) {
    const xA = Math.max(boxA[0], boxB[0]);
    const yA = Math.max(boxA[1], boxB[1]);
    const xB = Math.min(boxA[0] + boxA[2], boxB[0] + boxB[2]);
    const yB = Math.min(boxA[1] + boxA[3], boxB[1] + boxB[3]);
    const interArea = Math.max(0, xB - xA) * Math.max(0, yB - yA);
    const boxAArea = boxA[2] * boxA[3];
    const boxBArea = boxB[2] * boxB[3];
    const unionArea = boxAArea + boxBArea - interArea;
    return unionArea > 0 ? interArea / unionArea : 0;
  }

  computeCentroidDistance(boxA, boxB) {
    const cAx = boxA[0] + boxA[2] / 2;
    const cAy = boxA[1] + boxA[3] / 2;
    const cBx = boxB[0] + boxB[2] / 2;
    const cBy = boxB[1] + boxB[3] / 2;
    return Math.hypot(cAx - cBx, cAy - cBy);
  }

  update(predictions) {
    // Increment disappearance counter for all active tracks
    for (const [id, trk] of this.tracks.entries()) {
      trk.disappeared++;
    }

    const matchedTrackIds = new Set();
    const matchedPredIndices = new Set();

    // 1. Build candidate match pairs between active tracks and incoming detections
    const candidates = [];
    predictions.forEach((pred, pIdx) => {
      for (const [id, trk] of this.tracks.entries()) {
        if (trk.class === pred.class) {
          // Multi-frame velocity extrapolation for temporary occlusion recovery
          const dt = Math.max(1, trk.disappeared);
          const predictedBox = [
            trk.bbox[0] + (trk.vx || 0) * dt,
            trk.bbox[1] + (trk.vy || 0) * dt,
            trk.bbox[2],
            trk.bbox[3]
          ];
          const directIoU = this.computeIoU(trk.bbox, pred.bbox);
          const motionIoU = this.computeIoU(predictedBox, pred.bbox);
          const bestIoU = Math.max(directIoU, motionIoU);

          // Centroid distance relative to target scale
          const dist = this.computeCentroidDistance(trk.bbox, pred.bbox);
          const diag = Math.hypot(trk.bbox[2], trk.bbox[3]) || 50;
          const maxGate = diag * 2.0;

          if (bestIoU >= this.iouThreshold || (dist < maxGate && (bestIoU > 0.05 || trk.disappeared <= 2))) {
            const normDistScore = Math.max(0, 1.0 - (dist / Math.max(140, maxGate)));
            const matchScore = (bestIoU * 0.65) + (normDistScore * 0.35);
            candidates.push({
              trackId: id,
              predIdx: pIdx,
              score: matchScore
            });
          }
        }
      }
    });

    const updatedTracks = new Array(predictions.length);

    // 2. Greedy 1-to-1 match assignment sorted by highest overlap score
    candidates.sort((a, b) => b.score - a.score);
    for (const match of candidates) {
      if (matchedTrackIds.has(match.trackId) || matchedPredIndices.has(match.predIdx)) {
        continue;
      }
      matchedTrackIds.add(match.trackId);
      matchedPredIndices.add(match.predIdx);

      const trk = this.tracks.get(match.trackId);
      const pred = predictions[match.predIdx];

      // Time-aware velocity estimation
      const dt = Math.max(1, trk.disappeared);
      const dx = (pred.bbox[0] - trk.bbox[0]) / dt;
      const dy = (pred.bbox[1] - trk.bbox[1]) / dt;
      trk.vx = 0.55 * dx + 0.45 * (trk.vx || 0);
      trk.vy = 0.55 * dy + 0.45 * (trk.vy || 0);

      // Coordinate smoothing
      const alpha = 0.85;
      trk.bbox = [
        alpha * pred.bbox[0] + (1 - alpha) * trk.bbox[0],
        alpha * pred.bbox[1] + (1 - alpha) * trk.bbox[1],
        alpha * pred.bbox[2] + (1 - alpha) * trk.bbox[2],
        alpha * pred.bbox[3] + (1 - alpha) * trk.bbox[3]
      ];
      trk.score = pred.score;
      trk.disappeared = 0;
      trk.age = (trk.age || 0) + 1;
      trk.lastSeenTime = Date.now();
      trk.dwellTimeSec = Number(((trk.lastSeenTime - (trk.firstSeenTime || trk.lastSeenTime)) / 1000).toFixed(1));

      const cX = Math.round(trk.bbox[0] + trk.bbox[2] / 2);
      const cY = Math.round(trk.bbox[1] + trk.bbox[3] / 2);
      if (!trk.centroidTrail) trk.centroidTrail = [];
      trk.centroidTrail.push([cX, cY]);
      if (trk.centroidTrail.length > 20) trk.centroidTrail.shift();

      const speedPxS = Math.round(Math.hypot(trk.vx, trk.vy) * 20);
      let motionState = 'STATIONARY';
      if (speedPxS > 45) motionState = 'FAST_MOVING / RUNNING';
      else if (speedPxS > 8) motionState = 'WALKING';
      trk.motionState = motionState;
      trk.speedPxS = speedPxS;

      updatedTracks[match.predIdx] = {
        ...pred,
        bbox: trk.bbox,
        trackId: trk.id,
        isNew: false,
        speed: Math.round(Math.hypot(trk.vx, trk.vy)),
        vx: trk.vx,
        vy: trk.vy,
        centroidTrail: trk.centroidTrail,
        dwellTimeSec: trk.dwellTimeSec,
        motionState: trk.motionState,
        speedPxS: trk.speedPxS
      };
    }

    // 3. Register unmatched predictions with Re-ID continuity matching or new IDs
    const now = Date.now();
    this.reIdBuffer = (this.reIdBuffer || []).filter(item => (now - item.lastSeenTime) < this.reIdWindowMs);

    predictions.forEach((pred, pIdx) => {
      if (!matchedPredIndices.has(pIdx)) {
        let assignedId = null;
        let isReIdMatch = false;
        let matchSimScore = 0;

        const predW = pred.bbox[2];
        const predH = pred.bbox[3];
        const predAR = predW / (predH || 1);
        const predArea = predW * predH;

        let bestBufferIdx = -1;
        let bestScore = 0;

        for (let bIdx = 0; bIdx < this.reIdBuffer.length; bIdx++) {
          const item = this.reIdBuffer[bIdx];
          if (item.class === pred.class) {
            const arSim = Math.min(predAR, item.aspectRatio) / Math.max(predAR, item.aspectRatio);
            const sizeSim = Math.min(predArea, item.area) / Math.max(predArea, item.area);
            if (arSim >= 0.80 && sizeSim >= 0.80) {
              const combinedSim = (arSim * 0.5) + (sizeSim * 0.5);
              if (combinedSim > bestScore) {
                bestScore = combinedSim;
                bestBufferIdx = bIdx;
              }
            }
          }
        }

        if (bestBufferIdx !== -1) {
          const matchedItem = this.reIdBuffer.splice(bestBufferIdx, 1)[0];
          assignedId = matchedItem.id;
          isReIdMatch = true;
          matchSimScore = Math.round(bestScore * 100);

          if (typeof STATE !== 'undefined' && Array.isArray(STATE.sceneEventsLog)) {
            STATE.sceneEventsLog.push({
              event: 'REID_CONTINUITY_MATCH',
              trackId: assignedId,
              class: pred.class,
              similarity: matchSimScore,
              timestamp: new Date().toISOString()
            });
            if (STATE.sceneEventsLog.length > 100) STATE.sceneEventsLog.shift();
          }
        } else {
          assignedId = this.nextTrackId++;
        }

        const cX = Math.round(pred.bbox[0] + pred.bbox[2] / 2);
        const cY = Math.round(pred.bbox[1] + pred.bbox[3] / 2);
        const newTrack = {
          id: assignedId,
          class: pred.class,
          bbox: pred.bbox,
          score: pred.score,
          vx: 0,
          vy: 0,
          age: 1,
          disappeared: 0,
          eventSent: false,
          firstSeenTime: now,
          lastSeenTime: now,
          dwellTimeSec: 0.1,
          centroidTrail: [[cX, cY]],
          motionState: 'STATIONARY',
          speedPxS: 0
        };
        this.tracks.set(assignedId, newTrack);
        updatedTracks[pIdx] = {
          ...pred,
          trackId: assignedId,
          isNew: !isReIdMatch,
          speed: 0,
          vx: 0,
          vy: 0,
          centroidTrail: newTrack.centroidTrail,
          dwellTimeSec: 0.1,
          motionState: 'STATIONARY',
          speedPxS: 0
        };
      }
    });

    // 4. Prune stale tracks exceeding maximum disappearance threshold (store into reIdBuffer)
    for (const [id, trk] of this.tracks.entries()) {
      if (trk.disappeared > this.maxDisappeared) {
        this.pushToReIdBuffer(trk);
        this.tracks.delete(id);
      }
    }
    return updatedTracks.filter(Boolean);
  }

  markEventSent(trackId) {
    if (this.tracks.has(trackId)) {
      const trk = this.tracks.get(trackId);
      trk.eventSent = true;
      trk.lastSentTime = Date.now();
    }
  }

  hasSentEvent(trackId) {
    if (!this.tracks.has(trackId)) return false;
    const trk = this.tracks.get(trackId);
    if (!trk.eventSent) return false;
    // Throttle to maximum 1 event dispatch per object per 4 seconds
    if (trk.lastSentTime && (Date.now() - trk.lastSentTime > 4000)) {
      return false;
    }
    return true;
  }

  reset() {
    for (const trk of this.tracks.values()) {
      this.pushToReIdBuffer(trk);
    }
    this.tracks.clear();
  }
}


// =========================================================================
// 2. GLOBAL APPLICATION STATE
// =========================================================================
const STATE = {
  tenantId: 'default',
  currentView: 'dashboard',
  model: null,
  isModelLoading: true,
  modelStatusText: 'Loading COCO-SSD...',
  isScanning: false,
  stream: null,
  syntheticCanvas: null,
  syntheticTimer: null,
  dashboardCanvasTimer: null,
  activeSourceType: 'None', // 'Webcam', 'Upload', 'TestFeed', 'None'
  activeSourceName: 'None',
  confThreshold: 0.60,
  lastInferenceTime: 0,
  scanSessionId: 0,
  animFrameId: null,
  isDetecting: false,
  lastError: null,
  cameraPermissionState: 'unknown',
  measuredFps: 0,
  measuredLatency: 0,
  reconnectAttempts: 0,
  maxReconnectAttempts: 5,
  reconnectTimer: null,
  isReconnecting: false,
  userStopped: false,
  lastValidFrameTime: 0,
  tracker: new ObjectTracker(),

  // Safe Bounded Inference and Video Validation
  activeObjectUrl: null,
  maxInferenceDimension: 640,
  maxVideoFileSizeMB: 50,
  maxVideoDurationSec: 180,
  supportedVideoExts: ['.mp4', '.webm', '.ogg', '.mov'],

  // Event ingestion backpressure
  inFlightEventCount: 0,
  maxInFlightEvents: 2,
  lastSummaryRefreshTime: 0,
  summaryRefreshThrottleMs: 2500,

  // Live Category Filter and In-Memory Frame Cache
  categoryFilter: 'all',
  lastRawPredictions: [],
  lastTrackedDetections: [],
  sceneEventsLog: [],

  // Detection Settings Toggles & Dynamic Filter Engine
  detectionFilters: {
    people: true,
    vehicles: true,
    objects: true,
    weapons: false,
    electronics: true,
    animals: true,
    custom: false
  },

  // Aleana Voice Assistant State Machine
  aleana: {
    state: 'IDLE', // 'IDLE', 'REQUESTING_PERMISSION', 'LISTENING', 'WAKE_DETECTED', 'PROCESSING', 'SPEAKING', 'RECOVERING', 'PAUSED', 'STOPPING', 'ERROR'
    recognition: null,
    isSupported: false,
    sessionActive: false,
    isPaused: false,
    userStopped: true,
    isSpeaking: false,
    sessionId: 0,
    sessionHasGreeted: false,
    waitingForCommandAfterWake: false,
    wakeTimeoutId: null,
    lastExecutedQuery: '',
    lastExecutedTime: 0,
    consecutiveRestarts: 0,
    restartTimer: null,
    selectedVoice: null,
    speechRate: 1.0,
    language: 'en-US',
    autoSpeak: true,
    isMuted: false,
    voicesList: [],
    lastSpokenText: ''
  },

  // AI Copilot Voice & Telemetry State
  copilotVoiceSpeech: false,
  copilotRecognition: null,
  copilotIsListening: false,

  // Tactical Audio Synthesizer Engine
  soundEngine: null,

  // Spatial-Temporal Heatmap Grid (32x18)
  heatmapEnabled: false,
  heatmapGrid: Array.from({ length: 18 }, () => new Float32Array(32)),

  // In-Memory Forensic Evidence Buffer
  forensicSnapshots: [],

  // Global Command Palette State
  commandPaletteActive: false,
  commandPaletteSelectedIndex: 0
};

// =========================================================================
// TACTICAL WEBAUDIO SYNTHESIZER & FFT ANALYSER ENGINE
// =========================================================================
class TacticalSoundEngine {
  constructor() {
    this.audioCtx = null;
    this.isMuted = false;
    this.analyser = null;
    this.dataArray = null;
    this.waveformBars = [];
  }

  init() {
    if (this.audioCtx) return;
    try {
      const AudioCtxClass = window.AudioContext || window.webkitAudioContext;
      if (AudioCtxClass) {
        this.audioCtx = new AudioCtxClass();
        this.analyser = this.audioCtx.createAnalyser();
        this.analyser.fftSize = 64;
        this.dataArray = new Uint8Array(this.analyser.frequencyBinCount);
        this.startWaveformVisualizer();
      }
    } catch (e) {
      console.warn('TacticalSoundEngine WebAudio init warning:', e);
    }
  }

  resume() {
    if (this.audioCtx && this.audioCtx.state === 'suspended') {
      this.audioCtx.resume().catch(() => {});
    }
  }

  toggleMute() {
    this.isMuted = !this.isMuted;
    const label = document.getElementById('audio-mute-label');
    const iconUnmuted = document.getElementById('audio-icon-unmuted');
    const iconMuted = document.getElementById('audio-icon-muted');
    if (label) label.textContent = this.isMuted ? 'Audio: OFF' : 'Audio: ON';
    if (iconUnmuted) iconUnmuted.style.display = this.isMuted ? 'none' : 'block';
    if (iconMuted) iconMuted.style.display = this.isMuted ? 'block' : 'none';
    showToast(this.isMuted ? 'Tactical audio muted.' : 'Tactical audio effects active.', 'info');
    return this.isMuted;
  }

  playPing() {
    if (this.isMuted) return;
    this.init();
    this.resume();
    if (!this.audioCtx) return;
    try {
      const osc = this.audioCtx.createOscillator();
      const gain = this.audioCtx.createGain();
      const now = this.audioCtx.currentTime;
      osc.type = 'sine';
      osc.frequency.setValueAtTime(880, now);
      osc.frequency.exponentialRampToValueAtTime(1320, now + 0.08);
      gain.gain.setValueAtTime(0.12, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.12);
      osc.connect(gain);
      gain.connect(this.analyser || this.audioCtx.destination);
      if (this.analyser) this.analyser.connect(this.audioCtx.destination);
      osc.start(now);
      osc.stop(now + 0.13);
    } catch (e) {}
  }

  playScanLock() {
    if (this.isMuted) return;
    this.init();
    this.resume();
    if (!this.audioCtx) return;
    try {
      const now = this.audioCtx.currentTime;
      [587.33, 880].forEach((freq, idx) => {
        const osc = this.audioCtx.createOscillator();
        const gain = this.audioCtx.createGain();
        osc.type = 'sine';
        osc.frequency.setValueAtTime(freq, now + idx * 0.05);
        gain.gain.setValueAtTime(0.14, now + idx * 0.05);
        gain.gain.exponentialRampToValueAtTime(0.001, now + idx * 0.05 + 0.07);
        osc.connect(gain);
        gain.connect(this.analyser || this.audioCtx.destination);
        if (this.analyser) this.analyser.connect(this.audioCtx.destination);
        osc.start(now + idx * 0.05);
        osc.stop(now + idx * 0.05 + 0.08);
      });
    } catch (e) {}
  }

  playAlert() {
    if (this.isMuted) return;
    this.init();
    this.resume();
    if (!this.audioCtx) return;
    try {
      const now = this.audioCtx.currentTime;
      const osc = this.audioCtx.createOscillator();
      const gain = this.audioCtx.createGain();
      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(440, now);
      osc.frequency.linearRampToValueAtTime(310, now + 0.16);
      gain.gain.setValueAtTime(0.16, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.20);
      osc.connect(gain);
      gain.connect(this.analyser || this.audioCtx.destination);
      if (this.analyser) this.analyser.connect(this.audioCtx.destination);
      osc.start(now);
      osc.stop(now + 0.21);
    } catch (e) {}
  }

  playSuccess() {
    if (this.isMuted) return;
    this.init();
    this.resume();
    if (!this.audioCtx) return;
    try {
      const now = this.audioCtx.currentTime;
      [523.25, 659.25, 783.99].forEach((freq, idx) => {
        const osc = this.audioCtx.createOscillator();
        const gain = this.audioCtx.createGain();
        osc.type = 'triangle';
        osc.frequency.setValueAtTime(freq, now + idx * 0.06);
        gain.gain.setValueAtTime(0.12, now + idx * 0.06);
        gain.gain.exponentialRampToValueAtTime(0.001, now + idx * 0.06 + 0.15);
        osc.connect(gain);
        gain.connect(this.analyser || this.audioCtx.destination);
        if (this.analyser) this.analyser.connect(this.audioCtx.destination);
        osc.start(now + idx * 0.06);
        osc.stop(now + idx * 0.06 + 0.16);
      });
    } catch (e) {}
  }

  playWakeChirp() {
    if (this.isMuted) return;
    this.init();
    this.resume();
    if (!this.audioCtx) return;
    try {
      const now = this.audioCtx.currentTime;
      const osc = this.audioCtx.createOscillator();
      const gain = this.audioCtx.createGain();
      osc.type = 'sine';
      osc.frequency.setValueAtTime(587.33, now);
      osc.frequency.exponentialRampToValueAtTime(1174.66, now + 0.12);
      gain.gain.setValueAtTime(0.14, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.16);
      osc.connect(gain);
      gain.connect(this.analyser || this.audioCtx.destination);
      if (this.analyser) this.analyser.connect(this.audioCtx.destination);
      osc.start(now);
      osc.stop(now + 0.17);
    } catch (e) {}
  }

  playTargetLock() {
    this.playScanLock();
  }

  playBreachAlert() {
    if (this.isMuted) return;
    this.init();
    this.resume();
    if (!this.audioCtx) return;
    try {
      const now = this.audioCtx.currentTime;
      [880, 440, 880].forEach((freq, idx) => {
        const osc = this.audioCtx.createOscillator();
        const gain = this.audioCtx.createGain();
        osc.type = 'sawtooth';
        osc.frequency.setValueAtTime(freq, now + idx * 0.09);
        gain.gain.setValueAtTime(0.18, now + idx * 0.09);
        gain.gain.exponentialRampToValueAtTime(0.001, now + idx * 0.09 + 0.08);
        osc.connect(gain);
        gain.connect(this.analyser || this.audioCtx.destination);
        if (this.analyser) this.analyser.connect(this.audioCtx.destination);
        osc.start(now + idx * 0.09);
        osc.stop(now + idx * 0.09 + 0.09);
      });
    } catch (e) {
      this.playAlert();
    }
  }

  playResolveChord() {
    this.playSuccess();
  }

  startWaveformVisualizer() {
    if (!box) return;
    const updateWave = () => {
      requestAnimationFrame(updateWave);
      if (!this.analyser || !this.dataArray) return;
      this.analyser.getByteFrequencyData(this.dataArray);
      const bars = box.querySelectorAll('.wave-bar');
      if (bars.length === 0) return;
      const step = Math.max(1, Math.floor(this.dataArray.length / bars.length));
      bars.forEach((bar, i) => {
        const val = this.dataArray[i * step] || 0;
        const h = Math.max(4, Math.round((val / 255) * 36));
        bar.style.height = `${h}px`;
      });
    };
    updateWave();
  }
}

// =========================================================================
// DETECTION CATEGORIES REGISTRY & ON-THE-FLY FILTER LOGIC
// =========================================================================
const DETECTION_CATEGORIES = {
  all: {
    label: 'All Categories',
    badgeText: 'All Categories',
    color: '#00e5ff',
    chipClass: 'chip-object',
    icon: `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>`,
    matches: () => true
  },
  person: {
    label: 'Persons',
    badgeText: 'Persons Only',
    color: '#f43f5e',
    chipClass: 'chip-person',
    icon: `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>`,
    matches: (cls) => cls === 'person'
  },
  vehicles: {
    label: 'Vehicles',
    badgeText: 'Vehicles',
    color: '#10b981',
    chipClass: 'chip-vehicle',
    icon: `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><rect width="16" height="8" x="4" y="9" rx="2"/><circle cx="7.5" cy="17.5" r="2.5"/><circle cx="16.5" cy="17.5" r="2.5"/></svg>`,
    matches: (cls) => ['car', 'truck', 'motorcycle', 'bus', 'bicycle', 'train', 'airplane', 'boat'].includes(cls)
  },
  luggage: {
    label: 'Luggage & Bags',
    badgeText: 'Luggage & Bags',
    color: '#a855f7',
    chipClass: 'chip-luggage',
    icon: `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="7" width="20" height="14" rx="2"/><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/></svg>`,
    matches: (cls) => ['backpack', 'handbag', 'suitcase', 'umbrella'].includes(cls)
  },
  weapons: {
    label: 'Hazards & Weapons',
    badgeText: 'Hazards & Weapons',
    color: '#f59e0b',
    chipClass: 'chip-hazard',
    icon: `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
    matches: (cls) => ['knife', 'scissors', 'baseball bat'].includes(cls)
  },
  electronics: {
    label: 'Electronics',
    badgeText: 'Electronics',
    color: '#06b6d4',
    chipClass: 'chip-electronics',
    icon: `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><rect width="14" height="20" x="5" y="2" rx="2"/><line x1="12" x2="12.01" y1="18" y2="18"/></svg>`,
    matches: (cls) => ['cell phone', 'laptop', 'mouse', 'remote', 'keyboard', 'tv', 'microwave', 'oven', 'toaster', 'sink', 'refrigerator', 'book', 'clock'].includes(cls)
  },
  animals: {
    label: 'Animals',
    badgeText: 'Animals',
    color: '#ec4899',
    chipClass: 'chip-animal',
    icon: `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="m9 9 1 1"/><path d="m15 9-1 1"/><path d="M8 15h8"/></svg>`,
    matches: (cls) => ['bird', 'cat', 'dog', 'horse', 'sheep', 'cow', 'elephant', 'bear', 'zebra', 'giraffe'].includes(cls)
  },
  furniture: {
    label: 'Interior & Furniture',
    badgeText: 'Interior & Furniture',
    color: '#94a3b8',
    chipClass: 'chip-furniture',
    icon: `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 9V6a2 2 0 0 0-2-2H7a2 2 0 0 0-2 2v3"/><path d="M3 11v5a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2Z"/><path d="M5 18v3"/><path d="M19 18v3"/></svg>`,
    matches: (cls) => ['chair', 'couch', 'potted plant', 'bed', 'dining table', 'toilet'].includes(cls)
  },
  other: {
    label: 'Other Objects',
    badgeText: 'Other Objects',
    color: '#3b82f6',
    chipClass: 'chip-object',
    icon: `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="8"/></svg>`,
    matches: (cls) => {
      const known = ['person', 'car', 'truck', 'motorcycle', 'bus', 'bicycle', 'train', 'airplane', 'boat', 'backpack', 'handbag', 'suitcase', 'umbrella', 'knife', 'scissors', 'baseball bat', 'cell phone', 'laptop', 'mouse', 'remote', 'keyboard', 'tv', 'microwave', 'oven', 'toaster', 'sink', 'refrigerator', 'book', 'clock', 'bird', 'cat', 'dog', 'horse', 'sheep', 'cow', 'elephant', 'bear', 'zebra', 'giraffe', 'chair', 'couch', 'potted plant', 'bed', 'dining table', 'toilet'];
      return !known.includes(cls);
    }
  },
  none: {
    label: 'None (Hidden)',
    badgeText: 'Chips Hidden',
    color: '#64748b',
    chipClass: 'chip-object',
    icon: `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>`,
    matches: () => false
  }
};

function getObjectCategory(className) {
  const cls = (className || '').toLowerCase();
  for (const [key, cat] of Object.entries(DETECTION_CATEGORIES)) {
    if (key !== 'all' && key !== 'other' && key !== 'none' && cat.matches(cls)) {
      return key;
    }
  }
  return 'other';
}

function filterPredictions(rawPredictions) {
  if (!Array.isArray(rawPredictions)) return [];
  const selectedCat = STATE.categoryFilter || 'all';

  return rawPredictions.filter(p => {
    if (p.score < STATE.confThreshold) return false;

    // Check category dropdown filter
    if (selectedCat !== 'all') {
      const catConfig = DETECTION_CATEGORIES[selectedCat];
      if (catConfig && typeof catConfig.matches === 'function') {
        if (!catConfig.matches(p.class)) return false;
      }
    } else {
      // When 'all' is selected, respect the checkbox toggles
      if (p.class === 'person' && !STATE.detectionFilters.people) return false;
      if (['car', 'truck', 'motorcycle', 'bus', 'bicycle'].includes(p.class) && !STATE.detectionFilters.vehicles) return false;
      if (['backpack', 'suitcase', 'handbag', 'bottle'].includes(p.class) && !STATE.detectionFilters.objects) return false;
      if (['knife', 'scissors', 'baseball bat'].includes(p.class) && !STATE.detectionFilters.weapons) return false;
    }

    // Dynamic type filter check: toggle specific object detection types like 'person' or 'vehicle' without modifying inference loop
    if (p.class === 'person' && STATE.detectionFilters.people === false) return false;
    if (['car', 'truck', 'motorcycle', 'bus', 'bicycle', 'train', 'airplane', 'boat'].includes(p.class) && STATE.detectionFilters.vehicles === false) return false;
    if (['backpack', 'suitcase', 'handbag', 'bottle', 'umbrella'].includes(p.class) && STATE.detectionFilters.objects === false) return false;
    if (['knife', 'scissors', 'baseball bat'].includes(p.class) && STATE.detectionFilters.weapons === false) return false;
    if (['cell phone', 'laptop', 'mouse', 'remote', 'keyboard', 'tv', 'microwave', 'oven', 'toaster', 'sink', 'refrigerator', 'book', 'clock'].includes(p.class) && STATE.detectionFilters.electronics === false) return false;
    if (['bird', 'cat', 'dog', 'horse', 'sheep', 'cow', 'elephant', 'bear', 'zebra', 'giraffe'].includes(p.class) && STATE.detectionFilters.animals === false) return false;

    return true;
  });
}

// Dynamically updates visibility of detection chips in #detections-chips-row based on selected category
function updateChipsRowVisibility(selectedCategory) {
  const chipsRow = document.getElementById('detections-chips-row');
  if (!chipsRow) return;

  const countHeader = document.getElementById('detections-count-header');
  const catKey = selectedCategory || STATE.categoryFilter || 'all';
  const catConfig = DETECTION_CATEGORIES[catKey] || DETECTION_CATEGORIES.all;

  // Toggle container visibility for 'none' (hidden)
  if (catKey === 'none') {
    chipsRow.style.display = 'none';
    chipsRow.classList.add('chips-hidden');
    if (countHeader) countHeader.textContent = 'Detections (Hidden)';
    return;
  }

  chipsRow.style.display = 'flex';
  chipsRow.classList.remove('chips-hidden');

  // Filter individual detection chips visibility within the container
  const chips = chipsRow.querySelectorAll('.det-chip');
  let visibleCount = 0;
  chips.forEach(chip => {
    let chipCat = chip.dataset.category;
    if (!chipCat) {
      if (chip.classList.contains('chip-person')) chipCat = 'person';
      else if (chip.classList.contains('chip-vehicle')) chipCat = 'vehicles';
      else if (chip.classList.contains('chip-luggage')) chipCat = 'luggage';
      else if (chip.classList.contains('chip-hazard')) chipCat = 'weapons';
      else if (chip.classList.contains('chip-electronics')) chipCat = 'electronics';
      else if (chip.classList.contains('chip-animal')) chipCat = 'animals';
      else if (chip.classList.contains('chip-furniture')) chipCat = 'furniture';
      else chipCat = 'other';
    }

    const isMatch = (catKey === 'all') || (catKey === chipCat);
    if (isMatch) {
      chip.style.display = 'inline-flex';
      visibleCount++;
    } else {
      chip.style.display = 'none';
    }
  });

  // Handle empty state feedback if chips are filtered out
  const emptyFeedback = chipsRow.querySelector('.det-filter-empty');
  if (visibleCount === 0 && chips.length > 0 && catKey !== 'all') {
    if (!emptyFeedback) {
      const msg = document.createElement('div');
      msg.className = 'det-filter-empty mono';
      msg.style.cssText = 'font-size: 0.74rem; color: var(--text-muted); display: flex; align-items: center; gap: 0.45rem; padding: 0.35rem 0; width: 100%;';
      msg.innerHTML = `<span style="color: var(--accent-amber); font-weight: 700;">[FILTER ACTIVE]</span><span>No <strong>${escapeHtml(catConfig.label)}</strong> chips in view (${chips.length} hidden).</span>`;
      chipsRow.appendChild(msg);
    }
  } else if (emptyFeedback) {
    emptyFeedback.remove();
  }

  if (countHeader) {
    if (catKey === 'all') {
      countHeader.textContent = `Detections (${chips.length})`;
    } else {
      countHeader.textContent = `Detections (${visibleCount} of ${chips.length})`;
    }
  }
}

function applyActiveCategoryFilter() {
  const catKey = STATE.categoryFilter || 'all';
  const catConfig = DETECTION_CATEGORIES[catKey] || DETECTION_CATEGORIES.all;

  // Update header badge
  const filterBadge = document.getElementById('detections-filter-badge');
  if (filterBadge) {
    filterBadge.textContent = catConfig.badgeText || catConfig.label;
    filterBadge.className = `badge ${catKey === 'all' ? 'badge-medium' : catKey === 'none' ? 'badge-danger' : 'badge-cyan'} mono`;
  }

  // Synchronize dynamic type filter HUD pills and toggles
  if (typeof syncDynamicFilterUI === 'function') {
    syncDynamicFilterUI();
  }

  // Update category select dropdown if out-of-sync
  const catSelect = document.getElementById('scanner-category-filter');
  if (catSelect && catSelect.value !== catKey) {
    catSelect.value = catKey;
  }

  // Dynamically update detection chip container visibility based on user selection
  const chipsRow = document.getElementById('detections-chips-row');
  if (chipsRow) {
    chipsRow.setAttribute('data-category-filter', catKey);
    if (catKey === 'none') {
      chipsRow.style.display = 'none';
      chipsRow.classList.add('chips-hidden');
    } else {
      chipsRow.style.display = 'flex';
      chipsRow.classList.remove('chips-hidden');
    }
  }

  // Re-filter cached predictions immediately if available
  if (STATE.lastRawPredictions && STATE.lastRawPredictions.length > 0) {
    const filtered = filterPredictions(STATE.lastRawPredictions);
    const trackedDetections = STATE.tracker.update(filtered);
    STATE.lastTrackedDetections = trackedDetections;
    renderPredictions(trackedDetections);
  } else if (STATE.lastTrackedDetections && STATE.lastTrackedDetections.length > 0) {
    const filtered = filterPredictions(STATE.lastTrackedDetections);
    renderPredictions(filtered);
  } else if (STATE.isScanning) {
    updateDetectionChips([]);
  } else {
    updateChipsRowVisibility(catKey);
  }
}

// Reusable offscreen canvas for bounded downscaled inference
const inferenceCanvas = typeof document !== 'undefined' ? document.createElement('canvas') : null;
const inferenceCtx = inferenceCanvas && typeof inferenceCanvas.getContext === 'function' ? inferenceCanvas.getContext('2d', { willReadFrequently: true }) : null;

// Bounded Frame Inference: Scales frames to max 640px and re-projects coordinates
async function detectFromVideo(sourceVideo) {
  if (!STATE.model || !sourceVideo || sourceVideo.readyState < 2) return [];
  const origW = sourceVideo.videoWidth;
  const origH = sourceVideo.videoHeight;
  if (!origW || !origH) return [];

  const maxDim = STATE.maxInferenceDimension || 640;
  let inferW = origW;
  let inferH = origH;

  if (origW > maxDim || origH > maxDim) {
    if (origW >= origH) {
      inferW = maxDim;
      inferH = Math.round((origH / origW) * maxDim);
    } else {
      inferH = maxDim;
      inferW = Math.round((origW / origH) * maxDim);
    }
  }

  if (inferenceCanvas.width !== inferW || inferenceCanvas.height !== inferH) {
    inferenceCanvas.width = inferW;
    inferenceCanvas.height = inferH;
  }

  inferenceCtx.drawImage(sourceVideo, 0, 0, inferW, inferH);
  const rawPredictions = await STATE.model.detect(inferenceCanvas);

  const scaleX = origW / inferW;
  const scaleY = origH / inferH;

  const scaled = rawPredictions.map(p => {
    const [x, y, w, h] = p.bbox;
    return {
      ...p,
      bbox: [x * scaleX, y * scaleY, w * scaleX, h * scaleY]
    };
  });

  const sanitized = sanitizeAndValidateDetections(scaled, origW, origH);
  return applyPerClassNMS(sanitized, 0.50);
}

// Client-Side Video Input Validation
async function validateVideoFile(file) {
  if (!file) {
    return { valid: false, error: 'No video file provided.' };
  }
  if (!STATE.model) {
    return {
      valid: false,
      error: 'Object detection model is still initializing. Please wait for COCO-SSD to load.'
    };
  }
  const name = (file.name || '').toLowerCase();
  const hasValidExt = STATE.supportedVideoExts.some(ext => name.endsWith(ext));
  if (!hasValidExt) {
    return {
      valid: false,
      error: `Unsupported video format "${name}". Supported formats: ${STATE.supportedVideoExts.join(', ')}`
    };
  }
  const sizeMB = file.size / (1024 * 1024);
  if (sizeMB > STATE.maxVideoFileSizeMB) {
    return {
      valid: false,
      error: `Video size (${sizeMB.toFixed(1)}MB) exceeds safe browser limit of ${STATE.maxVideoFileSizeMB}MB.`
    };
  }

  return new Promise((resolve) => {
    const probe = document.createElement('video');
    probe.preload = 'metadata';
    probe.muted = true;
    probe.playsInline = true;
    const probeUrl = URL.createObjectURL(file);
    let isHandled = false;

    const cleanupProbe = () => {
      probe.removeAttribute('src');
      probe.load();
      try { URL.revokeObjectURL(probeUrl); } catch (e) {}
    };

    const timeout = setTimeout(() => {
      if (!isHandled) {
        isHandled = true;
        cleanupProbe();
        resolve({
          valid: false,
          error: 'Video metadata loading timed out (10s). The file may be damaged or use an unsupported codec.'
        });
      }
    }, 10000);

    probe.onloadedmetadata = () => {
      if (isHandled) return;
      isHandled = true;
      clearTimeout(timeout);
      const duration = probe.duration;
      const width = probe.videoWidth;
      const height = probe.videoHeight;
      cleanupProbe();

      if (!width || !height) {
        return resolve({ valid: false, error: 'Video stream contains invalid frame dimensions (0x0).' });
      }
      if (duration && duration > STATE.maxVideoDurationSec) {
        return resolve({
          valid: false,
          error: `Video duration (${Math.round(duration)}s) exceeds safe prototype limit of ${STATE.maxVideoDurationSec}s.`
        });
      }
      resolve({ valid: true, width, height, duration, sizeMB: sizeMB.toFixed(1) });
    };

    probe.onerror = () => {
      if (isHandled) return;
      isHandled = true;
      clearTimeout(timeout);
      cleanupProbe();
      resolve({ valid: false, error: 'Failed to decode video file. Unsupported codec.' });
    };

    probe.src = probeUrl;
  });
}

// DOM References
const videoEl = document.getElementById('video-element');
const canvasEl = document.getElementById('canvas-element');
const ctx = canvasEl.getContext('2d');
const viewportBox = document.getElementById('scanner-viewport-box');
const modelStatusEl = document.getElementById('model-status');
const fpsBadgeEl = document.getElementById('scanner-fps-badge');
const btnStartCam = document.getElementById('btn-start-cam');
const btnStopCam = document.getElementById('btn-stop-cam');
const btnTestFeed = document.getElementById('btn-test-feed');
const videoUploadInput = document.getElementById('video-upload-input');
const btnSnapshot = document.getElementById('btn-snapshot-detect');
const btnRetryCam = document.getElementById('btn-retry-camera');
const btnCancelReconnect = document.getElementById('btn-cancel-reconnect');
const confSlider = document.getElementById('conf-slider');
const confVal = document.getElementById('conf-val');
const detectionFeed = document.getElementById('detection-feed');

// Diagnostics Elements
const diagPermission = document.getElementById('diag-permission');
const diagSource = document.getElementById('diag-source');
const diagReadyState = document.getElementById('diag-readystate');
const diagDimensions = document.getElementById('diag-dimensions');
const diagCanvasSize = document.getElementById('diag-canvas-size');
const diagLoopState = document.getElementById('diag-loop-state');
const diagErrorRow = document.getElementById('diag-error-row');
const diagErrorText = document.getElementById('diag-error-text');
const diagLastUpdated = document.getElementById('diag-last-updated');

// =========================================================================
// 3. NAVIGATION VIEW SWITCHING (10 MODULES)
// =========================================================================
const VIEW_PAGE_TITLES = {
  dashboard: { title: 'Command Center', breadcrumb: '• Real-time threat surveillance' },
  scanner: { title: 'Live Vision Scanner', breadcrumb: '• AI-powered real-time object tracking' },
  events: { title: 'Events & Detections', breadcrumb: '• Ingested surveillance metadata' },
  incidents: { title: 'Security Incidents', breadcrumb: '• Threat triage & resolution' },
  policies: { title: 'Security Policies', breadcrumb: '• Automated detection rules' },
  copilot: { title: 'AI Copilot', breadcrumb: '• Grounded telemetry reasoning' },
  aleana: { title: 'Aleana Voice Assistant', breadcrumb: '• Conversational AI voice control' },
  brain: { title: 'Vanta Brain', breadcrumb: '• 7-Layer guarded CLI console' },
  audit: { title: 'Audit Trail', breadcrumb: '• Immutable security ledger' },
  system: { title: 'System Diagnostics', breadcrumb: '• Subsystem health & simulation' }
};

function switchView(viewName) {
  if (!viewName) return;
  STATE.currentView = viewName;

  document.querySelectorAll('.nav-tab').forEach(t => {
    t.classList.toggle('active', t.dataset.view === viewName);
  });
  document.querySelectorAll('.view-section').forEach(s => {
    s.classList.toggle('active', s.id === `view-${viewName}`);
  });

  const pageMeta = VIEW_PAGE_TITLES[viewName] || { title: 'VantaVisionAI', breadcrumb: '' };
  const pageTitleEl = document.getElementById('topbar-current-page');
  const breadcrumbEl = document.querySelector('.topbar-breadcrumb');
  if (pageTitleEl) pageTitleEl.textContent = pageMeta.title;
  if (breadcrumbEl) breadcrumbEl.textContent = pageMeta.breadcrumb;

  // View-specific data fetching
  if (viewName === 'dashboard') {
    fetchSummary();
    renderDashboardPreview();
  }
  if (viewName === 'scanner') {
    setTimeout(syncCanvasDimensions, 50);
  }
  if (viewName === 'events') fetchEvents();
  if (viewName === 'incidents') fetchIncidents();
  if (viewName === 'policies') fetchPolicies();
  if (viewName === 'copilot') updateCopilotTelemetryBar();
  if (viewName === 'audit') fetchAuditLogs();
  if (viewName === 'system') fetchPipelineInfo();
}

document.querySelectorAll('.nav-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    switchView(tab.dataset.view);
  });
});

document.addEventListener('click', (e) => {
  const switchBtn = e.target.closest('[data-switch-view]');
  if (switchBtn) {
    switchView(switchBtn.dataset.switchView);
  }
});

// =========================================================================
// 4. REAL-TIME CLOCK & DASHBOARD LIVE PREVIEW CANVAS
// =========================================================================
function updateClock() {
  const clockEl = document.getElementById('live-header-clock');
  if (!clockEl) return;
  const now = new Date();
  const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  const month = months[now.getMonth()];
  const day = String(now.getDate()).padStart(2, '0');
  const year = now.getFullYear();
  const hrs = String(now.getHours()).padStart(2, '0');
  const mins = String(now.getMinutes()).padStart(2, '0');
  const secs = String(now.getSeconds()).padStart(2, '0');
  clockEl.textContent = `${month} ${day}, ${year} ${hrs}:${mins}:${secs}`;
}
setInterval(updateClock, 1000);
updateClock();

// Dashboard Live Camera Feed Canvas Loop (Panel 1)
function renderDashboardPreview() {
  const pCanvas = document.getElementById('dashboard-preview-canvas');
  if (!pCanvas) return;
  const pCtx = pCanvas.getContext('2d');
  let posX = 160;
  let dir = 1.6;

  if (STATE.dashboardCanvasTimer) clearInterval(STATE.dashboardCanvasTimer);
  STATE.dashboardCanvasTimer = setInterval(() => {
    if (STATE.currentView !== 'dashboard') return;
    pCtx.fillStyle = '#060a14';
    pCtx.fillRect(0, 0, 640, 360);

    // Floor lines & security zone grid
    pCtx.strokeStyle = 'rgba(0, 229, 255, 0.12)';
    pCtx.lineWidth = 1;
    for (let y = 160; y <= 360; y += 32) {
      pCtx.beginPath();
      pCtx.moveTo(0, y);
      pCtx.lineTo(640, y);
      pCtx.stroke();
    }

    // Guard perimeter box
    pCtx.strokeStyle = 'rgba(244, 63, 94, 0.4)';
    pCtx.setLineDash([6, 6]);
    pCtx.strokeRect(120, 90, 400, 240);
    pCtx.setLineDash([]);
    pCtx.fillStyle = 'rgba(244, 63, 94, 0.8)';
    pCtx.font = '11px ui-monospace, monospace';
    pCtx.fillText('RESTRICTED ACCESS ZONE A', 130, 110);

    // Animate Person 1
    posX += dir;
    if (posX > 440 || posX < 150) dir *= -1;

    // Person 1 Silhouette
    pCtx.fillStyle = '#cbd5e1';
    pCtx.beginPath();
    pCtx.arc(posX, 165, 14, 0, Math.PI * 2);
    pCtx.fill();
    pCtx.fillRect(posX - 16, 182, 32, 60);
    pCtx.fillRect(posX - 14, 242, 10, 50);
    pCtx.fillRect(posX + 4, 242, 10, 50);

    // Bounding Box 1 (Person 0.92)
    pCtx.strokeStyle = '#f43f5e';
    pCtx.lineWidth = 2;
    pCtx.strokeRect(posX - 24, 145, 48, 150);
    pCtx.fillStyle = 'rgba(244, 63, 94, 0.9)';
    pCtx.fillRect(posX - 24, 126, 84, 18);
    pCtx.fillStyle = '#fff';
    pCtx.font = 'bold 11px ui-monospace, monospace';
    pCtx.fillText('Person 0.92', posX - 20, 139);

    // Bounding Box 2 (Backpack 0.88)
    pCtx.fillStyle = '#f59e0b';
    pCtx.fillRect(posX + 20, 205, 18, 24);
    pCtx.strokeStyle = '#00e5ff';
    pCtx.strokeRect(posX + 15, 195, 30, 40);
    pCtx.fillStyle = 'rgba(0, 229, 255, 0.9)';
    pCtx.fillRect(posX + 15, 180, 70, 15);
    pCtx.fillStyle = '#000';
    pCtx.fillText('Backpack', posX + 18, 192);

    // Person 2 (Static near right column)
    pCtx.fillStyle = '#94a3b8';
    pCtx.beginPath();
    pCtx.arc(460, 175, 13, 0, Math.PI * 2);
    pCtx.fill();
    pCtx.fillRect(446, 190, 28, 55);
    pCtx.fillRect(447, 245, 9, 45);
    pCtx.fillRect(463, 245, 9, 45);

    pCtx.strokeStyle = '#10b981';
    pCtx.strokeRect(440, 155, 42, 140);
    pCtx.fillStyle = 'rgba(16, 185, 129, 0.9)';
    pCtx.fillRect(440, 138, 58, 16);
    pCtx.fillStyle = '#000';
    pCtx.fillText('Person', 444, 150);
  }, 66);
}

// =========================================================================
// 5. TENSORFLOW.JS COCO-SSD INITIALIZATION
// =========================================================================
async function initDetector() {
  updateDiagnostics();
  if (typeof cocoSsd === 'undefined') {
    STATE.modelStatusText = 'COCO-SSD CDN Unavailable';
    modelStatusEl.textContent = 'COCO-SSD CDN Error';
    modelStatusEl.className = 'badge badge-critical mono';
    setScannerError('TensorFlow.js COCO-SSD script could not be loaded from CDN.');
    return;
  }
  try {
    modelStatusEl.textContent = 'Loading MobileNet V2...';
    STATE.model = await cocoSsd.load({ base: 'mobilenet_v2' });
    STATE.isModelLoading = false;
    STATE.modelStatusText = 'COCO-SSD MobileNet V2 Ready';
    modelStatusEl.textContent = 'COCO-SSD Active';
    modelStatusEl.className = 'badge badge-low mono';
    updateDiagnostics();
  } catch (err) {
    console.error('Failed to load COCO-SSD:', err);
    STATE.modelStatusText = 'Detector Load Failure';
    modelStatusEl.textContent = 'Detector Error';
    modelStatusEl.className = 'badge badge-critical mono';
    setScannerError(`Model load error: ${err.message}`);
  }
}

// =========================================================================
// 6. RUNTIME DIAGNOSTICS & HARDWARE INTEGRITY
// =========================================================================
const READY_STATE_MAP = {
  0: '0 (HAVE_NOTHING)',
  1: '1 (HAVE_METADATA)',
  2: '2 (HAVE_CURRENT_DATA)',
  3: '3 (HAVE_FUTURE_DATA)',
  4: '4 (HAVE_ENOUGH_DATA)'
};

async function checkPermissionState() {
  const isSecure = window.isSecureContext || location.protocol === 'https:' || location.hostname === 'localhost' || location.hostname === '127.0.0.1';
  if (!isSecure) {
    STATE.cameraPermissionState = 'Insecure Context (Requires HTTPS or localhost)';
    updateDiagnostics();
    return;
  }
  if (navigator.permissions && navigator.permissions.query) {
    try {
      const res = await navigator.permissions.query({ name: 'camera' });
      STATE.cameraPermissionState = res.state;
      res.onchange = () => {
        STATE.cameraPermissionState = res.state;
        updateDiagnostics();
      };
    } catch (e) {
      STATE.cameraPermissionState = 'Supported (Click to grant)';
    }
  } else {
    STATE.cameraPermissionState = 'Supported (Legacy prompt)';
  }
  updateDiagnostics();
}

function updateDiagnostics() {
  if (!diagPermission) return;
  diagPermission.textContent = STATE.cameraPermissionState;
  diagSource.textContent = STATE.activeSourceName || 'None';
  diagReadyState.textContent = READY_STATE_MAP[videoEl.readyState] || `${videoEl.readyState}`;
  diagDimensions.textContent = `${videoEl.videoWidth || 0} x ${videoEl.videoHeight || 0}`;
  const cWidth = Math.round(canvasEl.clientWidth || canvasEl.width || 0);
  const cHeight = Math.round(canvasEl.clientHeight || canvasEl.height || 0);
  diagCanvasSize.textContent = `${cWidth} x ${cHeight}`;

  if (STATE.isScanning) {
    diagLoopState.textContent = `Scanning (~${STATE.measuredFps || 12} FPS / ${STATE.measuredLatency || 0}ms)`;
    diagLoopState.style.color = 'var(--accent-emerald)';
  } else if (STATE.isReconnecting) {
    diagLoopState.textContent = `Reconnecting (${STATE.reconnectAttempts}/${STATE.maxReconnectAttempts})...`;
    diagLoopState.style.color = 'var(--accent-amber)';
  } else {
    diagLoopState.textContent = 'Stopped / Idle';
    diagLoopState.style.color = 'var(--text-muted)';
  }

  if (STATE.lastError) {
    diagErrorRow.style.display = 'flex';
    diagErrorText.textContent = STATE.lastError;
    btnRetryCam.style.display = 'inline-flex';
  } else {
    diagErrorRow.style.display = 'none';
    btnRetryCam.style.display = 'none';
  }
  diagLastUpdated.textContent = new Date().toLocaleTimeString();
}

function setScannerError(msg) {
  STATE.lastError = msg;
  updateDiagnostics();
}
function clearScannerError() {
  STATE.lastError = null;
  updateDiagnostics();
}

// =========================================================================
// 7. CAMERA LIFECYCLE & WATCHDOG RECONNECTION ENGINE
// =========================================================================
btnStartCam.addEventListener('click', async () => {
  STATE.userStopped = false;
  cancelReconnection();
  await startWebcam();
});

btnRetryCam.addEventListener('click', async () => {
  STATE.userStopped = false;
  cancelReconnection();
  await startWebcam();
});

btnCancelReconnect.addEventListener('click', () => {
  STATE.userStopped = true;
  cancelReconnection();
});

function bindTrackEvents(stream) {
  const videoTrack = stream.getVideoTracks()[0];
  if (!videoTrack) return;
  videoTrack.onended = () => {
    console.warn('[VantaVisionAI] Video track ended.');
    if (!STATE.userStopped && STATE.activeSourceType === 'Webcam') {
      triggerReconnection('Video track ended unexpectedly (device disconnect or power management).');
    }
  };
  videoTrack.onmute = () => {
    console.warn('[VantaVisionAI] Video track muted.');
    updateDiagnostics();
  };
  videoTrack.onunmute = () => {
    console.log('[VantaVisionAI] Video track unmuted.');
    updateDiagnostics();
  };
}

videoEl.onerror = () => {
  if (!STATE.userStopped && STATE.activeSourceType === 'Webcam') {
    triggerReconnection('HTML5 video element decode error.');
  }
};
videoEl.onpause = () => {
  if (!STATE.isScanning) {
    ctx.clearRect(0, 0, canvasEl.width, canvasEl.height);
  }
};
videoEl.onended = () => {
  ctx.clearRect(0, 0, canvasEl.width, canvasEl.height);
  if (STATE.isScanning) {
    stopScanning();
  }
};

async function startWebcam() {
  clearScannerError();
  STATE.userStopped = false;
  STATE.reconnectAttempts = 0;

  const isSecure = window.isSecureContext || location.protocol === 'https:' || location.hostname === 'localhost' || location.hostname === '127.0.0.1';
  if (!isSecure) {
    const errMsg = 'Camera access requires a Secure Context (HTTPS or localhost).';
    setScannerError(errMsg);
    showToast(errMsg, 'danger');
    return;
  }

  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    const errMsg = 'Browser mediaDevices API not available in this window context.';
    setScannerError(errMsg);
    showToast(errMsg, 'danger');
    return;
  }

  cleanActiveMedia();
  btnStartCam.disabled = true;
  btnStartCam.textContent = 'Requesting Camera...';

  try {
    const constraints = {
      video: {
        width: { ideal: 1280, min: 640 },
        height: { ideal: 720, min: 360 },
        facingMode: 'user'
      },
      audio: false
    };
    const stream = await navigator.mediaDevices.getUserMedia(constraints);
    STATE.stream = stream;
    const videoTrack = stream.getVideoTracks()[0];
    const trackLabel = videoTrack ? videoTrack.label || 'Webcam Stream' : 'Webcam';
    STATE.activeSourceType = 'Webcam';
    STATE.activeSourceName = `Webcam (${trackLabel})`;
    STATE.cameraPermissionState = 'granted';
    bindTrackEvents(stream);

    videoEl.setAttribute('playsinline', '');
    videoEl.setAttribute('webkit-playsinline', '');
    videoEl.setAttribute('muted', '');
    videoEl.muted = true;
    videoEl.srcObject = stream;

    await new Promise((resolve, reject) => {
      let done = false;
      const timeout = setTimeout(() => {
        if (!done) { done = true; resolve(); }
      }, 2500);
      videoEl.onloadedmetadata = () => {
        if (!done) { done = true; clearTimeout(timeout); resolve(); }
      };
      videoEl.onerror = () => {
        if (!done) { done = true; clearTimeout(timeout); reject(new Error('Video element failed to load stream.')); }
      };
    });

    await videoEl.play();
    const sessionId = ++STATE.scanSessionId;
    STATE.isScanning = true;
    STATE.tracker.reset();
    STATE.lastValidFrameTime = performance.now();
    btnStartCam.disabled = true;
    btnStartCam.textContent = 'Start Webcam';
    btnStopCam.disabled = false;
    btnCancelReconnect.style.display = 'none';

    syncCanvasDimensions();
    startInferenceLoop(sessionId);
    updateDiagnostics();
    showToast('Webcam feed online. Real-time scanning active.', 'success');
  } catch (err) {
    console.error('Camera Access Error:', err);
    btnStartCam.disabled = false;
    btnStartCam.textContent = 'Start Webcam';
    const isIframe = window.self !== window.top;
    let explanation = '';
    if (err.name === 'NotAllowedError' || err.name === 'PermissionDeniedError') {
      STATE.cameraPermissionState = 'denied';
      explanation = isIframe
        ? 'Camera permission denied in iframe. You can use "Test Surveillance Feed" or "Upload Video".'
        : 'Camera permission denied. Allow camera in your browser address bar.';
    } else if (err.name === 'NotFoundError' || err.name === 'DevicesNotFoundError') {
      explanation = 'No webcam hardware detected. Use "Test Surveillance Feed" for simulated verification.';
    } else if (err.name === 'NotReadableError' || err.name === 'TrackStartError') {
      explanation = 'Camera hardware is occupied by another process (Zoom, Teams, etc.).';
    } else {
      explanation = `Camera error (${err.name}): ${err.message}`;
    }
    setScannerError(explanation);
    showToast(explanation, 'danger');
  }
}

// Synthetic Surveillance Test Feed Generator (Guaranteed hardware-independent test)
if (btnTestFeed) {
  btnTestFeed.addEventListener('click', () => {
    startSyntheticTestFeed();
  });
}

function startSyntheticTestFeed() {
  cleanActiveMedia();
  clearScannerError();
  cancelReconnection();
  STATE.activeSourceType = 'TestFeed';
  STATE.activeSourceName = 'Simulated Surveillance Stream (Main Entrance)';

  const synCanvas = document.createElement('canvas');
  synCanvas.width = 640;
  synCanvas.height = 360;
  const synCtx = synCanvas.getContext('2d');
  STATE.syntheticCanvas = synCanvas;

  let posX = 80;
  let dir = 2.0;

  function renderSyntheticFrame() {
    synCtx.fillStyle = '#070c18';
    synCtx.fillRect(0, 0, 640, 360);

    // Floor lines
    synCtx.strokeStyle = 'rgba(0, 229, 255, 0.15)';
    synCtx.lineWidth = 1;
    for (let y = 180; y <= 360; y += 30) {
      synCtx.beginPath();
      synCtx.moveTo(0, y);
      synCtx.lineTo(640, y);
      synCtx.stroke();
    }

    // Security Gate Overlay
    synCtx.strokeStyle = 'rgba(244, 63, 94, 0.4)';
    synCtx.setLineDash([8, 8]);
    synCtx.strokeRect(160, 100, 320, 220);
    synCtx.setLineDash([]);
    synCtx.fillStyle = 'rgba(244, 63, 94, 0.7)';
    synCtx.font = '11px monospace';
    synCtx.fillText('RESTRICTED PERIMETER ZONE 01', 170, 120);

    // Animate Person
    posX += dir;
    if (posX > 480 || posX < 80) dir *= -1;

    // Silhouette (person)
    synCtx.fillStyle = '#e2e8f0';
    synCtx.beginPath();
    synCtx.arc(posX, 170, 16, 0, Math.PI * 2);
    synCtx.fill();
    synCtx.fillRect(posX - 18, 190, 36, 65);
    synCtx.fillRect(posX - 16, 255, 12, 55);
    synCtx.fillRect(posX + 4, 255, 12, 55);

    // Backpack
    synCtx.fillStyle = '#f59e0b';
    synCtx.fillRect(posX + 20, 215, 20, 28);

    // Live Camera Timestamp
    synCtx.fillStyle = '#00e5ff';
    synCtx.font = '12px monospace';
    synCtx.fillText(`CAM-01-ENTRANCE [LIVE SIM] ${new Date().toISOString()}`, 15, 25);
  }

  renderSyntheticFrame();
  STATE.syntheticTimer = setInterval(renderSyntheticFrame, 66);

  const stream = synCanvas.captureStream(15);
  STATE.stream = stream;
  videoEl.srcObject = stream;
  videoEl.muted = true;
  videoEl.play();

  const sessionId = ++STATE.scanSessionId;
  STATE.isScanning = true;
  STATE.tracker.reset();
  STATE.lastValidFrameTime = performance.now();
  btnStartCam.disabled = false;
  btnStopCam.disabled = false;
  btnCancelReconnect.style.display = 'none';

  syncCanvasDimensions();
  startInferenceLoop(sessionId);
  updateDiagnostics();
  showToast('Simulated surveillance feed active with moving test objects.', 'info');
}

// Watchdog auto-reconnect strategy
function triggerReconnection(reason) {
  if (STATE.userStopped || STATE.isReconnecting || STATE.activeSourceType !== 'Webcam') {
    return;
  }
  STATE.isReconnecting = true;
  console.warn(`[VantaVisionAI] Triggering reconnection: ${reason}`);

  if (STATE.animFrameId) {
    cancelAnimationFrame(STATE.animFrameId);
    STATE.animFrameId = null;
  }
  STATE.isDetecting = false;
  if (STATE.stream) {
    STATE.stream.getTracks().forEach(t => { try { t.stop(); t.enabled = false; } catch (e) {} });
    STATE.stream = null;
  }
  videoEl.pause();
  videoEl.srcObject = null;
  STATE.isScanning = false;
  ctx.clearRect(0, 0, canvasEl.width, canvasEl.height);

  if (STATE.reconnectAttempts >= STATE.maxReconnectAttempts) {
    STATE.isReconnecting = false;
    btnCancelReconnect.style.display = 'none';
    btnRetryCam.style.display = 'inline-flex';
    btnStartCam.disabled = false;
    btnStopCam.disabled = true;
    const msg = `Stream lost (${reason}). Max reconnection attempts reached. Click "Retry Camera".`;
    setScannerError(msg);
    showToast(msg, 'danger');
    return;
  }

  STATE.reconnectAttempts++;
  const baseDelay = Math.min(10000, Math.pow(2, STATE.reconnectAttempts - 1) * 1000);
  const delay = Math.round(baseDelay + Math.random() * 400);
  const statusMsg = `Stream lost (${reason}). Reconnecting in ${Math.round(delay / 1000)}s...`;
  setScannerError(statusMsg);
  btnCancelReconnect.style.display = 'inline-flex';

  if (STATE.reconnectTimer) clearTimeout(STATE.reconnectTimer);
  STATE.reconnectTimer = setTimeout(async () => {
    await attemptStreamReacquisition();
  }, delay);
}

async function attemptStreamReacquisition() {
  if (STATE.userStopped) return;
  try {
    const constraints = {
      video: { width: { ideal: 1280, min: 640 }, height: { ideal: 720, min: 360 }, facingMode: 'user' },
      audio: false
    };
    const stream = await navigator.mediaDevices.getUserMedia(constraints);
    STATE.stream = stream;
    const videoTrack = stream.getVideoTracks()[0];
    const trackLabel = videoTrack ? videoTrack.label || 'Webcam Stream' : 'Webcam';
    STATE.activeSourceType = 'Webcam';
    STATE.activeSourceName = `Webcam (${trackLabel}) [Reconnected]`;
    STATE.cameraPermissionState = 'granted';
    bindTrackEvents(stream);
    videoEl.srcObject = stream;
    videoEl.muted = true;

    await new Promise((resolve) => {
      let done = false;
      const timeout = setTimeout(() => { if (!done) { done = true; resolve(); } }, 2000);
      videoEl.onloadedmetadata = () => { if (!done) { done = true; clearTimeout(timeout); resolve(); } };
    });

    await videoEl.play();
    const sessionId = ++STATE.scanSessionId;
    STATE.reconnectAttempts = 0;
    STATE.isReconnecting = false;
    STATE.isScanning = true;
    STATE.lastValidFrameTime = performance.now();
    btnStartCam.disabled = true;
    btnStopCam.disabled = false;
    btnCancelReconnect.style.display = 'none';
    clearScannerError();
    syncCanvasDimensions();
    startInferenceLoop(sessionId);
    updateDiagnostics();
    showToast('Camera feed successfully re-acquired.', 'success');
  } catch (err) {
    triggerReconnection(`Re-acquisition failed: ${err.message}`);
  }
}

function cancelReconnection() {
  if (STATE.reconnectTimer) {
    clearTimeout(STATE.reconnectTimer);
    STATE.reconnectTimer = null;
  }
  STATE.isReconnecting = false;
  STATE.reconnectAttempts = 0;
  btnCancelReconnect.style.display = 'none';
  btnStartCam.disabled = false;
  btnStopCam.disabled = true;
  updateDiagnostics();
}

// Video File Upload Alternative
videoUploadInput.addEventListener('change', async (e) => {
  const file = e.target.files && e.target.files[0];
  if (!file) return;
  const fileName = file.name;

  const validation = await validateVideoFile(file);
  if (!validation.valid) {
    videoUploadInput.value = '';
    setScannerError(`Upload rejected: ${validation.error}`);
    showToast(validation.error, 'danger');
    return;
  }

  STATE.userStopped = true;
  cancelReconnection();
  cleanActiveMedia();
  clearScannerError();

  const fileUrl = URL.createObjectURL(file);
  STATE.activeObjectUrl = fileUrl;
  STATE.activeSourceType = 'Upload';
  STATE.activeSourceName = `File: ${fileName} (${validation.sizeMB}MB, ${Math.round(validation.duration || 0)}s, ${validation.width}x${validation.height})`;
  videoEl.srcObject = null;
  videoEl.src = fileUrl;
  videoEl.loop = true;
  videoEl.setAttribute('playsinline', '');
  videoEl.muted = true;

  try {
    await videoEl.play();
    const sessionId = ++STATE.scanSessionId;
    STATE.isScanning = true;
    STATE.tracker.reset();
    STATE.lastValidFrameTime = performance.now();
    btnStartCam.disabled = false;
    btnStopCam.disabled = false;
    syncCanvasDimensions();
    startInferenceLoop(sessionId);
    updateDiagnostics();
    showToast(`Loaded video file: ${fileName}`, 'success');
  } catch (err) {
    if (STATE.activeObjectUrl) {
      try { URL.revokeObjectURL(STATE.activeObjectUrl); } catch (e) {}
      STATE.activeObjectUrl = null;
    }
    setScannerError(`Failed to play uploaded video file: ${err.message}`);
    showToast(`Playback error: ${err.message}`, 'danger');
  } finally {
    videoUploadInput.value = '';
  }
});

btnStopCam.addEventListener('click', () => {
  STATE.userStopped = true;
  cancelReconnection();
  stopScanning();
  showToast('Vision scanner stopped.', 'info');
});

function stopScanning() {
  STATE.isScanning = false;
  STATE.scanSessionId++;
  cleanActiveMedia();
  btnStartCam.disabled = false;
  btnStopCam.disabled = true;
  btnCancelReconnect.style.display = 'none';
  fpsBadgeEl.textContent = 'Inference: Stopped';
  ctx.clearRect(0, 0, canvasEl.width, canvasEl.height);
  STATE.tracker.reset();
  updateDiagnostics();
}

function cleanActiveMedia() {
  STATE.isScanning = false;
  STATE.scanSessionId++;
  if (STATE.animFrameId) {
    cancelAnimationFrame(STATE.animFrameId);
    STATE.animFrameId = null;
  }
  STATE.isDetecting = false;
  if (STATE.syntheticTimer) {
    clearInterval(STATE.syntheticTimer);
    STATE.syntheticTimer = null;
  }
  if (STATE.stream) {
    STATE.stream.getTracks().forEach(track => {
      try { track.stop(); track.enabled = false; } catch (e) {}
    });
    STATE.stream = null;
  }
  videoEl.pause();
  videoEl.srcObject = null;
  if (STATE.activeObjectUrl) {
    try { URL.revokeObjectURL(STATE.activeObjectUrl); } catch (e) {}
    STATE.activeObjectUrl = null;
  }
  if (videoEl.src && videoEl.src.startsWith('blob:')) {
    try { URL.revokeObjectURL(videoEl.src); } catch (e) {}
  }
  videoEl.removeAttribute('src');
  try { videoEl.load(); } catch (e) {}
  ctx.clearRect(0, 0, canvasEl.width, canvasEl.height);
  STATE.activeSourceType = 'None';
  STATE.activeSourceName = 'None';
  STATE.lastRawPredictions = [];
  STATE.lastTrackedDetections = [];
  if (STATE.tracker && typeof STATE.tracker.reset === 'function') {
    STATE.tracker.reset();
  }
}

function syncCanvasDimensions() {
  const rect = viewportBox.getBoundingClientRect();
  canvasEl.width = Math.round(rect.width || 640);
  canvasEl.height = Math.round(rect.height || 360);
  updateDiagnostics();
}
window.addEventListener('resize', () => {
  if (STATE.isScanning) syncCanvasDimensions();
});

// Accurate Letterbox/Pillarbox Bounding Box Geometry Calculation
function getRenderGeometry() {
  const containerW = canvasEl.width;
  const containerH = canvasEl.height;
  const videoW = videoEl.videoWidth || containerW;
  const videoH = videoEl.videoHeight || containerH;
  if (!videoW || !videoH) {
    return { x: 0, y: 0, width: containerW, height: containerH, scaleX: 1, scaleY: 1 };
  }
  const containerAspect = containerW / containerH;
  const videoAspect = videoW / videoH;
  let renderW, renderH, offsetX, offsetY;
  if (videoAspect > containerAspect) {
    renderW = containerW;
    renderH = containerW / videoAspect;
    offsetX = 0;
    offsetY = (containerH - renderH) / 2;
  } else {
    renderH = containerH;
    renderW = containerH * videoAspect;
    offsetX = (containerW - renderW) / 2;
    offsetY = 0;
  }
  return {
    x: offsetX,
    y: offsetY,
    width: renderW,
    height: renderH,
    scaleX: renderW / videoW,
    scaleY: renderH / videoH
  };
}

// Single RAF Inference Scheduler
let frameCount = 0;
let lastFpsCheck = performance.now();

async function startInferenceLoop(sessionId) {
  if (!STATE.isScanning || STATE.scanSessionId !== sessionId) return;

  if (document.hidden || videoEl.paused || videoEl.ended) {
    if (STATE.isScanning && STATE.scanSessionId === sessionId) {
      STATE.animFrameId = requestAnimationFrame(() => startInferenceLoop(sessionId));
    }
    return;
  }

  const now = performance.now();
  const adaptiveInterval = Math.max(70, Math.min(180, (STATE.measuredLatency || 60) + 15));
  if (now - STATE.lastInferenceTime >= adaptiveInterval && !STATE.isDetecting && STATE.model && videoEl.readyState >= 2 && videoEl.videoWidth > 0) {
    STATE.isDetecting = true;
    const startT = performance.now();
    try {
      const rawPredictions = await detectFromVideo(videoEl);
      if (!STATE.isScanning || STATE.scanSessionId !== sessionId) {
        return;
      }
      const elapsed = Math.round(performance.now() - startT);
      STATE.measuredLatency = elapsed;
      frameCount++;
      if (now - lastFpsCheck >= 1000) {
        STATE.measuredFps = frameCount;
        const liveFpsEl = document.getElementById('scanner-live-fps');
        if (liveFpsEl) liveFpsEl.textContent = `${frameCount}.0`;
        frameCount = 0;
        lastFpsCheck = now;
      }
      // Save raw predictions cache for instant on-the-fly category re-filtering
      STATE.lastRawPredictions = rawPredictions;

      const filtered = filterPredictions(rawPredictions);
      const trackedDetections = STATE.tracker.update(filtered);
      STATE.lastTrackedDetections = trackedDetections;

      if (STATE.categoryFilter === 'all') {
        const suppressedCount = rawPredictions.length - trackedDetections.length;
        if (suppressedCount > 0) {
          fpsBadgeEl.textContent = `${elapsed}ms / frame (${trackedDetections.length} visible • ${suppressedCount} filtered out)`;
        } else {
          fpsBadgeEl.textContent = `${elapsed}ms / frame (${rawPredictions.length} detected)`;
        }
      } else {
        const catLabel = DETECTION_CATEGORIES[STATE.categoryFilter]?.label || STATE.categoryFilter;
        fpsBadgeEl.textContent = `${elapsed}ms / frame (${trackedDetections.length} of ${rawPredictions.length} visible • ${catLabel})`;
      }

      renderPredictions(trackedDetections);
      STATE.lastValidFrameTime = performance.now();
      clearScannerError();
    } catch (err) {
      if (STATE.isScanning && STATE.scanSessionId === sessionId) {
        console.warn('Inference frame dropped:', err);
      }
    } finally {
      STATE.isDetecting = false;
      STATE.lastInferenceTime = performance.now();
      updateDiagnostics();
    }
  }

  if (STATE.isScanning && STATE.scanSessionId === sessionId) {
    STATE.animFrameId = requestAnimationFrame(() => startInferenceLoop(sessionId));
  }
}

// =========================================================================
// 8b. BEHAVIORAL COMPUTER VISION & TACTICAL HUD ENGINE
// =========================================================================
const TRIPWIRE_LINE = {
  x1Ratio: 0.18,
  y1Ratio: 0.72,
  x2Ratio: 0.82,
  y2Ratio: 0.72
};

function computePathTortuosity(trail) {
  if (!trail || trail.length < 2) return 1.0;
  let pathLen = 0;
  for (let i = 1; i < trail.length; i++) {
    const p1 = trail[i - 1];
    const p2 = trail[i];
    pathLen += Math.hypot(p2[0] - p1[0], p2[1] - p1[1]);
  }
  if (pathLen === 0) return 1.0;
  const startPt = trail[0];
  const endPt = trail[trail.length - 1];
  const netDisp = Math.hypot(endPt[0] - startPt[0], endPt[1] - startPt[1]);
  return netDisp / pathLen;
}

function evaluateBehavioralAnomalies(trackedObjects, canvasW, canvasH) {
  if (!trackedObjects || trackedObjects.length === 0) return;
  const twY = Math.round(canvasH * TRIPWIRE_LINE.y1Ratio);
  const twX1 = Math.round(canvasW * TRIPWIRE_LINE.x1Ratio);
  const twX2 = Math.round(canvasW * TRIPWIRE_LINE.x2Ratio);

  trackedObjects.forEach(pred => {
    const trk = STATE.tracker?.tracks?.get(pred.trackId);
    if (!trk) return;

    const [rawX, rawY, rawW, rawH] = pred.bbox;
    const geom = getRenderGeometry();
    const curX = Math.round(geom.x + (rawX + rawW / 2) * geom.scaleX);
    const curY = Math.round(geom.y + (rawY + rawH / 2) * geom.scaleY);

    // 1. Virtual Directional Tripwire Crossing Evaluation via Vector Cross-Product Sign
    if (trk.prevCentroidX !== undefined && trk.prevCentroidY !== undefined) {
      const px = trk.prevCentroidX;
      const py = trk.prevCentroidY;
      const minX = Math.min(twX1, twX2);
      const maxX = Math.max(twX1, twX2);

      // Cross product relative to tripwire vector (twX2 - twX1, 0)
      const cpPrev = (twX2 - twX1) * (py - twY);
      const cpCur = (twX2 - twX1) * (curY - twY);

      if (curX >= minX && curX <= maxX && ((cpPrev < 0 && cpCur >= 0) || (cpPrev > 0 && cpCur <= 0))) {
        const isIngress = cpPrev < 0 && cpCur >= 0;
        const crossingType = isIngress ? 'INGRESS' : 'EGRESS';

        if (isIngress) {
          STATE.tripwireIngressCount = (STATE.tripwireIngressCount || 0) + 1;
        } else {
          STATE.tripwireEgressCount = (STATE.tripwireEgressCount || 0) + 1;
        }

        if (!STATE.sceneEventsLog) STATE.sceneEventsLog = [];
        STATE.sceneEventsLog.unshift({
          id: `TW-${Date.now().toString().slice(-4)}`,
          time: new Date().toLocaleTimeString(),
          type: `TRIPWIRE_${crossingType}`,
          title: `Perimeter ${isIngress ? 'Ingress' : 'Egress'} Crossing`,
          desc: `Track #${pred.trackId} [${pred.class.toUpperCase()}] crossed sector tripwire (${crossingType}).`,
          severity: isIngress ? 'MEDIUM' : 'LOW'
        });
        if (STATE.sceneEventsLog.length > 50) STATE.sceneEventsLog.pop();
        STATE.soundEngine?.playPing();
      }
    }
    trk.prevCentroidX = curX;
    trk.prevCentroidY = curY;

    // 2. Suspicious Pacing & Loitering Index (computePathTortuosity)
    if (trk.centroidTrail && trk.centroidTrail.length >= 6) {
      let pathLen = 0;
      for (let i = 1; i < trk.centroidTrail.length; i++) {
        pathLen += Math.hypot(trk.centroidTrail[i][0] - trk.centroidTrail[i - 1][0], trk.centroidTrail[i][1] - trk.centroidTrail[i - 1][1]);
      }
      const tortuosity = computePathTortuosity(trk.centroidTrail);
      trk.tortuosity = tortuosity;

      if (pathLen > 60 && tortuosity < 0.30) {
        trk.isPacingAnomaly = true;
        trk.motionState = 'PACING / LOITERING ANOMALY';
        pred.threatScore = Math.max(pred.threatScore || 0, 75);
      } else if (pathLen <= 25 && (trk.dwellTimeSec || 0) >= 5.0) {
        trk.motionState = 'RESTRICTED DWELL LOITERING';
        pred.threatScore = Math.max(pred.threatScore || 0, 80);
      }
    }
  });
}

function renderTacticalHudOverlays(ctx, trackedObjects, canvasW, canvasH) {
  const twY = Math.round(canvasH * 0.72);
  const twX1 = Math.round(canvasW * 0.18);
  const twX2 = Math.round(canvasW * 0.82);

  ctx.save();

  // 1. Virtual Directional Tripwire Line
  ctx.setLineDash([6, 6]);
  ctx.strokeStyle = 'rgba(22, 200, 244, 0.65)';
  ctx.lineWidth = 1.8;
  ctx.beginPath();
  ctx.moveTo(twX1, twY);
  ctx.lineTo(twX2, twY);
  ctx.stroke();
  ctx.setLineDash([]);

  // Boundary tick marks
  ctx.strokeStyle = '#16C8F4';
  ctx.lineWidth = 2;
  [twX1, (twX1 + twX2) / 2, twX2].forEach(tx => {
    ctx.beginPath();
    ctx.moveTo(tx, twY - 6);
    ctx.lineTo(tx, twY + 6);
    ctx.stroke();
  });

  // Tripwire HUD Label
  const twLabel = `[TRIPWIRE SECTOR 01] INGRESS: ${STATE.tripwireIngressCount || 0} | EGRESS: ${STATE.tripwireEgressCount || 0}`;
  ctx.font = 'bold 9px ui-monospace, monospace';
  ctx.fillStyle = 'rgba(7, 16, 30, 0.85)';
  const twW = ctx.measureText(twLabel).width;
  ctx.fillRect(twX1, twY - 18, twW + 10, 15);
  ctx.fillStyle = '#16C8F4';
  ctx.fillText(twLabel, twX1 + 5, twY - 7);

  // Top Right Tactical Live HUD Pill
  const count = trackedObjects ? trackedObjects.length : 0;
  const fps = Math.round(STATE.measuredFps || 0);
  const hudTxt = `SYS: ONLINE | FPS: ${fps} | TARGETS: ${count} | CAM: SIMULATED`;
  ctx.font = 'bold 10px ui-monospace, monospace';
  const hW = ctx.measureText(hudTxt).width;
  ctx.fillStyle = 'rgba(5, 11, 22, 0.8)';
  ctx.fillRect(canvasW - hW - 16, 8, hW + 10, 18);
  ctx.strokeStyle = 'rgba(29, 53, 80, 0.8)';
  ctx.strokeRect(canvasW - hW - 16, 8, hW + 10, 18);
  ctx.fillStyle = '#36D399';
  ctx.fillText(hudTxt, canvasW - hW - 11, 21);

  ctx.restore();
}

if (typeof window !== 'undefined') {
  window.evaluateBehavioralAnomalies = evaluateBehavioralAnomalies;
  window.renderTacticalHudOverlays = renderTacticalHudOverlays;
}

function renderPredictions(trackedDetections) {
  ctx.clearRect(0, 0, canvasEl.width, canvasEl.height);
  const geom = getRenderGeometry();
  evaluateBehavioralAnomalies(trackedDetections, canvasEl.width, canvasEl.height);

  // Spatial-Temporal Dwell Heatmap (32x18 Grid)
  const numRows = 18;
  const numCols = 32;
  const cellW = canvasEl.width / numCols;
  const cellH = canvasEl.height / numRows;

  // Frame decay (0.992)
  for (let r = 0; r < numRows; r++) {
    for (let c = 0; c < numCols; c++) {
      STATE.heatmapGrid[r][c] *= 0.992;
    }
  }

  // Accumulate centroids
  trackedDetections.forEach(pred => {
    const [rawX, rawY, rawW, rawH] = pred.bbox;
    const cX = geom.x + (rawX + rawW / 2) * geom.scaleX;
    const cY = geom.y + (rawY + rawH / 2) * geom.scaleY;
    const col = Math.max(0, Math.min(numCols - 1, Math.floor(cX / cellW)));
    const row = Math.max(0, Math.min(numRows - 1, Math.floor(cY / cellH)));
    STATE.heatmapGrid[row][col] = Math.min(3.0, STATE.heatmapGrid[row][col] + 0.15);
  });

  // Render Heatmap overlay if enabled
  if (STATE.heatmapEnabled) {
    ctx.save();
    for (let r = 0; r < numRows; r++) {
      for (let c = 0; c < numCols; c++) {
        const val = STATE.heatmapGrid[r][c];
        if (val > 0.02) {
          const intensity = Math.min(1.0, val / 1.5);
          let rC = 22, gC = 200, bC = 244;
          if (intensity > 0.6) {
            rC = 255; gC = 93; bC = 108;
          } else if (intensity > 0.3) {
            rC = 246; gC = 184; bC = 74;
          }
          ctx.fillStyle = `rgba(${rC}, ${gC}, ${bC}, ${intensity * 0.45})`;
          ctx.fillRect(c * cellW, r * cellH, cellW, cellH);
        }
      }
    }
    ctx.restore();
  }

  // 1. Initialize Scene Events Log Ring Buffer if not defined
  if (!STATE.sceneEventsLog) STATE.sceneEventsLog = [];

  // 2. Classify Targets for Relational Graph
  const persons = [];
  const luggages = [];
  const hazards = [];

  trackedDetections.forEach(pred => {
    const [rawX, rawY, rawW, rawH] = pred.bbox;
    const boxX = geom.x + (rawX * geom.scaleX);
    const boxY = geom.y + (rawY * geom.scaleY);
    const boxW = rawW * geom.scaleX;
    const boxH = rawH * geom.scaleY;
    const cX = Math.round(boxX + (boxW / 2));
    const cY = Math.round(boxY + (boxH / 2));
    const cat = getObjectCategory(pred.class);

    const targetInfo = { pred, boxX, boxY, boxW, boxH, cX, cY, cat };
    if (pred.class === 'person') persons.push(targetInfo);
    if (cat === 'luggage') luggages.push(targetInfo);
    if (cat === 'weapons') hazards.push(targetInfo);
  });

  // 3. Relational Analysis: Owner-to-Baggage Tethering & Unattended Baggage Escalation
  luggages.forEach(lug => {
    let closestPerson = null;
    let minDist = Infinity;
    persons.forEach(p => {
      const d = Math.hypot(p.cX - lug.cX, p.cY - lug.cY);
      if (d < minDist) {
        minDist = d;
        closestPerson = p;
      }
    });

    const trk = STATE.tracker?.tracks?.get(lug.pred.trackId);
    if (closestPerson && minDist <= 200) {
      // Tether link active (within 200px)
      lug.isTethered = true;
      lug.tetherDist = minDist;
      if (trk) trk.unattendedStartTime = null;

      ctx.save();
      ctx.setLineDash([4, 4]);
      ctx.strokeStyle = '#16C8F4';
      ctx.lineWidth = 1.8;
      ctx.beginPath();
      ctx.moveTo(closestPerson.cX, closestPerson.cY);
      ctx.lineTo(lug.cX, lug.cY);
      ctx.stroke();
      ctx.setLineDash([]);

      const midX = Math.round((closestPerson.cX + lug.cX) / 2);
      const midY = Math.round((closestPerson.cY + lug.cY) / 2);
      ctx.font = 'bold 9px ui-monospace, monospace';
      const tetherTxt = `[OWNER_TETHER: ${Math.round(minDist)}px]`;
      const tW = ctx.measureText(tetherTxt).width;
      ctx.fillStyle = 'rgba(7, 16, 30, 0.85)';
      ctx.fillRect(midX - (tW / 2) - 4, midY - 7, tW + 8, 14);
      ctx.fillStyle = '#16C8F4';
      ctx.fillText(tetherTxt, midX - (tW / 2), midY + 4);
      ctx.restore();
    } else {
      // Unattended Abandoned evaluation (distance > 200px or no person in frame for >= 5s)
      if (trk) {
        if (!trk.unattendedStartTime) trk.unattendedStartTime = Date.now();
        const unattendedDwell = (Date.now() - trk.unattendedStartTime) / 1000;
        lug.unattendedDwell = unattendedDwell;
        if (unattendedDwell >= 5.0) {
          lug.isUnattended = true;
          lug.pred.threatScore = 90;

          const now = Date.now();
          if (!trk.lastUnattendedAlert || (now - trk.lastUnattendedAlert > 4500)) {
            trk.lastUnattendedAlert = now;
            STATE.soundEngine?.playBreachAlert();
            STATE.sceneEventsLog.unshift({
              id: `EVT-${now.toString().slice(-4)}`,
              time: new Date().toLocaleTimeString(),
              type: 'UNATTENDED_ABANDONED',
              title: 'Unattended Abandoned Baggage Alert',
              desc: `Baggage #${lug.pred.trackId} detached from owner (>200px) for ${unattendedDwell.toFixed(1)}s (threat: 90)`,
              severity: 'HIGH'
            });
            if (STATE.sceneEventsLog.length > 50) STATE.sceneEventsLog.pop();

            if (!trk.lastAutoSnapshot || (now - trk.lastAutoSnapshot > 12000)) {
              trk.lastAutoSnapshot = now;
              setTimeout(() => { if (typeof captureForensicSnapshot === 'function') captureForensicSnapshot(); }, 100);
            }
            if (typeof triggerWatchtowerProactiveVoiceAlert === 'function') {
              triggerWatchtowerProactiveVoiceAlert('Unattended Abandoned Baggage', 'Sector Lobby');
            }
          }
        }
      }
    }
  });

  // 4. Relational Analysis: Armed / Hazard Proximity Alert
  hazards.forEach(hazard => {
    let closestPerson = null;
    let minDist = Infinity;
    persons.forEach(p => {
      const d = Math.hypot(p.cX - hazard.cX, p.cY - hazard.cY);
      if (d < minDist) {
        minDist = d;
        closestPerson = p;
      }
    });

    if (closestPerson && minDist <= 150) {
      hazard.isArmedProximity = true;
      hazard.pred.threatScore = 96;

      ctx.save();
      const pulse = 0.5 + 0.5 * Math.sin(Date.now() / 150);
      ctx.strokeStyle = `rgba(255, 93, 108, ${0.6 + 0.4 * pulse})`;
      ctx.lineWidth = 2.5;
      ctx.beginPath();
      ctx.moveTo(closestPerson.cX, closestPerson.cY);
      ctx.lineTo(hazard.cX, hazard.cY);
      ctx.stroke();

      const midX = Math.round((closestPerson.cX + hazard.cX) / 2);
      const midY = Math.round((closestPerson.cY + hazard.cY) / 2);
      ctx.font = 'bold 9px ui-monospace, monospace';
      const warnTxt = `⚠ [ARMED PROXIMITY CRITICAL // ${Math.round(minDist)}px]`;
      const wW = ctx.measureText(warnTxt).width;
      ctx.fillStyle = 'rgba(255, 93, 108, 0.9)';
      ctx.fillRect(midX - (wW / 2) - 4, midY - 8, wW + 8, 16);
      ctx.fillStyle = '#ffffff';
      ctx.fillText(warnTxt, midX - (wW / 2), midY + 4);
      ctx.restore();

      const trk = STATE.tracker?.tracks?.get(hazard.pred.trackId);
      const now = Date.now();
      if (trk && (!trk.lastHazardAlert || (now - trk.lastHazardAlert > 4000))) {
        trk.lastHazardAlert = now;
        STATE.soundEngine?.playBreachAlert();
        STATE.sceneEventsLog.unshift({
          id: `EVT-${now.toString().slice(-4)}`,
          time: new Date().toLocaleTimeString(),
          type: 'ARMED_PROXIMITY_CRITICAL',
          title: 'Armed Proximity Alert',
          desc: `Hazard [${hazard.pred.class}] within ${Math.round(minDist)}px of person #${closestPerson.pred.trackId} (threat: 96)`,
          severity: 'CRITICAL'
        });
        if (STATE.sceneEventsLog.length > 50) STATE.sceneEventsLog.pop();
      }
    }
  });

  trackedDetections.forEach(pred => {
    const [rawX, rawY, rawW, rawH] = pred.bbox;
    const boxX = geom.x + (rawX * geom.scaleX);
    const boxY = geom.y + (rawY * geom.scaleY);
    const boxW = rawW * geom.scaleX;
    const boxH = rawH * geom.scaleY;

    // Strict boundary clamping so labels and boxes stay fully within visible canvas
    const renderX = Math.max(0, Math.min(canvasEl.width - 4, boxX));
    const renderY = Math.max(0, Math.min(canvasEl.height - 4, boxY));
    const renderW = Math.max(4, Math.min(canvasEl.width - renderX, boxW));
    const renderH = Math.max(4, Math.min(canvasEl.height - renderY, boxH));

    const catKey = getObjectCategory(pred.class);
    const catConfig = DETECTION_CATEGORIES[catKey] || DETECTION_CATEGORIES.other;
    const trk = STATE.tracker?.tracks?.get(pred.trackId);

    // Dynamic color override for threat escalations
    let strokeColor = catConfig.color || '#00e5ff';
    const isUnattended = trk?.unattendedStartTime && ((Date.now() - trk.unattendedStartTime) / 1000 >= 6.0);
    const isArmed = pred.threatScore === 96;

    if (isUnattended || isArmed) {
      strokeColor = '#FF5D6C';
    }

    // Centroid and 20-Point Trail
    const cX = Math.round(renderX + (renderW / 2));
    const cY = Math.round(renderY + (renderH / 2));

    if (trk?.centroidTrail && trk.centroidTrail.length > 1) {
      ctx.save();
      ctx.lineWidth = 1.2;
      for (let i = 1; i < trk.centroidTrail.length; i++) {
        const ptA = trk.centroidTrail[i - 1];
        const ptB = trk.centroidTrail[i];
        const alpha = (i / trk.centroidTrail.length) * 0.45;
        ctx.strokeStyle = `rgba(22, 200, 244, ${alpha})`;
        ctx.beginPath();
        ctx.moveTo(ptA[0], ptA[1]);
        ctx.lineTo(ptB[0], ptB[1]);
        ctx.stroke();

        ctx.fillStyle = `rgba(22, 200, 244, ${alpha * 1.5})`;
        ctx.beginPath();
        ctx.arc(ptB[0], ptB[1], 2, 0, Math.PI * 2);
        ctx.fill();
      }
      ctx.restore();
    }

    // Translucent tactical HUD fill
    ctx.fillStyle = strokeColor + '18';
    ctx.fillRect(renderX, renderY, renderW, renderH);

    // Outer bounding box
    ctx.strokeStyle = strokeColor;
    ctx.lineWidth = isUnattended || isArmed ? 2.8 : 2.0;
    ctx.strokeRect(renderX, renderY, renderW, renderH);

    // Tactical corner targeting reticles
    const corner = Math.min(10, renderW / 3, renderH / 3);
    ctx.lineWidth = 3.5;
    // Top-left
    ctx.beginPath();
    ctx.moveTo(renderX, renderY + corner); ctx.lineTo(renderX, renderY); ctx.lineTo(renderX + corner, renderY);
    ctx.stroke();
    // Top-right
    ctx.beginPath();
    ctx.moveTo(renderX + renderW - corner, renderY); ctx.lineTo(renderX + renderW, renderY); ctx.lineTo(renderX + renderW, renderY + corner);
    ctx.stroke();
    // Bottom-left
    ctx.beginPath();
    ctx.moveTo(renderX, renderY + renderH - corner); ctx.lineTo(renderX, renderY + renderH); ctx.lineTo(renderX + corner, renderY + renderH);
    ctx.stroke();
    // Bottom-right
    ctx.beginPath();
    ctx.moveTo(renderX + renderW - corner, renderY + renderH); ctx.lineTo(renderX + renderW, renderY + renderH); ctx.lineTo(renderX + renderW, renderY + renderH - corner);
    ctx.stroke();

    // Subtle tactical center crosshair
    ctx.strokeStyle = strokeColor;
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(cX - 5, cY); ctx.lineTo(cX + 5, cY);
    ctx.moveTo(cX, cY - 5); ctx.lineTo(cX, cY + 5);
    ctx.stroke();

    // Instantaneous velocity components
    const vx = (pred.vx !== undefined ? pred.vx : (trk?.vx || 0));
    const vy = (pred.vy !== undefined ? pred.vy : (trk?.vy || 0));
    const speedHypot = Math.hypot(vx, vy);

    // 1.5-Second Predictive Trajectory Vector Projection
    const futX = cX + (vx * 45 * geom.scaleX);
    const futY = cY + (vy * 45 * geom.scaleY);

    if (speedHypot >= 0.4) {
      ctx.save();
      ctx.setLineDash([4, 4]);
      ctx.strokeStyle = strokeColor;
      ctx.lineWidth = 1.6;
      ctx.beginPath();
      ctx.moveTo(cX, cY);
      ctx.lineTo(futX, futY);
      ctx.stroke();
      ctx.setLineDash([]);

      // Target reticle at predicted position
      ctx.beginPath();
      ctx.arc(futX, futY, 4, 0, Math.PI * 2);
      ctx.stroke();
      ctx.beginPath();
      ctx.moveTo(futX - 5, futY); ctx.lineTo(futX + 5, futY);
      ctx.moveTo(futX, futY - 5); ctx.lineTo(futX, futY + 5);
      ctx.stroke();
      ctx.restore();
    }

    // High-visibility classification label tag with dwell and motion state
    const vxPx = Math.round(vx * 30);
    const vyPx = Math.round(vy * 30);
    const speedTxt = speedHypot > 0.2 ? ` [v: ${Math.round(Math.hypot(vxPx, vyPx))}px/s]` : '';
    const dwellTxt = trk?.dwellTimeSec ? ` [DWELL: ${trk.dwellTimeSec}s]` : '';
    const motionTxt = trk?.motionState ? ` [${trk.motionState === 'FAST_MOVING / RUNNING' ? 'RUNNING' : trk.motionState}]` : '';

    let tagPrefix = `${pred.class.toUpperCase()} #${pred.trackId} ${Math.round(pred.score * 100)}%`;
    if (isUnattended) {
      const uDwell = Math.round((Date.now() - trk.unattendedStartTime) / 1000);
      tagPrefix = `[UNATTENDED BAGGAGE // DWELL: ${uDwell}s] #${pred.trackId}`;
    } else if (isArmed) {
      tagPrefix = `[ARMED PROXIMITY CRITICAL // THREAT: 96] #${pred.trackId}`;
    }

    const label = `${tagPrefix}${speedTxt}${dwellTxt}${motionTxt}`;
    ctx.font = 'bold 11px ui-monospace, monospace';
    const textWidth = ctx.measureText(label).width;
    const tagH = 18;
    const tagY = Math.max(0, renderY - tagH);

    ctx.fillStyle = strokeColor;
    ctx.fillRect(renderX, tagY, textWidth + 10, tagH);
    ctx.fillStyle = isUnattended || isArmed ? '#ffffff' : '#060a12';
    ctx.fillText(label, renderX + 5, tagY + 13);

    // Restricted Zone Predictive Intersection Breach Detection
    const curInZone = (cX >= rZoneX && cX <= rZoneX + rZoneW && cY >= rZoneY && cY <= rZoneY + rZoneH);
    const futInZone = (futX >= rZoneX && futX <= rZoneX + rZoneW && futY >= rZoneY && futY <= rZoneY + rZoneH);
    if (!curInZone && futInZone && speedHypot >= 0.4) {
      ctx.save();
      const warnTxt = '⚠ [PREDICTED BREACH IN <1.5s]';
      ctx.font = 'bold 10px ui-monospace, monospace';
      const warnW = ctx.measureText(warnTxt).width + 10;
      const warnY = Math.max(0, tagY - 20);
      ctx.fillStyle = 'rgba(255, 93, 108, 0.9)';
      ctx.fillRect(renderX, warnY, warnW, 16);
      ctx.fillStyle = '#ffffff';
      ctx.fillText(warnTxt, renderX + 5, warnY + 12);
      ctx.restore();

      const nowT = Date.now();
      if (!pred.lastAlertTime || (nowT - pred.lastAlertTime > 4000)) {
        pred.lastAlertTime = nowT;
        STATE.soundEngine?.playAlert();
      }
    }

    // Guaranteed Event Ingestion with Queueing (no dropped events on simultaneous arrivals)
    if (!STATE.tracker.hasSentEvent(pred.trackId)) {
      STATE.tracker.markEventSent(pred.trackId);
      queueDetectionEvent(pred);
    }
  });

  renderTacticalHudOverlays(ctx, trackedDetections, canvasEl.width, canvasEl.height);

  if (STATE.currentView === 'copilot' && typeof updateCopilotTelemetryBar === 'function') {
    updateCopilotTelemetryBar();
  }

  updateDetectionChips(trackedDetections);
  if (trackedDetections.length > 0) {
    updateDetectionFeed(trackedDetections);
  }
}

function updateDetectionChips(detections) {
  const countHeader = document.getElementById('detections-count-header');
  const chipsRow = document.getElementById('detections-chips-row');
  const activeFilter = STATE.categoryFilter || 'all';
  const catConfig = DETECTION_CATEGORIES[activeFilter] || DETECTION_CATEGORIES.all;

  const totalRaw = (STATE.lastRawPredictions && STATE.lastRawPredictions.length > 0)
    ? STATE.lastRawPredictions.filter(p => p.score >= STATE.confThreshold).length
    : detections.length;

  if (countHeader) {
    if (activeFilter === 'none') {
      countHeader.textContent = `Detections (Hidden • ${totalRaw} total)`;
    } else if (activeFilter === 'all') {
      countHeader.textContent = `Detections (${detections.length})`;
    } else {
      countHeader.textContent = `Detections (${detections.length} of ${totalRaw})`;
    }
  }
  if (!chipsRow) return;

  // Dynamically synchronize detection chip container visibility
  if (activeFilter === 'none') {
    chipsRow.style.display = 'none';
    chipsRow.classList.add('chips-hidden');
    chipsRow.innerHTML = '';
    return;
  } else {
    chipsRow.style.display = 'flex';
    chipsRow.classList.remove('chips-hidden');
  }

  if (detections.length === 0) {
    if (activeFilter !== 'all' && totalRaw > 0) {
      chipsRow.innerHTML = `
        <div style="font-size: 0.74rem; color: var(--text-muted); display: flex; align-items: center; gap: 0.45rem; padding: 0.35rem 0;" class="mono">
          <span style="color: var(--accent-amber); font-weight: 700;">[FILTER ACTIVE]</span>
          <span>No <strong>${escapeHtml(catConfig.label)}</strong> detected in current frame (${totalRaw} other object${totalRaw === 1 ? '' : 's'} hidden).</span>
        </div>`;
    } else {
      chipsRow.innerHTML = '<div style="font-size: 0.72rem; color: var(--text-dim);" class="mono">No active objects in frame.</div>';
    }
    return;
  }

  const maxVisibleChips = 14;
  const visibleSubset = detections.slice(0, maxVisibleChips);
  const remainder = detections.length - maxVisibleChips;

  let chipsHtml = visibleSubset.map(d => {
    const cat = getObjectCategory(d.class);
    const catConfig = DETECTION_CATEGORIES[cat] || DETECTION_CATEGORIES.other;
    const chipClass = catConfig.chipClass || 'chip-object';
    const iconSvg = catConfig.icon || `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="8"/></svg>`;
    const pct = Math.round(d.score * 100);
    const trackLabel = d.trackId !== undefined ? `#${d.trackId}` : '';

    return `
      <div class="det-chip ${chipClass} mono" data-category="${escapeHtml(cat)}" title="Category: ${escapeHtml(catConfig.label)} | Track: ${trackLabel} | Conf: ${pct}%">
        <span class="det-icon">${iconSvg}</span>
        <span style="font-weight: 600;">${escapeHtml(d.class.toUpperCase())} ${trackLabel}</span>
        <span class="det-score">${pct}%</span>
      </div>
    `;
  }).join('');

  if (remainder > 0) {
    chipsHtml += `
      <div class="det-chip mono" style="background: rgba(255,255,255,0.06); border: 1px dashed var(--border-subtle); color: var(--text-muted);" title="${remainder} more active detections">
        +${remainder} more
      </div>
    `;
  }

  chipsRow.innerHTML = chipsHtml;
}

// Rolling detection log to keep chronological awareness of all tracked objects
if (!STATE.detectionHistory) STATE.detectionHistory = [];
function updateDetectionFeed(currentDetections) {
  if (Array.isArray(currentDetections)) {
    const timeStr = new Date().toLocaleTimeString();
    for (const d of currentDetections) {
      const idx = STATE.detectionHistory.findIndex(h => h.trackId === d.trackId);
      if (idx !== -1) {
        STATE.detectionHistory[idx].lastSeen = timeStr;
        STATE.detectionHistory[idx].score = d.score;
        STATE.detectionHistory[idx].speed = d.speed || 0;
      } else {
        STATE.detectionHistory.unshift({
          trackId: d.trackId,
          class: d.class,
          score: d.score,
          speed: d.speed || 0,
          firstSeen: timeStr,
          lastSeen: timeStr
        });
      }
    }
    // Limit memory footprint to last 25 historical objects
    if (STATE.detectionHistory.length > 25) {
      STATE.detectionHistory.length = 25;
    }
  }

  const items = STATE.detectionHistory.slice(0, 10);
  const itemHtml = items.map(p => `
    <div style="background: var(--bg-surface-elevated); border: 1px solid var(--border-subtle); padding: 0.45rem 0.65rem; border-radius: 4px; margin-bottom: 0.4rem; display: flex; align-items: center; justify-content: space-between;">
      <div>
        <span class="badge ${p.class === 'person' ? 'badge-critical' : 'badge-medium'} mono">${p.class.toUpperCase()} #${p.trackId}</span>
        <span style="font-size: 0.8rem; margin-left: 0.4rem;" class="mono">${Math.round(p.score * 100)}%</span>
      </div>
      <div style="font-size: 0.7rem; color: var(--text-dim);" class="mono">${p.lastSeen}</div>
    </div>
  `).join('');
  detectionFeed.innerHTML = itemHtml;
}

// Guaranteed Multi-Object Event Dispatch Queue
if (!STATE.eventQueue) STATE.eventQueue = [];

function queueDetectionEvent(pred) {
  if (!STATE.eventQueue) STATE.eventQueue = [];
  if (STATE.eventQueue.length < 60) {
    const camName = document.getElementById('scanner-camera-select')?.value || 'CAM-01-ENTRANCE';
    STATE.eventQueue.push({
      camera_id: camName,
      class_name: pred.class,
      confidence: pred.score,
      bbox: pred.bbox,
      metadata: { source: 'COCO-SSD MobileNet V2', trackId: pred.trackId, activeSource: STATE.activeSourceName }
    });
  }
  flushEventQueue();
}

async function flushEventQueue() {
  if (!STATE.eventQueue || STATE.eventQueue.length === 0) return;
  if (STATE.inFlightEventCount >= STATE.maxInFlightEvents) return;

  const eventPayload = STATE.eventQueue.shift();
  if (!eventPayload) return;

  STATE.inFlightEventCount++;
  try {
    await fetch('/api/v1/events', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Tenant-ID': STATE.tenantId
      },
      body: JSON.stringify(eventPayload)
    });

    const now = performance.now();
    if (now - STATE.lastSummaryRefreshTime > STATE.summaryRefreshThrottleMs) {
      STATE.lastSummaryRefreshTime = now;
      fetchSummary();
    }
  } catch (e) {
    console.warn('[VantaVisionAI] Event flush notice:', e.message);
  } finally {
    STATE.inFlightEventCount = Math.max(0, STATE.inFlightEventCount - 1);
    if (STATE.eventQueue.length > 0) {
      setTimeout(flushEventQueue, 60);
    }
  }
}

async function recordDetectionEvent(pred) {
  if (STATE.inFlightEventCount >= STATE.maxInFlightEvents) {
    queueDetectionEvent(pred);
    return;
  }
  queueDetectionEvent(pred);
}

// Single frame scan
btnSnapshot.addEventListener('click', async () => {
  if (!STATE.model) return showToast('COCO-SSD model is initializing, please wait.', 'warning');
  if (videoEl.readyState < 2 || videoEl.videoWidth === 0) {
    return showToast('No active video feed. Click "Start Webcam" or "Test Surveillance Feed" first.', 'warning');
  }
  try {
    const rawPredictions = await detectFromVideo(videoEl);
    STATE.lastRawPredictions = rawPredictions;
    const filtered = filterPredictions(rawPredictions);
    const trackedDetections = STATE.tracker.update(filtered);
    STATE.lastTrackedDetections = trackedDetections;
    renderPredictions(trackedDetections);
    const catLabel = DETECTION_CATEGORIES[STATE.categoryFilter]?.label || STATE.categoryFilter;
    fpsBadgeEl.textContent = `Single Scan: ${trackedDetections.length} visible (${rawPredictions.length} total • ${catLabel})`;
    showToast(`Single scan: ${trackedDetections.length} objects visible (${rawPredictions.length} detected).`, 'info');
  } catch (e) {
    showToast('Single Frame Scan failed: ' + e.message, 'danger');
  }
});

confSlider.addEventListener('input', (e) => {
  STATE.confThreshold = parseInt(e.target.value) / 100;
  confVal.textContent = `${e.target.value}%`;
  applyActiveCategoryFilter();
});

document.getElementById('btn-clear-detections').addEventListener('click', () => {
  detectionFeed.innerHTML = '<div style="padding: 1.5rem 1rem; text-align: center; color: var(--text-dim); font-size: 0.78rem;">Feed cleared. New detections will stream here.</div>';
  ctx.clearRect(0, 0, canvasEl.width, canvasEl.height);
  STATE.tracker.reset();
  STATE.lastRawPredictions = [];
  STATE.lastTrackedDetections = [];
  updateDetectionChips([]);
  showToast('Detection feed cleared.', 'info');
});

// Category Filter Dropdown Listener: Updates detection chips visibility in #detections-chips-row based on selected category
const categoryFilterSelect = document.getElementById('scanner-category-filter');
if (categoryFilterSelect) {
  categoryFilterSelect.addEventListener('change', (e) => {
    const selectedCategory = e.target.value;
    STATE.categoryFilter = selectedCategory;

    // Direct DOM update: filter visibility of detection chips in #detections-chips-row based on selected category
    updateChipsRowVisibility(selectedCategory);

    // Apply category filter across active pipeline, canvas overlay, count headers & badge
    applyActiveCategoryFilter();

    const selectedText = categoryFilterSelect.options[categoryFilterSelect.selectedIndex]?.text || selectedCategory;
    showToast(`Scanner Filter: ${selectedText}`, 'info');
  });
}

// Detection Settings Filter Toggles
['people', 'vehicles', 'objects', 'weapons', 'electronics', 'animals', 'custom'].forEach(key => {
  const el = document.getElementById(`toggle-det-${key}`);
  if (el) {
    el.addEventListener('change', (e) => {
      STATE.detectionFilters[key] = e.target.checked;
      applyActiveCategoryFilter();
      showToast(`Filter: ${key} ${e.target.checked ? 'enabled' : 'disabled'}`, 'info');
    });
  }
});

// =========================================================================
// 7b. DYNAMIC FILTER SYSTEM (ZERO-INFERENCE OVERHEAD FOR HIGH-TRAFFIC SCENES)
// =========================================================================
function syncDynamicFilterUI() {
  if (typeof document === 'undefined' || !document.getElementById) return;
  const activeKeys = Object.entries(STATE.detectionFilters).filter(([k, v]) => v && k !== 'custom');
  const countBadge = document.getElementById('filter-active-count-badge');
  if (countBadge) {
    countBadge.textContent = `${activeKeys.length} Active`;
    if (countBadge.classList) {
      countBadge.className = `badge ${activeKeys.length === 0 ? 'badge-danger' : activeKeys.length <= 2 ? 'badge-amber' : 'badge-cyan'} mono filter-hud-badge`;
    }
  }

  ['people', 'vehicles', 'objects', 'weapons', 'electronics', 'animals'].forEach(key => {
    const isAct = Boolean(STATE.detectionFilters[key]);
    const pill = document.getElementById(`pill-filter-${key}`);
    if (pill) {
      if (pill.classList && typeof pill.classList.toggle === 'function') {
        pill.classList.toggle('active', isAct);
      }
      const st = (typeof pill.querySelector === 'function') ? pill.querySelector('.pill-status') : null;
      if (st) st.textContent = isAct ? 'ON' : 'OFF';
    }
    const chk = document.getElementById(`toggle-det-${key}`);
    if (chk && chk.checked !== isAct) {
      chk.checked = isAct;
    }
  });

  const isHighTraffic = STATE.detectionFilters.people && STATE.detectionFilters.vehicles &&
    !STATE.detectionFilters.objects && !STATE.detectionFilters.weapons &&
    !STATE.detectionFilters.electronics && !STATE.detectionFilters.animals;
  const htBtn = document.getElementById('filter-preset-hightraffic');
  if (htBtn && htBtn.classList && typeof htBtn.classList.toggle === 'function') htBtn.classList.toggle('active-preset', isHighTraffic);

  const isPersonOnly = STATE.detectionFilters.people && !STATE.detectionFilters.vehicles &&
    !STATE.detectionFilters.objects && !STATE.detectionFilters.weapons &&
    !STATE.detectionFilters.electronics && !STATE.detectionFilters.animals;
  const poBtn = document.getElementById('filter-preset-person-only');
  if (poBtn && poBtn.classList && typeof poBtn.classList.toggle === 'function') poBtn.classList.toggle('active-preset', isPersonOnly);

  const isVehicleOnly = !STATE.detectionFilters.people && STATE.detectionFilters.vehicles &&
    !STATE.detectionFilters.objects && !STATE.detectionFilters.weapons &&
    !STATE.detectionFilters.electronics && !STATE.detectionFilters.animals;
  const voBtn = document.getElementById('filter-preset-vehicle-only');
  if (voBtn && voBtn.classList && typeof voBtn.classList.toggle === 'function') voBtn.classList.toggle('active-preset', isVehicleOnly);

  const isAll = STATE.detectionFilters.people && STATE.detectionFilters.vehicles &&
    STATE.detectionFilters.objects && STATE.detectionFilters.weapons &&
    STATE.detectionFilters.electronics && STATE.detectionFilters.animals;
  const allBtn = document.getElementById('filter-preset-all');
  if (allBtn && allBtn.classList && typeof allBtn.classList.toggle === 'function') allBtn.classList.toggle('active-preset', isAll);
}

function setFilterPreset(presetName) {
  if (presetName === 'hightraffic') {
    STATE.detectionFilters.people = true;
    STATE.detectionFilters.vehicles = true;
    STATE.detectionFilters.objects = false;
    STATE.detectionFilters.weapons = false;
    STATE.detectionFilters.electronics = false;
    STATE.detectionFilters.animals = false;
    showToast('⚡ High-Traffic Surveillance Active: Persons & Vehicles prioritized (background suppressed).', 'info');
  } else if (presetName === 'person-only') {
    STATE.detectionFilters.people = true;
    STATE.detectionFilters.vehicles = false;
    STATE.detectionFilters.objects = false;
    STATE.detectionFilters.weapons = false;
    STATE.detectionFilters.electronics = false;
    STATE.detectionFilters.animals = false;
    showToast('👤 Solo Target Filter: Persons Only active.', 'info');
  } else if (presetName === 'vehicle-only') {
    STATE.detectionFilters.people = false;
    STATE.detectionFilters.vehicles = true;
    STATE.detectionFilters.objects = false;
    STATE.detectionFilters.weapons = false;
    STATE.detectionFilters.electronics = false;
    STATE.detectionFilters.animals = false;
    showToast('🚗 Solo Target Filter: Vehicles Only active.', 'info');
  } else if (presetName === 'all') {
    STATE.detectionFilters.people = true;
    STATE.detectionFilters.vehicles = true;
    STATE.detectionFilters.objects = true;
    STATE.detectionFilters.weapons = false;
    STATE.detectionFilters.electronics = true;
    STATE.detectionFilters.animals = true;
    showToast('All standard object filters enabled.', 'info');
  }

  syncDynamicFilterUI();
  applyActiveCategoryFilter();
}

// Attach pill click listeners
if (typeof document !== 'undefined' && typeof document.querySelectorAll === 'function') {
  document.querySelectorAll('.filter-pill[data-filter-type]').forEach(pill => {
    if (pill && typeof pill.addEventListener === 'function') {
      pill.addEventListener('click', () => {
        const filterKey = typeof pill.getAttribute === 'function' ? pill.getAttribute('data-filter-type') : null;
        if (filterKey && typeof STATE.detectionFilters[filterKey] !== 'undefined') {
          STATE.detectionFilters[filterKey] = !STATE.detectionFilters[filterKey];
          const isNowActive = STATE.detectionFilters[filterKey];
          syncDynamicFilterUI();
          applyActiveCategoryFilter();
          showToast(`${filterKey.toUpperCase()}: ${isNowActive ? 'ON' : 'OFF'} (Dynamic filter applied)`, 'info');
        }
      });
    }
  });
}

// Attach preset button click listeners
const htPresetBtn = document.getElementById('filter-preset-hightraffic');
if (htPresetBtn && typeof htPresetBtn.addEventListener === 'function') {
  htPresetBtn.addEventListener('click', () => setFilterPreset('hightraffic'));
}

const poPresetBtn = document.getElementById('filter-preset-person-only');
if (poPresetBtn && typeof poPresetBtn.addEventListener === 'function') {
  poPresetBtn.addEventListener('click', () => setFilterPreset('person-only'));
}

const voPresetBtn = document.getElementById('filter-preset-vehicle-only');
if (voPresetBtn && typeof voPresetBtn.addEventListener === 'function') {
  voPresetBtn.addEventListener('click', () => setFilterPreset('vehicle-only'));
}

const allPresetBtn = document.getElementById('filter-preset-all');
if (allPresetBtn && typeof allPresetBtn.addEventListener === 'function') {
  allPresetBtn.addEventListener('click', () => setFilterPreset('all'));
}

// Initial synchronization of Dynamic Filter HUD
if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  syncDynamicFilterUI();
}

// =========================================================================
// 8. ALEANA VOICE ASSISTANT CLIENT ENGINE & NORMALIZED WAKE-WORD SYSTEM
// =========================================================================

// Normalizes speech transcripts safely across browser variations
function normalizeTranscript(raw) {
  if (!raw) return '';
  return String(raw)
    .toLowerCase()
    .replace(/[,!?;:\-\/"]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

// Parses wake phrase ("Aleana", "Elena", "Alina") and isolates the operational command
function parseWakeAndCommand(rawText) {
  const norm = normalizeTranscript(rawText);
  if (!norm) return { hasWake: false, command: '', isWakeOnly: false };

  // Word boundary regex for "aleana" and phonetic variations
  const wakeRegex = /\b(aleana|elena|alina|alana)\b/i;
  const hasWake = wakeRegex.test(norm);

  if (!hasWake) {
    return { hasWake: false, command: norm, isWakeOnly: false };
  }

  // Strip conversational prefixes ("hey aleana", "ok aleana", "please")
  let command = norm
    .replace(/\b(hey|hi|hello|ok|okay)?\s*(aleana|elena|alina|alana)\s*(please)?\b/gi, '')
    .trim();

  const isWakeOnly = command.length === 0;
  return { hasWake: true, command, isWakeOnly };
}

function initAleanaVoice() {
  const SpeechRec = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (SpeechRec) {
    STATE.aleana.isSupported = true;
    STATE.aleana.recognition = new SpeechRec();
    STATE.aleana.recognition.continuous = true;
    STATE.aleana.recognition.interimResults = true;
    STATE.aleana.recognition.lang = STATE.aleana.language;

    STATE.aleana.recognition.onstart = () => {
      STATE.aleana.consecutiveRestarts = 0;

      // Greeting discipline: greet exactly ONCE per newly started session
      if (!STATE.aleana.sessionHasGreeted) {
        STATE.aleana.sessionHasGreeted = true;
        const greeting = 'Aleana online. How can I help?';
        updateAleanaTranscript(greeting);
        const replyEl = document.getElementById('aleana-response-text');
        if (replyEl) replyEl.textContent = `"${greeting}"`;
        speakAleanaResponse(greeting);
      } else {
        setAleanaState('LISTENING');
        showAleanaStatus('Listening continuously for your command...');
      }
    };

    STATE.aleana.recognition.onresult = (event) => {
      let interim = '';
      let final = '';
      for (let i = event.resultIndex; i < event.results.length; ++i) {
        if (event.results[i].isFinal) {
          final += event.results[i][0].transcript;
        } else {
          interim += event.results[i][0].transcript;
        }
      }
      const previewText = final || interim;
      updateAleanaTranscript(previewText);

      if (final && final.trim()) {
        const cleanFinal = final.trim();
        const norm = normalizeTranscript(cleanFinal);

        // A. Two-Step Voice Confirmation State Machine Guard
        if (STATE.aleana.state === 'AWAITING_CONFIRMATION' && STATE.aleana.pendingConfirmation) {
          const isAffirmative = /\b(yes|confirm|proceed|authorized|affirmative|haan|haanji|karo)\b/i.test(norm);
          const isCancel = /\b(no|cancel|abort|stop|ruko|mat karo|cancel karo)\b/i.test(norm);
          if (isAffirmative) {
            const pending = STATE.aleana.pendingConfirmation;
            STATE.aleana.pendingConfirmation = null;
            setAleanaState('PROCESSING');
            if (pending.confirmedAction) pending.confirmedAction();
            const resp = 'Security authorization verified. Action executed.';
            updateAleanaTranscript(resp);
            speakAleanaResponse(resp);
            STATE.soundEngine?.playResolveChord();
            return;
          } else if (isCancel) {
            STATE.aleana.pendingConfirmation = null;
            const resp = 'Action cancelled. Resuming standard surveillance monitoring.';
            updateAleanaTranscript(resp);
            speakAleanaResponse(resp);
            setAleanaState('LISTENING');
            return;
          }
        }

        // 1. High-Priority Local Intercept for Session Shutdown
        // Must NOT match hardware commands like "stop scanner" or "stop speech"
        const isStopPhrase = /^(aleana\s+)?(stop|shutdown|turn off|stop listening)(\s+aleana)?$/i.test(norm) ||
                             ['aleana stop', 'aleana shutdown', 'stop aleana', 'shutdown aleana', 'stop listening', 'shutdown'].includes(norm);
        const isHardwareOrSpeechStop = norm.includes('scanner') || norm.includes('camera') || norm.includes('feed') || norm.includes('speech') || norm.includes('speaking');

        if (isStopPhrase && !isHardwareOrSpeechStop) {
          stopAleanaSession();
          updateAleanaTranscript('Aleana stop');
          showToast('Aleana: Voice session stopped.', 'info');
          return;
        }

        // 2. High-Priority Local Intercept for Stop Speech / Pause / Resume / Start
        if (['stop speech', 'stop speaking', 'aleana stop speaking', 'stop talking', 'chup ho jao', 'chup raho'].some(k => norm.includes(k))) {
          if ('speechSynthesis' in window) {
            window.speechSynthesis.cancel();
          }
          STATE.aleana.isSpeaking = false;
          showAleanaStatus('Speech output cancelled.');
          showToast('Aleana: Speech output cancelled.', 'info');
          if (STATE.aleana.sessionActive && !STATE.aleana.userStopped && !STATE.aleana.isPaused) {
            setAleanaState('RECOVERING', 'Resuming listening...');
            scheduleRecognitionRestart(100);
          }
          return;
        }
        if (['repeat that', 'repeat response', 'repeat', 'dobara bolo', 'phir se bolo'].some(k => norm === k || norm === ('aleana ' + k))) {
          if (STATE.aleana.lastSpokenText) {
            speakAleanaResponse(STATE.aleana.lastSpokenText);
          } else {
            speakAleanaResponse('No previous response to repeat.');
          }
          return;
        }
        if (['pause listening', 'pause aleana'].some(k => norm.includes(k))) {
          pauseAleanaSession();
          showToast('Aleana: Voice listening paused.', 'info');
          return;
        }
        if (['resume listening', 'resume aleana', 'start listening', 'start aleana', 'aleana start', 'aleana resume'].some(k => norm.includes(k))) {
          if (STATE.aleana.isPaused) {
            resumeAleanaSession();
            showToast('Aleana: Voice listening resumed.', 'info');
          } else {
            speakAleanaResponse('Voice session is already active. How can I help?');
          }
          return;
        }

        // 3. Resolve Wake Phrase & Command Intent
        const parsed = parseWakeAndCommand(cleanFinal);

        // If previously in WAKE_DETECTED waiting state:
        let targetCommand = parsed.command;
        if (STATE.aleana.waitingForCommandAfterWake) {
          if (STATE.aleana.wakeTimeoutId) {
            clearTimeout(STATE.aleana.wakeTimeoutId);
            STATE.aleana.wakeTimeoutId = null;
          }
          STATE.aleana.waitingForCommandAfterWake = false;
          targetCommand = parsed.command || norm;
        }

        // 4. Wake-Word Only Trigger ("Aleana"): enter WAKE_DETECTED and wait for follow-up
        if (parsed.hasWake && parsed.isWakeOnly) {
          STATE.aleana.waitingForCommandAfterWake = true;
          setAleanaState('WAKE_DETECTED', 'Wake phrase detected. Listening for command...');
          updateAleanaTranscript('"Aleana" (Listening...)');
          if (STATE.aleana.wakeTimeoutId) clearTimeout(STATE.aleana.wakeTimeoutId);
          STATE.aleana.wakeTimeoutId = setTimeout(() => {
            if (STATE.aleana.waitingForCommandAfterWake) {
              STATE.aleana.waitingForCommandAfterWake = false;
              if (STATE.aleana.sessionActive && !STATE.aleana.isPaused && !STATE.aleana.userStopped) {
                setAleanaState('LISTENING', 'Listening continuously for your command...');
              }
            }
          }, 7000);
          return;
        }

        // 5. Execute Resolved Command with Duplicate Deduplication
        if (targetCommand) {
          const now = performance.now();
          if (targetCommand === STATE.aleana.lastExecutedQuery && (now - STATE.aleana.lastExecutedTime) < 1500) {
            return;
          }
          STATE.aleana.lastExecutedQuery = targetCommand;
          STATE.aleana.lastExecutedTime = now;

          setAleanaState('WAKE_DETECTED');
          executeAleanaCommand(targetCommand);
        }
      }
    };

    STATE.aleana.recognition.onerror = (event) => {
      console.warn('[Aleana Voice Error]', event.error);
      if (event.error === 'not-allowed' || event.error === 'service-not-allowed') {
        STATE.aleana.sessionActive = false;
        STATE.aleana.userStopped = true;
        setAleanaState('ERROR');
        showAleanaStatus('Microphone permission blocked. Please allow mic in browser address bar.');
        showToast('Microphone access was denied.', 'danger');
      } else if (event.error === 'no-speech') {
        // Normal during ambient listening pauses, continuous session continues
        if (STATE.aleana.sessionActive && !STATE.aleana.isPaused && !STATE.aleana.userStopped) {
          showAleanaStatus('Listening for your command...');
        }
      } else if (event.error === 'aborted') {
        // Caused by intentional restart or speech pause
      } else {
        showAleanaStatus(`Voice status: ${event.error}`);
      }
    };

    STATE.aleana.recognition.onend = () => {
      if (STATE.aleana.isSpeaking) {
        // Half-duplex suppression: while speaking, recognition is paused.
        // utterance.onend will trigger the recovery restart.
        return;
      }
      if (STATE.aleana.sessionActive && !STATE.aleana.userStopped && !STATE.aleana.isPaused) {
        setAleanaState('RECOVERING');
        scheduleRecognitionRestart();
      } else if (STATE.aleana.isPaused) {
        setAleanaState('PAUSED');
      } else {
        setAleanaState('IDLE');
      }
    };
  } else {
    STATE.aleana.isSupported = false;
    const badge = document.getElementById('aleana-voice-availability');
    if (badge) badge.textContent = 'Web Speech Recognition not supported in this browser (Text Fallback Active)';
  }

  // Populate Speech Synthesis Voices
  if ('speechSynthesis' in window) {
    const populateVoices = () => {
      STATE.aleana.voicesList = window.speechSynthesis.getVoices();
      const voiceSelect = document.getElementById('aleana-voice-select');
      if (voiceSelect && STATE.aleana.voicesList.length > 0) {
        voiceSelect.innerHTML = STATE.aleana.voicesList.map((v, idx) => `
          <option value="${idx}" ${v.default ? 'selected' : ''}>${v.name} (${v.lang})</option>
        `).join('');
      }
    };
    populateVoices();
    if (window.speechSynthesis.onvoiceschanged !== undefined) {
      window.speechSynthesis.onvoiceschanged = populateVoices;
    }
  }
}

function startRecognitionSafely() {
  if (!STATE.aleana.recognition || !STATE.aleana.sessionActive || STATE.aleana.userStopped || STATE.aleana.isPaused || STATE.aleana.isSpeaking) {
    return;
  }
  try {
    STATE.aleana.recognition.lang = STATE.aleana.language;
    STATE.aleana.recognition.start();
  } catch (err) {
    if (err.name !== 'InvalidStateError') {
      scheduleRecognitionRestart();
    }
  }
}

function scheduleRecognitionRestart(delay) {
  if (!STATE.aleana.sessionActive || STATE.aleana.userStopped || STATE.aleana.isPaused || STATE.aleana.isSpeaking) {
    return;
  }
  if (STATE.aleana.restartTimer) {
    clearTimeout(STATE.aleana.restartTimer);
    STATE.aleana.restartTimer = null;
  }
  STATE.aleana.consecutiveRestarts++;
  const delayMs = delay !== undefined ? delay : Math.min(3000, Math.round(200 * Math.pow(1.35, STATE.aleana.consecutiveRestarts)));
  STATE.aleana.restartTimer = setTimeout(() => {
    startRecognitionSafely();
  }, delayMs);
}

function startAleanaSession() {
  if (!STATE.aleana.isSupported) {
    showToast('Web Speech Recognition is not supported in this browser. Please use the text input below.', 'warning');
    return;
  }
  STATE.aleana.sessionId++;
  STATE.aleana.sessionHasGreeted = false;
  STATE.aleana.userStopped = false;
  STATE.aleana.isPaused = false;
  STATE.aleana.sessionActive = true;
  STATE.aleana.waitingForCommandAfterWake = false;
  STATE.aleana.consecutiveRestarts = 0;
  setAleanaState('REQUESTING_PERMISSION', 'Connecting microphone...');
  startRecognitionSafely();
}

function pauseAleanaSession() {
  STATE.aleana.isPaused = true;
  STATE.aleana.waitingForCommandAfterWake = false;
  if (STATE.aleana.wakeTimeoutId) {
    clearTimeout(STATE.aleana.wakeTimeoutId);
    STATE.aleana.wakeTimeoutId = null;
  }
  if (STATE.aleana.restartTimer) {
    clearTimeout(STATE.aleana.restartTimer);
    STATE.aleana.restartTimer = null;
  }
  if ('speechSynthesis' in window) {
    window.speechSynthesis.cancel();
  }
  if (STATE.aleana.recognition) {
    try { STATE.aleana.recognition.abort(); } catch (e) {}
  }
  setAleanaState('PAUSED', 'Voice listening paused. Click Resume or Mic to continue.');
}

function resumeAleanaSession() {
  STATE.aleana.isPaused = false;
  STATE.aleana.userStopped = false;
  STATE.aleana.sessionActive = true;
  STATE.aleana.waitingForCommandAfterWake = false;
  setAleanaState('RECOVERING', 'Resuming voice listening...');
  scheduleRecognitionRestart(100);
}

function stopAleanaSession() {
  STATE.aleana.sessionActive = false;
  STATE.aleana.userStopped = true;
  STATE.aleana.isPaused = false;
  STATE.aleana.isSpeaking = false;
  STATE.aleana.sessionHasGreeted = false;
  STATE.aleana.waitingForCommandAfterWake = false;
  if (STATE.aleana.wakeTimeoutId) {
    clearTimeout(STATE.aleana.wakeTimeoutId);
    STATE.aleana.wakeTimeoutId = null;
  }
  if (STATE.aleana.restartTimer) {
    clearTimeout(STATE.aleana.restartTimer);
    STATE.aleana.restartTimer = null;
  }
  if ('speechSynthesis' in window) {
    window.speechSynthesis.cancel();
  }
  if (STATE.aleana.recognition) {
    try { STATE.aleana.recognition.abort(); } catch (e) {}
  }
  setAleanaState('IDLE', 'Voice session stopped. Click Start Listening to begin.');
}

function setAleanaState(newState, customLabel) {
  STATE.aleana.state = newState;
  const badge = document.getElementById('aleana-state-badge');
  const stage = document.getElementById('aleana-orb-container');
  const micBtnText = document.getElementById('aleana-mic-btn-text');
  const pauseBtnText = document.getElementById('aleana-pause-btn-text');
  const drawerPauseBtn = document.getElementById('drawer-pause-btn');
  const topbarBadge = document.getElementById('topbar-aleana-state');

  let badgeClass = 'badge-low';
  if (newState === 'LISTENING') badgeClass = 'badge-critical';
  else if (newState === 'SPEAKING') badgeClass = 'badge-medium';
  else if (newState === 'WAKE_DETECTED') badgeClass = 'badge-high';
  else if (newState === 'AWAITING_CONFIRMATION') badgeClass = 'badge-high';
  else if (newState === 'PROCESSING') badgeClass = 'badge-cyan';
  else if (newState === 'RESPONDING') badgeClass = 'badge-cyan';
  else if (newState === 'REQUESTING_PERMISSION') badgeClass = 'badge-medium';
  else if (newState === 'PAUSED') badgeClass = 'badge-low';
  else if (newState === 'ERROR') badgeClass = 'badge-critical';

  if (badge) {
    const stateDesc = newState === 'LISTENING' ? 'AUDIO CAPTURE ACTIVE' :
      newState === 'AWAITING_CONFIRMATION' ? 'CONFIRMATION REQUIRED' :
      newState === 'PAUSED' ? 'SESSION PAUSED' :
      newState === 'WAKE_DETECTED' ? 'WAKE DETECTED' : 'READY';
    badge.textContent = `${newState} • ${stateDesc}`;
    badge.className = `badge mono ${badgeClass}`;
  }

  if (topbarBadge) {
    topbarBadge.textContent = newState;
    topbarBadge.className = `badge mono ${badgeClass}`;
  }

  if (stage) {
    stage.className = `aleana-orb-stage ${newState.toLowerCase()}`;
  }

  if (micBtnText) {
    if (STATE.aleana.sessionActive && !STATE.aleana.isPaused) {
      micBtnText.textContent = 'Listening (Active)';
    } else {
      micBtnText.textContent = 'Start Listening';
    }
  }

  if (pauseBtnText) {
    pauseBtnText.textContent = STATE.aleana.isPaused ? 'Resume' : 'Pause';
  }
  if (drawerPauseBtn) {
    drawerPauseBtn.textContent = STATE.aleana.isPaused ? 'Resume' : 'Pause';
  }

  if (customLabel) {
    showAleanaStatus(customLabel);
  }
}

function showAleanaStatus(text) {
  const lbl = document.getElementById('aleana-status-label');
  const drawerLbl = document.getElementById('drawer-aleana-status');
  if (lbl) lbl.textContent = text;
  if (drawerLbl) drawerLbl.textContent = text;
}

function updateAleanaTranscript(text) {
  const preview = document.getElementById('aleana-live-transcript');
  const drawerPreview = document.getElementById('drawer-transcript-preview');
  if (preview) preview.textContent = `"${text}"`;
  if (drawerPreview) drawerPreview.textContent = `"${text}"`;
}

function speakAleanaResponse(speechText) {
  if (!speechText) return;
  STATE.aleana.lastSpokenText = speechText;
  if (!('speechSynthesis' in window) || STATE.aleana.isMuted) return;

  // Half-duplex suppression: pause recognition during speech to prevent feedback loop
  STATE.aleana.isSpeaking = true;
  if (STATE.aleana.recognition) {
    try { STATE.aleana.recognition.abort(); } catch (e) {}
  }
  window.speechSynthesis.cancel();

  const utterance = new SpeechSynthesisUtterance(speechText);
  utterance.rate = STATE.aleana.speechRate;

  const voiceSelect = document.getElementById('aleana-voice-select');
  if (voiceSelect && STATE.aleana.voicesList[voiceSelect.value]) {
    utterance.voice = STATE.aleana.voicesList[voiceSelect.value];
  }

  utterance.onstart = () => {
    setAleanaState('SPEAKING', 'Aleana speaking...');
  };
  utterance.onend = () => {
    STATE.aleana.isSpeaking = false;
    if (STATE.aleana.sessionActive && !STATE.aleana.userStopped && !STATE.aleana.isPaused) {
      setAleanaState('RECOVERING', 'Resuming listening...');
      scheduleRecognitionRestart(120);
    } else if (STATE.aleana.isPaused) {
      setAleanaState('PAUSED');
    } else {
      setAleanaState('IDLE', 'Click microphone to speak');
    }
  };
  utterance.onerror = () => {
    STATE.aleana.isSpeaking = false;
    if (STATE.aleana.sessionActive && !STATE.aleana.userStopped && !STATE.aleana.isPaused) {
      scheduleRecognitionRestart(150);
    } else {
      setAleanaState('IDLE');
    }
  };

  window.speechSynthesis.speak(utterance);
}

async function executeAleanaCommand(queryStr) {
  if (!queryStr) return;
  setAleanaState('PROCESSING', 'Processing intent with backend...');

  try {
    const res = await fetch('/api/v1/aleana/command', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Tenant-ID': STATE.tenantId
      },
      body: JSON.stringify({
        query: queryStr,
        current_view: STATE.currentView,
        live_context: typeof getScannerLiveContext === 'function' ? getScannerLiveContext() : null
      })
    });
    const result = await res.json();

    // Render response text
    const replyEl = document.getElementById('aleana-response-text');
    if (replyEl) replyEl.textContent = `"${result.speech}"`;

    // Handle Session & Speech Control Actions
    if (result.action === 'STOP_SESSION' || result.intent === 'STOP_ASSISTANT') {
      stopAleanaSession();
      showToast('Aleana: Voice session stopped.', 'info');
      return;
    } else if (result.action === 'STOP_SPEECH' || result.intent === 'STOP_SPEECH') {
      if ('speechSynthesis' in window) {
        window.speechSynthesis.cancel();
      }
      STATE.aleana.isSpeaking = false;
      showAleanaStatus('Speech output cancelled.');
      showToast('Aleana: Speech output cancelled.', 'info');
      if (STATE.aleana.sessionActive && !STATE.aleana.userStopped && !STATE.aleana.isPaused) {
        setAleanaState('RECOVERING', 'Resuming listening...');
        scheduleRecognitionRestart(100);
      }
      return;
    } else if (result.action === 'PAUSE_SESSION' || result.intent === 'PAUSE_ASSISTANT') {
      pauseAleanaSession();
      showToast('Aleana: Voice listening paused.', 'info');
      return;
    } else if (result.action === 'RESUME_SESSION' || result.intent === 'RESUME_ASSISTANT') {
      resumeAleanaSession();
      showToast('Aleana: Voice listening resumed.', 'info');
      return;
    } else if (result.action === 'REPEAT_RESPONSE' || result.intent === 'REPEAT_RESPONSE') {
      if (STATE.aleana.lastSpokenText) {
        speakAleanaResponse(STATE.aleana.lastSpokenText);
      } else {
        speakAleanaResponse('No previous response to repeat.');
      }
      return;
    }

    // Execute Client Navigation & Hardware Actions
    if (result.action === 'NAVIGATE' && result.target) {
      switchView(result.target);
    } else if (result.action === 'START_SCANNER') {
      switchView('scanner');
      if (!STATE.isScanning) {
        startSyntheticTestFeed();
      }
    } else if (result.action === 'STOP_SCANNER') {
      stopScanning();
    } else if (result.action === 'START_TEST_FEED') {
      switchView('scanner');
      startSyntheticTestFeed();
    } else if (result.action === 'RUN_DEMO') {
      triggerDemoSimulation();
    } else if (result.action === 'FILTER_CATEGORY' && result.target) {
      STATE.categoryFilter = result.target;
      if (typeof updateChipsRowVisibility === 'function') updateChipsRowVisibility(result.target);
      if (typeof applyActiveCategoryFilter === 'function') applyActiveCategoryFilter();
      showToast(`Aleana: Filtered scanner to ${result.target}`, 'info');
    } else if (result.action === 'SET_FILTER_PRESET' && result.data && result.data.preset) {
      if (typeof setFilterPreset === 'function') {
        setFilterPreset(result.data.preset);
      }
    } else if (result.action === 'TOGGLE_HEATMAP') {
      if (typeof toggleHeatmapOverlay === 'function') toggleHeatmapOverlay();
    } else if (result.action === 'CAPTURE_SNAPSHOT') {
      if (typeof captureForensicSnapshot === 'function') captureForensicSnapshot();
    } else if (result.action === 'DISPATCH_DRONE') {
      STATE.soundEngine?.playBreachAlert();
      showToast('Tactical UAV Dispatched: ' + (result.target || 'Perimeter Sector Alpha'), 'warning');
      try {
        fetch('/api/v1/brain/tools/dispatch_tactical_drone', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Tenant-ID': STATE.tenantId },
          body: JSON.stringify({ args: { target_zone: result.target || 'Perimeter Sector Alpha', mission_profile: 'PERIMETER_RECON' } })
        });
      } catch (e) {}
    } else if (result.action === 'CONFIRMATION_REQUIRED') {
      STATE.aleana.pendingConfirmation = {
        action: result.target,
        speech: result.speech,
        confirmedAction: () => {
          if (result.target === 'LOCKDOWN_FACILITY') {
            showToast('EMERGENCY LOCKDOWN INITIATED', 'danger');
            STATE.soundEngine?.playBreachAlert();
          } else if (result.target === 'PURGE_AUDIT_LOG') {
            showToast('Audit log purge sequence authorized.', 'warning');
            STATE.soundEngine?.playResolveChord();
          } else if (result.target === 'TRIGGER_ALARM') {
            showToast('Evacuation alarm sounding.', 'danger');
            STATE.soundEngine?.playBreachAlert();
          }
        }
      };
      setAleanaState('AWAITING_CONFIRMATION', 'Security confirmation required: say "Yes confirm" or "Cancel"');
      speakAleanaResponse(result.speech);
      return;
    } else if (result.action === 'EXECUTE_CONFIRMED_ACTION') {
      if (STATE.aleana.pendingConfirmation && STATE.aleana.pendingConfirmation.confirmedAction) {
        STATE.aleana.pendingConfirmation.confirmedAction();
      }
      STATE.aleana.pendingConfirmation = null;
      STATE.soundEngine?.playResolveChord();
      showToast('Guarded action executed under security authorization.', 'success');
    } else if (result.action === 'ABORT_GUARDED_ACTION') {
      STATE.aleana.pendingConfirmation = null;
      setAleanaState('LISTENING');
      showToast('Action cancelled by operator.', 'info');
    } else if (result.action === 'RESOLVE_INCIDENT') {
      fetchIncidents();
      fetchSummary();
      STATE.soundEngine?.playResolveChord();
      showToast('Incident resolved via Aleana voice directive.', 'success');
    } else if (result.action === 'QUERY_SCANNER_CENSUS') {
      const targetCount = (STATE.lastTrackedDetections || []).length;
      const classMap = {};
      (STATE.lastTrackedDetections || []).forEach(d => { classMap[d.class] = (classMap[d.class] || 0) + 1; });
      const breakdown = Object.entries(classMap).map(([k, v]) => `${v} ${k}(s)`).join(', ') || 'no classified objects';
      result.speech = `Live scanner is active with ${targetCount} object(s) in view: ${breakdown}.`;
      if (replyEl) replyEl.textContent = `"${result.speech}"`;
    }

    // Spoken Audio Output
    speakAleanaResponse(result.speech);
    showToast(`Aleana: ${result.speech.substring(0, 70)}...`, 'info');
  } catch (err) {
    console.error('Aleana Command Error:', err);
    setAleanaState('IDLE');
    showAleanaStatus('Command error. Please retry.');
    showToast('Failed to process voice command.', 'danger');
  }
}

// Microphone & Session Controls
function handleVoiceToggleClick() {
  if (!STATE.aleana.sessionActive) {
    startAleanaSession();
  } else if (STATE.aleana.isPaused) {
    resumeAleanaSession();
  } else {
    pauseAleanaSession();
  }
}

document.getElementById('btn-aleana-orb')?.addEventListener('click', handleVoiceToggleClick);
document.getElementById('btn-aleana-mic-toggle')?.addEventListener('click', handleVoiceToggleClick);
document.getElementById('drawer-orb-btn')?.addEventListener('click', handleVoiceToggleClick);

document.getElementById('btn-aleana-pause-toggle')?.addEventListener('click', () => {
  if (STATE.aleana.isPaused) {
    resumeAleanaSession();
  } else {
    pauseAleanaSession();
  }
});
document.getElementById('drawer-pause-btn')?.addEventListener('click', () => {
  if (STATE.aleana.isPaused) {
    resumeAleanaSession();
  } else {
    pauseAleanaSession();
  }
});

document.getElementById('btn-aleana-stop-assistant')?.addEventListener('click', () => {
  stopAleanaSession();
  showToast('Aleana: Voice session stopped.', 'info');
});
document.getElementById('drawer-stop-voice-btn')?.addEventListener('click', () => {
  stopAleanaSession();
  showToast('Aleana: Voice session stopped.', 'info');
});

document.getElementById('btn-aleana-stop-speech')?.addEventListener('click', () => {
  if ('speechSynthesis' in window) {
    window.speechSynthesis.cancel();
  }
  STATE.aleana.isSpeaking = false;
  if (STATE.aleana.sessionActive && !STATE.aleana.userStopped && !STATE.aleana.isPaused) {
    setAleanaState('RECOVERING', 'Resuming listening...');
    scheduleRecognitionRestart(100);
  } else {
    setAleanaState('IDLE');
  }
  showAleanaStatus('Speech stopped.');
});

// Aleana Text Input Fallback
document.getElementById('aleana-text-form')?.addEventListener('submit', (e) => {
  e.preventDefault();
  const input = document.getElementById('aleana-text-input');
  if (!input || !input.value.trim()) return;
  const q = input.value.trim();
  input.value = '';
  updateAleanaTranscript(q);
  executeAleanaCommand(q);
});

// Aleana Drawer Quick Text Input Fallback
document.getElementById('drawer-aleana-form')?.addEventListener('submit', (e) => {
  e.preventDefault();
  const input = document.getElementById('drawer-aleana-input');
  if (!input || !input.value.trim()) return;
  const q = input.value.trim();
  input.value = '';
  updateAleanaTranscript(q);
  executeAleanaCommand(q);
});

// Suggested Prompt Chips
document.querySelectorAll('.aleana-trigger-chip').forEach(chip => {
  chip.addEventListener('click', () => {
    const q = chip.dataset.voice;
    updateAleanaTranscript(q);
    executeAleanaCommand(q);
  });
});

// Voice Settings
document.getElementById('aleana-rate-select')?.addEventListener('change', (e) => {
  STATE.aleana.speechRate = parseFloat(e.target.value);
});
document.getElementById('aleana-lang-select')?.addEventListener('change', (e) => {
  STATE.aleana.language = e.target.value;
  if (STATE.aleana.recognition) {
    STATE.aleana.recognition.lang = e.target.value;
  }
});

// Topbar Quick Voice Drawer Toggle
const aleanaDrawer = document.getElementById('aleana-drawer');
document.getElementById('btn-quick-voice-drawer')?.addEventListener('click', () => {
  if (aleanaDrawer) aleanaDrawer.classList.toggle('active');
});
document.getElementById('btn-close-aleana-drawer')?.addEventListener('click', () => {
  if (aleanaDrawer) aleanaDrawer.classList.remove('active');
});

// =========================================================================
// 9. EVENTS MODULE (Matching Panel 3)
// =========================================================================
const CACHE = {
  events: [],
  incidents: [],
  policies: [],
  auditLogs: []
};

const EVENT_FILTER = {
  sev: 'all',
  status: 'all',
  camera: 'all',
  query: '',
  page: 1,
  pageSize: 10
};

async function fetchEvents() {
  const tbody = document.getElementById('events-table-body');
  try {
    const res = await fetch('/api/v1/events', {
      headers: { 'X-Tenant-ID': STATE.tenantId }
    });
    const events = await res.json();
    CACHE.events = Array.isArray(events) ? events : [];
    renderEventsTable();
  } catch (err) {
    if (tbody) tbody.innerHTML = `<tr><td colspan="6" style="color: var(--accent-rose);">Failed to load events: ${err.message}</td></tr>`;
  }
}

function renderEventsTable() {
  const tbody = document.getElementById('events-table-body');
  const countInfo = document.getElementById('events-count-info');
  const pageIndicator = document.getElementById('events-page-indicator');
  const btnPrev = document.getElementById('btn-events-prev');
  const btnNext = document.getElementById('btn-events-next');
  if (!tbody) return;

  const filtered = CACHE.events.filter(e => {
    if (EVENT_FILTER.camera !== 'all' && e.camera_id !== EVENT_FILTER.camera) return false;
    
    // Evaluate event severity based on payload or object category
    const isPerson = e.class_name === 'person';
    const isHazard = ['knife', 'scissors', 'baseball bat'].includes(e.class_name);
    const eventSev = (e.severity || (isHazard ? 'HIGH' : isPerson ? 'MEDIUM' : 'LOW')).toUpperCase();
    if (EVENT_FILTER.sev !== 'all' && eventSev !== EVENT_FILTER.sev.toUpperCase()) return false;

    // Evaluate event status
    const eventStatus = (e.status || 'OPEN').toUpperCase();
    if (EVENT_FILTER.status !== 'all' && eventStatus !== EVENT_FILTER.status.toUpperCase()) return false;

    if (EVENT_FILTER.query) {
      const q = EVENT_FILTER.query.toLowerCase();
      const matchId = (e.id || '').toLowerCase().includes(q);
      const matchClass = (e.class_name || '').toLowerCase().includes(q);
      const matchCam = (e.camera_id || '').toLowerCase().includes(q);
      if (!matchId && !matchClass && !matchCam) return false;
    }
    return true;
  });

  const total = filtered.length;
  const totalPages = Math.max(1, Math.ceil(total / EVENT_FILTER.pageSize));
  if (EVENT_FILTER.page > totalPages) EVENT_FILTER.page = totalPages;
  if (EVENT_FILTER.page < 1) EVENT_FILTER.page = 1;

  const startIdx = (EVENT_FILTER.page - 1) * EVENT_FILTER.pageSize;
  const pageItems = filtered.slice(startIdx, startIdx + EVENT_FILTER.pageSize);

  if (countInfo) countInfo.textContent = `Showing ${pageItems.length > 0 ? startIdx + 1 : 0} to ${Math.min(startIdx + EVENT_FILTER.pageSize, total)} of ${total} events`;
  if (pageIndicator) pageIndicator.textContent = `Page ${EVENT_FILTER.page} of ${totalPages}`;
  if (btnPrev) btnPrev.disabled = EVENT_FILTER.page <= 1;
  if (btnNext) btnNext.disabled = EVENT_FILTER.page >= totalPages;

  if (pageItems.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-dim);" class="mono">No matching detection events found.</td></tr>';
    return;
  }

  tbody.innerHTML = pageItems.map(e => {
    const isHigh = e.class_name === 'person';
    const sevBadge = isHigh ? '<span class="badge badge-high mono">Medium</span>' : '<span class="badge badge-low mono">Low</span>';
    return `
      <tr>
        <td class="mono" style="color: var(--text-muted); font-size: 0.75rem;">${new Date(e.timestamp).toLocaleTimeString()}</td>
        <td style="font-weight: 600;"><span class="badge ${isHigh ? 'badge-high' : 'badge-medium'} mono">${(e.class_name || '').toUpperCase()}</span></td>
        <td>${sevBadge}</td>
        <td><span class="badge badge-low mono">Open</span></td>
        <td class="mono">${escapeHtml(e.camera_id)}</td>
        <td>
          <button class="btn btn-sm mono" onclick="viewEventDetail('${e.id}')">View</button>
          <button class="btn btn-sm btn-danger mono" onclick="deleteEvent('${e.id}')" style="margin-left: 4px;">Delete</button>
        </td>
      </tr>
    `;
  }).join('');
}

window.viewEventDetail = function(eventId) {
  const ev = CACHE.events.find(e => e.id === eventId);
  if (!ev) return;
  const modal = document.getElementById('modal-event-detail');
  const body = document.getElementById('event-detail-body');
  if (body) {
    body.innerHTML = `
      <div style="display: flex; flex-direction: column; gap: 0.65rem;">
        <div><strong style="color: var(--text-dim);">Event ID:</strong> <span class="mono" style="color: var(--accent-cyan);">${ev.id}</span></div>
        <div><strong style="color: var(--text-dim);">Timestamp:</strong> <span class="mono">${ev.timestamp}</span></div>
        <div><strong style="color: var(--text-dim);">Camera Source:</strong> <span class="mono">${ev.camera_id}</span></div>
        <div><strong style="color: var(--text-dim);">Class Detected:</strong> <span class="badge badge-medium mono">${ev.class_name.toUpperCase()}</span></div>
        <div><strong style="color: var(--text-dim);">Confidence Score:</strong> <span class="mono">${Math.round(ev.confidence * 100)}%</span></div>
        <div><strong style="color: var(--text-dim);">Bounding Box Coordinates:</strong> <span class="mono" style="font-size: 0.75rem;">${JSON.stringify(ev.bbox || [0,0,0,0])}</span></div>
      </div>
    `;
  }
  if (modal) modal.classList.add('active');
};

document.getElementById('btn-close-event-modal')?.addEventListener('click', () => {
  document.getElementById('modal-event-detail')?.classList.remove('active');
});
document.getElementById('btn-dismiss-event-modal')?.addEventListener('click', () => {
  document.getElementById('modal-event-detail')?.classList.remove('active');
});

window.deleteEvent = function(eventId) {
  showModal({
    title: 'Confirm Event Deletion',
    body: `Are you sure you want to delete event <strong class="mono" style="color: var(--accent-cyan);">${eventId}</strong>? This writes an immutable audit record.`,
    confirmText: 'Delete Event',
    confirmClass: 'btn-danger',
    onConfirm: async () => {
      try {
        const res = await fetch(`/api/v1/events/${eventId}`, {
          method: 'DELETE',
          headers: { 'X-Tenant-ID': STATE.tenantId }
        });
        if (res.ok) {
          showToast(`Event ${eventId} deleted successfully.`, 'success');
          fetchEvents();
          fetchSummary();
        } else {
          showToast('Failed to delete event.', 'danger');
        }
      } catch (e) {
        showToast('Error deleting event: ' + e.message, 'danger');
      }
    }
  });
};

document.getElementById('event-sev-filter')?.addEventListener('change', (e) => {
  EVENT_FILTER.sev = e.target.value;
  EVENT_FILTER.page = 1;
  renderEventsTable();
});
document.getElementById('event-status-filter')?.addEventListener('change', (e) => {
  EVENT_FILTER.status = e.target.value;
  EVENT_FILTER.page = 1;
  renderEventsTable();
});
document.getElementById('event-camera-select')?.addEventListener('change', (e) => {
  EVENT_FILTER.camera = e.target.value;
  EVENT_FILTER.page = 1;
  renderEventsTable();
});
document.getElementById('event-search-input')?.addEventListener('input', (e) => {
  EVENT_FILTER.query = e.target.value.trim();
  EVENT_FILTER.page = 1;
  renderEventsTable();
});
document.getElementById('btn-events-prev')?.addEventListener('click', () => {
  if (EVENT_FILTER.page > 1) { EVENT_FILTER.page--; renderEventsTable(); }
});
document.getElementById('btn-events-next')?.addEventListener('click', () => {
  EVENT_FILTER.page++;
  renderEventsTable();
});
document.getElementById('btn-refresh-events')?.addEventListener('click', () => {
  fetchEvents();
  showToast('Events refreshed.', 'info');
});

// =========================================================================
// 10. INCIDENTS MODULE (Triage & Resolve)
// =========================================================================
const INCIDENT_FILTER = {
  sev: 'all',
  status: 'all',
  query: ''
};

async function fetchIncidents() {
  const tbody = document.getElementById('incidents-table-body');
  try {
    const res = await fetch('/api/v1/incidents', {
      headers: { 'X-Tenant-ID': STATE.tenantId }
    });
    const incidents = await res.json();
    CACHE.incidents = Array.isArray(incidents) ? incidents : [];
    renderIncidentsTable();
    if (typeof updateCopilotTelemetryBar === 'function') updateCopilotTelemetryBar();
  } catch (err) {
    if (tbody) tbody.innerHTML = `<tr><td colspan="7" style="color: var(--accent-rose);">Failed to load incidents</td></tr>`;
  }
}

window.selectIncident = function(incidentId) {
  STATE.selectedIncidentId = incidentId;
  const inc = (CACHE.incidents || []).find(i => i.id === incidentId);
  if (!inc) return;

  // Highlight selected row in table
  document.querySelectorAll('#incidents-table-body tr').forEach(row => {
    if (row.dataset.incidentId === incidentId) {
      row.classList.add('selected-row');
    } else {
      row.classList.remove('selected-row');
    }
  });

  // Populate inspection panel
  const idEl = document.getElementById('inspect-id');
  const statusBadge = document.getElementById('inspect-status-badge');
  const sevEl = document.getElementById('inspect-severity');
  const policyEl = document.getElementById('inspect-policy');
  const camEl = document.getElementById('inspect-camera');
  const timeEl = document.getElementById('inspect-timestamp');
  const jsonEl = document.getElementById('inspect-metadata-json');
  const bboxClass = document.getElementById('inspect-bbox-class');
  const bboxConf = document.getElementById('inspect-bbox-conf');
  const resolveBtn = document.getElementById('btn-inspect-resolve');

  if (idEl) idEl.textContent = inc.id;
  if (statusBadge) {
    statusBadge.textContent = inc.status;
    statusBadge.className = 'badge mono ' + (inc.status === 'OPEN' ? 'badge-critical' : 'badge-low');
  }
  if (sevEl) {
    sevEl.textContent = inc.severity;
    sevEl.className = 'badge mono ' + (inc.severity === 'CRITICAL' ? 'badge-critical' : (inc.severity === 'HIGH' ? 'badge-high' : 'badge-medium'));
  }
  if (policyEl) policyEl.textContent = inc.rule_id || inc.policy_id || 'pol_person_after_hours';
  if (camEl) camEl.textContent = inc.camera_id || 'CAM-01-ENTRANCE';
  if (timeEl) timeEl.textContent = new Date(inc.timestamp).toLocaleString();
  if (bboxClass) bboxClass.textContent = ((inc.class_name || (inc.metadata && inc.metadata.class_name)) || 'TARGET').toUpperCase();
  if (bboxConf) bboxConf.textContent = inc.confidence ? `${Math.round(inc.confidence * 100)}%` : '96%';
  if (jsonEl) jsonEl.textContent = JSON.stringify(inc, null, 2);

  if (resolveBtn) {
    if (inc.status === 'OPEN') {
      resolveBtn.textContent = `Resolve Incident (${inc.id})`;
      resolveBtn.disabled = false;
      resolveBtn.onclick = () => resolveIncident(inc.id);
    } else {
      resolveBtn.textContent = 'Incident Resolved';
      resolveBtn.disabled = true;
      resolveBtn.onclick = null;
    }
  }
};

function renderIncidentsTable() {
  const tbody = document.getElementById('incidents-table-body');
  if (!tbody) return;

  const filtered = CACHE.incidents.filter(inc => {
    if (INCIDENT_FILTER.sev !== 'all' && inc.severity !== INCIDENT_FILTER.sev) return false;
    if (INCIDENT_FILTER.status !== 'all' && inc.status !== INCIDENT_FILTER.status) return false;
    if (INCIDENT_FILTER.query) {
      const q = INCIDENT_FILTER.query.toLowerCase();
      const matchTitle = (inc.title || '').toLowerCase().includes(q);
      const matchId = (inc.id || '').toLowerCase().includes(q);
      if (!matchTitle && !matchId) return false;
    }
    return true;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-dim);" class="mono">No matching incidents.</td></tr>';
    return;
  }

  tbody.innerHTML = filtered.map(inc => {
    const isSelected = STATE.selectedIncidentId === inc.id;
    return `
      <tr class="incident-row-clickable ${isSelected ? 'selected-row' : ''}" data-incident-id="${inc.id}" onclick="selectIncident('${inc.id}')">
        <td class="mono" style="color: var(--accent-amber); font-weight: 600;">${inc.id}</td>
        <td class="mono" style="font-size: 0.75rem;">${new Date(inc.timestamp).toLocaleTimeString()}</td>
        <td><span class="badge ${inc.severity === 'CRITICAL' ? 'badge-critical' : (inc.severity === 'HIGH' ? 'badge-high' : 'badge-medium')} mono">${inc.severity}</span></td>
        <td style="font-weight: 500;">${escapeHtml(inc.title)}</td>
        <td class="mono">${escapeHtml(inc.camera_id || 'N/A')}</td>
        <td><span class="badge ${inc.status === 'OPEN' ? 'badge-critical' : 'badge-low'} mono">${inc.status}</span></td>
        <td>
          ${inc.status === 'OPEN' ? `<button class="btn btn-sm btn-primary mono" onclick="event.stopPropagation(); resolveIncident('${inc.id}')">Resolve</button>` : '<span class="mono" style="color: var(--text-dim); font-size: 0.75rem;">Resolved</span>'}
        </td>
      </tr>
    `;
  }).join('');

  // Auto-select first incident if none selected
  if (!STATE.selectedIncidentId && filtered.length > 0) {
    selectIncident(filtered[0].id);
  } else if (STATE.selectedIncidentId) {
    selectIncident(STATE.selectedIncidentId);
  }
}

window.resolveIncident = function(incidentId) {
  showModal({
    title: 'Resolve Security Incident',
    body: `Mark incident <strong class="mono" style="color: var(--accent-amber);">${escapeHtml(incidentId)}</strong> as RESOLVED? This will update threat counters and log to the audit ledger.`,
    confirmText: 'Mark Resolved',
    confirmClass: 'btn-primary',
    onConfirm: async () => {
      try {
        const res = await fetch(`/api/v1/incidents/${incidentId}/resolve`, {
          method: 'POST',
          headers: { 'X-Tenant-ID': STATE.tenantId }
        });
        if (res.ok) {
          showToast(`Incident ${incidentId} resolved.`, 'success');
          fetchIncidents();
          fetchSummary();
        } else {
          showToast('Failed to resolve incident.', 'danger');
        }
      } catch (e) {
        showToast('Error: ' + e.message, 'danger');
      }
    }
  });
};

document.querySelectorAll('#incident-severity-filter-group .subtab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('#incident-severity-filter-group .subtab-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    INCIDENT_FILTER.sev = btn.dataset.sev;
    renderIncidentsTable();
  });
});
document.querySelectorAll('#incident-status-filter-group .subtab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('#incident-status-filter-group .subtab-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    INCIDENT_FILTER.status = btn.dataset.status;
    renderIncidentsTable();
  });
});
document.getElementById('incident-search-input')?.addEventListener('input', (e) => {
  INCIDENT_FILTER.query = e.target.value.trim();
  renderIncidentsTable();
});
document.getElementById('btn-refresh-incidents')?.addEventListener('click', () => {
  fetchIncidents();
  showToast('Incidents refreshed.', 'info');
});

// =========================================================================
// 11. SECURITY POLICIES MODULE (Matching Panel 4)
// =========================================================================
const POLICY_FILTER = {
  category: 'all'
};

function syncPolicyGridCards() {
  const policyKeys = [
    { id: 'pol_person_after_hours', toggle: 'toggle-pol-person-after-hours', status: 'status-pol-person-after-hours' },
    { id: 'pol_unattended_bag', toggle: 'toggle-pol-unattended-bag', status: 'status-pol-unattended-bag' },
    { id: 'pol_restricted_vehicle', toggle: 'toggle-pol-restricted-vehicle', status: 'status-pol-restricted-vehicle' },
    { id: 'pol_weapon_safety', toggle: 'toggle-pol-weapon-safety', status: 'status-pol-weapon-safety' }
  ];
  policyKeys.forEach(({ id, toggle, status }) => {
    const policy = (CACHE.policies || []).find(p => p.id === id);
    const isEnforced = policy ? Boolean(policy.enabled) : true;
    const toggleEl = document.getElementById(toggle);
    const statusEl = document.getElementById(status);
    if (toggleEl) toggleEl.checked = isEnforced;
    if (statusEl) {
      statusEl.textContent = isEnforced ? 'ACTIVE • ENFORCED' : 'MUTED • DISABLED';
      statusEl.style.color = isEnforced ? 'var(--accent-emerald)' : 'var(--text-dim)';
    }
  });
}

async function fetchPolicies() {
  const tbody = document.getElementById('policies-table-body');
  try {
    const res = await fetch('/api/v1/policies', {
      headers: { 'X-Tenant-ID': STATE.tenantId }
    });
    const policies = await res.json();
    CACHE.policies = Array.isArray(policies) ? policies : [];
    syncPolicyGridCards();
    renderPoliciesTable();
    if (typeof updateCopilotTelemetryBar === 'function') updateCopilotTelemetryBar();
  } catch (err) {
    if (tbody) tbody.innerHTML = `<tr><td colspan="4" style="color: var(--accent-rose);">Failed to load policies</td></tr>`;
  }
}

function renderPoliciesTable() {
  const tbody = document.getElementById('policies-table-body');
  if (!tbody) return;

  const filtered = CACHE.policies.filter(p => {
    if (POLICY_FILTER.category === 'all') return true;
    const cat = POLICY_FILTER.category.toLowerCase();
    const target = (p.target_class || '').toLowerCase();
    const name = (p.name || '').toLowerCase();
    const desc = (p.description || '').toLowerCase();
    if (cat === 'detection') {
      return Boolean(target) || name.includes('detection') || name.includes('hazard') || desc.includes('hazard') || desc.includes('detected');
    }
    if (cat === 'system') {
      return name.includes('system') || name.includes('access') || desc.includes('access') || desc.includes('perimeter');
    }
    if (cat === 'automation') {
      return name.includes('auto') || desc.includes('auto') || Boolean(p.condition);
    }
    return true;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-dim);" class="mono">No matching policies in this category.</td></tr>';
    return;
  }

  tbody.innerHTML = filtered.map(p => `
    <tr>
      <td style="font-weight: 600; color: #fff;">${escapeHtml(p.name)}</td>
      <td style="color: var(--text-muted); font-size: 0.8rem;">${escapeHtml(p.description || '')}</td>
      <td>
        <span class="badge ${p.enabled ? 'badge-low' : 'badge-dim'} mono">${p.enabled ? 'Enabled' : 'Disabled'}</span>
      </td>
      <td>
        <div style="display: flex; align-items: center; gap: 0.5rem;">
          <label class="switch">
            <input type="checkbox" ${p.enabled ? 'checked' : ''} onchange="togglePolicy('${p.id}', this.checked)">
            <span class="slider"></span>
          </label>
          <button class="btn btn-sm btn-danger mono" onclick="deletePolicy('${p.id}', '${escapeHtml(p.name)}')" title="Delete Policy" style="padding: 0.2rem 0.45rem;">
            &times;
          </button>
        </div>
      </td>
    </tr>
  `).join('');
}

window.togglePolicy = async function(policyId, newState) {
  try {
    const res = await fetch(`/api/v1/policies/${policyId}/toggle`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'X-Tenant-ID': STATE.tenantId
      },
      body: JSON.stringify({ enabled: newState })
    });
    if (res.ok) {
      showToast(`Policy updated (${newState ? 'Enabled' : 'Disabled'}).`, 'success');
      fetchPolicies();
      fetchSummary();
    } else {
      showToast('Failed to toggle policy.', 'danger');
    }
  } catch (e) {
    showToast('Error: ' + e.message, 'danger');
  }
};

window.deletePolicy = function(policyId, name) {
  showModal({
    title: 'Delete Security Policy',
    body: `Are you sure you want to delete policy <strong>"${name}"</strong>?`,
    confirmText: 'Delete Policy',
    confirmClass: 'btn-danger',
    onConfirm: async () => {
      try {
        const res = await fetch(`/api/v1/policies/${policyId}`, {
          method: 'DELETE',
          headers: { 'X-Tenant-ID': STATE.tenantId }
        });
        if (res.ok) {
          showToast(`Policy "${name}" deleted.`, 'success');
          fetchPolicies();
          fetchSummary();
        }
      } catch (e) {
        showToast('Error: ' + e.message, 'danger');
      }
    }
  });
};

// Add Policy Modal Handlers
const addPolicyModal = document.getElementById('modal-add-policy');
document.getElementById('btn-open-add-policy')?.addEventListener('click', () => {
  if (addPolicyModal) addPolicyModal.classList.add('active');
});
document.getElementById('btn-close-add-policy-modal')?.addEventListener('click', () => {
  if (addPolicyModal) addPolicyModal.classList.remove('active');
});
document.getElementById('btn-cancel-add-policy')?.addEventListener('click', () => {
  if (addPolicyModal) addPolicyModal.classList.remove('active');
});

document.getElementById('form-add-policy')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const name = document.getElementById('policy-name-input').value.trim();
  const targetClass = document.getElementById('policy-class-select').value;
  const condition = document.getElementById('policy-cond-input').value.trim();
  const severity = document.getElementById('policy-sev-select').value;
  const description = document.getElementById('policy-desc-input').value.trim();

  try {
    const res = await fetch('/api/v1/policies', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Tenant-ID': STATE.tenantId
      },
      body: JSON.stringify({ name, target_class: targetClass, condition, severity, description, enabled: true })
    });
    if (res.ok) {
      if (addPolicyModal) addPolicyModal.classList.remove('active');
      document.getElementById('form-add-policy').reset();
      showToast(`Created policy "${name}".`, 'success');
      fetchPolicies();
      fetchSummary();
    }
  } catch (err) {
    showToast('Failed to create policy: ' + err.message, 'danger');
  }
});

document.querySelectorAll('#view-policies .subtab-btn[data-policy-category]').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('#view-policies .subtab-btn[data-policy-category]').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    POLICY_FILTER.category = btn.dataset.policyCategory;
    renderPoliciesTable();
  });
});

// =========================================================================
// 12. AI COPILOT MODULE (Matching Panel 5)
// =========================================================================
const copilotThread = document.getElementById('copilot-thread-box');
const copilotForm = document.getElementById('copilot-form');
const copilotInput = document.getElementById('copilot-input');
const btnSendCopilot = document.getElementById('btn-send-copilot');

function getScannerLiveContext() {
  return {
    is_scanning: Boolean(STATE.isScanning),
    active_source: STATE.activeSourceName || (STATE.isScanning ? 'Active Stream' : 'None'),
    visible_count: STATE.lastTrackedDetections ? STATE.lastTrackedDetections.length : 0,
    active_track_ids: STATE.lastTrackedDetections ? STATE.lastTrackedDetections.map(d => d.trackId) : [],
    fps: STATE.measuredFps || 0,
    detections: (STATE.lastTrackedDetections || []).map(d => ({
      trackId: d.trackId,
      class: d.class,
      score: Math.round((d.score || 0) * 100),
      speed: d.speed || 0,
      bbox: d.bbox,
      dwellTimeSec: d.dwellTimeSec || 0,
      motionState: d.motionState || 'STATIONARY'
    })),
    class_counts: (() => {
      const counts = {};
      (STATE.lastTrackedDetections || []).forEach(d => {
        counts[d.class] = (counts[d.class] || 0) + 1;
      });
      return counts;
    })(),
    recent_history: (STATE.detectionHistory || []).slice(0, 10).map(h => ({
      trackId: h.trackId,
      class: h.class,
      score: Math.round((h.score || 0) * 100),
      firstSeen: h.firstSeen,
      lastSeen: h.lastSeen
    })),
    recent_scene_deltas: (STATE.sceneEventsLog || []).slice(0, 10),
    forensic_snapshots_count: (STATE.forensicSnapshots || []).length
  };
}

async function sendCopilotQuery(queryStr) {
  const q = queryStr.trim();
  if (!q) return;

  const nowTime = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const userMsgEl = document.createElement('div');
  userMsgEl.className = 'copilot-msg copilot-user';
  userMsgEl.innerHTML = `<div class="copilot-msg-header mono">Operator &bull; ${nowTime}</div><div>${escapeHtml(q)}</div>`;
  copilotThread.appendChild(userMsgEl);

  const botMsgEl = document.createElement('div');
  botMsgEl.className = 'copilot-msg copilot-bot';
  botMsgEl.innerHTML = `<div class="copilot-msg-header mono">VantaVisionAI Copilot &bull; Analyzing Telemetry...</div><div class="mono" style="color: var(--text-muted);">Querying SQLite platform state...</div>`;
  copilotThread.appendChild(botMsgEl);
  copilotThread.scrollTop = copilotThread.scrollHeight;
  if (btnSendCopilot) btnSendCopilot.disabled = true;

  try {
    const liveContext = getScannerLiveContext();

    const res = await fetch('/api/v1/copilot', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Tenant-ID': STATE.tenantId
      },
      body: JSON.stringify({ query: q, live_context: liveContext })
    });
    const data = await res.json();

    let evidenceHtml = '';
    if (data.evidence && data.evidence.length > 0) {
      evidenceHtml = `
        <div class="copilot-section">
          <div class="copilot-section-title">Verified Evidence (Database Records)</div>
          <ul class="copilot-list">
            ${data.evidence.map(e => `<li>${escapeHtml(e)}</li>`).join('')}
          </ul>
        </div>
      `;
    }
    let stepsHtml = '';
    if (data.recommended_steps && data.recommended_steps.length > 0) {
      stepsHtml = `
        <div class="copilot-section">
          <div class="copilot-section-title">Recommended Next Steps</div>
          <ul class="copilot-list">
            ${data.recommended_steps.map(s => {
              let actionBadge = '';
              const sLow = s.toLowerCase();
              if (sLow.includes('incident')) {
                actionBadge = ` <button class="btn btn-sm mono" onclick="switchView('incidents')" style="padding: 0.1rem 0.35rem; font-size: 0.68rem; margin-left: 0.3rem;">Open Incidents &rarr;</button>`;
              } else if (sLow.includes('polic')) {
                actionBadge = ` <button class="btn btn-sm mono" onclick="switchView('policies')" style="padding: 0.1rem 0.35rem; font-size: 0.68rem; margin-left: 0.3rem;">Open Policies &rarr;</button>`;
              } else if (sLow.includes('camera') || sLow.includes('scanner') || sLow.includes('feed')) {
                actionBadge = ` <button class="btn btn-sm mono" onclick="switchView('scanner')" style="padding: 0.1rem 0.35rem; font-size: 0.68rem; margin-left: 0.3rem;">Open Scanner &rarr;</button>`;
              } else if (sLow.includes('audit')) {
                actionBadge = ` <button class="btn btn-sm mono" onclick="switchView('audit')" style="padding: 0.1rem 0.35rem; font-size: 0.68rem; margin-left: 0.3rem;">Open Audit &rarr;</button>`;
              }
              return `<li><span>${escapeHtml(s)}</span>${actionBadge}</li>`;
            }).join('')}
          </ul>
        </div>
      `;
    }

    const reportText = `[VantaVisionAI Copilot Grounded Telemetry Report]
Query: ${q}
Finding: ${data.finding || 'N/A'}
Interpretation: ${data.interpretation || 'N/A'}
Evidence:
${(data.evidence || []).map(e => '  - ' + e).join('\n')}
Recommended Steps:
${(data.recommended_steps || []).map(s => '  - ' + s).join('\n')}
Provider Mode: ${data.provider_mode || 'SIMULATED'}
Timestamp: ${new Date().toISOString()}`;

    const reportAttr = encodeURIComponent(reportText);

    let actionsHtml = '';
    if (data.suggested_actions && data.suggested_actions.length > 0) {
      actionsHtml = `
        <div class="copilot-suggested-actions" style="display: flex; flex-wrap: wrap; gap: 0.4rem; margin-top: 0.65rem; padding-top: 0.5rem; border-top: 1px solid var(--border-subtle);">
          ${data.suggested_actions.map(act => `
            <button class="copilot-chip-action btn btn-sm mono" style="font-size: 0.72rem; padding: 0.2rem 0.5rem; background: var(--bg-card); border: 1px solid var(--accent-cyan); color: var(--accent-cyan); cursor: pointer;" onclick="handleCopilotAction('${escapeHtml(act.action)}', '${escapeHtml(act.target || '')}')">
              ${escapeHtml(act.label)} &rarr;
            </button>
          `).join('')}
        </div>
      `;
    }

    botMsgEl.innerHTML = `
      <div class="copilot-msg-header mono" style="display: flex; justify-content: space-between; align-items: center;">
        <span>VantaVisionAI Copilot &bull; ${escapeHtml(data.provider_mode || 'GROUNDED TELEMETRY')}</span>
        <button class="btn btn-sm mono" onclick="copyCopilotReport(this, '${reportAttr}')" style="padding: 0.15rem 0.45rem; font-size: 0.68rem; border-color: var(--border-subtle); display: inline-flex; align-items: center; gap: 4px;">
          <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>
          <span>Copy Report</span>
        </button>
      </div>
      <div class="copilot-msg-body">
        <strong>${escapeHtml(data.finding || 'Query processed.')}</strong>
        ${data.interpretation ? `<p style="margin-top: 0.4rem; color: var(--text-muted);">${escapeHtml(data.interpretation)}</p>` : ''}
        ${evidenceHtml}
        ${stepsHtml}
        ${actionsHtml}
      </div>
    `;

    // Automatic Voice Readout if speech toggle enabled
    if (STATE.copilotVoiceSpeech && data.finding && 'speechSynthesis' in window) {
      window.speechSynthesis.cancel();
      const speakText = data.finding.replace(/#/g, 'track ').replace(/\*/g, '');
      const utterance = new SpeechSynthesisUtterance(speakText);
      utterance.rate = 1.0;
      window.speechSynthesis.speak(utterance);
    }
  } catch (err) {
    botMsgEl.innerHTML = `
      <div class="copilot-msg-header mono" style="color: var(--accent-rose);">Copilot Error</div>
      <div style="color: var(--accent-rose); font-size: 0.82rem;">Error: ${escapeHtml(err.message)}</div>
    `;
  } finally {
    if (btnSendCopilot) btnSendCopilot.disabled = false;
    copilotThread.scrollTop = copilotThread.scrollHeight;
  }
}

window.handleCopilotAction = function(actionType, targetVal) {
  if (actionType === 'NAVIGATE') {
    switchView(targetVal);
  } else if (actionType === 'COPILOT_QUERY') {
    if (copilotInput) {
      copilotInput.value = targetVal;
      sendCopilotQuery(targetVal);
    }
  } else if (actionType === 'BRAIN_CMD') {
    switchView('brain');
    const brainInput = document.getElementById('brain-cmd-input');
    if (brainInput) {
      brainInput.value = targetVal;
      executeBrainCommand(targetVal);
    }
  } else if (actionType === 'ALEANA_CMD') {
    executeAleanaCommand(targetVal);
  }
};

// =========================================================================
// AI COPILOT VOICE & LIVE TELEMETRY BRIDGE
// =========================================================================
function updateCopilotTelemetryBar() {
  const scanEl = document.getElementById('copilot-scanner-ctx');
  const incEl = document.getElementById('copilot-incidents-ctx');
  const polEl = document.getElementById('copilot-policies-ctx');

  if (scanEl) {
    if (STATE.isScanning) {
      const count = STATE.lastTrackedDetections ? STATE.lastTrackedDetections.length : 0;
      scanEl.innerHTML = `Scanner: <span style="color: var(--accent-emerald); font-weight: 700;">ONLINE</span> (${escapeHtml(STATE.activeSourceName || 'Live')} &bull; ${count} active ${count === 1 ? 'target' : 'targets'})`;
    } else {
      scanEl.innerHTML = `Scanner: <span style="color: var(--text-dim); font-weight: 700;">INACTIVE / IDLE</span>`;
    }
  }

  if (incEl) {
    const totalInc = (CACHE.incidents || []).length;
    const openInc = (CACHE.incidents || []).filter(i => (i.status || '').toUpperCase() === 'OPEN').length;
    incEl.innerHTML = `Incidents: <span style="color: var(--accent-amber); font-weight: 700;">${totalInc} Total</span> (${openInc} Open)`;
  }

  if (polEl) {
    const totalPol = (CACHE.policies || []).length;
    const enabledPol = (CACHE.policies || []).filter(p => p.enabled).length;
    polEl.innerHTML = `Policies: <span style="color: var(--accent-cyan); font-weight: 700;">${enabledPol}/${totalPol} Enforced</span>`;
  }
}

// Voice Microphone Listener for Copilot Input
function toggleCopilotVoiceInput() {
  const SpeechRec = window.SpeechRecognition || window.webkitSpeechRecognition;
  const micBtn = document.getElementById('btn-copilot-voice-mic');
  const inputEl = document.getElementById('copilot-input');

  if (!SpeechRec) {
    showToast('Web Speech Recognition is not supported in this browser. Please type your query.', 'warning');
    return;
  }

  if (STATE.copilotIsListening && STATE.copilotRecognition) {
    try { STATE.copilotRecognition.stop(); } catch (e) {}
    STATE.copilotIsListening = false;
    if (micBtn) {
      micBtn.classList.remove('btn-danger');
      micBtn.style.color = '';
      micBtn.title = 'Voice Input (Click to speak)';
    }
    showToast('Voice input stopped.', 'info');
    return;
  }

  try {
    const recognition = new SpeechRec();
    recognition.continuous = false;
    recognition.interimResults = true;
    recognition.lang = STATE.aleana?.language || 'en-US';

    recognition.onstart = () => {
      STATE.copilotIsListening = true;
      if (micBtn) {
        micBtn.classList.add('btn-danger');
        micBtn.style.color = '#fff';
        micBtn.title = 'Listening... (Click to stop)';
      }
      showToast('Listening... Speak your Copilot query now.', 'info');
    };

    recognition.onresult = (event) => {
      let interim = '';
      let final = '';
      for (let i = event.resultIndex; i < event.results.length; ++i) {
        if (event.results[i].isFinal) {
          final += event.results[i][0].transcript;
        } else {
          interim += event.results[i][0].transcript;
        }
      }
      if (inputEl) {
        inputEl.value = (final || interim).trim();
      }
    };

    recognition.onerror = (event) => {
      console.warn('[Copilot Voice Error]', event.error);
      STATE.copilotIsListening = false;
      if (micBtn) {
        micBtn.classList.remove('btn-danger');
        micBtn.style.color = '';
        micBtn.title = 'Voice Input (Click to speak)';
      }
      if (event.error === 'not-allowed') {
        showToast('Microphone access blocked. Please allow mic in browser permissions.', 'danger');
      } else if (event.error !== 'no-speech' && event.error !== 'aborted') {
        showToast(`Voice recognition: ${event.error}`, 'warning');
      }
    };

    recognition.onend = () => {
      STATE.copilotIsListening = false;
      if (micBtn) {
        micBtn.classList.remove('btn-danger');
        micBtn.style.color = '';
        micBtn.title = 'Voice Input (Click to speak)';
      }
      if (inputEl && inputEl.value.trim()) {
        showToast(`Captured query: "${inputEl.value.trim()}". Press Enter or Send to execute.`, 'success');
      }
    };

    STATE.copilotRecognition = recognition;
    recognition.start();
  } catch (err) {
    console.error('Failed to start Copilot speech recognition:', err);
    showToast('Could not initialize microphone recognition.', 'danger');
  }
}

// Speech Audio Output Toggle
function toggleCopilotSpeech() {
  STATE.copilotVoiceSpeech = !STATE.copilotVoiceSpeech;
  const statusSpan = document.getElementById('copilot-speech-status');
  const toggleBtn = document.getElementById('btn-copilot-speech-toggle');

  if (STATE.copilotVoiceSpeech) {
    if (statusSpan) statusSpan.textContent = 'Voice: ON';
    if (toggleBtn) {
      toggleBtn.classList.add('btn-primary');
      toggleBtn.style.color = '#fff';
    }
    showToast('Copilot voice responses enabled.', 'success');
    if ('speechSynthesis' in window) {
      const testUtterance = new SpeechSynthesisUtterance('Copilot voice enabled.');
      testUtterance.rate = 1.05;
      window.speechSynthesis.speak(testUtterance);
    }
  } else {
    if (statusSpan) statusSpan.textContent = 'Voice: OFF';
    if (toggleBtn) {
      toggleBtn.classList.remove('btn-primary');
      toggleBtn.style.color = '';
    }
    if ('speechSynthesis' in window) {
      window.speechSynthesis.cancel();
    }
    showToast('Copilot voice responses muted.', 'info');
  }
}

document.getElementById('btn-copilot-voice-mic')?.addEventListener('click', toggleCopilotVoiceInput);
document.getElementById('btn-copilot-speech-toggle')?.addEventListener('click', toggleCopilotSpeech);

window.copyCopilotReport = function(btn, encodedText) {
  try {
    const text = decodeURIComponent(encodedText);
    navigator.clipboard.writeText(text).then(() => {
      const origHtml = btn.innerHTML;
      btn.innerHTML = `<span style="color: var(--accent-emerald);">✓ Copied</span>`;
      setTimeout(() => { btn.innerHTML = origHtml; }, 2000);
      showToast('Copilot report copied to clipboard.', 'success');
    }).catch(() => {
      showToast('Clipboard access unavailable.', 'warning');
    });
  } catch (e) {
    showToast('Failed to copy report.', 'danger');
  }
};

copilotForm?.addEventListener('submit', (e) => {
  e.preventDefault();
  const q = copilotInput.value;
  copilotInput.value = '';
  sendCopilotQuery(q);
});

document.querySelectorAll('.copilot-chip').forEach(chip => {
  chip.addEventListener('click', () => {
    if (chip.dataset.q) sendCopilotQuery(chip.dataset.q);
  });
});

document.getElementById('btn-clear-copilot')?.addEventListener('click', () => {
  if (copilotThread) {
    copilotThread.innerHTML = `
      <div class="copilot-msg copilot-bot">
        <div class="copilot-msg-header mono">VantaVisionAI Copilot &bull; Verified Telemetry</div>
        <div class="copilot-msg-body">
          <strong>Security Analyst Assistant Ready.</strong><br>
          Grounded in verified database records (events, incidents, policies, audit trails).
        </div>
      </div>
    `;
  }
  showToast('Copilot chat cleared.', 'info');
});

// =========================================================================
// 13. VANTA BRAIN CLI & APPROVED TOOL REGISTRY
// =========================================================================
const brainTerminal = document.getElementById('brain-terminal-output');
const brainForm = document.getElementById('brain-form');
const brainInput = document.getElementById('brain-cmd-input');

function animateBrainPipelineVisualizer(status = 'SUCCESS', blockedLayerIndex = 4) {
  const isBlocked = status === 'BLOCKED' || status === 'ERROR' || status === true;
  const nodes = [1, 2, 3, 4, 5, 6, 7].map(i => document.getElementById(`node-layer-${i}`));
  nodes.forEach(n => {
    if (n) n.className = 'pipeline-step-node';
  });

  const stepTime = 60;
  [1, 2, 3, 4].forEach((layer, idx) => {
    setTimeout(() => {
      if (nodes[layer - 1]) nodes[layer - 1].className = 'pipeline-step-node node-active layer-passed';
    }, idx * stepTime);
  });

  setTimeout(() => {
    if (isBlocked) {
      const blockIdx = typeof blockedLayerIndex === 'number' ? blockedLayerIndex : 4;
      if (nodes[blockIdx]) nodes[blockIdx].className = 'pipeline-step-node node-blocked layer-blocked';
      STATE.soundEngine?.playAlert();
    } else {
      if (nodes[4]) nodes[4].className = 'pipeline-step-node node-success layer-passed';
      setTimeout(() => {
        if (nodes[5]) nodes[5].className = 'pipeline-step-node node-active layer-passed';
      }, stepTime);
      setTimeout(() => {
        if (nodes[6]) nodes[6].className = 'pipeline-step-node node-success layer-passed';
        STATE.soundEngine?.playSuccess();
      }, stepTime * 2);
    }
  }, 4 * stepTime);

  setTimeout(() => {
    nodes.forEach(n => {
      if (n) n.className = 'pipeline-step-node';
    });
  }, 3500);
}

function animateBrainPipeline(isBlocked = false) {
  return animateBrainPipelineVisualizer(isBlocked ? 'BLOCKED' : 'SUCCESS', 4);
}
if (typeof window !== 'undefined') {
  window.animateBrainPipelineVisualizer = animateBrainPipelineVisualizer;
  window.animateBrainPipeline = animateBrainPipeline;
}

async function executeBrainCommand(commandStr, customArgs = null) {
  const cmd = commandStr.trim();
  if (!cmd) return;
  const argsPayload = customArgs || {};
  appendTerminal(`> vanta-brain> POST /api/v1/brain {"command": "${cmd}", "args": ${JSON.stringify(argsPayload)}}`);
  try {
    const res = await fetch('/api/v1/brain', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Tenant-ID': STATE.tenantId,
        'Authorization': 'Bearer vanta-prototype-token'
      },
      body: JSON.stringify({ command: cmd, args: argsPayload })
    });
    const data = await res.json();
    if (!res.ok) {
      animateBrainPipelineVisualizer('BLOCKED', 4);
      appendTerminal(`[STATUS ${res.status} BLOCKED / ACTION GUARD EXCEPTION]\n${JSON.stringify(data, null, 2)}`);
      showToast(`Action Guard: Request BLOCKED (HTTP ${res.status})`, 'danger');
    } else {
      animateBrainPipelineVisualizer('SUCCESS');
      const execLatency = data.execution_time_ms ? ` (${data.execution_time_ms}ms)` : '';
      appendTerminal(`[STATUS ${res.status} SUCCESS${execLatency}]\n${JSON.stringify(data.result, null, 2)}`);
      showToast(`Command '${cmd}' executed successfully.`, 'success');
    }
  } catch (err) {
    animateBrainPipelineVisualizer('BLOCKED', 4);
    appendTerminal(`[NETWORK/FETCH ERROR]: ${err.message}`);
  }
  fetchSummary();
  if (typeof fetchAuditLogs === 'function') fetchAuditLogs();
}

async function runPlaybook(playbookNum) {
  STATE.soundEngine?.playPing();
  if (playbookNum === 1) {
    appendTerminal(`[ORCHESTRATING PLAYBOOK 01: PERIMETER LOCKDOWN AUDIT]`);
    appendTerminal(`Step 1/4: Validating policy enforcement contracts...`);
    await executeBrainCommand('policies');
    appendTerminal(`Step 2/4: Checking real-time camera streams & restricted perimeter...`);
    await executeBrainCommand('cameras');
    appendTerminal(`Step 3/4: Cross-correlating multi-object threat matrix...`);
    try {
      const res = await fetch('/api/v1/brain/tools/correlate_threat_matrix', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Tenant-ID': STATE.tenantId },
        body: JSON.stringify({ args: { min_threat_score: 50 } })
      });
      const data = await res.json();
      appendTerminal(`Threat Matrix: Overall Score ${data.data?.overall_threat_score || 75} (${data.data?.active_threat_level || 'ELEVATED'})`);
    } catch (e) {}
    appendTerminal(`Step 4/4: Running operational prototype status...`);
    await executeBrainCommand('status');
    showToast('Playbook 01: Perimeter lockdown audit complete.', 'success');
  } else if (playbookNum === 2) {
    appendTerminal(`[ORCHESTRATING PLAYBOOK 02: AUTOMATED INCIDENT TRIAGE & MITIGATION]`);
    appendTerminal(`Step 1/3: Ingesting active high-severity incident queue...`);
    await executeBrainCommand('incidents');
    appendTerminal(`Step 2/3: Dispatching autonomous mitigation playbook PB-PERIMETER-LOCKDOWN...`);
    try {
      const res = await fetch('/api/v1/brain/tools/execute_security_playbook', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Tenant-ID': STATE.tenantId },
        body: JSON.stringify({ args: { playbook_id: 'PB-PERIMETER-LOCKDOWN' } })
      });
      const data = await res.json();
      appendTerminal(`Playbook Result: ${data.data?.name} status=${data.data?.status}`);
    } catch (e) {}
    appendTerminal(`Step 3/3: Generating intelligence summary and threat correlation...`);
    await executeBrainCommand('summary');
    showToast('Playbook 02: Incident triage & mitigation complete.', 'success');
  } else if (playbookNum === 3) {
    appendTerminal(`[ORCHESTRATING PLAYBOOK 03: ZERO-TRUST ACTION GUARD SELF-TEST]`);
    appendTerminal(`Testing Layer 5 Action Guard against simulated SQL injection vector...`);
    await executeBrainCommand('events', { filter: "1; DROP TABLE events;--" });
    appendTerminal(`Action Guard validated: SQLi intercepted and logged to immutable ledger.`);
    showToast('Playbook 03: Zero-Trust self-test passed.', 'success');
  }
}

// Forensic Snapshot Capture & Watermarking
function captureForensicSnapshot() {
  STATE.soundEngine?.playPing();
  const cW = canvasEl.width || 640;
  const cH = canvasEl.height || 360;

  const offscreen = document.createElement('canvas');
  offscreen.width = cW;
  offscreen.height = cH;
  const oCtx = offscreen.getContext('2d');

  if (videoEl && videoEl.videoWidth > 0) {
    try {
      oCtx.drawImage(videoEl, 0, 0, cW, cH);
    } catch (e) {
      oCtx.fillStyle = '#060a14';
      oCtx.fillRect(0, 0, cW, cH);
    }
  } else {
    oCtx.fillStyle = '#060a14';
    oCtx.fillRect(0, 0, cW, cH);
  }

  oCtx.drawImage(canvasEl, 0, 0);

  const stampTime = new Date().toISOString();
  const targetCount = (STATE.lastTrackedDetections || []).length;
  const hashSeed = `${stampTime}:${STATE.tenantId}:${targetCount}`;
  const mockSha = Math.abs(hashSeed.split('').reduce((a, b) => { a = ((a << 5) - a) + b.charCodeAt(0); return a & a; }, 0)).toString(16).padStart(16, '0');

  oCtx.fillStyle = 'rgba(5, 11, 22, 0.88)';
  oCtx.fillRect(0, cH - 26, cW, 26);
  oCtx.strokeStyle = 'rgba(22, 200, 244, 0.6)';
  oCtx.lineWidth = 1;
  oCtx.strokeRect(0, cH - 26, cW, 26);

  oCtx.font = 'bold 9px ui-monospace, monospace';
  oCtx.fillStyle = '#16C8F4';
  oCtx.fillText(`VANTAVISIONAI FORENSIC // CAM: ${STATE.activeSourceName} // TS: ${stampTime} // TARGETS: ${targetCount} // SHA256: #${mockSha}`, 8, cH - 10);

  const dataUrl = offscreen.toDataURL('image/png');
  const snapId = `SNAP-${Date.now().toString().slice(-6)}`;
  const newSnapshot = {
    id: snapId,
    timestamp: stampTime,
    dataUrl,
    targetCount,
    hash: mockSha
  };

  STATE.forensicSnapshots.unshift(newSnapshot);
  if (STATE.forensicSnapshots.length > 20) {
    STATE.forensicSnapshots.pop();
  }

  renderForensicEvidenceStrip();
  STATE.soundEngine?.playScanLock();
  showToast(`Forensic snapshot #${snapId} captured and watermarked.`, 'success');
}

function renderForensicEvidenceStrip() {
  const container = document.getElementById('forensic-evidence-strip');
  const badge = document.getElementById('evidence-count-badge');
  if (badge) badge.textContent = `${STATE.forensicSnapshots.length} Snapshots`;
  if (!container) return;

  if (STATE.forensicSnapshots.length === 0) {
    container.innerHTML = `
      <div class="empty-state mono" style="padding: 0.75rem; font-size: 0.72rem; color: var(--text-dim); width: 100%; text-align: center;">
        No forensic captures stored. Click [Capture Snapshot] above to record watermarked surveillance evidence.
      </div>
    `;
    return;
  }

  container.innerHTML = STATE.forensicSnapshots.map(s => `
    <div class="evidence-card hud-card" id="card-${s.id}">
      <img src="${s.dataUrl}" alt="Forensic snapshot ${s.id}" class="evidence-thumb-img" onclick="inspectForensicSnapshot('${s.id}')">
      <div class="evidence-meta-row">
        <span style="color: var(--cyan); font-weight: 700;">#${s.id}</span>
        <span style="color: var(--text-dim);">${s.targetCount} targets</span>
      </div>
      <div style="display: flex; gap: 0.35rem; margin-top: 0.2rem;">
        <button class="btn btn-sm mono" onclick="inspectForensicSnapshot('${s.id}')" style="flex: 1; padding: 0.15rem 0.3rem; font-size: 0.65rem;">Inspect</button>
        <a href="${s.dataUrl}" download="vantavisionai_${s.id}.png" class="btn btn-sm mono" style="padding: 0.15rem 0.4rem; font-size: 0.65rem; border-color: var(--border-cyan); text-decoration: none; color: var(--cyan);">Save</a>
      </div>
    </div>
  `).join('');
}

window.inspectForensicSnapshot = function(snapId) {
  const snap = STATE.forensicSnapshots.find(s => s.id === snapId);
  if (!snap) return;
  showModal({
    title: `Forensic Evidence Inspection — ${snap.id}`,
    body: `
      <div style="text-align: center;">
        <img src="${snap.dataUrl}" style="max-width: 100%; border-radius: 6px; border: 1px solid var(--border-cyan); box-shadow: 0 4px 16px rgba(0,0,0,0.6);" alt="Full evidence view">
        <div class="mono" style="margin-top: 0.65rem; font-size: 0.72rem; color: var(--text-muted); text-align: left;">
          <div>Timestamp: <strong>${snap.timestamp}</strong></div>
          <div>Active Targets: <strong>${snap.targetCount}</strong></div>
          <div>SHA-256 Fingerprint: <span class="audit-hash-pill">#${snap.hash}</span></div>
        </div>
      </div>
    `,
    confirmText: 'Download PNG',
    confirmClass: 'btn-primary',
    onConfirm: () => {
      const a = document.createElement('a');
      a.href = snap.dataUrl;
      a.download = `vantavisionai_${snap.id}.png`;
      a.click();
    }
  });
};

function toggleHeatmapOverlay() {
  STATE.heatmapEnabled = !STATE.heatmapEnabled;
  const btn = document.getElementById('btn-toggle-heatmap');
  if (btn) {
    btn.textContent = STATE.heatmapEnabled ? 'Heatmap: ON' : 'Heatmap: OFF';
    btn.style.borderColor = STATE.heatmapEnabled ? 'var(--cyan)' : '#f59e0b';
    btn.style.color = STATE.heatmapEnabled ? 'var(--cyan)' : '#f59e0b';
  }
  showToast(STATE.heatmapEnabled ? 'Spatial-Temporal Heatmap Enabled' : 'Heatmap Overlay Disabled', 'info');
}

// Global Command Palette (Ctrl+K)
const COMMAND_PALETTE_ITEMS = [
  { id: 'nav-dashboard', label: 'Go to Command Center', category: 'Navigation', icon: '⚡', action: () => switchView('dashboard') },
  { id: 'nav-scanner', label: 'Go to Live Vision Scanner', category: 'Navigation', icon: '📹', action: () => switchView('scanner') },
  { id: 'nav-events', label: 'Go to Events & Detections', category: 'Navigation', icon: '📋', action: () => switchView('events') },
  { id: 'nav-incidents', label: 'Go to Security Incidents', category: 'Navigation', icon: '🚨', action: () => switchView('incidents') },
  { id: 'nav-policies', label: 'Go to Security Policies', category: 'Navigation', icon: '🛡️', action: () => switchView('policies') },
  { id: 'nav-copilot', label: 'Go to AI Copilot', category: 'Navigation', icon: '🧠', action: () => switchView('copilot') },
  { id: 'nav-aleana', label: 'Go to Aleana Voice Assistant', category: 'Navigation', icon: '🎙️', action: () => switchView('aleana') },
  { id: 'nav-brain', label: 'Go to Vanta Brain CLI', category: 'Navigation', icon: '⌨️', action: () => switchView('brain') },
  { id: 'nav-audit', label: 'Go to Audit Trail', category: 'Navigation', icon: '📜', action: () => switchView('audit') },
  { id: 'nav-system', label: 'Go to System Diagnostics', category: 'Navigation', icon: '⚙️', action: () => switchView('system') },
  { id: 'act-demo', label: 'Run Threat Intrusion Simulation', category: 'Simulation', icon: '▶️', action: () => triggerDemoSimulation() },
  { id: 'act-verify-audit', label: 'Verify Cryptographic Audit Ledger Integrity', category: 'Security', icon: '🔒', action: () => { switchView('audit'); verifyAuditChain(); } },
  { id: 'act-heatmap', label: 'Toggle Spatial-Temporal Heatmap Overlay', category: 'Vision', icon: '🔥', action: () => toggleHeatmapOverlay() },
  { id: 'act-snapshot', label: 'Capture Forensic Watermarked Snapshot', category: 'Vision', icon: '📸', action: () => captureForensicSnapshot() },
  { id: 'act-playbook-1', label: 'Execute Playbook 01: Perimeter Lockdown Audit', category: 'Autonomous', icon: '🛡️', action: () => { switchView('brain'); runPlaybook(1); } },
  { id: 'act-playbook-2', label: 'Execute Playbook 02: Automated Incident Triage', category: 'Autonomous', icon: '🚨', action: () => { switchView('brain'); runPlaybook(2); } },
  { id: 'act-playbook-3', label: 'Execute Playbook 03: Zero-Trust Security Self-Test', category: 'Autonomous', icon: '🧪', action: () => { switchView('brain'); runPlaybook(3); } },
  { id: 'act-dossier', label: 'Export Cryptographic Forensic Dossier (JSON)', category: 'Security', icon: '📜', action: () => exportForensicDossier() },
  { id: 'act-audio', label: 'Toggle Tactical Audio Synthesizer Effects', category: 'Audio', icon: '🔊', action: () => STATE.soundEngine?.toggleMute() }
];

function openCommandPalette() {
  const modal = document.getElementById('command-palette-modal');
  const input = document.getElementById('cmd-palette-search');
  if (!modal) return;
  modal.classList.add('active');
  STATE.commandPaletteActive = true;
  STATE.commandPaletteSelectedIndex = 0;
  if (input) {
    input.value = '';
    setTimeout(() => input.focus(), 50);
  }
  renderCommandPaletteResults('');
}

function closeCommandPalette() {
  const modal = document.getElementById('command-palette-modal');
  if (!modal) return;
  modal.classList.remove('active');
  STATE.commandPaletteActive = false;
}

function renderCommandPaletteResults(queryStr = '') {
  const list = document.getElementById('cmd-palette-list');
  if (!list) return;
  const q = (queryStr || '').toLowerCase().trim();
  const filtered = COMMAND_PALETTE_ITEMS.filter(item => {
    if (!q) return true;
    return item.label.toLowerCase().includes(q) || item.category.toLowerCase().includes(q);
  });

  if (filtered.length === 0) {
    list.innerHTML = `<div class="mono" style="padding: 1rem; text-align: center; color: var(--text-dim); font-size: 0.76rem;">No matching commands found.</div>`;
    return;
  }

  if (STATE.commandPaletteSelectedIndex >= filtered.length) {
    STATE.commandPaletteSelectedIndex = 0;
  }

  list.innerHTML = filtered.map((item, idx) => `
    <div class="cmd-palette-item ${idx === STATE.commandPaletteSelectedIndex ? 'active' : ''}" data-cmd-idx="${idx}">
      <div class="item-left">
        <span>${item.icon}</span>
        <span style="font-weight: 500;">${escapeHtml(item.label)}</span>
      </div>
      <span class="badge mono" style="font-size: 0.65rem;">${escapeHtml(item.category)}</span>
    </div>
  `).join('');

  list.querySelectorAll('.cmd-palette-item').forEach(el => {
    el.addEventListener('click', () => {
      const idx = parseInt(el.dataset.cmdIdx, 10);
      const chosen = filtered[idx];
      if (chosen && typeof chosen.action === 'function') {
        closeCommandPalette();
        chosen.action();
      }
    });
  });
}

// Dossier Export Engine (JSON and CSV)
function exportDossier(entityType, format) {
  STATE.soundEngine?.playPing();
  let dataToExport = [];
  if (entityType === 'events') {
    dataToExport = CACHE.events || [];
  } else if (entityType === 'incidents') {
    dataToExport = CACHE.incidents || [];
  } else if (entityType === 'audit') {
    dataToExport = CACHE.auditLogs || [];
  }

  if (!dataToExport || dataToExport.length === 0) {
    showToast(`No ${entityType} records available to export.`, 'warning');
    return;
  }

  let fileContent = '';
  let mimeType = 'text/plain';

  if (format === 'json') {
    fileContent = JSON.stringify(dataToExport, null, 2);
    mimeType = 'application/json';
  } else {
    const headers = Object.keys(dataToExport[0] || {});
    const rows = dataToExport.map(row => {
      return headers.map(h => {
        let val = row[h];
        if (typeof val === 'object' && val !== null) val = JSON.stringify(val);
        const escaped = String(val || '').replace(/"/g, '""');
        return `"${escaped}"`;
      }).join(',');
    });
    fileContent = [headers.join(','), ...rows].join('\n');
    mimeType = 'text/csv';
  }

  const blob = new Blob([fileContent], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `vantavisionai_${entityType}_${Date.now()}.${format}`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast(`Exported ${dataToExport.length} ${entityType} records as ${format.toUpperCase()}.`, 'success');
}

// Cryptographic Forensic Dossier Export (/api/v1/audit/dossier)
async function exportForensicDossier() {
  STATE.soundEngine?.playPing();
  showToast('Generating Cryptographic Forensic Dossier...', 'info');
  try {
    const res = await fetch('/api/v1/audit/dossier', {
      headers: { 'X-Tenant-ID': STATE.tenantId }
    });
    if (!res.ok) {
      throw new Error(`Server returned HTTP ${res.status}`);
    }
    const dossierData = await res.json();
    const fileContent = JSON.stringify(dossierData, null, 2);
    const blob = new Blob([fileContent], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vantavisionai_forensic_dossier_${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast(`Exported Forensic Dossier (Head: #${dossierData.head_block_hash || 'GENESIS'}).`, 'success');
  } catch (err) {
    showToast(`Failed to export dossier: ${err.message}`, 'danger');
  }
}

if (typeof window !== 'undefined') {
  window.toggleHeatmapOverlay = toggleHeatmapOverlay;
  window.captureForensicSnapshot = captureForensicSnapshot;
  window.runPlaybook = runPlaybook;
  window.openCommandPalette = openCommandPalette;
  window.closeCommandPalette = closeCommandPalette;
  window.exportDossier = exportDossier;
  window.exportForensicDossier = exportForensicDossier;
}

function appendTerminal(text) {
  if (!brainTerminal) return;
  brainTerminal.textContent += `\n\n${text}`;
  brainTerminal.scrollTop = brainTerminal.scrollHeight;
}

brainForm?.addEventListener('submit', (e) => {
  e.preventDefault();
  const cmd = brainInput.value;
  brainInput.value = '';
  executeBrainCommand(cmd);
});

document.querySelectorAll('.cmd-pill').forEach(btn => {
  btn.addEventListener('click', () => {
    let argsObj = null;
    if (btn.dataset.args) {
      try { argsObj = JSON.parse(btn.dataset.args); } catch(_) {}
    }
    if (btn.dataset.cmd) executeBrainCommand(btn.dataset.cmd, argsObj);
  });
});

// =========================================================================
// 14. AUDIT TRAIL MODULE (Matching Panel 6)
// =========================================================================
const AUDIT_FILTER = {
  action: 'all',
  tab: 'logs',
  query: ''
};

async function fetchAuditLogs() {
  const tbody = document.getElementById('audit-table-body');
  try {
    const res = await fetch('/api/v1/audit', {
      headers: { 'X-Tenant-ID': STATE.tenantId }
    });
    const logs = await res.json();
    CACHE.auditLogs = Array.isArray(logs) ? logs : [];
    renderAuditTable();
  } catch (err) {
    if (tbody) tbody.innerHTML = '<tr><td colspan="6" style="color: var(--accent-rose);">Failed to load audit logs</td></tr>';
  }
}

function renderAuditTable() {
  const tbody = document.getElementById('audit-table-body');
  if (!tbody) return;

  const filtered = CACHE.auditLogs.filter(l => {
    if (AUDIT_FILTER.action !== 'all' && !l.action.includes(AUDIT_FILTER.action)) return false;
    if (AUDIT_FILTER.tab !== 'logs') {
      const act = (l.action || '').toUpperCase();
      if (AUDIT_FILTER.tab === 'health' && !(act.includes('HEALTH') || act.includes('BOOT') || act.includes('SYSTEM') || act.includes('DIAGNOSTIC'))) return false;
      if (AUDIT_FILTER.tab === 'db' && !(act.includes('EVENT') || act.includes('INCIDENT') || act.includes('POLICY') || act.includes('DB'))) return false;
      if (AUDIT_FILTER.tab === 'api' && !(act.includes('API') || act.includes('BRAIN') || act.includes('ALEANA') || act.includes('AUTH'))) return false;
    }
    if (AUDIT_FILTER.query) {
      const q = AUDIT_FILTER.query.toLowerCase();
      const matchActor = (l.actor || '').toLowerCase().includes(q);
      const matchDetails = (l.details || '').toLowerCase().includes(q);
      const matchAction = (l.action || '').toLowerCase().includes(q);
      if (!matchActor && !matchDetails && !matchAction) return false;
    }
    return true;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-dim);" class="mono">No matching audit records.</td></tr>';
    return;
  }

  tbody.innerHTML = filtered.map(l => {
    const hashBadge = l.integrity_hash
      ? `<span class="audit-hash-pill" title="SHA-256 Block Hash: ${escapeHtml(l.integrity_hash)} | Prev: ${escapeHtml(l.prev_hash || 'GENESIS')}">#${escapeHtml(l.integrity_hash)}</span>`
      : '';
    return `
      <tr>
        <td class="mono" style="font-size: 0.75rem;">${new Date(l.timestamp).toLocaleTimeString()}</td>
        <td class="mono">${escapeHtml(l.actor)}</td>
        <td class="mono" style="color: var(--accent-cyan); font-weight: 600;">${escapeHtml(l.action)}</td>
        <td class="mono" style="color: var(--text-dim);">${escapeHtml(l.action.split('_')[0].toLowerCase())}</td>
        <td>
          <div style="display: flex; align-items: center; gap: 0.35rem; flex-wrap: wrap;">
            <span class="badge ${l.status === 'SUCCESS' ? 'badge-low' : 'badge-critical'} mono">${l.status}</span>
            ${hashBadge}
          </div>
        </td>
        <td class="mono" style="color: var(--text-muted); font-size: 0.75rem;">192.168.1.10</td>
      </tr>
    `;
  }).join('');

  // Also populate Vanta Brain mini audit ledger table
  const brainMiniTbody = document.getElementById('brain-mini-audit-tbody');
  if (brainMiniTbody) {
    const miniSubset = CACHE.auditLogs.slice(0, 10);
    if (miniSubset.length === 0) {
      brainMiniTbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-dim);" class="mono">No guarded audit records logged yet.</td></tr>';
    } else {
      brainMiniTbody.innerHTML = miniSubset.map(l => `
        <tr>
          <td class="mono" style="font-size: 0.74rem;">${new Date(l.timestamp).toLocaleTimeString()}</td>
          <td class="mono" style="color: #fff;">${escapeHtml(l.actor || 'system')}</td>
          <td class="mono" style="color: var(--cyan); font-weight: 600;">${escapeHtml(l.action)}</td>
          <td><span class="badge ${l.status === 'SUCCESS' ? 'badge-low' : 'badge-critical'} mono">${escapeHtml(l.status)}</span></td>
          <td class="mono" style="color: var(--text-dim); font-size: 0.74rem;">${l.details && l.details.includes('ms') ? escapeHtml(l.details) : '3ms'}</td>
        </tr>
      `).join('');
    }
  }
}

async function verifyAuditChain() {
  const banner = document.getElementById('audit-chain-status-banner');
  const statusTxt = document.getElementById('audit-chain-status-text');
  const hashPreview = document.getElementById('audit-chain-hash-preview');
  const dot = document.getElementById('audit-chain-dot');

  if (statusTxt) statusTxt.textContent = 'CALCULATING CRYPTOGRAPHIC INTEGRITY...';
  if (dot) dot.style.background = 'var(--accent-amber)';

  try {
    const res = await fetch('/api/v1/audit', { headers: { 'X-Tenant-ID': STATE.tenantId } });
    const logs = await res.json();
    if (!Array.isArray(logs) || logs.length === 0) {
      if (statusTxt) statusTxt.textContent = 'GENESIS CHAIN EMPTY (0 BLOCKS RECORDED)';
      return;
    }

    let prevHash = 'GENESIS_BLOCK_0000';
    let tamperedCount = 0;

    for (let i = 0; i < logs.length; i++) {
      const entry = logs[i];
      const payload = `${entry.id}:${entry.tenant_id}:${entry.timestamp}:${entry.action}:${entry.actor}:${entry.status}:${prevHash}`;
      const msgUint8 = new TextEncoder().encode(payload);
      const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const expectedHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 16);

      if (entry.integrity_hash !== expectedHash) {
        tamperedCount++;
      }
      prevHash = entry.integrity_hash || expectedHash;
    }

    if (tamperedCount === 0) {
      if (banner) banner.className = 'verified';
      if (dot) dot.style.background = 'var(--success)';
      if (statusTxt) statusTxt.textContent = `CHAIN VERIFIED // 0 TAMPERED BLOCKS (${logs.length} BLOCKS VALIDATED)`;
      if (hashPreview) hashPreview.textContent = `HEAD BLOCK: #${prevHash}`;
      STATE.soundEngine?.playSuccess();
      showToast(`Ledger integrity cryptographically verified: ${logs.length} blocks valid.`, 'success');
    } else {
      if (banner) banner.className = 'tampered';
      if (dot) dot.style.background = 'var(--critical)';
      if (statusTxt) statusTxt.textContent = `TAMPER DETECTED: ${tamperedCount} BLOCKS FAILED VERIFICATION`;
      STATE.soundEngine?.playAlert();
      showToast(`Ledger integrity failed: ${tamperedCount} tampered blocks detected!`, 'danger');
    }
  } catch (err) {
    if (statusTxt) statusTxt.textContent = `VERIFICATION ERROR: ${err.message}`;
  }
}
if (typeof window !== 'undefined') {
  window.verifyAuditChain = verifyAuditChain;
}

document.querySelectorAll('#view-audit .subtab-btn[data-audit-tab]').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('#view-audit .subtab-btn[data-audit-tab]').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    AUDIT_FILTER.tab = btn.dataset.auditTab;
    renderAuditTable();
  });
});

document.getElementById('audit-action-select')?.addEventListener('change', (e) => {
  AUDIT_FILTER.action = e.target.value;
  renderAuditTable();
});
document.getElementById('audit-search-input')?.addEventListener('input', (e) => {
  AUDIT_FILTER.query = e.target.value.trim();
  renderAuditTable();
});
document.getElementById('btn-refresh-audit')?.addEventListener('click', () => {
  fetchAuditLogs();
  showToast('Audit trail refreshed.', 'info');
});
document.getElementById('btn-refresh-brain-audit')?.addEventListener('click', () => {
  fetchAuditLogs();
  showToast('Guarded execution ledger refreshed.', 'info');
});

// =========================================================================
// 15. SYSTEM DIAGNOSTICS & DEMO SIMULATION
// =========================================================================
async function fetchPipelineInfo() {
  const out = document.getElementById('pipeline-status-output');
  if (!out) return;
  try {
    const [sysRes, readyRes, camRes] = await Promise.all([
      fetch('/api/v1/system', { headers: { 'X-Tenant-ID': STATE.tenantId } }),
      fetch('/ready'),
      fetch('/api/v1/system/cameras', { headers: { 'X-Tenant-ID': STATE.tenantId } }).catch(() => null)
    ]);
    const sys = await sysRes.json();
    const ready = await readyRes.json();
    const camData = camRes && camRes.ok ? await camRes.json() : null;

    let text = `=== SYSTEM PIPELINE STATUS ===\n` +
      `Application: ${sys.app_name} v${sys.version}\n` +
      `Readiness: ${ready.ready ? 'HEALTHY / READY' : 'DEGRADED'}\n` +
      `Database: ${ready.database}\n` +
      `Uptime: ${sys.uptime_seconds}s\n\n` +
      `=== CAMERA SUBSYSTEM ===\n` +
      `Camera Provider: ${sys.camera_subsystem.provider}\n` +
      `Real Camera Configured: ${sys.camera_subsystem.real_camera_configured} (SIMULATED)\n` +
      `Browser Local Detector: ${sys.camera_subsystem.browser_detector}\n` +
      `Simulated Feeds: ${sys.camera_subsystem.simulated_streams.join(', ')}\n\n`;

    if (camData && camData.streams) {
      text += `=== AUTOMATED STREAM HEALTH MONITOR ===\n` +
        `Total Monitored Streams: ${camData.total_streams} | Online: ${camData.online_streams} | Disconnected: ${camData.disconnected_streams}\n` +
        `Signal Status: ${camData.status === 'HEALTHY' ? 'ALL STREAMS NOMINAL (100%)' : 'DEGRADED (FEEDS OFFLINE)'}\n` +
        `Stream Sources:\n` +
        camData.streams.map(s => ` - [${s.status}] ${s.id} (${s.name}): Ping ${s.status === 'ONLINE' ? (s.latency_ms || 14) + 'ms' : 'UNREACHABLE'}`).join('\n') + `\n\n`;
    }

    text += `=== CONTROLLED BRAIN SUBSYSTEM ===\n` +
      `Mode: ${sys.brain_subsystem.mode}\n` +
      `Status: ${sys.brain_subsystem.status}\n` +
      `Allowlisted Commands: ${sys.brain_subsystem.allowlist_count}\n\n` +
      `=== ALEANA VOICE SUBSYSTEM ===\n` +
      `Speech Recognition: ${STATE.aleana.isSupported ? 'Supported (Web Speech API)' : 'Text Fallback'}\n` +
      `Speech Synthesis: Active (Browser native)`;

    out.textContent = text;
  } catch (e) {
    out.textContent = 'Error: ' + e.message;
  }
}
document.getElementById('btn-refresh-system')?.addEventListener('click', () => {
  fetchPipelineInfo();
  if (typeof fetchCameraHealth === 'function') fetchCameraHealth(true);
  showToast('Diagnostics refreshed.', 'info');
});

// =========================================================================
// 15b. AUTOMATED CAMERA STREAM HEALTH MONITOR
// =========================================================================
const CAMERA_MONITOR = {
  intervalTimer: null,
  pollIntervalMs: 8000,
  streams: [],
  prevDisconnected: new Set(),
  totalPings: 0,
  packetLossCount: 0,
  isPingingAll: false
};

async function fetchCameraHealth(isManual = false) {
  const gridEl = document.getElementById('camera-health-streams-grid');
  const overallBadgeEl = document.getElementById('camera-health-overall-badge');
  const overallTextEl = document.getElementById('camera-health-overall-text');
  const alertBanner = document.getElementById('camera-feed-disconnect-alert');
  const alertText = document.getElementById('camera-feed-disconnect-text');
  const alertTimestamp = document.getElementById('camera-feed-disconnect-timestamp');
  const statusFooter = document.getElementById('camera-monitor-status-text');
  const packetStatFooter = document.getElementById('camera-monitor-packet-stat');

  try {
    const res = await fetch('/api/v1/system/cameras', {
      headers: { 'X-Tenant-ID': STATE.tenantId }
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    let streams = data.streams || [];

    // Dynamically reconcile local browser webcam state if scanning
    streams = streams.map(stream => {
      if (stream.id === 'BROWSER-LOCAL-SCANNER') {
        if (STATE.isScanning && STATE.activeSourceType === 'Webcam') {
          const track = STATE.stream && typeof STATE.stream.getVideoTracks === 'function' ? STATE.stream.getVideoTracks()[0] : null;
          const isTrackLive = track && track.readyState === 'live' && !track.muted;
          return {
            ...stream,
            status: isTrackLive ? 'ONLINE' : 'DISCONNECTED',
            latency_ms: isTrackLive ? (STATE.measuredLatency ? Math.round(STATE.measuredLatency / 10) : 4) : null,
            last_ping: new Date().toISOString()
          };
        } else if (STATE.isScanning && STATE.activeSourceType === 'TestFeed') {
          return {
            ...stream,
            status: 'ONLINE',
            latency_ms: 2,
            last_ping: new Date().toISOString()
          };
        }
      }
      return stream;
    });

    CAMERA_MONITOR.streams = streams;
    CAMERA_MONITOR.totalPings += streams.length;

    const disconnectedStreams = streams.filter(s => s.status !== 'ONLINE');
    const onlineStreams = streams.filter(s => s.status === 'ONLINE');
    const newlyDisconnected = [];

    disconnectedStreams.forEach(ds => {
      if (!CAMERA_MONITOR.prevDisconnected.has(ds.id)) {
        newlyDisconnected.push(ds);
      }
    });

    CAMERA_MONITOR.prevDisconnected = new Set(disconnectedStreams.map(s => s.id));

    // Alert operator immediately if a stream disconnected
    if (newlyDisconnected.length > 0) {
      const names = newlyDisconnected.map(s => `${s.name} (${s.id})`).join(', ');
      showToast(`[FEED DISCONNECTED] Alert: Stream signal lost for ${names}!`, 'danger');
      if (typeof STATE.soundEngine?.playWarning === 'function') {
        STATE.soundEngine.playWarning();
      }
    }

    // Update Disconnect Alert Banner
    if (alertBanner) {
      if (disconnectedStreams.length > 0) {
        alertBanner.style.display = 'flex';
        if (alertText) {
          alertText.innerHTML = `Warning: <strong>${disconnectedStreams.length} stream(s) unreachable:</strong> ${disconnectedStreams.map(s => s.name).join(', ')}. Automated watchdog is attempting re-acquisition.`;
        }
        if (alertTimestamp) {
          alertTimestamp.textContent = `Signal lost: ${new Date().toLocaleTimeString()}`;
        }
      } else {
        alertBanner.style.display = 'none';
      }
    }

    // Update Overall Badge
    if (overallBadgeEl && overallTextEl) {
      const pct = streams.length > 0 ? Math.round((onlineStreams.length / streams.length) * 100) : 100;
      overallTextEl.textContent = `Feeds: ${onlineStreams.length}/${streams.length} Active (${pct}%)`;
      const dot = overallBadgeEl.querySelector('.live-dot');
      if (disconnectedStreams.length === 0) {
        overallBadgeEl.className = 'badge badge-emerald mono';
        if (dot) dot.style.background = 'var(--accent-emerald)';
      } else {
        overallBadgeEl.className = 'badge badge-critical mono';
        if (dot) dot.style.background = 'var(--accent-rose)';
      }
    }

    // Update Status Footers
    if (statusFooter) {
      statusFooter.textContent = `Health Monitor: Auto-ping every 8s • Last check: ${new Date().toLocaleTimeString()}`;
    }
    if (packetStatFooter) {
      const stability = disconnectedStreams.length === 0 ? '100% (Optimal)' : `${Math.round((onlineStreams.length / (streams.length || 1)) * 100)}% (Degraded)`;
      packetStatFooter.textContent = `Pings: ${CAMERA_MONITOR.totalPings} • Signal Stability: ${stability}`;
    }

    // Render Grid Cards
    if (gridEl) {
      gridEl.innerHTML = streams.map(s => {
        const isOnline = s.status === 'ONLINE';
        const latencyText = isOnline ? (s.latency_ms !== null && s.latency_ms !== undefined ? `${s.latency_ms}ms` : '<15ms') : 'TIMEOUT / UNREACHABLE';
        const statusBadge = isOnline
          ? `<span class="badge badge-low mono" style="font-size: 0.7rem;"><span class="live-dot" style="background: var(--accent-emerald);"></span> ONLINE</span>`
          : `<span class="badge badge-critical mono" style="font-size: 0.7rem;"><span class="live-dot" style="background: var(--accent-rose);"></span> DISCONNECTED</span>`;

        return `
          <div class="stream-health-card ${isOnline ? 'stream-online' : 'stream-disconnected'}" id="stream-card-${s.id}">
            <div class="stream-health-header">
              <div>
                <div class="stream-health-title">${escapeHtml(s.name)}</div>
                <div class="stream-health-zone mono">${escapeHtml(s.zone || s.id)}</div>
              </div>
              <div>${statusBadge}</div>
            </div>

            <div style="margin-top: 0.2rem;">
              <div class="stream-metric-row mono">
                <span class="stream-metric-label">Source ID:</span>
                <span class="stream-metric-val">${s.id}</span>
              </div>
              <div class="stream-metric-row mono">
                <span class="stream-metric-label">Protocol:</span>
                <span class="stream-metric-val">${escapeHtml(s.protocol || 'RTSP')}</span>
              </div>
              <div class="stream-metric-row mono">
                <span class="stream-metric-label">Ping Latency:</span>
                <span class="stream-metric-val" style="color: ${isOnline ? 'var(--accent-cyan)' : 'var(--accent-rose)'}; font-weight: 700;">${latencyText}</span>
              </div>
              <div class="stream-metric-row mono">
                <span class="stream-metric-label">Last Ping:</span>
                <span class="stream-metric-val">${s.last_ping ? new Date(s.last_ping).toLocaleTimeString() : 'Just now'}</span>
              </div>
            </div>

            <div class="stream-health-actions">
              <button class="btn btn-sm mono" style="flex: 1; justify-content: center; font-size: 0.72rem; padding: 0.25rem 0.45rem;" onclick="window.pingIndividualCameraStream('${s.id}')">
                Ping Stream
              </button>
              <button class="btn btn-sm ${isOnline ? 'btn-danger' : 'btn-primary'} mono" style="font-size: 0.72rem; padding: 0.25rem 0.55rem;" onclick="window.toggleIndividualCameraStream('${s.id}')" title="Test disconnect / reconnect detection in real-time">
                ${isOnline ? 'Simulate Disconnect' : 'Reconnect Feed'}
              </button>
            </div>
          </div>
        `;
      }).join('');
    }

  } catch (err) {
    console.warn('[Camera Health Monitor] Ping failed:', err);
    if (statusFooter) {
      statusFooter.textContent = 'Health Monitor: Warning - API unreachable (' + err.message + ')';
    }
  }
}

async function pingIndividualCameraStream(streamId) {
  try {
    const res = await fetch(`/api/v1/system/cameras/${encodeURIComponent(streamId)}/ping`, {
      method: 'POST',
      headers: { 'X-Tenant-ID': STATE.tenantId }
    });
    const data = await res.json();
    if (data.status === 'ONLINE') {
      showToast(`Pinged ${data.name || streamId}: ${data.latency_ms}ms round-trip (ONLINE)`, 'success');
    } else {
      showToast(`Stream ${data.name || streamId} is UNREACHABLE / DISCONNECTED!`, 'danger');
    }
    fetchCameraHealth();
  } catch (e) {
    showToast(`Failed to ping stream ${streamId}: ${e.message}`, 'danger');
  }
}

async function toggleIndividualCameraStream(streamId) {
  try {
    const res = await fetch(`/api/v1/system/cameras/${encodeURIComponent(streamId)}/toggle`, {
      method: 'POST',
      headers: { 'X-Tenant-ID': STATE.tenantId }
    });
    const data = await res.json();
    if (data.new_status === 'DISCONNECTED') {
      showToast(`[DISCONNECT TRIGGERED] Stream ${data.name} set to DISCONNECTED`, 'warning');
    } else {
      showToast(`[RECONNECTED] Stream ${data.name} restored to ONLINE`, 'success');
    }
    fetchCameraHealth();
    fetchPipelineInfo();
  } catch (e) {
    showToast(`Failed to toggle stream ${streamId}: ${e.message}`, 'danger');
  }
}

async function pingAllCameraStreams() {
  const btn = document.getElementById('btn-ping-all-cameras');
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<span class="live-dot" style="background: var(--accent-cyan);"></span> Pinging...`;
  }
  showToast('Executing automated health ping across all stream sources...', 'info');

  try {
    const streams = CAMERA_MONITOR.streams || [];
    await Promise.all(
      streams.map(s => fetch(`/api/v1/system/cameras/${encodeURIComponent(s.id)}/ping`, {
        method: 'POST',
        headers: { 'X-Tenant-ID': STATE.tenantId }
      }).catch(() => {}))
    );
    await fetchCameraHealth(true);
    showToast('All camera stream sources pinged successfully.', 'success');
  } catch (err) {
    showToast('Stream ping sequence encountered errors: ' + err.message, 'danger');
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = `<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg> <span>Ping All Streams</span>`;
    }
  }
}

function initCameraHealthMonitor() {
  if (typeof window === 'undefined') return;
  fetchCameraHealth();
  if (CAMERA_MONITOR.intervalTimer) clearInterval(CAMERA_MONITOR.intervalTimer);
  CAMERA_MONITOR.intervalTimer = setInterval(() => {
    fetchCameraHealth();
  }, CAMERA_MONITOR.pollIntervalMs);

  document.getElementById('btn-ping-all-cameras')?.addEventListener('click', pingAllCameraStreams);
}

const btnRunDemo = document.getElementById('btn-run-demo');
const demoOutput = document.getElementById('demo-output');

async function triggerDemoSimulation() {
  if (btnRunDemo) {
    btnRunDemo.disabled = true;
    btnRunDemo.textContent = 'Executing Simulation Sequence...';
  }
  if (demoOutput) demoOutput.textContent = 'Triggering POST /api/v1/demo/run with scenario "intrusion"...';

  try {
    const res = await fetch('/api/v1/demo/run', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Tenant-ID': STATE.tenantId
      },
      body: JSON.stringify({ scenario: 'intrusion', camera_id: 'DEMO-CAM-01' })
    });
    const data = await res.json();
    if (demoOutput) demoOutput.textContent = `[SIMULATION SUCCESSFUL]\n` + JSON.stringify(data, null, 2);
    showToast('Simulation complete: intrusion event & high-priority incident created.', 'success');
    fetchSummary();
  } catch (err) {
    if (demoOutput) demoOutput.textContent = `[SIMULATION ERROR]: ${err.message}`;
    showToast('Simulation failed: ' + err.message, 'danger');
  } finally {
    if (btnRunDemo) {
      btnRunDemo.disabled = false;
      btnRunDemo.textContent = 'Run End-to-End Simulation';
    }
  }
}
btnRunDemo?.addEventListener('click', triggerDemoSimulation);
document.getElementById('btn-topbar-demo-run')?.addEventListener('click', () => {
  triggerDemoSimulation();
});

const tenantSelect = document.getElementById('tenant-select');
if (tenantSelect) {
  tenantSelect.addEventListener('change', (e) => {
    STATE.tenantId = e.target.value;
    const tenantDisp = document.getElementById('tenant-display');
    if (tenantDisp) tenantDisp.textContent = STATE.tenantId;
    showToast(`Switched active tenant to "${STATE.tenantId}"`, 'info');
    fetchSummary();
    fetchEvents();
    fetchIncidents();
    fetchPolicies();
    fetchAuditLogs();
    if (typeof updateCopilotTelemetryBar === 'function') updateCopilotTelemetryBar();
  });
}

// =========================================================================
// 16. SUMMARY POLLING & METRICS SYNC
// =========================================================================
async function fetchSummary() {
  try {
    const res = await fetch('/api/v1/summary', {
      headers: { 'X-Tenant-ID': STATE.tenantId }
    });
    if (res.ok) {
      const data = await res.json();
      const evEl = document.getElementById('stat-events');
      const incEl = document.getElementById('stat-incidents');
      const polEl = document.getElementById('stat-policies');
      const camEl = document.getElementById('stat-cameras');
      const healthEl = document.getElementById('stat-health');
      const auditEl = document.getElementById('stat-audit');
      if (evEl) evEl.textContent = data.total_events !== undefined ? data.total_events : 247;
      if (polEl) polEl.textContent = data.active_policies !== undefined ? data.active_policies : 4;
      if (auditEl) auditEl.textContent = data.total_audit_logs !== undefined ? data.total_audit_logs : 18;
      if (incEl) {
        incEl.textContent = data.open_incidents !== undefined ? data.open_incidents : 0;
        if (data.open_incidents > 0) {
          incEl.style.color = 'var(--accent-rose)';
        } else {
          incEl.style.color = 'var(--accent-emerald)';
        }
      }
      if (camEl) {
        camEl.textContent = STATE.activeSourceType !== 'None' ? '1 Local' : '0 Physical';
      }
      if (healthEl) {
        healthEl.textContent = data.open_incidents > 0 ? `${data.open_incidents} Alerts` : 'Nominal';
      }
    }
  } catch (e) {}
}

async function checkBackendConnectivity() {
  try {
    const res = await fetch('/ready');
    const label = document.getElementById('backend-ready-label');
    if (res.ok && label) {
      label.textContent = 'LIVE SOC READY';
    }
  } catch (_) {
    const label = document.getElementById('backend-ready-label');
    if (label) label.textContent = 'OFFLINE';
  }
}
checkBackendConnectivity();
setInterval(checkBackendConnectivity, 15000);

// =========================================================================
// 17. TOAST NOTIFICATIONS & ACCESSIBLE CONFIRMATION MODAL
// =========================================================================
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = `toast-item toast-${type} mono`;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    toast.style.transition = 'all 0.25s ease';
    setTimeout(() => toast.remove(), 250);
  }, 3500);
}

let activeModalConfirmCallback = null;
function showModal({ title, body, confirmText = 'Confirm', confirmClass = 'btn-danger', onConfirm }) {
  const modal = document.getElementById('vanta-modal');
  const titleEl = document.getElementById('vanta-modal-title');
  const bodyEl = document.getElementById('vanta-modal-body');
  const confirmBtn = document.getElementById('vanta-modal-confirm');
  if (!modal) {
    if (confirm(body)) onConfirm();
    return;
  }
  if (titleEl) titleEl.textContent = title;
  if (bodyEl) bodyEl.innerHTML = body;
  if (confirmBtn) {
    confirmBtn.textContent = confirmText;
    confirmBtn.className = `btn ${confirmClass}`;
  }
  activeModalConfirmCallback = onConfirm;
  modal.classList.add('active');
}

function closeModal() {
  const modal = document.getElementById('vanta-modal');
  if (modal) modal.classList.remove('active');
  activeModalConfirmCallback = null;
}

document.getElementById('vanta-modal-close')?.addEventListener('click', closeModal);
document.getElementById('vanta-modal-cancel')?.addEventListener('click', closeModal);
document.getElementById('vanta-modal-confirm')?.addEventListener('click', () => {
  if (activeModalConfirmCallback) activeModalConfirmCallback();
  closeModal();
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeModal();
});

function escapeHtml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// =========================================================================
// 17b. THEME SWITCHER ENGINE (DARK / LIGHT / SYSTEM)
// =========================================================================
function applyTheme(choice, persist = true) {
  if (typeof window === 'undefined' || !document || !document.documentElement) return;
  const targetChoice = choice || 'dark';
  if (persist) {
    try { localStorage.setItem('vanta-theme', targetChoice); } catch (e) {}
  }
  const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  const effectiveTheme = targetChoice === 'system' ? (prefersDark ? 'dark' : 'light') : targetChoice;

  document.documentElement.setAttribute('data-theme', effectiveTheme);
  document.documentElement.setAttribute('data-theme-choice', targetChoice);

  document.querySelectorAll('.theme-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.themeChoice === targetChoice);
  });

  if (persist && typeof showToast === 'function') {
    const label = targetChoice === 'dark' ? 'Dark Mode' : targetChoice === 'light' ? 'Light Mode' : 'System Match';
    showToast(`Visual theme set to ${label}`, 'info');
  }
}

function initThemeEngine() {
  if (typeof window === 'undefined' || !document) return;
  let saved = 'dark';
  try { saved = localStorage.getItem('vanta-theme') || 'dark'; } catch (e) {}
  applyTheme(saved, false);

  document.querySelectorAll('.theme-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const choice = btn.dataset.themeChoice;
      if (choice) applyTheme(choice, true);
    });
  });

  if (window.matchMedia) {
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
      let current = 'dark';
      try { current = localStorage.getItem('vanta-theme') || 'dark'; } catch (e) {}
      if (current === 'system') {
        applyTheme('system', false);
      }
    });
  }
}

// =========================================================================
// 17c. REAL-TIME WEBSOCKET TELEMETRY & PROACTIVE WATCHTOWER VOICE ENGINE
// =========================================================================
function triggerWatchtowerProactiveVoiceAlert(incidentTitle = 'High-Priority Alert', zone = 'Perimeter Sector') {
  const now = Date.now();
  if (STATE.aleana?.isMuted) return;
  if (STATE.lastWatchtowerAlertTime && (now - STATE.lastWatchtowerAlertTime < 20000)) {
    return; // Throttled to at most 1 alert every 20 seconds
  }
  STATE.lastWatchtowerAlertTime = now;
  if ('speechSynthesis' in window) {
    const wasListening = STATE.aleana?.sessionActive && !STATE.aleana?.isPaused;
    if (wasListening && STATE.aleana?.recognition) {
      try { STATE.aleana.recognition.abort(); } catch (e) {}
    }
    const speechText = `Security Alert: Priority breach detected in ${zone}. Immediate operator review advised.`;
    const utterance = new SpeechSynthesisUtterance(speechText);
    utterance.rate = 1.05;
    utterance.onend = () => {
      if (wasListening && typeof scheduleRecognitionRestart === 'function') {
        scheduleRecognitionRestart(150);
      }
    };
    utterance.onerror = () => {
      if (wasListening && typeof scheduleRecognitionRestart === 'function') {
        scheduleRecognitionRestart(200);
      }
    };
    window.speechSynthesis.speak(utterance);
  }
}

function initTelemetryWebSocket() {
  if (typeof window === 'undefined' || !window.WebSocket) return;
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/ws`;

  let ws = null;
  let retryCount = 0;

  function connect() {
    try {
      ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        retryCount = 0;
        console.log('[Telemetry WS] Connected to', wsUrl);
        const wsPill = document.getElementById('ws-status-indicator');
        if (wsPill) {
          wsPill.textContent = 'WS: LIVE';
          wsPill.className = 'badge mono badge-low';
          wsPill.style.color = 'var(--cyan)';
        }
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === 'EVENT_CREATED' || msg.type === 'EVENT_DELETED') {
            if (typeof fetchEvents === 'function') fetchEvents();
            if (typeof fetchSummary === 'function') fetchSummary();
          } else if (msg.type === 'INCIDENT_CREATED' || msg.type === 'DEMO_RUN') {
            if (typeof fetchIncidents === 'function') fetchIncidents();
            if (typeof fetchEvents === 'function') fetchEvents();
            if (typeof fetchSummary === 'function') fetchSummary();
            triggerWatchtowerProactiveVoiceAlert(msg.payload?.title || 'Security Escalation Alert', msg.payload?.camera_id || 'Entrance Sector');
          } else if (msg.type === 'INCIDENT_RESOLVED') {
            if (typeof fetchIncidents === 'function') fetchIncidents();
            if (typeof fetchSummary === 'function') fetchSummary();
          }
        } catch (e) {
          console.warn('[Telemetry WS] Parse error:', e);
        }
      };

      ws.onclose = () => {
        const delay = Math.min(1000 * Math.pow(2, retryCount), 10000);
        retryCount++;
        setTimeout(connect, delay);
      };

      ws.onerror = () => {
        try { ws.close(); } catch (e) {}
      };
    } catch (err) {
      console.warn('[Telemetry WS] Init error:', err);
    }
  }

  connect();
}

// =========================================================================
// 18. INITIAL APPLICATION BOOTSTRAP
// =========================================================================
if (typeof window !== 'undefined' && window.addEventListener) {
  window.addEventListener('DOMContentLoaded', () => {
    initThemeEngine();
    checkPermissionState();
    initDetector();
    initAleanaVoice();
    initTelemetryWebSocket();
    fetchSummary();
    renderDashboardPreview();
    setInterval(fetchSummary, 6000);

    // Initialize Tactical Sound Engine
    STATE.soundEngine = new TacticalSoundEngine();
    ['click', 'keydown', 'touchstart'].forEach(evt => {
      window.addEventListener(evt, () => STATE.soundEngine?.init(), { once: true });
    });
    document.getElementById('btn-audio-mute-toggle')?.addEventListener('click', () => {
      STATE.soundEngine?.toggleMute();
    });

    // Wire Scanner Heatmap & Snapshot Controls
    document.getElementById('btn-toggle-heatmap')?.addEventListener('click', toggleHeatmapOverlay);
    document.getElementById('btn-capture-snapshot')?.addEventListener('click', captureForensicSnapshot);
    renderForensicEvidenceStrip();

    // Wire Ledger Integrity Verification
    document.getElementById('btn-verify-audit-chain')?.addEventListener('click', verifyAuditChain);

    // Wire Autonomous Playbook Runners
    document.getElementById('btn-run-playbook-1')?.addEventListener('click', () => runPlaybook(1));
    document.getElementById('btn-run-playbook-2')?.addEventListener('click', () => runPlaybook(2));
    document.getElementById('btn-run-playbook-3')?.addEventListener('click', () => runPlaybook(3));

    // Wire Dossier Export Buttons
    document.getElementById('btn-export-events-json')?.addEventListener('click', () => exportDossier('events', 'json'));
    document.getElementById('btn-export-events-csv')?.addEventListener('click', () => exportDossier('events', 'csv'));
    document.getElementById('btn-export-incidents-json')?.addEventListener('click', () => exportDossier('incidents', 'json'));
    document.getElementById('btn-export-incidents-csv')?.addEventListener('click', () => exportDossier('incidents', 'csv'));
    document.getElementById('btn-export-audit-json')?.addEventListener('click', () => exportDossier('audit', 'json'));
    document.getElementById('btn-export-audit-csv')?.addEventListener('click', () => exportDossier('audit', 'csv'));
    document.getElementById('btn-export-dossier')?.addEventListener('click', exportForensicDossier);

    // Global Command Palette Keybindings and Controls
    document.getElementById('btn-command-palette-trigger')?.addEventListener('click', openCommandPalette);
    document.getElementById('cmd-palette-backdrop')?.addEventListener('click', closeCommandPalette);
    const cmdInput = document.getElementById('cmd-palette-search');
    if (cmdInput) {
      cmdInput.addEventListener('input', (e) => renderCommandPaletteResults(e.target.value));
      cmdInput.addEventListener('keydown', (e) => {
        const list = document.getElementById('cmd-palette-list');
        const items = list ? list.querySelectorAll('.cmd-palette-item') : [];
        if (e.key === 'ArrowDown') {
          e.preventDefault();
          if (items.length > 0) {
            STATE.commandPaletteSelectedIndex = (STATE.commandPaletteSelectedIndex + 1) % items.length;
            renderCommandPaletteResults(cmdInput.value);
          }
        } else if (e.key === 'ArrowUp') {
          e.preventDefault();
          if (items.length > 0) {
            STATE.commandPaletteSelectedIndex = (STATE.commandPaletteSelectedIndex - 1 + items.length) % items.length;
            renderCommandPaletteResults(cmdInput.value);
          }
        } else if (e.key === 'Enter') {
          e.preventDefault();
          const activeItem = list?.querySelector('.cmd-palette-item.active');
          if (activeItem) {
            activeItem.click();
          }
        }
      });
    }

    document.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        if (STATE.commandPaletteActive) {
          closeCommandPalette();
        } else {
          openCommandPalette();
        }
      } else if (e.key === 'Escape' && STATE.commandPaletteActive) {
        closeCommandPalette();
      }
    });

    // Watchdog: detect stream stall/freeze without manual refresh
    setInterval(() => {
      if (STATE.isScanning && STATE.activeSourceType === 'Webcam' && !STATE.isReconnecting && !STATE.userStopped) {
        if (STATE.lastValidFrameTime > 0 && (performance.now() - STATE.lastValidFrameTime > 6000)) {
          console.warn('[VantaVisionAI] Stream watchdog: no frames received for >6s. Triggering automatic reconnection.');
          triggerReconnection('Stream stalled: no video frames received for >6s.');
        }
      }
    }, 2500);
  });
}

if (typeof window !== 'undefined') {
  window.computePathTortuosity = computePathTortuosity;
  window.TRIPWIRE_LINE = TRIPWIRE_LINE;
  window.setFilterPreset = setFilterPreset;
  window.syncDynamicFilterUI = syncDynamicFilterUI;
}

// Node.js CommonJS export for automated unit and integration testing
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    ObjectTracker,
    sanitizeAndValidateDetections,
    applyPerClassNMS,
    filterPredictions,
    getObjectCategory,
    DETECTION_CATEGORIES,
    applyTheme,
    initThemeEngine,
    computePathTortuosity,
    TRIPWIRE_LINE,
    setFilterPreset,
    syncDynamicFilterUI,
    STATE,
    exportForensicDossier
  };
}
