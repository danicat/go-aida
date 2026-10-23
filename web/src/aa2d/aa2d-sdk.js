/**
 * Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * AA2D Standalone Zero-Dependency SDK v3.0.0
 * AI Expression & Viseme Face-Patch Compositor + WebAudio Formant Lip-Sync Engine
 */

export class AA2DSchemaError extends Error {
  constructor(message) {
    super(message);
    this.name = "AA2DSchemaError";
  }
}

export class AA2DRendererError extends Error {
  constructor(message) {
    super(message);
    this.name = "AA2DRendererError";
  }
}

export class AA2DAudioError extends Error {
  constructor(message) {
    super(message);
    this.name = "AA2DAudioError";
  }
}

const REQUIRED_EYE_PATCHES = [
  "neutral_open",
  "neutral_half",
  "neutral_closed",
  "happy",
  "sad",
  "angry",
  "surprised",
];

const REQUIRED_MOUTH_PATCHES = ["SIL", "A", "O", "I", "U", "E"];

/**
 * Validates an A2D v3.0 AvatarBundle JSON document.
 * Throws AA2DSchemaError immediately on any missing or malformed field.
 */
export function validateAvatarBundle(bundle) {
  if (!bundle || typeof bundle !== "object") {
    throw new AA2DSchemaError("Bundle must be a non-null JSON object.");
  }
  if (bundle.version !== "3.0.0") {
    throw new AA2DSchemaError(
      `Unsupported A2D bundle version "${bundle.version}" (expected "3.0.0").`
    );
  }
  if (bundle.standard !== "A2D") {
    throw new AA2DSchemaError(
      `Invalid bundle standard "${bundle.standard}" (expected "A2D").`
    );
  }
  if (!bundle.metadata?.id || !bundle.metadata?.name) {
    throw new AA2DSchemaError("Bundle metadata.id and metadata.name are required.");
  }
  if (!bundle.base_sprite?.startsWith("data:image/png;base64,")) {
    throw new AA2DSchemaError("Bundle base_sprite must be a valid PNG data URI.");
  }
  if (!bundle.eyes_rect || bundle.eyes_rect.w <= 0 || bundle.eyes_rect.h <= 0) {
    throw new AA2DSchemaError("Bundle eyes_rect is missing or invalid.");
  }
  if (!bundle.mouth_rect || bundle.mouth_rect.w <= 0 || bundle.mouth_rect.h <= 0) {
    throw new AA2DSchemaError("Bundle mouth_rect is missing or invalid.");
  }
  if (!bundle.eye_patches || typeof bundle.eye_patches !== "object") {
    throw new AA2DSchemaError("Bundle eye_patches map is required.");
  }
  for (const id of REQUIRED_EYE_PATCHES) {
    const p = bundle.eye_patches[id];
    if (!p || !p.data_uri?.startsWith("data:image/png;base64,")) {
      throw new AA2DSchemaError(`Missing or invalid required eye_patch "${id}".`);
    }
  }
  if (!bundle.mouth_patches || typeof bundle.mouth_patches !== "object") {
    throw new AA2DSchemaError("Bundle mouth_patches map is required.");
  }
  for (const id of REQUIRED_MOUTH_PATCHES) {
    const p = bundle.mouth_patches[id];
    if (!p || !p.data_uri?.startsWith("data:image/png;base64,")) {
      throw new AA2DSchemaError(`Missing or invalid required mouth_patch "${id}".`);
    }
  }
  return true;
}

/**
 * AA2DLipSync: Hardware-clock WebAudio PCM16 streaming player + real-time F1/F2 FFT formant vowel classifier.
 */
export class AA2DLipSync {
  constructor() {
    this.audioCtx = null;
    this.analyser = null;
    this.gainNode = null;
    this.freqBins = null;
    this.timeBins = null;
    this.nextPlayTime = 0;
    this.activeSources = new Set();
    this.telemetryQueue = [];
    this.micStream = null;
    this.micSource = null;

    this.currentViseme = "SIL";
    this.lastVisemeSwitchMs = 0;
    this.smoothOpenY = 0;
    this.smoothForm = 0;
    this.smoothRMS = 0;
  }

  ensureContext() {
    if (!this.audioCtx) {
      const Ctx = globalThis.AudioContext || globalThis.webkitAudioContext;
      if (!Ctx) {
        throw new AA2DAudioError("WebAudio API is not supported in this browser.");
      }
      this.audioCtx = new Ctx({ sampleRate: 24000 });
      this.analyser = this.audioCtx.createAnalyser();
      this.analyser.fftSize = 1024;
      this.analyser.smoothingTimeConstant = 0.5;
      this.gainNode = this.audioCtx.createGain();
      this.gainNode.gain.value = 1.0;
      this.analyser.connect(this.gainNode);
      this.gainNode.connect(this.audioCtx.destination);
      this.freqBins = new Uint8Array(this.analyser.frequencyBinCount);
      this.timeBins = new Float32Array(this.analyser.fftSize);
    }
    if (this.audioCtx.state === "suspended") {
      this.audioCtx.resume();
    }
    return this.audioCtx;
  }

  async unlockAudio() {
    const ctx = this.ensureContext();
    if (ctx.state === "suspended") {
      await ctx.resume();
    }
    return true;
  }

  /**
   * Schedules a streamed 16-bit signed little-endian mono PCM chunk on the WebAudio hardware clock.
   */
  speakPCM(pcm16Base64OrBytes, options = {}) {
    const ctx = this.ensureContext();
    const sampleRate = options.sampleRate || 24000;

    let bytes;
    if (typeof pcm16Base64OrBytes === "string") {
      const bin = atob(pcm16Base64OrBytes);
      bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) {
        bytes[i] = bin.charCodeAt(i);
      }
    } else if (pcm16Base64OrBytes instanceof Uint8Array) {
      bytes = pcm16Base64OrBytes;
    } else if (pcm16Base64OrBytes instanceof ArrayBuffer) {
      bytes = new Uint8Array(pcm16Base64OrBytes);
    } else {
      throw new AA2DAudioError("speakPCM requires a base64 string, Uint8Array, or ArrayBuffer.");
    }

    const sampleCount = Math.floor(bytes.byteLength / 2);
    if (sampleCount <= 0) {
      return 0;
    }

    const audioBuf = ctx.createBuffer(1, sampleCount, sampleRate);
    const channel = audioBuf.getChannelData(0);
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    for (let i = 0; i < sampleCount; i++) {
      channel[i] = view.getInt16(i * 2, true) / 32768.0;
    }

    const now = ctx.currentTime;
    const startAt = Math.max(now + 0.015, this.nextPlayTime);
    const duration = sampleCount / sampleRate;
    this.nextPlayTime = startAt + duration;

    const src = ctx.createBufferSource();
    src.buffer = audioBuf;
    src.connect(this.analyser);
    this.activeSources.add(src);
    src.onended = () => {
      this.activeSources.delete(src);
    };
    src.start(startAt);

    if (Array.isArray(options.frames) && options.frames.length > 0) {
      const frameDur = duration / options.frames.length;
      for (let i = 0; i < options.frames.length; i++) {
        const f = options.frames[i];
        this.telemetryQueue.push({
          t0: startAt + i * frameDur,
          t1: startAt + (i + 1) * frameDur,
          amp: f.amp ?? 0,
          form: f.form ?? 0.5,
          viseme: f.viseme || "SIL",
        });
      }
    }

    return duration;
  }

  stopSpeaking() {
    for (const src of this.activeSources) {
      try {
        src.stop();
        src.disconnect();
      } catch (err) {
        // Source already ended
      }
    }
    this.activeSources.clear();
    this.telemetryQueue.length = 0;
    if (this.audioCtx) {
      this.nextPlayTime = this.audioCtx.currentTime;
    }
    this.currentViseme = "SIL";
    this.smoothOpenY = 0;
    this.smoothRMS = 0;
  }

  async startMicrophone() {
    const ctx = this.ensureContext();
    await this.unlockAudio();
    if (this.micStream) {
      return;
    }
    this.micStream = await navigator.mediaDevices.getUserMedia({
      audio: {
        echoCancellation: true,
        noiseSuppression: true,
        autoGainControl: true,
      },
    });
    this.micSource = ctx.createMediaStreamSource(this.micStream);
    // Connect mic only to analyser, disconnect analyser from destination while mic is active to prevent feedback
    this.analyser.disconnect();
    this.micSource.connect(this.analyser);
  }

  stopMicrophone() {
    if (this.micSource) {
      this.micSource.disconnect();
      this.micSource = null;
    }
    if (this.micStream) {
      for (const track of this.micStream.getTracks()) {
        track.stop();
      }
      this.micStream = null;
    }
    if (this.analyser && this.gainNode) {
      this.analyser.disconnect();
      this.analyser.connect(this.gainNode);
    }
    this.currentViseme = "SIL";
    this.smoothOpenY = 0;
    this.smoothRMS = 0;
  }

  isSpeaking() {
    return this.activeSources.size > 0 || Boolean(this.micStream);
  }

  /**
   * Samples live audio formants (F1: 250-950Hz, F2: 950-2900Hz) and server telemetry at 60fps.
   */
  sample(nowMs = performance.now()) {
    if (!this.audioCtx || !this.analyser || !this.isSpeaking()) {
      this.smoothOpenY *= 0.72;
      this.smoothRMS *= 0.72;
      if (this.smoothOpenY < 0.04) {
        this.currentViseme = "SIL";
      }
      return {
        speaking: false,
        rms: this.smoothRMS,
        openY: this.smoothOpenY,
        form: this.smoothForm,
        viseme: this.currentViseme,
      };
    }

    this.analyser.getFloatTimeDomainData(this.timeBins);
    this.analyser.getByteFrequencyData(this.freqBins);

    let sumSq = 0;
    for (let i = 0; i < this.timeBins.length; i++) {
      const s = this.timeBins[i];
      sumSq += s * s;
    }
    const rms = Math.sqrt(sumSq / this.timeBins.length);

    const nyquist = this.audioCtx.sampleRate / 2;
    const binHz = nyquist / this.freqBins.length;

    const bandEnergy = (loHz, hiHz) => {
      const i0 = Math.max(1, Math.floor(loHz / binHz));
      const i1 = Math.min(this.freqBins.length - 1, Math.ceil(hiHz / binHz));
      let sum = 0;
      let count = 0;
      for (let i = i0; i <= i1; i++) {
        sum += this.freqBins[i] / 255.0;
        count++;
      }
      return count > 0 ? sum / count : 0;
    };

    // F1 (jaw openness: 250-950Hz) and F2 (tongue frontness/lip spread: 950-2900Hz)
    const f1 = bandEnergy(250, 950);
    const f2 = bandEnergy(950, 2900);

    let targetOpen = Math.min(1.0, Math.max(0.0, (rms - 0.015) * 5.2 + f1 * 0.65));
    let targetForm = Math.min(1.0, Math.max(0.0, f1 / (f1 + f2 + 0.05)));

    // Blend with hardware-clock aligned server telemetry frame if available
    const audioNow = this.audioCtx.currentTime;
    while (this.telemetryQueue.length > 0 && this.telemetryQueue[0].t1 < audioNow) {
      this.telemetryQueue.shift();
    }
    const activeFrame = this.telemetryQueue.find(
      (f) => audioNow >= f.t0 && audioNow <= f.t1
    );
    if (activeFrame) {
      targetOpen = Math.max(targetOpen, activeFrame.amp);
      targetForm = 0.5 * targetForm + 0.5 * activeFrame.form;
    }

    this.smoothRMS = 0.6 * this.smoothRMS + 0.4 * rms;
    this.smoothOpenY = 0.55 * this.smoothOpenY + 0.45 * targetOpen;
    this.smoothForm = 0.6 * this.smoothForm + 0.4 * targetForm;

    let candidate = "SIL";
    if (this.smoothOpenY < 0.09) {
      candidate = "SIL";
    } else if (activeFrame && activeFrame.viseme && REQUIRED_MOUTH_PATCHES.includes(activeFrame.viseme)) {
      candidate = activeFrame.viseme;
    } else if (this.smoothOpenY >= 0.48) {
      candidate = this.smoothForm >= 0.58 ? "O" : "A";
    } else if (this.smoothOpenY < 0.25) {
      candidate = this.smoothForm >= 0.56 ? "U" : "E";
    } else {
      candidate = this.smoothForm < 0.46 ? "I" : "E";
    }

    // Apply 55ms vowel hold hysteresis so visemes never flutter at 60Hz,
    // while allowing immediate closure to SIL.
    if (
      candidate === "SIL" ||
      this.currentViseme === "SIL" ||
      nowMs - this.lastVisemeSwitchMs >= 55
    ) {
      if (candidate !== this.currentViseme) {
        this.currentViseme = candidate;
        this.lastVisemeSwitchMs = nowMs;
      }
    }

    return {
      speaking: true,
      rms: this.smoothRMS,
      openY: this.smoothOpenY,
      form: this.smoothForm,
      viseme: this.currentViseme,
    };
  }
}

/**
 * AA2DAvatar: High-frame-rate 2D Canvas compositor for A2D v3.0 AvatarBundles.
 * Composites BaseSprite + seamless raised-cosine Eye+Brow patches + Mouth Viseme patches
 * under a 2D spring-damper affine motion rig.
 */
export class AA2DAvatar {
  constructor(options = {}) {
    if (!options.canvas || !(options.canvas instanceof HTMLCanvasElement)) {
      throw new AA2DRendererError("AA2DAvatar requires a valid HTMLCanvasElement in options.canvas.");
    }
    this.canvas = options.canvas;
    this.ctx = this.canvas.getContext("2d", { alpha: true });
    if (!this.ctx) {
      throw new AA2DRendererError("Failed to acquire 2D rendering context on canvas.");
    }

    this.bundle = null;
    this.images = {
      master: null,
      base: null,
      eyes: new Map(),
      mouths: new Map(),
    };

    this.lipSync = new AA2DLipSync();

    // State
    this.currentEmotion = "neutral";
    this.currentAction = "idle";
    this.actionStartMs = performance.now();
    this.manualMouthOverride = null; // null = auto (emotion / lip-sync), or "SIL"|"A"|"O"|"I"|"U"|"E"
    this.manualEyeOverride = null;   // null = auto (emotion + blink), or eye patch ID

    // Crossfade state for smooth transitions
    this.activeEyeId = "neutral_open";
    this.prevEyeId = "neutral_open";
    this.eyeFadeStartMs = 0;
    this.eyeFadeDurationMs = 90;

    this.activeMouthId = "SIL";
    this.prevMouthId = "SIL";
    this.mouthFadeStartMs = 0;
    this.mouthFadeDurationMs = 45;

    // Poisson blink state machine
    this.blinkPhase = "open"; // "open" | "closing_half" | "closed" | "opening_half"
    this.nextBlinkAtMs = performance.now() + 2600;
    this.blinkStepUntilMs = 0;

    // 2D Spring-damper gaze & pose state
    this.lookTarget = { x: 0, y: 0 };
    this.lookCurrent = { x: 0, y: 0 };
    this.poseOffset = { x: 0, y: 0, rotDeg: 0, scale: 1.0 };

    // Viewport & diagnostic flags
    this.viewportMode = "stage"; // "stage" | "patches" | "onion"
    this.viewTransform = { zoom: 1.0, panX: 0, panY: 0 };
    this.onionSplitX = 0.5;
    this.debugFlags = {
      showPatchBounds: false,
      showPivot: false,
    };

    // Telemetry
    this.fps = 60;
    this.frameTimeMs = 1.0;
    this._lastFrameMs = performance.now();
    this._rafId = null;

    if (options.autoStart !== false) {
      this.start();
    }
  }

  async loadBundle(bundleOrUrl) {
    let bundle = bundleOrUrl;
    if (typeof bundleOrUrl === "string") {
      const resp = await fetch(bundleOrUrl, { cache: "no-store" });
      if (!resp.ok) {
        throw new AA2DSchemaError(`Failed to fetch avatar bundle from "${bundleOrUrl}": HTTP ${resp.status}`);
      }
      bundle = await resp.json();
    }

    validateAvatarBundle(bundle);

    const loadImg = (uri, label) =>
      new Promise((resolve, reject) => {
        const img = new Image();
        img.onload = () => resolve(img);
        img.onerror = () => reject(new AA2DRendererError(`Failed to decode image for ${label}`));
        img.src = uri;
      });

    const [masterImg, baseImg] = await Promise.all([
      loadImg(bundle.master_image, "master_image"),
      loadImg(bundle.base_sprite, "base_sprite"),
    ]);

    const eyeMap = new Map();
    await Promise.all(
      Object.entries(bundle.eye_patches).map(async ([id, spec]) => {
        const img = await loadImg(spec.data_uri, `eye_patch:${id}`);
        eyeMap.set(id, img);
      })
    );

    const mouthMap = new Map();
    await Promise.all(
      Object.entries(bundle.mouth_patches).map(async ([id, spec]) => {
        const img = await loadImg(spec.data_uri, `mouth_patch:${id}`);
        mouthMap.set(id, img);
      })
    );

    this.bundle = bundle;
    this.images = {
      master: masterImg,
      base: baseImg,
      eyes: eyeMap,
      mouths: mouthMap,
    };

    this.canvas.width = bundle.canvas.width || 1024;
    this.canvas.height = bundle.canvas.height || 1024;

    this.setEmotion("neutral");
    this.setAction("idle");
    this.renderFrame(performance.now());
    return bundle;
  }

  // Alias for compatibility
  async loadDocument(doc) {
    return this.loadBundle(doc);
  }

  start() {
    if (this._rafId !== null) {
      return;
    }
    const loop = (now) => {
      this.renderFrame(now);
      this._rafId = requestAnimationFrame(loop);
    };
    this._rafId = requestAnimationFrame(loop);
  }

  stop() {
    if (this._rafId !== null) {
      cancelAnimationFrame(this._rafId);
      this._rafId = null;
    }
  }

  setEmotion(emotionId) {
    if (!this.bundle) {
      this.currentEmotion = emotionId;
      return;
    }
    if (!this.bundle.emotions[emotionId]) {
      throw new AA2DSchemaError(`Unknown emotion preset "${emotionId}".`);
    }
    this.currentEmotion = emotionId;
    this.manualEyeOverride = null;
    const preset = this.bundle.emotions[emotionId];
    this._transitionEyePatch(preset.eye_patch_open, 140);
    if (!this.lipSync.isSpeaking() && !this.manualMouthOverride) {
      this._transitionMouthPatch(preset.default_mouth || "SIL", 90);
    }
  }

  setAction(actionId) {
    if (this.bundle && !this.bundle.actions[actionId]) {
      throw new AA2DSchemaError(`Unknown action preset "${actionId}".`);
    }
    this.currentAction = actionId;
    this.actionStartMs = performance.now();
  }

  setManualViseme(visemeId) {
    if (visemeId && !REQUIRED_MOUTH_PATCHES.includes(visemeId)) {
      throw new AA2DSchemaError(`Unknown mouth viseme "${visemeId}".`);
    }
    this.manualMouthOverride = visemeId || null;
    if (visemeId) {
      this._transitionMouthPatch(visemeId, 45);
    } else if (this.bundle) {
      const preset = this.bundle.emotions[this.currentEmotion] || this.bundle.emotions.neutral;
      this._transitionMouthPatch(preset.default_mouth || "SIL", 60);
    }
  }

  setManualEyePatch(eyePatchId) {
    if (eyePatchId && !REQUIRED_EYE_PATCHES.includes(eyePatchId)) {
      throw new AA2DSchemaError(`Unknown eye patch "${eyePatchId}".`);
    }
    this.manualEyeOverride = eyePatchId || null;
    if (eyePatchId) {
      this._transitionEyePatch(eyePatchId, 80);
    } else if (this.bundle) {
      const preset = this.bundle.emotions[this.currentEmotion] || this.bundle.emotions.neutral;
      this._transitionEyePatch(preset.eye_patch_open, 80);
    }
  }

  triggerBlink() {
    const now = performance.now();
    this.blinkPhase = "closing_half";
    this.blinkStepUntilMs = now + 48;
    if (this.bundle) {
      const preset = this.bundle.emotions[this.currentEmotion] || this.bundle.emotions.neutral;
      this._transitionEyePatch(preset.eye_patch_half, 0);
    }
  }

  lookAt(nx, ny) {
    this.lookTarget.x = Math.max(-1, Math.min(1, Number(nx) || 0));
    this.lookTarget.y = Math.max(-1, Math.min(1, Number(ny) || 0));
  }

  clearLookAt() {
    this.lookTarget.x = 0;
    this.lookTarget.y = 0;
  }

  setViewportMode(mode) {
    if (!["stage", "patches", "onion"].includes(mode)) {
      throw new AA2DRendererError(`Unsupported viewport mode "${mode}".`);
    }
    this.viewportMode = mode;
  }

  setViewTransform({ zoom, panX, panY }) {
    if (typeof zoom === "number") this.viewTransform.zoom = Math.max(0.4, Math.min(3.0, zoom));
    if (typeof panX === "number") this.viewTransform.panX = panX;
    if (typeof panY === "number") this.viewTransform.panY = panY;
  }

  setOnionSplit(splitX) {
    this.onionSplitX = Math.max(0.0, Math.min(1.0, Number(splitX) || 0.5));
  }

  setDebugFlags(flags = {}) {
    this.debugFlags = { ...this.debugFlags, ...flags };
  }

  async unlockAudio() {
    return this.lipSync.unlockAudio();
  }

  speakPCM(pcm16Base64OrBytes, options = {}) {
    return this.lipSync.speakPCM(pcm16Base64OrBytes, options);
  }

  stopSpeaking() {
    this.lipSync.stopSpeaking();
  }

  async startMicrophone() {
    return this.lipSync.startMicrophone();
  }

  stopMicrophone() {
    this.lipSync.stopMicrophone();
  }

  getTelemetry() {
    return {
      fps: Math.round(this.fps),
      frameTimeMs: Number(this.frameTimeMs.toFixed(2)),
      emotion: this.currentEmotion,
      action: this.currentAction,
      activeEyePatch: this.activeEyeId,
      activeMouthPatch: this.activeMouthId,
      eyePatchCount: this.bundle ? Object.keys(this.bundle.eye_patches).length : 0,
      mouthPatchCount: this.bundle ? Object.keys(this.bundle.mouth_patches).length : 0,
      lipSync: this.lipSync.sample(),
    };
  }

  _transitionEyePatch(nextId, durationMs = 0) {
    if (nextId === this.activeEyeId) return;
    this.prevEyeId = this.activeEyeId;
    this.activeEyeId = nextId;
    this.eyeFadeStartMs = performance.now();
    this.eyeFadeDurationMs = Math.max(0, durationMs);
  }

  _transitionMouthPatch(nextId, durationMs = 0) {
    if (nextId === this.activeMouthId) return;
    this.prevMouthId = this.activeMouthId;
    this.activeMouthId = nextId;
    this.mouthFadeStartMs = performance.now();
    this.mouthFadeDurationMs = Math.max(0, durationMs);
  }

  _updateBlinkAndLipSync(nowMs) {
    if (!this.bundle) return;
    const preset = this.bundle.emotions[this.currentEmotion] || this.bundle.emotions.neutral;

    // 1. Update Poisson blink state machine using crisp discrete anime key-frames (zero ghost double-lashes)
    if (!this.manualEyeOverride) {
      if (this.blinkPhase === "open") {
        if (nowMs >= this.nextBlinkAtMs) {
          this.blinkPhase = "closing_half";
          this.blinkStepUntilMs = nowMs + 48;
          this._transitionEyePatch(preset.eye_patch_half, 0);
        } else if (this.activeEyeId !== preset.eye_patch_open) {
          this._transitionEyePatch(preset.eye_patch_open, 90);
        }
      } else if (this.blinkPhase === "closing_half" && nowMs >= this.blinkStepUntilMs) {
        this.blinkPhase = "closed";
        this.blinkStepUntilMs = nowMs + 76;
        this._transitionEyePatch(preset.eye_patch_closed, 0);
      } else if (this.blinkPhase === "closed" && nowMs >= this.blinkStepUntilMs) {
        this.blinkPhase = "opening_half";
        this.blinkStepUntilMs = nowMs + 48;
        this._transitionEyePatch(preset.eye_patch_half, 0);
      } else if (this.blinkPhase === "opening_half" && nowMs >= this.blinkStepUntilMs) {
        this.blinkPhase = "open";
        const doubleBlink = Math.random() < 0.14;
        this.nextBlinkAtMs = nowMs + (doubleBlink ? 240 : 2500 + Math.random() * 3200);
        this._transitionEyePatch(preset.eye_patch_open, 0);
      }
    }

    // 2. Update mouth viseme from live WebAudio lip-sync, or procedural syllable cadence when action==="speak", or resting emotion mouth
    const lip = this.lipSync.sample(nowMs);
    let proceduralSpeakBounce = 0;
    if (this.manualMouthOverride) {
      this._transitionMouthPatch(this.manualMouthOverride, 0);
    } else if (lip.speaking && lip.viseme !== "SIL") {
      this._transitionMouthPatch(lip.viseme, 0);
    } else if (lip.speaking && lip.viseme === "SIL") {
      this._transitionMouthPatch("SIL", 0);
    } else if (this.currentAction === "speak") {
      // Procedural anime speech syllable cadence when driven via action="speak" attribute without WebAudio PCM
      const syllables = ["A", "E", "O", "I", "A", "U", "E", "SIL"];
      const slot = Math.floor(nowMs / 115) % syllables.length;
      const vis = syllables[slot];
      this._transitionMouthPatch(vis, 0);
      proceduralSpeakBounce = vis === "SIL" ? 0 : -2.6;
    } else {
      this._transitionMouthPatch(preset.default_mouth || "SIL", 0);
    }

    // 3. Update 2D spring-damper affine body/head pose
    this.lookCurrent.x += (this.lookTarget.x - this.lookCurrent.x) * 0.12;
    this.lookCurrent.y += (this.lookTarget.y - this.lookCurrent.y) * 0.12;

    const tSec = nowMs * 0.001;
    const breathY = Math.sin(tSec * 2.0) * 3.0;
    const breathScale = 1.0 + Math.sin(tSec * 2.0) * 0.0035;

    let actX = 0;
    let actY = 0;
    let actRot = 0;
    let actScale = 0;

    const action = this.bundle.actions[this.currentAction] || this.bundle.actions.idle;
    if (action) {
      const elapsed = (nowMs - this.actionStartMs) * 0.001;
      if (!action.loop && action.duration_sec > 0 && elapsed > action.duration_sec) {
        this.currentAction = "idle";
      } else {
        const envelope =
          !action.loop && action.duration_sec > 0
            ? Math.sin((Math.min(elapsed, action.duration_sec) / action.duration_sec) * Math.PI)
            : 1.0;
        const phase = elapsed * action.freq_hz * Math.PI * 2;
        actX = Math.sin(phase) * action.amp_x * envelope;
        actY = Math.abs(Math.sin(phase)) * action.amp_y * envelope;
        actRot = Math.sin(phase * 0.5) * action.amp_rot_deg * envelope;
        actScale = Math.sin(phase) * action.amp_scale * envelope;
      }
    }

    const speechBounceY = lip.speaking ? -lip.openY * 4.2 : proceduralSpeakBounce;
    const targetX = this.lookCurrent.x * 10.0 + actX;
    const targetY = breathY + (preset.offset_y || 0) + this.lookCurrent.y * 6.0 + actY + speechBounceY;
    const targetRot = (preset.head_tilt_deg || 0) + this.lookCurrent.x * 2.8 + actRot;
    const targetScale = breathScale + actScale;

    this.poseOffset.x += (targetX - this.poseOffset.x) * 0.18;
    this.poseOffset.y += (targetY - this.poseOffset.y) * 0.18;
    this.poseOffset.rotDeg += (targetRot - this.poseOffset.rotDeg) * 0.18;
    this.poseOffset.scale += (targetScale - this.poseOffset.scale) * 0.18;
  }

  renderFrame(nowMs = performance.now()) {
    const t0 = performance.now();
    const dt = Math.max(1, nowMs - this._lastFrameMs);
    this._lastFrameMs = nowMs;
    this.fps = 0.9 * this.fps + 0.1 * (1000 / dt);

    if (!this.bundle || !this.images.base) {
      return;
    }

    this._updateBlinkAndLipSync(nowMs);

    const ctx = this.ctx;
    const W = this.canvas.width;
    const H = this.canvas.height;
    ctx.clearRect(0, 0, W, H);

    if (this.viewportMode === "patches") {
      this._renderPatchesContactSheet(ctx, W, H);
      this.frameTimeMs = performance.now() - t0;
      return;
    }

    ctx.save();
    // Apply user pan & zoom around canvas center
    ctx.translate(W * 0.5 + this.viewTransform.panX, H * 0.5 + this.viewTransform.panY);
    ctx.scale(this.viewTransform.zoom, this.viewTransform.zoom);
    ctx.translate(-W * 0.5, -H * 0.5);

    this._drawCompositedAvatar(ctx, nowMs);

    // If Onion-Skin split-wipe mode is active, draw MasterImage on the left side of splitX
    if (this.viewportMode === "onion" && this.images.master) {
      const splitPx = Math.round(W * this.onionSplitX);
      ctx.save();
      ctx.beginPath();
      ctx.rect(0, 0, splitPx, H);
      ctx.clip();
      ctx.drawImage(this.images.master, 0, 0, W, H);
      ctx.restore();

      ctx.save();
      ctx.strokeStyle = "#38BDF8";
      ctx.lineWidth = 3;
      ctx.beginPath();
      ctx.moveTo(splitPx, 0);
      ctx.lineTo(splitPx, H);
      ctx.stroke();
      ctx.restore();
    }

    ctx.restore();
    this.frameTimeMs = performance.now() - t0;
  }

  _drawCompositedAvatar(ctx, nowMs) {
    const W = this.canvas.width;
    const H = this.canvas.height;
    const pivot = this.bundle.head_pivot || { x: W * 0.5, y: H * 0.68 };

    ctx.save();
    ctx.translate(pivot.x + this.poseOffset.x, pivot.y + this.poseOffset.y);
    ctx.rotate((this.poseOffset.rotDeg * Math.PI) / 180.0);
    ctx.scale(this.poseOffset.scale, this.poseOffset.scale);
    ctx.translate(-pivot.x, -pivot.y);

    // 1. Draw full BaseSprite (hair, head, ears, torso, clothing 100% intact)
    ctx.drawImage(this.images.base, 0, 0, W, H);

    // 2. Draw active Eye+Brow Patch
    const er = this.bundle.eyes_rect;
    const eyeAlpha =
      this.eyeFadeDurationMs <= 0
        ? 1.0
        : Math.min(1.0, Math.max(0.0, (nowMs - this.eyeFadeStartMs) / this.eyeFadeDurationMs));
    if (eyeAlpha < 1.0 && this.prevEyeId && this.images.eyes.has(this.prevEyeId)) {
      ctx.drawImage(this.images.eyes.get(this.prevEyeId), er.x, er.y, er.w, er.h);
    }
    if (this.images.eyes.has(this.activeEyeId)) {
      ctx.save();
      ctx.globalAlpha = eyeAlpha;
      ctx.drawImage(this.images.eyes.get(this.activeEyeId), er.x, er.y, er.w, er.h);
      ctx.restore();
    }

    // 3. Draw active Mouth Viseme Patch
    const mr = this.bundle.mouth_rect;
    const mouthAlpha =
      this.mouthFadeDurationMs <= 0
        ? 1.0
        : Math.min(1.0, Math.max(0.0, (nowMs - this.mouthFadeStartMs) / this.mouthFadeDurationMs));
    if (mouthAlpha < 1.0 && this.prevMouthId && this.images.mouths.has(this.prevMouthId)) {
      ctx.drawImage(this.images.mouths.get(this.prevMouthId), mr.x, mr.y, mr.w, mr.h);
    }
    if (this.images.mouths.has(this.activeMouthId)) {
      ctx.save();
      ctx.globalAlpha = mouthAlpha;
      ctx.drawImage(this.images.mouths.get(this.activeMouthId), mr.x, mr.y, mr.w, mr.h);
      ctx.restore();
    }

    // 4. Optional Debug Overlays (EyesRect, MouthRect, HeadPivot)
    if (this.debugFlags.showPatchBounds) {
      ctx.save();
      ctx.strokeStyle = "#38BDF8";
      ctx.lineWidth = 2;
      ctx.setLineDash([6, 4]);
      ctx.strokeRect(er.x, er.y, er.w, er.h);
      ctx.fillStyle = "rgba(56, 189, 248, 0.88)";
      ctx.font = "600 18px ui-monospace, SFMono-Regular, monospace";
      ctx.fillText(`eyes_rect (${this.activeEyeId})`, er.x + 8, er.y - 8);

      ctx.strokeStyle = "#F472B6";
      ctx.strokeRect(mr.x, mr.y, mr.w, mr.h);
      ctx.fillStyle = "rgba(244, 114, 182, 0.9)";
      ctx.fillText(`mouth_rect (${this.activeMouthId})`, mr.x + 8, mr.y + mr.h + 22);
      ctx.restore();
    }

    if (this.debugFlags.showPivot) {
      ctx.save();
      ctx.strokeStyle = "#A3E635";
      ctx.lineWidth = 2.5;
      ctx.beginPath();
      ctx.arc(pivot.x, pivot.y, 12, 0, Math.PI * 2);
      ctx.moveTo(pivot.x - 18, pivot.y);
      ctx.lineTo(pivot.x + 18, pivot.y);
      ctx.moveTo(pivot.x, pivot.y - 18);
      ctx.lineTo(pivot.x, pivot.y + 18);
      ctx.stroke();
      ctx.restore();
    }

    ctx.restore();
  }

  _renderPatchesContactSheet(ctx, W, H) {
    ctx.fillStyle = "#0B0E17";
    ctx.fillRect(0, 0, W, H);

    ctx.fillStyle = "#E2E8F0";
    ctx.font = "700 22px system-ui, -apple-system, sans-serif";
    ctx.fillText("A2D v3.0 · Seamless AI Expression & Viseme Patch Atlas", 28, 42);

    // Draw Eye Patches (7) in left/top grid
    let y = 68;
    ctx.fillStyle = "#38BDF8";
    ctx.font = "600 16px ui-monospace, monospace";
    ctx.fillText("7 Eye + Eyebrow Expression Patches (Raised-Cosine Feathered):", 28, y);
    y += 14;

    const cols = 2;
    const cellW = Math.floor((W - 72) / cols);
    const cellH = 128;
    REQUIRED_EYE_PATCHES.forEach((id, idx) => {
      const col = idx % cols;
      const row = Math.floor(idx / cols);
      const cx = 28 + col * (cellW + 16);
      const cy = y + row * (cellH + 14);
      const img = this.images.eyes.get(id);
      const isActive = id === this.activeEyeId;

      ctx.fillStyle = isActive ? "rgba(56, 189, 248, 0.16)" : "rgba(30, 41, 59, 0.65)";
      ctx.strokeStyle = isActive ? "#38BDF8" : "rgba(148, 163, 184, 0.25)";
      ctx.lineWidth = isActive ? 2.5 : 1;
      ctx.beginPath();
      ctx.roundRect(cx, cy, cellW, cellH, 8);
      ctx.fill();
      ctx.stroke();

      if (img) {
        const pad = 8;
        const availW = cellW - pad * 2;
        const availH = cellH - 32;
        const scale = Math.min(availW / img.width, availH / img.height);
        const dw = img.width * scale;
        const dh = img.height * scale;
        ctx.drawImage(img, cx + (cellW - dw) * 0.5, cy + 6 + (availH - dh) * 0.5, dw, dh);
      }

      ctx.fillStyle = isActive ? "#38BDF8" : "#CBD5E1";
      ctx.font = "600 14px ui-monospace, monospace";
      ctx.fillText(`eye: ${id}${isActive ? " ● ACTIVE" : ""}`, cx + 10, cy + cellH - 8);
    });

    // Draw Mouth Viseme Patches (6) in bottom 3x2 grid
    const mouthStartY = y + 4 * (cellH + 14) + 18;
    ctx.fillStyle = "#F472B6";
    ctx.font = "600 16px ui-monospace, monospace";
    ctx.fillText("6 Mouth Viseme Patches (SIL, A, O, I, U, E):", 28, mouthStartY);

    const mCols = 3;
    const mCellW = Math.floor((W - 88) / mCols);
    const mCellH = 132;
    REQUIRED_MOUTH_PATCHES.forEach((id, idx) => {
      const col = idx % mCols;
      const row = Math.floor(idx / mCols);
      const cx = 28 + col * (mCellW + 16);
      const cy = mouthStartY + 14 + row * (mCellH + 14);
      const img = this.images.mouths.get(id);
      const isActive = id === this.activeMouthId;

      ctx.fillStyle = isActive ? "rgba(244, 114, 182, 0.16)" : "rgba(30, 41, 59, 0.65)";
      ctx.strokeStyle = isActive ? "#F472B6" : "rgba(148, 163, 184, 0.25)";
      ctx.lineWidth = isActive ? 2.5 : 1;
      ctx.beginPath();
      ctx.roundRect(cx, cy, mCellW, mCellH, 8);
      ctx.fill();
      ctx.stroke();

      if (img) {
        const pad = 10;
        const availW = mCellW - pad * 2;
        const availH = mCellH - 34;
        const scale = Math.min(availW / img.width, availH / img.height);
        const dw = img.width * scale;
        const dh = img.height * scale;
        ctx.drawImage(img, cx + (mCellW - dw) * 0.5, cy + 6 + (availH - dh) * 0.5, dw, dh);
      }

      ctx.fillStyle = isActive ? "#F472B6" : "#CBD5E1";
      ctx.font = "600 14px ui-monospace, monospace";
      ctx.fillText(`viseme: ${id}${isActive ? " ● ACTIVE" : ""}`, cx + 10, cy + mCellH - 8);
    });
  }
}

/**
 * <aa2d-avatar> Custom Web Component
 */
export class AA2DElement extends (globalThis.HTMLElement || class {}) {
  static get observedAttributes() {
    return ["src", "emotion", "action", "follow-cursor"];
  }

  constructor() {
    super();
    this.attachShadow({ mode: "open" });
    this.shadowRoot.innerHTML = `
      <style>
        :host { display: inline-block; width: 512px; height: 512px; }
        canvas { width: 100%; height: 100%; display: block; object-fit: contain; }
      </style>
      <canvas width="1024" height="1024"></canvas>
    `;
    this.canvas = this.shadowRoot.querySelector("canvas");
    this.avatar = null;
    this._onWindowPointerMove = (e) => {
      if (!this.avatar || !this.followCursor) return;
      const rect = this.getBoundingClientRect();
      if (rect.width <= 0 || rect.height <= 0) return;
      const cx = rect.left + rect.width * 0.5;
      const cy = rect.top + rect.height * 0.5;
      const nx = Math.max(-1, Math.min(1, (e.clientX - cx) / Math.max(120, rect.width * 0.75)));
      const ny = Math.max(-1, Math.min(1, (e.clientY - cy) / Math.max(120, rect.height * 0.75)));
      this.avatar.lookAt(nx, ny);
    };
  }

  _dispatchError(err) {
    this.dispatchEvent(
      new CustomEvent("aa2d-error", {
        detail: {
          error: err instanceof Error ? err : new Error(String(err)),
        },
        bubbles: true,
        composed: true,
      })
    );
  }

  connectedCallback() {
    if (!this.avatar) {
      this.avatar = new AA2DAvatar({ canvas: this.canvas, autoStart: true });
    }
    globalThis.addEventListener("pointermove", this._onWindowPointerMove, { passive: true });
    const src = this.getAttribute("src");
    if (src) {
      this.avatar
        .loadBundle(src)
        .then(() => {
          if (this.hasAttribute("emotion")) {
            this.avatar.setEmotion(this.getAttribute("emotion"));
          }
          if (this.hasAttribute("action")) {
            this.avatar.setAction(this.getAttribute("action"));
          }
        })
        .catch((err) => this._dispatchError(err));
    }
  }

  disconnectedCallback() {
    globalThis.removeEventListener("pointermove", this._onWindowPointerMove);
    if (this.avatar) {
      this.avatar.stopSpeaking();
      this.avatar.stopMicrophone();
      this.avatar.stop();
    }
  }

  attributeChangedCallback(name, oldVal, newVal) {
    if (!this.avatar || oldVal === newVal) return;
    if (name === "src" && newVal) {
      this.avatar.loadBundle(newVal).catch((err) => this._dispatchError(err));
    } else if (name === "emotion" && newVal) {
      this.avatar.setEmotion(newVal);
    } else if (name === "action" && newVal) {
      this.avatar.setAction(newVal);
    } else if (name === "follow-cursor" && newVal === null) {
      this.avatar.clearLookAt();
    }
  }

  get src() {
    return this.getAttribute("src") || "";
  }
  set src(val) {
    this.setAttribute("src", val);
  }

  get emotion() {
    return this.getAttribute("emotion") || "neutral";
  }
  set emotion(val) {
    this.setAttribute("emotion", val);
  }

  get action() {
    return this.getAttribute("action") || "idle";
  }
  set action(val) {
    this.setAttribute("action", val);
  }

  get followCursor() {
    return this.hasAttribute("follow-cursor") && this.getAttribute("follow-cursor") !== "false";
  }
  set followCursor(val) {
    if (val) {
      this.setAttribute("follow-cursor", "");
    } else {
      this.removeAttribute("follow-cursor");
    }
  }

  setEmotion(emotionId) {
    if (this.avatar) this.avatar.setEmotion(emotionId);
  }
  setAction(actionId) {
    if (this.avatar) this.avatar.setAction(actionId);
  }
  triggerBlink() {
    if (this.avatar) this.avatar.triggerBlink();
  }
  lookAt(nx, ny) {
    if (this.avatar) this.avatar.lookAt(nx, ny);
  }
  clearLookAt() {
    if (this.avatar) this.avatar.clearLookAt();
  }
  speakPCM(pcm, options) {
    return this.avatar ? this.avatar.speakPCM(pcm, options) : 0;
  }
  stopSpeaking() {
    if (this.avatar) this.avatar.stopSpeaking();
  }
  getTelemetry() {
    return this.avatar ? this.avatar.getTelemetry() : null;
  }
}

if (globalThis.customElements && !globalThis.customElements.get("aa2d-avatar")) {
  globalThis.customElements.define("aa2d-avatar", AA2DElement);
}
