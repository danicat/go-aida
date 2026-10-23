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

export class AA2DSchemaError extends Error {}
export class AA2DRendererError extends Error {}
export class AA2DAudioError extends Error {}

export interface AA2DRect {
  x: number;
  y: number;
  w: number;
  h: number;
}

export interface AA2DPoint {
  x: number;
  y: number;
}

export interface AA2DPatchSprite {
  id: string;
  label: string;
  category: "eyes" | "mouth";
  rect: AA2DRect;
  data_uri: string;
}

export interface AA2DEmotionPreset {
  id: string;
  label: string;
  eye_patch_open: string;
  eye_patch_half: string;
  eye_patch_closed: string;
  default_mouth: string;
  cheek_tint_opacity: number;
  head_tilt_deg: number;
  offset_y: number;
}

export interface AA2DActionPreset {
  id: string;
  label: string;
  loop: boolean;
  duration_sec: number;
  freq_hz: number;
  amp_x: number;
  amp_y: number;
  amp_rot_deg: number;
  amp_scale: number;
}

export interface AA2DAvatarBundle {
  version: "3.0.0";
  standard: "A2D";
  metadata: {
    id: string;
    name: string;
    description?: string;
    chroma_key_color: string;
    eye_patch_count: number;
    mouth_patch_count: number;
    created_at: string;
  };
  canvas: {
    width: number;
    height: number;
    background_color: string;
  };
  master_image: string;
  base_sprite: string;
  eyes_rect: AA2DRect;
  mouth_rect: AA2DRect;
  head_pivot: AA2DPoint;
  eye_patches: Record<string, AA2DPatchSprite>;
  mouth_patches: Record<string, AA2DPatchSprite>;
  emotions: Record<string, AA2DEmotionPreset>;
  actions: Record<string, AA2DActionPreset>;
}

export function validateAvatarBundle(bundle: unknown): bundle is AA2DAvatarBundle;

export class AA2DLipSync {
  unlockAudio(): Promise<boolean>;
  speakPCM(
    pcm16Base64OrBytes: string | Uint8Array | ArrayBuffer,
    options?: {
      sampleRate?: number;
      frames?: Array<{ amp: number; form: number; viseme: string }>;
    }
  ): number;
  stopSpeaking(): void;
  startMicrophone(): Promise<void>;
  stopMicrophone(): void;
  isSpeaking(): boolean;
  sample(nowMs?: number): {
    speaking: boolean;
    rms: number;
    openY: number;
    form: number;
    viseme: string;
  };
}

export class AA2DAvatar {
  constructor(options: { canvas: HTMLCanvasElement; autoStart?: boolean });
  loadBundle(bundleOrUrl: AA2DAvatarBundle | string): Promise<AA2DAvatarBundle>;
  loadDocument(doc: AA2DAvatarBundle | string): Promise<AA2DAvatarBundle>;
  start(): void;
  stop(): void;
  setEmotion(emotionId: string): void;
  setAction(actionId: string): void;
  setManualViseme(visemeId: string | null): void;
  setManualEyePatch(eyePatchId: string | null): void;
  triggerBlink(): void;
  lookAt(nx: number, ny: number): void;
  clearLookAt(): void;
  setViewportMode(mode: "stage" | "patches" | "onion"): void;
  setViewTransform(transform: { zoom?: number; panX?: number; panY?: number }): void;
  setOnionSplit(splitX: number): void;
  setDebugFlags(flags: { showPatchBounds?: boolean; showPivot?: boolean }): void;
  unlockAudio(): Promise<boolean>;
  speakPCM(
    pcm16Base64OrBytes: string | Uint8Array | ArrayBuffer,
    options?: {
      sampleRate?: number;
      frames?: Array<{ amp: number; form: number; viseme: string }>;
    }
  ): number;
  stopSpeaking(): void;
  startMicrophone(): Promise<void>;
  stopMicrophone(): void;
  getTelemetry(): {
    fps: number;
    frameTimeMs: number;
    emotion: string;
    action: string;
    activeEyePatch: string;
    activeMouthPatch: string;
    eyePatchCount: number;
    mouthPatchCount: number;
    lipSync: {
      speaking: boolean;
      rms: number;
      openY: number;
      form: number;
      viseme: string;
    };
  };
}

export class AA2DElement extends HTMLElement {
  avatar: AA2DAvatar | null;
  src: string;
  emotion: string;
  action: string;
  followCursor: boolean;
  setEmotion(emotionId: string): void;
  setAction(actionId: string): void;
  triggerBlink(): void;
  lookAt(nx: number, ny: number): void;
  clearLookAt(): void;
  speakPCM(
    pcm16Base64OrBytes: string | Uint8Array | ArrayBuffer,
    options?: {
      sampleRate?: number;
      frames?: Array<{ amp: number; form: number; viseme: string }>;
    }
  ): number;
  stopSpeaking(): void;
  getTelemetry(): ReturnType<AA2DAvatar["getTelemetry"]> | null;
}

declare global {
  interface HTMLElementTagNameMap {
    "aa2d-avatar": AA2DElement;
  }
}
