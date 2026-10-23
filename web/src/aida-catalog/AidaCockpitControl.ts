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

import { html, css, nothing, type PropertyValues } from "lit";
import { customElement, state } from "lit/decorators.js";
import { z } from "zod";
import { type LitComponentApi } from "@a2ui/lit/v0_9";
import { CommonSchemas } from "@a2ui/web_core/v0_9";
import { AidaCatalogElement, aidaCatalogBaseStyles } from "./base.js";
import type { StylePresetId, ThemeMode } from "../types.js";

const PRESET_CHIPS: ReadonlyArray<{
  id: StylePresetId;
  label: string;
  accent: string;
  theme: ThemeMode;
}> = [
  { id: "pc98-cyan", label: "PC-98 Cyan", accent: "#00f0ff", theme: "dark" },
  {
    id: "amber-phosphor",
    label: "Amber Phosphor",
    accent: "#ffb000",
    theme: "dark",
  },
  {
    id: "emerald-matrix",
    label: "Emerald Matrix",
    accent: "#00ff88",
    theme: "dark",
  },
  {
    id: "crimson-alert",
    label: "Crimson Alert",
    accent: "#ff2a6d",
    theme: "dark",
  },
  {
    id: "violet-synth",
    label: "Violet Synth",
    accent: "#c084fc",
    theme: "dark",
  },
  {
    id: "daylight-paper",
    label: "Daylight Paper",
    accent: "#0055cc",
    theme: "light",
  },
];

export const AidaCockpitApplyStyleSchema = z.object({
  theme: z.enum(["dark", "light"]).optional(),
  preset: z
    .enum([
      "pc98-cyan",
      "amber-phosphor",
      "emerald-matrix",
      "crimson-alert",
      "violet-synth",
      "daylight-paper",
    ])
    .optional(),
  accent: z.string().optional(),
  bgPanel: z.string().optional(),
  text: z.string().optional(),
  fontScale: z.number().optional(),
  scanlines: z.boolean().optional(),
});

export const AidaCockpitApplyAvatarSchema = z.object({
  renderer: z.enum(["pc98", "aa2d"]).optional(),
  state: z.enum(["idle", "think", "talk", "teehee", "error"]).optional(),
  aa2dAction: z.string().optional(),
  aa2dEmotion: z.string().optional(),
  speech: z.string().optional(),
  statusText: z.string().optional(),
});

export const AidaCockpitShortcutSchema = z.object({
  label: z.string(),
  action: z.string(),
  target: z.union([z.string(), z.number()]).optional(),
});

export const AidaCockpitControlSchema = z.object({
  title: CommonSchemas.DynamicString.optional(),
  subtitle: CommonSchemas.DynamicString.optional(),
  mode: z
    .enum(["all", "navigation", "style", "avatar", "workspace"])
    .default("all")
    .optional(),
  applyStyle: AidaCockpitApplyStyleSchema.optional(),
  applyAvatar: AidaCockpitApplyAvatarSchema.optional(),
  shortcuts: z.array(AidaCockpitShortcutSchema).optional(),
  weight: z.number().optional(),
});

export type AidaCockpitControlProps = z.infer<typeof AidaCockpitControlSchema>;

@customElement("aida-cockpit-control")
export class AidaCockpitControlElement extends AidaCatalogElement<
  typeof AidaCockpitControlApi
> {
  static tagName = "aida-cockpit-control";
  protected override readonly api = AidaCockpitControlApi;

  @state() private accessor activePreset: StylePresetId = "pc98-cyan";
  @state() private accessor fontScale = 1;
  @state() private accessor scanlines = true;
  @state() private accessor avatarRenderer: "pc98" | "aa2d" = "pc98";
  @state() private accessor avatarState:
    | "idle"
    | "think"
    | "talk"
    | "teehee"
    | "error" = "idle";

  private appliedSignature = "";

  static override styles = [
    aidaCatalogBaseStyles,
    css`
      .sections-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
        gap: 12px;
      }

      .ctrl-section {
        border: 1px solid var(--aida-border, #3b4cca);
        background: var(--aida-bg-elevated, #111a3a);
        padding: 10px 12px;
        display: flex;
        flex-direction: column;
        gap: 10px;
      }

      .sec-title {
        margin: 0;
        font-family: var(--aida-font-display, "Orbitron", sans-serif);
        font-size: 0.72rem;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        color: var(--aida-accent, #00f0ff);
        display: flex;
        align-items: center;
        justify-content: space-between;
      }

      .btn-row {
        display: flex;
        flex-wrap: wrap;
        gap: 6px;
      }

      .ctrl-btn {
        appearance: none;
        background: var(--aida-bg-panel, #0a1026);
        border: 1px solid var(--aida-border, #3b4cca);
        color: var(--aida-text, #e2f1ff);
        font-family: inherit;
        font-size: 0.74rem;
        padding: 5px 10px;
        cursor: pointer;
        display: inline-flex;
        align-items: center;
        gap: 6px;
        transition: all 0.14s ease;
      }

      .ctrl-btn:hover {
        border-color: var(--aida-accent, #00f0ff);
        background: var(--aida-glow, rgba(0, 240, 255, 0.16));
      }

      .ctrl-btn.active {
        background: var(--aida-accent, #00f0ff);
        color: var(--aida-bg-panel, #0a1026);
        border-color: var(--aida-accent, #00f0ff);
        font-weight: 700;
      }

      .preset-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(125px, 1fr));
        gap: 6px;
      }

      .preset-chip {
        appearance: none;
        background: var(--aida-bg-panel, #0a1026);
        border: 1px solid var(--aida-border, #3b4cca);
        color: var(--aida-text, #e2f1ff);
        font-family: inherit;
        font-size: 0.72rem;
        padding: 6px 8px;
        cursor: pointer;
        display: flex;
        align-items: center;
        gap: 7px;
        text-align: left;
      }

      .preset-chip:hover,
      .preset-chip.active {
        border-color: var(--aida-accent, #00f0ff);
        background: var(--aida-glow, rgba(0, 240, 255, 0.15));
        font-weight: 700;
      }

      .swatch-dot {
        width: 10px;
        height: 10px;
        border-radius: 50%;
        flex-shrink: 0;
      }

      .slider-row {
        display: flex;
        align-items: center;
        gap: 10px;
        font-size: 0.72rem;
      }

      .slider-row input[type="range"] {
        flex: 1;
        accent-color: var(--aida-accent, #00f0ff);
        cursor: pointer;
      }
    `,
  ];

  private dispatchSelfAction(
    name: string,
    context: Record<string, unknown> = {}
  ): void {
    window.dispatchEvent(
      new CustomEvent("aida:self-action", {
        detail: { name, context },
      })
    );
  }

  override willUpdate(changedProperties: PropertyValues): void {
    super.willUpdate(changedProperties);
    const props = this.controller?.props as AidaCockpitControlProps | undefined;
    if (props?.applyStyle || props?.applyAvatar) {
      const sig = JSON.stringify({
        s: props.applyStyle,
        a: props.applyAvatar,
      });
      if (sig !== this.appliedSignature) {
        this.appliedSignature = sig;
        if (props.applyStyle) {
          if (props.applyStyle.preset) {
            this.activePreset = props.applyStyle.preset;
          }
          if (props.applyStyle.fontScale !== undefined) {
            this.fontScale = props.applyStyle.fontScale;
          }
          if (props.applyStyle.scanlines !== undefined) {
            this.scanlines = props.applyStyle.scanlines;
          }
          this.dispatchSelfAction(
            "apply_style",
            props.applyStyle as Record<string, unknown>
          );
        }
        if (props.applyAvatar) {
          if (props.applyAvatar.renderer) {
            this.avatarRenderer = props.applyAvatar.renderer;
          }
          if (props.applyAvatar.state) {
            this.avatarState = props.applyAvatar.state;
          }
          this.dispatchSelfAction(
            "set_avatar",
            props.applyAvatar as Record<string, unknown>
          );
        }
      }
    }
  }

  override render() {
    const props = this.controller?.props as AidaCockpitControlProps | undefined;
    if (!props) {
      return nothing;
    }

    const shortcuts = Array.isArray(props.shortcuts) ? props.shortcuts : [];

    return html`
      <div class="ctrl-shell">
        <div class="ctrl-header">
          <div class="title-group">
            <h4 class="ctrl-title">
              ${props.title ? String(props.title) : "AIDA Controls"}
            </h4>
            ${props.subtitle
              ? html`<p class="ctrl-subtitle">${String(props.subtitle)}</p>`
              : nothing}
          </div>
        </div>

        <div class="sections-grid">
          <div class="ctrl-section">
            <h5 class="sec-title">
              <span>Theme & Palette Presets</span>
              <span>${this.activePreset}</span>
            </h5>

            <div class="preset-grid">
              ${PRESET_CHIPS.map(
                (p) => html`
                  <button
                    type="button"
                    class="preset-chip ${this.activePreset === p.id ? "active" : ""}"
                    @click=${() => {
                      this.activePreset = p.id;
                      this.dispatchSelfAction("apply_style", {
                        preset: p.id,
                        theme: p.theme,
                      });
                    }}
                  >
                    <span
                      class="swatch-dot"
                      style="background: ${p.accent}; box-shadow: 0 0 6px ${p.accent}"
                    ></span>
                    <span>${p.label}</span>
                  </button>
                `
              )}
            </div>

            <div class="slider-row">
              <span>Font Scale (${Math.round(this.fontScale * 100)}%)</span>
              <input
                type="range"
                aria-label="Font scale"
                min="0.85"
                max="1.25"
                step="0.05"
                .value=${String(this.fontScale)}
                @input=${(e: Event) => {
                  const scale = Number.parseFloat(
                    (e.target as HTMLInputElement).value
                  );
                  this.fontScale = scale;
                  this.dispatchSelfAction("set_font_scale", {
                    fontScale: scale,
                  });
                }}
              />
            </div>

            <div class="btn-row">
              <button
                type="button"
                class="ctrl-btn ${this.scanlines ? "active" : ""}"
                @click=${() => {
                  this.scanlines = !this.scanlines;
                  this.dispatchSelfAction("toggle_scanlines", {
                    scanlines: this.scanlines,
                  });
                }}
              >
                Scanlines: ${this.scanlines ? "ON" : "OFF"}
              </button>
              <button
                type="button"
                class="ctrl-btn"
                @click=${() => {
                  this.activePreset = "pc98-cyan";
                  this.fontScale = 1;
                  this.scanlines = true;
                  this.dispatchSelfAction("reset_style");
                }}
              >
                Reset Style
              </button>
            </div>
          </div>

          <div class="ctrl-section">
            <h5 class="sec-title">
              <span>AIDA Avatar Controls</span>
              <span
                >${this.avatarRenderer.toUpperCase()} •
                ${this.avatarState.toUpperCase()}</span
              >
            </h5>

            <div class="btn-row">
              <button
                type="button"
                class="ctrl-btn ${this.avatarRenderer === "pc98" ? "active" : ""}"
                @click=${() => {
                  this.avatarRenderer = "pc98";
                  this.dispatchSelfAction("set_avatar", { renderer: "pc98" });
                }}
              >
                PC-98 Pixel
              </button>
              <button
                type="button"
                class="ctrl-btn ${this.avatarRenderer === "aa2d" ? "active" : ""}"
                @click=${() => {
                  this.avatarRenderer = "aa2d";
                  this.dispatchSelfAction("set_avatar", { renderer: "aa2d" });
                }}
              >
                AA2D 3.0 Rig
              </button>
            </div>

            <div class="btn-row">
              ${(["idle", "think", "talk", "teehee", "error"] as const).map(
                (st) => html`
                  <button
                    type="button"
                    class="ctrl-btn ${this.avatarState === st ? "active" : ""}"
                    @click=${() => {
                      this.avatarState = st;
                      this.dispatchSelfAction("set_avatar", { state: st });
                    }}
                  >
                    ${st.toUpperCase()}
                  </button>
                `
              )}
            </div>

            ${shortcuts.length > 0
              ? html`
                  <div class="btn-row">
                    ${shortcuts.map(
                      (sc) => html`
                        <button
                          type="button"
                          class="ctrl-btn"
                          @click=${() =>
                            this.dispatchSelfAction(
                              sc.action,
                              sc.target !== undefined ? { tab: sc.target } : {}
                            )}
                        >
                          ${sc.label}
                        </button>
                      `
                    )}
                  </div>
                `
              : nothing}
          </div>
        </div>
      </div>
    `;
  }
}

export const AidaCockpitControlApi: LitComponentApi = {
  name: "CockpitControl",
  schema: AidaCockpitControlSchema,
  tagName: "aida-cockpit-control",
  element: AidaCockpitControlElement,
};
