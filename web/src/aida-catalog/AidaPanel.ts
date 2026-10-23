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

import { html, css, nothing } from "lit";
import { customElement } from "lit/decorators.js";
import { z } from "zod";
import { type LitComponentApi } from "@a2ui/lit/v0_9";
import { CommonSchemas } from "@a2ui/web_core/v0_9";
import { AidaCatalogElement, aidaCatalogBaseStyles } from "./base.js";

export const AidaPanelSchema = z.object({
  title: CommonSchemas.DynamicString.optional(),
  subtitle: CommonSchemas.DynamicString.optional(),
  status: z.enum(["nominal", "warning", "critical"]).optional(),
  direction: z.enum(["column", "row", "grid"]).default("column").optional(),
  children: z.array(CommonSchemas.ComponentId),
  weight: z.number().optional(),
});

export type AidaPanelProps = z.infer<typeof AidaPanelSchema>;

@customElement("aida-panel")
export class AidaPanelElement extends AidaCatalogElement<typeof AidaPanelApi> {
  static tagName = "aida-panel";
  protected override readonly api = AidaPanelApi;

  static override styles = [
    aidaCatalogBaseStyles,
    css`
      .panel-frame {
        position: relative;
        background: var(--aida-bg-panel, #0a1026);
        border: 1px solid var(--aida-border, #3b4cca);
        box-shadow: var(--aida-shadow, 0 8px 30px rgba(0, 0, 0, 0.4));
        padding: 12px 14px;
        overflow: hidden;
        background-image:
          linear-gradient(var(--aida-grid-line, rgba(59, 76, 202, 0.14)) 1px, transparent 1px),
          linear-gradient(90deg, var(--aida-grid-line, rgba(59, 76, 202, 0.14)) 1px, transparent 1px);
        background-size: 24px 24px;
      }

      .panel-frame.status-nominal {
        --panel-status-color: var(--aida-nominal, #00ff88);
      }

      .panel-frame.status-warning {
        --panel-status-color: var(--aida-warning, #ffb000);
        border-color: var(--aida-warning, #ffb000);
      }

      .panel-frame.status-critical {
        --panel-status-color: var(--aida-critical, #ff2a6d);
        border-color: var(--aida-critical, #ff2a6d);
      }

      .reticle {
        position: absolute;
        width: 10px;
        height: 10px;
        pointer-events: none;
        border-color: var(--panel-status-color, var(--aida-accent, #00f0ff));
        border-style: solid;
        z-index: 2;
      }
      .reticle.tl {
        top: 0;
        left: 0;
        border-width: 2px 0 0 2px;
      }
      .reticle.tr {
        top: 0;
        right: 0;
        border-width: 2px 2px 0 0;
      }
      .reticle.bl {
        bottom: 0;
        left: 0;
        border-width: 0 0 2px 2px;
      }
      .reticle.br {
        bottom: 0;
        right: 0;
        border-width: 0 2px 2px 0;
      }

      .panel-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        padding-bottom: 8px;
        margin-bottom: 12px;
        border-bottom: 1px solid var(--aida-border, #3b4cca);
        position: relative;
      }

      .panel-header::after {
        content: "";
        position: absolute;
        bottom: -1px;
        left: 0;
        width: 72px;
        height: 2px;
        background: var(--panel-status-color, var(--aida-accent, #00f0ff));
      }

      .header-left {
        display: flex;
        align-items: center;
        gap: 10px;
        min-width: 0;
      }

      .status-led {
        width: 9px;
        height: 9px;
        border-radius: 50%;
        flex-shrink: 0;
        background: var(--panel-status-color, var(--aida-accent, #00f0ff));
        box-shadow: 0 0 10px var(--panel-status-color, var(--aida-accent, #00f0ff));
        animation: pulse-led 2s infinite ease-in-out;
      }

      .status-critical .status-led {
        animation-duration: 0.75s;
      }

      @keyframes pulse-led {
        0%,
        100% {
          opacity: 1;
          transform: scale(1);
        }
        50% {
          opacity: 0.45;
          transform: scale(0.85);
        }
      }

      .panel-title {
        font-family: var(--aida-font-display, "Orbitron", sans-serif);
        font-size: 0.88rem;
        font-weight: 700;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        color: var(--aida-text, #e2f1ff);
        margin: 0;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }

      .panel-subtitle {
        font-size: 0.74rem;
        letter-spacing: 0.06em;
        color: var(--aida-text-muted, #7c93c3);
        margin: 0;
      }

      .status-pill {
        font-size: 0.68rem;
        letter-spacing: 0.14em;
        text-transform: uppercase;
        padding: 2px 8px;
        border: 1px solid var(--panel-status-color, var(--aida-accent, #00f0ff));
        color: var(--panel-status-color, var(--aida-accent, #00f0ff));
        background: var(--aida-bg-elevated, #111a3a);
        font-weight: 600;
      }

      .panel-body {
        display: flex;
        gap: 12px;
        width: 100%;
        box-sizing: border-box;
      }

      .panel-body.dir-column {
        flex-direction: column;
      }

      .panel-body.dir-row {
        flex-direction: row;
        flex-wrap: wrap;
        align-items: stretch;
      }

      .panel-body.dir-row > * {
        flex: 1 1 240px;
        min-width: 0;
      }

      .panel-body.dir-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
        gap: 12px;
        align-items: stretch;
      }
    `,
  ];

  override render() {
    const props = this.controller?.props as AidaPanelProps | undefined;
    if (!props) {
      return nothing;
    }

    const status = props.status ?? "nominal";
    const direction = props.direction ?? "column";
    const title = props.title ? String(props.title) : "";
    const subtitle = props.subtitle ? String(props.subtitle) : "";
    const children = Array.isArray(props.children) ? props.children : [];
    const hasHeader = Boolean(title || subtitle);

    if (!hasHeader) {
      return html`
        <div class="panel-body dir-${direction}">
          ${children.map((childId) => this.renderNode(childId))}
        </div>
      `;
    }

    return html`
      <section class="panel-frame status-${status}">
        <span class="reticle tl"></span>
        <span class="reticle tr"></span>
        <span class="reticle bl"></span>
        <span class="reticle br"></span>

        <header class="panel-header">
          <div class="header-left">
            <span class="status-led"></span>
            <div class="title-group">
              ${title ? html`<h3 class="panel-title">${title}</h3>` : nothing}
              ${subtitle ? html`<p class="panel-subtitle">${subtitle}</p>` : nothing}
            </div>
          </div>
          ${status !== "nominal"
            ? html`<span class="status-pill">${status}</span>`
            : nothing}
        </header>

        <div class="panel-body dir-${direction}">
          ${children.map((childId) => this.renderNode(childId))}
        </div>
      </section>
    `;
  }
}

export const AidaPanelApi: LitComponentApi = {
  name: "Panel",
  schema: AidaPanelSchema,
  tagName: "aida-panel",
  element: AidaPanelElement,
};
