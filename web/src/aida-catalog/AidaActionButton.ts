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
import { AidaFlexibleActionSchema, slugifyActionName } from "./action-helper.js";
import { AidaCatalogElement, aidaCatalogBaseStyles } from "./base.js";

export const AidaActionButtonSchema = z.object({
  label: CommonSchemas.DynamicString,
  variant: z.enum(["primary", "default", "danger"]).default("default").optional(),
  action: AidaFlexibleActionSchema.optional(),
  actionName: z.string().optional(),
  actionContext: z.record(z.string(), z.unknown()).optional(),
  weight: z.number().optional(),
});

export type AidaActionButtonProps = z.infer<typeof AidaActionButtonSchema>;

@customElement("aida-action-button")
export class AidaActionButtonElement extends AidaCatalogElement<
  typeof AidaActionButtonApi
> {
  static tagName = "aida-action-button";
  protected override readonly api = AidaActionButtonApi;

  static override styles = [
    aidaCatalogBaseStyles,
    css`
      :host {
        display: inline-block;
      }

      .action-btn {
        appearance: none;
        position: relative;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
        width: 100%;
        padding: 8px 14px;
        background: var(--aida-bg-elevated, #111a3a);
        border: 1px solid var(--btn-color, var(--aida-accent, #00f0ff));
        color: var(--btn-color, var(--aida-accent, #00f0ff));
        font-family: var(--aida-font-display, "Orbitron", sans-serif);
        font-size: 0.74rem;
        font-weight: 700;
        letter-spacing: 0.12em;
        text-transform: uppercase;
        cursor: pointer;
        transition: all 0.16s ease;
      }

      .action-btn.variant-primary {
        --btn-color: var(--aida-nominal, #00ff88);
      }

      .action-btn.variant-danger {
        --btn-color: var(--aida-critical, #ff2a6d);
      }

      .action-btn:hover {
        background: var(--btn-color, var(--aida-accent, #00f0ff));
        color: var(--aida-bg-panel, #0a1026);
        box-shadow: 0 0 16px var(--aida-glow, rgba(0, 240, 255, 0.28));
      }

      .btn-led {
        width: 6px;
        height: 6px;
        border-radius: 50%;
        background: currentColor;
        box-shadow: 0 0 6px currentColor;
      }
    `,
  ];

  private handleClick(): void {
    const props = this.controller?.props as AidaActionButtonProps | undefined;
    const label = props?.label ? String(props.label) : "EXECUTE";
    this.dispatchCatalogAction(slugifyActionName(label, "execute_action"), {
      label,
    });
  }

  override render() {
    const props = this.controller?.props as AidaActionButtonProps | undefined;
    if (!props) {
      return nothing;
    }

    const label = props.label ? String(props.label) : "EXECUTE";
    const variant = props.variant ?? "default";

    return html`
      <button
        type="button"
        class="action-btn variant-${variant}"
        @click=${() => this.handleClick()}
      >
        <span class="btn-led"></span>
        <span>${label}</span>
        <span aria-hidden="true">▸</span>
      </button>
    `;
  }
}

export const AidaActionButtonApi: LitComponentApi = {
  name: "ActionButton",
  schema: AidaActionButtonSchema,
  tagName: "aida-action-button",
  element: AidaActionButtonElement,
};
