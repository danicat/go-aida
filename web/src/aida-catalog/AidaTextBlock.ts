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
import { customElement, state } from "lit/decorators.js";
import { z } from "zod";
import { type LitComponentApi } from "@a2ui/lit/v0_9";
import { CommonSchemas } from "@a2ui/web_core/v0_9";
import { AidaFlexibleActionSchema, slugifyActionName } from "./action-helper.js";
import {
  AidaCatalogElement,
  aidaCatalogBaseStyles,
  handleInteractiveKeydown,
} from "./base.js";

export const AidaTextBlockSchema = z.object({
  text: CommonSchemas.DynamicString,
  title: CommonSchemas.DynamicString.optional(),
  variant: z
    .enum(["heading", "body", "caption", "callout", "log"])
    .default("body")
    .optional(),
  status: z.enum(["nominal", "warning", "critical"]).optional(),
  action: AidaFlexibleActionSchema.optional(),
  actionName: z.string().optional(),
  actionContext: z.record(z.string(), z.unknown()).optional(),
  weight: z.number().optional(),
});

export type AidaTextBlockProps = z.infer<typeof AidaTextBlockSchema>;

@customElement("aida-text-block")
export class AidaTextBlockElement extends AidaCatalogElement<
  typeof AidaTextBlockApi
> {
  static tagName = "aida-text-block";
  protected override readonly api = AidaTextBlockApi;

  @state() private accessor copied = false;
  @state() private accessor copyError: string | null = null;

  static override styles = [
    aidaCatalogBaseStyles,
    css`
      .actionable {
        cursor: pointer;
        transition: transform 0.14s ease, box-shadow 0.14s ease;
      }

      .actionable:hover {
        transform: translateX(2px);
        box-shadow: 0 0 12px var(--aida-glow, rgba(0, 240, 255, 0.2));
      }

      .text-heading {
        margin: 0;
        font-family: var(--aida-font-display, "Orbitron", sans-serif);
        font-size: 0.94rem;
        font-weight: 700;
        letter-spacing: 0.12em;
        text-transform: uppercase;
        color: var(--aida-accent, #00f0ff);
        border-left: 3px solid var(--aida-accent, #00f0ff);
        padding-left: 10px;
      }

      .text-body {
        margin: 0;
        font-size: 0.84rem;
        line-height: 1.55;
        color: var(--aida-text, #e2f1ff);
        white-space: pre-wrap;
      }

      .text-caption {
        margin: 0;
        font-size: 0.72rem;
        letter-spacing: 0.06em;
        color: var(--aida-text-muted, #7c93c3);
      }

      .callout-box {
        padding: 10px 14px;
        background: var(--aida-bg-elevated, #111a3a);
        border: 1px solid var(--aida-border, #3b4cca);
        border-left: 4px solid var(--callout-color, var(--aida-accent, #00f0ff));
      }

      .callout-box.status-nominal {
        --callout-color: var(--aida-nominal, #00ff88);
      }

      .callout-box.status-warning {
        --callout-color: var(--aida-warning, #ffb000);
        border-color: var(--aida-warning, #ffb000);
      }

      .callout-box.status-critical {
        --callout-color: var(--aida-critical, #ff2a6d);
        border-color: var(--aida-critical, #ff2a6d);
      }

      .callout-title {
        display: flex;
        align-items: center;
        gap: 8px;
        font-family: var(--aida-font-display, "Orbitron", sans-serif);
        font-size: 0.76rem;
        font-weight: 700;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        color: var(--callout-color, var(--aida-accent, #00f0ff));
        margin-bottom: 5px;
      }

      .callout-dot {
        width: 7px;
        height: 7px;
        border-radius: 50%;
        background: var(--callout-color, var(--aida-accent, #00f0ff));
        box-shadow: 0 0 8px var(--callout-color, var(--aida-accent, #00f0ff));
      }

      .log-terminal {
        border: 1px solid var(--aida-border, #3b4cca);
        background: var(--aida-lcd-bg, var(--aida-bg-elevated, #111a3a));
        overflow: hidden;
      }

      .log-bar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 5px 10px;
        background: var(--aida-bg-elevated, #111a3a);
        border-bottom: 1px solid var(--aida-border, #3b4cca);
        font-size: 0.68rem;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        color: var(--aida-accent, #00f0ff);
      }

      .copy-btn {
        appearance: none;
        background: transparent;
        border: 1px solid var(--aida-border, #3b4cca);
        color: var(--aida-accent, #00f0ff);
        font-family: inherit;
        font-size: 0.64rem;
        width: 24px;
        height: 24px;
        padding: 0;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        cursor: pointer;
      }

      .copy-btn svg {
        width: 14px;
        height: 14px;
        fill: currentColor;
      }

      .copy-btn:hover {
        background: var(--aida-accent, #00f0ff);
        color: var(--aida-bg-panel, #0a1026);
      }

      .log-pre {
        margin: 0;
        padding: 10px 12px;
        font-size: 0.76rem;
        line-height: 1.5;
        color: var(--aida-nominal, #00ff88);
        overflow-x: auto;
        white-space: pre-wrap;
        word-break: break-word;
      }
    `,
  ];

  private hasConfiguredAction(props?: AidaTextBlockProps): boolean {
    const rawProps = (this.context?.componentModel?.properties ?? {}) as Record<
      string,
      unknown
    >;
    return Boolean(
      rawProps.action !== undefined ||
        rawProps.actionName !== undefined ||
        props?.action !== undefined ||
        props?.actionName !== undefined
    );
  }

  private handleBlockClick(props: AidaTextBlockProps): void {
    if (!this.hasConfiguredAction(props)) return;
    const title = props.title ? String(props.title) : "";
    const text = props.text !== undefined ? String(props.text) : "";
    this.dispatchCatalogAction(
      slugifyActionName(title || text.slice(0, 32), "inspect_callout"),
      { title, text }
    );
  }

  private async copyLogText(text: string): Promise<void> {
    try {
      if (!navigator.clipboard?.writeText) {
        throw new Error("Clipboard API unavailable");
      }
      await navigator.clipboard.writeText(text);
      this.copied = true;
      this.copyError = null;
      window.setTimeout(() => {
        this.copied = false;
      }, 1500);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      this.copyError = msg;
      this.dispatchEvent(
        new CustomEvent("aida-copy-error", {
          detail: { error: msg },
          bubbles: true,
          composed: true,
        })
      );
    }
  }

  override render() {
    const props = this.controller?.props as AidaTextBlockProps | undefined;
    if (!props) {
      return nothing;
    }

    const text = props.text !== undefined ? String(props.text) : "";
    const title = props.title ? String(props.title) : "";
    const variant = props.variant ?? "body";
    const status = props.status ?? "nominal";
    const actionable = this.hasConfiguredAction(props);
    const actionClass = actionable ? "actionable" : "";

    if (variant === "heading") {
      return html`<h4
        class="text-heading ${actionClass}"
        tabindex=${actionable ? "0" : nothing}
        role=${actionable ? "button" : nothing}
        @click=${() => this.handleBlockClick(props)}
        @keydown=${(e: KeyboardEvent) =>
          actionable && handleInteractiveKeydown(e, () => this.handleBlockClick(props))}
      >
        ${title || text}
      </h4>`;
    }

    if (variant === "caption") {
      return html`<p
        class="text-caption ${actionClass}"
        tabindex=${actionable ? "0" : nothing}
        role=${actionable ? "button" : nothing}
        @click=${() => this.handleBlockClick(props)}
        @keydown=${(e: KeyboardEvent) =>
          actionable && handleInteractiveKeydown(e, () => this.handleBlockClick(props))}
      >
        ${text}
      </p>`;
    }

    if (variant === "log") {
      return html`
        <div class="log-terminal">
          <div class="log-bar">
            <span>${title || "TERMINAL // DIAGNOSTIC STREAM"}</span>
            <button
              type="button"
              class="copy-btn"
              aria-label=${this.copied ? "Copied to clipboard" : "Copy log output"}
              title=${this.copyError ? `Copy error: ${this.copyError}` : this.copied ? "Copied to clipboard" : "Copy log output"}
              @click=${() => this.copyLogText(text)}
            >
              ${this.copied
                ? html`<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>`
                : html`<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg>`}
            </button>
          </div>
          <pre class="log-pre">${text}</pre>
        </div>
      `;
    }

    if (variant === "callout" || props.status || title) {
      return html`
        <div
          class="callout-box status-${status} ${actionClass}"
          tabindex=${actionable ? "0" : nothing}
          role=${actionable ? "button" : nothing}
          @click=${() => this.handleBlockClick(props)}
          @keydown=${(e: KeyboardEvent) =>
            actionable && handleInteractiveKeydown(e, () => this.handleBlockClick(props))}
        >
          ${title || props.status
            ? html`
                <div class="callout-title">
                  <span class="callout-dot"></span>
                  <span>${title || status.toUpperCase()}</span>
                </div>
              `
            : nothing}
          <p class="text-body">${text}</p>
        </div>
      `;
    }

    return html`<p
      class="text-body ${actionClass}"
      tabindex=${actionable ? "0" : nothing}
      role=${actionable ? "button" : nothing}
      @click=${() => this.handleBlockClick(props)}
      @keydown=${(e: KeyboardEvent) =>
        actionable && handleInteractiveKeydown(e, () => this.handleBlockClick(props))}
    >
      ${text}
    </p>`;
  }
}

export const AidaTextBlockApi: LitComponentApi = {
  name: "TextBlock",
  schema: AidaTextBlockSchema,
  tagName: "aida-text-block",
  element: AidaTextBlockElement,
};
