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

import { css, type PropertyValues } from "lit";
import { A2uiLitElement, type LitComponentApi } from "@a2ui/lit/v0_9";
import { resolveAndDispatchAction } from "./action-helper.js";

const SERIES_PALETTE = [
  "var(--aida-accent, #00f0ff)",
  "var(--aida-nominal, #00ff88)",
  "#ff00a0",
  "var(--aida-warning, #ffb000)",
  "#7b61ff",
  "#00d2ff",
];

export function resolveStatusColor(
  status?: "nominal" | "warning" | "critical",
  idx = 0
): string {
  if (status === "critical") return "var(--aida-critical, #ff2a6d)";
  if (status === "warning") return "var(--aida-warning, #ffb000)";
  if (status === "nominal" && idx === 0) return "var(--aida-accent, #00f0ff)";
  return SERIES_PALETTE[idx % SERIES_PALETTE.length];
}

export function handleInteractiveKeydown(
  e: KeyboardEvent,
  callback: () => void
): void {
  if (e.key === "Enter" || e.key === " ") {
    e.preventDefault();
    callback();
  }
}

export const aidaCatalogBaseStyles = css`
  :host {
    display: block;
    width: 100%;
    box-sizing: border-box;
    font-family: var(--aida-font-mono, "Share Tech Mono", "VT323", monospace);
    color: var(--aida-text, #e2f1ff);
  }

  button,
  input,
  select {
    font: inherit;
    color: inherit;
  }

  button:focus-visible,
  input:focus-visible,
  select:focus-visible,
  [role="button"]:focus-visible,
  [role="columnheader"]:focus-visible,
  [tabindex="0"]:focus-visible {
    outline: 2px solid var(--aida-border-bright, var(--aida-accent, #00f0ff));
    outline-offset: 2px;
    box-shadow: 0 0 10px var(--aida-glow, rgba(0, 240, 255, 0.28));
  }

  /* Shared Theme-Aware Card Shell, Header, Titles & Mode Switchers */
  .catalog-shell,
  .chart-shell,
  .gauge-container,
  .matrix-shell,
  .ctrl-shell,
  .holo-wrapper {
    position: relative;
    border: 1px solid var(--aida-border, #3b4cca);
    background: var(--aida-bg-panel, #0a1026);
    color: var(--aida-text, #e2f1ff);
    padding: 10px 12px;
    overflow: hidden;
    box-sizing: border-box;
  }

  .catalog-header,
  .chart-header,
  .gauge-header,
  .ctrl-header {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding-bottom: 8px;
    margin-bottom: 8px;
    border-bottom: 1px solid var(--aida-border, #3b4cca);
  }

  .title-col,
  .title-group {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }

  .catalog-title,
  .chart-title,
  .gauge-title,
  .matrix-title,
  .ctrl-title,
  .holo-title {
    margin: 0;
    font-family: var(--aida-font-display, "Orbitron", sans-serif);
    font-size: 0.82rem;
    font-weight: 700;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--aida-accent, #00f0ff);
  }

  .catalog-subtitle,
  .chart-subtitle,
  .ctrl-subtitle,
  .holo-subtitle {
    margin: 0;
    font-size: 0.7rem;
    color: var(--aida-text-muted, #7c93c3);
    letter-spacing: 0.05em;
  }

  .mode-pills,
  .variant-switch,
  .mode-switch {
    display: inline-flex;
    border: 1px solid var(--aida-border, #3b4cca);
    background: var(--aida-bg-elevated, #111a3a);
  }

  .mode-pill,
  .variant-btn,
  .mode-btn {
    appearance: none;
    background: transparent;
    border: none;
    border-right: 1px solid var(--aida-border, #3b4cca);
    color: var(--aida-text-muted, #7c93c3);
    font-family: inherit;
    font-size: 0.62rem;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    padding: 3px 7px;
    cursor: pointer;
    transition: background 0.15s ease, color 0.15s ease;
  }

  .mode-pill:last-child,
  .variant-btn:last-child,
  .mode-btn:last-child {
    border-right: none;
  }

  .mode-pill:hover,
  .variant-btn:hover,
  .mode-btn:hover {
    color: var(--aida-text, #e2f1ff);
    background: var(--aida-glow, rgba(0, 240, 255, 0.14));
  }

  .mode-pill.active,
  .variant-btn.active,
  .mode-btn.active {
    background: var(--aida-accent, #00f0ff);
    color: var(--aida-bg-panel, #0a1026);
    font-weight: 700;
  }

  /* Shared Status Badges & Dots */
  .status-badge {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    font-size: 0.68rem;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    padding: 2px 7px;
    border: 1px solid currentColor;
    background: var(--aida-bg-elevated, #111a3a);
  }

  .status-badge.nominal {
    color: var(--aida-nominal, #00ff88);
  }

  .status-badge.warning {
    color: var(--aida-warning, #ffb000);
  }

  .status-badge.critical {
    color: var(--aida-critical, #ff2a6d);
  }

  .led-dot,
  .status-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: currentColor;
    box-shadow: 0 0 6px currentColor;
    flex-shrink: 0;
  }

  /* Shared 20-Segment LED Bar Matrix (CyberChart bar + HudGauge plasma) */
  .bar-matrix {
    width: 100%;
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 4px 0;
  }

  .bar-row {
    display: flex;
    flex-direction: column;
    gap: 5px;
    padding: 7px 10px;
    background: var(--aida-bg-elevated, #111a3a);
    border: 1px solid var(--aida-border, #3b4cca);
    cursor: pointer;
    transition: border-color 0.15s ease, transform 0.12s ease;
  }

  .bar-row:hover,
  .bar-row.hovered {
    border-color: var(--aida-accent, #00f0ff);
    transform: translateX(2px);
  }

  .bar-row-top {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 8px;
  }

  .bar-label-group {
    display: flex;
    align-items: center;
    gap: 7px;
    min-width: 0;
  }

  .bar-label {
    font-size: 0.76rem;
    font-weight: 700;
    letter-spacing: 0.06em;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .bar-sub {
    font-size: 0.68rem;
    color: var(--aida-text-muted, #7c93c3);
  }

  .bar-value {
    text-align: right;
    font-family: var(--aida-font-display, "Orbitron", sans-serif);
    font-weight: 700;
    font-size: 0.8rem;
    color: var(--aida-accent, #00f0ff);
  }

  .bar-segments {
    display: grid;
    grid-template-columns: repeat(20, 1fr);
    gap: 3px;
    height: 14px;
    padding: 2px;
    background: var(--aida-bg-panel, #0a1026);
    border: 1px solid var(--aida-border, #3b4cca);
  }

  .seg {
    background: var(--aida-grid-line, rgba(59, 76, 202, 0.22));
    transition: background 0.2s ease, box-shadow 0.2s ease;
  }

  .seg.lit {
    background: var(--seg-color, var(--aida-accent, #00f0ff));
    box-shadow: 0 0 6px var(--seg-color, var(--aida-accent, #00f0ff));
  }

  .seg.peak {
    background: var(--aida-text, #e2f1ff);
    box-shadow: 0 0 7px var(--aida-text, #e2f1ff);
  }

  /* Shared Arc Gauge Grid & Compact KPI Grid */
  .arc-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(132px, 1fr));
    gap: 10px;
    align-items: stretch;
  }

  .arc-card {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: space-between;
    padding: 8px 6px;
    background: var(--aida-bg-elevated, #111a3a);
    border: 1px solid var(--aida-border, #3b4cca);
    position: relative;
    cursor: pointer;
    transition: border-color 0.2s ease, box-shadow 0.2s ease, transform 0.15s ease;
  }

  .arc-card:hover {
    border-color: var(--aida-accent, #00f0ff);
    box-shadow: 0 0 14px var(--aida-glow, rgba(0, 240, 255, 0.2));
    transform: translateY(-2px);
  }

  .arc-card.status-warning {
    border-color: var(--aida-warning, #ffb000);
  }

  .arc-card.status-critical {
    border-color: var(--aida-critical, #ff2a6d);
  }

  svg.arc-svg {
    width: 104px;
    height: 104px;
    overflow: visible;
  }

  .ring-spin-cw {
    transform-origin: 70px 70px;
    animation: gauge-spin-cw 18s linear infinite;
  }

  .ring-spin-ccw {
    transform-origin: 70px 70px;
    animation: gauge-spin-ccw 24s linear infinite;
  }

  @keyframes gauge-spin-cw {
    from {
      transform: rotate(0deg);
    }
    to {
      transform: rotate(360deg);
    }
  }

  @keyframes gauge-spin-ccw {
    from {
      transform: rotate(360deg);
    }
    to {
      transform: rotate(0deg);
    }
  }

  .arc-meta {
    text-align: center;
    width: 100%;
    margin-top: 2px;
  }

  .arc-label {
    font-family: var(--aida-font-display, "Orbitron", sans-serif);
    font-size: 0.74rem;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--aida-text, #e2f1ff);
  }

  .arc-subtitle {
    font-size: 0.66rem;
    color: var(--aida-text-muted, #7c93c3);
    margin-top: 2px;
  }

  .compact-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(145px, 1fr));
    gap: 8px;
  }

  .compact-tile {
    padding: 8px 10px;
    background: var(--aida-bg-elevated, #111a3a);
    border: 1px solid var(--aida-border, #3b4cca);
    display: flex;
    flex-direction: column;
    gap: 4px;
    cursor: pointer;
    transition: border-color 0.15s ease, transform 0.15s ease;
  }

  .compact-tile:hover {
    border-color: var(--aida-accent, #00f0ff);
    transform: translateY(-1px);
  }

  .compact-top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    font-size: 0.68rem;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--aida-text-muted, #7c93c3);
  }

  .compact-val {
    font-family: var(--aida-font-display, "Orbitron", sans-serif);
    font-size: 1.15rem;
    font-weight: 700;
    letter-spacing: 0.05em;
  }

  .compact-bar {
    width: 100%;
    height: 4px;
    background: var(--aida-bg-panel, #0a1026);
    overflow: hidden;
    margin-top: 2px;
  }

  .compact-bar-fill {
    height: 100%;
    transition: width 0.3s ease;
  }

  @media (prefers-reduced-motion: reduce) {
    *,
    *::before,
    *::after {
      animation-duration: 0.01ms !important;
      animation-iteration-count: 1 !important;
      transition-duration: 0.01ms !important;
    }
  }
`;

export abstract class AidaCatalogElement<
  Api extends LitComponentApi,
> extends A2uiLitElement<Api> {
  protected override adoptLightDomStyles(): void {}

  override willUpdate(changedProperties: PropertyValues): void {
    super.willUpdate(changedProperties);
    const props = this.controller?.props as
      | { weight?: number }
      | undefined;
    if (props && props.weight !== undefined) {
      this.style.flex = String(props.weight);
    } else {
      this.style.removeProperty("flex");
    }
  }

  protected dispatchCatalogAction(
    fallbackName: string,
    itemContext: Record<string, unknown> = {},
    itemAction?: unknown
  ): void {
    const props = (this.controller?.props ?? {}) as Record<string, unknown>;
    const rawProps = (this.context?.componentModel?.properties ?? {}) as Record<
      string,
      unknown
    >;

    let itemRawAction: unknown = undefined;
    let itemActionName: string | undefined;
    let itemActionContext: Record<string, unknown> | undefined;

    if (typeof itemAction === "string" || typeof itemAction === "function") {
      itemRawAction = itemAction;
    } else if (
      itemAction &&
      typeof itemAction === "object" &&
      !Array.isArray(itemAction)
    ) {
      const obj = itemAction as Record<string, unknown>;
      if (
        "action" in obj ||
        "actionName" in obj ||
        "actionContext" in obj
      ) {
        itemRawAction = obj.action;
        if (typeof obj.actionName === "string") {
          itemActionName = obj.actionName;
        }
        if (
          obj.actionContext &&
          typeof obj.actionContext === "object" &&
          !Array.isArray(obj.actionContext)
        ) {
          itemActionContext = obj.actionContext as Record<string, unknown>;
        }
      } else if (
        "event" in obj ||
        (typeof obj.name === "string" && !("value" in obj))
      ) {
        itemRawAction = obj;
      }
    }

    const componentActionContext =
      (rawProps.actionContext as Record<string, unknown> | undefined) ??
      (props.actionContext as Record<string, unknown> | undefined) ??
      {};

    void resolveAndDispatchAction({
      componentContext: this.context,
      rawAction: itemRawAction ?? rawProps.action,
      boundAction: itemRawAction ?? props.action,
      explicitActionName:
        itemActionName ??
        (rawProps.actionName as string | undefined) ??
        (props.actionName as string | undefined) ??
        (rawProps.rowActionName as string | undefined) ??
        (props.rowActionName as string | undefined),
      explicitActionContext: {
        ...itemContext,
        ...componentActionContext,
        ...(itemActionContext ?? {}),
      },
      fallbackName,
      fallbackContext: itemContext,
    });
  }
}
