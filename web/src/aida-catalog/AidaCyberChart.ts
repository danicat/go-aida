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

import { html, svg, css, nothing, type TemplateResult } from "lit";
import { customElement, state } from "lit/decorators.js";
import { z } from "zod";
import { type LitComponentApi } from "@a2ui/lit/v0_9";
import { CommonSchemas } from "@a2ui/web_core/v0_9";
import { AidaFlexibleActionSchema } from "./action-helper.js";
import {
  AidaCatalogElement,
  aidaCatalogBaseStyles,
  handleInteractiveKeydown,
  resolveStatusColor,
} from "./base.js";

export const AidaCyberChartSeriesItemSchema = z.object({
  label: z.string(),
  value: z.number(),
  max: z.number().optional(),
  unit: z.string().optional(),
  subtitle: z.string().optional(),
  status: z.enum(["nominal", "warning", "critical"]).optional(),
  actionName: z.string().optional(),
  actionContext: z.record(z.string(), z.unknown()).optional(),
  action: AidaFlexibleActionSchema.optional(),
});

export const AidaCyberChartSchema = z.object({
  title: CommonSchemas.DynamicString,
  subtitle: CommonSchemas.DynamicString.optional(),
  chartType: z
    .enum(["radar", "radial", "area", "bar", "donut"])
    .default("radar"),
  series: z.array(AidaCyberChartSeriesItemSchema),
  xAxisLabel: CommonSchemas.DynamicString.optional(),
  yAxisLabel: CommonSchemas.DynamicString.optional(),
  actionName: z.string().optional(),
  actionContext: z.record(z.string(), z.unknown()).optional(),
  action: AidaFlexibleActionSchema.optional(),
  weight: z.number().optional(),
});

export type AidaCyberChartSeriesItem = z.infer<typeof AidaCyberChartSeriesItemSchema>;
export type AidaCyberChartProps = z.infer<typeof AidaCyberChartSchema>;
type ChartMode = "radar" | "radial" | "area" | "bar" | "donut";

export function computeSeriesMax(series: AidaCyberChartSeriesItem[]): number {
  let maxVal = 0;
  for (const item of series) {
    const m = item.max && item.max > 0 ? item.max : item.value;
    if (m > maxVal) maxVal = m;
  }
  return maxVal > 0 ? maxVal : 100;
}

export function renderSegmentedBarMatrix<T extends AidaCyberChartSeriesItem>(
  items: T[],
  globalMax: number,
  onSelect: (item: T) => void,
  hoveredIndex: number | null = null,
  onHover?: (idx: number) => void
): TemplateResult {
  const totalSegments = 20;
  return html`
    <div class="bar-matrix">
      ${items.map((item, idx) => {
        const itemMax = item.max && item.max > 0 ? item.max : globalMax;
        const ratio = Math.min(Math.max(item.value / itemMax, 0), 1);
        const litCount = Math.round(ratio * totalSegments);
        const color = resolveStatusColor(item.status, idx);

        return html`
          <div
            class="bar-row ${hoveredIndex === idx ? "hovered" : ""}"
            style="--seg-color: ${color}"
            tabindex="0"
            role="button"
            aria-label="${item.label}: ${item.value}${item.unit ?? ""}"
            title="Click to inspect ${item.label}"
            @pointerenter=${() => onHover?.(idx)}
            @click=${() => onSelect(item)}
            @keydown=${(e: KeyboardEvent) =>
              handleInteractiveKeydown(e, () => onSelect(item))}
          >
            <div class="bar-row-top">
              <div class="bar-label-group">
                <span
                  class="status-dot"
                  style="color: ${color}; background: ${color}"
                ></span>
                <span class="bar-label">${item.label}</span>
                ${item.subtitle
                  ? html`<span class="bar-sub">• ${item.subtitle}</span>`
                  : nothing}
              </div>
              <span class="bar-value" style="color: ${color}">
                ${item.value}${item.unit ? ` ${item.unit}` : ""}
              </span>
            </div>
            <div class="bar-segments">
              ${Array.from({ length: totalSegments }, (_, segIdx) => {
                const isLit = segIdx < litCount;
                const isPeak =
                  segIdx === litCount && litCount < totalSegments && litCount > 0;
                return html`<span
                  class="seg ${isLit ? "lit" : ""} ${isPeak ? "peak" : ""}"
                ></span>`;
              })}
            </div>
          </div>
        `;
      })}
    </div>
  `;
}

export function renderArcGaugeGrid<T extends AidaCyberChartSeriesItem>(
  items: T[],
  onSelect: (item: T) => void
): TemplateResult {
  const cx = 70;
  const cy = 70;
  const r = 48;
  const circumference = 2 * Math.PI * r;
  const arcSpan = circumference * 0.75;

  return html`
    <div class="arc-grid">
      ${items.map((item, idx) => {
        const maxVal = item.max && item.max > 0 ? item.max : 100;
        const pct = Math.min(Math.max(item.value / maxVal, 0), 1);
        const dashOffset = arcSpan * (1 - pct);
        const status = item.status ?? "nominal";
        const color = resolveStatusColor(status, idx);

        return html`
          <div
            class="arc-card status-${status}"
            tabindex="0"
            role="button"
            aria-label="${item.label}: ${item.value}${item.unit ?? ""}"
            title="Click to inspect ${item.label}"
            @click=${() => onSelect(item)}
            @keydown=${(e: KeyboardEvent) =>
              handleInteractiveKeydown(e, () => onSelect(item))}
          >
            <svg class="arc-svg" viewBox="0 0 140 140" role="img" aria-hidden="true">
              <circle
                class="ring-spin-cw"
                cx=${cx}
                cy=${cy}
                r="62"
                fill="none"
                stroke=${color}
                stroke-opacity="0.3"
                stroke-width="1"
                stroke-dasharray="4 8"
              />
              <circle
                class="ring-spin-ccw"
                cx=${cx}
                cy=${cy}
                r="36"
                fill="none"
                stroke=${color}
                stroke-opacity="0.22"
                stroke-width="1"
                stroke-dasharray="2 5"
              />
              <circle
                cx=${cx}
                cy=${cy}
                r=${r}
                fill="none"
                stroke="var(--aida-grid-line, rgba(59, 76, 202, 0.22))"
                stroke-width="8"
                stroke-linecap="round"
                stroke-dasharray="${arcSpan} ${circumference}"
                transform="rotate(135 ${cx} ${cy})"
              />
              <circle
                cx=${cx}
                cy=${cy}
                r=${r}
                fill="none"
                stroke=${color}
                stroke-width="8"
                stroke-linecap="round"
                stroke-dasharray="${arcSpan} ${circumference}"
                stroke-dashoffset=${dashOffset}
                transform="rotate(135 ${cx} ${cy})"
              />
              <text
                x=${cx}
                y=${cy + 2}
                fill="var(--aida-text, #e2f1ff)"
                font-size="17"
                font-weight="bold"
                text-anchor="middle"
                dominant-baseline="middle"
              >
                ${item.value}${item.unit ?? ""}
              </text>
            </svg>

            <div class="arc-meta">
              <div class="arc-label">${item.label}</div>
              ${item.subtitle
                ? html`<div class="arc-subtitle">${item.subtitle}</div>`
                : nothing}
            </div>
          </div>
        `;
      })}
    </div>
  `;
}

export function renderCompactMetricGrid<T extends AidaCyberChartSeriesItem>(
  items: T[],
  onSelect: (item: T) => void
): TemplateResult {
  return html`
    <div class="compact-grid">
      ${items.map((item, idx) => {
        const maxVal = item.max && item.max > 0 ? item.max : 100;
        const pct = Math.min(Math.max((item.value / maxVal) * 100, 0), 100);
        const color = resolveStatusColor(item.status, idx);

        return html`
          <div
            class="compact-tile"
            tabindex="0"
            role="button"
            aria-label="${item.label}: ${item.value}${item.unit ?? ""}"
            title="Click to inspect ${item.label}"
            @click=${() => onSelect(item)}
            @keydown=${(e: KeyboardEvent) =>
              handleInteractiveKeydown(e, () => onSelect(item))}
          >
            <div class="compact-top">
              <span>${item.label}</span>
              <span
                class="status-dot"
                style="color: ${color}; background: ${color}"
              ></span>
            </div>
            <div class="compact-val" style="color: ${color}">
              ${item.value}${item.unit ? ` ${item.unit}` : ""}
            </div>
            ${item.subtitle
              ? html`<div class="arc-subtitle">${item.subtitle}</div>`
              : nothing}
            <div class="compact-bar">
              <div
                class="compact-bar-fill"
                style="width: ${pct.toFixed(1)}%; background: ${color}"
              ></div>
            </div>
          </div>
        `;
      })}
    </div>
  `;
}

@customElement("aida-cyber-chart")
export class AidaCyberChartElement extends AidaCatalogElement<
  typeof AidaCyberChartApi
> {
  static tagName = "aida-cyber-chart";
  protected override readonly api = AidaCyberChartApi;

  @state() private accessor overrideChartType: ChartMode | null = null;
  @state() private accessor hoveredIndex: number | null = null;

  static override styles = [
    aidaCatalogBaseStyles,
    css`
      .chart-body {
        position: relative;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        min-height: 175px;
      }

      svg.cyber-svg {
        width: 100%;
        max-height: 195px;
        overflow: visible;
      }

      .scanline-sweep {
        animation: sweep-x 5.5s linear infinite;
      }

      @keyframes sweep-x {
        0% {
          transform: translateX(0px);
          opacity: 0.15;
        }
        50% {
          opacity: 0.55;
        }
        100% {
          transform: translateX(460px);
          opacity: 0.15;
        }
      }

      .orbit-rotator {
        transform-origin: 180px 140px;
        animation: spin-slow 24s linear infinite;
      }

      @keyframes spin-slow {
        from {
          transform: rotate(0deg);
        }
        to {
          transform: rotate(360deg);
        }
      }

      .chart-footer {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        justify-content: space-between;
        gap: 8px;
        margin-top: 8px;
        padding-top: 6px;
        border-top: 1px dashed var(--aida-border, #3b4cca);
        font-size: 0.72rem;
      }

      .legend-items {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
      }

      .legend-chip {
        display: inline-flex;
        align-items: center;
        gap: 5px;
        cursor: pointer;
        padding: 2px 6px;
        background: var(--aida-bg-elevated, #111a3a);
        border: 1px solid var(--aida-border, #3b4cca);
        transition: all 0.15s ease;
      }

      .legend-chip:hover,
      .legend-chip.active {
        border-color: var(--aida-accent, #00f0ff);
        background: var(--aida-glow, rgba(0, 240, 255, 0.14));
      }

      .legend-swatch {
        width: 8px;
        height: 8px;
        display: inline-block;
      }
    `,
  ];

  private triggerItemDrillDown(item: AidaCyberChartSeriesItem): void {
    const props = this.controller?.props as AidaCyberChartProps | undefined;
    this.dispatchCatalogAction(
      "inspect_metric",
      {
        chartTitle: props?.title ? String(props.title) : "Telemetry Chart",
        label: item.label,
        value: item.value,
        max: item.max ?? 100,
        unit: item.unit ?? "",
        status: item.status ?? "nominal",
      },
      item
    );
  }

  private renderRadarChart(
    series: AidaCyberChartSeriesItem[],
    globalMax: number
  ) {
    const cx = 180;
    const cy = 140;
    const radius = 98;
    const count = Math.max(series.length, 3);
    const rings = [0.25, 0.5, 0.75, 1.0];

    const pointFor = (idx: number, ratio: number) => {
      const angle = (idx / count) * Math.PI * 2 - Math.PI / 2;
      return {
        x: cx + Math.cos(angle) * radius * ratio,
        y: cy + Math.sin(angle) * radius * ratio,
        angle,
      };
    };

    const dataPoints = series.map((item, idx) => {
      const itemMax = item.max && item.max > 0 ? item.max : globalMax;
      const ratio = Math.min(Math.max(item.value / itemMax, 0.06), 1.0);
      return { ...pointFor(idx, ratio), item, idx };
    });

    const polygonPoints = dataPoints
      .map((p) => `${p.x.toFixed(1)},${p.y.toFixed(1)}`)
      .join(" ");

    return svg`
      <svg class="cyber-svg" viewBox="0 0 360 280" role="img">
        <defs>
          <radialGradient id="radar-fill" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stop-color="#00f0ff" stop-opacity="0.38" />
            <stop offset="100%" stop-color="#ff00a0" stop-opacity="0.14" />
          </radialGradient>
        </defs>

        <circle
          class="orbit-rotator"
          cx=${cx}
          cy=${cy}
          r=${radius + 14}
          fill="none"
          stroke="var(--aida-border, #3b4cca)"
          stroke-width="1"
          stroke-dasharray="4 8"
        />

        ${rings.map((r) => {
          const pts = Array.from({ length: count }, (_, i) => {
            const p = pointFor(i, r);
            return `${p.x.toFixed(1)},${p.y.toFixed(1)}`;
          }).join(" ");
          return svg`
            <polygon
              points=${pts}
              fill="none"
              stroke="var(--aida-grid-line, rgba(59, 76, 202, 0.22))"
              stroke-width="1"
            />
          `;
        })}

        ${series.map((item, idx) => {
          const outer = pointFor(idx, 1.0);
          const labelPos = pointFor(idx, 1.24);
          return svg`
            <line
              x1=${cx}
              y1=${cy}
              x2=${outer.x}
              y2=${outer.y}
              stroke="var(--aida-grid-line, rgba(59, 76, 202, 0.25))"
              stroke-width="1"
            />
            <text
              x=${labelPos.x}
              y=${labelPos.y}
              fill="var(--aida-text, #e2f1ff)"
              font-size="10"
              text-anchor="middle"
              dominant-baseline="middle"
            >
              ${item.label}
            </text>
          `;
        })}

        ${dataPoints.length >= 3
          ? svg`
              <polygon
                points=${polygonPoints}
                fill="url(#radar-fill)"
                stroke="var(--aida-accent, #00f0ff)"
                stroke-width="2"
              />
            `
          : nothing}

        ${dataPoints.map(
          (p) => svg`
            <g
              style="cursor: pointer"
              tabindex="0"
              role="button"
              aria-label="${p.item.label}: ${p.item.value}${p.item.unit ?? ""}"
              @pointerenter=${() => {
                this.hoveredIndex = p.idx;
              }}
              @click=${() => this.triggerItemDrillDown(p.item)}
              @keydown=${(e: KeyboardEvent) =>
                handleInteractiveKeydown(e, () => this.triggerItemDrillDown(p.item))}
            >
              <circle
                cx=${p.x}
                cy=${p.y}
                r=${this.hoveredIndex === p.idx ? 7 : 4.5}
                fill=${resolveStatusColor(p.item.status, p.idx)}
                stroke="var(--aida-bg-panel, #0a1026)"
                stroke-width="1.5"
              />
            </g>
          `
        )}
      </svg>
    `;
  }

  private renderRadialChart(
    series: AidaCyberChartSeriesItem[],
    globalMax: number
  ) {
    const cx = 180;
    const cy = 140;
    const maxRadius = 110;
    const minRadius = 34;
    const visible = series.slice(0, 6);
    const step =
      visible.length > 1 ? (maxRadius - minRadius) / visible.length : 22;

    return svg`
      <svg class="cyber-svg" viewBox="0 0 360 280" role="img">
        <circle
          class="orbit-rotator"
          cx=${cx}
          cy=${cy}
          r=${maxRadius + 10}
          fill="none"
          stroke="var(--aida-border, #3b4cca)"
          stroke-dasharray="3 6"
        />
        ${visible.map((item, idx) => {
          const r = maxRadius - idx * step;
          const itemMax = item.max && item.max > 0 ? item.max : globalMax;
          const pct = Math.min(Math.max(item.value / itemMax, 0.02), 1);
          const circumference = 2 * Math.PI * r;
          const arcSpan = circumference * 0.75;
          const dashOffset = arcSpan * (1 - pct);
          const color = resolveStatusColor(item.status, idx);

          return svg`
            <g
              style="cursor: pointer"
              tabindex="0"
              role="button"
              aria-label="${item.label}: ${item.value}${item.unit ?? ""}"
              @pointerenter=${() => {
                this.hoveredIndex = idx;
              }}
              @click=${() => this.triggerItemDrillDown(item)}
              @keydown=${(e: KeyboardEvent) =>
                handleInteractiveKeydown(e, () => this.triggerItemDrillDown(item))}
            >
              <circle
                cx=${cx}
                cy=${cy}
                r=${r}
                fill="none"
                stroke="var(--aida-grid-line, rgba(59, 76, 202, 0.22))"
                stroke-width="8"
                stroke-dasharray="${arcSpan} ${circumference}"
                transform="rotate(135 ${cx} ${cy})"
              />
              <circle
                cx=${cx}
                cy=${cy}
                r=${r}
                fill="none"
                stroke=${color}
                stroke-width=${this.hoveredIndex === idx ? 10 : 8}
                stroke-linecap="round"
                stroke-dasharray="${arcSpan} ${circumference}"
                stroke-dashoffset=${dashOffset}
                transform="rotate(135 ${cx} ${cy})"
              />
              <text
                x=${cx + 6}
                y=${cy + r - 2}
                fill="var(--aida-text, #e2f1ff)"
                font-size="9"
              >
                ${item.label}: ${item.value}${item.unit ?? ""}
              </text>
            </g>
          `;
        })}
      </svg>
    `;
  }

  private renderAreaChart(
    series: AidaCyberChartSeriesItem[],
    globalMax: number,
    props: AidaCyberChartProps
  ) {
    const padL = 44;
    const padR = 24;
    const padT = 22;
    const padB = 38;
    const w = 520;
    const h = 250;
    const plotW = w - padL - padR;
    const plotH = h - padT - padB;

    const pts = series.map((item, idx) => {
      const x =
        series.length > 1
          ? padL + (idx / (series.length - 1)) * plotW
          : padL + plotW / 2;
      const ratio = Math.min(Math.max(item.value / globalMax, 0), 1);
      const y = padT + plotH - ratio * plotH;
      return { x, y, item, idx };
    });

    const polylineStr = pts
      .map((p) => `${p.x.toFixed(1)},${p.y.toFixed(1)}`)
      .join(" ");
    const areaStr =
      pts.length > 0
        ? `${pts[0].x.toFixed(1)},${padT + plotH} ${polylineStr} ${pts[pts.length - 1].x.toFixed(1)},${padT + plotH}`
        : "";

    return svg`
      <svg class="cyber-svg" viewBox="0 0 ${w} ${h}" role="img">
        <defs>
          <linearGradient id="cyber-area-grad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="#00f0ff" stop-opacity="0.45" />
            <stop offset="100%" stop-color="#00f0ff" stop-opacity="0.02" />
          </linearGradient>
        </defs>

        ${[0, 0.25, 0.5, 0.75, 1].map((step) => {
          const y = padT + plotH * (1 - step);
          const val = (globalMax * step).toFixed(0);
          return svg`
            <line
              x1=${padL}
              y1=${y}
              x2=${padL + plotW}
              y2=${y}
              stroke="var(--aida-grid-line, rgba(59, 76, 202, 0.22))"
              stroke-dasharray="3 3"
            />
            <text
              x=${padL - 6}
              y=${y + 3}
              fill="var(--aida-text-muted, #7c93c3)"
              font-size="9"
              text-anchor="end"
            >
              ${val}
            </text>
          `;
        })}

        <line
          class="scanline-sweep"
          x1=${padL}
          y1=${padT}
          x2=${padL}
          y2=${padT + plotH}
          stroke="var(--aida-nominal, #00ff88)"
          stroke-width="1.5"
        />

        ${areaStr
          ? svg`<polygon points=${areaStr} fill="url(#cyber-area-grad)" />`
          : nothing}
        ${polylineStr
          ? svg`
              <polyline
                points=${polylineStr}
                fill="none"
                stroke="var(--aida-accent, #00f0ff)"
                stroke-width="2.5"
              />
            `
          : nothing}

        ${pts.map(
          (p) => svg`
            <g
              style="cursor: pointer"
              tabindex="0"
              role="button"
              aria-label="${p.item.label}: ${p.item.value}${p.item.unit ?? ""}"
              @pointerenter=${() => {
                this.hoveredIndex = p.idx;
              }}
              @click=${() => this.triggerItemDrillDown(p.item)}
              @keydown=${(e: KeyboardEvent) =>
                handleInteractiveKeydown(e, () => this.triggerItemDrillDown(p.item))}
            >
              <line
                x1=${p.x}
                y1=${p.y}
                x2=${p.x}
                y2=${padT + plotH}
                stroke="var(--aida-grid-line, rgba(59, 76, 202, 0.22))"
                stroke-dasharray="2 3"
              />
              <circle
                cx=${p.x}
                cy=${p.y}
                r=${this.hoveredIndex === p.idx ? 6.5 : 4.2}
                fill=${resolveStatusColor(p.item.status, p.idx)}
                stroke="var(--aida-bg-panel, #0a1026)"
                stroke-width="1.5"
              />
              <text
                x=${p.x}
                y=${padT + plotH + 16}
                fill="var(--aida-text, #e2f1ff)"
                font-size="9.5"
                text-anchor="middle"
              >
                ${p.item.label}
              </text>
            </g>
          `
        )}

        ${props.xAxisLabel
          ? svg`
              <text
                x=${padL + plotW / 2}
                y=${h - 4}
                fill="var(--aida-accent, #00f0ff)"
                font-size="9.5"
                text-anchor="middle"
              >
                ${String(props.xAxisLabel)}
              </text>
            `
          : nothing}
      </svg>
    `;
  }

  private renderDonutChart(series: AidaCyberChartSeriesItem[]) {
    const cx = 180;
    const cy = 140;
    const r = 86;
    const circumference = 2 * Math.PI * r;
    const total = series.reduce((acc, s) => acc + Math.max(s.value, 0), 0) || 1;
    let accumulatedAngle = -90;

    const activeItem =
      this.hoveredIndex !== null && series[this.hoveredIndex]
        ? series[this.hoveredIndex]
        : series[0];

    return svg`
      <svg class="cyber-svg" viewBox="0 0 360 280" role="img">
        <circle
          class="orbit-rotator"
          cx=${cx}
          cy=${cy}
          r=${r + 18}
          fill="none"
          stroke="var(--aida-border, #3b4cca)"
          stroke-dasharray="5 7"
        />
        ${series.map((item, idx) => {
          const frac = Math.max(item.value, 0) / total;
          const segLength = Math.max(frac * circumference - 3, 1);
          const rot = accumulatedAngle;
          accumulatedAngle += frac * 360;
          const color = resolveStatusColor(item.status, idx);

          return svg`
            <circle
              cx=${cx}
              cy=${cy}
              r=${r}
              fill="none"
              stroke=${color}
              stroke-width=${this.hoveredIndex === idx ? 22 : 16}
              stroke-dasharray="${segLength} ${circumference}"
              transform="rotate(${rot} ${cx} ${cy})"
              style="cursor: pointer; transition: stroke-width 0.15s ease"
              tabindex="0"
              role="button"
              aria-label="${item.label}: ${item.value}${item.unit ?? ""}"
              @pointerenter=${() => {
                this.hoveredIndex = idx;
              }}
              @click=${() => this.triggerItemDrillDown(item)}
              @keydown=${(e: KeyboardEvent) =>
                handleInteractiveKeydown(e, () => this.triggerItemDrillDown(item))}
            />
          `;
        })}

        <circle
          cx=${cx}
          cy=${cy}
          r=${r - 22}
          fill="var(--aida-bg-elevated, #111a3a)"
          stroke="var(--aida-border, #3b4cca)"
          style="cursor: pointer"
          @click=${() => activeItem && this.triggerItemDrillDown(activeItem)}
        />
        ${activeItem
          ? svg`
              <text
                x=${cx}
                y=${cy - 10}
                fill="var(--aida-text-muted, #7c93c3)"
                font-size="9.5"
                text-anchor="middle"
                style="pointer-events: none"
              >
                ${activeItem.label.toUpperCase()}
              </text>
              <text
                x=${cx}
                y=${cy + 14}
                fill="var(--aida-accent, #00f0ff)"
                font-size="18"
                font-weight="bold"
                text-anchor="middle"
                style="pointer-events: none"
              >
                ${activeItem.value}${activeItem.unit ?? ""}
              </text>
            `
          : nothing}
      </svg>
    `;
  }

  override render() {
    const props = this.controller?.props as AidaCyberChartProps | undefined;
    if (!props) {
      return nothing;
    }

    const series = Array.isArray(props.series) ? props.series : [];
    const activeType: ChartMode =
      this.overrideChartType ?? props.chartType ?? "radar";
    const globalMax = computeSeriesMax(series);
    const modes: ChartMode[] = ["radar", "radial", "area", "bar", "donut"];

    return html`
      <div class="chart-shell">
        <div class="chart-header">
          <div class="title-col">
            <h4 class="chart-title">${String(props.title)}</h4>
            ${props.subtitle
              ? html`<p class="chart-subtitle">${String(props.subtitle)}</p>`
              : nothing}
          </div>

          <div class="mode-pills" role="group" aria-label="Chart Display Mode">
            ${modes.map(
              (m) => html`
                <button
                  type="button"
                  class="mode-pill ${activeType === m ? "active" : ""}"
                  @click=${() => {
                    this.overrideChartType = m;
                  }}
                >
                  ${m}
                </button>
              `
            )}
          </div>
        </div>

        <div class="chart-body">
          ${activeType === "radar"
            ? this.renderRadarChart(series, globalMax)
            : activeType === "radial"
              ? this.renderRadialChart(series, globalMax)
              : activeType === "area"
                ? this.renderAreaChart(series, globalMax, props)
                : activeType === "donut"
                  ? this.renderDonutChart(series)
                  : renderSegmentedBarMatrix(
                      series,
                      globalMax,
                      (item) => this.triggerItemDrillDown(item),
                      this.hoveredIndex,
                      (idx) => {
                        this.hoveredIndex = idx;
                      }
                    )}
        </div>

        ${activeType === "donut" && series.length > 0
          ? html`
              <div class="chart-footer">
                <div class="legend-items">
                  ${series.map(
                    (item, idx) => html`
                      <span
                        class="legend-chip ${this.hoveredIndex === idx ? "active" : ""}"
                        tabindex="0"
                        role="button"
                        aria-label="${item.label}: ${item.value}${item.unit ?? ""}"
                        title="Click to inspect ${item.label}"
                        @pointerenter=${() => {
                          this.hoveredIndex = idx;
                        }}
                        @click=${() => this.triggerItemDrillDown(item)}
                        @keydown=${(e: KeyboardEvent) =>
                          handleInteractiveKeydown(e, () =>
                            this.triggerItemDrillDown(item)
                          )}
                      >
                        <span
                          class="legend-swatch"
                          style="background: ${resolveStatusColor(item.status, idx)}"
                        ></span>
                        <span>${item.label}: ${item.value}${item.unit ?? ""}</span>
                      </span>
                    `
                  )}
                </div>
              </div>
            `
          : nothing}
      </div>
    `;
  }
}

export const AidaCyberChartApi: LitComponentApi = {
  name: "CyberChart",
  schema: AidaCyberChartSchema,
  tagName: "aida-cyber-chart",
  element: AidaCyberChartElement,
};
