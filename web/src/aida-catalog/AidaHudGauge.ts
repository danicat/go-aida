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

import { html, nothing } from "lit";
import { customElement, state } from "lit/decorators.js";
import { z } from "zod";
import { type LitComponentApi } from "@a2ui/lit/v0_9";
import { CommonSchemas } from "@a2ui/web_core/v0_9";
import { AidaFlexibleActionSchema } from "./action-helper.js";
import { AidaCatalogElement, aidaCatalogBaseStyles } from "./base.js";
import {
  AidaCyberChartSeriesItemSchema,
  computeSeriesMax,
  renderArcGaugeGrid,
  renderCompactMetricGrid,
  renderSegmentedBarMatrix,
} from "./AidaCyberChart.js";

export const AidaHudGaugeItemSchema = AidaCyberChartSeriesItemSchema;

export const AidaHudGaugeSchema = z.object({
  title: CommonSchemas.DynamicString.optional(),
  variant: z.enum(["arc", "plasma", "compact"]).default("arc").optional(),
  items: z.array(AidaHudGaugeItemSchema),
  actionName: z.string().optional(),
  actionContext: z.record(z.string(), z.unknown()).optional(),
  action: AidaFlexibleActionSchema.optional(),
  weight: z.number().optional(),
});

export type AidaHudGaugeItem = z.infer<typeof AidaHudGaugeItemSchema>;
export type AidaHudGaugeProps = z.infer<typeof AidaHudGaugeSchema>;
type GaugeVariant = "arc" | "plasma" | "compact";

@customElement("aida-hud-gauge")
export class AidaHudGaugeElement extends AidaCatalogElement<
  typeof AidaHudGaugeApi
> {
  static tagName = "aida-hud-gauge";
  protected override readonly api = AidaHudGaugeApi;

  static override styles = [aidaCatalogBaseStyles];

  @state() private accessor overrideVariant: GaugeVariant | null = null;

  private triggerGaugeDrillDown(item: AidaHudGaugeItem): void {
    const props = this.controller?.props as AidaHudGaugeProps | undefined;
    this.dispatchCatalogAction(
      "inspect_gauge",
      {
        gaugeTitle: props?.title ? String(props.title) : "HUD Gauge",
        label: item.label,
        value: item.value,
        max: item.max ?? 100,
        unit: item.unit ?? "",
        subtitle: item.subtitle ?? "",
        status: item.status ?? "nominal",
      },
      item
    );
  }

  override render() {
    const props = this.controller?.props as AidaHudGaugeProps | undefined;
    if (!props) {
      return nothing;
    }

    const items = Array.isArray(props.items) ? props.items : [];
    const activeVariant: GaugeVariant =
      this.overrideVariant ?? props.variant ?? "arc";
    const variants: GaugeVariant[] = ["arc", "plasma", "compact"];
    const onSelect = (item: AidaHudGaugeItem) => this.triggerGaugeDrillDown(item);

    return html`
      <div class="gauge-container">
        <div class="gauge-header">
          <h4 class="gauge-title">
            ${props.title ? String(props.title) : "Metrics"}
          </h4>
          <div class="variant-switch" role="group" aria-label="Gauge Display Mode">
            ${variants.map(
              (v) => html`
                <button
                  type="button"
                  class="variant-btn ${activeVariant === v ? "active" : ""}"
                  @click=${() => {
                    this.overrideVariant = v;
                  }}
                >
                  ${v}
                </button>
              `
            )}
          </div>
        </div>

        ${activeVariant === "plasma"
          ? renderSegmentedBarMatrix(items, computeSeriesMax(items), onSelect)
          : activeVariant === "compact"
            ? renderCompactMetricGrid(items, onSelect)
            : renderArcGaugeGrid(items, onSelect)}
      </div>
    `;
  }
}

export const AidaHudGaugeApi: LitComponentApi = {
  name: "HudGauge",
  schema: AidaHudGaugeSchema,
  tagName: "aida-hud-gauge",
  element: AidaHudGaugeElement,
};
