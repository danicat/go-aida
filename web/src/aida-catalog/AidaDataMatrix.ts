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
import { AidaFlexibleActionSchema } from "./action-helper.js";
import {
  AidaCatalogElement,
  aidaCatalogBaseStyles,
  handleInteractiveKeydown,
} from "./base.js";

export const AidaDataMatrixColumnSchema = z.object({
  key: z.string(),
  label: z.string(),
});

export const AidaDataMatrixCellValueSchema = z.unknown();

export const AidaDataMatrixSchema = z.object({
  title: CommonSchemas.DynamicString.optional(),
  columns: z.array(AidaDataMatrixColumnSchema),
  rows: z.array(z.record(z.string(), AidaDataMatrixCellValueSchema)),
  rowActionName: z.string().optional(),
  actionName: z.string().optional(),
  action: AidaFlexibleActionSchema.optional(),
  weight: z.number().optional(),
});

export type AidaDataMatrixColumn = z.infer<typeof AidaDataMatrixColumnSchema>;
export type AidaDataMatrixRow = Record<string, unknown>;
export type AidaDataMatrixProps = z.infer<typeof AidaDataMatrixSchema>;

const PERCENT_KEY_RE = /(cpu|mem|pct|percent|usage|load|util|capacity|ratio)/i;
const STATUS_KEY_RE = /^(status|state|health|severity|risk)$/i;

@customElement("aida-data-matrix")
export class AidaDataMatrixElement extends AidaCatalogElement<
  typeof AidaDataMatrixApi
> {
  static tagName = "aida-data-matrix";
  protected override readonly api = AidaDataMatrixApi;

  @state() private accessor filterQuery = "";
  @state() private accessor sortKey: string | null = null;
  @state() private accessor sortAsc = true;
  @state() private accessor selectedRowIndex: number | null = null;

  static override styles = [
    aidaCatalogBaseStyles,
    css`
      .matrix-shell {
        padding: 0;
      }

      .matrix-toolbar {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        justify-content: space-between;
        gap: 10px;
        padding: 10px 14px;
        border-bottom: 1px solid var(--aida-border, #3b4cca);
        background: var(--aida-bg-elevated, #111a3a);
      }

      .matrix-title-group {
        display: flex;
        align-items: center;
        gap: 10px;
      }

      .row-count-badge {
        font-size: 0.68rem;
        letter-spacing: 0.1em;
        padding: 2px 7px;
        border: 1px solid var(--aida-border, #3b4cca);
        color: var(--aida-text-muted, #7c93c3);
        background: var(--aida-bg-panel, #0a1026);
      }

      .filter-box {
        display: flex;
        align-items: center;
        gap: 6px;
      }

      .filter-input {
        background: var(--aida-bg-panel, #0a1026);
        border: 1px solid var(--aida-border, #3b4cca);
        color: var(--aida-text, #e2f1ff);
        font-family: inherit;
        font-size: 0.74rem;
        padding: 4px 10px;
        min-width: 190px;
        outline: none;
      }

      .filter-input:focus {
        border-color: var(--aida-accent, #00f0ff);
        box-shadow: 0 0 8px var(--aida-glow, rgba(0, 240, 255, 0.28));
      }

      .table-scroll {
        width: 100%;
        overflow-x: auto;
        max-height: 225px;
        overflow-y: auto;
      }

      table {
        width: 100%;
        border-collapse: collapse;
        font-size: 0.78rem;
        text-align: left;
      }

      thead th {
        position: sticky;
        top: 0;
        z-index: 1;
        background: var(--aida-bg-elevated, #111a3a);
        color: var(--aida-accent, #00f0ff);
        font-family: var(--aida-font-display, "Orbitron", sans-serif);
        font-size: 0.68rem;
        font-weight: 700;
        letter-spacing: 0.11em;
        text-transform: uppercase;
        padding: 7px 12px;
        border-bottom: 1px solid var(--aida-border, #3b4cca);
        cursor: pointer;
        user-select: none;
        white-space: nowrap;
      }

      thead th:hover {
        background: var(--aida-glow, rgba(0, 240, 255, 0.14));
      }

      tbody tr {
        border-bottom: 1px solid var(--aida-grid-line, rgba(59, 76, 202, 0.22));
        transition: background 0.12s ease;
      }

      tbody tr:nth-child(even) {
        background: color-mix(
          in srgb,
          var(--aida-bg-elevated, #111a3a) 45%,
          var(--aida-bg-panel, #0a1026)
        );
      }

      tbody tr:hover {
        background: var(--aida-glow, rgba(0, 240, 255, 0.14));
      }

      tbody tr.clickable {
        cursor: pointer;
      }

      tbody tr.selected {
        background: var(--aida-glow, rgba(0, 240, 255, 0.22));
        box-shadow: inset 3px 0 0 var(--aida-accent, #00f0ff);
      }

      td {
        padding: 6px 12px;
        vertical-align: middle;
        white-space: nowrap;
      }

      .cell-pct-wrap {
        display: flex;
        align-items: center;
        gap: 8px;
        min-width: 120px;
      }

      .cell-pct-bar {
        flex: 1;
        height: 7px;
        background: var(--aida-bg-elevated, #111a3a);
        border: 1px solid var(--aida-border, #3b4cca);
        overflow: hidden;
      }

      .cell-pct-fill {
        height: 100%;
        transition: width 0.25s ease;
      }

      .empty-state {
        padding: 18px;
        text-align: center;
        color: var(--aida-text-muted, #7c93c3);
        font-size: 0.78rem;
      }
    `,
  ];

  private toggleSort(key: string): void {
    if (this.sortKey === key) {
      this.sortAsc = !this.sortAsc;
    } else {
      this.sortKey = key;
      this.sortAsc = true;
    }
  }

  private handleRowClick(row: AidaDataMatrixRow, index: number): void {
    this.selectedRowIndex = index;
    const props = this.controller?.props as AidaDataMatrixProps | undefined;

    const cleanRowContext: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(row)) {
      if (k !== "action" && k !== "actionName" && k !== "actionContext") {
        cleanRowContext[k] = v;
      }
    }

    const tableTitle = props?.title
      ? String(props.title)
      : "Telemetry Data Matrix";

    this.dispatchCatalogAction(
      "inspect_row",
      {
        tableTitle,
        ...cleanRowContext,
      },
      row
    );
  }

  private renderCell(colKey: string, rawVal: unknown) {
    if (rawVal === null || rawVal === undefined) {
      return html`<span style="color: var(--aida-text-muted, #7c93c3)">—</span>`;
    }

    const strVal =
      typeof rawVal === "object" ? JSON.stringify(rawVal) : String(rawVal);

    if (STATUS_KEY_RE.test(colKey)) {
      const lower = strVal.toLowerCase();
      const tone =
        lower.includes("crit") ||
        lower.includes("err") ||
        lower.includes("high") ||
        lower.includes("dead") ||
        lower.includes("fail")
          ? "critical"
          : lower.includes("warn") ||
              lower.includes("med") ||
              lower.includes("listen") ||
              lower.includes("zombie")
            ? "warning"
            : "nominal";
      return html`
        <span class="status-badge ${tone}">
          <span class="led-dot"></span>
          ${strVal}
        </span>
      `;
    }

    const numericCandidate =
      typeof rawVal === "number"
        ? rawVal
        : strVal.endsWith("%")
          ? Number.parseFloat(strVal.slice(0, -1))
          : Number.NaN;

    if (
      !Number.isNaN(numericCandidate) &&
      numericCandidate >= 0 &&
      numericCandidate <= 100 &&
      (PERCENT_KEY_RE.test(colKey) || strVal.endsWith("%"))
    ) {
      const color =
        numericCandidate >= 85
          ? "var(--aida-critical, #ff2a6d)"
          : numericCandidate >= 65
            ? "var(--aida-warning, #ffb000)"
            : "var(--aida-accent, #00f0ff)";
      const displayStr = strVal.endsWith("%")
        ? strVal
        : `${numericCandidate.toFixed(1)}%`;

      return html`
        <div class="cell-pct-wrap">
          <div class="cell-pct-bar">
            <div
              class="cell-pct-fill"
              style="width: ${numericCandidate}%; background: ${color}"
            ></div>
          </div>
          <span style="color: ${color}; font-weight: 700">${displayStr}</span>
        </div>
      `;
    }

    return html`${strVal}`;
  }

  override render() {
    const props = this.controller?.props as AidaDataMatrixProps | undefined;
    if (!props) {
      return nothing;
    }

    const columns = Array.isArray(props.columns) ? props.columns : [];
    const rawRows = Array.isArray(props.rows) ? props.rows : [];
    const q = this.filterQuery.trim().toLowerCase();

    const filteredRows = q
      ? rawRows.filter((r) =>
          Object.values(r).some(
            (v) =>
              v !== null &&
              v !== undefined &&
              String(v).toLowerCase().includes(q)
          )
        )
      : [...rawRows];

    if (this.sortKey) {
      const k = this.sortKey;
      const dir = this.sortAsc ? 1 : -1;
      filteredRows.sort((a, b) => {
        const va = a[k];
        const vb = b[k];
        if (typeof va === "number" && typeof vb === "number") {
          return (va - vb) * dir;
        }
        return (
          String(va ?? "").localeCompare(String(vb ?? ""), undefined, {
            numeric: true,
          }) * dir
        );
      });
    }

    return html`
      <div class="matrix-shell">
        <div class="matrix-toolbar">
          <div class="matrix-title-group">
            <h4 class="matrix-title">
              ${props.title ? String(props.title) : "Data"}
            </h4>
            <span class="row-count-badge">
              ${filteredRows.length === rawRows.length
                ? `${rawRows.length} rows`
                : `${filteredRows.length} / ${rawRows.length}`}
            </span>
          </div>

          <div class="filter-box">
            <input
              type="search"
              class="filter-input"
              aria-label="Filter table rows"
              placeholder="Filter..."
              .value=${this.filterQuery}
              @input=${(e: Event) => {
                this.filterQuery = (e.target as HTMLInputElement).value;
              }}
            />
          </div>
        </div>

        <div class="table-scroll">
          ${filteredRows.length === 0
            ? html`<div class="empty-state">No matching rows</div>`
            : html`
                <table>
                  <thead>
                    <tr>
                      ${columns.map((col) => {
                        const isSorted = this.sortKey === col.key;
                        const ariaSort = isSorted
                          ? this.sortAsc
                            ? "ascending"
                            : "descending"
                          : "none";
                        return html`
                          <th
                            scope="col"
                            tabindex="0"
                            role="columnheader"
                            aria-sort=${ariaSort}
                            @click=${() => this.toggleSort(col.key)}
                            @keydown=${(e: KeyboardEvent) =>
                              handleInteractiveKeydown(e, () =>
                                this.toggleSort(col.key)
                              )}
                          >
                            ${col.label}
                            ${isSorted ? (this.sortAsc ? " ▲" : " ▼") : ""}
                          </th>
                        `;
                      })}
                    </tr>
                  </thead>
                  <tbody>
                    ${filteredRows.map(
                      (row, idx) => html`
                        <tr
                          class="clickable ${this.selectedRowIndex === idx ? "selected" : ""}"
                          tabindex="0"
                          role="button"
                          title="Click to inspect row"
                          @click=${() => this.handleRowClick(row, idx)}
                          @keydown=${(e: KeyboardEvent) =>
                            handleInteractiveKeydown(e, () =>
                              this.handleRowClick(row, idx)
                            )}
                        >
                          ${columns.map(
                            (col) =>
                              html`<td>
                                ${this.renderCell(col.key, row[col.key])}
                              </td>`
                          )}
                        </tr>
                      `
                    )}
                  </tbody>
                </table>
              `}
        </div>
      </div>
    `;
  }
}

export const AidaDataMatrixApi: LitComponentApi = {
  name: "DataMatrix",
  schema: AidaDataMatrixSchema,
  tagName: "aida-data-matrix",
  element: AidaDataMatrixElement,
};
