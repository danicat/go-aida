// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package agent

import (
	"errors"
	"fmt"

	"github.com/firebase/genkit/go/genkit"
	a2uix "github.com/firebase/genkit/go/plugins/a2ui/exp"
)

// CatalogID is the standalone A2UI v0.9 catalog identifier shared between the
// Go backend and the Lit/Three.js frontend.
const CatalogID = "aida"

// AidaCatalog returns the standalone 7-component A2UI v0.9 catalog for the
// AIDA Cyber-Diagnostic Cockpit. It intentionally excludes BasicCatalog()
// components so the model emits only flat, schema-safe AIDA components.
func AidaCatalog() *a2uix.Catalog {
	return &a2uix.Catalog{
		ID: CatalogID,
		Components: []a2uix.CatalogComponent{
			{
				Name:        "Panel",
				Description: "A framed HUD container that groups related components into rows, columns, or grids, complete with a status badge ('nominal', 'warning', or 'critical').",
				Props:       "id: string (required, use 'root' for top-level panel); title?: string; subtitle?: string; status?: 'nominal' | 'warning' | 'critical'; direction?: 'column' | 'row' | 'grid'; children: string[] of child component ids (required); weight?: number.",
			},
			{
				Name:        "Scene3D",
				Description: "An interactive 3D wireframe canvas for visualising system topologies (process trees, CPU cores, storage mounts, or threat radar) with clickable nodes for drilling down.",
				Props:       "id: string (required); title?: string; subtitle?: string; mode: 'topology' | 'cores' | 'storage' | 'threat_radar' (required); nodes: Array<{id: string, label: string, value: number, max?: number, unit?: string, status?: 'nominal' | 'warning' | 'critical', group?: string, actionName?: string, actionContext?: object}> (required); links?: Array<{source: string, target: string, label?: string, bandwidth?: number}>; weight?: number.",
			},
			{
				Name:        "CyberChart",
				Description: "A multi-series chart (line, bar, area, scatter, radar, radial, or donut) for plotting metrics like CPU load, network throughput, and latency.",
				Props:       "id: string (required); title: string (required); subtitle?: string; chartType: 'line' | 'bar' | 'area' | 'scatter' | 'radar' | 'radial' | 'donut' (required); series: Array<{label: string, value: number, max?: number, unit?: string, status?: 'nominal' | 'warning' | 'critical'}> (required); xAxisLabel?: string; yAxisLabel?: string; weight?: number.",
			},
			{
				Name:        "HudGauge",
				Description: "A visual meter (circular arc, plasma bar, segmented bar, or compact) for capacity and percentage metrics.",
				Props:       "id: string (required); title?: string; variant?: 'arc' | 'plasma' | 'segmented' | 'compact'; label?: string; value?: number; max?: number; unit?: string; status?: 'nominal' | 'warning' | 'critical'; items?: Array<{label: string, value: number, max?: number, unit?: string, subtitle?: string, status?: 'nominal' | 'warning' | 'critical'}>; weight?: number.",
			},
			{
				Name:        "DataMatrix",
				Description: "A filterable, sortable table for osquery results where clicking any row triggers a follow-up inspection on that item.",
				Props:       "id: string (required); title?: string; columns: Array<{key: string, label: string}> (required); rows: Array<Record<string, string|number|boolean|null>> (required); rowActionName?: string; weight?: number.",
			},
			{
				Name:        "TextBlock",
				Description: "A monospaced diagnostic note for summaries, SQL queries, command output, and copyable snippets.",
				Props:       "id: string (required); text: string (required); title?: string; variant?: 'heading' | 'body' | 'caption' | 'callout' | 'log'; status?: 'nominal' | 'warning' | 'critical'; weight?: number.",
			},
			{
				Name:        "ActionButton",
				Description: "An interactive button that triggers a follow-up diagnostic or remediation action.",
				Props:       "id: string (required); label: string (required); action: string | {event: {name: string, context?: object}} (required); variant?: 'primary' | 'warning' | 'danger' | 'default'; weight?: number.",
			},
		},
	}
}

// RegisterCatalog registers the standalone AIDA A2UI catalog in the Genkit
// registry so `&a2uix.Surfaces{CatalogID: CatalogID}` can resolve and validate it.
func RegisterCatalog(g *genkit.Genkit) (*a2uix.Catalog, error) {
	if g == nil {
		return nil, errors.New("cannot register aida A2UI catalog: genkit instance is nil")
	}
	catalog := AidaCatalog()
	if err := a2uix.LoadCatalog(g, catalog); err != nil {
		return nil, fmt.Errorf("failed to register aida A2UI catalog %q: %w", CatalogID, err)
	}
	return catalog, nil
}
