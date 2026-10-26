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
				Description: "Layout container card with optional title, subtitle, status indicator, and child components.",
				Props:       "id: string (required, use 'root' for top-level panel); title?: string; subtitle?: string; status?: nominal|warning|critical; direction?: column|row|grid; children: string[] of child component ids (required); weight?: number.",
			},
			{
				Name:        "Scene3D",
				Description: "Interactive 3D WebGL graph for process trees, socket connections, CPU cores, disk mounts, or CVE alerts.",
				Props:       "id: string (required); title?: string; subtitle?: string; mode: topology|cores|storage|threat_radar (required); nodes: Array<{id: string, label: string, value: number, max?: number, unit?: string, status?: nominal|warning|critical, group?: string, actionName?: string, actionContext?: object}> (required); links?: Array<{source: string, target: string, label?: string, bandwidth?: number}>; weight?: number.",
			},
			{
				Name:        "CyberChart",
				Description: "Interactive SVG chart supporting bar, donut, area, radial, and radar views.",
				Props:       "id: string (required); title: string (required); subtitle?: string; chartType: radar|radial|area|bar|donut (required); series: Array<{label: string, value: number, max?: number, unit?: string, status?: nominal|warning|critical}> (required); xAxisLabel?: string; yAxisLabel?: string; weight?: number.",
			},
			{
				Name:        "HudGauge",
				Description: "Metric gauges (arc, plasma, or compact) for CPU, memory, swap, disk, or load averages.",
				Props:       "id: string (required); title?: string; variant?: arc|plasma|compact; items: Array<{label: string, value: number, max?: number, unit?: string, subtitle?: string, status?: nominal|warning|critical}> (required); weight?: number.",
			},
			{
				Name:        "DataMatrix",
				Description: "Sortable, filterable table for osquery rows with inline percentage bars and status badges.",
				Props:       "id: string (required); title?: string; columns: Array<{key: string, label: string}> (required); rows: Array<Record<string, string|number|boolean|null>> (required); rowActionName?: string; weight?: number.",
			},
			{
				Name:        "TextBlock",
				Description: "Code, SQL, command output, or log block.",
				Props:       "id: string (required); text: string (required); title?: string; variant?: heading|body|caption|callout|log; status?: nominal|warning|critical; weight?: number.",
			},
			{
				Name:        "ActionButton",
				Description: "Button that dispatches a follow-up inspection or remediation command.",
				Props:       "id: string (required); label: string (required); variant?: primary|default|danger; action: {event: {name: string, context?: object}} (required); weight?: number.",
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
