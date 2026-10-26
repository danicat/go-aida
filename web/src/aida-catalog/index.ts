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

import { Catalog, BASIC_FUNCTIONS } from "@a2ui/web_core/v0_9";
import { type LitComponentApi } from "@a2ui/lit/v0_9";

import { AidaCatalogElement, aidaCatalogBaseStyles } from "./base.js";
import { AidaPanelApi, AidaPanelElement, AidaPanelSchema } from "./AidaPanel.js";
import { AidaScene3DApi, AidaScene3DElement, AidaScene3DSchema } from "./AidaScene3D.js";
import {
  AidaCyberChartApi,
  AidaCyberChartElement,
  AidaCyberChartSchema,
} from "./AidaCyberChart.js";
import {
  AidaHudGaugeApi,
  AidaHudGaugeElement,
  AidaHudGaugeSchema,
} from "./AidaHudGauge.js";
import {
  AidaDataMatrixApi,
  AidaDataMatrixElement,
  AidaDataMatrixSchema,
} from "./AidaDataMatrix.js";
import {
  AidaTextBlockApi,
  AidaTextBlockElement,
  AidaTextBlockSchema,
} from "./AidaTextBlock.js";
import {
  AidaActionButtonApi,
  AidaActionButtonElement,
  AidaActionButtonSchema,
} from "./AidaActionButton.js";

export const AIDA_CATALOG_ID = "aida";

export const AIDA_COMPONENTS: LitComponentApi[] = [
  AidaPanelApi,
  AidaScene3DApi,
  AidaCyberChartApi,
  AidaHudGaugeApi,
  AidaDataMatrixApi,
  AidaTextBlockApi,
  AidaActionButtonApi,
];

export const aidaCatalog = new Catalog<LitComponentApi>(
  AIDA_CATALOG_ID,
  "0.9",
  AIDA_COMPONENTS,
  BASIC_FUNCTIONS
);

export {
  AidaCatalogElement,
  aidaCatalogBaseStyles,
  AidaPanelApi,
  AidaPanelElement,
  AidaPanelSchema,
  AidaScene3DApi,
  AidaScene3DElement,
  AidaScene3DSchema,
  AidaCyberChartApi,
  AidaCyberChartElement,
  AidaCyberChartSchema,
  AidaHudGaugeApi,
  AidaHudGaugeElement,
  AidaHudGaugeSchema,
  AidaDataMatrixApi,
  AidaDataMatrixElement,
  AidaDataMatrixSchema,
  AidaTextBlockApi,
  AidaTextBlockElement,
  AidaTextBlockSchema,
  AidaActionButtonApi,
  AidaActionButtonElement,
  AidaActionButtonSchema,
};
