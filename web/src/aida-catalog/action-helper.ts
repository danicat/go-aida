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

import { z } from "zod";
import { CommonSchemas, type ComponentContext } from "@a2ui/web_core/v0_9";

export const AidaEventPayloadSchema = z.object({
  name: z.string(),
  context: z.record(z.string(), z.unknown()).optional(),
  userMessage: z.string().optional(),
});

export const AidaFlexibleActionSchema = z.union([
  z.object({
    event: AidaEventPayloadSchema,
  }),
  AidaEventPayloadSchema,
  z.string(),
  CommonSchemas.Action,
]);

export type AidaFlexibleAction = z.infer<typeof AidaFlexibleActionSchema>;

export function slugifyActionName(label: string, fallback = "execute_action"): string {
  const slug = label
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 48);
  return slug || fallback;
}

export interface DispatchActionOptions {
  componentContext: ComponentContext | undefined;
  rawAction?: unknown;
  boundAction?: unknown;
  explicitActionName?: string;
  explicitActionContext?: Record<string, unknown>;
  fallbackName: string;
  fallbackContext?: Record<string, unknown>;
}

/**
 * Normalizes any A2UI action representation (bound GenericBinder function closure,
 * `{ event: { name, context } }`, `{ name, context }`, string action name,
 * `actionName` + `actionContext`, or fallback) and dispatches it on the active surface.
 */
export async function resolveAndDispatchAction(opts: DispatchActionOptions): Promise<void> {
  const {
    componentContext,
    rawAction,
    boundAction,
    explicitActionName,
    explicitActionContext,
    fallbackName,
    fallbackContext = {},
  } = opts;

  if (!componentContext) {
    return;
  }

  const candidate =
    rawAction !== undefined
      ? rawAction
      : typeof boundAction !== "function"
        ? boundAction
        : undefined;

  let resolvedName: string | undefined;
  let resolvedContext: Record<string, unknown> = {
    ...fallbackContext,
    ...(explicitActionContext ?? {}),
  };

  if (candidate && typeof candidate === "object" && !Array.isArray(candidate)) {
    const obj = candidate as Record<string, unknown>;
    if (obj.event && typeof obj.event === "object" && !Array.isArray(obj.event)) {
      const ev = obj.event as Record<string, unknown>;
      if (typeof ev.name === "string" && ev.name.trim()) {
        resolvedName = ev.name.trim();
      }
      if (ev.context && typeof ev.context === "object" && !Array.isArray(ev.context)) {
        resolvedContext = {
          ...resolvedContext,
          ...(ev.context as Record<string, unknown>),
        };
      }
    } else if (typeof obj.name === "string" && obj.name.trim()) {
      resolvedName = obj.name.trim();
      if (obj.context && typeof obj.context === "object" && !Array.isArray(obj.context)) {
        resolvedContext = {
          ...resolvedContext,
          ...(obj.context as Record<string, unknown>),
        };
      }
    }
  } else if (typeof candidate === "string" && candidate.trim()) {
    resolvedName = candidate.trim();
  }

  if (!resolvedName && explicitActionName && explicitActionName.trim()) {
    resolvedName = explicitActionName.trim();
  }

  // If GenericBinder bound `action` into a closure and we didn't extract a raw name,
  // invoke the bound closure directly.
  if (!resolvedName && typeof boundAction === "function") {
    await (boundAction as () => Promise<void>)();
    return;
  }

  const finalName = resolvedName || fallbackName || "inspect_element";
  const payload = {
    event: {
      name: finalName,
      context: resolvedContext,
    },
  };

  const surface = componentContext.dataContext?.surface;
  const sourceId = componentContext.componentModel?.id ?? "aida-component";
  if (surface) {
    await surface.dispatchAction(payload, sourceId);
  } else {
    await componentContext.dispatchAction(payload);
  }
}
