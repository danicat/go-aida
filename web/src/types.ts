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

export type AvatarState =
  | 'idle'
  | 'blink'
  | 'talk'
  | 'think'
  | 'think_blink'
  | 'error'
  | 'teehee';

export type ThemeMode = 'dark' | 'light';

export interface SystemStatus {
  hostname: string;
  os: string;
  arch?: string;
  osSkill?: string;
  kernel: string;
  uptime: string;
  osqueryVersion: string;
  model: string;
  thinkingLevel?: string;
  health: 'NOMINAL' | 'WARNING' | 'CRITICAL' | 'OFFLINE' | string;
  cpu?: number;
  memory?: number;
}

export interface TargetDeployment {
  label: string;
  url: string;
}

export interface DiagnosticLogEntry {
  id: string;
  timestamp: string;
  level: 'INFO' | 'TOOL' | 'SURFACE' | 'WARN' | 'ERROR';
  summary: string;
  detail?: string;
}

export interface SecurityInterruptItem {
  id: string;
  toolName: string;
  command: string;
  reason: string;
  risk: string;
  rawInterrupt: unknown;
  status: 'pending' | 'approved' | 'rejected';
  feedback: string;
}

export interface ChatTurn {
  id: string;
  timestamp: string;
  userPrompt?: string;
  isActionTurn?: boolean;
  actionName?: string;
  agentText: string;
  surfaceIds: string[];
  toolCalls: string[];
  interrupts: SecurityInterruptItem[];
  status: 'streaming' | 'awaiting_approval' | 'completed' | 'error';
  errorMessage?: string;
}

export interface QuickProbe {
  id: string;
  title: string;
  subtitle: string;
  badge: string;
  icon: string;
  prompt: string;
}
