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

import { LitElement, html, nothing } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import '@a2ui/lit/v0_9';
import {
  setMarkdownRenderer,
  MessageProcessor,
  type ActionPayload,
} from '@a2ui/web_core/v0_9';
import { type LitComponentApi } from '@a2ui/lit/v0_9';
import { renderMarkdown } from '@a2ui/markdown-it';
import {
  a2uiEnvelopesFromParts,
  actionToMessage,
  type A2uiServerEnvelope,
} from '@genkit-ai/a2ui/client';
import {
  remoteAgent,
  type AgentAPI,
  type AgentChat,
  type AgentTurn,
  type AgentInput,
} from 'genkit/beta/client';
import { aidaCatalog } from './aida-catalog/index.js';
import type {
  AvatarState,
  ChatTurn,
  DiagnosticLogEntry,
  QuickProbe,
  SecurityInterruptItem,
  SystemStatus,
  TargetDeployment,
  ThemeMode,
} from './types.js';

setMarkdownRenderer(renderMarkdown);

const QUICK_PROBES: QuickProbe[] = [
  {
    id: 'probe-cpu-processes',
    title: 'Processes & CPU / Memory',
    subtitle:
      'Top processes by CPU time, resident memory (RSS), and host load average.',
    badge: 'PROCESSES',
    icon: 'memory',
    prompt:
      'Query the top CPU and memory consuming processes and host load using osquery. Render a root Panel ("Processes & Load") with a Scene3D (mode="topology", title="Process Graph"), a HudGauge (title="CPU & Memory"), and a DataMatrix (title="Top Processes") with columns PID, Process, RSS MB, CPU s, and State.',
  },
  {
    id: 'probe-network-ports',
    title: 'Listening Ports & Sockets',
    subtitle:
      'Open TCP/UDP ports, bind addresses, socket states, and owning processes.',
    badge: 'NETWORK',
    icon: 'lan',
    prompt:
      'Query all listening TCP/UDP ports, active sockets, and network interfaces using osquery. Render a root Panel ("Network Listeners") with a Scene3D (mode="topology", title="Port Map"), a CyberChart (chartType="bar", title="Ports by Process"), and a DataMatrix (title="Listening Ports") with columns Port, Protocol, Address, PID, and Process.',
  },
  {
    id: 'probe-storage-memory',
    title: 'Filesystems & Virtual Memory',
    subtitle:
      'Mounted disks, free capacity, swap usage, and virtual memory page stats.',
    badge: 'STORAGE',
    icon: 'hard_drive',
    prompt:
      'Query mounted filesystems and memory utilization via osquery. Render a root Panel ("Storage & Memory") with a Scene3D (mode="storage", title="Disk Mounts"), a HudGauge (variant="plasma", title="Memory Pressure"), and a DataMatrix (title="Mounted Filesystems") showing Mount, Device, Type, Used %, and Free GB.',
  },
  {
    id: 'probe-security-cve',
    title: 'Security & CVE Audit',
    subtitle:
      'OS build version, exposed network services, and known CVE advisories.',
    badge: 'SECURITY',
    icon: 'shield',
    prompt:
      'Inspect the current OS version, kernel version, and exposed network services using osquery, then check recent advisories using Google Search. Render a root Panel ("Security Audit") with a Scene3D (mode="threat_radar", title="Exposed Services"), a CyberChart (chartType="radar", title="Risk Summary"), and a DataMatrix (title="Findings").',
  },
  {
    id: 'probe-hitl-remediation',
    title: 'Command Execution (HITL)',
    subtitle:
      'Run a host check and propose a shell command to test operator approval.',
    badge: 'REMEDIATE',
    icon: 'terminal',
    prompt:
      'Check temporary directory usage or DNS resolver configuration, render a concise summary Panel, and invoke the runCommand tool with a safe diagnostic command (such as checking disk usage in /tmp or inspecting local DNS state) to trigger operator approval.',
  },
];

const PC98_SPRITES: AvatarState[] = [
  'idle',
  'blink',
  'talk',
  'think',
  'think_blink',
  'error',
  'teehee',
];

function stripA2uiBlocks(raw: string): string {
  return raw.replace(/```a2ui[\s\S]*?(?:```|$)/gi, '').trim();
}

@customElement('aida-cockpit')
export class AidaCockpit extends LitElement {
  @state() private targetBaseUrl: string = '';
  @state() private deployments: TargetDeployment[] = [];
  @state() private newTargetUrl: string = '';

  @state() private systemStatus: SystemStatus | null = null;
  @state() private statusOfflineError: string | null = null;

  @state() private theme: ThemeMode = 'dark';

  @state() private baseAvatarMode: 'idle' | 'think' | 'talk' | 'error' | 'teehee' = 'idle';
  @state() private lcdOverrideSpeech: string = '';
  @state() private displayedSpeech: string = '';
  @state() private isTypingSpeech: boolean = false;
  @state() private isMouthOpen: boolean = false;
  @state() private isBlinking: boolean = false;

  @state() private lcdOperationText: string = 'READY';
  @state() private lcdSeverity: 'nominal' | 'warning' | 'critical' = 'nominal';

  @state() private turns: ChatTurn[] = [];
  @state() private activeTurnIndex: number = -1;
  @state() private isStreaming: boolean = false;
  @state() private promptInput: string = '';
  @state() private criticalError: string | null = null;

  @state() private showLogs: boolean = false;
  @state() private logs: DiagnosticLogEntry[] = [];
  @state() private surfaceTick: number = 0;

  private agent!: AgentAPI<any>;
  private chat!: AgentChat<any>;
  private processor!: MessageProcessor<LitComponentApi>;

  private targetSpeech: string = '';
  private speechTurnId: string = '';
  private statusPollTimer?: number;
  private blinkTimeoutId?: number;
  private blinkEndTimeoutId?: number;
  private talkTimer?: number;
  private typewriterTimer?: number;

  private get currentAvatarSprite(): AvatarState {
    if (this.baseAvatarMode === 'error') return 'error';
    if (this.baseAvatarMode === 'teehee') return 'teehee';
    if (this.baseAvatarMode === 'talk') {
      return this.isMouthOpen ? 'talk' : 'idle';
    }
    if (this.baseAvatarMode === 'think') {
      return this.isBlinking ? 'think_blink' : 'think';
    }
    return this.isBlinking ? 'blink' : 'idle';
  }

  protected override createRenderRoot(): HTMLElement | DocumentFragment {
    return this;
  }

  public override connectedCallback(): void {
    super.connectedCallback();
    this.initTheme();
    this.initDeployments();
    this.initProcessor();
    this.initAgentClient();
    this.startAvatarTimers();
    this.enqueueSpeech(
      '__greeting__',
      'Select a diagnostic view below or enter a query.',
      true
    );
    void this.fetchSystemStatus();
    this.statusPollTimer = window.setInterval(() => {
      void this.fetchSystemStatus();
    }, 10000);
  }

  public override disconnectedCallback(): void {
    super.disconnectedCallback();
    if (this.statusPollTimer !== undefined) {
      window.clearInterval(this.statusPollTimer);
    }
    if (this.blinkTimeoutId !== undefined) {
      window.clearTimeout(this.blinkTimeoutId);
    }
    if (this.blinkEndTimeoutId !== undefined) {
      window.clearTimeout(this.blinkEndTimeoutId);
    }
    if (this.talkTimer !== undefined) {
      window.clearInterval(this.talkTimer);
    }
    if (this.typewriterTimer !== undefined) {
      window.clearInterval(this.typewriterTimer);
    }
    this.processor?.dispose();
  }

  private initTheme(): void {
    const saved = localStorage.getItem('aida_theme');
    const initial: ThemeMode = saved === 'light' || saved === 'dark' ? saved : 'dark';
    this.applyTheme(initial);
  }

  private applyTheme(mode: ThemeMode): void {
    this.theme = mode;
    localStorage.setItem('aida_theme', mode);
    const root = document.documentElement;
    root.setAttribute('data-theme', mode);
    root.classList.remove('a2ui-dark', 'a2ui-light');
    root.classList.add(`a2ui-${mode}`);
    const meta = document.querySelector('meta[name="color-scheme"]');
    if (meta) {
      meta.setAttribute('content', mode === 'light' ? 'light' : 'dark');
    }
  }

  private toggleTheme(): void {
    this.applyTheme(this.theme === 'dark' ? 'light' : 'dark');
    this.addLog('INFO', `Switched display theme to ${this.theme.toUpperCase()}`);
  }

  private initDeployments(): void {
    const origin = window.location.origin;
    const defaultLocal = 'http://localhost:8080';
    const list: TargetDeployment[] = [];

    if (window.location.port === '5173') {
      list.push({ label: `VITE PROXY (${origin})`, url: origin });
      list.push({ label: `LOCALHOST (${defaultLocal})`, url: defaultLocal });
      this.targetBaseUrl = origin;
    } else {
      list.push({ label: `CURRENT ORIGIN (${origin})`, url: origin });
      if (origin !== defaultLocal) {
        list.push({ label: `LOCALHOST (${defaultLocal})`, url: defaultLocal });
      }
      this.targetBaseUrl = origin;
    }

    this.deployments = list;
  }

  private initProcessor(): void {
    this.processor = new MessageProcessor<LitComponentApi>(
      [aidaCatalog],
      async (action: ActionPayload) => {
        await this.handleSurfaceAction(action);
      }
    );
    this.processor.onSurfaceCreated((surface) => {
      this.addLog(
        'SURFACE',
        `Surface created: "${surface.id}" (catalog: ${surface.defaultCatalog.id})`
      );
      surface.onError.subscribe((err) => {
        const msg = `A2UI Surface Error [${err.code}]: ${err.message}`;
        this.triggerFailFast(msg);
      });
      this.surfaceTick++;
    });
    this.processor.onSurfaceDeleted((id) => {
      this.addLog('SURFACE', `Surface deleted: "${id}"`);
      this.surfaceTick++;
    });
  }

  private initAgentClient(): void {
    const agentUrl = `${this.targetBaseUrl}/agents/aida`;
    this.agent = remoteAgent({ url: agentUrl });
    this.chat = this.agent.chat();
    this.addLog('INFO', `Bound Genkit remoteAgent client to ${agentUrl}`);
  }

  private scheduleNextBlink(): void {
    if (this.blinkTimeoutId !== undefined) {
      window.clearTimeout(this.blinkTimeoutId);
    }
    const delay = 2500 + Math.random() * 3500;
    this.blinkTimeoutId = window.setTimeout(() => {
      if (this.baseAvatarMode === 'idle' || this.baseAvatarMode === 'think') {
        this.isBlinking = true;
        this.blinkEndTimeoutId = window.setTimeout(() => {
          this.isBlinking = false;
          this.scheduleNextBlink();
        }, 150);
      } else {
        this.scheduleNextBlink();
      }
    }, delay);
  }

  private startAvatarTimers(): void {
    this.scheduleNextBlink();

    // PC-98 visual-novel talking loop: 240ms interval (~4.1 Hz) alternating between 'talk' and 'idle'
    this.talkTimer = window.setInterval(() => {
      if (this.baseAvatarMode === 'talk') {
        this.isMouthOpen = !this.isMouthOpen;
      } else if (this.isMouthOpen) {
        this.isMouthOpen = false;
      }
    }, 240);
  }

  private setAvatarMode(mode: 'idle' | 'think' | 'talk' | 'error' | 'teehee'): void {
    if (this.baseAvatarMode === mode) return;
    this.baseAvatarMode = mode;
    if (mode === 'talk') {
      this.isBlinking = false;
      this.isMouthOpen = true;
    } else {
      this.isMouthOpen = false;
      if (mode === 'error' || mode === 'teehee') {
        this.isBlinking = false;
      }
    }
  }

  private stopTypewriter(): void {
    if (this.typewriterTimer !== undefined) {
      window.clearInterval(this.typewriterTimer);
      this.typewriterTimer = undefined;
    }
    this.isTypingSpeech = false;
  }

  /**
   * Queues spoken text into the PC-98 speech bubble. When `animate` is true, reveals characters
   * progressively via a typewriter interval and drives AIDA's 'talk' mouth animation until
   * the entire utterance has been spoken on screen.
   */
  private enqueueSpeech(turnId: string, fullText: string, animate = true): void {
    const trimmed = fullText.trim();
    if (!animate) {
      this.stopTypewriter();
      this.speechTurnId = turnId;
      this.targetSpeech = trimmed;
      this.displayedSpeech = trimmed;
      return;
    }

    if (
      turnId !== this.speechTurnId ||
      !trimmed.startsWith(this.displayedSpeech.slice(0, Math.min(12, this.displayedSpeech.length)))
    ) {
      this.displayedSpeech = '';
    }

    this.speechTurnId = turnId;
    this.targetSpeech = trimmed;

    if (this.displayedSpeech.length < this.targetSpeech.length) {
      this.isTypingSpeech = true;
      if (this.baseAvatarMode !== 'error') {
        this.setAvatarMode('talk');
      }
      if (this.typewriterTimer === undefined) {
        this.typewriterTimer = window.setInterval(() => {
          this.stepTypewriter();
        }, 30);
      }
    }
  }

  private stepTypewriter(): void {
    if (this.displayedSpeech.length < this.targetSpeech.length) {
      const remaining = this.targetSpeech.length - this.displayedSpeech.length;
      const step = remaining > 180 ? 2 : 1;
      const nextLen = Math.min(this.targetSpeech.length, this.displayedSpeech.length + step);
      this.displayedSpeech = this.targetSpeech.slice(0, nextLen);

      if (this.baseAvatarMode !== 'error' && this.baseAvatarMode !== 'talk') {
        this.setAvatarMode('talk');
      }

      const speechEl = this.querySelector<HTMLElement>('.lcd-speech');
      if (speechEl) {
        speechEl.scrollTop = speechEl.scrollHeight;
      }
    } else {
      this.stopTypewriter();
      if (this.criticalError) {
        this.setAvatarMode('error');
      } else {
        const activeTurn =
          this.activeTurnIndex >= 0 && this.activeTurnIndex < this.turns.length
            ? this.turns[this.activeTurnIndex]
            : null;
        if (this.isStreaming || activeTurn?.status === 'awaiting_approval') {
          this.setAvatarMode('think');
        } else {
          this.setAvatarMode('idle');
        }
      }
    }
  }

  private handleAvatarClick(): void {
    if (this.baseAvatarMode === 'idle') {
      this.setAvatarMode('teehee');
      window.setTimeout(() => {
        if (this.baseAvatarMode === 'teehee') {
          this.setAvatarMode('idle');
        }
      }, 1200);
    }
  }

  private addLog(
    level: DiagnosticLogEntry['level'],
    summary: string,
    detail?: string
  ): void {
    const now = new Date();
    const timestamp = now.toTimeString().split(' ')[0];
    this.logs = [
      {
        id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
        timestamp,
        level,
        summary,
        detail,
      },
      ...this.logs.slice(0, 99),
    ];
  }

  private triggerFailFast(errorMessage: string): void {
    this.criticalError = errorMessage;
    this.lcdOperationText = `ERROR`;
    this.lcdSeverity = 'critical';
    this.setAvatarMode('error');
    this.addLog('ERROR', errorMessage);
  }

  private async fetchSystemStatus(): Promise<void> {
    const url = `${this.targetBaseUrl}/api/system-status`;
    try {
      const response = await fetch(url, {
        method: 'GET',
        headers: { Accept: 'application/json' },
      });
      if (!response.ok) {
        const errText = await response.text();
        throw new Error(`HTTP ${response.status} from ${url}: ${errText}`);
      }
      const data = (await response.json()) as SystemStatus;
      this.systemStatus = data;
      this.statusOfflineError = null;
    } catch (err: any) {
      const msg = err?.message ?? String(err);
      this.systemStatus = null;
      this.statusOfflineError = msg;
      this.triggerFailFast(`Telemetry endpoint failure (${url}): ${msg}`);
    }
  }

  private handleTargetChange(e: Event): void {
    const select = e.target as HTMLSelectElement;
    const nextUrl = select.value;
    if (!nextUrl || nextUrl === this.targetBaseUrl) return;
    this.switchTargetDeployment(nextUrl);
  }

  private switchTargetDeployment(nextUrl: string): void {
    const normalized = nextUrl.trim().replace(/\/+$/, '');
    this.targetBaseUrl = normalized;
    this.criticalError = null;
    this.setAvatarMode('idle');
    this.lcdOperationText = `TARGET: ${normalized}`;
    this.lcdSeverity = 'nominal';
    this.initAgentClient();
    void this.fetchSystemStatus();
  }

  private submitNewTarget(): void {
    const candidate = this.newTargetUrl.trim().replace(/\/+$/, '');
    if (!/^https?:\/\/[^/]+$/i.test(candidate)) {
      this.triggerFailFast(
        `Invalid target deployment URL "${candidate}". Must be http(s)://host[:port].`
      );
      return;
    }
    if (!this.deployments.some((d) => d.url === candidate)) {
      this.deployments = [
        ...this.deployments,
        { label: `REMOTE (${candidate})`, url: candidate },
      ];
    }
    this.newTargetUrl = '';
    this.switchTargetDeployment(candidate);
  }

  private resetSession(): void {
    this.processor.dispose();
    this.initProcessor();
    this.initAgentClient();
    this.turns = [];
    this.activeTurnIndex = -1;
    this.criticalError = null;
    this.isStreaming = false;
    this.lcdOverrideSpeech = '';
    this.lcdOperationText = 'READY';
    this.lcdSeverity = 'nominal';
    this.enqueueSpeech('__greeting__', 'Select a diagnostic view below or enter a query.', true);
    this.addLog('INFO', 'Cleared all A2UI surfaces and initialized fresh session.');
  }

  private selectTab(index: number): void {
    if (index === -1) {
      this.activeTurnIndex = -1;
      this.lcdOperationText = 'READY';
      this.lcdSeverity = 'nominal';
      this.enqueueSpeech('__greeting__', 'Select a diagnostic view below or enter a query.', false);
      this.addLog('INFO', 'Navigated to Home launcher');
      return;
    }
    if (index >= 0 && index < this.turns.length) {
      this.activeTurnIndex = index;
      this.lcdOperationText = 'READY';
      this.lcdSeverity = 'nominal';
      this.enqueueSpeech(this.turns[index].id, this.turns[index].agentText || '', false);
      this.addLog('INFO', `Selected tab #${index + 1}`);
    }
  }

  private closeTurnTab(e: Event, index: number): void {
    e.stopPropagation();
    const targetTurn = this.turns[index];
    if (!targetTurn) return;

    for (const sid of targetTurn.surfaceIds) {
      this.processor.model.deleteSurface(sid);
    }

    const nextTurns = this.turns.filter((_, i) => i !== index);
    this.turns = nextTurns;

    if (nextTurns.length === 0) {
      this.activeTurnIndex = -1;
      this.enqueueSpeech('__greeting__', 'Select a diagnostic view below or enter a query.', false);
    } else {
      if (index < this.activeTurnIndex) {
        this.activeTurnIndex--;
      } else if (index === this.activeTurnIndex) {
        this.activeTurnIndex = Math.min(this.activeTurnIndex, nextTurns.length - 1);
      }
      const nextActive = nextTurns[this.activeTurnIndex];
      if (nextActive) {
        this.enqueueSpeech(nextActive.id, nextActive.agentText || '', false);
      }
    }
    this.surfaceTick++;
  }

  private ingestEnvelopes(
    envelopes: A2uiServerEnvelope[],
    turnId: string,
    processedKeys: Set<string>
  ): void {
    if (!envelopes || envelopes.length === 0) return;

    const freshEnvelopes: A2uiServerEnvelope[] = [];
    for (const env of envelopes) {
      const key = JSON.stringify(env);
      if (processedKeys.has(key)) continue;
      processedKeys.add(key);
      freshEnvelopes.push(env);
    }

    if (freshEnvelopes.length === 0) return;

    const touchedSurfaceIds: string[] = [];

    for (const env of freshEnvelopes) {
      const anyEnv = env as Record<string, any>;
      if (anyEnv.createSurface && typeof anyEnv.createSurface.surfaceId === 'string') {
        const sid = anyEnv.createSurface.surfaceId;
        if (this.processor.model.getSurface(sid)) {
          this.processor.model.deleteSurface(sid);
        }
        touchedSurfaceIds.push(sid);
        this.lcdOperationText = `RENDERING VIEW...`;
      } else if (
        anyEnv.updateComponents &&
        typeof anyEnv.updateComponents.surfaceId === 'string'
      ) {
        touchedSurfaceIds.push(anyEnv.updateComponents.surfaceId);
        this.lcdOperationText = `RENDERING VIEW...`;
      } else if (
        anyEnv.updateDataModel &&
        typeof anyEnv.updateDataModel.surfaceId === 'string'
      ) {
        touchedSurfaceIds.push(anyEnv.updateDataModel.surfaceId);
      }
    }

    this.processor.processMessages(freshEnvelopes as any);

    if (touchedSurfaceIds.length > 0) {
      this.turns = this.turns.map((t) => {
        if (t.id === turnId) {
          const merged = Array.from(new Set([...t.surfaceIds, ...touchedSurfaceIds]));
          return { ...t, surfaceIds: merged };
        }
        return {
          ...t,
          surfaceIds: t.surfaceIds.filter((id) => !touchedSurfaceIds.includes(id)),
        };
      });
      const idx = this.turns.findIndex((t) => t.id === turnId);
      if (idx >= 0) {
        this.activeTurnIndex = idx;
      }
      this.surfaceTick++;
    }
  }

  private toggleLogs(): void {
    this.showLogs = !this.showLogs;
  }

  private async handleSurfaceAction(action: ActionPayload): Promise<void> {
    const ctx = (action.context ?? {}) as Record<string, any>;

    if (this.isStreaming) return;

    const targetDesc =
      ctx.label ??
      ctx.name ??
      ctx.process ??
      (ctx.pid !== undefined ? `PID ${ctx.pid}` : undefined) ??
      (ctx.port !== undefined ? `Port ${ctx.port}` : undefined) ??
      ctx.nodeId ??
      action.name.replace(/_/g, ' ');

    this.addLog(
      'SURFACE',
      `Action "${action.name}" on "${targetDesc}" (surface "${action.surfaceId}")`,
      JSON.stringify(ctx)
    );
    const message = actionToMessage(action as any);
    await this.executeTurn(
      { message },
      String(targetDesc),
      true,
      action.name
    );
  }

  private async handlePromptSubmit(e: Event): Promise<void> {
    e.preventDefault();
    const text = this.promptInput.trim();
    if (!text || this.isStreaming) return;
    this.promptInput = '';
    await this.executeTurn(text, text, false);
  }

  private async runQuickProbe(probe: QuickProbe): Promise<void> {
    if (this.isStreaming) return;
    await this.executeTurn(probe.prompt, probe.title, false);
  }

  private async executeTurn(
    input: string | AgentInput,
    displayPrompt: string,
    isActionTurn: boolean,
    actionName?: string
  ): Promise<void> {
    const turnId = `turn-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const timestamp = new Date().toTimeString().split(' ')[0];

    const newTurn: ChatTurn = {
      id: turnId,
      timestamp,
      userPrompt: displayPrompt,
      isActionTurn,
      actionName,
      agentText: '',
      surfaceIds: [],
      toolCalls: [],
      interrupts: [],
      status: 'streaming',
    };

    const hadActiveSurface =
      this.activeTurnIndex >= 0 &&
      this.turns[this.activeTurnIndex]?.surfaceIds.length > 0;

    this.turns = [...this.turns, newTurn];
    if (!hadActiveSurface) {
      this.activeTurnIndex = this.turns.length - 1;
    }

    this.criticalError = null;
    this.lcdOverrideSpeech = '';
    this.stopTypewriter();
    this.displayedSpeech = '';
    this.targetSpeech = '';
    this.speechTurnId = turnId;
    this.isStreaming = true;
    this.setAvatarMode('think');
    this.lcdOperationText = `QUERYING: ${displayPrompt}`;
    this.lcdSeverity = 'nominal';

    this.addLog('INFO', `Turn started: ${displayPrompt}`);

    const turn = this.chat.sendStream(input);
    await this.consumeTurnStream(turn, turnId);
  }

  private dismissInterrupt(turnId: string, interruptId: string): void {
    this.turns = this.turns.map((t) =>
      t.id === turnId
        ? {
            ...t,
            interrupts: t.interrupts.filter((intr) => intr.id !== interruptId),
          }
        : t
    );
  }

  private clearResolvedInterrupts(turnId: string): void {
    this.turns = this.turns.map((t) =>
      t.id === turnId
        ? {
            ...t,
            interrupts: t.interrupts.filter((intr) => intr.status === 'pending'),
          }
        : t
    );
  }

  private async handleInterruptDecision(
    turnId: string,
    interruptItem: SecurityInterruptItem,
    approved: boolean
  ): Promise<void> {
    if (this.isStreaming) return;

    this.turns = this.turns.map((t) => {
      if (t.id !== turnId) return t;
      return {
        ...t,
        status: 'streaming',
        interrupts: t.interrupts.map((intr) =>
          intr.id === interruptItem.id
            ? { ...intr, status: approved ? 'approved' : 'rejected' }
            : intr
        ),
      };
    });

    this.isStreaming = true;
    this.criticalError = null;
    this.stopTypewriter();
    this.displayedSpeech = '';
    this.targetSpeech = '';
    this.speechTurnId = turnId;
    this.setAvatarMode('think');
    this.lcdOperationText = approved
      ? `RUNNING COMMAND: ${interruptItem.command}`
      : `COMMAND DENIED`;
    this.lcdSeverity = approved ? 'warning' : 'nominal';

    this.addLog(
      'TOOL',
      `Operator ${approved ? 'APPROVED' : 'DENIED'} runCommand: ${interruptItem.command}`,
      interruptItem.feedback
    );

    const rawIntr = interruptItem.rawInterrupt as { restart: () => any };
    const restartPart = rawIntr.restart();
    restartPart.metadata = {
      ...(restartPart.metadata ?? {}),
      resumed: {
        approved,
        feedback: interruptItem.feedback || undefined,
      },
    };

    const resumedTurn = this.chat.resumeStream({ restart: [restartPart] });
    await this.consumeTurnStream(resumedTurn, turnId);
  }

  private async consumeTurnStream(
    turn: AgentTurn<any>,
    turnId: string
  ): Promise<void> {
    const processedEnvelopeKeys = new Set<string>();
    let rawTextBuffer = '';

    try {
      for await (const chunk of turn.stream) {
        if (chunk.toolRequests && chunk.toolRequests.length > 0) {
          for (const tr of chunk.toolRequests) {
            const toolName = tr.toolRequest.name;
            if (!this.isTypingSpeech) {
              this.setAvatarMode('think');
            }
            this.lcdOperationText = `EXECUTING: ${toolName}`;
            this.lcdSeverity = 'warning';
            this.addLog(
              'TOOL',
              `Tool request: ${toolName}`,
              JSON.stringify(tr.toolRequest.input ?? {})
            );
            this.turns = this.turns.map((t) =>
              t.id === turnId && !t.toolCalls.includes(toolName)
                ? { ...t, toolCalls: [...t.toolCalls, toolName] }
                : t
            );
          }
        }

        if (chunk.text) {
          rawTextBuffer += chunk.text;
          const cleanSpoken = stripA2uiBlocks(rawTextBuffer);
          this.turns = this.turns.map((t) =>
            t.id === turnId ? { ...t, agentText: cleanSpoken } : t
          );

          if (cleanSpoken.length > 0) {
            this.enqueueSpeech(turnId, cleanSpoken, true);
          }
        }

        const envelopes = a2uiEnvelopesFromParts(chunk.raw.modelChunk?.content);
        if (envelopes.length > 0) {
          if (!this.isTypingSpeech) {
            this.setAvatarMode('think');
          }
          this.clearResolvedInterrupts(turnId);
          this.ingestEnvelopes(envelopes, turnId, processedEnvelopeKeys);
        }
      }

      const res = await turn.response;

      const finalEnvelopes = a2uiEnvelopesFromParts(res.message?.content);
      if (finalEnvelopes.length > 0) {
        if (!this.isTypingSpeech) {
          this.setAvatarMode('think');
        }
        this.clearResolvedInterrupts(turnId);
        this.ingestEnvelopes(finalEnvelopes, turnId, processedEnvelopeKeys);
      }

      if (res.text) {
        const cleanFinal = stripA2uiBlocks(res.text);
        this.turns = this.turns.map((t) =>
          t.id === turnId && !t.agentText ? { ...t, agentText: cleanFinal } : t
        );
        if (cleanFinal.length > 0) {
          this.enqueueSpeech(turnId, cleanFinal, true);
        }
      }

      const turnIndex = this.turns.findIndex((t) => t.id === turnId);
      if (turnIndex >= 0) {
        this.activeTurnIndex = turnIndex;
      }

      if (res.interrupts && res.interrupts.length > 0) {
        const batchTs = Date.now();
        const mappedInterrupts: SecurityInterruptItem[] = res.interrupts.map(
          (intr, idx) => {
            const rawInput = (intr.input ?? {}) as Record<string, any>;
            const metaInterrupt =
              ((intr as any).metadata?.interrupt as Record<string, any>) ?? {};
            const command =
              String(rawInput.command ?? metaInterrupt.command ?? 'UNKNOWN COMMAND');
            const reason =
              String(
                rawInput.reason ??
                  metaInterrupt.reason ??
                  'Remediation requires explicit operator confirmation.'
              );
            const risk = String(rawInput.risk ?? metaInterrupt.risk ?? 'HIGH');
            return {
              id: `${turnId}-intr-${batchTs}-${idx}`,
              toolName: intr.name,
              command,
              reason,
              risk,
              rawInterrupt: intr,
              status: 'pending',
              feedback: '',
            };
          }
        );

        this.turns = this.turns.map((t) =>
          t.id === turnId
            ? {
                ...t,
                status: 'awaiting_approval',
                // Automatically clear any previously executed/denied commands so only pending interrupts are shown
                interrupts: mappedInterrupts,
              }
            : t
        );
        if (!this.isTypingSpeech) {
          this.setAvatarMode('think');
        }
        this.lcdOperationText = 'APPROVAL REQUIRED: runCommand';
        this.lcdSeverity = 'critical';
        this.addLog(
          'WARN',
          `Security interrupt triggered (${mappedInterrupts.length} pending confirmation)`
        );
      } else {
        this.turns = this.turns.map((t) =>
          t.id === turnId
            ? {
                ...t,
                status: 'completed',
                // Automatically clear executed/denied commands when the turn finishes
                interrupts: [],
              }
            : t
        );
        if (!this.isTypingSpeech) {
          this.setAvatarMode('idle');
        }
        this.lcdOperationText = 'READY';
        this.lcdSeverity = 'nominal';
      }
    } catch (err: any) {
      const msg = err?.message ?? String(err);
      this.turns = this.turns.map((t) =>
        t.id === turnId
          ? {
              ...t,
              status: 'error',
              errorMessage: msg,
              interrupts: t.interrupts.filter((intr) => intr.status === 'pending'),
            }
          : t
      );
      const turnIndex = this.turns.findIndex((t) => t.id === turnId);
      if (turnIndex >= 0) {
        this.activeTurnIndex = turnIndex;
      }
      this.triggerFailFast(`Agent stream failure: ${msg}`);
    } finally {
      this.isStreaming = false;
    }
  }

  private renderTopBar() {
    const status = this.systemStatus;
    const healthRaw =
      status?.health?.toUpperCase() ?? (this.statusOfflineError ? 'OFFLINE' : 'NOMINAL');
    const healthClass =
      healthRaw === 'NOMINAL'
        ? 'nominal'
        : healthRaw === 'WARNING'
          ? 'warning'
          : 'critical';
    const healthLabel = healthRaw;

    return html`
      <header class="cockpit-topbar">
        <div class="brand-cluster">
          <h1 class="brand-title">AIDA // SYSTEM DIAGNOSTICS</h1>
          <span class="health-badge ${healthClass}">
            <span class="health-dot"></span>
            ${healthLabel}
          </span>
        </div>

        <div class="header-controls">
          <button
            type="button"
            class="cyber-btn icon-btn"
            popovertarget="host-popover"
            aria-label="Configure Host Target"
            title="Configure Host Target"
          >
            <span class="material-symbols-outlined">tune</span>
          </button>

          <div id="host-popover" popover="auto" class="host-popover">
            <div class="host-popover-header">
              <span class="host-popover-title">TARGET DEPLOYMENT</span>
            </div>
            <div class="host-popover-body">
              <label class="host-popover-label" for="host-target-select">ACTIVE HOST:</label>
              <select
                id="host-target-select"
                class="cyber-select"
                aria-label="Target Deployment Selector"
                .value=${this.targetBaseUrl}
                @change=${this.handleTargetChange}
              >
                ${this.deployments.map(
                  (d) => html`
                    <option value=${d.url} ?selected=${d.url === this.targetBaseUrl}>
                      ${d.label}
                    </option>
                  `
                )}
              </select>

              <div class="host-popover-custom">
                <input
                  type="url"
                  class="cyber-input-sm"
                  aria-label="Remote target deployment URL"
                  placeholder="http://host:8080"
                  .value=${this.newTargetUrl}
                  @input=${(e: Event) => {
                    this.newTargetUrl = (e.target as HTMLInputElement).value;
                  }}
                  @keydown=${(e: KeyboardEvent) => {
                    if (e.key === 'Enter') this.submitNewTarget();
                  }}
                />
                <button
                  type="button"
                  class="cyber-btn nominal"
                  @click=${this.submitNewTarget}
                  aria-label="Connect to target"
                >
                  CONNECT
                </button>
              </div>
            </div>
          </div>

          <button
            type="button"
            class="cyber-btn icon-btn"
            @click="${this.toggleTheme}"
            aria-label="Toggle Theme"
            title="Toggle Theme"
          >
            <span class="material-symbols-outlined">${this.theme === 'dark' ? 'light_mode' : 'dark_mode'}</span>
          </button>

          <button
            type="button"
            class="cyber-btn icon-btn ${this.showLogs ? 'active' : ''}"
            @click="${this.toggleLogs}"
            aria-label="Toggle Diagnostic Logs"
            title="Toggle Diagnostic Logs"
          >
            <span class="material-symbols-outlined">terminal</span>
          </button>

          <button
            type="button"
            class="cyber-btn icon-btn danger"
            @click="${this.resetSession}"
            aria-label="Reset Session"
            title="Reset Session"
          >
            <span class="material-symbols-outlined">restart_alt</span>
          </button>
        </div>
      </header>
    `;
  }

  private renderOperatorSidebar() {
    const status = this.systemStatus;
    const cpuMemStr =
      status?.cpu !== undefined && status?.memory !== undefined
        ? `${status.cpu.toFixed(1)}% / ${status.memory.toFixed(1)}%`
        : status?.model ?? 'N/A';

    const activeSprite = this.currentAvatarSprite;

    return html`
      <aside class="operator-sidebar pc98-frame" aria-label="AIDA Avatar & Host Telemetry">
        <div class="avatar-crt-wrapper">
          <div
            class="avatar-crt-frame ${this.baseAvatarMode === 'error' ? 'error-state' : ''}"
            @click=${this.handleAvatarClick}
            title="AIDA (Click to interact)"
          >
            <div class="avatar-sprite-stack">
              ${PC98_SPRITES.map(
                (sprite) => html`
                  <img
                    class="avatar-img ${activeSprite === sprite ? 'active' : ''}"
                    src="${this.targetBaseUrl}/assets/${sprite}.png"
                    alt="AIDA Avatar (${sprite})"
                    decoding="async"
                    @error=${() => {
                      this.triggerFailFast(
                        `Failed to load PC-98 avatar sprite from ${this.targetBaseUrl}/assets/${sprite}.png`
                      );
                    }}
                  />
                `
              )}
            </div>
          </div>
        </div>

        <div class="sysinfo-grid">
          <div class="sysinfo-cell">
            <span class="sysinfo-key">HOST</span>
            <span class="sysinfo-val" title=${status?.hostname ?? 'OFFLINE'}>
              ${status?.hostname ?? 'OFFLINE'}
            </span>
          </div>
          <div class="sysinfo-cell">
            <span class="sysinfo-key">KERNEL</span>
            <span class="sysinfo-val" title=${status?.kernel ?? 'OFFLINE'}>
              ${status?.kernel ?? 'OFFLINE'}
            </span>
          </div>
          <div class="sysinfo-cell">
            <span class="sysinfo-key">OSQUERY</span>
            <span class="sysinfo-val">v${status?.osqueryVersion ?? '---'}</span>
          </div>
          <div class="sysinfo-cell">
            <span class="sysinfo-key">OS / ARCH</span>
            <span class="sysinfo-val">${status?.os ?? 'OFFLINE'}</span>
          </div>
          <div class="sysinfo-cell">
            <span class="sysinfo-key">UPTIME</span>
            <span class="sysinfo-val">${status?.uptime ?? 'OFFLINE'}</span>
          </div>
          <div class="sysinfo-cell">
            <span class="sysinfo-key">CPU / MEM</span>
            <span class="sysinfo-val">${cpuMemStr}</span>
          </div>
        </div>
      </aside>
    `;
  }

  private renderOperatorConsole(activeTurn: ChatTurn | null) {
    const spokenText =
      this.lcdOverrideSpeech ||
      this.displayedSpeech ||
      (this.isStreaming
        ? 'Running host queries...'
        : activeTurn?.agentText?.trim() || 'Select a diagnostic view below or enter a query.');

    const showCursor = this.isTypingSpeech || (this.isStreaming && !this.displayedSpeech);

    return html`
      <section class="operator-console" aria-label="AIDA Conversation Console">
        <div class="avatar-caption">
          <span>AIDA [PC-98]</span>
          <span class="caption-state ${this.baseAvatarMode}">${this.baseAvatarMode.toUpperCase()}</span>
        </div>
        <div class="lcd-bezel" aria-live="polite">
          <div class="lcd-line status-line ${this.lcdSeverity}">
            <span>● ${this.lcdOperationText}</span>
            ${activeTurn && activeTurn.toolCalls.length > 0
              ? html`
                  <div class="turn-meta">
                    ${activeTurn.toolCalls.map(
                      (tc) => html`<span class="tool-pill">⚙ ${tc}</span>`
                    )}
                  </div>
                `
              : nothing}
          </div>
          <div class="lcd-speech">
            ${spokenText}${showCursor
              ? html`<span class="speech-cursor" aria-hidden="true"></span>`
              : nothing}
          </div>
        </div>
      </section>
    `;
  }

  private renderQuickProbes() {
    return html`
      <section class="quick-probe-stage">
        <div class="probe-grid">
          ${QUICK_PROBES.map(
            (probe) => html`
              <button
                type="button"
                class="probe-card pc98-frame"
                ?disabled=${this.isStreaming}
                @click=${() => this.runQuickProbe(probe)}
              >
                <div class="probe-card-top">
                  <span class="probe-badge">${probe.badge}</span>
                  <span class="material-symbols-outlined" aria-hidden="true">${probe.icon}</span>
                </div>
                <div class="probe-title">${probe.title}</div>
                <div class="probe-desc">${probe.subtitle}</div>
              </button>
            `
          )}
        </div>
      </section>
    `;
  }

  private renderInterruptCard(turn: ChatTurn, intr: SecurityInterruptItem) {
    const isPending = intr.status === 'pending';

    if (!isPending) {
      return html`
        <div class="hitl-executed-pill pc98-frame ${intr.status}">
          <span class="hitl-executed-status">
            ${intr.status === 'approved' ? '⚙ RUNNING:' : '✗ DENIED:'}
          </span>
          <code class="hitl-executed-cmd">${intr.command}</code>
          <button
            type="button"
            class="cyber-btn icon-btn"
            @click=${() => this.dismissInterrupt(turn.id, intr.id)}
            aria-label="Clear command notification"
            title="Clear command notification"
          >
            <span class="material-symbols-outlined">close</span>
          </button>
        </div>
      `;
    }

    return html`
      <div class="hitl-interrupt-card pc98-frame">
        <div class="hitl-header">
          <span class="hitl-title">
            🚨 COMMAND APPROVAL REQUIRED
          </span>
          <div style="display: inline-flex; align-items: center; gap: 8px;">
            <span class="hitl-risk-badge">RISK: ${intr.risk.toUpperCase()}</span>
          </div>
        </div>

        <div class="hitl-grid">
          <div class="hitl-key">TOOL</div>
          <div>${intr.toolName}</div>

          <div class="hitl-key">COMMAND</div>
          <div class="hitl-code">${intr.command}</div>

          <div class="hitl-key">REASON</div>
          <div>${intr.reason}</div>

          <div class="hitl-key">STATUS</div>
          <div>AWAITING APPROVAL</div>
        </div>

        <div class="hitl-actions">
          <input
            type="text"
            class="hitl-feedback-input"
            aria-label="Operator approval feedback"
            placeholder="Optional note..."
            .value=${intr.feedback}
            @input=${(e: Event) => {
              const val = (e.target as HTMLInputElement).value;
              intr.feedback = val;
              this.requestUpdate();
            }}
          />
          <button
            type="button"
            class="cyber-btn nominal"
            ?disabled=${this.isStreaming}
            @click=${() => this.handleInterruptDecision(turn.id, intr, true)}
          >
            <span class="material-symbols-outlined" aria-hidden="true" style="font-size: 16px;">check</span>
            APPROVE
          </button>
          <button
            type="button"
            class="cyber-btn danger"
            ?disabled=${this.isStreaming}
            @click=${() => this.handleInterruptDecision(turn.id, intr, false)}
          >
            <span class="material-symbols-outlined" aria-hidden="true" style="font-size: 16px;">close</span>
            DENY
          </button>
        </div>
      </div>
    `;
  }

  private handleTabKeydown(e: KeyboardEvent, idx: number): void {
    if (this.turns.length === 0) return;
    if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
    e.preventDefault();
    const delta = e.key === 'ArrowRight' ? 1 : -1;
    const nextIdx = (idx + delta + this.turns.length) % this.turns.length;
    this.selectTab(nextIdx);
    void this.updateComplete.then(() => {
      const nextBtn = this.querySelector<HTMLButtonElement>(`#aida-tab-${nextIdx}`);
      nextBtn?.focus();
    });
  }

  private renderCanvasNavBar() {
    if (this.turns.length === 0) {
      return nothing;
    }

    const canBack = this.activeTurnIndex > 0;
    const canForward =
      this.activeTurnIndex >= 0 && this.activeTurnIndex < this.turns.length - 1;

    return html`
      <nav class="canvas-nav-bar" aria-label="View Tabs">
        <div class="nav-controls-left">
          <button
            type="button"
            class="cyber-btn icon-btn ${this.activeTurnIndex === -1 ? 'active' : ''}"
            @click=${() => {
              this.selectTab(-1);
            }}
            aria-label="Diagnostic Views"
            title="Diagnostic Views"
          >
            <span class="material-symbols-outlined">grid_view</span>
          </button>
          <button
            type="button"
            class="cyber-btn icon-btn"
            ?disabled=${!canBack}
            @click=${() => {
              if (this.activeTurnIndex > 0) this.selectTab(this.activeTurnIndex - 1);
            }}
            aria-label="Previous tab"
            title="Previous tab"
          >
            <span class="material-symbols-outlined">chevron_left</span>
          </button>
          <button
            type="button"
            class="cyber-btn icon-btn"
            ?disabled=${!canForward}
            @click=${() => {
              if (this.activeTurnIndex < this.turns.length - 1) {
                this.selectTab(this.activeTurnIndex + 1);
              }
            }}
            aria-label="Next tab"
            title="Next tab"
          >
            <span class="material-symbols-outlined">chevron_right</span>
          </button>
        </div>

        <div class="breadcrumb-trail" role="tablist">
          ${this.turns.map((t, idx) => {
            const isCurrent = idx === this.activeTurnIndex;
            const rawPrompt = (t.userPrompt ?? 'View')
              .replace(/^DRILL-DOWN\s*\/\/\s*/i, '')
              .replace(/^\[|\]$/g, '');
            const shortLabel =
              rawPrompt.length > 26 ? `${rawPrompt.slice(0, 24)}…` : rawPrompt;
            return html`
              <div
                class="breadcrumb-step ${isCurrent ? 'active' : ''} ${t.status}"
              >
                <button
                  type="button"
                  id="aida-tab-${idx}"
                  class="breadcrumb-tab-btn"
                  role="tab"
                  aria-controls="aida-tabpanel"
                  aria-selected=${isCurrent ? 'true' : 'false'}
                  tabindex=${isCurrent ? '0' : '-1'}
                  title=${t.userPrompt ?? ''}
                  @click=${() => {
                    this.selectTab(idx);
                  }}
                  @keydown=${(e: KeyboardEvent) => this.handleTabKeydown(e, idx)}
                >
                  <span class="step-idx">#${idx + 1}</span>
                  <span class="step-label">${shortLabel}</span>
                </button>
                <button
                  type="button"
                  class="tab-close-btn"
                  title="Close tab"
                  aria-label="Close tab ${shortLabel}"
                  @click=${(e: Event) => this.closeTurnTab(e, idx)}
                >
                  ×
                </button>
              </div>
            `;
          })}
        </div>
      </nav>
    `;
  }

  private renderActiveCanvasTurn(turn: ChatTurn) {
    void this.surfaceTick;
    const latestTurn = this.turns[this.turns.length - 1];
    const isSynthesizingNextTurn =
      this.isStreaming && latestTurn && latestTurn.id !== turn.id;

    return html`
      <div
        class="active-stage-container"
        role="tabpanel"
        id="aida-tabpanel"
        aria-labelledby="aida-tab-${this.activeTurnIndex}"
      >
        ${turn.interrupts.length > 0
          ? html`
              <div class="hitl-interrupt-list">
                ${turn.interrupts.map((intr) => this.renderInterruptCard(turn, intr))}
              </div>
            `
          : nothing}

        <div class="stage-surface-viewport">
          ${turn.surfaceIds.length > 0
            ? html`
                <div class="turn-surfaces">
                  ${turn.surfaceIds.map((sid) => {
                    const surfaceModel = this.processor.getSurface(sid);
                    if (!surfaceModel) return nothing;
                    return html`
                      <div class="surface-wrapper">
                        <a2ui-surface .surface=${surfaceModel}></a2ui-surface>
                      </div>
                    `;
                  })}
                </div>
              `
            : turn.status === 'streaming'
              ? html`
                  <div class="stage-loading-holo">
                    <div class="holo-spinner"></div>
                    <div class="holo-loading-title">
                      QUERYING HOST...
                    </div>
                    <div class="holo-loading-sub">${this.lcdOperationText}</div>
                  </div>
                `
              : nothing}

          ${isSynthesizingNextTurn
            ? html`
                <div class="drilldown-loading-overlay">
                  <div class="holo-spinner"></div>
                  <div class="holo-loading-title">
                    LOADING: ${latestTurn.userPrompt}
                  </div>
                  <div class="holo-loading-sub">${this.lcdOperationText}</div>
                </div>
              `
            : nothing}
        </div>

        ${turn.errorMessage
          ? html`
              <div class="fail-fast-detail" style="color: var(--aida-critical);">
                [ERROR]: ${turn.errorMessage}
              </div>
            `
          : nothing}
      </div>
    `;
  }

  protected override render() {
    const activeTurn =
      this.activeTurnIndex >= 0 && this.activeTurnIndex < this.turns.length
        ? this.turns[this.activeTurnIndex]
        : null;

    return html`
      ${this.renderTopBar()}

      ${this.criticalError
        ? html`
            <div class="fail-fast-banner" role="alert">
              <div class="fail-fast-content">
                <div class="fail-fast-title">
                  🚨 DIAGNOSTIC ERROR
                </div>
                <div class="fail-fast-detail">${this.criticalError}</div>
              </div>
              <button
                type="button"
                class="cyber-btn icon-btn danger"
                aria-label="Dismiss error"
                title="Dismiss error"
                @click=${() => {
                  this.criticalError = null;
                  if (!this.isStreaming) this.setAvatarMode('idle');
                }}
              >
                <span class="material-symbols-outlined">close</span>
              </button>
            </div>
          `
        : nothing}

      ${this.showLogs
        ? html`
            <aside class="log-drawer">
              ${this.logs.length === 0
                ? html`<div class="log-entry">No events recorded yet.</div>`
                : this.logs.map(
                    (entry) => html`
                      <div class="log-entry">
                        <span class="log-time">[${entry.timestamp}]</span>
                        <span class="log-level ${entry.level}">${entry.level}</span>
                        <span>${entry.summary}</span>
                        ${entry.detail ? html`<span>— ${entry.detail}</span>` : nothing}
                      </div>
                    `
                  )}
            </aside>
          `
        : nothing}

      <div class="cockpit-deck">
        ${this.renderOperatorSidebar()}

        <main class="cockpit-canvas">
          ${this.renderOperatorConsole(activeTurn)}
          ${this.renderCanvasNavBar()}
          <div class="canvas-stage-body">
            ${activeTurn ? this.renderActiveCanvasTurn(activeTurn) : this.renderQuickProbes()}
          </div>
        </main>
      </div>

      <form class="cockpit-prompt-bar" @submit=${this.handlePromptSubmit}>
        <span class="prompt-prefix">aida&gt;</span>
        <input
          type="text"
          class="prompt-input"
          aria-label="Diagnostic query or command prompt"
          placeholder="Inspect processes, ports, filesystems, or ask AIDA to run a command..."
          .value=${this.promptInput}
          ?disabled=${this.isStreaming}
          @input=${(e: Event) => {
            this.promptInput = (e.target as HTMLInputElement).value;
          }}
        />
        <button
          type="submit"
          class="cyber-btn accent"
          aria-label="Run query"
          ?disabled=${this.isStreaming || !this.promptInput.trim()}
        >
          <span class="material-symbols-outlined" aria-hidden="true" style="font-size: 16px;">${this.isStreaming ? 'sync' : 'play_arrow'}</span>
          ${this.isStreaming ? 'RUNNING...' : 'RUN'}
        </button>
      </form>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'aida-cockpit': AidaCockpit;
  }
}
