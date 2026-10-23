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

import { html, css, nothing, type PropertyValues } from "lit";
import { customElement, state } from "lit/decorators.js";
import { z } from "zod";
import {
  AmbientLight,
  BoxGeometry,
  BufferAttribute,
  BufferGeometry,
  CircleGeometry,
  CylinderGeometry,
  DoubleSide,
  EdgesGeometry,
  FogExp2,
  GridHelper,
  Group,
  IcosahedronGeometry,
  Line,
  LineBasicMaterial,
  LineSegments,
  Mesh,
  MeshBasicMaterial,
  MeshStandardMaterial,
  OctahedronGeometry,
  PerspectiveCamera,
  PointLight,
  Points,
  PointsMaterial,
  Raycaster,
  RingGeometry,
  Scene,
  SphereGeometry,
  TorusGeometry,
  Vector2,
  Vector3,
  WebGLRenderer,
} from "three";
import { type LitComponentApi } from "@a2ui/lit/v0_9";
import { CommonSchemas } from "@a2ui/web_core/v0_9";
import { AidaFlexibleActionSchema } from "./action-helper.js";
import {
  AidaCatalogElement,
  aidaCatalogBaseStyles,
  handleInteractiveKeydown,
} from "./base.js";

export const AidaScene3DNodeSchema = z.object({
  id: z.string(),
  label: z.string(),
  value: z.number(),
  max: z.number().optional(),
  unit: z.string().optional(),
  status: z.enum(["nominal", "warning", "critical"]).optional(),
  group: z.string().optional(),
  actionName: z.string().optional(),
  actionContext: z.record(z.string(), z.unknown()).optional(),
  action: AidaFlexibleActionSchema.optional(),
});

export const AidaScene3DLinkSchema = z.object({
  source: z.string(),
  target: z.string(),
  label: z.string().optional(),
  bandwidth: z.number().optional(),
});

export const AidaScene3DSchema = z.object({
  title: CommonSchemas.DynamicString.optional(),
  subtitle: CommonSchemas.DynamicString.optional(),
  mode: z
    .enum(["topology", "cores", "storage", "threat_radar"])
    .default("topology"),
  nodes: z.array(AidaScene3DNodeSchema),
  links: z.array(AidaScene3DLinkSchema).optional(),
  actionName: z.string().optional(),
  actionContext: z.record(z.string(), z.unknown()).optional(),
  action: AidaFlexibleActionSchema.optional(),
  weight: z.number().optional(),
});

export type AidaScene3DNode = z.infer<typeof AidaScene3DNodeSchema>;
export type AidaScene3DLink = z.infer<typeof AidaScene3DLinkSchema>;
export type AidaScene3DProps = z.infer<typeof AidaScene3DSchema>;
type SceneMode = "topology" | "cores" | "storage" | "threat_radar";

interface LinkParticle {
  mesh: Mesh;
  start: Vector3;
  end: Vector3;
  progress: number;
  speed: number;
}

interface InteractiveNodeRecord {
  data: AidaScene3DNode;
  mesh: Mesh;
  halo: LineSegments;
  basePosition: Vector3;
  baseScale: number;
  phase: number;
  isTower: boolean;
}

const STATUS_COLORS: Record<"nominal" | "warning" | "critical", number> = {
  nominal: 0x00f0ff,
  warning: 0xffb800,
  critical: 0xff2a54,
};

@customElement("aida-scene-3d")
export class AidaScene3DElement extends AidaCatalogElement<
  typeof AidaScene3DApi
> {
  static tagName = "aida-scene-3d";
  protected override readonly api = AidaScene3DApi;

  @state() private accessor autoOrbit = true;
  @state() private accessor hoveredNode: AidaScene3DNode | null = null;
  @state() private accessor selectedNode: AidaScene3DNode | null = null;

  private renderer: WebGLRenderer | null = null;
  private scene: Scene | null = null;
  private camera: PerspectiveCamera | null = null;
  private animationFrameId: number | null = null;
  private resizeObserver: ResizeObserver | null = null;

  private rootGroup: Group | null = null;
  private coreMesh: Mesh | null = null;
  private gyroRingA: Mesh | null = null;
  private gyroRingB: Mesh | null = null;
  private radarSweepMesh: Mesh | null = null;
  private dustPoints: Points | null = null;
  private interactiveNodes: InteractiveNodeRecord[] = [];
  private linkParticles: LinkParticle[] = [];

  private raycaster = new Raycaster();
  private pointerNDC = new Vector2(-999, -999);
  private isDragging = false;
  private dragMoved = false;
  private pointerDownPos = { x: 0, y: 0 };
  private prevPointerPos = { x: 0, y: 0 };

  private camTheta = 0.65;
  private camPhi = 1.05;
  private camRadius = 10.5;

  private lastSceneSignature = "";

  static override styles = [
    aidaCatalogBaseStyles,
    css`
      .holo-wrapper {
        padding: 0;
        background:
          radial-gradient(
            circle at 50% 50%,
            var(--aida-glow, rgba(0, 240, 255, 0.09)) 0%,
            transparent 78%
          ),
          var(--aida-bg-panel, #0a1026);
      }

      .holo-header {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        justify-content: space-between;
        gap: 8px;
        padding: 10px 14px;
        border-bottom: 1px solid var(--aida-border, #3b4cca);
        background: var(--aida-bg-elevated, #111a3a);
        z-index: 3;
        position: relative;
      }

      .holo-title-block {
        display: flex;
        flex-direction: column;
        gap: 2px;
      }

      .holo-controls {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: 6px;
      }

      .hud-btn {
        appearance: none;
        background: var(--aida-bg-panel, #0a1026);
        border: 1px solid var(--aida-border, #3b4cca);
        color: var(--aida-text-muted, #7c93c3);
        font-family: inherit;
        font-size: 0.68rem;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        padding: 4px 8px;
        cursor: pointer;
        transition: all 0.15s ease;
      }

      .hud-btn:hover {
        color: var(--aida-text, #e2f1ff);
        background: var(--aida-glow, rgba(0, 240, 255, 0.16));
      }

      .hud-btn.active {
        color: var(--aida-bg-panel, #0a1026);
        background: var(--aida-accent, #00f0ff);
        border-color: var(--aida-accent, #00f0ff);
        font-weight: 700;
      }

      .viewport-stage {
        position: relative;
        width: 100%;
        height: 250px;
        cursor: grab;
        user-select: none;
        touch-action: none;
      }

      .viewport-stage:active {
        cursor: grabbing;
      }

      canvas {
        display: block;
        width: 100%;
        height: 100%;
      }

      .hud-readout-card {
        position: absolute;
        bottom: 8px;
        left: 10px;
        right: 10px;
        background: var(--aida-bg-elevated, #111a3a);
        border: 1px solid var(--aida-accent, #00f0ff);
        box-shadow: 0 0 14px var(--aida-glow, rgba(0, 240, 255, 0.25));
        padding: 5px 10px;
        z-index: 2;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 10px;
        font-size: 0.74rem;
        cursor: pointer;
      }

      .hud-readout-card.status-warning {
        border-color: var(--aida-warning, #ffb000);
      }

      .hud-readout-card.status-critical {
        border-color: var(--aida-critical, #ff2a6d);
      }

      .readout-label {
        font-family: var(--aida-font-display, "Orbitron", sans-serif);
        font-size: 0.76rem;
        font-weight: 700;
        color: var(--aida-text, #e2f1ff);
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }

      .readout-val {
        font-weight: 700;
        color: var(--aida-accent, #00f0ff);
        white-space: nowrap;
      }

      .node-strip {
        display: flex;
        flex-wrap: wrap;
        gap: 6px;
        padding: 8px 12px;
        border-top: 1px solid var(--aida-border, #3b4cca);
        background: var(--aida-bg-elevated, #111a3a);
      }

      .node-chip {
        appearance: none;
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background: var(--aida-bg-panel, #0a1026);
        border: 1px solid var(--aida-border, #3b4cca);
        color: var(--aida-text, #e2f1ff);
        font-family: inherit;
        font-size: 0.7rem;
        padding: 3px 9px;
        cursor: pointer;
        transition: all 0.15s ease;
      }

      .node-chip:hover,
      .node-chip.active {
        background: var(--aida-glow, rgba(0, 240, 255, 0.18));
        border-color: var(--aida-accent, #00f0ff);
      }

      .chip-dot {
        width: 6px;
        height: 6px;
        border-radius: 50%;
        background: var(--aida-nominal, #00ff88);
        box-shadow: 0 0 6px var(--aida-nominal, #00ff88);
      }
      .chip-dot.warning {
        background: var(--aida-warning, #ffb000);
        box-shadow: 0 0 6px var(--aida-warning, #ffb000);
      }
      .chip-dot.critical {
        background: var(--aida-critical, #ff2a6d);
        box-shadow: 0 0 6px var(--aida-critical, #ff2a6d);
      }
    `,
  ];

  override connectedCallback(): void {
    super.connectedCallback();
    if (this.hasUpdated && !this.renderer) {
      this.initThreeScene();
      this.rebuildHologramIfNeeded(true);
    }
  }

  override firstUpdated(): void {
    this.initThreeScene();
    this.rebuildHologramIfNeeded(true);
  }

  override updated(changedProperties: PropertyValues): void {
    super.updated(changedProperties);
    const onlyInternalStateChanged =
      changedProperties.size > 0 &&
      Array.from(changedProperties.keys()).every(
        (k) => k === "hoveredNode" || k === "selectedNode" || k === "autoOrbit"
      );
    if (!onlyInternalStateChanged) {
      this.rebuildHologramIfNeeded(false);
    }
  }

  override disconnectedCallback(): void {
    super.disconnectedCallback();
    if (this.animationFrameId !== null) {
      cancelAnimationFrame(this.animationFrameId);
      this.animationFrameId = null;
    }
    if (this.resizeObserver) {
      this.resizeObserver.disconnect();
      this.resizeObserver = null;
    }
    this.disposeSceneObjects();
    if (this.dustPoints) {
      this.dustPoints.geometry?.dispose();
      if (Array.isArray(this.dustPoints.material)) {
        this.dustPoints.material.forEach((m) => m.dispose());
      } else {
        this.dustPoints.material?.dispose();
      }
      this.dustPoints = null;
    }
    if (this.renderer) {
      this.renderer.forceContextLoss();
      this.renderer.dispose();
      this.renderer = null;
    }
    this.scene = null;
    this.camera = null;
  }

  private initThreeScene(): void {
    const stage = this.renderRoot.querySelector(
      ".viewport-stage"
    ) as HTMLElement | null;
    const canvas = this.renderRoot.querySelector(
      "canvas"
    ) as HTMLCanvasElement | null;
    if (!stage || !canvas) {
      return;
    }

    const width = stage.clientWidth || 640;
    const height = stage.clientHeight || 360;

    this.scene = new Scene();
    this.scene.fog = new FogExp2(0x030914, 0.042);

    this.camera = new PerspectiveCamera(48, width / height, 0.1, 120);
    this.updateCameraPosition();

    this.renderer = new WebGLRenderer({
      canvas,
      antialias: true,
      alpha: true,
      powerPreference: "high-performance",
    });
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    this.renderer.setSize(width, height, false);
    this.renderer.setClearColor(0x000000, 0);

    const ambientLight = new AmbientLight(0x88e8ff, 0.85);
    this.scene.add(ambientLight);

    const keyLight = new PointLight(0x00f0ff, 2.6, 45);
    keyLight.position.set(8, 12, 10);
    this.scene.add(keyLight);

    const rimLight = new PointLight(0xff00a0, 1.8, 40);
    rimLight.position.set(-10, -6, -8);
    this.scene.add(rimLight);

    this.rootGroup = new Group();
    this.scene.add(this.rootGroup);

    this.createAmbientDust();

    this.resizeObserver = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const w = Math.max(entry.contentRect.width, 100);
        const h = Math.max(entry.contentRect.height, 100);
        if (this.camera && this.renderer) {
          this.camera.aspect = w / h;
          this.camera.updateProjectionMatrix();
          this.renderer.setSize(w, h, false);
        }
      }
    });
    this.resizeObserver.observe(stage);

    const animate = (timestamp: number) => {
      this.animationFrameId = requestAnimationFrame(animate);
      this.stepAnimation(timestamp * 0.001);
      if (this.renderer && this.scene && this.camera) {
        this.renderer.render(this.scene, this.camera);
      }
    };
    this.animationFrameId = requestAnimationFrame(animate);
  }

  private createAmbientDust(): void {
    if (!this.scene) return;
    const count = 200;
    const positions = new Float32Array(count * 3);
    for (let i = 0; i < count; i++) {
      positions[i * 3] = (Math.random() - 0.5) * 26;
      positions[i * 3 + 1] = (Math.random() - 0.5) * 16;
      positions[i * 3 + 2] = (Math.random() - 0.5) * 26;
    }
    const geo = new BufferGeometry();
    geo.setAttribute("position", new BufferAttribute(positions, 3));
    const mat = new PointsMaterial({
      color: 0x00f0ff,
      size: 0.08,
      transparent: true,
      opacity: 0.45,
    });
    this.dustPoints = new Points(geo, mat);
    this.scene.add(this.dustPoints);
  }

  private disposeSceneObjects(): void {
    if (!this.rootGroup) return;
    this.rootGroup.traverse((obj) => {
      if (obj instanceof Mesh || obj instanceof Line || obj instanceof Points) {
        obj.geometry?.dispose();
        if (Array.isArray(obj.material)) {
          obj.material.forEach((m) => m.dispose());
        } else {
          obj.material?.dispose();
        }
      }
    });
    this.rootGroup.clear();
    this.interactiveNodes = [];
    this.linkParticles = [];
    this.coreMesh = null;
    this.gyroRingA = null;
    this.gyroRingB = null;
    this.radarSweepMesh = null;
  }

  private rebuildHologramIfNeeded(force: boolean): void {
    if (!this.rootGroup) return;
    const props = this.controller?.props as AidaScene3DProps | undefined;
    if (!props) return;

    const mode: SceneMode = props.mode ?? "topology";
    const sig = JSON.stringify({
      mode,
      nodes: props.nodes,
      links: props.links,
    });
    if (!force && sig === this.lastSceneSignature) {
      return;
    }
    this.lastSceneSignature = sig;

    this.disposeSceneObjects();

    const nodes = Array.isArray(props.nodes) ? props.nodes : [];
    const links = Array.isArray(props.links) ? props.links : [];

    if (mode === "cores" || mode === "storage") {
      this.buildIsometricTowersScene(mode, nodes);
    } else {
      this.buildOrbitalTopologyScene(mode, nodes, links);
    }
  }

  private buildOrbitalTopologyScene(
    mode: SceneMode,
    nodes: AidaScene3DNode[],
    links: AidaScene3DLink[]
  ): void {
    if (!this.rootGroup) return;

    const coreGeo =
      mode === "threat_radar"
        ? new OctahedronGeometry(0.95, 1)
        : new IcosahedronGeometry(0.95, 1);
    const coreMat = new MeshBasicMaterial({
      color: mode === "threat_radar" ? 0xff2a54 : 0x00f0ff,
      wireframe: true,
      transparent: true,
      opacity: 0.78,
    });
    this.coreMesh = new Mesh(coreGeo, coreMat);
    this.rootGroup.add(this.coreMesh);

    const ringGeoA = new TorusGeometry(1.45, 0.018, 12, 64);
    const ringMatA = new MeshBasicMaterial({
      color: 0x00f0ff,
      transparent: true,
      opacity: 0.55,
    });
    this.gyroRingA = new Mesh(ringGeoA, ringMatA);
    this.gyroRingA.rotation.x = Math.PI / 2.4;
    this.rootGroup.add(this.gyroRingA);

    const ringGeoB = new TorusGeometry(1.85, 0.015, 12, 64);
    const ringMatB = new MeshBasicMaterial({
      color: mode === "threat_radar" ? 0xffb800 : 0x00ff9d,
      transparent: true,
      opacity: 0.4,
    });
    this.gyroRingB = new Mesh(ringGeoB, ringMatB);
    this.gyroRingB.rotation.y = Math.PI / 3;
    this.rootGroup.add(this.gyroRingB);

    if (mode === "threat_radar") {
      for (const r of [2.4, 3.8, 5.2]) {
        const polarGeo = new RingGeometry(r - 0.02, r + 0.02, 64);
        polarGeo.rotateX(-Math.PI / 2);
        const polarMat = new MeshBasicMaterial({
          color: 0xff2a54,
          side: DoubleSide,
          transparent: true,
          opacity: 0.28,
        });
        this.rootGroup.add(new Mesh(polarGeo, polarMat));
      }

      const sweepGeo = new CircleGeometry(5.2, 32, 0, Math.PI / 4);
      sweepGeo.rotateX(-Math.PI / 2);
      const sweepMat = new MeshBasicMaterial({
        color: 0xff2a54,
        side: DoubleSide,
        transparent: true,
        opacity: 0.18,
      });
      this.radarSweepMesh = new Mesh(sweepGeo, sweepMat);
      this.radarSweepMesh.position.y = -0.02;
      this.rootGroup.add(this.radarSweepMesh);
    }

    const nodePositions = new Map<string, Vector3>();
    const total = Math.max(nodes.length, 1);

    nodes.forEach((node, idx) => {
      const status = node.status ?? "nominal";
      const colorHex = STATUS_COLORS[status];
      const maxVal = node.max && node.max > 0 ? node.max : 100;
      const ratio = Math.min(Math.max(node.value / maxVal, 0.12), 1.4);

      const angle = (idx / total) * Math.PI * 2;
      const shellRadius =
        mode === "threat_radar"
          ? 2.5 + (idx % 3) * 1.15
          : 3.6 + (idx % 2) * 0.95;
      const elevation =
        mode === "threat_radar"
          ? ((idx % 3) - 1) * 0.45
          : Math.sin(angle * 2 + idx) * 1.35;

      const pos = new Vector3(
        Math.cos(angle) * shellRadius,
        elevation,
        Math.sin(angle) * shellRadius
      );
      nodePositions.set(node.id, pos);

      const baseScale = 0.28 + ratio * 0.34;
      const nodeGeo =
        status === "critical"
          ? new OctahedronGeometry(1, 0)
          : new IcosahedronGeometry(1, 0);

      const nodeMat = new MeshStandardMaterial({
        color: colorHex,
        emissive: colorHex,
        emissiveIntensity: 0.48,
        roughness: 0.2,
        metalness: 0.75,
        transparent: true,
        opacity: 0.92,
      });

      const mesh = new Mesh(nodeGeo, nodeMat);
      mesh.position.copy(pos);
      mesh.scale.setScalar(baseScale);
      mesh.userData = { node };
      this.rootGroup!.add(mesh);

      const edgesGeo = new EdgesGeometry(nodeGeo);
      const edgesMat = new LineBasicMaterial({
        color: 0xffffff,
        transparent: true,
        opacity: 0.55,
      });
      const halo = new LineSegments(edgesGeo, edgesMat);
      halo.position.copy(pos);
      halo.scale.setScalar(baseScale * 1.28);
      this.rootGroup!.add(halo);

      this.interactiveNodes.push({
        data: node,
        mesh,
        halo,
        basePosition: pos.clone(),
        baseScale,
        phase: idx * 0.7,
        isTower: false,
      });
    });

    const effectiveLinks: Array<{ start: Vector3; end: Vector3 }> = [];
    if (links.length > 0) {
      for (const link of links) {
        const s = nodePositions.get(link.source);
        const t = nodePositions.get(link.target);
        if (s && t) {
          effectiveLinks.push({ start: s, end: t });
        }
      }
    }
    for (const [, pos] of nodePositions) {
      effectiveLinks.push({ start: new Vector3(0, 0, 0), end: pos });
    }

    const particleGeo = new SphereGeometry(0.065, 8, 8);
    effectiveLinks.forEach((seg, idx) => {
      const lineGeo = new BufferGeometry().setFromPoints([seg.start, seg.end]);
      const lineMat = new LineBasicMaterial({
        color: 0x00f0ff,
        transparent: true,
        opacity: 0.32,
      });
      const line = new Line(lineGeo, lineMat);
      this.rootGroup!.add(line);

      const pMat = new MeshBasicMaterial({
        color: idx % 2 === 0 ? 0x00ff9d : 0x00f0ff,
      });
      const pMesh = new Mesh(particleGeo, pMat);
      this.rootGroup!.add(pMesh);
      this.linkParticles.push({
        mesh: pMesh,
        start: seg.start,
        end: seg.end,
        progress: (idx * 0.19) % 1,
        speed: 0.35 + (idx % 4) * 0.12,
      });
    });
  }

  private buildIsometricTowersScene(
    mode: SceneMode,
    nodes: AidaScene3DNode[]
  ): void {
    if (!this.rootGroup) return;

    const grid = new GridHelper(9, 18, 0x00f0ff, 0x0c3554);
    grid.position.y = -1.6;
    this.rootGroup.add(grid);

    const floorRingGeo = new TorusGeometry(4.8, 0.025, 12, 72);
    floorRingGeo.rotateX(Math.PI / 2);
    const floorRingMat = new MeshBasicMaterial({
      color: 0x00f0ff,
      transparent: true,
      opacity: 0.5,
    });
    this.gyroRingA = new Mesh(floorRingGeo, floorRingMat);
    this.gyroRingA.position.y = -1.55;
    this.rootGroup.add(this.gyroRingA);

    const count = Math.max(nodes.length, 1);
    const cols = Math.ceil(Math.sqrt(count));
    const rows = Math.ceil(count / cols);
    const spacing = 1.65;

    nodes.forEach((node, idx) => {
      const col = idx % cols;
      const row = Math.floor(idx / cols);
      const x = (col - (cols - 1) / 2) * spacing;
      const z = (row - (rows - 1) / 2) * spacing;

      const status = node.status ?? "nominal";
      const colorHex = STATUS_COLORS[status];
      const maxVal = node.max && node.max > 0 ? node.max : 100;
      const ratio = Math.min(Math.max(node.value / maxVal, 0.08), 1.0);
      const towerHeight = 0.45 + ratio * 3.2;

      const towerGeo =
        mode === "cores"
          ? new CylinderGeometry(0.44, 0.44, 1, 6)
          : new BoxGeometry(0.75, 1, 0.75);

      const towerMat = new MeshStandardMaterial({
        color: colorHex,
        emissive: colorHex,
        emissiveIntensity: 0.42,
        roughness: 0.22,
        metalness: 0.7,
        transparent: true,
        opacity: 0.9,
      });

      const basePos = new Vector3(x, -1.6 + towerHeight / 2, z);
      const mesh = new Mesh(towerGeo, towerMat);
      mesh.position.copy(basePos);
      mesh.scale.set(1, towerHeight, 1);
      mesh.userData = { node };
      this.rootGroup!.add(mesh);

      const edgesGeo = new EdgesGeometry(towerGeo);
      const edgesMat = new LineBasicMaterial({
        color: 0xffffff,
        transparent: true,
        opacity: 0.65,
      });
      const halo = new LineSegments(edgesGeo, edgesMat);
      halo.position.copy(basePos);
      halo.scale.set(1.06, towerHeight * 1.02, 1.06);
      this.rootGroup!.add(halo);

      this.interactiveNodes.push({
        data: node,
        mesh,
        halo,
        basePosition: basePos,
        baseScale: towerHeight,
        phase: idx * 0.55,
        isTower: true,
      });
    });
  }

  private stepAnimation(timeSec: number): void {
    if (!this.rootGroup || !this.camera) return;

    if (this.autoOrbit && !this.isDragging) {
      this.camTheta += 0.0045;
      this.updateCameraPosition();
    }

    if (this.coreMesh) {
      this.coreMesh.rotation.y = timeSec * 0.55;
      this.coreMesh.rotation.x = timeSec * 0.32;
    }

    if (this.gyroRingA) {
      this.gyroRingA.rotation.z = timeSec * 0.45;
    }

    if (this.gyroRingB) {
      this.gyroRingB.rotation.x = timeSec * 0.6;
      this.gyroRingB.rotation.y = timeSec * 0.35;
    }

    if (this.radarSweepMesh) {
      this.radarSweepMesh.rotation.y = -timeSec * 1.4;
    }

    if (this.dustPoints) {
      this.dustPoints.rotation.y = timeSec * 0.04;
    }

    for (const rec of this.interactiveNodes) {
      const isHovered = this.hoveredNode?.id === rec.data.id;
      const isSelected = this.selectedNode?.id === rec.data.id;
      const pulse = 1 + Math.sin(timeSec * 2.8 + rec.phase) * 0.06;
      const boost = isHovered || isSelected ? 1.24 : 1.0;

      if (rec.isTower) {
        const dynamicH = rec.baseScale * pulse * (isHovered ? 1.08 : 1.0);
        rec.mesh.scale.set(boost, dynamicH, boost);
        rec.mesh.position.y = -1.6 + dynamicH / 2;
        rec.halo.scale.set(boost * 1.06, dynamicH * 1.02, boost * 1.06);
        rec.halo.position.y = rec.mesh.position.y;
      } else {
        rec.mesh.rotation.y = timeSec * 0.9 + rec.phase;
        rec.mesh.rotation.x = timeSec * 0.5 + rec.phase;
        rec.halo.rotation.copy(rec.mesh.rotation);
        rec.mesh.scale.setScalar(rec.baseScale * pulse * boost);
        rec.halo.scale.setScalar(rec.baseScale * pulse * boost * 1.28);
      }
    }

    for (const lp of this.linkParticles) {
      lp.progress = (lp.progress + 0.008 * lp.speed) % 1;
      lp.mesh.position.lerpVectors(lp.start, lp.end, lp.progress);
    }
  }

  private updateCameraPosition(): void {
    if (!this.camera) return;
    const phi = Math.min(Math.max(this.camPhi, 0.25), Math.PI - 0.25);
    const x = this.camRadius * Math.sin(phi) * Math.sin(this.camTheta);
    const y = this.camRadius * Math.cos(phi);
    const z = this.camRadius * Math.sin(phi) * Math.cos(this.camTheta);
    this.camera.position.set(x, y, z);
    this.camera.lookAt(0, 0, 0);
  }

  private handlePointerDown(e: PointerEvent): void {
    this.isDragging = true;
    this.dragMoved = false;
    this.pointerDownPos = { x: e.clientX, y: e.clientY };
    this.prevPointerPos = { x: e.clientX, y: e.clientY };
    (e.currentTarget as HTMLElement)?.setPointerCapture?.(e.pointerId);
  }

  private handlePointerMove(e: PointerEvent): void {
    const stage = e.currentTarget as HTMLElement;
    const rect = stage.getBoundingClientRect();
    this.pointerNDC.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
    this.pointerNDC.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;

    if (this.isDragging) {
      const dx = e.clientX - this.prevPointerPos.x;
      const dy = e.clientY - this.prevPointerPos.y;
      if (
        Math.abs(e.clientX - this.pointerDownPos.x) > 4 ||
        Math.abs(e.clientY - this.pointerDownPos.y) > 4
      ) {
        this.dragMoved = true;
      }
      this.camTheta -= dx * 0.0075;
      this.camPhi -= dy * 0.0075;
      this.prevPointerPos = { x: e.clientX, y: e.clientY };
      this.updateCameraPosition();
      return;
    }

    this.performRaycastHover();
  }

  private handlePointerUp(e: PointerEvent): void {
    const wasClick = !this.dragMoved;
    this.isDragging = false;
    (e.currentTarget as HTMLElement)?.releasePointerCapture?.(e.pointerId);

    if (wasClick) {
      const hit = this.performRaycastHover();
      if (hit) {
        this.triggerNodeAction(hit);
      }
    }
  }

  private handleWheel(e: WheelEvent): void {
    e.preventDefault();
    this.camRadius = Math.min(
      Math.max(this.camRadius + e.deltaY * 0.006, 4.5),
      20
    );
    this.updateCameraPosition();
  }

  private performRaycastHover(): AidaScene3DNode | null {
    if (!this.camera || this.interactiveNodes.length === 0) {
      return null;
    }
    this.raycaster.setFromCamera(this.pointerNDC, this.camera);
    const meshes = this.interactiveNodes.map((n) => n.mesh);
    const hits = this.raycaster.intersectObjects(meshes, false);
    const nextNode =
      hits.length > 0
        ? ((hits[0].object.userData?.node as AidaScene3DNode | undefined) ??
          null)
        : null;
    if (this.hoveredNode?.id !== nextNode?.id) {
      this.hoveredNode = nextNode;
    }
    return nextNode;
  }

  private triggerNodeAction(node: AidaScene3DNode): void {
    this.selectedNode = node;
    this.dispatchCatalogAction(
      "inspect_node",
      {
        nodeId: node.id,
        label: node.label,
        value: node.value,
        unit: node.unit ?? "",
        status: node.status ?? "nominal",
      },
      node
    );
  }

  private resetCamera(): void {
    this.camTheta = 0.65;
    this.camPhi = 1.05;
    this.camRadius = 10.5;
    this.updateCameraPosition();
  }

  override render() {
    const props = this.controller?.props as AidaScene3DProps | undefined;
    if (!props) {
      return nothing;
    }

    const nodes = Array.isArray(props.nodes) ? props.nodes : [];
    const activeReadout = this.hoveredNode ?? this.selectedNode ?? null;

    return html`
      <div class="holo-wrapper">
        <div class="holo-header">
          <div class="holo-title-block">
            <h4 class="holo-title">
              ${props.title ? String(props.title) : "Topology"}
            </h4>
            ${props.subtitle
              ? html`<p class="holo-subtitle">${String(props.subtitle)}</p>`
              : nothing}
          </div>

          <div class="holo-controls">
            <button
              type="button"
              class="hud-btn ${this.autoOrbit ? "active" : ""}"
              @click=${() => {
                this.autoOrbit = !this.autoOrbit;
              }}
            >
              Orbit
            </button>
            <button
              type="button"
              class="hud-btn"
              @click=${() => this.resetCamera()}
            >
              Reset
            </button>
          </div>
        </div>

        <div
          class="viewport-stage"
          @pointerdown=${(e: PointerEvent) => this.handlePointerDown(e)}
          @pointermove=${(e: PointerEvent) => this.handlePointerMove(e)}
          @pointerup=${(e: PointerEvent) => this.handlePointerUp(e)}
          @pointerleave=${() => {
            if (this.hoveredNode !== null) {
              this.hoveredNode = null;
            }
          }}
          @wheel=${(e: WheelEvent) => this.handleWheel(e)}
        >
          <canvas></canvas>

          ${activeReadout
            ? html`
                <div
                  class="hud-readout-card status-${activeReadout.status ??
                  "nominal"}"
                  tabindex="0"
                  role="button"
                  aria-label="Inspect ${activeReadout.label}: ${activeReadout.value}${activeReadout.unit ?? ""}"
                  @pointerdown=${(e: PointerEvent) => e.stopPropagation()}
                  @click=${(e: Event) => {
                    e.stopPropagation();
                    this.triggerNodeAction(activeReadout);
                  }}
                  @keydown=${(e: KeyboardEvent) =>
                    handleInteractiveKeydown(e, () =>
                      this.triggerNodeAction(activeReadout)
                    )}
                >
                  <span class="readout-label">${activeReadout.label}</span>
                  <span class="readout-val">
                    ${activeReadout.value}${activeReadout.unit
                      ? ` ${activeReadout.unit}`
                      : ""}
                  </span>
                </div>
              `
            : nothing}
        </div>

        ${nodes.length > 0
          ? html`
              <div class="node-strip">
                ${nodes.map(
                  (node) => html`
                    <button
                      type="button"
                      class="node-chip ${activeReadout?.id === node.id
                        ? "active"
                        : ""}"
                      @pointerenter=${() => {
                        this.hoveredNode = node;
                      }}
                      @pointerleave=${() => {
                        if (this.hoveredNode?.id === node.id) {
                          this.hoveredNode = null;
                        }
                      }}
                      @click=${() => this.triggerNodeAction(node)}
                    >
                      <span
                        class="chip-dot ${node.status ?? "nominal"}"
                      ></span>
                      <span>${node.label}</span>
                      <strong>${node.value}${node.unit ?? ""}</strong>
                    </button>
                  `
                )}
              </div>
            `
          : nothing}
      </div>
    `;
  }
}

export const AidaScene3DApi: LitComponentApi = {
  name: "Scene3D",
  schema: AidaScene3DSchema,
  tagName: "aida-scene-3d",
  element: AidaScene3DElement,
};
