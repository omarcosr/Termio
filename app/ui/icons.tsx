import { Icon } from "@tarve/core";
import type { SvgNode } from "@tarve/core";

// Lucide geometry (ISC licence), drawn at one stroke width everywhere.
const p = (d: string): SvgNode => ["path", { d }];
const nodes = {
  server: [["rect", { x: 2, y: 2, width: 20, height: 8, rx: 2 }], ["rect", { x: 2, y: 14, width: 20, height: 8, rx: 2 }], p("M6 6h.01"), p("M6 18h.01")],
  key: [p("m15.5 7.5 2.3 2.3a1 1 0 0 0 1.4 0l2.1-2.1a1 1 0 0 0 0-1.4L19 4"), p("m21 2-9.6 9.6"), ["circle", { cx: 7.5, cy: 15.5, r: 5.5 }]],
  shield: [p("M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"), p("m9 12 2 2 4-4")],
  cloud: [p("M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9Z")],
  terminal: [p("m4 17 6-6-6-6"), p("M12 19h8")],
  plus: [p("M5 12h14"), p("M12 5v14")],
  search: [["circle", { cx: 11, cy: 11, r: 8 }], p("m21 21-4.3-4.3")],
  lock: [["rect", { x: 3, y: 11, width: 18, height: 11, rx: 2 }], p("M7 11V7a5 5 0 0 1 10 0v4")],
  x: [p("M18 6 6 18"), p("m6 6 12 12")],
  copy: [["rect", { x: 8, y: 8, width: 14, height: 14, rx: 2 }], p("M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2")],
  refresh: [p("M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"), p("M21 3v5h-5"), p("M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"), p("M8 16H3v5")],
  trash: [p("M3 6h18"), p("M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"), p("M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2")],
  check: [p("M20 6 9 17l-5-5")],
  alert: [p("m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"), p("M12 9v4"), p("M12 17h.01")],
  route: [["circle", { cx: 6, cy: 19, r: 3 }], p("M9 19h8.5a3.5 3.5 0 0 0 0-7h-11a3.5 3.5 0 0 1 0-7H15"), ["circle", { cx: 18, cy: 5, r: 3 }]],
  pencil: [p("M21.17 6.81a1 1 0 0 0-3.99-3.99L3.84 16.17a2 2 0 0 0-.5.83l-1.32 4.35a.5.5 0 0 0 .62.62l4.35-1.32a2 2 0 0 0 .83-.5z")],
  play: [p("M6 3l14 9-14 9V3z")],
  folder: [p("M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z")],
  folderPlus: [p("M12 10v6"), p("M9 13h6"), p("M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z")],
  file: [p("M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"), p("M14 2v4a2 2 0 0 0 2 2h4")],
  code: [p("m16 18 6-6-6-6"), p("m8 6-6 6 6 6")],
  activity: [p("M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.49 12H2")],
  columns: [["rect", { x: 3, y: 3, width: 18, height: 18, rx: 2 }], p("M12 3v18")],
  rows: [["rect", { x: 3, y: 3, width: 18, height: 18, rx: 2 }], p("M3 12h18")],
  upload: [p("M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"), p("m17 8-5-5-5 5"), p("M12 3v12")],
  download: [p("M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"), p("m7 10 5 5 5-5"), p("M12 15V3")],
  up: [p("m5 12 7-7 7 7"), p("M12 19V5")],
  broadcast: [p("M4.9 19.1C1 15.2 1 8.8 4.9 4.9"), p("M7.8 16.2c-2.3-2.3-2.3-6.1 0-8.5"), ["circle", { cx: 12, cy: 12, r: 2 }], p("M16.2 7.8c2.3 2.3 2.3 6.1 0 8.5"), p("M19.1 4.9C23 8.8 23 15.1 19.1 19")],
} satisfies Record<string, readonly SvgNode[]>;

export type IconId = keyof typeof nodes;

export function Glyph({ name, size = 16, color, strokeWidth = 1.75 }: { name: IconId; size?: number; color?: string; strokeWidth?: number }) {
  return <Icon iconNode={nodes[name]} size={size} color={color} strokeWidth={strokeWidth} />;
}
