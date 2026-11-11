// Termio's visual system: a graphite instrument panel with one amber signal colour.
// Amber marks what is live or actionable (the active tab, the primary action, a connected
// session); everything else stays in the greys so the terminal text is the brightest thing.

const graphite = {
  canvas: "#0d0f12",
  panel: "#131619",
  raised: "#1a1d22",
  hover: "#20242a",
  line: "#252a31",
  lineStrong: "#323843",
  text: "#e7e9ec",
  muted: "#9aa1ab",
  faint: "#6b727d",
  accent: "#f2a33a",
  accentHover: "#f7b55c",
  accentInk: "#1b1203",
  accentSoft: "#f2a33a1f",
  ok: "#3fd08a",
  danger: "#f0595e",
  dangerSoft: "#f0595e1a",
  warn: "#e8c547",
  /** The terminal's own background, so the area around the grid matches it. */
  terminal: "#101216",
};

export type Palette = typeof graphite;

/** The whole app follows the terminal colour scheme chosen in Settings. */
const palettes: Record<string, Palette> = {
  termio: graphite,
  dracula: { ...graphite, canvas: "#21222c", panel: "#282a36", raised: "#313341", hover: "#3a3c4e", line: "#3b3d4f", lineStrong: "#4a4d63", text: "#f8f8f2", muted: "#b8bad0", faint: "#7c7f9c", accent: "#bd93f9", accentHover: "#cba6fb", accentInk: "#1e1430", accentSoft: "#bd93f924", ok: "#50fa7b", danger: "#ff5555", dangerSoft: "#ff55551f", terminal: "#282a36" },
  solarized: { ...graphite, canvas: "#00212b", panel: "#002b36", raised: "#073642", hover: "#0b404e", line: "#0e4554", lineStrong: "#245563", text: "#eee8d5", muted: "#93a1a1", faint: "#657b83", accent: "#b58900", accentHover: "#c99a10", accentInk: "#1d1600", accentSoft: "#b5890024", ok: "#859900", danger: "#dc322f", dangerSoft: "#dc322f1f", terminal: "#002b36" },
  gruvbox: { ...graphite, canvas: "#1d2021", panel: "#282828", raised: "#32302f", hover: "#3c3836", line: "#3c3836", lineStrong: "#504945", text: "#ebdbb2", muted: "#bdae93", faint: "#928374", accent: "#fe8019", accentHover: "#fe9440", accentInk: "#241000", accentSoft: "#fe801924", ok: "#b8bb26", danger: "#fb4934", dangerSoft: "#fb49341f", terminal: "#282828" },
  light: { ...graphite, canvas: "#f3f4f6", panel: "#ffffff", raised: "#f0f1f3", hover: "#e8eaed", line: "#e1e4e8", lineStrong: "#cfd4da", text: "#1f2328", muted: "#57606a", faint: "#8c959f", accent: "#d97706", accentHover: "#b45309", accentInk: "#ffffff", accentSoft: "#d977061f", ok: "#1a7f37", danger: "#cf222e", dangerSoft: "#cf222e14", warn: "#9a6700", terminal: "#ffffff" },
};

/** The live palette: views read it on every render, so switching a scheme recolours everything. */
export const color: Palette = { ...graphite };

export function setPalette(name: string): void {
  Object.assign(color, palettes[name] ?? graphite);
}

export function isLight(): boolean {
  return color.canvas === palettes.light!.canvas;
}

/** Host label colours: distinct at a glance on the dark panel, none of them the accent. */
export const labels: Record<string, string> = {
  slate: "#7d8794",
  blue: "#5b9cf5",
  teal: "#3cc4b4",
  green: "#5ccf7a",
  violet: "#a487f2",
  pink: "#e57bb8",
  red: "#ef6b6b",
};

export const font = {
  ui: "Segoe UI Variable Text",
  display: "Segoe UI Variable Display",
  mono: "Cascadia Mono",
} as const;

export const radius = { control: 7, panel: 12 } as const;
