// Termio's visual system: a graphite instrument panel with one amber signal colour.
// Amber marks what is live or actionable (the active tab, the primary action, a connected
// session); everything else stays in the greys so the terminal text is the brightest thing.

export const color = {
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
} as const;

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
