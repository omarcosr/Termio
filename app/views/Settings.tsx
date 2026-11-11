import { Column, Modal, Pressable, Row, Scroll, Select, Text, viewport } from "@tarve/core";
import { saveAppearance, ui, type Appearance } from "../state/store";
import { Glyph, type IconId } from "../ui/icons";
import { ANDROID, compact, dialogWidth, IconAction, Segments, WINDOWS } from "../ui/kit";
import { color, radius } from "../ui/tokens";

/** Android ships few monospace faces; the desktop list names fonts it never has. */
const ANDROID_FAMILIES = ["Droid Sans Mono", "Cutive Mono"];
const DESKTOP_FAMILIES = ["Cascadia Mono", "Cascadia Code", "Consolas", "JetBrains Mono", "Fira Code", "Source Code Pro", "Ubuntu Mono", "DejaVu Sans Mono", "Lucida Console", "Courier New"];
const FAMILIES = ANDROID ? ANDROID_FAMILIES : DESKTOP_FAMILIES;

const SIZES = [11, 12, 13, 14, 15, 16, 18, 20];

/** Each scheme with the colours the preview shows: background, foreground, then red, green, yellow, blue, magenta, cyan. */
const THEMES: { value: string; label: string; colors: string[] }[] = [
  { value: "termio", label: "Termio", colors: ["#101216", "#d8dee9", "#e06c75", "#98c379", "#e5c07b", "#61afef", "#c678dd", "#56b6c2"] },
  { value: "dracula", label: "Dracula", colors: ["#282a36", "#f8f8f2", "#ff5555", "#50fa7b", "#f1fa8c", "#bd93f9", "#ff79c6", "#8be9fd"] },
  { value: "solarized", label: "Solarized", colors: ["#002b36", "#93a1a1", "#dc322f", "#859900", "#b58900", "#268bd2", "#d33682", "#2aa198"] },
  { value: "gruvbox", label: "Gruvbox", colors: ["#282828", "#ebdbb2", "#cc241d", "#98971a", "#d79921", "#458588", "#b16286", "#689d6a"] },
  { value: "light", label: "Light", colors: ["#ffffff", "#24292f", "#cf222e", "#116329", "#7d4e00", "#0969da", "#8250df", "#1b7c83"] },
];

const SHELLS = [
  { value: "", label: "System default" },
  { value: "powershell.exe", label: "Windows PowerShell" },
  { value: "pwsh.exe", label: "PowerShell 7" },
  { value: "cmd.exe", label: "Command Prompt" },
  { value: "wsl.exe", label: "WSL" },
];

type Page = "appearance" | "terminal";
let page: Page = "appearance";

const PAGES: { value: Page; label: string; icon: IconId }[] = [
  { value: "appearance", label: "Appearance", icon: "settings" },
  { value: "terminal", label: "Terminal", icon: "terminal" },
];

/** One setting: label and help on the left, the control on the right, a hairline between rows. */
function Setting(props: { label: string; hint?: string; children: unknown; stacked?: boolean }) {
  // A phone has no room for the control beside its label: it goes underneath.
  const stacked = props.stacked || compact();
  return (
    <Column gap={10} style={{ padding: { top: 16, bottom: 16 }, borderColor: color.line, borderWidth: { bottom: 1 } }}>
      <Row gap={24} align={stacked ? "start" : "center"}>
        <Column flex={1} gap={3} style={{ minWidth: 0 }}>
          <Text size={13} weight={600} color={color.text}>{props.label}</Text>
          {props.hint ? <Text size={12} color={color.faint} style={{ lineHeight: 1.45 }}>{props.hint}</Text> : null}
        </Column>
        {stacked ? null : <Row style={{ shrink: 0 }}>{props.children as never}</Row>}
      </Row>
      {stacked ? (props.children as never) : null}
    </Column>
  );
}

function ThemeSwatch({ theme, selected, narrow }: { theme: (typeof THEMES)[number]; selected: boolean; narrow?: boolean }) {
  const [background, foreground, ...accents] = theme.colors;
  return (
    <Pressable
      focusable
      onClick={() => saveAppearance({ theme: theme.value })}
      style={{ direction: "column", gap: 8, flex: narrow ? undefined : 1, width: narrow ? 96 : undefined, minWidth: 0, shrink: 0, padding: 4, radius: 10, borderColor: selected ? color.accent : "transparent", borderWidth: 2, hover: { borderColor: selected ? color.accent : color.lineStrong } }}
    >
      <Column gap={6} style={{ height: 58, padding: 10, radius: 7, background: background!, borderColor: color.line, borderWidth: 1 }}>
        <Row style={{ width: 34, height: 4, radius: 2, background: foreground! }} />
        <Row gap={3}>{accents.slice(0, 5).map(accent => <Row key={accent} style={{ width: 9, height: 4, radius: 2, background: accent }} />)}</Row>
        <Row style={{ width: 20, height: 4, radius: 2, background: foreground!, opacity: 0.5 }} />
      </Column>
      <Row gap={6} align="center" style={{ padding: { left: 2 } }}>
        <Text size={12} weight={selected ? 650 : 500} color={selected ? color.text : color.muted}>{theme.label}</Text>
        {selected ? <Glyph name="check" size={12} color={color.accent} strokeWidth={2.5} /> : null}
      </Row>
    </Pressable>
  );
}

function Preview({ appearance, scheme }: { appearance: Appearance; scheme: (typeof THEMES)[number] }) {
  const [background, foreground, red, green, , blue] = scheme.colors;
  const line = (parts: [string, string][]) => <Row>{parts.map(([text, tint], index) => <Text key={index} size={appearance.fontSize} color={tint} style={{ fontFamily: appearance.fontFamily, whiteSpace: "pre" }}>{text}</Text>)}</Row>;
  return (
    <Column gap={2} style={{ padding: appearance.padding + 10, radius: 10, background: background!, borderColor: color.line, borderWidth: 1 }}>
      {line([["root@instafast", green!], [":", foreground!], ["~", blue!], ["$ ls -la", foreground!]])}
      {line([["drwxr-xr-x  ", foreground!], ["nginx-1.29.5", blue!], ["  error.log", red!]])}
      {line([["0O 1lI {}[] => != ", foreground!], [appearance.cursor === "beam" ? "▏" : appearance.cursor === "underline" ? "_" : "█", foreground!]])}
    </Column>
  );
}

function SettingsNav({ height }: { height: number }) {
  return (
    <Column gap={2} style={{ width: 188, height, padding: 12, radius: { topLeft: 14, bottomLeft: 14 }, background: color.canvas, borderColor: color.line, borderWidth: { right: 1 } }}>
      <Text size={11.5} weight={650} color={color.faint} style={{ padding: { left: 10, top: 6, bottom: 8 } }}>SETTINGS</Text>
      {PAGES.map(item => {
        const active = page === item.value;
        return (
          <Pressable key={item.value} focusable onClick={() => { page = item.value; ui.settingsOpen = true; }} style={{ direction: "row", align: "center", gap: 10, height: 34, padding: { left: 10, right: 10 }, radius: 7, background: active ? color.raised : "transparent", hover: { background: active ? color.raised : color.hover } }}>
            <Glyph name={item.icon} size={15} color={active ? color.accent : color.muted} />
            <Text size={13} weight={active ? 600 : 500} color={active ? color.text : color.muted}>{item.label}</Text>
          </Pressable>
        );
      })}
      <Column flex={1} />
      <Text size={11} color={color.faint} style={{ padding: 10, lineHeight: 1.45 }}>Saved in your vault and synced to your other devices.</Text>
    </Column>
  );
}

/** App settings in a dialog, saved in the vault so they follow it to every device. */
export function Settings() {
  const appearance: Appearance = ui.appearance;
  const scheme = THEMES.find(theme => theme.value === appearance.theme) ?? THEMES[0]!;
  const narrow = compact();
  const width = dialogWidth(820);
  const height = Math.min(560, viewport().height - 48);
  const gutter = narrow ? 16 : 28;
  return (
    <Modal open={ui.settingsOpen} onOpenChange={open => { ui.settingsOpen = open; }} width={width} closeOnOverlay closeOnEscape showClose={false} style={{ maxWidth: "100%", padding: 0, background: color.panel, borderColor: color.lineStrong, borderWidth: 1, radius: 14 }}>
      <Row align="stretch" style={{ width, height, radius: 14, overflow: "hidden" }}>
        {narrow ? null : <SettingsNav height={height} />}
        <Column flex={1} style={{ minWidth: 0, height }}>
          <Row align="center" justify="between" style={{ height: 58, shrink: 0, padding: { left: gutter, right: 14 }, borderColor: color.line, borderWidth: { bottom: 1 } }}>
            <Text size={16} weight={650} color={color.text}>{PAGES.find(item => item.value === page)!.label}</Text>
            <IconAction icon="x" label="Close settings" onClick={() => { ui.settingsOpen = false; }} />
          </Row>
          {narrow ? (
            // No room for the side list on a phone: the pages become a switch under the title.
            <Row style={{ shrink: 0, padding: { left: gutter, right: gutter, top: 12 } }}>
              <Segments value={page} options={PAGES} onChange={value => { page = value; ui.settingsOpen = true; }} />
            </Row>
          ) : null}
          <Scroll flex={1} style={{ minHeight: 0 }}>
            <Column style={{ padding: { left: gutter, right: gutter, bottom: 20 } }}>
              {page === "appearance" ? (
                <Column>
                  <Setting label="Color scheme" hint="The whole app and every terminal follow it." stacked>
                    {narrow ? (
                      // Five swatches do not fit a phone: they scroll sideways.
                      <Scroll orientation="horizontal" style={{ height: 104, scrollbarWidth: "none" }}>
                        <Row gap={8}>{THEMES.map(theme => <ThemeSwatch key={theme.value} theme={theme} selected={theme.value === scheme.value} narrow />)}</Row>
                      </Scroll>
                    ) : (
                      <Row gap={8}>{THEMES.map(theme => <ThemeSwatch key={theme.value} theme={theme} selected={theme.value === scheme.value} />)}</Row>
                    )}
                  </Setting>
                  <Setting label="Font" hint="Falls back to the next monospace font when missing here.">
                    <Select style={{ width: narrow ? "100%" : 220 }} id="font-family" value={FAMILIES.includes(appearance.fontFamily) ? appearance.fontFamily : FAMILIES[0]} options={FAMILIES.map(family => ({ value: family, label: family }))} onValueChange={fontFamily => saveAppearance({ fontFamily })} />
                  </Setting>
                  <Setting label="Size">
                    <Segments value={String(appearance.fontSize)} options={SIZES.map(size => ({ value: String(size), label: String(size) }))} onChange={value => saveAppearance({ fontSize: Number(value) })} />
                  </Setting>
                  <Column style={{ padding: { top: 18 } }}><Preview appearance={appearance} scheme={scheme} /></Column>
                </Column>
              ) : (
                <Column>
                  <Setting label="Cursor">
                    <Segments value={appearance.cursor} options={[{ value: "block", label: "Block" }, { value: "beam", label: "Bar" }, { value: "underline", label: "Underline" }] as const} onChange={cursor => saveAppearance({ cursor })} />
                  </Setting>
                  <Setting label="Padding" hint="Space between the text and the edge of the pane.">
                    <Segments value={String(appearance.padding)} options={[0, 4, 6, 10, 16].map(padding => ({ value: String(padding), label: `${padding}` }))} onChange={value => saveAppearance({ padding: Number(value) })} />
                  </Setting>
                  {/* Only Windows offers a choice of shells; elsewhere a local tab runs the system's. */}
                  {WINDOWS ? (
                    <Setting label="Local shell" hint="What a new local tab runs.">
                      <Select style={{ width: narrow ? "100%" : 220 }} id="local-shell" value={appearance.shell} options={SHELLS} onValueChange={shell => saveAppearance({ shell })} />
                    </Setting>
                  ) : null}
                  <Column style={{ padding: { top: 18 } }}><Preview appearance={appearance} scheme={scheme} /></Column>
                </Column>
              )}
            </Column>
          </Scroll>
        </Column>
      </Row>
    </Modal>
  );
}
