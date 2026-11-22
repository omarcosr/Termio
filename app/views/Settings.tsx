import { Column, Modal, Pressable, Row, Scroll, Select, Text, viewport } from "@tarve/core";
import { applyUpdate, canSelfUpdate, checkUpdates, openPage, releasePage, updates, updatesConfigured, version } from "../state/updates";
import { AUDIT_CATEGORIES, auditCategoryOn, defaultDownloadFolder, dialogs, saveAppearance, saveAuditSettings, saveTransferSettings, setFingerprint, ui, type Appearance } from "../state/store";
import { Glyph, type IconId } from "../ui/icons";
import { Action, ANDROID, compact, dialogWidth, IconAction, mono, relativeTime, Segments, TextField, WINDOWS } from "../ui/kit";
import { color, radius } from "../ui/tokens";
import { t, type LanguageChoice } from "../i18n";

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

const SHELLS = () => [
  { value: "", label: t("System default") },
  { value: "powershell.exe", label: "Windows PowerShell" },
  { value: "pwsh.exe", label: "PowerShell 7" },
  { value: "cmd.exe", label: t("Command Prompt") },
  { value: "wsl.exe", label: "WSL" },
];

type Page = "appearance" | "terminal" | "transfers" | "security" | "about";
let page: Page = "appearance";

/** Opens Settings on a page (the UI check uses it). */
export function openSettingsPage(next: Page): void {
  page = next;
  ui.settingsOpen = true;
}

const PAGES = (): { value: Page; label: string; icon: IconId }[] => [
  { value: "appearance", label: t("Appearance"), icon: "settings" },
  { value: "terminal", label: t("Terminal"), icon: "terminal" },
  // Android saves through the system and has no editors to hand a file to.
  ...(ANDROID ? [] : [{ value: "transfers" as const, label: t("Transfers"), icon: "folder" as const }]),
  { value: "security", label: t("Security"), icon: "shield" },
  { value: "about", label: t("About"), icon: "download" },
];

const LANGUAGES = (): { value: LanguageChoice; label: string }[] => [
  { value: "auto", label: t("System") },
  { value: "en", label: "English" },
  { value: "pt-BR", label: "Português (Brasil)" },
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
      style={{ direction: "column", gap: 8, flex: narrow ? undefined : 1, width: narrow ? 96 : undefined, minWidth: 0, shrink: 0, cursor: selected ? "default" : "pointer", padding: 4, radius: 10, borderColor: selected ? color.accent : "transparent", borderWidth: 2, hover: { borderColor: selected ? color.accent : color.lineStrong } }}
    >
      <Column gap={6} style={{ height: 58, padding: 10, radius: 7, background: background!, borderColor: color.line, borderWidth: 1 }}>
        <Row style={{ width: 34, height: 4, radius: 2, background: foreground! }} />
        <Row gap={3}>{accents.slice(0, 5).map(accent => <Row key={accent} style={{ width: 9, height: 4, radius: 2, background: accent }} />)}</Row>
        <Row style={{ width: 20, height: 4, radius: 2, background: foreground!, opacity: 0.5 }} />
      </Column>
      <Row gap={6} align="center" style={{ padding: { left: 2 } }}>
        <Text size={12} weight={selected ? 650 : 500} color={selected ? color.text : color.muted}>{theme.value === "light" ? t("Light") : theme.label}</Text>
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
      {line([["root@server", green!], [":", foreground!], ["~", blue!], ["$ ls -la", foreground!]])}
      {line([["drwxr-xr-x  ", foreground!], ["nginx-1.29.5", blue!], ["  error.log", red!]])}
      {line([["0O 1lI {}[] => != ", foreground!], [appearance.cursor === "beam" ? "▏" : appearance.cursor === "underline" ? "_" : "█", foreground!]])}
    </Column>
  );
}

function SettingsNav({ height }: { height: number }) {
  return (
    <Column gap={2} style={{ width: 188, height, padding: 12, radius: { topLeft: 14, bottomLeft: 14 }, background: color.canvas, borderColor: color.line, borderWidth: { right: 1 } }}>
      <Text size={11.5} weight={650} color={color.faint} style={{ padding: { left: 10, top: 6, bottom: 8 } }}>{t("SETTINGS")}</Text>
      {PAGES().map(item => {
        const active = page === item.value;
        return (
          <Pressable key={item.value} focusable onClick={() => { page = item.value; ui.settingsOpen = true; }} style={{ direction: "row", align: "center", gap: 10, height: 34, cursor: active ? "default" : "pointer", padding: { left: 10, right: 10 }, radius: 7, background: active ? color.raised : "transparent", hover: { background: active ? color.raised : color.hover } }}>
            <Glyph name={item.icon} size={15} color={active ? color.accent : color.muted} />
            <Text size={13} weight={active ? 600 : 500} color={active ? color.text : color.muted}>{item.label}</Text>
          </Pressable>
        );
      })}
      <Column flex={1} />
      <Text size={11} color={color.faint} style={{ padding: 10, lineHeight: 1.45 }}>{t("Saved in your vault and synced to your other devices.")}</Text>
    </Column>
  );
}

/** What the updates row says, from the last check. */
function updateHint(): string {
  if (!updatesConfigured()) return t("Updates are not set up in this build.");
  const update = updates.update;
  switch (updates.state) {
    case "checking": return t("Checking GitHub for a newer release…");
    case "downloading": return t("Downloading {version}: {percent}%", { version: update?.version ?? "", percent: updates.total ? Math.round(updates.received / updates.total * 100) : 0 });
    case "available": return t("Termio {version} is available.", { version: update!.version }) + (update!.notes ? " " + update!.notes : "");
    case "current": return t("Up to date, checked {when}.", { when: relativeTime(updates.checkedAt) });
    case "error": return t("The last check failed: {error}", { error: String(updates.error) });
    default: return t("Checked on launch and every few hours.");
  }
}

function Toggle({ value, onChange }: { value: boolean; onChange: (value: boolean) => void }) {
  return <Segments value={value ? "on" : "off"} options={[{ value: "off", label: t("Off") }, { value: "on", label: t("On") }] as const} onChange={next => onChange(next === "on")} />;
}

/** The security audit: off until turned on, then every group of checks and every outside contact on its own switch. */
function Security() {
  const audit = ui.auditSettings;
  return (
    <Column>
      <Setting label={t("Security audit")} hint={t("Checks a server for vulnerabilities and weak settings with one read-only script over SSH. Nothing is installed or written on the server.")}>
        <Toggle value={audit.enabled} onChange={enabled => saveAuditSettings({ enabled })} />
      </Setting>
      {audit.enabled ? (
        <Column>
          <Row gap={10} align="start" style={{ padding: 12, radius: 8, background: color.accentSoft, margin: { top: 16 } }}>
            <Glyph name="shield" size={15} color={color.accent} />
            <Text size={12.5} color={color.text} style={{ flex: 1, lineHeight: 1.5 }}>{t("To run it, point at a host in the list and pick its shield, or open the host and use its Security section. Once a host has a report, a badge next to its name shows the worst finding; pick it to open the report.")}</Text>
          </Row>
          <Text size={11.5} weight={650} color={color.faint} style={{ padding: { top: 22, bottom: 2 } }}>{t("CHECKS · WHAT THE SCRIPT READS ON THE SERVER")}</Text>
          {AUDIT_CATEGORIES.map(item => (
            <Setting key={item.value} label={t(item.label)} hint={t(item.hint)}>
              <Toggle value={auditCategoryOn(item.value)} onChange={on => saveAuditSettings({ categories: { ...audit.categories, [item.value]: on } })} />
            </Setting>
          ))}
          <Text size={11.5} weight={650} color={color.faint} style={{ padding: { top: 22, bottom: 2 } }}>{t("REACH · PRIVILEGES AND WHAT LEAVES THIS DEVICE")}</Text>
          <Setting label={t("Use sudo")} hint={t("Reads what needs root (password hash kinds, sudoers, firewall, other users' files) with sudo -n. Only passwordless sudo works: it never asks for a password. Without it those checks are partial unless you log in as root.")}>
            <Toggle value={audit.sudo} onChange={sudo => saveAuditSettings({ sudo })} />
          </Setting>
          <Setting label={t("Match packages against CVEs")} hint={t("Sends the installed package names and versions, and nothing else, from this device to OSV.dev to list known vulnerabilities. Debian, Ubuntu, Alpine, Rocky Linux and AlmaLinux.")}>
            <Toggle value={audit.cve} onChange={cve => saveAuditSettings({ cve })} />
          </Setting>
          <Setting label={t("Try open ports from here")} hint={t("Connects from this device to each port the server exposes, to tell what is really reachable. Skipped for hosts behind a jump host.")}>
            <Toggle value={audit.probe} onChange={probe => saveAuditSettings({ probe })} />
          </Setting>
        </Column>
      ) : null}
    </Column>
  );
}

async function chooseDownloadFolder(): Promise<void> {
  const folder = await dialogs.folder(t("Download folder"));
  if (folder) saveTransferSettings({ folder });
}

async function chooseEditor(): Promise<void> {
  const editor = await dialogs.pick(t("Choose the editor"), WINDOWS ? [{ name: t("Programs"), extensions: ["exe", "cmd", "bat"] }] : []);
  if (editor) saveTransferSettings({ editor });
}

/** Downloads: a save dialog each time or straight into a folder; and the editor remote files open in. */
function TransferSettingsPage() {
  const settings = ui.transferSettings;
  return (
    <Column>
      <Setting label={t("When downloading")} hint={t("Ask where to save each file, or save it straight into the download folder.")}>
        <Segments value={settings.download} options={[{ value: "ask", label: t("Always ask") }, { value: "folder", label: t("Save to the folder") }] as const} onChange={download => saveTransferSettings({ download })} />
      </Setting>
      <Setting label={t("Download folder")} hint={t("Empty: your Downloads folder. A file never overwrites another: a number is added to its name.")} stacked>
        <Row gap={8} align="center">
          <TextField id="download-folder" value={settings.folder} placeholder={defaultDownloadFolder()} onChange={folder => saveTransferSettings({ folder }, true)} style={{ flex: 1, ...mono, fontSize: 12.5 }} />
          <Action icon="folder" label={t("Choose…")} onClick={() => { void chooseDownloadFolder(); }} />
        </Row>
      </Setting>
      <Setting label={t("Default editor")} hint={t("Opens remote files picked with Open in the editor: the program's path, optionally with arguments. Empty: the system's app for the file type.")} stacked>
        <Row gap={8} align="center">
          <TextField id="default-editor" value={settings.editor} placeholder={t("System app")} onChange={editor => saveTransferSettings({ editor }, true)} style={{ flex: 1, ...mono, fontSize: 12.5 }} />
          <Action icon="file" label={t("Choose…")} onClick={() => { void chooseEditor(); }} />
        </Row>
      </Setting>
    </Column>
  );
}

function About() {
  const busy = updates.state === "checking" || updates.state === "downloading";
  const install = canSelfUpdate() ? t("Install and restart") : ANDROID ? t("Download APK") : t("Open download page");
  return (
    <Column>
      <Setting label={t("Version")} hint={t("Termio, an SSH terminal for slow and distant links.")}>
        <Text size={13} weight={600} color={color.muted}>{version}</Text>
      </Setting>
      <Setting label={t("Updates")} hint={updateHint()}>
        <Row gap={8}>
          {updates.state === "available" ? <Action label={install} tone="primary" icon="download" onClick={() => { void applyUpdate(); }} /> : null}
          <Action label={t("Check now")} icon="refresh" disabled={busy || !updatesConfigured()} onClick={() => { void checkUpdates(); }} />
        </Row>
      </Setting>
      <Setting label={t("Release notes")} hint={t("Every version and its changes on GitHub.")}>
        <Action label={t("Open")} onClick={() => openPage(releasePage())} />
      </Setting>
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
            <Text size={16} weight={650} color={color.text}>{PAGES().find(item => item.value === page)!.label}</Text>
            <IconAction icon="x" label={t("Close settings")} onClick={() => { ui.settingsOpen = false; }} />
          </Row>
          {narrow ? (
            // No room for the side list on a phone: the pages become a switch under the title.
            <Row style={{ shrink: 0, padding: { left: gutter, right: gutter, top: 12 } }}>
              <Segments value={page} options={PAGES()} onChange={value => { page = value; ui.settingsOpen = true; }} />
            </Row>
          ) : null}
          <Scroll flex={1} style={{ minHeight: 0 }}>
            <Column style={{ padding: { left: gutter, right: gutter, bottom: 20 } }}>
              {page === "appearance" ? (
                <Column>
                  <Setting label={t("Language")} hint={t("Following the system picks Portuguese on a Portuguese system and English elsewhere.")}>
                      <Select style={{ width: narrow ? "100%" : 220 }} id="language" value={appearance.language ?? "auto"} options={LANGUAGES()} onValueChange={value => saveAppearance({ language: value as LanguageChoice })} />
                    </Setting>
                    <Setting label={t("Color scheme")} hint={t("The whole app and every terminal follow it.")} stacked>
                    {narrow ? (
                      // Five swatches do not fit a phone: they scroll sideways.
                      <Scroll orientation="horizontal" style={{ height: 104, scrollbarWidth: "none" }}>
                        <Row gap={8}>{THEMES.map(theme => <ThemeSwatch key={theme.value} theme={theme} selected={theme.value === scheme.value} narrow />)}</Row>
                      </Scroll>
                    ) : (
                      <Row gap={8}>{THEMES.map(theme => <ThemeSwatch key={theme.value} theme={theme} selected={theme.value === scheme.value} />)}</Row>
                    )}
                  </Setting>
                  <Setting label={t("Font")} hint={t("Falls back to the next monospace font when missing here.")}>
                    <Select style={{ width: narrow ? "100%" : 220 }} id="font-family" value={FAMILIES.includes(appearance.fontFamily) ? appearance.fontFamily : FAMILIES[0]} options={FAMILIES.map(family => ({ value: family, label: family }))} onValueChange={fontFamily => saveAppearance({ fontFamily })} />
                  </Setting>
                  <Setting label={t("Size")}>
                    <Segments value={String(appearance.fontSize)} options={SIZES.map(size => ({ value: String(size), label: String(size) }))} onChange={value => saveAppearance({ fontSize: Number(value) })} />
                  </Setting>
                  <Column style={{ padding: { top: 18 } }}><Preview appearance={appearance} scheme={scheme} /></Column>
                </Column>
              ) : page === "about" ? (
                <About />
                ) : page === "security" ? (
                <Security />
                ) : page === "transfers" ? (
                <TransferSettingsPage />
                ) : (
                  <Column>
                  <Setting label={t("Cursor")}>
                    <Segments value={appearance.cursor} options={[{ value: "block", label: t("Block") }, { value: "beam", label: t("Bar") }, { value: "underline", label: t("Underline") }] as const} onChange={cursor => saveAppearance({ cursor })} />
                  </Setting>
                  <Setting label={t("Padding")} hint={t("Space between the text and the edge of the pane.")}>
                    <Segments value={String(appearance.padding)} options={[0, 4, 6, 10, 16].map(padding => ({ value: String(padding), label: `${padding}` }))} onChange={value => saveAppearance({ padding: Number(value) })} />
                  </Setting>
                  {ANDROID ? (
                    <Setting label={t("Unlock with fingerprint")} hint={t("The vault password is sealed by this phone's secure hardware; your fingerprint or screen lock opens it.")}>
                      <Segments value={ui.fingerprint ? "on" : "off"} options={[{ value: "off", label: t("Off") }, { value: "on", label: t("On") }] as const} onChange={value => { void setFingerprint(value === "on"); }} />
                    </Setting>
                  ) : null}
                  {/* Only Windows offers a choice of shells; elsewhere a local tab runs the system's. */}
                  {WINDOWS ? (
                    <Setting label={t("Local shell")} hint={t("What a new local tab runs.")}>
                      <Select style={{ width: narrow ? "100%" : 220 }} id="local-shell" value={appearance.shell} options={SHELLS()} onValueChange={shell => saveAppearance({ shell })} />
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
