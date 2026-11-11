import { Window, authenticate, createApp, darkTheme, lightTheme, type WindowCloseRequestEvent } from "@tarve/core";
import { core, termioCore, type KeyInput } from "./core/plugin";
import {
  activate,
  activeTab,
  answerHostKey,
  connect,
  reload,
  closePane,
  closeTab,
  createVault,
  cycleTabs,
  dialogs,
  focusPane,
  focusedSession,
  installAgent,
  saveAppearance,
  listen,
  loadStatus,
  lockVault,
  newHost,
  openLocal,
  setRenderer,
  split,
  ui, biometrics, closeTermSearch, openTermSearch, setTermQuery, stepTermSearch, reportFault } from "./state/store";
import { color, font, isLight } from "./ui/tokens";
import { handleBack, Root } from "./views/Shell";
import { cancelPath } from "./views/Files";
import { forwardPointer, imeKey, sessionOfIme, sessionOfNode, touchPointer } from "./views/TerminalPane";
import { touch } from "./ui/kit";

/**
 * Android's Back arrives as a close request. It goes back a step in the app first; on the first
 * screen it sends the app to the background instead of ending it, so open sessions survive.
 */
function onCloseRequest(event: WindowCloseRequestEvent): void {
  if ((process.platform as string) !== "android") return;
  event.preventDefault();
  if (ui.phase === "ready" && handleBack()) {
    app.update();
    return;
  }
  try { core().call({ op: "android.background" }); } catch { /* stays open */ }
}

function App() {
  return (
    <Window title="Termio" onCloseRequest={onCloseRequest} width={1240} height={780} theme={isLight() ? lightTheme : darkTheme} style={{ background: color.canvas, fontFamily: font.ui, foreground: color.text }}>
      <Root />
    </Window>
  );
}

// Errors nothing else caught open a dialog instead of ending the process (an unhandled rejection
// in Bun exits, and the window went with it).
process.on("unhandledRejection", reason => reportFault(reason, "rejection"));
process.on("uncaughtException", error => reportFault(error, "exception"));
const app = createApp(App, { plugins: [termioCore], keyboardEvents: true, pointerEvents: true, onError: event => reportFault(event.error, event.source) });
await app.ready;
setRenderer(() => app.update());
dialogs.open = async () => (await app.openFilesDialog({ title: "Upload files" })) ?? [];
dialogs.save = async name => (await app.saveFileDialog({ title: "Save as", fileName: name })) ?? undefined;
dialogs.focus = id => app.focus(id);
biometrics.authenticate = async reason => {
  const result = await authenticate({ reason });
  return { supported: result.supported, success: result.success, error: result.code === "canceled" ? undefined : result.error };
};
dialogs.pick = async (title, filters) => (await app.openFileDialog({ title, ...(filters.length ? { filters } : {}) })) ?? undefined;
listen();
loadStatus();
// Smoke test of a built executable: TERMIO_SMOKE=1 with TERMIO_VAULT pointing at a scratch file
// creates a vault there and opens a local terminal straight away.
if (process.env.TERMIO_SMOKE) {
  createVault("termio-smoke-test", "termio-smoke-test");
  if (process.env.TERMIO_SMOKE_THEME) saveAppearance({ theme: process.env.TERMIO_SMOKE_THEME });
  // TERMIO_SMOKE_SSH="user:password@host:port" opens an SSH session instead, trusting its key.
  const ssh = /^([^:]+):([^@]+)@([^:]+):(\d+)$/.exec(process.env.TERMIO_SMOKE_SSH ?? "");
  if (ssh) {
    const agent = Boolean(process.env.TERMIO_SMOKE_AGENT);
    const id = core().call<{ id: string }>({ op: "records.put", kind: "host", data: { name: "smoke", user: ssh[1], password: ssh[2], address: ssh[3], port: Number(ssh[4]), agent } }).id;
    reload();
    if (process.env.TERMIO_SMOKE_INSTALL) installAgent(id);
    connect(id);
    setInterval(() => { for (const prompt of [...ui.prompts]) answerHostKey(prompt.request, true); }, 200);
  } else {
    openLocal();
  }
}
app.update();

/**
 * App shortcuts. Inside a terminal they all take Shift, because Ctrl+W, Ctrl+L, Ctrl+K and
 * Ctrl+N already mean something to shells and editors. Returns true when the key was used.
 */
function shortcut(event: KeyInput): boolean {
  if (event.phase !== "down" || ui.phase !== "ready") return false;
  const key = event.key.toLowerCase();
  // The search bar is modal while it is open: Enter walks the matches, Escape closes it.
  if (ui.termSearch) {
    if (key === "enter") {
      stepTermSearch(event.shiftKey);
      app.update();
      return true;
    }
    if (key === "escape") {
      closeTermSearch();
      app.update();
      return true;
    }
    // Everything else typed here belongs to the search field, not to the pane behind it.
    if (!event.ctrlKey && !event.metaKey) return true;
  }
  const inTerminal = ui.active !== "home";
  const chord = event.ctrlKey && !event.altKey && (inTerminal ? event.shiftKey : true);
  if (event.ctrlKey && key === "tab") {
    cycleTabs(event.shiftKey ? -1 : 1);
    return true;
  }
  if (!chord) return false;
  switch (key) {
    case "k":
      ui.paletteOpen = !ui.paletteOpen;
      ui.paletteQuery = "";
      break;
    case "t":
      if (!event.shiftKey) return false;
      openLocal();
      break;
    case "w": {
      // Close the focused pane; the tab goes with its last one.
      const session = focusedSession();
      if (session !== undefined) closePane(session);
      else if (typeof ui.active === "number") closeTab(ui.active);
      else return false;
      break;
    }
    case "d":
      if (!event.shiftKey) return false;
      split("row");
      break;
    case "e":
      if (!event.shiftKey) return false;
      split("column");
      break;
    case "arrowleft":
    case "arrowright":
    case "arrowup":
    case "arrowdown": {
      // Move between panes of a split.
      const tab = activeTab();
      if (!tab || tab.panes.length < 2 || !event.shiftKey) return false;
      const step = key === "arrowleft" || key === "arrowup" ? -1 : 1;
      const index = tab.panes.indexOf(tab.focus);
      focusPane(tab.panes[(index + step + tab.panes.length) % tab.panes.length]!);
      break;
    }
    case "f":
      // Find in the focused terminal.
      if (!event.shiftKey) return false;
      openTermSearch();
      app.focus("term-search");
      break;
    case "l":
      lockVault();
      break;
    case "n":
      ui.view = "hosts";
      activate("home");
      newHost();
      break;
    default:
      if (/^[1-9]$/.test(key) && event.altKey === false) {
        const index = Number(key) - 1;
        activate(index === 0 ? "home" : ui.tabs[index - 1]?.id ?? ui.active);
        break;
      }
      return false;
  }
  app.update();
  return true;
}

app.onEvent(event => {
  if (event.type === "keyboard") {
    if (shortcut(event)) return;
    // Escape in the Files path field puts the path bar back.
    if (event.phase === "down" && event.key === "Escape" && event.id?.startsWith("files-path-")) {
      const files = ui.tabs.find(tab => tab.files && `files-path-${tab.files.id}` === event.id)?.files;
      if (files) cancelPath(files);
      return;
    }
    // The soft keyboard's hidden field: its text arrives through the field (onChange), the
    // keys that type nothing (Enter, Backspace, arrows) as key events.
    const ime = sessionOfIme(event.id);
    if (ime !== undefined) {
      if (imeKey(ime, event)) app.update();
      return;
    }
    const session = focusedSession();
    // Keys go to the focused pane unless a text field, dialog or the palette has them.
    // A terminal tab has no text field of its own, so there the keys always belong to the pane:
    // the focus can still sit on what started the session (the quick-connect field, a host row),
    // hidden behind the tab, and that swallowed every key of a fresh SSH session.
    const free = event.id === null || typeof ui.active === "number" || sessionOfNode(event.id) !== undefined;
    if (session !== undefined && free && !ui.paletteOpen && ui.prompts.length === 0) core().key(session, event);
  } else if (event.type === "pointer") {
    const target = sessionOfNode(event.id);
    if (target !== undefined) {
      // Clicking into a pane of a split gives it the keyboard.
      if (event.phase === "down") focusPane(target);
      if (touch()) touchPointer(target, event.phase, event);
      else forwardPointer(target, event.phase, event);
    }
  }
});

await app.closed;
