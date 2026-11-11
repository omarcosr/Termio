import { Window, createApp, darkTheme } from "@tarve/core";
import { core, termioCore, type KeyInput } from "./core/plugin";
import {
  activate,
  activeTab,
  closePane,
  closeTab,
  cycleTabs,
  dialogs,
  focusPane,
  focusedSession,
  listen,
  loadStatus,
  lockVault,
  newHost,
  openLocal,
  setRenderer,
  split,
  ui,
} from "./state/store";
import { color, font } from "./ui/tokens";
import { Root } from "./views/Shell";
import { forwardPointer, sessionOfNode } from "./views/TerminalPane";

function App() {
  return (
    <Window title="Termio" width={1240} height={780} theme={darkTheme} style={{ background: color.canvas, fontFamily: font.ui, foreground: color.text }}>
      <Root />
    </Window>
  );
}

const app = createApp(App, { plugins: [termioCore], keyboardEvents: true, pointerEvents: true });
await app.ready;
setRenderer(() => app.update());
dialogs.open = async () => (await app.openFilesDialog({ title: "Upload files" })) ?? [];
dialogs.save = async name => (await app.saveFileDialog({ title: "Save as", fileName: name })) ?? undefined;
listen();
loadStatus();
app.update();

/**
 * App shortcuts. Inside a terminal they all take Shift, because Ctrl+W, Ctrl+L, Ctrl+K and
 * Ctrl+N already mean something to shells and editors. Returns true when the key was used.
 */
function shortcut(event: KeyInput): boolean {
  if (event.phase !== "down" || ui.phase !== "ready") return false;
  const key = event.key.toLowerCase();
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
    const session = focusedSession();
    // Keys go to the focused pane unless a text field, dialog or the palette has them.
    const free = event.id === null || sessionOfNode(event.id) !== undefined;
    if (session !== undefined && free && !ui.paletteOpen && ui.prompts.length === 0) core().key(session, event);
  } else if (event.type === "pointer") {
    const target = sessionOfNode(event.id);
    if (target !== undefined) {
      // Clicking into a pane of a split gives it the keyboard.
      if (event.phase === "down") focusPane(target);
      forwardPointer(target, event.phase, event);
    }
  }
});

await app.closed;
