// Renders every screen against a throwaway vault and saves a PNG of each, for review.
//   bun scripts/ui-check.tsx            (CPU renderer, so the captures include the terminal)
//   UI_SIZE=360x740 TERMIO_TOUCH=1 bun scripts/ui-check.tsx   (a phone: compact layout, touch controls)
import { Window, createTestRenderer, darkTheme } from "@tarve/core";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const dir = mkdtempSync(join(tmpdir(), "termio-ui-"));
process.env.TERMIO_VAULT = join(dir, "vault.termio");

const { core, termioCore } = await import("../app/core/plugin");
const store = await import("../app/state/store");
const { Root } = await import("../app/views/Shell");
const { color, font } = await import("../app/ui/tokens");
const { ui } = store;

const [width, height] = (process.env.UI_SIZE ?? "1240x780").split("x").map(Number);

function App() {
  return (
    <Window title="Termio" width={width} height={height} theme={darkTheme} style={{ background: color.canvas, fontFamily: font.ui, foreground: color.text }}>
      <Root />
    </Window>
  );
}

const test = await createTestRenderer(App, { plugins: [termioCore], renderer: "cpu", keyboardEvents: true, pointerEvents: true });
store.setRenderer(() => test.app.update());
store.listen();
const out = process.env.EMPRYO_TMP ?? tmpdir();
const shots: string[] = [];
const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
/**
 * Layout faults a picture hides from a quick look: two pieces of text or controls drawn over each
 * other (neither inside the other), or one running past the window's edge. Boxes a scroll area
 * clips are skipped, and so are shots with a dialog over the page (`overlay`).
 */
type Box = { id: string; kind: string; x: number; y: number; width: number; height: number; text: string; label?: string };
const faults: string[] = [];
const inside = (a: Box, b: Box) => a.x >= b.x - 1 && a.y >= b.y - 1 && a.x + a.width <= b.x + b.width + 1 && a.y + a.height <= b.y + b.height + 1;
const overlap = (a: Box, b: Box) => Math.min(a.x + a.width, b.x + b.width) - Math.max(a.x, b.x) > 2 && Math.min(a.y + a.height, b.y + b.height) - Math.max(a.y, b.y) > 2;
const describe = (box: Box) => `${box.kind} "${(box.label ?? box.text ?? box.id).slice(0, 30)}" @${Math.round(box.x)},${Math.round(box.y)} ${Math.round(box.width)}×${Math.round(box.height)}`;
async function checkLayout(name: string, overlay: boolean) {
  const snapshot = await test.inspect();
  const all = snapshot.nodes.map(node => ({ id: node.id, kind: node.kind, x: node.x, y: node.y, width: node.width, height: node.height, text: node.text, label: node.control?.label })) as Box[];
  const scrolls = all.filter(box => box.kind === "scroll");
  const leaf = all.filter(box => ["text", "pressable", "input", "button", "svg"].includes(box.kind) && box.width > 0 && box.height > 0);
  // Scroll areas clip what they hold: a box is checked as far as it shows through the
  // innermost scroll area that holds it, and dropped where none of it shows.
  const clip = (box: Box): Box | undefined => {
    const holders = scrolls.filter(scroll => scroll !== box && (
      // A sideways scroller holds what lies in its band; a vertical one, what lies in its column.
      (box.y >= scroll.y - 1 && box.y + box.height <= scroll.y + scroll.height + 1) ||
      (box.x >= scroll.x - 1 && box.x + box.width <= scroll.x + scroll.width + 1)));
    let shown: Box = box;
    for (const scroll of holders) {
      const x = Math.max(shown.x, scroll.x), y = Math.max(shown.y, scroll.y);
      const right = Math.min(shown.x + shown.width, scroll.x + scroll.width), bottom = Math.min(shown.y + shown.height, scroll.y + scroll.height);
      if (right - x <= 1 || bottom - y <= 1) return undefined;
      shown = { ...shown, x, y, width: right - x, height: bottom - y };
    }
    return shown;
  };
  const shown = leaf.map(clip).filter((box): box is Box => box !== undefined);
  const local: string[] = [];
  for (const box of shown) {
    if (box.x + box.width > snapshot.width + 1 || box.x < -1) local.push(`past the edge: ${describe(box)}`);
  }
  if (!overlay) {
    for (let i = 0; i < shown.length; i++) {
      for (let j = i + 1; j < shown.length; j++) {
        const a = shown[i]!, b = shown[j]!;
        if (overlap(a, b) && !inside(a, b) && !inside(b, a)) local.push(`overlap: ${describe(a)} × ${describe(b)}`);
      }
    }
  }
  for (const fault of local) faults.push(`${name}: ${fault}`);
}

async function shot(name: string, overlay = false) {
  test.app.update();
  await sleep(250);
  await test.waitForIdle().catch(() => undefined);
  await checkLayout(name, overlay);
  const path = join(out, `termio-${width}x${height}-${name}.png`);
  await test.capture(path);
  shots.push(path);
}

try {
  store.loadStatus();
  await shot("create");
  // The Cloudflare sign-in after Connect, with an account picked and its buckets listed.
  const { cf } = await import("../app/views/Cloudflare");
  Object.assign(cf, { token: "x".repeat(40), accounts: [{ id: "a1", name: "Personal" }, { id: "a2", name: "Work" }], account: "a1", buckets: ["termio-vault", "backups", "photos"] });
  ui.phase = "join";
  await shot("join", true);
  ui.phase = "create";
  store.createVault("correct horse battery", "correct horse battery");
  await shot("hosts-empty");

  const put = (data: Record<string, unknown>) => core().call<{ id: string }>({ op: "records.put", kind: "host", data }).id;
  const bastion = put({ name: "Bastion", address: "bastion.example.net", user: "ops", group: "Edge", color: "violet", password: "x" });
  put({ name: "API · São Paulo", address: "10.20.0.11", user: "deploy", group: "Production", color: "green", jump: bastion, lastConnected: Date.now() - 3 * 3600e3 });
  put({ name: "API · Frankfurt", address: "10.30.0.11", user: "deploy", group: "Production", color: "green", jump: bastion, lastConnected: Date.now() - 26 * 3600e3 });
  put({ name: "Postgres primary", address: "db-1.internal", port: 2222, user: "postgres", group: "Production", color: "blue" });
  put({ name: "Build runner", address: "ci.example.dev", user: "runner", group: "Tooling", color: "teal", lastConnected: Date.now() - 40e3 });
  put({ name: "Raspberry Pi", address: "192.168.1.40", user: "pi", color: "pink" });
  core().call({ op: "keys.generate", name: "Laptop" });
  store.reload();
  await shot("hosts");

  store.editHost(ui.hosts.find(host => host.data.name === "Postgres primary")!.id);
  await shot("host-editor", true);
  const edited = ui.editing!.id!;
  ui.agentInstall[edited] = { state: "uploading", message: "Uploading the agent (3624 KB)…", at: Date.now() };
  await shot("agent-installing", true);
  delete ui.agentInstall[edited];
  ui.editing = undefined;

  ui.view = "keys";
  await shot("keychain");
  core().call({ op: "records.put", kind: "host", id: ui.hosts.find(host => host.data.name === "Postgres primary")!.id, data: { ...ui.hosts.find(host => host.data.name === "Postgres primary")!.data, forwards: [{ local: 5432, host: "127.0.0.1", port: 5432 }, { local: 8080, host: "grafana.internal", port: 3000 }] } });
  store.reload();
  ui.view = "forwards";
  await shot("forwards");
  ui.view = "sync";
  await shot("sync");
  ui.view = "hosts";
  ui.settingsOpen = true;
  await shot("settings", true);
  ui.settingsOpen = false;
  ui.view = "hosts";

  ui.paletteOpen = true;
  ui.paletteQuery = "api";
  await shot("palette", true);
  ui.paletteOpen = false;

  core().call({ op: "records.put", kind: "snippet", data: { name: "Disk usage", command: "df -h" } });
  core().call({ op: "records.put", kind: "snippet", data: { name: "Say hello", command: "echo termio-snippet-ok" } });
  core().call({ op: "records.put", kind: "snippet", data: { name: "Follow the app log", command: "journalctl -u app -f" } });
  store.reload();
  ui.view = "snippets";
  await shot("snippets");
  ui.view = "hosts";

  store.openLocal();
  await sleep(2500);
  await shot("terminal");
  if (process.env.TERMIO_TOUCH === "1") {
    // A long press on a word: handles at its ends and the action bar.
    const { selectForTest } = await import("../app/views/TerminalPane");
    const session = store.activeTab()!.focus;
    selectForTest(session, "word", { x: 40, y: 30 });
    await shot("terminal-selection");
    selectForTest(session, "all");
    await shot("terminal-select-all");
    selectForTest(session, "clear");
  }
  // A crowded tab strip: long titles and several tabs, as a phone gets them.
  const crowd = ui.tabs.length;
  for (const title of ["Files · Instafast netcup six", "root@instafast:~ — a very long title"]) {
    ui.tabs.push({ id: 900 + ui.tabs.length, kind: "files", panes: [], direction: "row", focus: 0, files: { id: 900 + ui.tabs.length, host: ui.hosts[0]!.id, state: "connecting", path: "/", loading: false, entries: [], transfers: [] } } as never);
    void title;
  }
  ui.hosts[0]!.data.name = "Instafast netcup six with a long name";
  await shot("tabs-crowded");
  // Swiped to the end, with the long one active: what the phone showed overlapping.
  ui.active = ui.tabs[ui.tabs.length - 1]!.id;
  test.app.update();
  await shot("tabs-scrolled");
  // Phones: the switcher that lists every open tab.
  if ((width ?? 0) < 720) {
    await test.getByRole("button", { name: /open tabs/ }).click();
    await shot("tabs-switcher", true);
    // Back to the vault through the list, which closes it.
    await test.getByText("Hosts, keys, snippets").click();
    await test.waitFor(() => ui.active === "home" || undefined, { timeout: 3000 });
  }
  ui.tabs.splice(crowd);
  ui.active = ui.tabs[ui.tabs.length - 1]!.id;

  // A split: two panes in one tab, the new one focused; a snippet broadcast to both.
  store.split("row");
  await sleep(2500);
  const tab = store.activeTab()!;
  if (tab.panes.length !== 2 || tab.focus !== tab.panes[1]) throw new Error(`split: ${JSON.stringify(tab)}`);
  store.broadcastSnippet(ui.snippets.find(snippet => snippet.data.name === "Say hello")!.id);
  await sleep(1500);
  for (const pane of tab.panes) {
    const lines = core().call<{ lines: string[] }>({ op: "session.text", id: pane }).lines;
    if (!lines.some(line => line.trim() === "termio-snippet-ok")) throw new Error(`pane ${pane} did not run the snippet: ${lines.filter(Boolean).join(" | ")}`);
  }
  await shot("split");

  ui.prompts.push({ request: 0, session: tab.panes[0]!, host: "db-1.internal", port: 2222, algorithm: "ssh-ed25519", fingerprint: "SHA256:3x4mPl3kEyF1ng3rPr1nTn0tR34lAtAll0K", previous: "SHA256:0ldK3yTh4tW4sTru5t3dB3f0r3xYz12345678" });
  await shot("hostkey-changed", true);
  ui.prompts.length = 0;

  // The file browser, with a listing as the SFTP connection would deliver it.
  const host = ui.hosts.find(record => record.data.name === "Build runner")!;
  ui.tabs.push({
    id: 999, kind: "files", panes: [], direction: "row", focus: 0,
    files: {
      id: 999, host: host.id, state: "ready", path: "/home/runner/releases", loading: false,
      entries: [
        { name: "2026-11", directory: true, size: 0, modified: 1_762_800_000 },
        { name: "archive", directory: true, size: 0, modified: 1_760_000_000 },
        { name: "termio-0.4.2-linux-x64.tar.gz", directory: false, size: 18_437_120, modified: 1_762_790_000 },
        { name: "termio-0.4.2-windows-x64.zip", directory: false, size: 21_004_288, modified: 1_762_790_400 },
        { name: "checksums.txt", directory: false, size: 412, modified: 1_762_790_500 },
      ],
      transfers: [
        { request: 1, name: "termio-0.4.2-windows-x64.zip", direction: "down", total: 21_004_288, done: 13_600_000, state: "running" },
        { request: 2, name: "deploy.sh", direction: "up", total: 2_310, done: 2_310, state: "done" },
      ],
    },
  });
  ui.active = 999;
  await shot("files");
  // The path bar after a tap: a field holding the path.
  const { editPathForTest } = await import("../app/views/Files");
  editPathForTest(ui.tabs.find(item => item.id === 999)!.files!);
  await shot("files-path");
  ui.tabs.pop();
  ui.active = tab.id;

  store.lockVault();
  await shot("unlock");
} catch (error) {
  console.error(error);
  process.exitCode = 1;
}
console.log(shots.join("\n"));
if (faults.length) {
  console.error(`\n${faults.length} layout faults at ${width}x${height}:\n${faults.join("\n")}`);
  process.exitCode = 1;
}
test.close();
rmSync(dir, { recursive: true, force: true });
process.exit();
