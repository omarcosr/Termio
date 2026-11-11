// Renders every screen against a throwaway vault and saves a PNG of each, for review.
//   bun scripts/ui-check.tsx            (CPU renderer, so the captures include the terminal)
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

function App() {
  return (
    <Window title="Termio" width={1240} height={780} theme={darkTheme} style={{ background: color.canvas, fontFamily: font.ui, foreground: color.text }}>
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
async function shot(name: string) {
  test.app.update();
  await sleep(250);
  await test.waitForIdle().catch(() => undefined);
  const path = join(out, `termio-${name}.png`);
  await test.capture(path);
  shots.push(path);
}

try {
  store.loadStatus();
  await shot("create");
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
  await shot("host-editor");
  ui.editing = undefined;

  ui.view = "keys";
  await shot("keychain");
  ui.view = "sync";
  await shot("sync");
  ui.view = "hosts";

  ui.paletteOpen = true;
  ui.paletteQuery = "api";
  await shot("palette");
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
  await shot("hostkey-changed");
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
  ui.tabs.pop();
  ui.active = tab.id;

  store.lockVault();
  await shot("unlock");
} catch (error) {
  console.error(error);
  process.exitCode = 1;
}
console.log(shots.join("\n"));
test.close();
rmSync(dir, { recursive: true, force: true });
process.exit();
