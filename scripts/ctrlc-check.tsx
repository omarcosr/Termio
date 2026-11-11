// Types a long-running command into a local shell, interrupts it with Ctrl+C and checks the
// shell answers again: bun scripts/ctrlc-check.tsx
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

process.env.TERMIO_VAULT = join(mkdtempSync(join(tmpdir(), "termio-ctrlc-")), "vault.termio");
const { core, termioCore } = await import("../app/core/plugin");
const { createTestRenderer, Window } = await import("@tarve/core");
const { Root } = await import("../app/views/Shell");
const store = await import("../app/state/store");
const test = await createTestRenderer(() => <Window title="t" width={900} height={600}><Root /></Window>, { plugins: [termioCore], renderer: "cpu" });
store.setRenderer(() => test.app.update());
store.listen();
store.loadStatus();
store.createVault("termio-smoke-test", "termio-smoke-test");
store.openLocal();
const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
await sleep(3000);
const session = store.focusedSession()!;
const mods = { ctrlKey: false, altKey: false, shiftKey: false, metaKey: false };
const press = (key: string, extra = {}) => { core().key(session, { phase: "down", key, ...mods, ...extra }); core().key(session, { phase: "up", key, ...mods, ...extra }); };
const type = (text: string) => { for (const ch of text) press(ch); press("Enter"); };
const screen = () => core().call<{ lines: string[] }>({ op: "session.text", id: session }).lines.filter(line => line.trim()).join("\n");
type("ping -t 127.0.0.1");
await sleep(3000);
press("c", { ctrlKey: true });
await sleep(2000);
type("echo after-ctrl-c");
await sleep(2000);
const text = screen();
console.log(text.split("\n").slice(-8).join("\n"));
console.log(text.includes("after-ctrl-c\n") || /\nafter-ctrl-c/.test(text) ? "CTRL-C OK" : "CTRL-C BROKEN");
test.close();
process.exit();
