// Exercises ~/.ssh/config import and terminal search through the real core: bun scripts/features-check.tsx
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const dir = mkdtempSync(join(tmpdir(), "termio-features-"));
process.env.TERMIO_VAULT = join(dir, "vault.termio");
// A fake home with an ssh config, so the user's real one is untouched.
mkdirSync(join(dir, ".ssh"));
writeFileSync(join(dir, ".ssh", "config"), "Host *\n  User x\nHost web\n  HostName 10.0.0.5\n  User deploy\n  Port 2222\nHost db\n  HostName db.internal\n  ProxyJump web\n");
process.env.USERPROFILE = dir;
process.env.HOME = dir;

const { core, termioCore } = await import("../app/core/plugin");
const { createTestRenderer, Window } = await import("@tarve/core");
const { Root } = await import("../app/views/Shell");
const store = await import("../app/state/store");
const test = await createTestRenderer(() => <Window title="t" width={900} height={600}><Root /></Window>, { plugins: [termioCore], renderer: "cpu" });
store.setRenderer(() => test.app.update());
store.listen();
store.loadStatus();
store.createVault("termio-feature-test", "termio-feature-test");
const failures: string[] = [];
const check = (ok: boolean, what: string) => { console.log(`${ok ? "ok  " : "FAIL"} ${what}`); if (!ok) failures.push(what); };

const scanned = store.scanSshConfig() ?? [];
check(scanned.length === 2 && scanned[0]!.port === 2222, `ssh config scanned: ${JSON.stringify(scanned)}`);
store.importSshHosts(scanned, false);
const web = store.ui.hosts.find(host => host.data.name === "web");
const db = store.ui.hosts.find(host => host.data.name === "db");
check(Boolean(web && db && db.data.jump === web.id && db.data.group === "Imported"), "hosts imported, ProxyJump resolved to the web host");

store.openLocal();
await new Promise(resolve => setTimeout(resolve, 3000));
const session = store.focusedSession()!;
core().key(session, { phase: "down", key: "x", ctrlKey: false, altKey: false, shiftKey: false, metaKey: false });
for (const ch of "echo needle-1 needle-2\r") core().key(session, { phase: "down", key: ch === "\r" ? "Enter" : ch, ctrlKey: false, altKey: false, shiftKey: false, metaKey: false });
await new Promise(resolve => setTimeout(resolve, 2000));
const found = core().call<{ count: number }>({ op: "session.search", id: session, query: "NEEDLE" }).count;
check(found >= 4, `search found ${found} matches (command line and its output)`);
core().call({ op: "session.searchNext", id: session, backwards: true });
core().call({ op: "session.searchClear", id: session });
test.close();
process.exit(failures.length ? 1 : 0);
