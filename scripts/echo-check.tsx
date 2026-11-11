// Local echo over a real SSH session: typed characters must show before the server echoes them,
// never at a password prompt, and the server's echo must replace them.
//   TERMIO_ECHO_SSH="user:password@host:port" bun scripts/echo-check.tsx   (best on a slow link)
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const target = /^([^:]+):([^@]+)@([^:]+):(\d+)$/.exec(process.env.TERMIO_ECHO_SSH ?? "");
if (!target) throw new Error("set TERMIO_ECHO_SSH=user:password@host:port");
process.env.TERMIO_VAULT = join(mkdtempSync(join(tmpdir(), "termio-echo-")), "vault.termio");
const { core, termioCore } = await import("../app/core/plugin");
const { createTestRenderer, Window } = await import("@tarve/core");
const { Root } = await import("../app/views/Shell");
const store = await import("../app/state/store");
const test = await createTestRenderer(() => <Window title="t" width={1000} height={640}><Root /></Window>, { plugins: [termioCore], renderer: "cpu" });
store.setRenderer(() => test.app.update());
store.listen();
store.loadStatus();
store.createVault("termio-echo-test", "termio-echo-test");
setInterval(() => { for (const prompt of [...store.ui.prompts]) store.answerHostKey(prompt.request, true); }, 100);
const id = core().call<{ id: string }>({ op: "records.put", kind: "host", data: { name: "echo", user: target[1], password: target[2], address: target[3], port: Number(target[4]), agent: false } }).id;
store.reload();
store.connect(id);
const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
await sleep(6000);
const session = store.focusedSession()!;
const key = (k: string) => core().key(session, { phase: "down", key: k, ctrlKey: false, altKey: false, shiftKey: false, metaKey: false });
const screen = () => core().call<{ lines: string[] }>({ op: "session.text", id: session }).lines.join("\n");
const out = process.env.EMPRYO_TMP ?? tmpdir();
const failures: string[] = [];
const check = (ok: boolean, what: string) => { console.log(`${ok ? "ok  " : "FAIL"} ${what}`); if (!ok) failures.push(what); };

// Teach it the server echoes, then type a word and capture before the echo can come back.
key("e"); await sleep(1500); key("Backspace"); await sleep(1500);
for (const ch of "zqx") key(ch);
await sleep(30);
await test.capture(join(out, "echo-predicted.png"));
check(!screen().includes("zqx"), "the grid has no zqx yet: the server has not echoed");
await sleep(2000);
check(screen().includes("zqx"), "the server echo arrived and the grid has zqx");
for (let i = 0; i < 3; i++) key("Backspace");
await sleep(1500);

// A password prompt: after Enter nothing may be predicted.
for (const ch of "read -s secret") key(ch);
key("Enter");
await sleep(1500);
for (const ch of "hunter2") key(ch);
await sleep(30);
await test.capture(join(out, "echo-password.png"));
key("Enter");
await sleep(1500);
check(!screen().includes("hunter2"), "the typed password never reached the screen");
console.log(join(out, "echo-predicted.png"));
test.close();
process.exit(failures.length ? 1 : 0);
