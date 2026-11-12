// How much work one keystroke in a text field costs: renders per key and the time each takes.
//   bun scripts/input-bench.tsx            (UI_SIZE=360x740 TERMIO_TOUCH=1 for the phone layout)
import { Window, createTestRenderer, darkTheme } from "@tarve/core";
import { appendFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const dir = mkdtempSync(join(tmpdir(), "termio-bench-"));
process.env.TERMIO_VAULT = join(dir, "vault.termio");

const { core, termioCore } = await import("../app/core/plugin");
const store = await import("../app/state/store");
const { Root } = await import("../app/views/Shell");
const { color, font } = await import("../app/ui/tokens");

const [width, height] = (process.env.UI_SIZE ?? "360x740").split("x").map(Number);
let renders = 0;
function App() {
  renders++;
  return (
    <Window title="Termio" width={width} height={height} theme={darkTheme} style={{ background: color.canvas, fontFamily: font.ui, foreground: color.text }}>
      <Root />
    </Window>
  );
}

const test = await createTestRenderer(App, { plugins: [termioCore], renderer: "cpu", keyboardEvents: true, pointerEvents: true });
let updates = 0;
let updateTime = 0;
store.setRenderer(() => {
  const start = performance.now();
  test.app.update();
  updateTime += performance.now() - start;
  updates++;
});
store.listen();
store.loadStatus();
await test.waitForIdle();

async function bench(screen: string, id: string) {
  const field = test.getById(id);
  await field.waitFor();
  await field.click();
  await test.waitForIdle();
  const text = "correct horse battery staple ".repeat(Number(process.env.REPEAT ?? 1));
  renders = updates = updateTime = 0;
  const start = performance.now();
  for (const ch of text) {
    test.app.debug({ type: "input", action: "text", text: ch });
    await new Promise(resolve => setTimeout(resolve, 0));
  }
  await test.waitForIdle();
  const total = performance.now() - start;
  const node = await field.node();
  const typed = (((node as { value?: string }).value ?? node.text) ?? "").length;
  const line = JSON.stringify({ screen, keys: text.length, typed, rendersPerKey: +(renders / text.length).toFixed(2), wallMsPerKey: +(total / text.length).toFixed(2) });
  console.log(line);
  if (process.env.BENCH_OUT) appendFileSync(process.env.BENCH_OUT, line + "\n");
}

await bench("unlock", "master-password");
store.createVault("correct horse battery staple", "correct horse battery staple");
for (let index = 0; index < Number(process.env.HOSTS ?? 40); index++) {
  core().call({ op: "records.put", kind: "host", data: { name: `host ${index}`, address: `10.0.0.${index}`, port: 22, user: "root", group: index % 3 ? "prod" : "dev", color: "slate" } });
}
store.loadStatus();
store.newHost();
await test.waitForIdle();
await bench("host editor", "host-name");
test.close();
rmSync(dir, { recursive: true, force: true });
process.exit(0);
