// Step-3 check: a local shell in a real window. Opens cmd.exe (or sh), types a command through
// the same core calls the keyboard handler makes, and asserts on the terminal's own text.
//   SPIKE_RENDERER=cpu bun scripts/terminal-check.tsx    capture shows the terminal's pixels
//   bun scripts/terminal-check.tsx                       D3D11: capture cannot see the surface
// It does not cover Tarve delivering physical key presses; see docs/spike.md.
import { Window, createTestRenderer, darkTheme, type Renderer } from "@tarve/core";
import { join } from "node:path";
import { nextCoreEvent, onCoreEvent, type CoreEvent } from "../app/core/events";
import { core, termioCore, type Modifiers } from "../app/core/plugin";
import { TerminalPane } from "../app/views/TerminalPane";

const renderer = (process.env.SPIKE_RENDERER ?? "auto") as Renderer;
const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
const NONE: Modifiers = { shiftKey: false, altKey: false, ctrlKey: false, metaKey: false };
const MARKER = "termio-local-ok";
let session: number | undefined;

function View() {
  return (
    <Window title="Termio terminal check" width={720} height={420} theme={darkTheme}>
      {session === undefined ? null : <TerminalPane session={session} />}
    </Window>
  );
}

const test = await createTestRenderer(View, { plugins: [termioCore], keyboardEvents: true, pointerEvents: true, renderer });
const coreEvents: CoreEvent[] = [];
onCoreEvent(event => { coreEvents.push(event); });

const checks: Record<string, boolean> = {};
const result: Record<string, unknown> = { renderer, checks };
const screen = () => core().call<{ lines: string[] }>({ op: "session.text", id: session }).lines;
const frames = () => core().call<{ frames: number }>({ op: "session.stats", id: session }).frames;
const press = (key: string) => core().key(session!, { ...NONE, phase: "down", key });
async function until(what: string, test: () => boolean, timeoutMs = 10000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (test()) return (checks[what] = true);
    await sleep(50);
  }
  return (checks[what] = false);
}

try {
  const program = process.platform === "win32" ? "cmd.exe" : "/bin/sh";
  const ready = nextCoreEvent(event => event.type === "surface.ready" || event.type === "surface.error", 8000);
  session = core().call<{ id: number }>({ op: "session.open", kind: "local", program }).id;
  test.app.update();
  const first = await ready;
  checks.surfaceReady = first.type === "surface.ready";
  if (!checks.surfaceReady) throw new Error(`surface did not come up: ${first.message}`);

  await until("promptAppears", () => screen().some(line => /[>$#]\s*$/.test(line)));
  for (const key of `echo ${MARKER}`) press(key);
  press("Enter");
  await until("commandOutputOnScreen", () => screen().some(line => line === MARKER));
  result.screen = screen().filter(line => line.length > 0);
  result.size = coreEvents.find(event => event.type === "session.size");

  const capture = join(process.env.EMPRYO_TMP ?? process.env.TEMP ?? ".", `termio-terminal-${renderer}.png`);
  await test.capture(capture);
  result.capture = capture;

  const beforeIdle = frames();
  await sleep(1500);
  result.idleFrames = frames() - beforeIdle;
  checks.noFramesWhileIdle = result.idleFrames === 0;

  const closed = nextCoreEvent(event => event.type === "session.closed", 10000).then(() => true, () => false);
  for (const key of "exit") press(key);
  press("Enter");
  checks.exitClosesSession = await closed;
} catch (error) {
  result.error = error instanceof Error ? error.message : String(error);
}
result.errors = coreEvents.filter(event => event.type.endsWith(".error"));
const failed = result.error !== undefined || Object.values(checks).some(ok => !ok) || Object.keys(checks).length < 5;
console.log(JSON.stringify(result, null, 2));
test.close();
process.exit(failed ? 1 : 0);
