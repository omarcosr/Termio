// Step-2 spike: measures the risky paths with a real window and prints what it found.
//   bun scripts/spike.tsx                        default renderer (D3D11 on Windows)
//   SPIKE_RENDERER=cpu bun scripts/spike.tsx      the TarveFrames path
//   SPIKE_HOLD_MS=20000 bun scripts/spike.tsx     keeps the window open: type and scroll in it
//
// What the automated part can and cannot show: Tarve's scripted input synthesizes pointer
// down/up events only. Scripted keys and wheel turns never become `keyboard`/`pointer` app
// events, so keyboard and wheel coverage needs real input (SPIKE_HOLD_MS) and is reported as
// untested otherwise.
import { Window, createTestRenderer, darkTheme, type Renderer } from "@tarve/core";
import { existsSync, statSync } from "node:fs";
import { join } from "node:path";
import { nextCoreEvent, onCoreEvent, type CoreEvent } from "../app/core/events";
import { core, termioCore } from "../app/core/plugin";
import { TerminalPane, terminalNodeId } from "../app/views/TerminalPane";

const renderer = (process.env.SPIKE_RENDERER ?? "auto") as Renderer;
const holdMs = Number(process.env.SPIKE_HOLD_MS ?? 0);
const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
let session: number | undefined;

function View() {
  return (
    <Window title="Termio spike" width={640} height={360} theme={darkTheme}>
      {session === undefined ? null : <TerminalPane session={session} />}
    </Window>
  );
}

const test = await createTestRenderer(View, { plugins: [termioCore], keyboardEvents: true, pointerEvents: true, renderer });
const coreEvents: CoreEvent[] = [];
onCoreEvent(event => { coreEvents.push(event); });
const surfaces: { event: string; handleType?: string; width: number; height: number; scale: number; message?: string }[] = [];
const keyboard: { phase: string; key: string; code: string; repeat: boolean; mods: string }[] = [];
const pointers: { phase: string; id: string | null; button?: number; deltaY?: number }[] = [];

session = core().call<{ id: number }>({ op: "session.open", kind: "echo" }).id;
const frames = () => core().call<{ frames: number }>({ op: "session.stats", id: session }).frames;
test.app.onEvent(event => {
  if (event.type === "surface") surfaces.push({ event: event.event, handleType: event.handleType, width: event.width, height: event.height, scale: event.scale, message: event.message });
  if (event.type === "keyboard") {
    const mods = [event.ctrlKey && "ctrl", event.altKey && "alt", event.shiftKey && "shift", event.metaKey && "meta"].filter(Boolean).join("+");
    keyboard.push({ phase: event.phase, key: event.key, code: event.code, repeat: event.repeat, mods });
    core().key(session!, event);
  }
  if (event.type === "pointer") pointers.push({ phase: event.phase, id: event.id, button: event.button, deltaY: event.deltaY });
});

const result: Record<string, unknown> = { renderer };
let failed = false;
try {
  const ready = nextCoreEvent(event => event.type === "surface.ready" || event.type === "surface.error", 8000);
  test.app.update();
  const first = await ready;
  if (first.type !== "surface.ready") throw new Error(`surface did not come up: ${first.message}`);
  result.coreEventFromRenderThread = true;

  const afterAttach = frames();
  core().text(session, "hello from rust");
  await sleep(300);
  const afterText = frames();

  await test.getById(terminalNodeId(session)).click();
  await sleep(200);

  const capture = join(process.env.EMPRYO_TMP ?? process.env.TEMP ?? ".", `termio-spike-${renderer}.png`);
  try {
    await test.capture(capture);
    result.capture = existsSync(capture) ? { path: capture, bytes: statSync(capture).size } : "capture wrote no file";
  } catch (error) {
    result.capture = `capture failed: ${error instanceof Error ? error.message : String(error)}`;
  }

  const beforeIdle = frames();
  await sleep(1500);
  const afterIdle = frames();

  Object.assign(result, {
    frames: { afterAttach, afterText, beforeIdle, afterIdle },
    textRepaints: afterText > afterAttach,
    idleFrames: afterIdle - beforeIdle,
    scriptedClickReachedApp: pointers.some(pointer => pointer.phase === "down") && pointers.some(pointer => pointer.phase === "up"),
  });
  if (!(afterText > afterAttach) || afterIdle !== beforeIdle) failed = true;

  if (holdMs > 0) {
    console.error(`holding the window for ${holdMs} ms: type, hold a key, use AltGr and dead keys, paste, scroll`);
    const before = frames();
    await sleep(holdMs);
    Object.assign(result, {
      realInput: { keyboardEvents: keyboard.length, wheelEvents: pointers.filter(pointer => pointer.phase === "wheel").length, framesWhileHeld: frames() - before },
      keyboard,
    });
  } else {
    result.realInput = "untested: scripted input does not produce keyboard or wheel events; run with SPIKE_HOLD_MS";
  }
} catch (error) {
  failed = true;
  result.error = error instanceof Error ? error.message : String(error);
}
result.pointers = pointers;
result.surfaces = surfaces;
result.coreEvents = coreEvents;
console.log(JSON.stringify(result, null, 2));
test.close();
process.exit(failed ? 1 : 0);
