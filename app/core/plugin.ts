// The native core (crates/termio-core) as a Tarve plugin: opens the library, binds its C ABI
// and exposes a typed client. Terminal pixels never pass through here: the core presents them
// straight into the <surface>; this side carries control requests, input and events.
import { definePlugin } from "@tarve/core";
import { existsSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { dispatchCoreEvent, type CoreEvent } from "./events";

const ABI_VERSION = 2;

/** C ABI of crates/termio-core/src/ffi.rs. */
const SYMBOLS = {
  termio_abi_version: { args: [], returns: "u32" },
  termio_init: { args: ["ptr"], returns: "i32" },
  termio_call: { args: ["buffer", "u32", "buffer", "u32"], returns: "i32" },
  termio_take_response: { args: ["buffer", "u32"], returns: "i32" },
  termio_surface_attach: { args: ["u32", "u64", "u32", "u32", "u32", "f32"], returns: "i32" },
  termio_surface_resize: { args: ["u32", "u32", "u32", "f32"], returns: "i32" },
  termio_surface_detach: { args: ["u32"], returns: "i32" },
  termio_key: { args: ["u32", "u32", "buffer", "u32", "u32"], returns: "i32" },
  termio_text: { args: ["u32", "buffer", "u32"], returns: "i32" },
  termio_pointer: { args: ["u32", "u32", "f32", "f32", "i32", "f32", "u32"], returns: "i32" },
} as const;

export interface Modifiers {
  shiftKey: boolean;
  altKey: boolean;
  ctrlKey: boolean;
  metaKey: boolean;
}

export interface KeyInput extends Modifiers {
  phase: "down" | "up";
  /** DOM `key` value. */
  key: string;
}

export type PointerPhase = "down" | "up" | "wheel" | "move";

export interface PointerInput extends Modifiers {
  phase: PointerPhase;
  /** Device pixels from the surface's top-left corner. */
  x: number;
  y: number;
  button?: number;
  /** Wheel turn in layout pixels. */
  deltaY?: number;
}

/** How a `<surface>` presents, as the core numbers it. */
export const SURFACE_KIND = { TarveFrames: 0, ISwapChainPanelNative: 1 } as const;

export interface Core {
  /** Runs a control request; throws with the core's message when it fails. */
  call<T = Record<string, unknown>>(request: { op: string } & Record<string, unknown>): T;
  attach(session: number, handle: bigint, kind: number, width: number, height: number, scale: number): void;
  resize(session: number, width: number, height: number, scale: number): void;
  detach(session: number): void;
  key(session: number, input: KeyInput): void;
  /** Text that is not a key press: a paste or an IME commit. */
  text(session: number, text: string): void;
  pointer(session: number, input: PointerInput): void;
}

let client: Core | undefined;

/** The core client; available once the app's plugins are set up. */
export function core(): Core {
  if (!client) throw new Error("termio core is not loaded: pass termioCore to createApp({ plugins })");
  return client;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const PHASES: Record<PointerPhase, number> = { down: 0, up: 1, wheel: 2, move: 3 };

/** UTF-8 bytes and their length; never an empty view, so the address is always valid. */
function utf8(text: string): [Uint8Array, number] {
  const bytes = encoder.encode(text);
  return bytes.length ? [bytes, bytes.length] : [new Uint8Array(1), 0];
}

function modifiers(input: Modifiers): number {
  return (input.shiftKey ? 1 : 0) | (input.altKey ? 2 : 0) | (input.ctrlKey ? 4 : 0) | (input.metaKey ? 8 : 0);
}

/**
 * The core library: TERMIO_CORE, else the newer of this checkout's release and debug builds,
 * else (in a built executable) the copy `tarve build` embedded from package.json `tarve.native`.
 */
function libraryPath(root: string): string | undefined {
      if (process.env.TERMIO_CORE) return process.env.TERMIO_CORE;
      const name = process.platform === "win32" ? "termio_core.dll" : "libtermio_core.so";
      const built = ["release", "debug"].map(profile => join(root, "target", profile, name)).filter(path => existsSync(path));
      return built.sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs)[0];
}

export const termioCore = definePlugin({
  name: "termio",
  version: "0.1.0",
  namespace: "termio",
  tarvePluginApi: 1,
  root: join(import.meta.dirname, "..", ".."),
  setup(ctx) {
    const local = libraryPath(join(import.meta.dirname, "..", ".."));
    const library = local ? ctx.loadLibrary(local, SYMBOLS) : ctx.loadLibrary(SYMBOLS);
    const native = library.symbols;
    const abi = native.termio_abi_version();
    if (abi !== ABI_VERSION) throw new Error(`termio core ABI ${abi}, expected ${ABI_VERSION} (${library.path})`);

    // Core events arrive on Tarve's plugin channel, one JSON document each, from any core thread.
    const off = ctx.events("termio.events").on(bytes => dispatchCoreEvent(JSON.parse(decoder.decode(bytes)) as CoreEvent));
    // Events emitted before the app starts wait in Tarve and arrive once it is up.
    const started = native.termio_init(ctx.emitAddress());
    if (started !== 0) throw new Error(`termio core failed to start (${started})`);
    ctx.onClosed(() => {
      client = undefined;
      off();
    });

    // Bun's FFI takes a u64 as bigint; txiki.js and QuickJS take numbers.
    const bunFfi = typeof (globalThis as { Bun?: unknown }).Bun !== "undefined";
    let response = new Uint8Array(64 * 1024);
    const check = (code: number, what: string) => {
      if (code < 0 && code !== -3) throw new Error(`termio core: ${what} failed (${code})`);
    };
    client = {
      call<T>(request: { op: string } & Record<string, unknown>): T {
        const [body, length] = utf8(JSON.stringify(request));
        let written = native.termio_call(body, length, response, response.length);
        if (written < 0 && written > -100) throw new Error(`termio core: ${request.op} failed (${written})`);
        if (written <= -100) {
          response = new Uint8Array(-written);
          written = native.termio_take_response(response, response.length);
        }
        const result = JSON.parse(decoder.decode(response.subarray(0, written))) as { ok: boolean; error?: string };
        if (!result.ok) throw new Error(`${request.op}: ${result.error ?? "failed"}`);
        return result as T;
      },
      attach: (session, handle, kind, width, height, scale) => check(native.termio_surface_attach(session, bunFfi ? handle : Number(handle), kind, width, height, scale), "surface attach"),
      resize: (session, width, height, scale) => check(native.termio_surface_resize(session, width, height, scale), "surface resize"),
      detach: session => { native.termio_surface_detach(session); },
      key(session, input) {
        const [key, keyLength] = utf8(input.key);
        const down = input.phase === "down" ? 1 : 0;
        check(native.termio_key(session, down, key, keyLength, modifiers(input)), "key");
      },
      text(session, text) {
        const [bytes, length] = utf8(text);
        check(native.termio_text(session, bytes, length), "text");
      },
      pointer: (session, input) => check(native.termio_pointer(session, PHASES[input.phase], input.x, input.y, input.button ?? -1, input.deltaY ?? 0, modifiers(input)), "pointer"),
    };
  },
});
