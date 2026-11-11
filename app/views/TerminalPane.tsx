import { Input, Pressable, Row, Scroll, Surface, Text, type SurfaceEvent } from "@tarve/core";
import { dispatchCoreEvent } from "../core/events";
import { SURFACE_KIND, core, type KeyInput, type Modifiers, type PointerPhase } from "../core/plugin";
import { dialogs, refresh } from "../state/store";
import { Glyph } from "../ui/icons";
import { mono } from "../ui/kit";
import { color, radius } from "../ui/tokens";

/** The node id of a session's surface: pointer and keyboard events name it. */
export const terminalNodeId = (session: number) => `terminal-${session}`;

/** The session a surface node id belongs to, if it is a terminal's. */
export function sessionOfNode(id: string | null): number | undefined {
  const match = id ? /^terminal-(\d+)$/.exec(id) : null;
  return match ? Number(match[1]) : undefined;
}

/** The hidden text field that holds the soft keyboard for a session on a touch screen. */
export const imeNodeId = (session: number) => `terminal-ime-${session}`;

export function sessionOfIme(id: string | null): number | undefined {
  const match = id ? /^terminal-ime-(\d+)$/.exec(id) : null;
  return match ? Number(match[1]) : undefined;
}

/** Brings up the soft keyboard for a session: its hidden field takes the focus. */
export function openKeyboard(session: number): void {
  dialogs.focus(imeNodeId(session));
}

/** Ctrl and Alt from the extra-keys row: they hold for the next key, then let go. */
const latched = { ctrl: false, alt: false };

function sendKey(session: number, key: string, mods: Modifiers = NO_MODIFIERS): void {
  const held = { ...mods, ctrlKey: mods.ctrlKey || latched.ctrl, altKey: mods.altKey || latched.alt };
  core().key(session, { ...held, phase: "down", key });
  core().key(session, { ...held, phase: "up", key });
  if (latched.ctrl || latched.alt) {
    latched.ctrl = latched.alt = false;
    refresh();
  }
}

/** Text the soft keyboard typed. A latched Ctrl or Alt turns its first character into a chord. */
function typeText(session: number, text: string): void {
  if (!text) return;
  if (latched.ctrl || latched.alt) {
    const [first, ...rest] = Array.from(text);
    sendKey(session, first!);
    text = rest.join("");
    if (!text) return;
  }
  core().text(session, text.replace(/\r?\n/g, "\r"));
}

/**
 * A key event of the hidden field. Printable keys are skipped: the field reports what they typed
 * (with suggestions and pastes) through onChange. Returns true when the key went to the session.
 */
export function imeKey(session: number, event: KeyInput): boolean {
  const printable = Array.from(event.key).length === 1 && !event.ctrlKey && !event.metaKey;
  if (printable) return false;
  if (event.phase === "up") return false;
  sendKey(session, event.key, event);
  return true;
}

/** The keys a phone keyboard lacks, as the first row over it. */
const EXTRA: { key: string; label: string; latch?: "ctrl" | "alt" }[] = [
  { key: "Escape", label: "Esc" },
  { key: "Tab", label: "Tab" },
  { key: "Control", label: "Ctrl", latch: "ctrl" },
  { key: "Alt", label: "Alt", latch: "alt" },
  { key: "ArrowLeft", label: "←" },
  { key: "ArrowDown", label: "↓" },
  { key: "ArrowUp", label: "↑" },
  { key: "ArrowRight", label: "→" },
  { key: "|", label: "|" },
  { key: "~", label: "~" },
  { key: "/", label: "/" },
  { key: "-", label: "-" },
  { key: "Home", label: "Home" },
  { key: "End", label: "End" },
  { key: "PageUp", label: "PgUp" },
  { key: "PageDown", label: "PgDn" },
];

/**
 * Touch screens: the hidden field the soft keyboard types into, and a row of the keys it lacks.
 * The field stays empty (a controlled value of ""), so every change is new text for the session.
 */
export function SoftKeyboard({ session }: { session: number }) {
  return (
    <Row align="center" style={{ height: 40, shrink: 0, background: color.panel, borderColor: color.line, borderWidth: { top: 1 } }}>
      <Input
        id={imeNodeId(session)}
        value=""
        onChange={text => { typeText(session, text); refresh(); }}
        style={{ position: "absolute", left: 0, top: 0, width: 1, height: 1, opacity: 0 }}
      />
      <Pressable
        focusable={false}
        onClick={() => openKeyboard(session)}
        control={{ role: "button", label: "Show keyboard" }}
        style={{ width: 44, height: 40, shrink: 0, align: "center", justify: "center", borderColor: color.line, borderWidth: { right: 1 } }}
      >
        <Glyph name="terminal" size={17} color={color.accent} />
      </Pressable>
      <Scroll orientation="horizontal" flex={1} style={{ minWidth: 0, height: 40, overflow: "hidden", scrollbarWidth: "none" }}>
        <Row gap={4} align="center" style={{ height: 40, padding: { left: 6, right: 6 } }}>
          {EXTRA.map(item => {
            const on = item.latch ? latched[item.latch] : false;
            return (
              <Pressable
                key={item.key}
                focusable={false}
                onClick={() => {
                  if (item.latch) {
                    latched[item.latch] = !latched[item.latch];
                    refresh();
                  } else {
                    sendKey(session, item.key);
                  }
                }}
                control={{ role: "button", label: item.label, ...(item.latch ? { selected: on } : {}) }}
                style={{ height: 30, minWidth: 40, padding: { left: 10, right: 10 }, align: "center", justify: "center", radius: radius.control, background: on ? color.accentSoft : color.raised, borderColor: on ? color.accent : color.line, borderWidth: 1 }}
              >
                <Text size={13} weight={600} color={on ? color.accent : color.text} style={{ ...mono, whiteSpace: "nowrap" }}>{item.label}</Text>
              </Pressable>
            );
          })}
        </Row>
      </Scroll>
    </Row>
  );
}

interface PaneState {
  /** Device pixels per layout pixel, from the surface. */
  scale: number;
  /** Last pointer position inside the surface, in layout pixels. */
  x: number;
  y: number;
}

const panes = new Map<number, PaneState>();
const NO_MODIFIERS: Modifiers = { shiftKey: false, altKey: false, ctrlKey: false, metaKey: false };

function pane(session: number): PaneState {
  let state = panes.get(session);
  if (!state) {
    state = { scale: 1, x: 0, y: 0 };
    panes.set(session, state);
  }
  return state;
}

function onSurface(session: number, event: SurfaceEvent): void {
  pane(session).scale = event.scale;
  if (event.type === "resize") {
    core().resize(session, event.width, event.height, event.scale);
  } else if (event.type === "ready" && event.handle) {
    const kind = event.handleType ? SURFACE_KIND[event.handleType as keyof typeof SURFACE_KIND] : undefined;
    if (kind === undefined) {
      dispatchCoreEvent({ type: "surface.error", session, message: `surface type ${event.handleType} is not supported` });
      return;
    }
    core().attach(session, BigInt(event.handle), kind, event.width, event.height, event.scale);
  } else {
    core().detach(session);
    if (event.type === "destroyed") panes.delete(session);
    if (event.type === "unsupported") dispatchCoreEvent({ type: "surface.error", session, message: event.message ?? "surface unsupported" });
  }
}

/**
 * Forwards an app-level pointer event (press, release, wheel) to the session. Those events carry
 * window coordinates, so the position is the last one the surface itself reported.
 */
export function forwardPointer(session: number, phase: PointerPhase, input: Modifiers & { button?: number; deltaY?: number }): void {
  const state = pane(session);
  core().pointer(session, { ...input, phase, x: state.x * state.scale, y: state.y * state.scale });
}

/** A session's terminal: the native core paints and presents it into this surface. */
export function TerminalPane({ session }: { session: number }) {
  return (
    <Surface
      id={terminalNodeId(session)}
      style={{ flex: 1 }}
      onSurface={event => onSurface(session, event)}
      onPointerMove={point => {
        const state = pane(session);
        state.x = point.x;
        state.y = point.y;
        // Motion carries no modifier state; the core only needs it while a button is held or
        // the program asked for motion reports.
        core().pointer(session, { ...NO_MODIFIERS, phase: "move", x: point.x * state.scale, y: point.y * state.scale });
      }}
    />
  );
}
