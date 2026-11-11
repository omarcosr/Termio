import { Input, Pressable, Row, Scroll, Surface, Text, type SurfaceEvent } from "@tarve/core";
import { dispatchCoreEvent } from "../core/events";
import { SURFACE_KIND, core, type KeyInput, type Modifiers, type PointerPhase } from "../core/plugin";
import { dialogs, previewAppearance, refresh, saveAppearance, toast, ui } from "../state/store";
import { Glyph } from "../ui/icons";
import { mono, touch } from "../ui/kit";
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
  clearSelection(session);
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
  clearSelection(session);
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

/** Two fingers pinching over a terminal change the font size, saved when they lift. */
let pinchFrom = 0;
export function pinchFont(event: { phase: "start" | "move" | "end"; scale: number }): void {
  if (event.phase === "start") pinchFrom = ui.appearance.fontSize;
  if (!pinchFrom) return;
  const size = Math.max(8, Math.min(28, Math.round(pinchFrom * event.scale)));
  if (event.phase === "end") {
    pinchFrom = 0;
    saveAppearance({ fontSize: size });
  } else if (size !== ui.appearance.fontSize) {
    previewAppearance({ fontSize: size });
  }
}

/** Pastes the clipboard into the session, as the desktop's Ctrl+Shift+V. */
function paste(session: number): void {
  const mods = { shiftKey: true, ctrlKey: true, altKey: false, metaKey: false };
  core().key(session, { ...mods, phase: "down", key: "v" });
  core().key(session, { ...mods, phase: "up", key: "v" });
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
      <Pressable
        focusable={false}
        onClick={() => paste(session)}
        control={{ role: "button", label: "Paste" }}
        style={{ height: 40, shrink: 0, padding: { left: 10, right: 10 }, align: "center", justify: "center", borderColor: color.line, borderWidth: { right: 1 } }}
      >
        <Text size={12.5} weight={600} color={color.muted}>Paste</Text>
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
  /** Where the surface's top-left sits in the window (layout pixels), learnt from a press. */
  originX: number;
  originY: number;
  /** The surface's width in layout pixels, to keep the action bar inside it. */
  width: number;
  height: number;
}

/** A touch selection as the overlay draws it: layout pixels relative to the surface. */
interface Selection {
  text: string;
  start: { x: number; y: number };
  end: { x: number; y: number };
  cell: { w: number; h: number };
}

/** Each pane's touch selection while its handles and actions show. */
export const selections = new Map<number, Selection>();

type Point = { x: number; y: number };

/** Runs a selection action in the core and keeps what it reports, in layout pixels. */
function select(session: number, action: string, args: Record<string, Point> = {}): Selection | undefined {
  const scale = pane(session).scale;
  const device = Object.fromEntries(Object.entries(args).map(([key, point]) => [key, { x: point.x * scale, y: point.y * scale }]));
  let reply: { selection: { text: string; start: Point; end: Point; cell: { w: number; h: number } } | null };
  try {
    reply = core().call({ op: "session.select", id: session, action, ...device });
  } catch {
    return undefined;
  }
  const view = reply.selection;
  if (!view) {
    selections.delete(session);
    return undefined;
  }
  const shown: Selection = {
    text: view.text,
    start: { x: view.start.x / scale, y: view.start.y / scale },
    end: { x: view.end.x / scale, y: view.end.y / scale },
    cell: { w: view.cell.w / scale, h: view.cell.h / scale },
  };
  selections.set(session, shown);
  return shown;
}

/** Selects as a long press or the bar would (scripts/ui-check.tsx). */
export function selectForTest(session: number, action: string, at?: Point): void {
  select(session, action, at ? { at } : {});
  refresh();
}

/** Drops the selection of whichever pane shows one; false when none does (Android Back). */
export function dropSelection(): boolean {
  const [session] = selections.keys();
  if (session === undefined) return false;
  clearSelection(session);
  return true;
}

/** Drops a pane's selection (a tap elsewhere, typing, an action done). */
export function clearSelection(session: number): void {
  if (!selections.has(session)) return;
  selections.delete(session);
  try { core().call({ op: "session.select", id: session, action: "clear" }); } catch { /* gone */ }
  refresh();
}

/** The press of a finger waiting to be told apart: a tap releases at once, a long press does not. */
let pending: { session: number; input: Modifiers & { button?: number }; timer: ReturnType<typeof setTimeout> } | undefined;
let longPressing: number | undefined;
/** A long press just ended: the tap the pane sees on lift must not bring the keyboard up. */
let longPressEnded = 0;

/** Whether a tap on the pane should open the keyboard: not to end a long press, nor while a selection shows. */
export function tapOpensKeyboard(session: number): boolean {
  return !selections.has(session) && Date.now() - longPressEnded > 400;
}

/**
 * Touch screens: Tarve sends a tap as a press and a release together, and a long press as a
 * press alone, the release coming when the finger lifts. A press with no release right after it
 * is a long press: it selects the word under the finger, moves extend it by words, and when the
 * finger lifts the selection gets handles and a bar of actions, as Android text does. A tap is a
 * click (a program that reads the mouse gets it) and drops the selection.
 */
export function touchPointer(session: number, phase: PointerPhase, input: Modifiers & { button?: number; deltaY?: number; x: number; y: number }): void {
  const state = pane(session);
  if (phase === "down") {
    state.originX = input.x - state.x;
    state.originY = input.y - state.y;
    if (pending) clearTimeout(pending.timer);
    pending = {
      session,
      input,
      timer: setTimeout(() => {
        pending = undefined;
        longPressing = session;
        select(session, "word", { at: { x: state.x, y: state.y } });
        refresh();
      }, 90),
    };
    return;
  }
  if (phase === "up") {
    if (pending?.session === session) {
      clearTimeout(pending.timer);
      const press = pending.input;
      pending = undefined;
      // A tap with a selection showing only drops it, as on Android.
      if (selections.has(session)) {
        clearSelection(session);
        longPressEnded = Date.now();
        return;
      }
      forwardPointer(session, "down", press);
      forwardPointer(session, "up", input);
      return;
    }
    if (longPressing === session) {
      longPressing = undefined;
      longPressEnded = Date.now();
      forwardPointer(session, "up", input);
      select(session, "get");
      refresh();
      return;
    }
  }
  forwardPointer(session, phase, input);
  // The text moved under the selection: the handles follow it.
  if (phase === "wheel" && selections.has(session)) {
    select(session, "get");
    refresh();
  }
}

/** A handle dragged: the point it stands for is above the finger, on the text it marks. */
let dragging: { session: number; which: "start" | "end"; dx: number; dy: number } | undefined;

function handleStart(session: number, which: "start" | "end", at: Point): void {
  const shown = selections.get(session);
  if (!shown) return;
  const state = pane(session);
  const local = { x: at.x - state.originX, y: at.y - state.originY };
  const mark = which === "start"
    ? { x: shown.start.x + shown.cell.w / 2, y: shown.start.y + shown.cell.h / 2 }
    : { x: shown.end.x - shown.cell.w / 2, y: shown.end.y - shown.cell.h / 2 };
  dragging = { session, which, dx: mark.x - local.x, dy: mark.y - local.y };
}

function handleMove(at: Point): void {
  if (!dragging) return;
  const { session, which, dx, dy } = dragging;
  const shown = selections.get(session);
  if (!shown) return;
  const state = pane(session);
  const point = { x: at.x - state.originX + dx, y: at.y - state.originY + dy };
  const start = { x: shown.start.x + shown.cell.w / 2, y: shown.start.y + shown.cell.h / 2 };
  const end = { x: shown.end.x - shown.cell.w / 2, y: shown.end.y - shown.cell.h / 2 };
  const moved = which === "start" ? select(session, "range", { from: point, to: end }) : select(session, "range", { from: start, to: point });
  // Dragged past the other handle: the two swap, as on Android.
  if (moved && which === "start" && (point.y > end.y + shown.cell.h / 2 || (Math.abs(point.y - end.y) < shown.cell.h / 2 && point.x > end.x))) dragging.which = "end";
  else if (moved && which === "end" && (point.y < start.y - shown.cell.h / 2 || (Math.abs(point.y - start.y) < shown.cell.h / 2 && point.x < start.x))) dragging.which = "start";
  refresh();
}

const HANDLE = 22;

/**
 * A teardrop under one end of the selection, dragged to move that end. Its point touches the
 * bottom corner of the text it marks: the start's points up-right, the end's up-left, as on
 * Android. At an edge of the pane, where the drop would not fit, it turns the other way.
 */
function Handle({ session, which, at }: { session: number; which: "start" | "end"; at: Point }) {
  const state = pane(session);
  const pad = 8;
  const pointsLeft = which === "end" ? at.x + HANDLE <= state.width : at.x - HANDLE < 0;
  // The drop's corner, the point, sits exactly on `at`; the touch area reaches `pad` around it.
  const dropX = pointsLeft ? at.x : at.x - HANDLE;
  const top = Math.min(at.y, state.height - HANDLE);
  const round = HANDLE / 2;
  return (
    <Pressable
      focusable={false}
      draggable
      onDragStart={position => handleStart(session, which, position)}
      onDragMove={event => handleMove(event)}
      onDragEnd={() => { dragging = undefined; }}
      control={{ role: "button", label: which === "start" ? "Selection start" : "Selection end" }}
      style={{ position: "absolute", left: Math.max(0, Math.min(dropX - pad, state.width - HANDLE - pad * 2)), top, width: HANDLE + pad * 2, height: HANDLE + pad, padding: { left: Math.min(pad, Math.max(0, dropX)), right: pad, bottom: pad } }}
    >
      <Row style={{ width: HANDLE, height: HANDLE, background: color.accent, radius: pointsLeft ? { topLeft: 0, topRight: round, bottomLeft: round, bottomRight: round } : { topLeft: round, topRight: 0, bottomLeft: round, bottomRight: round } }} />
    </Pressable>
  );
}

/** Copy the selection to the clipboard and let it go. */
function copySelection(session: number): void {
  const shown = selections.get(session);
  if (!shown) return;
  try {
    core().call({ op: "clipboard.set", text: shown.text });
    toast("Copied");
  } catch {
    toast("Could not reach the clipboard", "error");
  }
  clearSelection(session);
}

function ToolbarAction({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <Pressable focusable={false} onClick={onClick} control={{ role: "button", label }} style={{ height: 40, padding: { left: 14, right: 14 }, align: "center", justify: "center", radius: radius.control, hover: { background: color.hover } }}>
      <Text size={13.5} weight={600} color={color.text} style={{ whiteSpace: "nowrap" }}>{label}</Text>
    </Pressable>
  );
}

/**
 * Android-style selection over a pane: handles at both ends and a floating bar of actions
 * above the text (below it when the text is at the top), kept inside the pane.
 */
export function SelectionOverlay({ session }: { session: number }) {
  const shown = selections.get(session);
  const width = pane(session).width;
  if (!shown) return null;
  const toolbarWidth = 248;
  const above = shown.start.y - 56;
  const top = Math.max(4, Math.min(above >= 4 ? above : shown.end.y + HANDLE + 12, pane(session).height - 48));
  const middle = (shown.start.x + shown.end.x) / 2;
  const left = Math.max(4, Math.min(middle - toolbarWidth / 2, width - toolbarWidth - 4));
  return (
    <>
      <Handle session={session} which="start" at={{ x: shown.start.x, y: shown.start.y + shown.cell.h }} />
      <Handle session={session} which="end" at={{ x: shown.end.x, y: shown.end.y }} />
      <Row
        align="center"
        style={{ position: "absolute", left, top, height: 44, padding: { left: 2, right: 2 }, background: color.raised, radius: 22, borderColor: color.lineStrong, borderWidth: 1, boxShadow: { y: 6, blur: 18, color: "#00000080" } }}
      >
        <ToolbarAction label="Copy" onClick={() => copySelection(session)} />
        <ToolbarAction label="Paste" onClick={() => { clearSelection(session); paste(session); }} />
        <ToolbarAction label="Select all" onClick={() => { select(session, "all"); refresh(); }} />
      </Row>
    </>
  );
}

const panes = new Map<number, PaneState>();
const NO_MODIFIERS: Modifiers = { shiftKey: false, altKey: false, ctrlKey: false, metaKey: false };

function pane(session: number): PaneState {
  let state = panes.get(session);
  if (!state) {
    state = { scale: 1, x: 0, y: 0, originX: 0, originY: 0, width: 360, height: 600 };
    panes.set(session, state);
  }
  return state;
}

function onSurface(session: number, event: SurfaceEvent): void {
  pane(session).scale = event.scale;
  if (event.type === "resize") {
    core().resize(session, event.width, event.height, event.scale);
    // A resize (the keyboard opening) reflows the screen and drops the selection: the handles go too.
    if (selections.has(session)) {
      select(session, "get");
      refresh();
    }
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
  // A finger drags the text along with it: one line per line height moved, where a mouse
  // wheel's notch (100 px) moves three lines.
  if (phase === "wheel" && touch() && input.deltaY) input = { ...input, deltaY: input.deltaY * 100 / (3 * ui.appearance.fontSize * 1.3) };
  core().pointer(session, { ...input, phase, x: state.x * state.scale, y: state.y * state.scale });
}

/** A session's terminal: the native core paints and presents it into this surface. */
export function TerminalPane({ session }: { session: number }) {
  return (
    <Surface
      id={terminalNodeId(session)}
      style={{ flex: 1 }}
      onSurface={event => onSurface(session, event)}
      onSize={size => { pane(session).width = size.width; pane(session).height = size.height; }}
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
