import { Surface, type SurfaceEvent } from "@tarve/core";
import { dispatchCoreEvent } from "../core/events";
import { SURFACE_KIND, core, type Modifiers, type PointerPhase } from "../core/plugin";

/** The node id of a session's surface: pointer and keyboard events name it. */
export const terminalNodeId = (session: number) => `terminal-${session}`;

/** The session a surface node id belongs to, if it is a terminal's. */
export function sessionOfNode(id: string | null): number | undefined {
  const match = id ? /^terminal-(\d+)$/.exec(id) : null;
  return match ? Number(match[1]) : undefined;
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
