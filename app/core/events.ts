/** An event from the native core: session state, surface state, prompts, progress. */
export interface CoreEvent {
  type: string;
  session?: number;
  message?: string;
  [key: string]: unknown;
}

type Listener = (event: CoreEvent) => void;
const listeners = new Set<Listener>();

/** Subscribes to core events; returns the unsubscribe. */
export function onCoreEvent(listener: Listener): () => void {
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}

/** Resolves with the first event `match` accepts, or rejects after `timeoutMs`. */
export function nextCoreEvent(match: (event: CoreEvent) => boolean, timeoutMs = 5000): Promise<CoreEvent> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { off(); reject(new Error(`no matching core event within ${timeoutMs} ms`)); }, timeoutMs);
    const off = onCoreEvent(event => {
      if (!match(event)) return;
      clearTimeout(timer);
      off();
      resolve(event);
    });
  });
}

export function dispatchCoreEvent(event: CoreEvent): void {
  for (const listener of [...listeners]) listener(event);
}
