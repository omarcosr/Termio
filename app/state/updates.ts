import { canInstallUpdate, checkForUpdate, downloadUpdate, installUpdate, openExternal, type Update } from "@tarve/core";
import pkg from "../../package.json";
import { refresh, toast } from "./store";

/**
 * Updates from GitHub Releases. Each release carries a `latest.json` signed with the key from
 * `tarve keygen` (scripts/release.ts publishes it); `releases/latest/download/` always serves the
 * newest one. The desktop app swaps its own executable and restarts; Android opens the APK download.
 */
const REPO = pkg.updates.repo;
const PUBLIC_KEY = pkg.updates.publicKey;
const MANIFEST = `https://github.com/${REPO}/releases/latest/download/latest.json`;
const ANDROID = (process.platform as string) === "android";
/** First check shortly after launch, then a few times a day while the app stays open. */
const FIRST_CHECK = 15_000;
const EVERY = 6 * 60 * 60_000;

export const version: string = pkg.version;

type UpdateState = "idle" | "checking" | "current" | "available" | "downloading" | "error";

export const updates = {
  state: "idle" as UpdateState,
  update: undefined as Update | undefined,
  received: 0,
  total: 0,
  error: undefined as string | undefined,
  checkedAt: 0,
};

/** Updates need the public key in package.json (`updates.publicKey`). */
export function updatesConfigured(): boolean {
  return PUBLIC_KEY.trim().length > 0;
}

/** Whether this copy can replace itself (a built executable in a writable folder). Android installs through the system. */
export function canSelfUpdate(): boolean {
  if (ANDROID || !updates.update) return false;
  try { return canInstallUpdate(updates.update); } catch { return false; }
}

export function releasePage(update = updates.update): string {
  return update ? `https://github.com/${REPO}/releases/tag/v${update.version}` : `https://github.com/${REPO}/releases/latest`;
}

/** Asks GitHub for the newest release; `quiet` (the background check) only speaks up when there is one. */
export async function checkUpdates(quiet = false): Promise<void> {
  if (!updatesConfigured() || updates.state === "checking" || updates.state === "downloading") return;
  updates.state = "checking";
  updates.error = undefined;
  refresh();
  try {
    const found = await checkForUpdate({ url: MANIFEST, publicKey: PUBLIC_KEY, currentVersion: version });
    const fresh = found && found.version !== updates.update?.version;
    updates.update = found ?? undefined;
    updates.state = found ? "available" : "current";
    updates.checkedAt = Date.now();
    if (found && (fresh || !quiet)) toast(`Termio ${found.version} is available: Settings › About`);
    else if (!quiet) toast("Termio is up to date");
  } catch (error) {
    updates.state = "error";
    updates.error = message(error);
    if (!quiet) toast(`Update check failed: ${updates.error}`, "error");
  }
  refresh();
}

/** Downloads and installs the update found by `checkUpdates`; the app restarts into it. */
export async function applyUpdate(): Promise<void> {
  const update = updates.update;
  if (!update || updates.state === "downloading") return;
  if (!canSelfUpdate()) return openPage(ANDROID ? update.url : releasePage(update));
  updates.state = "downloading";
  updates.received = 0;
  updates.total = update.size;
  refresh();
  try {
    const file = await downloadUpdate(update, {
      onProgress: (received, total) => {
        updates.received = received;
        updates.total = total;
        refresh();
      },
    });
    installUpdate(file);
  } catch (error) {
    updates.state = "error";
    updates.error = message(error);
    toast(`Update failed: ${updates.error}`, "error");
    refresh();
  }
}

export function openPage(url = releasePage()): void {
  try { openExternal(url); } catch (error) { toast(`Could not open ${url}: ${message(error)}`, "error"); }
}

let started = false;
/** Background checks; silent unless a newer release shows up. */
export function startUpdateChecks(): void {
  if (started || !updatesConfigured()) return;
  started = true;
  setTimeout(() => { void checkUpdates(true); }, FIRST_CHECK);
  setInterval(() => { void checkUpdates(true); }, EVERY);
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
