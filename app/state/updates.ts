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

/** The version `tarve build` baked in (what the updater compares), else package.json's. */
export const version: string = bakedVersion() ?? pkg.version;

function bakedVersion(): string | undefined {
  try { return (JSON.parse(process.env.TARVE_APP_METADATA ?? "{}") as { version?: string }).version; } catch { return undefined; }
}

/**
 * While the repository is private its release files need a token (TERMIO_GITHUB_TOKEN, e.g. from
 * `gh auth token`): github.com download URLs are resolved to API asset URLs, and the redirect to
 * storage is followed without the token. Public repositories need none of this.
 */
const TOKEN = process.env.TERMIO_GITHUB_TOKEN?.trim();
const DOWNLOAD = new RegExp(`^https://github\\.com/${REPO.replace(/[.]/g, "\\.")}/releases/(?:latest/download|download/([^/]+))/([^/?#]+)$`, "i");

async function githubFetch(input: string | URL | Request, init?: RequestInit): Promise<Response> {
  const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
  const match = TOKEN ? DOWNLOAD.exec(url) : null;
  if (!match) return fetch(input, init);
  const [, tag, file] = match;
  const auth = { authorization: `Bearer ${TOKEN}`, "x-github-api-version": "2022-11-28" };
  const releaseUrl = `https://api.github.com/repos/${REPO}/releases/${tag ? `tags/${tag}` : "latest"}`;
  const release = await fetch(releaseUrl, { signal: init?.signal, headers: { ...auth, accept: "application/vnd.github+json" } });
  if (!release.ok) return release;
  const assets = ((await release.json()) as { assets?: { name: string; url: string }[] }).assets ?? [];
  const asset = assets.find(item => item.name === decodeURIComponent(file!));
  if (!asset) return new Response(`No ${file} in the release`, { status: 404 });
  const response = await fetch(asset.url, { signal: init?.signal, redirect: "manual", headers: { ...auth, accept: "application/octet-stream" } });
  const location = response.status >= 300 && response.status < 400 ? response.headers.get("location") : null;
  return location ? fetch(location, { signal: init?.signal }) : response;
}

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
    const found = await checkForUpdate({ url: MANIFEST, publicKey: PUBLIC_KEY, currentVersion: version, fetch: githubFetch as typeof fetch });
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
  let drawnAt = 0;
  refresh();
  try {
    const file = await downloadUpdate(update, {
      fetch: githubFetch as typeof fetch,
      onProgress: (received, total) => {
        updates.received = received;
        updates.total = total;
        // A chunk is a few KB: redrawing for each one slowed the download to a crawl.
        const now = Date.now();
        if (now - drawnAt < 250) return;
        drawnAt = now;
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
