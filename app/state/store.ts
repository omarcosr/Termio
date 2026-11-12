// The UI's whole state and the actions that change it. Views read `ui` and call actions;
// actions talk to the native core and then ask for a render. Secrets never pass through here:
// the core hands back records with `has…` flags in their place.
import { onCoreEvent, type CoreEvent } from "../core/events";
import { core } from "../core/plugin";
import { setPalette } from "../ui/tokens";
import { keepAlive, openExternal, secureStore, toast as showToast, type KeepAlive, clipboard, store } from "@tarve/core";

export interface VaultRecord<T = Record<string, unknown>> {
  id: string;
  kind: string;
  data: T;
  updated: number;
}

export interface HostData {
  name: string;
  address: string;
  port?: number;
  user?: string;
  group?: string;
  color?: string;
  key?: string;
  jump?: string;
  forwards?: ForwardRule[];
  /** Run the session through the Termio agent when the server has it (default on). */
  agent?: boolean;
  notes?: string;
  lastConnected?: number;
  password?: string;
  hasPassword?: boolean;
    /** Sign in with the keys the running ssh-agent holds, like ssh itself does. */
      useAgent?: boolean;
}

export interface KeyData {
  name: string;
  algorithm: string;
  public: string;
  fingerprint: string;
}

export interface KnownHostData {
  host: string;
  port: number;
  algorithm: string;
  fingerprint: string;
}

export type SessionStatus = "connecting" | "authenticating" | "connected" | "reconnecting" | "closed";

export interface ForwardRule {
  local: number;
  host: string;
  port: number;
}

/** One terminal: a pane in a tab. */
export interface SessionInfo {
  session: number;
  title: string;
  /** The host record it connects to; none for a local shell. */
  host?: string;
  status: SessionStatus;
  reason?: string;
  size?: string;
  /** Keystroke-to-echo time in ms, measured on the link. */
  latency?: number;
  /** `agent`: resumable, over QUIC; `ssh`: a plain SSH channel. */
  transport?: "agent" | "ssh";
  forwards: { label: string; ok: boolean; message?: string }[];
}

export interface RemoteEntry {
  name: string;
  directory: boolean;
  size: number;
  modified: number;
}

export interface Transfer {
  request: number;
  name: string;
  direction: "up" | "down";
  total?: number;
  done: number;
  state: "running" | "done" | "error";
  message?: string;
}

/** A file browser on one host, over its own SFTP connection. */
export interface FilesInfo {
  /** The remote home folder, for a typed ~. */
  home?: string;
  id: number;
  host: string;
  state: "connecting" | "ready" | "error";
  message?: string;
  path: string;
  entries: RemoteEntry[];
  loading: boolean;
  transfers: Transfer[];
}

/** A tab: terminal panes side by side (or stacked), or a file browser. */
export interface Tab {
  id: number;
  kind: "terminal" | "files";
  panes: number[];
  direction: "row" | "column";
  /** The pane that receives the keyboard. */
  focus: number;
  files?: FilesInfo;
}

export interface SnippetData {
  name: string;
  command: string;
}

export interface HostKeyPrompt {
  request: number;
  session: number;
  host: string;
  port: number;
  algorithm: string;
  fingerprint: string;
  /** The fingerprint on record when the key changed. */
  previous: string | null;
}

export type View = "hosts" | "snippets" | "keys" | "known" | "sync" | "settings" | "forwards";
export type Phase = "locked" | "create" | "join" | "ready";

export type SyncProvider = "r2" | "s3";

export interface SyncSettings {
  provider?: SyncProvider;
  account: string;
  bucket: string;
  accessKey: string;
  endpoint?: string;
  /** AWS S3: the bucket's region. */
  region?: string;
  name?: string;
  hasSecretKey?: boolean;
}

/**
 * Everything the views draw from. A Tarve store: a change through it schedules one render, so a
 * view that only mutates `ui` needs no refresh(). Keep and mutate what `ui` hands back (a pushed
 * object is reached again through `ui`), and compare identity with toRaw.
 */
export const ui = store({
  phase: "locked" as Phase,
  vaultPath: "",
  busy: false,
  error: undefined as string | undefined,
  view: "hosts" as View,
  hosts: [] as VaultRecord<HostData>[],
  snippets: [] as VaultRecord<SnippetData>[],
  sessions: {} as Record<number, SessionInfo>,
  keys: [] as VaultRecord<KeyData>[],
  known: [] as VaultRecord<KnownHostData>[],
  search: "",
  /** The host being edited in the side panel (`id` undefined for a new one). */
  editing: undefined as { id?: string; data: HostData } | undefined,
  tabs: [] as Tab[],
  /** `home` or a tab id. */
  active: "home" as "home" | number,
  editingSnippet: undefined as { id?: string; data: SnippetData } | undefined,
  prompts: [] as HostKeyPrompt[],
  sync: { configured: false, state: "idle" as "idle" | "running" | "done" | "error", message: undefined as string | undefined, at: 0 },
  /** The buckets the vault syncs with, by provider: each holds the whole vault, a backup of the other. */
  syncTargets: {} as Partial<Record<SyncProvider, SyncSettings>>,
  settingsOpen: false,
  agentInstall: {} as Record<string, AgentInstall>,
  appearance: { fontFamily: "Cascadia Mono", fontSize: 13, theme: "termio", cursor: "block", padding: 6, shell: "" } as Appearance,
  paletteOpen: false,
  /** An error nothing else handled, shown in a dialog instead of closing the app. */
  fault: undefined as { message: string; detail: string } | undefined,
  /** The pane or tab being dragged, and the drop zone under the pointer ("<session>:<zone>", "tab:<id>", "new"). */
  drag: undefined as DragSource | undefined,
  dropZone: undefined as string | undefined,
  /** The terminal search bar, over the pane of `session`. */
  termSearch: undefined as { session: number; query: string; count: number } | undefined,
  paletteQuery: "",
  /** Android: the vault password is sealed here and a fingerprint unlocks it. */
  fingerprint: false,
});

/** Native file pickers, provided by the app handle once the window is up. */
export const dialogs = {
  open: async (): Promise<string[]> => [],
  save: async (_name: string): Promise<string | undefined> => undefined,
  /** One file to read, e.g. another program's export. */
  pick: async (_title: string, _filters: { name: string; extensions: string[] }[]): Promise<string | undefined> => undefined,
  /** Moves the keyboard focus to a node by id (on Android a text field brings up the soft keyboard). */
  focus: (_id: string): void => {},
};

let render: () => void = () => {};
export function setRenderer(next: () => void): void {
  render = () => {
    next();
    syncKeepAlive();
  };
}

const ANDROID = (process.platform as string) === "android";

/**
 * Android freezes an app in the background, and its sessions drop. While any is open a
 * foreground service with a notification ("2 sessions open") keeps the process running.
 */
let keptText = "";
let keptAlive: KeepAlive | undefined;
function syncKeepAlive(): void {
  if (!ANDROID) return;
  const terminals = Object.values(ui.sessions).filter(info => info.status !== "closed").length;
  const files = ui.tabs.filter(tab => tab.kind === "files").length;
  const open = terminals + files;
  const text = open === 0 ? "" : [terminals ? (terminals === 1 ? "1 session" : `${terminals} sessions`) : "", files ? (files === 1 ? "1 file browser" : `${files} file browsers`) : ""].filter(Boolean).join(", ") + " open";
  if (text === keptText) return;
  keptText = text;
  const report = (result: { error?: string }) => { if (result.error) console.warn("[termio] keepAlive", result.error); };
  if (!text) {
    void keptAlive?.release();
    keptAlive = undefined;
  } else if (keptAlive) {
    void keptAlive.update({ title: "Termio is connected", text }).then(report, () => {});
  } else {
    keptAlive = keepAlive({ title: "Termio is connected", text });
    void keptAlive.result.then(report, () => {});
  }
}

// --- Fingerprint unlock (Android) ------------------------------------------------------------

/** The password the vault was last opened with, while it is open: enabling fingerprint unlock seals it. */
let openedWith: string | undefined;

/** Where the vault password is sealed for fingerprint unlock (the Android Keystore, through Tarve). */
const UNLOCK_ALIAS = "termio.unlock";

/** Fingerprint (or device PIN) checks, provided by the app handle once the window is up. */
export const biometrics = {
  authenticate: async (_reason: string): Promise<{ supported: boolean; success: boolean; error?: string }> => ({ supported: false, success: false }),
};

function unlockSaved(): boolean {
  if (!ANDROID) return false;
  try { return secureStore.has(UNLOCK_ALIAS); } catch { return false; }
}

/** The vault password is sealed on this device and a fingerprint opens it. */
export function fingerprintEnabled(): boolean {
  return ui.fingerprint;
}

export async function unlockWithFingerprint(): Promise<void> {
  const check = await biometrics.authenticate("Unlock Termio");
  if (!check.success) {
    if (check.error) { ui.error = check.error; render(); }
    return;
  }
  const sealed = await secureStore.open(UNLOCK_ALIAS).catch((error: unknown) => ({ supported: true, error: message(error), data: undefined }));
  if (!sealed.data) {
    if (sealed.error) { ui.error = sealed.error; }
    return render();
  }
  unlockVault(new TextDecoder().decode(sealed.data));
  if (ui.phase !== "ready") {
    // The password changed elsewhere (a synced vault): the sealed one is useless now.
    await secureStore.delete(UNLOCK_ALIAS).catch(() => undefined);
    ui.fingerprint = false;
    ui.error = "The saved password no longer opens the vault: type it once to unlock.";
    render();
  }
}

export async function setFingerprint(on: boolean): Promise<void> {
  if (!on) {
    await secureStore.delete(UNLOCK_ALIAS).catch(() => undefined);
    ui.fingerprint = false;
    return render();
  }
  if (!openedWith) return toast("Lock and unlock the vault with its password once, then turn this on", "error");
  const check = await biometrics.authenticate("Turn on fingerprint unlock");
  if (!check.success) return toast(check.supported ? check.error ?? "Not confirmed" : "This device has no fingerprint or screen lock", "error");
  const saved = await secureStore.seal(UNLOCK_ALIAS, openedWith).catch((error: unknown) => ({ supported: true, error: message(error) }));
  if (!saved.supported || saved.error) return toast(saved.error ?? "Could not save", "error");
  ui.fingerprint = true;
  toast("Fingerprint unlock is on");
}
export function refresh(): void {
  render();
}

export function toast(text: string, tone: "ok" | "error" = "ok"): void {
  showToast(text, { tone });
}

const sources: Record<string, string> = {
  render: "while drawing the window",
  "event-handler": "while handling a click or key",
  listener: "in an event listener",
  hotkey: "in a shortcut",
  "file-dialog": "in the file dialog",
  request: "in a request",
  native: "in the window",
  plugin: "in the Termio core",
  rejection: "in a background task",
  exception: "in a background task",
  process: "in a background task",
};

/**
 * Shows an error nothing else caught in a dialog: the app keeps running and the person can read,
 * copy or dismiss it. Repeats of the open error are ignored so a failing render cannot loop.
 */
export function reportFault(error: unknown, where?: string): void {
  const text = message(error) || "Unknown error";
  const stack = error instanceof Error && error.stack ? error.stack : text;
  console.error(`[termio] ${where ?? "error"}`, error);
  if (ui.fault?.message === text) return;
  ui.fault = { message: text, detail: `${where ? `Where: ${sources[where] ?? where}\n` : ""}${stack}` };
  try { render(); } catch { /* the dialog shows on the next frame */ }
}

export function dismissFault(): void {
  ui.fault = undefined;
  render();
}

function message(error: unknown): string {
  const text = error instanceof Error ? error.message : String(error);
  // The core prefixes the op name; the person reading it does not need it.
  return text.replace(/^[a-z.]+: /, "");
}

/** Runs a core action, turning its failure into `ui.error` instead of an exception. */
function attempt<T>(action: () => T): T | undefined {
  try {
    ui.error = undefined;
    return action();
  } catch (error) {
    ui.error = message(error);
    return undefined;
  } finally {
    render();
  }
}

// --- Vault ---------------------------------------------------------------------------------

export function loadStatus(): void {
  const status = core().call<{ exists: boolean; unlocked: boolean; path: string; syncConfigured: boolean }>({ op: "vault.status" });
  ui.vaultPath = status.path;
  ui.sync.configured = status.syncConfigured;
  if (status.unlocked) {
    ui.phase = "ready";
    loadAppearance();
    reload();
  } else {
    ui.phase = status.exists ? "locked" : "create";
  }
  ui.fingerprint = unlockSaved();
}

export function createVault(password: string, confirm: string): void {
  if (password !== confirm) {
    ui.error = "The two passwords differ.";
    return render();
  }
  if (attempt(() => core().call({ op: "vault.create", password })) !== undefined) {
    openedWith = password;
    enterVault();
  }
}

export function unlockVault(password: string): void {
  if (attempt(() => core().call({ op: "vault.unlock", password })) !== undefined) {
    openedWith = password;
    enterVault();
  }
}

export function joinVault(password: string, r2: SyncForm): void {
  const joined = attempt(() => core().call<{ pulled: number }>({ op: "vault.join", password, ...r2 }));
  if (joined) {
    openedWith = password;
    enterVault();
    toast(`Joined the synced vault: ${joined.pulled} items`);
  }
}

/** A first vault that lives in an empty bucket from the start: created here, then synced up. */
export function createSyncedVault(password: string, confirm: string, r2: SyncForm): void {
  createVault(password, confirm);
  if (ui.phase === "ready") configureSync(r2);
}

/** The vault names in a bucket; undefined when the listing failed (reason in ui.error). */
export function listVaults(r2: SyncForm): string[] | undefined {
  return attempt(() => core().call<{ vaults: string[] }>({ op: "sync.vaults", ...r2 }))?.vaults;
}

function enterVault(): void {
  ui.phase = "ready";
  loadAppearance();
  const status = core().call<{ syncConfigured: boolean }>({ op: "vault.status" });
  ui.sync.configured = status.syncConfigured;
  reload();
}

export function lockVault(): void {
  for (const tab of [...ui.tabs]) closeTab(tab.id);
  core().call({ op: "vault.lock" });
  openedWith = undefined;
  Object.assign(ui, { phase: "locked", hosts: [], keys: [], known: [], editing: undefined, active: "home", prompts: [] });
  render();
}

export function reload(): void {
  const list = <T,>(kind: string) => core().call<{ records: VaultRecord<T>[] }>({ op: "records.list", kind }).records;
  ui.hosts = list<HostData>("host");
  ui.keys = list<KeyData>("key");
  ui.known = list<KnownHostData>("known_host");
  ui.snippets = list<SnippetData>("snippet");
  const targets = core().call<Record<SyncProvider, VaultRecord<SyncSettings> | null>>({ op: "sync.settings" });
  ui.syncTargets = {};
  for (const provider of ["r2", "s3"] as const) {
    const data = targets[provider]?.data;
    if (data) ui.syncTargets[provider] = data;
  }
  render();
}

// --- Hosts ---------------------------------------------------------------------------------

export function newHost(prefill: Partial<HostData> = {}): void {
  ui.editing = { data: { name: "", address: "", port: 22, user: "", group: "", color: "slate", ...prefill } };
  ui.error = undefined;
  render();
}

export function editHost(id: string): void {
  const host = ui.hosts.find(record => record.id === id);
  if (host) ui.editing = { id, data: { ...host.data } };
  ui.error = undefined;
  render();
}

export function saveHost(): void {
  const editing = ui.editing;
  if (!editing) return;
  const data = { ...editing.data, name: editing.data.name.trim(), address: editing.data.address.trim() };
  if (!data.address) {
    ui.error = "A host needs an address.";
    return render();
  }
  if (!data.name) data.name = data.address;
  // An empty password field means "keep the stored one".
  if (!data.password) delete data.password;
  const saved = attempt(() => core().call<VaultRecord<HostData>>({ op: "records.put", kind: "host", id: editing.id, data }));
  if (saved) {
    ui.editing = undefined;
    reload();
  }
}

export function removeHost(id: string): void {
  if (attempt(() => core().call({ op: "records.remove", id })) !== undefined) {
    if (ui.editing?.id === id) ui.editing = undefined;
    reload();
  }
}

/** A server `~/.ssh/config` names, as the core parsed it. */
export interface SshConfigHost {
  name: string;
  address: string;
  user?: string;
  port?: number;
  identityFile?: string;
  jump?: string;
}

/** Where hosts can be imported from. */
export type ImportSource = "sshConfig" | "filezilla" | "termius";

/** A host another program saved, as a scan reports it: its password stays in the core. */
export interface ImportHost extends SshConfigHost {
  key: string;
  group?: string;
  hasPassword: boolean;
  /** The program keeps a private key for this host in its own store (Termius). */
  hasKey?: boolean;
  /** The vault already has a host at this address. */
  exists: boolean;
}

export interface ImportScan {
  source: string;
  path: string;
  hosts: ImportHost[];
  /** Entries left out because they are not SSH (FTP sites, Telnet rows). */
  skipped: number;
}

/** The hosts in `~/.ssh/config`; undefined when it could not be read (reason in ui.error). */
export function scanSshConfig(): SshConfigHost[] | undefined {
  return attempt(() => core().call<{ hosts: SshConfigHost[] }>({ op: "import.sshConfig" }))?.hosts;
}

/** Reads another program's hosts: `~/.ssh/config`, FileZilla's Site Manager or Termius' own data. */
export function scanImport(source: ImportSource): ImportScan | undefined {
  return attempt(() => core().call<ImportScan>({ op: "import.scan", source }));
}

/** Saves the chosen hosts, with their keys when asked, under the "Imported" group. */
export function importSshHosts(hosts: SshConfigHost[], importKeys: boolean): void {
  const imported = attempt(() => core().call<{ imported: number }>({ op: "import.apply", hosts, importKeys }));
  if (!imported) return;
  reload();
  toast(imported.imported === 1 ? "Imported 1 host from ~/.ssh/config" : `Imported ${imported.imported} hosts from ~/.ssh/config`);
}

/** Saves hosts of the last scan by key, with their passwords, in their own groups (or "Imported"). */
export function importScanned(keys: string[], importKeys: boolean, from: string): void {
  const imported = attempt(() => core().call<{ imported: number }>({ op: "import.apply", keys, importKeys }));
  if (!imported) return;
  reload();
  toast(imported.imported === 1 ? `Imported 1 host from ${from}` : `Imported ${imported.imported} hosts from ${from}`);
}

/** `user@host:port`, `host:port` or `host`. */
export function parseQuickConnect(text: string): Partial<HostData> | undefined {
  const match = /^\s*(?:([^@\s]+)@)?(\[[^\]]+\]|[^:\s]+)(?::(\d{1,5}))?\s*$/.exec(text);
  if (!match) return undefined;
  return { user: match[1] ?? "", address: match[2]!.replace(/^\[|\]$/g, ""), port: match[3] ? Number(match[3]) : 22 };
}

// --- Tabs and panes ------------------------------------------------------------------------

let nextTab = 1;

/**
 * The shell a local tab runs. The setting syncs with the vault, so a Windows choice
 * (pwsh.exe) reaches Android and Linux too: there it falls back to the system default.
 */
function localShell(): string | undefined {
  const shell = ui.appearance.shell;
  if (!shell) return undefined;
  return process.platform === "win32" || !/\.exe$/i.test(shell) ? shell : undefined;
}

function newSession(host: VaultRecord<HostData> | undefined): number | undefined {
  const opened = attempt(() => host ? core().call<{ id: number }>({ op: "ssh.open", host: host.id }) : core().call<{ id: number }>({ op: "session.open", kind: "local", ...(localShell() ? { program: localShell() } : {}) }));
  if (!opened) {
    toast(ui.error ?? "Could not open the session", "error");
    return undefined;
  }
  ui.sessions[opened.id] = { session: opened.id, title: host?.data.name ?? "Local", host: host?.id, status: host ? "connecting" : "connected", forwards: [] };
  if (host) {
    const stamped = { ...host.data, lastConnected: Date.now() };
    try { core().call({ op: "records.put", kind: "host", id: host.id, data: stamped }); } catch { /* the stamp is cosmetic */ }
    ui.hosts = ui.hosts.map(record => record.id === host.id ? { ...record, data: stamped } : record);
  }
  return opened.id;
}

function openTab(host: VaultRecord<HostData> | undefined): void {
  const session = newSession(host);
  if (session === undefined) return;
  const tab: Tab = { id: nextTab++, kind: "terminal", panes: [session], direction: "row", focus: session };
  ui.tabs.push(tab);
  ui.active = tab.id;
  render();
}

export function connect(hostId: string): void {
  const host = ui.hosts.find(record => record.id === hostId);
  if (host) openTab(host);
}

export function openLocal(): void {
  openTab(undefined);
}

export function activeTab(): Tab | undefined {
  return ui.tabs.find(tab => tab.id === ui.active);
}

/** The session that should get the keyboard: the focused pane of the tab on screen. */
export function focusedSession(): number | undefined {
  const tab = activeTab();
  return tab?.kind === "terminal" ? tab.focus : undefined;
}

/** Opens another pane in the current tab, on the same host as the focused one. */
export function split(direction: "row" | "column"): void {
  const tab = activeTab();
  if (!tab || tab.kind !== "terminal" || tab.panes.length >= 4) return;
  const current = ui.sessions[tab.focus];
  const host = current?.host ? ui.hosts.find(record => record.id === current.host) : undefined;
  const session = newSession(host);
  if (session === undefined) return;
  if (tab.panes.length === 1) tab.direction = direction;
  tab.panes.splice(tab.panes.indexOf(tab.focus) + 1, 0, session);
  tab.focus = session;
  render();
}

export function focusPane(session: number): void {
  const tab = ui.tabs.find(item => item.panes.includes(session));
  if (tab && tab.focus !== session) {
    tab.focus = session;
    render();
  }
}

function endSession(session: number): void {
  try { core().call({ op: "session.close", id: session }); } catch { /* already gone */ }
  delete ui.sessions[session];
  ui.prompts = ui.prompts.filter(prompt => prompt.session !== session);
}

/** Closes one pane; the tab goes with its last pane. */
export function closePane(session: number): void {
  const tab = ui.tabs.find(item => item.panes.includes(session));
  endSession(session);
  if (!tab) return render();
  const index = tab.panes.indexOf(session);
  tab.panes.splice(index, 1);
  if (tab.panes.length === 0) return closeTab(tab.id);
  if (tab.focus === session) tab.focus = tab.panes[Math.max(0, index - 1)]!;
  render();
}

export function closeTab(id: number): void {
  const index = ui.tabs.findIndex(tab => tab.id === id);
  if (index < 0) return;
  const [tab] = ui.tabs.splice(index, 1);
  for (const session of tab!.panes) endSession(session);
  if (tab!.files) try { core().call({ op: "sftp.close", id: tab!.files.id }); } catch { /* gone */ }
  if (ui.active === id) ui.active = ui.tabs[Math.min(index, ui.tabs.length - 1)]?.id ?? "home";
  render();
}

// --- Dragging panes and tabs ---------------------------------------------------------------

export type DragSource = { kind: "pane"; session: number } | { kind: "tab"; id: number };
export type DropZone = "left" | "right" | "top" | "bottom" | "center";
const MAX_PANES = 4;

export function startDrag(source: DragSource): void {
  ui.drag = source;
  ui.dropZone = undefined;
  render();
}

export function endDrag(): void {
  if (!ui.drag && !ui.dropZone) return;
  ui.drag = undefined;
  ui.dropZone = undefined;
  render();
}

export function hoverDrop(zone: string | undefined): void {
  if (ui.dropZone === zone) return;
  ui.dropZone = zone;
  render();
}

/** The sessions a drag carries: one pane, or every pane of a terminal tab. */
function carried(source: DragSource): number[] | undefined {
  if (source.kind === "pane") return ui.tabs.some(tab => tab.panes.includes(source.session)) ? [source.session] : undefined;
  const tab = ui.tabs.find(item => item.id === source.id);
  return tab?.kind === "terminal" ? [...tab.panes] : undefined;
}

/** Takes sessions out of their tabs without ending them; a tab left without panes goes. */
function lift(sessions: number[]): void {
  for (const tab of [...ui.tabs]) {
    if (tab.kind !== "terminal") continue;
    const kept = tab.panes.filter(session => !sessions.includes(session));
    if (kept.length === tab.panes.length) continue;
    tab.panes = kept;
    if (kept.length === 0) ui.tabs.splice(ui.tabs.indexOf(tab), 1);
    else if (!kept.includes(tab.focus)) tab.focus = kept[0]!;
  }
}

function takeDrag(): DragSource | undefined {
  const source = ui.drag;
  ui.drag = undefined;
  ui.dropZone = undefined;
  return source;
}

/**
 * Drops the dragged pane or tab on a pane: an edge puts it beside that pane (splitting the tab
 * that way when the pane is alone), the centre swaps two panes or adds a whole tab after it.
 */
export function dropOnPane(target: number, zone: DropZone): void {
  const source = takeDrag();
  const moving = source && carried(source);
  const tab = ui.tabs.find(item => item.panes.includes(target));
  if (!source || !moving || !tab || moving.includes(target)) return render();
  if (zone === "center" && source.kind === "pane") {
    const from = ui.tabs.find(item => item.panes.includes(source.session))!;
    from.panes[from.panes.indexOf(source.session)] = target;
    tab.panes[tab.panes.indexOf(target)] = source.session;
    if (from !== tab && from.focus === source.session) from.focus = target;
    tab.focus = source.session;
    ui.active = tab.id;
    return render();
  }
  const staying = tab.panes.filter(session => !moving.includes(session));
  if (staying.length + moving.length > MAX_PANES) {
    toast(`A tab holds at most ${MAX_PANES} panes`, "error");
    return;
  }
  lift(moving);
  if (tab.panes.length === 1 && zone !== "center") tab.direction = zone === "left" || zone === "right" ? "row" : "column";
  const at = tab.panes.indexOf(target);
  tab.panes.splice(zone === "left" || zone === "top" ? at : at + 1, 0, ...moving);
  tab.focus = moving[0]!;
  ui.active = tab.id;
  render();
}

/** Drops on a tab button: a tab moves to that place in the bar, a pane joins that tab. */
export function dropOnTab(id: number): void {
  const source = takeDrag();
  const target = ui.tabs.find(tab => tab.id === id);
  if (!source || !target) return render();
  if (source.kind === "tab") {
    const from = ui.tabs.findIndex(tab => tab.id === source.id);
    if (from < 0 || source.id === id) return render();
    const [moved] = ui.tabs.splice(from, 1);
    ui.tabs.splice(ui.tabs.indexOf(target), 0, moved!);
    return render();
  }
  if (target.kind !== "terminal" || target.panes.includes(source.session)) return render();
  if (target.panes.length >= MAX_PANES) {
    toast(`A tab holds at most ${MAX_PANES} panes`, "error");
    return;
  }
  lift([source.session]);
  target.panes.push(source.session);
  target.focus = source.session;
  ui.active = target.id;
  render();
}

/** Drops on the free end of the tab bar: a pane becomes a tab of its own, a tab goes last. */
export function dropOnNewTab(): void {
  const source = takeDrag();
  if (!source) return render();
  if (source.kind === "tab") {
    const from = ui.tabs.findIndex(tab => tab.id === source.id);
    if (from >= 0) ui.tabs.push(...ui.tabs.splice(from, 1));
    return render();
  }
  const owner = ui.tabs.find(tab => tab.panes.includes(source.session));
  if (!owner || owner.panes.length === 1) return render();
  lift([source.session]);
  const tab: Tab = { id: nextTab++, kind: "terminal", panes: [source.session], direction: "row", focus: source.session };
  ui.tabs.splice(ui.tabs.indexOf(owner) + 1, 0, tab);
  ui.active = tab.id;
  render();
}

/** Replaces a finished pane's session with a fresh one to the same host. */
export function reconnect(session: number): void {
  const info = ui.sessions[session];
  const tab = ui.tabs.find(item => item.panes.includes(session));
  const host = info?.host ? ui.hosts.find(record => record.id === info.host) : undefined;
  if (!tab || !host) return;
  const fresh = newSession(host);
  if (fresh === undefined) return;
  endSession(session);
  tab.panes[tab.panes.indexOf(session)] = fresh;
  if (tab.focus === session) tab.focus = fresh;
  render();
}

export function activate(target: "home" | number): void {
  ui.active = target;
  render();
}

export function cycleTabs(step: 1 | -1): void {
  const order: ("home" | number)[] = ["home", ...ui.tabs.map(tab => tab.id)];
  const index = order.indexOf(ui.active);
  activate(order[(index + step + order.length) % order.length]!);
}

export function tabTitle(tab: Tab): string {
  if (tab.kind === "files") return `Files · ${ui.hosts.find(host => host.id === tab.files?.host)?.data.name ?? "host"}`;
  const titles = tab.panes.map(session => ui.sessions[session]?.title ?? "…");
  return titles.length > 1 ? `${titles[0]} +${titles.length - 1}` : titles[0] ?? "…";
}

export function answerHostKey(request: number, trust: boolean): void {
  try { core().call({ op: "hostkey.answer", request, trust, remember: true }); } catch { /* answered elsewhere */ }
  ui.prompts = ui.prompts.filter(prompt => prompt.request !== request);
  if (trust) reload();
  render();
}

// --- Snippets ------------------------------------------------------------------------------

/** Types a snippet into the focused pane and runs it. */
export function runSnippet(id: string, session = focusedSession()): void {
  const snippet = ui.snippets.find(record => record.id === id);
  if (!snippet) return;
  if (session === undefined) return toast("Open a terminal first", "error");
  const none = { shiftKey: false, altKey: false, ctrlKey: false, metaKey: false };
  // Line by line, each followed by Enter, so a multi-line snippet runs as typed.
  const lines = snippet.data.command.replace(/\r\n?/g, "\n").split("\n");
  lines.forEach((line, index) => {
    for (const ch of line) core().key(session, { ...none, phase: "down", key: ch });
    if (index < lines.length - 1 || line.length) core().key(session, { ...none, phase: "down", key: "Enter" });
  });
}

/** Runs a snippet in every pane of the current tab at once. */
export function broadcastSnippet(id: string): void {
  const tab = activeTab();
  if (!tab || tab.kind !== "terminal") return toast("Open a terminal first", "error");
  for (const session of tab.panes) runSnippet(id, session);
}

export function editSnippet(id?: string): void {
  const record = id ? ui.snippets.find(snippet => snippet.id === id) : undefined;
  ui.editingSnippet = { id, data: record ? { ...record.data } : { name: "", command: "" } };
  ui.error = undefined;
  render();
}

export function saveSnippet(): void {
  const editing = ui.editingSnippet;
  if (!editing) return;
  if (!editing.data.command.trim()) {
    ui.error = "A snippet needs a command.";
    return render();
  }
  const data = { name: editing.data.name.trim() || editing.data.command.trim().split("\n")[0]!.slice(0, 40), command: editing.data.command };
  if (attempt(() => core().call({ op: "records.put", kind: "snippet", id: editing.id, data })) !== undefined) {
    ui.editingSnippet = undefined;
    reload();
  }
}

// --- Files (SFTP) --------------------------------------------------------------------------

let nextRequest = 1;
const pending = new Map<number, (event: { ok: boolean; value?: unknown; error?: string }) => void>();

function sftpRequest<T>(op: string, args: Record<string, unknown>): Promise<T> {
  const request = nextRequest++;
  return new Promise<T>((resolve, reject) => {
    pending.set(request, event => event.ok ? resolve(event.value as T) : reject(new Error(event.error)));
    try {
      core().call({ op, request, ...args });
    } catch (error) {
      pending.delete(request);
      reject(error);
    }
  });
}

export function openFiles(hostId: string): void {
  const opened = attempt(() => core().call<{ id: number }>({ op: "sftp.open", host: hostId }));
  if (!opened) return toast(ui.error ?? "Could not open files", "error");
  const tab: Tab = { id: nextTab++, kind: "files", panes: [], direction: "row", focus: 0, files: { id: opened.id, host: hostId, state: "connecting", path: "", entries: [], loading: false, transfers: [] } };
  ui.tabs.push(tab);
  ui.active = tab.id;
  render();
}

function filesById(id: number): FilesInfo | undefined {
  return ui.tabs.find(tab => tab.files?.id === id)?.files;
}

export function joinPath(dir: string, name: string): string {
  return name === ".." ? dir.replace(/\/[^/]+\/?$/, "") || "/" : `${dir.replace(/\/$/, "")}/${name}`;
}

export async function browse(files: FilesInfo, path: string): Promise<void> {
  files.loading = true;
  render();
  try {
    files.entries = await sftpRequest<RemoteEntry[]>("sftp.list", { id: files.id, path });
    files.path = path;
  } catch (error) {
    toast(message(error), "error");
  } finally {
    files.loading = false;
    render();
  }
}

async function transfer(files: FilesInfo, direction: "up" | "down", name: string, args: Record<string, unknown>, total?: number): Promise<void> {
  const request = nextRequest;
  const entry: Transfer = { request, name, direction, total, done: 0, state: "running" };
  files.transfers.unshift(entry);
  render();
  try {
    const result = await sftpRequest<{ bytes: number }>(direction === "up" ? "sftp.upload" : "sftp.download", { id: files.id, ...args });
    entry.done = result.bytes;
    entry.total = result.bytes;
    entry.state = "done";
    if (direction === "up") await browse(files, files.path);
  } catch (error) {
    entry.state = "error";
    entry.message = message(error);
  }
  render();
}

export function download(files: FilesInfo, entry: RemoteEntry, local: string): void {
  void transfer(files, "down", entry.name, { remote: joinPath(files.path, entry.name), local }, entry.size);
}

export function upload(files: FilesInfo, local: string): void {
  const name = local.split(/[\\/]/).pop()!;
  void transfer(files, "up", name, { local, remote: joinPath(files.path, name) });
}

export async function makeDirectory(files: FilesInfo, name: string): Promise<void> {
  try {
    await sftpRequest("sftp.mkdir", { id: files.id, path: joinPath(files.path, name) });
    await browse(files, files.path);
  } catch (error) {
    toast(message(error), "error");
  }
}

export async function removeEntry(files: FilesInfo, entry: RemoteEntry): Promise<void> {
  try {
    await sftpRequest("sftp.remove", { id: files.id, path: joinPath(files.path, entry.name), directory: entry.directory });
    await browse(files, files.path);
  } catch (error) {
    toast(message(error), "error");
  }
}

export async function renameEntry(files: FilesInfo, entry: RemoteEntry, name: string): Promise<void> {
  try {
    await sftpRequest("sftp.rename", { id: files.id, from: joinPath(files.path, entry.name), to: joinPath(files.path, name) });
    await browse(files, files.path);
  } catch (error) {
    toast(message(error), "error");
  }
}

/** A shell's title, shortened: shells often report their own full path. */
export function shortTitle(title: string): string {
  return /^[A-Za-z]:\\|^\//.test(title) ? title.split(/[\\/]/).pop()!.replace(/\.exe$/i, "") : title;
}

// --- Keys ----------------------------------------------------------------------------------

export function generateKey(name: string): boolean {
  const created = attempt(() => core().call({ op: "keys.generate", name: name.trim() || "Termio key" }));
  if (created) {
    reload();
    toast("Key created. Copy its public half to your servers.");
  }
  return created !== undefined;
}

export function importKey(name: string, privateKey: string, passphrase: string): boolean {
  const created = attempt(() => core().call({ op: "keys.import", name: name.trim() || "Imported key", private: privateKey, passphrase }));
  if (created) {
    reload();
    toast("Key imported");
  }
  return created !== undefined;
}

export function removeRecord(id: string): void {
  if (attempt(() => core().call({ op: "records.remove", id })) !== undefined) reload();
}

// --- Sync ----------------------------------------------------------------------------------

export interface SyncForm {
  /** "r2" (Cloudflare, the default) or "s3" (AWS). */
  provider?: SyncProvider;
  /** R2 only. */
  account?: string;
  bucket: string;
  accessKey: string;
  /** Blank keeps the saved one. */
  secretKey: string;
  endpoint?: string;
  /** S3 only: detected from the bucket when blank. */
  region?: string;
  /** The vault's name in the bucket (`<name>.vault`). */
  name?: string;
}

/** Connects a bucket and syncs with it; false when that failed (reason in ui.error). */
export function configureSync(form: SyncForm): boolean {
  ui.busy = true;
  render();
  const result = attempt(() => core().call<{ pulled: number; pushed: number }>({ op: "sync.configure", ...form }));
  ui.busy = false;
  if (result) {
    ui.sync = { configured: true, state: "done", message: undefined, at: Date.now() };
    reload();
    toast(`${providerName(form.provider)} is on: ${result.pushed} sent, ${result.pulled} received`);
  }
  return Boolean(result);
}

export function syncNow(): void {
  attempt(() => core().call({ op: "sync.run" }));
}

export function providerName(provider: SyncProvider = "r2"): string {
  return provider === "s3" ? "AWS S3" : "Cloudflare R2";
}

/** Stops syncing with one provider's bucket (every device follows); the bucket keeps its copy. */
export function disableSync(provider: SyncProvider): void {
  if (attempt(() => core().call({ op: "sync.disable", provider })) !== undefined) {
    reload();
    ui.sync = Object.keys(ui.syncTargets).length ? ui.sync : { configured: false, state: "idle", message: undefined, at: 0 };
    toast(`${providerName(provider)} is off`);
  }
}

// --- Core events ---------------------------------------------------------------------------

function sessionOf(event: CoreEvent): SessionInfo | undefined {
  return typeof event.session === "number" ? ui.sessions[event.session] : undefined;
}

export function listen(): void {
  onCoreEvent(event => {
    switch (event.type) {
      case "session.status": {
        const info = sessionOf(event);
        if (!info) return;
        info.status = event.status as SessionStatus;
        if (info.status === "connected") info.reason = undefined;
        break;
      }
      case "session.closed": {
        const info = sessionOf(event);
        if (!info) return;
        info.status = "closed";
        info.reason = typeof event.reason === "string" ? event.reason : undefined;
        ui.prompts = ui.prompts.filter(prompt => prompt.session !== info.session);
        break;
      }
      case "session.title": {
        const info = sessionOf(event);
        if (info && typeof event.title === "string" && event.title) info.title = shortTitle(event.title);
        break;
      }
      case "session.size": {
        const info = sessionOf(event);
        if (info) info.size = `${event.columns}×${event.lines}`;
        break;
      }
      case "session.notice": {
        const info = sessionOf(event);
        if (!info) return;
        const detail = String(event.detail ?? "");
        if (event.kind === "latency") info.latency = Number(detail);
        else if (event.kind === "transport") info.transport = detail === "agent" ? "agent" : "ssh";
        else if (event.kind === "agent") toast(detail, "ok");
        else if (event.kind === "reconnect") info.reason = detail;
        else if (event.kind === "forward.up" || event.kind === "forward.error") {
          const label = detail.split(" ")[0]!;
          const rest = detail.slice(label.length + 1);
          info.forwards = [...info.forwards.filter(item => item.label !== label), { label, ok: event.kind === "forward.up", message: rest || undefined }];
          if (event.kind === "forward.error") toast(`Port forward ${label} failed: ${rest}`, "error");
        } else return;
        break;
      }
      case "session.openUrl":
        openExternal(String(event.url));
        return;
      case "hostkey":
        ui.prompts.push(event as unknown as HostKeyPrompt);
        break;
      case "agent.install": {
      const host = String(event.host);
      const state = String(event.state) as AgentInstall["state"];
      ui.agentInstall = { ...ui.agentInstall, [host]: { state, message: String(event.message ?? ""), at: Date.now() } };
      const name = ui.hosts.find(record => record.id === host)?.data.name ?? "the server";
      if (state === "done") toast(`Agent ready on ${name}: new sessions there are resumable`);
      else if (state === "error") toast(`Agent install on ${name} failed`, "error");
      break;
    }
    case "sync":
        ui.sync.state = event.state as typeof ui.sync.state;
        ui.sync.message = typeof event.message === "string" ? event.message : undefined;
        if (event.state !== "running") ui.sync.at = Date.now();
        break;
      case "records.changed":
        if (ui.phase === "ready") reload();
        return;
      case "sftp.ready": {
        const files = filesById(Number(event.id));
        if (!files) return;
        files.state = "ready";
        files.home = String(event.home ?? "/");
        void browse(files, files.home);
        break;
      }
      case "sftp.error": {
        const files = filesById(Number(event.id));
        if (!files) return;
        files.state = "error";
        files.message = String(event.message ?? "Could not connect");
        break;
      }
      case "sftp.result": {
        const resolve = pending.get(Number(event.request));
        pending.delete(Number(event.request));
        resolve?.(event as unknown as { ok: boolean; value?: unknown; error?: string });
        return;
      }
      case "sftp.progress": {
        for (const tab of ui.tabs) {
          const entry = tab.files?.transfers.find(item => item.request === Number(event.request));
          if (entry) entry.done = Number(event.done);
        }
        break;
      }
      // The core owns no clipboard: a session's copy and paste go through Tarve's.
      case "clipboard.copy":
        clipboard.writeText(String(event.message ?? "")).catch(() => toast("Could not reach the clipboard", "error"));
        return;
      case "clipboard.paste": {
        const session = event.session;
        if (session === undefined) return;
        clipboard.readText().then(text => { if (text) core().text(session, text); }, () => toast("Could not reach the clipboard", "error"));
        return;
      }
      case "session.error":
      case "surface.error":
        toast(String(event.message ?? "Something went wrong"), "error");
        return;
      default:
        return;
    }
    render();
  });
}

// --- Appearance ------------------------------------------------------------------------------

export interface Appearance {
  fontFamily: string;
  fontSize: number;
  theme: string;
  cursor: "block" | "beam" | "underline";
  padding: number;
  /** The program a new local tab runs; empty for the system default. */
  shell: string;
}

const DEFAULT_APPEARANCE: Appearance = { fontFamily: "Cascadia Mono", fontSize: 13, theme: "termio", cursor: "block", padding: 6, shell: "" };

function applyAppearance(): void {
  setPalette(ui.appearance.theme);
  attempt(() => core().call({ op: "terminal.appearance", ...ui.appearance }));
}

/** Reads the appearance saved in the vault and applies it to the terminals. */
export function loadAppearance(): void {
  const saved = attempt(() => core().call<{ records: VaultRecord<Partial<Appearance>>[] }>({ op: "records.list", kind: "settings" }))?.records.find(record => record.id === "appearance");
  ui.appearance = { ...DEFAULT_APPEARANCE, ...saved?.data };
  applyAppearance();
}

/** Shows an appearance without saving it (a pinch in progress); saveAppearance keeps it. */
export function previewAppearance(change: Partial<Appearance>): void {
  ui.appearance = { ...ui.appearance, ...change };
  applyAppearance();
  render();
}

export function saveAppearance(change: Partial<Appearance>): void {
  ui.appearance = { ...ui.appearance, ...change };
  applyAppearance();
  attempt(() => core().call({ op: "records.put", kind: "settings", id: "appearance", data: ui.appearance }));
  render();
}

/** Uploads the termio-agent binary to a host so its sessions resume over QUIC. */
export interface AgentInstall {
  state: "checking" | "uploading" | "done" | "error";
  message: string;
  at: number;
}

export function installAgent(hostId: string): void {
  ui.agentInstall = { ...ui.agentInstall, [hostId]: { state: "checking", message: "Connecting…", at: Date.now() } };
  if (attempt(() => core().call({ op: "agent.install", host: hostId })) === undefined) {
    ui.agentInstall = { ...ui.agentInstall, [hostId]: { state: "error", message: ui.error ?? "could not start", at: Date.now() } };
  }
  render();
}
let termSearchTimer: ReturnType<typeof setTimeout> | undefined;
/** Opens the search bar over the focused pane. */
export function openTermSearch(): void {
  const session = focusedSession();
  if (session === undefined) return;
  ui.termSearch = { session, query: "", count: 0 };
  render();
}
/** Types in the search bar; the core is asked once the typing pauses. */
export function setTermQuery(query: string): void {
  const search = ui.termSearch;
  if (!search) return;
  search.query = query;
  clearTimeout(termSearchTimer);
  termSearchTimer = setTimeout(() => {
    const current = ui.termSearch;
    if (!current) return;
    const result = attempt(() => core().call<{ count: number }>({ op: "session.search", id: current.session, query: current.query }));
    current.count = result?.count ?? 0;
    render();
  }, 120);
  render();
}
/** The next match, or the previous one when `backwards`. */
export function stepTermSearch(backwards = false): void {
  const search = ui.termSearch;
  if (!search) return;
  attempt(() => core().call({ op: "session.searchNext", id: search.session, backwards }));
  render();
}
/** Closes the bar and drops the highlight from the grid. */
export function closeTermSearch(): void {
  clearTimeout(termSearchTimer);
  const search = ui.termSearch;
  ui.termSearch = undefined;
  if (search) attempt(() => core().call({ op: "session.searchClear", id: search.session }));
  render();
}
