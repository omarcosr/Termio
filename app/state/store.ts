// The UI's whole state and the actions that change it. Views read `ui` and call actions;
// actions talk to the native core and then ask for a render. Secrets never pass through here:
// the core hands back records with `has…` flags in their place.
import { onCoreEvent, type CoreEvent } from "../core/events";
import { core } from "../core/plugin";

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

export type View = "hosts" | "snippets" | "keys" | "known" | "sync";
export type Phase = "locked" | "create" | "join" | "ready";

export interface SyncSettings {
  account: string;
  bucket: string;
  accessKey: string;
  endpoint?: string;
  hasSecretKey?: boolean;
}

export const ui = {
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
  syncSettings: undefined as SyncSettings | undefined,
  paletteOpen: false,
  paletteQuery: "",
  toast: undefined as { text: string; tone: "ok" | "error" } | undefined,
};

/** Native file pickers, provided by the app handle once the window is up. */
export const dialogs = {
  open: async (): Promise<string[]> => [],
  save: async (_name: string): Promise<string | undefined> => undefined,
};

let render: () => void = () => {};
export function setRenderer(next: () => void): void {
  render = next;
}
export function refresh(): void {
  render();
}

let toastTimer: ReturnType<typeof setTimeout> | undefined;
export function toast(text: string, tone: "ok" | "error" = "ok"): void {
  ui.toast = { text, tone };
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { ui.toast = undefined; render(); }, 3200);
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
    reload();
  } else {
    ui.phase = status.exists ? "locked" : "create";
  }
}

export function createVault(password: string, confirm: string): void {
  if (password !== confirm) {
    ui.error = "The two passwords differ.";
    return render();
  }
  if (attempt(() => core().call({ op: "vault.create", password })) !== undefined) enterVault();
}

export function unlockVault(password: string): void {
  if (attempt(() => core().call({ op: "vault.unlock", password })) !== undefined) enterVault();
}

export function joinVault(password: string, r2: SyncForm): void {
  const joined = attempt(() => core().call<{ pulled: number }>({ op: "vault.join", password, ...r2 }));
  if (joined) {
    enterVault();
    toast(`Joined the synced vault: ${joined.pulled} items`);
  }
}

/** A first vault that lives in an empty bucket from the start: created here, then synced up. */
export function createSyncedVault(password: string, confirm: string, r2: SyncForm): void {
  createVault(password, confirm);
  if (ui.phase === "ready") configureSync(r2);
}

/** Whether a bucket already holds a vault; undefined when the check failed (reason in ui.error). */
export function probeBucket(r2: SyncForm): boolean | undefined {
  return attempt(() => core().call<{ hasVault: boolean }>({ op: "sync.probe", ...r2 }))?.hasVault;
}

function enterVault(): void {
  ui.phase = "ready";
  const status = core().call<{ syncConfigured: boolean }>({ op: "vault.status" });
  ui.sync.configured = status.syncConfigured;
  reload();
}

export function lockVault(): void {
  for (const tab of [...ui.tabs]) closeTab(tab.id);
  core().call({ op: "vault.lock" });
  Object.assign(ui, { phase: "locked", hosts: [], keys: [], known: [], editing: undefined, active: "home", prompts: [] });
  render();
}

export function reload(): void {
  const list = <T,>(kind: string) => core().call<{ records: VaultRecord<T>[] }>({ op: "records.list", kind }).records;
  ui.hosts = list<HostData>("host");
  ui.keys = list<KeyData>("key");
  ui.known = list<KnownHostData>("known_host");
  ui.snippets = list<SnippetData>("snippet");
  const settings = core().call<VaultRecord<SyncSettings> | null>({ op: "sync.settings" });
  ui.syncSettings = settings?.data ?? undefined;
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

/** `user@host:port`, `host:port` or `host`. */
export function parseQuickConnect(text: string): Partial<HostData> | undefined {
  const match = /^\s*(?:([^@\s]+)@)?(\[[^\]]+\]|[^:\s]+)(?::(\d{1,5}))?\s*$/.exec(text);
  if (!match) return undefined;
  return { user: match[1] ?? "", address: match[2]!.replace(/^\[|\]$/g, ""), port: match[3] ? Number(match[3]) : 22 };
}

// --- Tabs and panes ------------------------------------------------------------------------

let nextTab = 1;

function newSession(host: VaultRecord<HostData> | undefined): number | undefined {
  const opened = attempt(() => host ? core().call<{ id: number }>({ op: "ssh.open", host: host.id }) : core().call<{ id: number }>({ op: "session.open", kind: "local" }));
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
  account: string;
  bucket: string;
  accessKey: string;
  secretKey: string;
  endpoint?: string;
}

export function configureSync(form: SyncForm): void {
  ui.busy = true;
  render();
  const result = attempt(() => core().call<{ pulled: number; pushed: number }>({ op: "sync.configure", ...form }));
  ui.busy = false;
  if (result) {
    ui.sync = { configured: true, state: "done", message: undefined, at: Date.now() };
    reload();
    toast(`Sync is on: ${result.pushed} sent, ${result.pulled} received`);
  }
}

export function syncNow(): void {
  attempt(() => core().call({ op: "sync.run" }));
}

export function disableSync(): void {
  if (attempt(() => core().call({ op: "sync.disable" })) !== undefined) {
    ui.sync = { configured: false, state: "idle", message: undefined, at: 0 };
    reload();
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
      case "hostkey":
        ui.prompts.push(event as unknown as HostKeyPrompt);
        break;
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
        void browse(files, String(event.home ?? "/"));
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
