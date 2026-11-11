import { Column, Pressable, Row, Scroll, Select, Text, Modal } from "@tarve/core";
import {
  connect,
  editHost,
  newHost,
  openFiles,
  parseQuickConnect,
  removeHost,
  saveHost,
  ui,
  type HostData,
  type VaultRecord, importScanned, refresh, scanImport, type ImportHost, type ImportScan, type ImportSource } from "../state/store";
import { AgentCard } from "./AgentCard";
import { Glyph } from "../ui/icons";
import { ANDROID, Action, compact, dialogWidth, Field, gutter, Hint, IconAction, Label, Segments, TextField, mono, relativeTime, touch } from "../ui/kit";
import { color, labels, radius } from "../ui/tokens";

let quick = "";
let hovered: string | undefined;

function address(host: HostData): string {
  const user = host.user ? `${host.user}@` : "";
  const port = host.port && host.port !== 22 ? `:${host.port}` : "";
  return `${user}${host.address}${port}`;
}

function matches(host: VaultRecord<HostData>, query: string): boolean {
  if (!query) return true;
  const haystack = `${host.data.name} ${host.data.address} ${host.data.user ?? ""} ${host.data.group ?? ""}`.toLowerCase();
  return query.toLowerCase().split(/\s+/).every(word => haystack.includes(word));
}

function quickConnect(text: string): void {
  const parsed = parseQuickConnect(text);
  if (!parsed) return;
  const existing = ui.hosts.find(host => host.data.address === parsed.address && (host.data.port ?? 22) === parsed.port && (!parsed.user || host.data.user === parsed.user));
  quick = "";
  if (existing) return connect(existing.id);
  // A new address: save it first so the password or key has somewhere to live.
  newHost({ ...parsed, name: parsed.address });
}

function HostRow({ host }: { host: VaultRecord<HostData> }) {
  const data = host.data;
  const active = hovered === host.id || ui.editing?.id === host.id;
  const narrow = compact();
  const jump = data.jump ? ui.hosts.find(other => other.id === data.jump)?.data.name : undefined;
  return (
    <Pressable
      key={host.id}
      focusable
      onClick={() => connect(host.id)}
      // Only entering counts: the leave the row reports when the pointer moves onto one of its
      // own buttons would hide the buttons under the pointer, and they flickered.
      onHover={inside => { if (inside && hovered !== host.id) hovered = host.id; }}
      onKeyDown={key => { if (key === "Enter") connect(host.id); }}
      style={{
        direction: "row",
        align: "center",
        gap: narrow ? 8 : 12,
        height: narrow ? 56 : 48,
        padding: { left: 14, right: 8 },
        radius: radius.control,
        background: ui.editing?.id === host.id ? color.raised : "transparent",
        hover: { background: color.raised },
        focusVisible: { outlineWidth: 2, outlineColor: color.accent },
      }}
    >
      <Row style={{ width: 8, height: 8, radius: 4, background: labels[data.color ?? "slate"] ?? labels.slate }} />
      <Column flex={1} gap={2} style={{ minWidth: 0 }}>
        <Text size={13.5} weight={600} color={color.text} style={{ whiteSpace: "nowrap", textOverflow: "ellipsis" }}>{data.name}</Text>
        <Row gap={8} align="center" style={{ minWidth: 0, overflow: "hidden" }}>
          <Text size={12} color={color.muted} style={{ ...mono, whiteSpace: "nowrap", textOverflow: "ellipsis", shrink: 1, minWidth: 0 }}>{address(data)}</Text>
          {jump && !narrow ? (
            <Row gap={4} align="center" style={{ shrink: 0 }}>
              <Glyph name="route" size={12} color={color.faint} />
              <Text size={11.5} color={color.faint} style={{ whiteSpace: "nowrap" }}>{`via ${jump}`}</Text>
            </Row>
          ) : null}
        </Row>
      </Column>
      <Row gap={6} align="center">
        {data.key ? <Glyph name="key" size={13} color={color.faint} /> : null}
        {narrow ? null : <Text size={11.5} color={color.faint} style={{ width: 84, textAlign: "end", whiteSpace: "nowrap" }}>{relativeTime(data.lastConnected)}</Text>}
      </Row>
      {/* A finger has no hover: the buttons stay visible, and the row itself connects. */}
      <Row gap={2} style={{ opacity: active || touch() ? 1 : 0, width: narrow ? undefined : 96, shrink: 0, justify: "end" }}>
        <IconAction icon="folder" label={`Files on ${data.name}`} onClick={() => openFiles(host.id)} />
        <IconAction icon="pencil" label={`Edit ${data.name}`} onClick={() => editHost(host.id)} />
        {narrow ? null : <IconAction icon="play" label={`Connect to ${data.name}`} color={color.accent} onClick={() => connect(host.id)} />}
      </Row>
    </Pressable>
  );
}

let importOpen = false;
let importSource: ImportSource = "sshConfig";
let importScan: ImportScan | undefined;
let importChosen = new Set<string>();
let importKeys = true;

const sources: readonly { value: ImportSource; label: string }[] = [
  { value: "sshConfig", label: "~/.ssh/config" },
  { value: "filezilla", label: "FileZilla" },
  { value: "termius", label: "Termius" },
];

/** Reads the hosts of `source` and ticks every one the vault does not have yet. */
async function scan(source: ImportSource): Promise<void> {
  importSource = source;
  importScan = undefined;
  ui.error = undefined;
  importScan = scanImport(source);
  importChosen = new Set(importScan?.hosts.filter(host => !host.exists).map(host => host.key) ?? []);
  refresh();
}

/** Opens the import picker on `~/.ssh/config`. */
function openImport(): void {
  importKeys = true;
  importOpen = true;
  void scan("sshConfig");
}

function reach(host: ImportHost): string {
  const user = host.user ? `${host.user}@` : "";
  const port = host.port && host.port !== 22 ? `:${host.port}` : "";
  return `${user}${host.address}${port}`;
}

function emptyText(): string {
  if (ui.error) return ui.error;
  if (importSource === "filezilla") return importScan?.skipped ? `FileZilla has ${importScan.skipped} sites, none of them SFTP: only SFTP sites are SSH servers.` : "FileZilla's Site Manager has no sites.";
  if (importSource === "termius") return importScan?.skipped ? `Termius has ${importScan.skipped} entries that could not be read: it may have changed how it stores them.` : "Termius has no saved hosts: log in to Termius once on this computer.";
  return "No named hosts in ~/.ssh/config: a Host line with * or ? describes a pattern, not a server.";
}

function summary(scan: ImportScan): string {
  const skipped = scan.skipped ? `, ${scan.skipped} skipped (not SSH)` : "";
  return `${scan.hosts.length} hosts${skipped}`;
}

/** Hosts saved by OpenSSH, FileZilla or Termius, ticked off before they are saved into the vault. */
function ImportHosts() {
  const hosts = importScan?.hosts ?? [];
  const chosen = hosts.filter(host => importChosen.has(host.key));
  const label = chosen.length === 1 ? "Import 1 host" : `Import ${chosen.length} hosts`;
  const from = importScan?.source ?? importSource;
  const withKeys = hosts.some(host => host.identityFile || host.hasKey);
  const allOn = hosts.length > 0 && chosen.length === hosts.length;
  return (
    <Modal
      open={importOpen}
      onOpenChange={open => { importOpen = open; refresh(); }}
      title="Import hosts"
      width={dialogWidth(620)}
      footer={
        <Row gap={8} justify="end">
          <Action label="Cancel" onClick={() => { importOpen = false; refresh(); }} />
          <Action tone="primary" icon="download" label={label} disabled={chosen.length === 0} onClick={() => { importOpen = false; importScanned(chosen.map(host => host.key), importKeys, from); }} />
        </Row>
      }
    >
      <Column gap={14}>
        <Row gap={10} align="center">
          <Segments value={importSource} options={sources} onChange={value => { void scan(value); }} />
        </Row>
        {importScan ? <Text size={11.5} color={color.faint} style={{ ...mono, whiteSpace: "nowrap", textOverflow: "ellipsis" }}>{importScan.path}</Text> : null}
        {hosts.length === 0 ? (
          <Text size={13} color={color.muted} style={{ lineHeight: 1.45 }}>{emptyText()}</Text>
        ) : (
          <Column gap={6}>
            <Row align="center" justify="between">
              <Text size={12} color={color.muted}>{summary(importScan!)}</Text>
              <Action label={allOn ? "Select none" : "Select all"} onClick={() => { importChosen = new Set(allOn ? [] : hosts.map(host => host.key)); refresh(); }} />
            </Row>
            <Scroll style={{ maxHeight: 300 }}>
              <Column gap={2}>
                {hosts.map(host => {
                  const on = importChosen.has(host.key);
                  return (
                    <Pressable
                      key={host.key}
                      focusable
                      control={{ role: "checkbox", label: host.name, checked: on }}
                      onClick={() => {
                        if (on) importChosen.delete(host.key);
                        else importChosen.add(host.key);
                        refresh();
                      }}
                      style={{ direction: "row", align: "center", gap: 10, height: 42, padding: { left: 10, right: 10 }, radius: radius.control, hover: { background: color.raised } }}
                    >
                      <Row
                        align="center"
                        justify="center"
                        style={{ width: 16, height: 16, radius: 4, borderColor: on ? color.accent : color.lineStrong, borderWidth: 1, background: on ? color.accentSoft : "transparent" }}
                      >
                        {on ? <Glyph name="check" size={11} color={color.accent} strokeWidth={2.5} /> : null}
                      </Row>
                      <Column flex={1} gap={2} style={{ minWidth: 0 }}>
                        <Row gap={8} align="center">
                          <Text size={13} weight={600} color={color.text} style={{ whiteSpace: "nowrap", textOverflow: "ellipsis" }}>{host.name}</Text>
                          {host.group ? <Text size={11} color={color.faint}>{host.group}</Text> : null}
                        </Row>
                        <Text size={11.5} color={color.faint} style={{ ...mono, whiteSpace: "nowrap", textOverflow: "ellipsis" }}>{reach(host)}</Text>
                      </Column>
                      {host.exists ? <Text size={11} color={color.warn}>already saved</Text> : null}
                      {host.hasPassword ? <Glyph name="lock" size={13} color={color.faint} /> : null}
                      {host.identityFile || host.hasKey ? <Glyph name="key" size={13} color={color.faint} /> : null}
                    </Pressable>
                  );
                })}
              </Column>
            </Scroll>
          </Column>
        )}
        {withKeys ? (
          <Column gap={6}>
            <Label>Key files</Label>
            <Segments
              value={importKeys ? "keys" : "hosts"}
              options={[{ value: "hosts", label: "Hosts only" }, { value: "keys", label: "Import keys too" }]}
              onChange={value => { importKeys = value === "keys"; refresh(); }}
            />
            <Hint>Key files the hosts name are copied into the vault; encrypted ones are left where they are. Keys kept inside Termius come with their passphrase.</Hint>
          </Column>
        ) : null}
        <Hint>Saved passwords come along, encrypted in the vault. FileZilla passwords behind its master password cannot be read: those hosts come without one. Termius has no export: its hosts are read from the app's own data.</Hint>
      </Column>
    </Modal>
  );
}

function Empty() {
  return (
    <Column flex={1} align="center" justify="center" gap={10} style={{ padding: compact() ? 20 : 40 }}>
      <Text size={17} weight={650} color={color.text}>No hosts yet</Text>
      <Text size={13} color={color.muted} style={{ textAlign: "center", maxWidth: 380, lineHeight: 1.5 }}>
        Type user@server above and press Enter, or add one with its password or key. Everything you save is encrypted in your vault.
      </Text>
      <Row style={{ margin: { top: 8 } }} gap={8}>
        {ANDROID ? null : <Action icon="download" label="Import" onClick={openImport} />}
        <Action tone="primary" icon="plus" label="New host" onClick={() => newHost()} />
      </Row>
    </Column>
  );
}

function Editor() {
  const editing = ui.editing!;
  const data = editing.data;
  const usesKey = Boolean(data.key);
  const keyOptions = ui.keys.map(key => ({ value: key.id, label: `${key.data.name} · ${key.data.algorithm}` }));
  const jumpOptions = [{ value: "", label: "Direct connection" }, ...ui.hosts.filter(host => host.id !== editing.id).map(host => ({ value: host.id, label: host.data.name }))];
  return (
    <Column style={compact()
      // A phone has no room beside the list: the editor covers it.
      ? { position: "absolute", left: 0, top: 0, right: 0, bottom: 0, background: color.panel }
      : { width: 360, shrink: 1, minWidth: 300, background: color.panel, borderColor: color.line, borderWidth: { left: 1 } }}>
      <Row align="center" justify="between" style={{ height: 56, padding: { left: 20, right: 12 } }}>
        <Text size={15} weight={650} color={color.text}>{editing.id ? "Edit host" : "New host"}</Text>
        <IconAction icon="x" label="Close" onClick={() => { ui.editing = undefined; ui.error = undefined; }} />
      </Row>
      <Scroll flex={1}>
        <Column gap={16} style={{ padding: { left: 20, right: 20, bottom: 20 } }}>
          <Field id="host-name" label="Name" value={data.name} placeholder="Production API" onChange={value => { data.name = value; }} />
          <Row gap={10}>
            <Field label="Address" value={data.address} placeholder="203.0.113.10 or host.example.com" monospace grow={3} onChange={value => { data.address = value; }} />
            <Field label="Port" value={String(data.port ?? 22)} monospace grow={1} onChange={value => { const port = Number(value.replace(/\D/g, "")); data.port = port || undefined; }} />
          </Row>
          <Field label="User" value={data.user ?? ""} placeholder="root" monospace onChange={value => { data.user = value; }} />
          <Column gap={8}>
            <Label>Sign in with</Label>
            <Segments
              value={usesKey ? "key" : "password"}
              options={[{ value: "password", label: "Password" }, { value: "key", label: "Key" }]}
              onChange={value => { data.key = value === "key" ? (ui.keys[0]?.id ?? "") : undefined; }}
            />
            {usesKey || data.key === "" ? (
              keyOptions.length ? (
                <Select style={{ width: "100%" }} id="host-key" value={data.key || undefined} options={keyOptions} placeholder="Choose a key" onValueChange={value => { data.key = value; }} />
              ) : (
                <Hint>No keys yet. Create or import one under Keychain.</Hint>
              )
            ) : (
              <TextField
                type="password"
                value={data.password ?? ""}
                placeholder={data.hasPassword ? "Saved. Type to replace it" : "Password"}
                onChange={value => { data.password = value; }}
              />
            )}
          </Column>
          <Column gap={6}>
            <Label>Jump host</Label>
            <Select style={{ width: "100%" }} id="host-jump" value={data.jump ?? ""} options={jumpOptions} onValueChange={value => { data.jump = value || undefined; }} />
            <Hint>Reach this server through another one, like ProxyJump.</Hint>
          </Column>
          <Column gap={6}>
            <Label>Session</Label>
            <Segments
              value={data.agent === false ? "ssh" : "agent"}
              options={[{ value: "agent", label: "Resumable" }, { value: "ssh", label: "Plain SSH" }]}
              onChange={value => { data.agent = value === "agent"; }}
            />
            <Hint>{data.agent === false ? "A standard SSH channel: works everywhere, ends when the link drops." : "Runs through termio-agent over QUIC; plain SSH when the server lacks it."}</Hint>
            {data.agent !== false && editing.id && !ANDROID ? <AgentCard hostId={editing.id} /> : null}
            {data.agent !== false && ANDROID ? <Hint>Install the agent on the server from Termio on a computer; this phone then resumes through it.</Hint> : null}
            </Column>
          {/* No ssh-agent runs on Android. */}
          {ANDROID ? null : (
            <Column gap={6}>
              <Label>ssh-agent</Label>
              <Segments
                value={data.useAgent ? "on" : "off"}
                options={[{ value: "off", label: "Off" }, { value: "on", label: "On" }]}
                onChange={value => { data.useAgent = value === "on"; }}
              />
              <Hint>Sign in with the keys your ssh-agent holds, the way ssh itself does.</Hint>
            </Column>
          )}
          <Column gap={8}>
            <Row align="center" justify="between">
              <Label>Port forwarding</Label>
              <IconAction icon="plus" label="Add a forward" onClick={() => { data.forwards = [...(data.forwards ?? []), { local: 8080, host: "127.0.0.1", port: 80 }]; }} />
            </Row>
            {(data.forwards ?? []).map((rule, index) => (
              <Row key={String(index)} gap={6} align="center">
                <TextField value={String(rule.local || "")} placeholder="Local" onChange={value => { rule.local = Number(value.replace(/\D/g, "")); }} style={{ width: 70, ...mono, fontSize: 12 }} />
                <Glyph name="route" size={13} color={color.faint} />
                <TextField value={rule.host} placeholder="127.0.0.1" onChange={value => { rule.host = value; }} style={{ flex: 1, ...mono, fontSize: 12 }} />
                <TextField value={String(rule.port || "")} placeholder="Port" onChange={value => { rule.port = Number(value.replace(/\D/g, "")); }} style={{ width: 64, ...mono, fontSize: 12 }} />
                <IconAction icon="x" label="Remove this forward" onClick={() => { data.forwards = (data.forwards ?? []).filter((_, other) => other !== index); }} />
              </Row>
            ))}
            <Hint>{data.forwards?.length ? "localhost:local on this computer reaches host:port as the server sees it, while the session is open." : "Reach a database or dashboard behind the server, like ssh -L."}</Hint>
          </Column>
          <Field label="Group" value={data.group ?? ""} placeholder="Ungrouped" onChange={value => { data.group = value; }} />
          <Column gap={8}>
            <Label>Label</Label>
            <Row gap={8}>
              {Object.entries(labels).map(([name, swatch]) => (
                <Pressable
                  key={name}
                  focusable
                  onClick={() => { data.color = name; }}
                  control={{ role: "radio", label: name, checked: (data.color ?? "slate") === name }}
                  style={{ width: 22, height: 22, radius: 11, background: swatch, borderColor: (data.color ?? "slate") === name ? color.text : "transparent", borderWidth: 2 }}
                />
              ))}
            </Row>
          </Column>
          {ui.error ? <Hint tone="danger">{ui.error}</Hint> : null}
        </Column>
      </Scroll>
      <Row gap={8} align="center" style={{ padding: 16, borderColor: color.line, borderWidth: { top: 1 } }}>
        {editing.id ? <Action tone="danger" icon="trash" label="Delete" onClick={() => removeHost(editing.id!)} /> : null}
        <Row flex={1} />
        <Action label="Cancel" onClick={() => { ui.editing = undefined; ui.error = undefined; }} />
        <Action tone="primary" label="Save" onClick={saveHost} />
      </Row>
    </Column>
  );
}

type Order = "recent" | "name" | "group";
/** How the list is ordered: the hosts used last come first unless the user picks otherwise. */
let order: Order = "recent";
const ORDERS: readonly { value: Order; label: string }[] = [
  { value: "recent", label: "Recent" },
  { value: "name", label: "Name" },
  { value: "group", label: "Group" },
];

const byName = (a: VaultRecord<HostData>, b: VaultRecord<HostData>) => a.data.name.localeCompare(b.data.name);
/** Most recently connected first; hosts never opened follow, by name. */
const byRecent = (a: VaultRecord<HostData>, b: VaultRecord<HostData>) => (b.data.lastConnected ?? 0) - (a.data.lastConnected ?? 0) || byName(a, b);

/** The sections of the list: one per group when grouping, else a single one. */
function sections(visible: VaultRecord<HostData>[]): [string, VaultRecord<HostData>[]][] {
  if (order !== "group") return [["", [...visible].sort(order === "recent" ? byRecent : byName)]];
  const groups = new Map<string, VaultRecord<HostData>[]>();
  for (const host of [...visible].sort(byName)) {
    const group = host.data.group?.trim() || "";
    groups.set(group, [...(groups.get(group) ?? []), host]);
  }
  return [...groups.entries()].sort(([a], [b]) => (a === "" ? 1 : b === "" ? -1 : a.localeCompare(b)));
}

function HostFilter() {
  return (
    <Row flex={1} style={{ maxWidth: compact() ? undefined : 240, minWidth: 0, overflow: "hidden", position: "relative" }} align="center">
      <TextField id="host-search" value={ui.search} placeholder="Filter" onChange={value => { ui.search = value; }} style={{ flex: 1, minWidth: 0, padding: { left: 32, right: 10 } }} />
      <Row style={{ position: "absolute", left: 10, pointerEvents: "none" }}>
        <Glyph name="search" size={14} color={color.faint} />
      </Row>
    </Row>
  );
}

export function Hosts() {
  const visible = ui.hosts.filter(host => matches(host, ui.search));
  const ordered = sections(visible);
  const parsed = parseQuickConnect(quick);
  const narrow = compact();
  return (
    <Row flex={1} align="stretch" style={{ position: "relative", minHeight: 0 }}>
      <Column flex={1} style={{ minWidth: 0 }}>
        <Column gap={14} style={{ padding: { top: narrow ? 14 : 22, left: gutter(), right: gutter(), bottom: 14 } }}>
          <Row align="center" justify="between">
            <Row gap={10} align="center">
              <Text size={20} weight={650} color={color.text} style={{ letterSpacing: -0.3 }}>Hosts</Text>
              <Text size={13} color={color.faint}>{String(ui.hosts.length)}</Text>
            </Row>
            <Row gap={8} align="center">
              {/* Android has no ~/.ssh/config, FileZilla or Termius data to read. */}
              {ANDROID ? null : narrow ? <IconAction icon="download" label="Import" onClick={openImport} /> : <Action icon="download" label="Import" onClick={openImport} />}
              <Action tone="primary" icon="plus" label={narrow ? "New" : "New host"} onClick={() => newHost()} />
            </Row>
          </Row>
          <Row gap={10} style={{ minWidth: 0 }}>
            <Row flex={2} align="center" style={{ position: "relative", minWidth: 0, overflow: "hidden" }}>
              <TextField
                id="quick-connect"
                value={quick}
                placeholder="Connect to user@host:port"
                onChange={value => { quick = value; }}
                onSubmit={quickConnect}
                style={{ flex: 1, minWidth: 0, padding: { left: 34, right: 10 }, fontFamily: "Cascadia Mono", fontSize: 12.5 }}
              />
              <Row style={{ position: "absolute", left: 11, pointerEvents: "none" }}>
                <Glyph name="terminal" size={14} color={parsed ? color.accent : color.faint} />
              </Row>
            </Row>
            {narrow ? null : <HostFilter />}
          </Row>
          {/* Side by side the two fields do not fit a phone: the filter gets a line of its own. */}
          {narrow ? <Row style={{ minWidth: 0 }}><HostFilter /></Row> : null}
          {ui.hosts.length > 0 ? (
            <Row gap={10} align="center">
              <Text size={12} color={color.faint}>Sort</Text>
              <Segments value={order} options={ORDERS} onChange={value => { order = value; }} />
            </Row>
          ) : null}
        </Column>
        {ui.hosts.length === 0 ? (
          <Empty />
        ) : (
          <Scroll flex={1}>
            <Column gap={18} style={{ padding: { left: narrow ? 6 : 20, right: narrow ? 6 : 20, bottom: 24 } }}>
              {ordered.map(([group, hosts]) => (
                <Column key={group || "-"} gap={2}>
                  <Row style={{ padding: { left: 14, bottom: 6 } }}>
                    <Text size={11.5} weight={650} color={color.faint}>{order === "recent" ? "Recently used" : order === "name" ? "All hosts" : group || (ordered.length > 1 ? "Ungrouped" : "All hosts")}</Text>
                  </Row>
                  {hosts.map(host => <HostRow key={host.id} host={host} />)}
                </Column>
              ))}
              {visible.length === 0 ? <Row style={{ padding: 14 }}><Text size={13} color={color.muted}>{`Nothing matches "${ui.search}".`}</Text></Row> : null}
            </Column>
          </Scroll>
        )}
      </Column>
      {ui.editing ? <Editor /> : null}
        <ImportHosts />
    </Row>
  );
}
