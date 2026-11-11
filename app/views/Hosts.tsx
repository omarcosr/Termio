import { Column, Pressable, Row, Scroll, Select, Text } from "@tarve/core";
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
  type VaultRecord,
} from "../state/store";
import { Glyph } from "../ui/icons";
import { Action, Field, Hint, IconAction, Label, Segments, TextField, mono, relativeTime } from "../ui/kit";
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
  const jump = data.jump ? ui.hosts.find(other => other.id === data.jump)?.data.name : undefined;
  return (
    <Pressable
      key={host.id}
      focusable
      onClick={() => connect(host.id)}
      onHover={inside => { hovered = inside ? host.id : hovered === host.id ? undefined : hovered; }}
      onKeyDown={key => { if (key === "Enter") connect(host.id); }}
      style={{
        direction: "row",
        align: "center",
        gap: 12,
        height: 48,
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
        <Row gap={8} align="center">
          <Text size={12} color={color.muted} style={mono}>{address(data)}</Text>
          {jump ? (
            <Row gap={4} align="center">
              <Glyph name="route" size={12} color={color.faint} />
              <Text size={11.5} color={color.faint}>{`via ${jump}`}</Text>
            </Row>
          ) : null}
        </Row>
      </Column>
      <Row gap={6} align="center">
        {data.key ? <Glyph name="key" size={13} color={color.faint} /> : null}
        <Text size={11.5} color={color.faint} style={{ width: 84, textAlign: "end" }}>{relativeTime(data.lastConnected)}</Text>
      </Row>
      <Row gap={2} style={{ opacity: active ? 1 : 0, width: 96, justify: "end" }}>
        <IconAction icon="folder" label={`Files on ${data.name}`} onClick={() => openFiles(host.id)} />
        <IconAction icon="pencil" label={`Edit ${data.name}`} onClick={() => editHost(host.id)} />
        <IconAction icon="play" label={`Connect to ${data.name}`} color={color.accent} onClick={() => connect(host.id)} />
      </Row>
    </Pressable>
  );
}

function Empty() {
  return (
    <Column flex={1} align="center" justify="center" gap={10} style={{ padding: 40 }}>
      <Text size={17} weight={650} color={color.text}>No hosts yet</Text>
      <Text size={13} color={color.muted} style={{ textAlign: "center", maxWidth: 380, lineHeight: 1.5 }}>
        Type user@server above and press Enter, or add one with its password or key. Everything you save is encrypted in your vault.
      </Text>
      <Row style={{ margin: { top: 8 } }}>
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
    <Column style={{ width: 360, background: color.panel, borderColor: color.line, borderWidth: { left: 1 } }}>
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
                <Select id="host-key" value={data.key || undefined} options={keyOptions} placeholder="Choose a key" onValueChange={value => { data.key = value; }} />
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
            <Select id="host-jump" value={data.jump ?? ""} options={jumpOptions} onValueChange={value => { data.jump = value || undefined; }} />
            <Hint>Reach this server through another one, like ProxyJump.</Hint>
          </Column>
          <Column gap={6}>
            <Label>Session</Label>
            <Segments
              value={data.agent === false ? "ssh" : "agent"}
              options={[{ value: "agent", label: "Resumable" }, { value: "ssh", label: "Plain SSH" }]}
              onChange={value => { data.agent = value === "agent"; }}
            />
            <Hint>{data.agent === false ? "A standard SSH channel: works everywhere, ends when the link drops." : "With termio-agent on the server the session runs over QUIC: it survives dropped links, sleep and network changes, and a flood of output cannot clog the line. Falls back to plain SSH when the agent is missing."}</Hint>
          </Column>
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

export function Hosts() {
  const visible = ui.hosts.filter(host => matches(host, ui.search));
  const groups = new Map<string, VaultRecord<HostData>[]>();
  for (const host of [...visible].sort((a, b) => a.data.name.localeCompare(b.data.name))) {
    const group = host.data.group?.trim() || "";
    groups.set(group, [...(groups.get(group) ?? []), host]);
  }
  const ordered = [...groups.entries()].sort(([a], [b]) => (a === "" ? 1 : b === "" ? -1 : a.localeCompare(b)));
  const parsed = parseQuickConnect(quick);
  return (
    <Row flex={1} align="stretch">
      <Column flex={1} style={{ minWidth: 0 }}>
        <Column gap={14} style={{ padding: { top: 22, left: 28, right: 28, bottom: 14 } }}>
          <Row align="center" justify="between">
            <Row gap={10} align="baseline">
              <Text size={20} weight={650} color={color.text} style={{ letterSpacing: -0.3 }}>Hosts</Text>
              <Text size={13} color={color.faint}>{String(ui.hosts.length)}</Text>
            </Row>
            <Action tone="primary" icon="plus" label="New host" onClick={() => newHost()} />
          </Row>
          <Row gap={10}>
            <Row flex={1} align="center" style={{ position: "relative" }}>
              <TextField
                id="quick-connect"
                value={quick}
                placeholder="Connect to user@host:port"
                onChange={value => { quick = value; }}
                onSubmit={quickConnect}
                style={{ flex: 1, padding: { left: 34, right: 10 }, fontFamily: "Cascadia Mono", fontSize: 12.5 }}
              />
              <Row style={{ position: "absolute", left: 11, pointerEvents: "none" }}>
                <Glyph name="terminal" size={14} color={parsed ? color.accent : color.faint} />
              </Row>
            </Row>
            <Row style={{ width: 240, position: "relative" }} align="center">
              <TextField id="host-search" value={ui.search} placeholder="Filter" onChange={value => { ui.search = value; }} style={{ flex: 1, padding: { left: 32, right: 10 } }} />
              <Row style={{ position: "absolute", left: 10, pointerEvents: "none" }}>
                <Glyph name="search" size={14} color={color.faint} />
              </Row>
            </Row>
          </Row>
        </Column>
        {ui.hosts.length === 0 ? (
          <Empty />
        ) : (
          <Scroll flex={1}>
            <Column gap={18} style={{ padding: { left: 20, right: 20, bottom: 24 } }}>
              {ordered.map(([group, hosts]) => (
                <Column key={group || "-"} gap={2}>
                  <Row style={{ padding: { left: 14, bottom: 6 } }}>
                    <Text size={11.5} weight={650} color={color.faint}>{group || (ordered.length > 1 ? "Ungrouped" : "All hosts")}</Text>
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
    </Row>
  );
}
