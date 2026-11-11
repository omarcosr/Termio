import { Column, CommandPalette, Pressable, Row, Text, TitleBar, type CommandItem } from "@tarve/core";
import {
  activate,
  closePane,
  closeTab,
  connect,
  focusPane,
  lockVault,
  newHost,
  openFiles,
  openLocal,
  reconnect,
  runSnippet,
  broadcastSnippet,
  split,
  syncNow,
  tabTitle,
  ui,
  type SessionInfo,
  type SessionStatus,
  type Tab,
  type View,
} from "../state/store";
import { Glyph, type IconId } from "../ui/icons";
import { Action, IconAction, mono } from "../ui/kit";
import { color, font, radius } from "../ui/tokens";
import { Files } from "./Files";
import { HostKeyPrompt } from "./HostKeyPrompt";
import { Hosts } from "./Hosts";
import { Keychain, KnownHosts } from "./Keychain";
import { Snippets } from "./Snippets";
import { Sync } from "./Sync";
import { TerminalPane } from "./TerminalPane";
import { Unlock } from "./Unlock";

const statusTone: Record<SessionStatus, string> = {
  connecting: color.warn,
  authenticating: color.warn,
  reconnecting: color.warn,
  connected: color.ok,
  closed: color.faint,
};

/** The worst state among a tab's panes, for its dot. */
function tabTone(tab: Tab): string {
  if (tab.kind === "files") return tab.files?.state === "ready" ? color.ok : tab.files?.state === "error" ? color.danger : color.warn;
  const states = tab.panes.map(session => ui.sessions[session]?.status ?? "closed");
  const worst = (["closed", "reconnecting", "authenticating", "connecting"] as const).find(state => states.includes(state));
  return statusTone[worst ?? "connected"];
}

function TabButton({ tab }: { tab: Tab }) {
  const active = ui.active === tab.id;
  const title = tabTitle(tab);
  return (
    <Pressable
      key={tab.id}
      focusable
      onClick={() => activate(tab.id)}
      control={{ role: "tab", label: title, selected: active }}
      style={{
        direction: "row",
        align: "center",
        gap: 8,
        height: 30,
        padding: { left: 12, right: 4 },
        maxWidth: 230,
        radius: radius.control,
        background: active ? color.raised : "transparent",
        borderColor: active ? color.line : "transparent",
        borderWidth: 1,
        hover: { background: active ? color.raised : color.hover },
      }}
    >
      {tab.kind === "files" ? <Glyph name="folder" size={13} color={active ? color.accent : color.muted} /> : <Row style={{ width: 6, height: 6, radius: 3, background: tabTone(tab) }} />}
      <Text size={12.5} weight={active ? 600 : 500} color={active ? color.text : color.muted} style={{ whiteSpace: "nowrap", textOverflow: "ellipsis", flex: 1 }}>{title}</Text>
      <IconAction icon="x" size={22} label={`Close ${title}`} onClick={() => closeTab(tab.id)} />
    </Pressable>
  );
}

function Tabs() {
  const home = ui.active === "home";
  return (
    <Row gap={4} align="center" flex={1} style={{ padding: { left: 6 } }}>
      <Pressable
        focusable
        onClick={() => activate("home")}
        control={{ role: "tab", label: "Vault", selected: home }}
        style={{ direction: "row", align: "center", gap: 8, height: 30, padding: { left: 10, right: 12 }, radius: radius.control, background: home ? color.raised : "transparent", borderColor: home ? color.line : "transparent", borderWidth: 1, hover: { background: home ? color.raised : color.hover } }}
      >
        <Row style={{ width: 18, height: 18, radius: 5, background: color.accent, align: "center", justify: "center" }}>
          <Glyph name="terminal" size={11} color={color.accentInk} strokeWidth={2.5} />
        </Row>
        <Text size={12.5} weight={600} color={home ? color.text : color.muted}>Termio</Text>
      </Pressable>
      {ui.tabs.length ? <Row style={{ width: 1, height: 16, background: color.line, margin: { left: 4, right: 4 } }} /> : null}
      {ui.tabs.map(tab => <TabButton key={tab.id} tab={tab} />)}
      <IconAction icon="plus" label="New local terminal" onClick={openLocal} />
      <Row flex={1} dragRegion style={{ height: 30 }} />
    </Row>
  );
}

function NavItem({ view, icon, label, count }: { view: View; icon: IconId; label: string; count?: number }) {
  const active = ui.view === view;
  return (
    <Pressable
      focusable
      onClick={() => { ui.view = view; ui.error = undefined; }}
      control={{ role: "tab", label, selected: active }}
      style={{
        direction: "row",
        align: "center",
        gap: 10,
        height: 34,
        padding: { left: 10, right: 10 },
        radius: radius.control,
        background: active ? color.raised : "transparent",
        hover: { background: active ? color.raised : color.hover },
        focusVisible: { outlineWidth: 2, outlineColor: color.accent },
      }}
    >
      <Glyph name={icon} size={16} color={active ? color.accent : color.muted} />
      <Text size={13} weight={active ? 600 : 500} color={active ? color.text : color.muted} style={{ flex: 1 }}>{label}</Text>
      {count !== undefined ? <Text size={11.5} color={color.faint}>{String(count)}</Text> : null}
    </Pressable>
  );
}

function SyncBadge() {
  const { configured, state } = ui.sync;
  const [tone, text] = !configured ? [color.faint, "Sync off"] : state === "running" ? [color.accent, "Syncing"] : state === "error" ? [color.danger, "Sync failed"] : [color.ok, "Synced"];
  return (
    <Pressable focusable onClick={() => { ui.view = "sync"; activate("home"); }} style={{ direction: "row", align: "center", gap: 8, height: 30, padding: { left: 10, right: 10 }, radius: radius.control, hover: { background: color.hover } }}>
      <Row style={{ width: 6, height: 6, radius: 3, background: tone }} />
      <Text size={12} color={color.muted}>{text}</Text>
    </Pressable>
  );
}

function Sidebar() {
  return (
    <Column style={{ width: 216, background: color.panel, borderColor: color.line, borderWidth: { right: 1 }, padding: { top: 14, left: 10, right: 10, bottom: 12 } }} gap={2}>
      <NavItem view="hosts" icon="server" label="Hosts" count={ui.hosts.length} />
      <NavItem view="snippets" icon="code" label="Snippets" count={ui.snippets.length} />
      <NavItem view="keys" icon="key" label="Keychain" count={ui.keys.length} />
      <NavItem view="known" icon="shield" label="Known hosts" count={ui.known.length} />
      <NavItem view="sync" icon="cloud" label="Sync" />
      <Column flex={1} />
      <Pressable focusable onClick={() => { ui.paletteOpen = true; ui.paletteQuery = ""; }} style={{ direction: "row", align: "center", gap: 10, height: 34, padding: { left: 10, right: 10 }, radius: radius.control, hover: { background: color.hover } }}>
        <Glyph name="search" size={15} color={color.muted} />
        <Text size={13} color={color.muted} style={{ flex: 1 }}>Commands</Text>
        <Text size={11} color={color.faint} style={mono}>Ctrl K</Text>
      </Pressable>
      <Pressable focusable onClick={lockVault} style={{ direction: "row", align: "center", gap: 10, height: 34, padding: { left: 10, right: 10 }, radius: radius.control, hover: { background: color.hover } }}>
        <Glyph name="lock" size={15} color={color.muted} />
        <Text size={13} color={color.muted}>Lock vault</Text>
      </Pressable>
    </Column>
  );
}

function SessionOverlay({ info }: { info: SessionInfo }) {
  if (info.status === "connected") return null;
  const host = ui.hosts.find(record => record.id === info.host);
  const closed = info.status === "closed";
  const reconnecting = info.status === "reconnecting";
  const title = closed ? (info.reason ? "Disconnected" : "Session ended") : reconnecting ? "Link lost, reconnecting" : info.status === "authenticating" ? "Signing in" : "Connecting";
  return (
    <Column align="center" justify="center" style={{ position: "absolute", left: 0, top: 0, right: 0, bottom: 0, background: closed || reconnecting ? "#0d0f12b3" : "transparent" }}>
      <Column gap={12} align="center" style={{ padding: { top: 22, bottom: 22, left: 28, right: 28 }, minWidth: 300, background: color.panel, radius: radius.panel, borderColor: color.line, borderWidth: 1, boxShadow: { y: 14, blur: 40, color: "#00000080" } }}>
        <Text size={15} weight={650} color={color.text}>{title}</Text>
        {host ? <Text size={12.5} color={color.muted} style={mono}>{`${host.data.user || "root"}@${host.data.address}`}</Text> : null}
        {info.reason ? <Text size={12.5} color={reconnecting ? color.muted : color.danger} style={{ textAlign: "center", maxWidth: 360 }}>{info.reason}</Text> : null}
        {closed ? (
          <Row gap={8} style={{ margin: { top: 4 } }}>
            <Action label="Close" onClick={() => closePane(info.session)} />
            {info.host ? <Action tone="primary" icon="refresh" label="Reconnect" onClick={() => reconnect(info.session)} /> : null}
          </Row>
        ) : reconnecting ? (
          <Action label="Stop" onClick={() => closePane(info.session)} />
        ) : null}
      </Column>
    </Column>
  );
}

function latencyTone(ms: number): string {
  return ms < 80 ? color.ok : ms < 250 ? color.warn : color.danger;
}

function StatusBar({ info, panes }: { info: SessionInfo; panes: number }) {
  const host = ui.hosts.find(record => record.id === info.host);
  const where = host ? `${host.data.user || "root"}@${host.data.address}${host.data.port && host.data.port !== 22 ? `:${host.data.port}` : ""}` : "local shell";
  return (
    <Row gap={14} align="center" style={{ height: 28, padding: { left: 12, right: 6 }, background: color.panel, borderColor: color.line, borderWidth: { top: 1 } }}>
      <Row gap={6} align="center">
        <Row style={{ width: 6, height: 6, radius: 3, background: statusTone[info.status] }} />
        <Text size={11.5} color={color.muted}>{info.status}</Text>
      </Row>
      <Text size={11.5} color={color.faint} style={mono}>{where}</Text>
      {info.transport === "agent" ? (
        <Row gap={5} align="center">
          <Glyph name="shield" size={12} color={color.accent} />
          <Text size={11.5} color={color.muted}>resumable</Text>
        </Row>
      ) : null}
      {info.latency !== undefined && info.host ? (
        <Row gap={6} align="center">
          <Glyph name="activity" size={12} color={latencyTone(info.latency)} />
          <Text size={11.5} color={color.muted} style={mono}>{`${info.latency} ms`}</Text>
        </Row>
      ) : null}
      {info.forwards.map(forward => (
        <Row key={forward.label} gap={5} align="center">
          <Glyph name="route" size={12} color={forward.ok ? color.ok : color.danger} />
          <Text size={11.5} color={color.faint} style={mono}>{forward.label.split(":")[0]!}</Text>
        </Row>
      ))}
      <Row flex={1} />
      {info.size ? <Text size={11.5} color={color.faint} style={mono}>{info.size}</Text> : null}
      <IconAction icon="columns" size={24} label="Split right" onClick={() => split("row")} />
      <IconAction icon="rows" size={24} label="Split down" onClick={() => split("column")} />
      {info.host ? <IconAction icon="folder" size={24} label="Open files" onClick={() => openFiles(info.host!)} /> : null}
      {panes > 1 ? <IconAction icon="x" size={24} label="Close pane" onClick={() => closePane(info.session)} /> : null}
    </Row>
  );
}

function TerminalTab({ tab, visible }: { tab: Tab; visible: boolean }) {
  return (
    <Column flex={1} style={{ display: visible ? "flex" : "none", minWidth: 0 }}>
      <View direction={tab.direction}>
        {tab.panes.map((session, index) => {
          const info = ui.sessions[session];
          if (!info) return null;
          const focused = tab.focus === session && tab.panes.length > 1;
          return (
            <Column
              key={session}
              flex={1}
              style={{
                minWidth: 0,
                minHeight: 0,
                borderColor: focused ? color.accent : color.line,
                borderWidth: tab.panes.length > 1 ? (index === 0 ? 0 : tab.direction === "row" ? { left: 1 } : { top: 1 }) : 0,
              }}
            >
              <Pressable flex={1} onClick={() => focusPane(session)} style={{ position: "relative", background: "#101216", outlineWidth: focused ? 1 : 0, outlineColor: color.accent }}>
                <TerminalPane session={session} />
                <SessionOverlay info={info} />
              </Pressable>
              <StatusBar info={info} panes={tab.panes.length} />
            </Column>
          );
        })}
      </View>
    </Column>
  );
}

function View({ direction, children }: { direction: "row" | "column"; children: unknown }) {
  return direction === "row"
    ? <Row flex={1} align="stretch" style={{ minHeight: 0 }}>{children as never}</Row>
    : <Column flex={1} style={{ minHeight: 0 }}>{children as never}</Column>;
}

function Palette() {
  const terminal = ui.tabs.find(tab => tab.id === ui.active)?.kind === "terminal";
  const items: CommandItem[] = [
    ...ui.hosts.map(host => ({ value: `connect:${host.id}`, label: `Connect to ${host.data.name}`, keywords: [host.data.address, host.data.user ?? "", host.data.group ?? ""], group: "Hosts" })),
    ...ui.hosts.map(host => ({ value: `files:${host.id}`, label: `Files on ${host.data.name}`, keywords: [host.data.address, "sftp"], group: "Files" })),
    ...(terminal ? ui.snippets.map(snippet => ({ value: `snippet:${snippet.id}`, label: `Run ${snippet.data.name}`, keywords: [snippet.data.command], group: "Snippets" })) : []),
    ...(terminal ? ui.snippets.map(snippet => ({ value: `broadcast:${snippet.id}`, label: `Run ${snippet.data.name} in every pane`, keywords: [snippet.data.command, "broadcast"], group: "Snippets" })) : []),
    { value: "new-host", label: "New host", group: "Actions", shortcut: "Ctrl N" },
    { value: "local", label: "New local terminal", group: "Actions", shortcut: "Ctrl Shift T" },
    ...(terminal ? [{ value: "split-right", label: "Split right", group: "Actions", shortcut: "Ctrl Shift D" }, { value: "split-down", label: "Split down", group: "Actions", shortcut: "Ctrl Shift E" }] : []),
    { value: "sync", label: "Sync now", group: "Actions" },
    { value: "lock", label: "Lock vault", group: "Actions", shortcut: "Ctrl L" },
  ];
  return (
    <CommandPalette
      id="palette"
      open={ui.paletteOpen}
      query={ui.paletteQuery}
      items={items}
      placeholder="Connect, open files, run a snippet"
      emptyText="Nothing found"
      width={540}
      onOpenChange={open => { ui.paletteOpen = open; }}
      onQueryChange={query => { ui.paletteQuery = query; }}
      onSelect={value => {
        ui.paletteOpen = false;
        const [kind, id] = value.split(/:(.*)/s) as [string, string | undefined];
        if (kind === "connect") return connect(id!);
        if (kind === "files") return openFiles(id!);
        if (kind === "snippet") return runSnippet(id!);
        if (kind === "broadcast") return broadcastSnippet(id!);
        if (value === "new-host") { ui.view = "hosts"; activate("home"); return newHost(); }
        if (value === "local") return openLocal();
        if (value === "split-right") return split("row");
        if (value === "split-down") return split("column");
        if (value === "sync") return syncNow();
        if (value === "lock") return lockVault();
      }}
    />
  );
}

function Toast() {
  if (!ui.toast) return null;
  const error = ui.toast.tone === "error";
  return (
    <Row style={{ position: "absolute", bottom: 44, left: 0, right: 0, justify: "center", pointerEvents: "none" }}>
      <Row gap={10} align="center" style={{ padding: { top: 10, bottom: 10, left: 14, right: 16 }, background: color.raised, radius: radius.control, borderColor: error ? color.danger : color.lineStrong, borderWidth: 1, boxShadow: { y: 10, blur: 28, color: "#00000080" } }}>
        <Glyph name={error ? "alert" : "check"} size={15} color={error ? color.danger : color.ok} />
        <Text size={13} color={color.text}>{ui.toast.text}</Text>
      </Row>
    </Row>
  );
}

/**
 * The window's whole content. The title bar stays mounted through lock and unlock: Tarve
 * cannot add or remove it once the window exists.
 */
export function Root() {
  const ready = ui.phase === "ready";
  return (
    <Column flex={1} style={{ background: color.canvas, fontFamily: font.ui }}>
      <TitleBar height={42} style={{ background: color.panel, borderColor: color.line, borderWidth: { bottom: 1 } }} buttonStyle={{ foreground: color.muted }} actions={ready ? <SyncBadge /> : null}>
        {ready ? <Tabs /> : <Row flex={1} dragRegion style={{ height: 30 }} />}
      </TitleBar>
      {ready ? <Shell /> : <Unlock />}
    </Column>
  );
}

function Shell() {
  const tab = ui.tabs.find(item => item.id === ui.active);
  return (
    <Column flex={1} style={{ minHeight: 0 }}>
      <Row flex={1} align="stretch" style={{ minHeight: 0 }}>
        {tab ? null : <Sidebar />}
        <Column flex={1} style={{ minWidth: 0, display: tab ? "none" : "flex" }}>
          {ui.view === "hosts" ? <Hosts /> : ui.view === "snippets" ? <Snippets /> : ui.view === "keys" ? <Keychain /> : ui.view === "known" ? <KnownHosts /> : <Sync />}
        </Column>
        {ui.tabs.map(item =>
          // Every tab keeps its surfaces mounted, so switching costs no reconnect or repaint.
          item.kind === "terminal"
            ? <TerminalTab key={item.id} tab={item} visible={item.id === ui.active} />
            : <Column key={item.id} flex={1} style={{ display: item.id === ui.active ? "flex" : "none", minWidth: 0 }}>{item.files ? <Files files={item.files} /> : null}</Column>,
        )}
      </Row>
      <HostKeyPrompt />
      <Palette />
      <Toast />
    </Column>
  );
}
