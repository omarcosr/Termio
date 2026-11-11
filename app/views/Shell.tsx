import { Column, CommandPalette, Modal, Pressable, Row, Scroll, Text, TitleBar, type CommandItem } from "@tarve/core";
import { core } from "../core/plugin";
import {
  activate,
  closePane,
  closeTab,
  connect,
  focusPane,
  installAgent,
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
  type View, closeTermSearch, setTermQuery,
  dropOnNewTab,
  dropOnPane,
  dropOnTab,
  endDrag,
  hoverDrop,
  startDrag,
  type DropZone,
  dismissFault, refresh } from "../state/store";
import type { DragEndEvent } from "@tarve/core";
import { Glyph, type IconId } from "../ui/icons";
import { ANDROID, touch, Action, compact, dialogWidth, IconAction, mono, TextField } from "../ui/kit";
import { color, font, radius } from "../ui/tokens";
import { cancelPath, Files } from "./Files";
import { HostKeyPrompt } from "./HostKeyPrompt";
import { closeImport, Hosts } from "./Hosts";
import { closeNewKey, Keychain, KnownHosts } from "./Keychain";
import { Snippets } from "./Snippets";
import { Sync } from "./Sync";
import { dropSelection, openKeyboard, tapOpensKeyboard, pinchFont, SelectionOverlay, SoftKeyboard, TerminalPane } from "./TerminalPane";
import { Unlock } from "./Unlock";
import { Settings } from "./Settings";
import { Forwards } from "./Forwards";

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
  const target = ui.drag !== undefined && ui.dropZone === `tab:${tab.id}`;
  const dragged = ui.drag?.kind === "tab" && ui.drag.id === tab.id;
  return (
    <Pressable
      key={tab.id}
      focusable={false}
      onClick={() => activate(tab.id)}
      draggable
      onDragStart={() => startDrag({ kind: "tab", id: tab.id })}
      onDragEnd={finishDrag}
      onDragEnter={() => hoverDrop(`tab:${tab.id}`)}
      onDragLeave={() => { if (ui.dropZone === `tab:${tab.id}`) hoverDrop(undefined); }}
      onDrop={() => dropOnTab(tab.id)}
      control={{ role: "tab", label: title, selected: active }}
      style={{
        direction: "row",
        align: "center",
        gap: 8,
        height: 30,
        padding: { left: 12, right: 4 },
        maxWidth: compact() ? 160 : 230,
        shrink: 0,
        radius: radius.control,
        background: target ? color.accentSoft : active ? color.raised : "transparent",
        borderColor: target ? color.accent : active ? color.line : "transparent",
        borderWidth: 1,
        opacity: dragged ? 0.5 : 1,
        focusVisible: { outlineWidth: 0 },
        hover: { background: active ? color.raised : color.hover },
      }}
    >
      {tab.kind === "files" ? <Glyph name="folder" size={13} color={active ? color.accent : color.muted} /> : <Row style={{ width: 6, height: 6, radius: 3, background: tabTone(tab) }} />}
      <Text size={12.5} weight={active ? 600 : 500} color={active ? color.text : color.muted} style={{ whiteSpace: "nowrap", textOverflow: "ellipsis", flex: 1, minWidth: 0 }}>{title}</Text>
      <IconAction icon="x" size={22} label={`Close ${title}`} focusable={false} onClick={() => closeTab(tab.id)} />
    </Pressable>
  );
}

function Tabs() {
  const home = ui.active === "home";
  const narrow = compact();
  const strip = [
    ui.tabs.length ? <Row key="sep" style={{ width: 1, height: 16, shrink: 0, background: color.line, margin: { left: 4, right: 4 } }} /> : null,
    ...ui.tabs.map(tab => <TabButton key={tab.id} tab={tab} />),
    <IconAction key="new" icon="plus" label="New local terminal" focusable={false} onClick={openLocal} />,
    ui.drag ? <NewTabZone key="zone" /> : null,
  ];
  return (
    <Row gap={4} align="center" flex={1} style={{ padding: { left: 6 }, minWidth: 0 }}>
      <Pressable
        focusable={false}
        onClick={() => activate("home")}
        control={{ role: "tab", label: "Vault", selected: home }}
        style={{ direction: "row", align: "center", gap: 8, height: 30, shrink: 0, padding: narrow ? { left: 6, right: 6 } : { left: 10, right: 12 }, radius: radius.control, background: home ? color.raised : "transparent", borderColor: home ? color.line : "transparent", borderWidth: 1, hover: { background: home ? color.raised : color.hover } }}
      >
        <Row style={{ width: 18, height: 18, radius: 5, background: color.accent, align: "center", justify: "center" }}>
          <Glyph name="terminal" size={11} color={color.accentInk} strokeWidth={2.5} />
        </Row>
        {narrow ? null : <Text size={12.5} weight={600} color={home ? color.text : color.muted}>Termio</Text>}
      </Pressable>
      {narrow ? (
        // A phone shows one tab: the open one, with how many there are. A tap lists them all.
        <Row gap={4} align="center" flex={1} style={{ minWidth: 0, padding: { right: 4 } }}>
          {ui.tabs.length ? <TabSwitch /> : <Row flex={1} />}
          <IconAction icon="plus" label="New local terminal" focusable={false} onClick={openLocal} />
        </Row>
      ) : (
        <Row gap={4} align="center" flex={1} style={{ minWidth: 0 }}>
          {strip}
          <Row flex={1} dragRegion style={{ height: 30 }} />
        </Row>
      )}
    </Row>
  );
}


let switcherOpen = false;

/** Phones: the open tab (or "N open" from the vault), with the count; a tap opens the list. */
function TabSwitch() {
  const tab = ui.tabs.find(item => item.id === ui.active);
  const count = ui.tabs.length;
  return (
    <Pressable
      flex={1}
      focusable={false}
      onClick={() => { switcherOpen = true; refresh(); }}
      control={{ role: "button", label: `${count} open tabs. Switch` }}
      style={{ direction: "row", align: "center", gap: 8, height: 32, minWidth: 0, padding: { left: 10, right: 6 }, radius: radius.control, background: tab ? color.raised : "transparent", borderColor: color.line, borderWidth: 1 }}
    >
      {tab ? (tab.kind === "files" ? <Glyph name="folder" size={13} color={color.accent} /> : <Row style={{ width: 6, height: 6, radius: 3, background: tabTone(tab), shrink: 0 }} />) : null}
      <Row flex={1} style={{ minWidth: 0, overflow: "hidden" }}>
        <Text size={12.5} weight={600} color={tab ? color.text : color.muted} style={{ minWidth: 0, whiteSpace: "nowrap", textOverflow: "ellipsis" }}>{tab ? tabTitle(tab) : count === 1 ? "1 open" : `${count} open`}</Text>
      </Row>
      <Row style={{ minWidth: 20, height: 20, padding: { left: 6, right: 6 }, radius: 10, background: color.accentSoft, align: "center", justify: "center", shrink: 0 }}>
        <Text size={11} weight={700} color={color.accent}>{String(count)}</Text>
      </Row>
    </Pressable>
  );
}

/** The open tabs as a list on a phone: tap one to go there, ✕ to close it. */
function TabSwitcher() {
  if (!compact()) return null;
  const close = () => { switcherOpen = false; refresh(); };
  const go = (target: "home" | number) => { switcherOpen = false; activate(target); };
  const row = (key: string, active: boolean, icon: unknown, title: string, detail: string, onOpen: () => void, onClose?: () => void) => (
    <Pressable
      key={key}
      focusable
      onClick={onOpen}
      control={{ role: "tab", label: title, selected: active }}
      style={{ direction: "row", align: "center", gap: 12, height: 52, padding: { left: 12, right: 4 }, radius: radius.control, background: active ? color.raised : "transparent", borderColor: active ? color.line : "transparent", borderWidth: 1 }}
    >
      <Row style={{ width: 18, align: "center", justify: "center", shrink: 0 }}>{icon as never}</Row>
      <Column flex={1} gap={2} style={{ minWidth: 0 }}>
        <Text size={13.5} weight={active ? 650 : 500} color={color.text} style={{ whiteSpace: "nowrap", textOverflow: "ellipsis" }}>{title}</Text>
        {detail ? <Text size={11.5} color={color.faint} style={{ ...mono, whiteSpace: "nowrap", textOverflow: "ellipsis" }}>{detail}</Text> : null}
      </Column>
      {onClose ? <IconAction icon="x" size={40} label={`Close ${title}`} onClick={onClose} /> : null}
    </Pressable>
  );
  const where = (tab: Tab) => {
    const session = tab.kind === "terminal" ? ui.sessions[tab.focus] : undefined;
    const host = ui.hosts.find(record => record.id === (tab.files?.host ?? session?.host));
    const address = host ? `${host.data.user || "root"}@${host.data.address}` : "local shell";
    return tab.kind === "files" ? `${address} · ${tab.files?.path ?? ""}` : `${address}${tab.panes.length > 1 ? ` · ${tab.panes.length} panes` : ""}`;
  };
  return (
    <Modal open={switcherOpen} onOpenChange={open => { if (!open) close(); }} title={`Open tabs · ${ui.tabs.length}`} width={dialogWidth(420)} style={{ padding: 16, gap: 12 }}>
      <Scroll style={{ maxHeight: 420 }}>
        <Column gap={2}>
          {row("home", ui.active === "home", <Glyph name="server" size={16} color={ui.active === "home" ? color.accent : color.muted} />, "Vault", "Hosts, keys, snippets", () => go("home"))}
          {ui.tabs.map(tab => row(
            String(tab.id),
            ui.active === tab.id,
            tab.kind === "files" ? <Glyph name="folder" size={16} color={color.accent} /> : <Row style={{ width: 8, height: 8, radius: 4, background: tabTone(tab) }} />,
            tabTitle(tab),
            where(tab),
            () => go(tab.id),
            () => { closeTab(tab.id); if (!ui.tabs.length) close(); },
          ))}
        </Column>
      </Scroll>
      <Action icon="plus" label="New local terminal" onClick={() => { switcherOpen = false; openLocal(); }} />
    </Modal>
  );
}

/** A drag ends without a drop (outside every target, or Escape): nothing moves. */
function finishDrag(event: DragEndEvent): void {
  if (event.cancelled || !event.target) endDrag();
}

/** Where a dragged pane becomes a tab of its own, or a dragged tab goes last. */
function NewTabZone() {
  const over = ui.dropZone === "new";
  const label = ui.drag?.kind === "pane" ? "Drop here: own tab" : "Drop here: last";
  return (
    <Row
      align="center"
      gap={6}
      dropTarget
      onDragEnter={() => hoverDrop("new")}
      onDragLeave={() => { if (ui.dropZone === "new") hoverDrop(undefined); }}
      onDrop={dropOnNewTab}
      style={{ height: 30, padding: { left: 10, right: 12 }, radius: radius.control, borderWidth: 1, borderColor: over ? color.accent : color.lineStrong, background: over ? color.accentSoft : "transparent" }}
    >
      <Glyph name="plus" size={12} color={over ? color.accent : color.muted} />
      <Text size={12} color={over ? color.accent : color.muted} style={{ whiteSpace: "nowrap" }}>{label}</Text>
    </Row>
  );
}

/** One edge (or the centre) of a pane while something is dragged over the terminals. */
function Zone({ session, zone, flex }: { session: number; zone: DropZone; flex: number }) {
  const id = `${session}:${zone}`;
  const over = ui.dropZone === id;
  return (
    <Column
      flex={flex}
      dropTarget
      onDragEnter={() => hoverDrop(id)}
      onDragLeave={() => { if (ui.dropZone === id) hoverDrop(undefined); }}
      onDrop={() => dropOnPane(session, zone)}
      style={{ minWidth: 0, minHeight: 0, margin: 3, radius: radius.control, background: over ? color.accentSoft : "transparent", borderWidth: over ? 2 : 0, borderColor: color.accent }}
    />
  );
}

/** Drop targets over a pane: the four edges place the dragged pane beside it, the centre swaps. */
function DropZones({ session }: { session: number }) {
  return (
    <Column style={{ position: "absolute", left: 0, top: 0, right: 0, bottom: 0, background: "#0d0f1259" }}>
      <Row flex={1} align="stretch"><Zone session={session} zone="top" flex={1} /></Row>
      <Row flex={2} align="stretch">
        <Zone session={session} zone="left" flex={1} />
        <Zone session={session} zone="center" flex={2} />
        <Zone session={session} zone="right" flex={1} />
      </Row>
      <Row flex={1} align="stretch"><Zone session={session} zone="bottom" flex={1} /></Row>
    </Column>
  );
}

/** The sessions the current drag carries, which cannot be dropped on themselves. */
function draggedSessions(): number[] {
  const drag = ui.drag;
  if (!drag) return [];
  if (drag.kind === "pane") return [drag.session];
  return ui.tabs.find(tab => tab.id === drag.id)?.panes ?? [];
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
      <NavItem view="forwards" icon="route" label="Forwarding" count={ui.hosts.reduce((sum, host) => sum + (host.data.forwards?.length ?? 0), 0)} />
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


/** The vault's sections as short labels for the bottom bar of a phone. */
const SECTIONS: { view: View; icon: IconId; label: string }[] = [
  { view: "hosts", icon: "server", label: "Hosts" },
  { view: "snippets", icon: "code", label: "Snippets" },
  { view: "keys", icon: "key", label: "Keys" },
  { view: "known", icon: "shield", label: "Known" },
  { view: "forwards", icon: "route", label: "Ports" },
  { view: "sync", icon: "cloud", label: "Sync" },
];

/** The sidebar of a narrow screen: the sections along the bottom, within reach of a thumb. */
function BottomNav() {
  return (
    <Row align="stretch" style={{ height: 58, shrink: 0, padding: { left: 4, right: 4 }, background: color.panel, borderColor: color.line, borderWidth: { top: 1 } }}>
      {SECTIONS.map(item => {
        const active = ui.view === item.view;
        return (
          <Pressable
            key={item.view}
            flex={1}
            focusable
            onClick={() => { ui.view = item.view; ui.error = undefined; }}
            control={{ role: "tab", label: item.label, selected: active }}
            style={{ direction: "column", align: "center", justify: "center", gap: 4, minWidth: 0, radius: radius.control, focusVisible: { outlineWidth: 2, outlineColor: color.accent } }}
          >
            <Glyph name={item.icon} size={19} color={active ? color.accent : color.muted} />
            <Text size={10.5} weight={active ? 650 : 500} color={active ? color.text : color.muted} style={{ whiteSpace: "nowrap", textOverflow: "ellipsis" }}>{item.label}</Text>
          </Pressable>
        );
      })}
    </Row>
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
      <Column gap={12} align="center" style={{ padding: { top: 22, bottom: 22, left: 28, right: 28 }, minWidth: dialogWidth(300), maxWidth: dialogWidth(420), background: color.panel, radius: radius.panel, borderColor: color.line, borderWidth: 1, boxShadow: { y: 14, blur: 40, color: "#00000080" } }}>
        <Text size={15} weight={650} color={color.text}>{title}</Text>
        {host ? <Text size={12.5} color={color.muted} style={mono}>{`${host.data.user || "root"}@${host.data.address}`}</Text> : null}
        {info.reason ? <Text size={12.5} color={reconnecting ? color.muted : color.danger} style={{ textAlign: "center", maxWidth: dialogWidth(360) - 56 }}>{info.reason}</Text> : null}
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
  const narrow = compact();
  const where = host ? `${host.data.user || "root"}@${host.data.address}${host.data.port && host.data.port !== 22 ? `:${host.data.port}` : ""}` : "local shell";
  return (
    <Row gap={narrow ? 8 : 14} align="center" style={{ height: narrow ? 34 : 28, padding: { left: 4, right: 6 }, background: color.panel, borderColor: color.line, borderWidth: { top: 1 } }}>
      <Pressable
        focusable={false}
        draggable
        onDragStart={() => startDrag({ kind: "pane", session: info.session })}
        onDragEnd={finishDrag}
        onClick={() => focusPane(info.session)}
        control={{ role: "button", label: "Drag to move this terminal" }}
        style={{ direction: "row", align: "center", gap: 8, height: 22, shrink: 1, minWidth: 0, padding: { left: 4, right: 8 }, radius: radius.control, hover: { background: color.hover } }}
      >
        <Glyph name="grip" size={12} color={color.faint} />
        <Row gap={6} align="center">
          <Row style={{ width: 6, height: 6, radius: 3, background: statusTone[info.status] }} />
          <Text size={11.5} color={color.muted}>{info.status}</Text>
        </Row>
        <Text size={11.5} color={color.faint} style={{ ...mono, whiteSpace: "nowrap", textOverflow: "ellipsis", shrink: 1, minWidth: 0 }}>{where}</Text>
      </Pressable>
      {info.transport === "agent" && !narrow ? (
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
      {narrow ? null : info.forwards.map(forward => (
        <Row key={forward.label} gap={5} align="center">
          <Glyph name="route" size={12} color={forward.ok ? color.ok : color.danger} />
          <Text size={11.5} color={color.faint} style={mono}>{forward.label.split(":")[0]!}</Text>
        </Row>
      ))}
      <Row flex={1} style={{ minWidth: 0 }} />
      {info.size && !narrow ? <Text size={11.5} color={color.faint} style={mono}>{info.size}</Text> : null}
      {narrow ? null : <IconAction icon="columns" size={24} label="Split right" onClick={() => split("row")} />}
      {narrow ? null : <IconAction icon="rows" size={24} label="Split down" onClick={() => split("column")} />}
      {info.host && info.transport === "ssh" && !ANDROID ? <AgentChip hostId={info.host} session={info.session} /> : null}
      {info.host ? <IconAction icon="folder" size={24} label="Open files" onClick={() => openFiles(info.host!)} /> : null}
      {panes > 1 ? <IconAction icon="x" size={24} label="Close pane" onClick={() => closePane(info.session)} /> : null}
    </Row>
  );
}

/** Plain-SSH sessions offer the agent; once asked, the chip shows each step and the outcome. */
function AgentChip({ hostId, session }: { hostId: string; session: number }) {
  const install = ui.agentInstall[hostId];
  const running = install?.state === "checking" || install?.state === "uploading";
  const [icon, tone, label]: [IconId, string, string] =
    install?.state === "done" ? ["check", color.ok, "Agent ready: reconnect to resume"]
    : install?.state === "error" ? ["alert", color.danger, `Agent install failed: ${install.message}`]
    : running ? ["refresh", color.accent, install!.message]
    : ["download", color.accent, "Make this session resumable"];
  return (
    <Pressable
      focusable={false}
      onClick={running ? undefined : install?.state === "done" ? () => reconnect(session) : () => installAgent(hostId)}
      control={{ role: "button", label }}
      style={{ direction: "row", align: "center", gap: 6, height: 22, shrink: 0, padding: { left: 8, right: 8 }, radius: 11, background: color.accentSoft, maxWidth: 420, hover: { background: color.hover } }}
    >
      <Glyph name={icon} size={12} color={tone} />
      {compact() ? null : <Text size={11.5} weight={600} color={tone} style={{ whiteSpace: "nowrap", textOverflow: "ellipsis" }}>{label}</Text>}
    </Pressable>
  );
}

function TerminalTab({ tab, visible }: { tab: Tab; visible: boolean }) {
  const carried = visible ? draggedSessions() : [];
  return (
    <Column flex={1} style={{ display: visible ? "flex" : "none", minWidth: 0 }}>
      {/* Side by side, two panes of a phone are a few columns each: they stack instead. */}
      <View direction={compact() ? "column" : tab.direction}>
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
              {/* The window has a 1 px frame, so a surface at its edge starts at 1.25 device px at
                  125% scale and the compositor resamples every glyph across two pixels (blurry
                  text). 3 px more puts it 4 px in: whole device pixels at 100/125/150/175/200%. The
                  title bar is 43 + 1 for the same reason. */}
              {/* Not focusable and square: a Pressable takes the keyboard focus on click and Tarve then
                  drew its rounded focus ring around the whole terminal. Splits mark the focused pane
                  with the border above instead. */}
              <Pressable flex={1} focusable={false} onClick={() => { focusPane(session); if (touch() && tapOpensKeyboard(session)) openKeyboard(session); }} onPinch={pinchFont} style={{ position: "relative", padding: { left: index === 0 ? 3 : 0 }, background: color.terminal, radius: 0, outlineWidth: 0, focus: { outlineWidth: 0 }, focusVisible: { outlineWidth: 0 } }}>
                <TerminalPane session={session} />
                <SessionOverlay info={info} />
                {touch() ? <SelectionOverlay session={session} /> : null}
                {ui.termSearch?.session === session ? <TermSearch /> : null}
                {ui.drag && visible && !carried.includes(session) ? <DropZones session={session} /> : null}
              </Pressable>
              <StatusBar info={info} panes={tab.panes.length} />
              {/* A phone has no keyboard until a text field asks for one: this row holds it. */}
              {touch() && tab.focus === session ? <SoftKeyboard session={session} /> : null}
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
  // Keyboard shortcuts mean nothing on a phone.
  if (touch()) for (const item of items) delete item.shortcut;
  return (
    <CommandPalette
      id="palette"
      open={ui.paletteOpen}
      query={ui.paletteQuery}
      items={items}
      placeholder="Connect, open files, run a snippet"
      emptyText="Nothing found"
      width={dialogWidth(540)}
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
    <Row style={{ position: "absolute", bottom: compact() ? 72 : 44, left: 0, right: 0, justify: "center", pointerEvents: "none" }}>
      <Row gap={10} align="center" style={{ maxWidth: dialogWidth(560), padding: { top: 10, bottom: 10, left: 14, right: 16 }, background: color.raised, radius: radius.control, borderColor: error ? color.danger : color.lineStrong, borderWidth: 1, boxShadow: { y: 10, blur: 28, color: "#00000080" } }}>
        <Glyph name={error ? "alert" : "check"} size={15} color={error ? color.danger : color.ok} />
        <Text size={13} color={color.text} style={{ shrink: 1, minWidth: 0 }}>{ui.toast.text}</Text>
      </Row>
    </Row>
  );
}

/**
 * The window's whole content. The title bar stays mounted through lock and unlock: Tarve
 * cannot add or remove it once the window exists.
 */
/** The title bar's right end. A phone has no sidebar, so the palette and the lock move up here. */
function TitleActions() {
  const settings = <IconAction icon="settings" label="Settings" focusable={false} color={ui.settingsOpen ? color.accent : color.muted} onClick={() => { ui.settingsOpen = true; }} />;
  if (!compact()) return <Row gap={2} align="center"><SyncBadge />{settings}</Row>;
  return (
    <Row gap={0} align="center" style={{ shrink: 0 }}>
      <IconAction icon="search" label="Commands" focusable={false} onClick={() => { ui.paletteOpen = true; ui.paletteQuery = ""; }} />
      {settings}
    </Row>
  );
}

/**
 * Android Back: closes what sits on top (a dialog, a form, the search bar), then leaves a tab
 * for the vault, then a section for Hosts. Returns false when there is nothing left to go back
 * from: the app then goes to the background, keeping its sessions.
 */
export function handleBack(): boolean {
  if (ui.fault) { dismissFault(); return true; }
  if (switcherOpen) { switcherOpen = false; return true; }
  if (ui.paletteOpen) { ui.paletteOpen = false; return true; }
  if (ui.settingsOpen) { ui.settingsOpen = false; return true; }
  if (closeImport()) return true;
  if (ui.termSearch) { closeTermSearch(); return true; }
  if (dropSelection()) return true;
  const tab = ui.tabs.find(item => item.id === ui.active);
  if (tab?.files && cancelPath(tab.files)) return true;
  if (tab) { activate("home"); return true; }
  if (ui.editing) { ui.editing = undefined; ui.error = undefined; return true; }
  if (ui.editingSnippet) { ui.editingSnippet = undefined; ui.error = undefined; return true; }
  if (closeNewKey()) return true;
  if (ui.view !== "hosts") { ui.view = "hosts"; ui.error = undefined; return true; }
  return false;
}

export function Root() {
  const ready = ui.phase === "ready";
  return (
    <Column flex={1} style={{ background: color.canvas, fontFamily: font.ui }}>
      <TitleBar height={43} showMinimize={!compact()} showMaximize={!compact()} style={{ background: color.panel, borderColor: color.line, borderWidth: { bottom: 1 } }} buttonStyle={{ foreground: color.muted }} actions={ready ? <TitleActions /> : null}>
        {ready ? <Tabs /> : <Row flex={1} dragRegion style={{ height: 30 }} />}
      </TitleBar>
      {ready ? <Shell /> : <Unlock />}
      <FaultDialog />
    </Column>
  );
}

/** An error nothing handled: told in a dialog, with details to copy, while the app keeps running. */
function FaultDialog() {
  const fault = ui.fault;
  return (
    <Modal
      open={fault !== undefined}
      onOpenChange={open => { if (!open) dismissFault(); }}
      title="Something went wrong"
      width={dialogWidth(520)}
      footer={
        <Row gap={8} justify="end">
          <Action icon="copy" label="Copy details" onClick={() => {
            try { core().call({ op: "clipboard.set", text: `${fault?.message}\n\n${fault?.detail}` }); } catch { /* nothing to copy into */ }
          }} />
          <Action tone="primary" label="Close" onClick={dismissFault} />
        </Row>
      }
    >
      <Column gap={12}>
        <Row gap={10} align="start">
          <Glyph name="alert" size={18} color={color.danger} />
          <Text size={13.5} color={color.text} style={{ flex: 1, lineHeight: 1.45 }}>{fault?.message ?? ""}</Text>
        </Row>
        <Text size={12} color={color.muted} style={{ lineHeight: 1.45 }}>Termio kept running; what you were doing may not have finished. Your vault and open sessions are unaffected.</Text>
        <Scroll style={{ maxHeight: 180, background: color.canvas, radius: radius.control, borderColor: color.line, borderWidth: 1, padding: 10 }}>
          <Text size={11} color={color.faint} style={{ ...mono, whiteSpace: "pre-wrap" }}>{fault?.detail ?? ""}</Text>
        </Scroll>
      </Column>
    </Modal>
  );
}

function Shell() {
  const tab = ui.tabs.find(item => item.id === ui.active);
  const narrow = compact();
  return (
    <Column flex={1} style={{ minHeight: 0 }}>
      <Row flex={1} align="stretch" style={{ minHeight: 0 }}>
        {tab || narrow ? null : <Sidebar />}
        <Column flex={1} style={{ minWidth: 0, display: tab ? "none" : "flex" }}>
          {ui.view === "hosts" ? <Hosts /> : ui.view === "snippets" ? <Snippets /> : ui.view === "keys" ? <Keychain /> : ui.view === "known" ? <KnownHosts /> : ui.view === "forwards" ? <Forwards /> : <Sync />}
        </Column>
        {ui.tabs.map(item =>
          // Every tab keeps its surfaces mounted, so switching costs no reconnect or repaint.
          item.kind === "terminal"
            ? <TerminalTab key={item.id} tab={item} visible={item.id === ui.active} />
            : <Column key={item.id} flex={1} style={{ display: item.id === ui.active ? "flex" : "none", minWidth: 0 }}>{item.files ? <Files files={item.files} /> : null}</Column>,
        )}
      </Row>
      {narrow && !tab ? <BottomNav /> : null}
      <Settings />
      <TabSwitcher />
      <HostKeyPrompt />
      <Palette />
      <Toast />
    </Column>
  );
}
/** The find bar over a terminal pane: Enter walks the matches, Escape closes it. */
function TermSearch() {
  const search = ui.termSearch;
  if (!search) return null;
  return (
    <Row
      align="center"
      gap={8}
      style={{
        position: "absolute",
        top: 8,
        right: compact() ? 6 : 12,
        padding: { left: 10, right: 4, top: 4, bottom: 4 },
        background: color.panel,
        borderColor: color.line,
        borderWidth: 1,
        radius: 8,
      }}
    >
      <TextField id="term-search" value={search.query} onChange={setTermQuery} placeholder="Find" style={{ width: compact() ? 140 : 240, height: 28 }} />
      <Text size={11} color={color.faint} style={{ whiteSpace: "nowrap" }}>{`${search.count} matches`}</Text>
      <IconAction icon="x" label="Close search" size={24} onClick={closeTermSearch} />
    </Row>
  );
}
