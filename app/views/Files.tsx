import { Column, Pressable, Row, Scroll, Text } from "@tarve/core";
import { browse, dialogs, download, joinPath, makeDirectory, removeEntry, renameEntry, ui, upload, type FilesInfo, type RemoteEntry, type Transfer } from "../state/store";
import { Glyph } from "../ui/icons";
import { Action, IconAction, TextField, mono } from "../ui/kit";
import { color, radius } from "../ui/tokens";

const drafts = new Map<number, { newFolder?: string; renaming?: { entry: string; name: string }; selected?: string }>();

function draft(files: FilesInfo) {
  let value = drafts.get(files.id);
  if (!value) drafts.set(files.id, (value = {}));
  return value;
}

export function size(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`;
}

function when(seconds: number): string {
  if (!seconds) return "";
  const date = new Date(seconds * 1000);
  const sameYear = date.getFullYear() === new Date().getFullYear();
  return date.toLocaleDateString(undefined, sameYear ? { day: "numeric", month: "short" } : { day: "numeric", month: "short", year: "numeric" }) + (sameYear ? ` ${date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })}` : "");
}

async function pickDownload(files: FilesInfo, entry: RemoteEntry) {
  const local = await dialogs.save(entry.name);
  if (local) download(files, entry, local);
}

async function pickUpload(files: FilesInfo) {
  for (const local of await dialogs.open()) upload(files, local);
}

function Crumbs({ files }: { files: FilesInfo }) {
  const parts = files.path.split("/").filter(Boolean);
  return (
    <Row gap={2} align="center" flex={1} style={{ minWidth: 0 }}>
      <Pressable focusable onClick={() => browse(files, "/")} style={{ padding: { left: 6, right: 6, top: 4, bottom: 4 }, radius: 5, hover: { background: color.hover } }}>
        <Text size={12.5} color={color.muted} style={mono}>/</Text>
      </Pressable>
      {parts.map((part, index) => {
        const path = `/${parts.slice(0, index + 1).join("/")}`;
        const last = index === parts.length - 1;
        return (
          <Row key={path} gap={2} align="center">
            {index > 0 ? <Text size={12.5} color={color.faint} style={mono}>/</Text> : null}
            <Pressable focusable onClick={() => browse(files, path)} style={{ padding: { left: 6, right: 6, top: 4, bottom: 4 }, radius: 5, hover: { background: color.hover } }}>
              <Text size={12.5} weight={last ? 600 : 400} color={last ? color.text : color.muted} style={mono}>{part}</Text>
            </Pressable>
          </Row>
        );
      })}
    </Row>
  );
}

function EntryRow({ files, entry }: { files: FilesInfo; entry: RemoteEntry }) {
  const state = draft(files);
  const selected = state.selected === entry.name;
  const renaming = state.renaming?.entry === entry.name ? state.renaming : undefined;
  const open = () => entry.directory ? browse(files, joinPath(files.path, entry.name)) : pickDownload(files, entry);
  return (
    <Pressable
      key={entry.name}
      focusable
      onClick={() => { state.selected = entry.name; }}
      onKeyDown={key => { if (key === "Enter") open(); }}
      style={{ direction: "row", align: "center", gap: 12, height: 36, padding: { left: 14, right: 6 }, radius: radius.control, background: selected ? color.raised : "transparent", hover: { background: color.raised } }}
    >
      <Glyph name={entry.directory ? "folder" : "file"} size={15} color={entry.directory ? color.accent : color.muted} />
      {renaming ? (
        <Row flex={1}>
          <TextField
            value={renaming.name}
            onChange={value => { renaming.name = value; }}
            onSubmit={value => { state.renaming = undefined; if (value && value !== entry.name) void renameEntry(files, entry, value); }}
            style={{ flex: 1, height: 28 }}
          />
        </Row>
      ) : (
        <Pressable flex={1} onClick={open} style={{ minWidth: 0 }}>
          <Text size={13} color={color.text} style={{ whiteSpace: "nowrap", textOverflow: "ellipsis" }}>{entry.name}</Text>
        </Pressable>
      )}
      <Text size={12} color={color.faint} style={{ ...mono, width: 80, textAlign: "end" }}>{entry.directory ? "" : size(entry.size)}</Text>
      <Text size={12} color={color.faint} style={{ width: 130, textAlign: "end" }}>{when(entry.modified)}</Text>
      <Row gap={2} style={{ width: 96, justify: "end", opacity: selected ? 1 : 0.0 }}>
        {entry.directory ? null : <IconAction icon="download" label={`Download ${entry.name}`} onClick={() => pickDownload(files, entry)} />}
        <IconAction icon="pencil" label={`Rename ${entry.name}`} onClick={() => { state.renaming = { entry: entry.name, name: entry.name }; }} />
        <IconAction icon="trash" label={`Delete ${entry.name}`} onClick={() => removeEntry(files, entry)} />
      </Row>
    </Pressable>
  );
}

function TransferRow({ transfer }: { transfer: Transfer }) {
  const fraction = transfer.total ? Math.min(1, transfer.done / transfer.total) : transfer.state === "done" ? 1 : 0;
  const tone = transfer.state === "error" ? color.danger : transfer.state === "done" ? color.ok : color.accent;
  return (
    <Column gap={6} style={{ padding: { top: 8, bottom: 8 } }}>
      <Row gap={8} align="center">
        <Glyph name={transfer.direction === "up" ? "upload" : "download"} size={13} color={tone} />
        <Text size={12.5} color={color.text} style={{ flex: 1, whiteSpace: "nowrap", textOverflow: "ellipsis" }}>{transfer.name}</Text>
        <Text size={11.5} color={color.faint} style={{ ...mono, whiteSpace: "nowrap" }}>{transfer.state === "error" ? "failed" : transfer.total ? `${size(transfer.done)} / ${size(transfer.total)}` : size(transfer.done)}</Text>
      </Row>
      <Row style={{ height: 3, radius: 2, background: color.line }}>
        <Row style={{ width: `${Math.round(fraction * 100)}%`, height: 3, radius: 2, background: tone }} />
      </Row>
      {transfer.message ? <Text size={11.5} color={color.danger}>{transfer.message}</Text> : null}
    </Column>
  );
}

export function Files({ files }: { files: FilesInfo }) {
  const host = ui.hosts.find(record => record.id === files.host);
  const state = draft(files);
  if (files.state !== "ready") {
    return (
      <Column flex={1} align="center" justify="center" gap={10}>
        <Text size={15} weight={650} color={color.text}>{files.state === "error" ? "Could not open files" : `Opening files on ${host?.data.name ?? "host"}…`}</Text>
        {files.message ? <Text size={12.5} color={color.danger} style={{ maxWidth: 420, textAlign: "center" }}>{files.message}</Text> : null}
      </Column>
    );
  }
  return (
    <Row flex={1} align="stretch" style={{ minHeight: 0 }}>
      <Column flex={1} style={{ minWidth: 0 }}>
        <Row gap={8} align="center" style={{ height: 52, padding: { left: 16, right: 16 }, borderColor: color.line, borderWidth: { bottom: 1 } }}>
          <IconAction icon="up" label="Up one folder" onClick={() => browse(files, joinPath(files.path, ".."))} />
          <Crumbs files={files} />
          <IconAction icon="refresh" label="Refresh" onClick={() => browse(files, files.path)} />
          <Action icon="folderPlus" label="New folder" onClick={() => { state.newFolder = ""; }} />
          <Action tone="primary" icon="upload" label="Upload" onClick={() => pickUpload(files)} />
        </Row>
        {state.newFolder !== undefined ? (
          <Row gap={8} align="center" style={{ padding: { left: 16, right: 16, top: 10, bottom: 10 }, borderColor: color.line, borderWidth: { bottom: 1 } }}>
            <Glyph name="folder" size={15} color={color.accent} />
            <TextField
              value={state.newFolder}
              placeholder="Folder name"
              onChange={value => { state.newFolder = value; }}
              onSubmit={value => { state.newFolder = undefined; if (value.trim()) void makeDirectory(files, value.trim()); }}
              style={{ flex: 1 }}
            />
            <IconAction icon="x" label="Cancel" onClick={() => { state.newFolder = undefined; }} />
          </Row>
        ) : null}
        <Row gap={12} style={{ padding: { left: 30, right: 108, top: 10, bottom: 6 } }}>
          <Text size={11.5} weight={650} color={color.faint} style={{ flex: 1 }}>Name</Text>
          <Text size={11.5} weight={650} color={color.faint} style={{ width: 80, textAlign: "end" }}>Size</Text>
          <Text size={11.5} weight={650} color={color.faint} style={{ width: 130, textAlign: "end" }}>Modified</Text>
        </Row>
        <Scroll flex={1}>
          <Column gap={1} style={{ padding: { left: 8, right: 8, bottom: 16 }, opacity: files.loading ? 0.6 : 1 }}>
            {files.entries.map(entry => <EntryRow key={entry.name} files={files} entry={entry} />)}
            {files.entries.length === 0 && !files.loading ? <Row style={{ padding: 16 }}><Text size={13} color={color.faint}>This folder is empty.</Text></Row> : null}
          </Column>
        </Scroll>
      </Column>
      {files.transfers.length ? (
        <Column style={{ width: 280, padding: 16, background: color.panel, borderColor: color.line, borderWidth: { left: 1 } }}>
          <Text size={13} weight={650} color={color.text}>Transfers</Text>
          <Scroll flex={1}>
            <Column>{files.transfers.map(transfer => <TransferRow key={transfer.request} transfer={transfer} />)}</Column>
          </Scroll>
        </Column>
      ) : null}
    </Row>
  );
}
