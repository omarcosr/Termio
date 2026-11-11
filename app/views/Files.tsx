import { Column, Pressable, Row, Scroll, Text } from "@tarve/core";
import { browse, dialogs, refresh, download, joinPath, makeDirectory, removeEntry, renameEntry, ui, upload, type FilesInfo, type RemoteEntry, type Transfer } from "../state/store";
import { Glyph } from "../ui/icons";
import { compact, Action, IconAction, TextField, mono } from "../ui/kit";
import { color, radius } from "../ui/tokens";

const drafts = new Map<number, { newFolder?: string; renaming?: { entry: string; name: string }; selected?: string; path?: string }>();

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

/** Goes to a typed path: absolute, ~ for home, or relative to the folder shown. */
function goTo(files: FilesInfo, typed: string): void {
  draft(files).path = undefined;
  const path = typed.trim();
  if (!path) return;
  const home = files.home ?? "/";
  const absolute = path === "~" ? home : path.startsWith("~/") ? joinPath(home, path.slice(2)) : path.startsWith("/") ? path : joinPath(files.path, path);
  // Back to the crumbs only once the folder opened; a wrong path keeps the field to fix it.
  void browse(files, absolute).then(() => { if (files.path !== absolute) draft(files).path = path; });
}

/** Turns the path bar into a field holding the current path, focused once it is drawn. */
function editPath(files: FilesInfo): void {
  draft(files).path = files.path;
  refresh();
  setTimeout(() => dialogs.focus(pathFieldId(files)), 0);
}

export const editPathForTest = editPath;

/** Leaves the field without going anywhere (Escape, or a tap on the list). */
export function cancelPath(files: FilesInfo): void {
  if (draft(files).path === undefined) return;
  draft(files).path = undefined;
  refresh();
}

/** The path bar: the folders as text; a tap turns it into a field, Enter goes there. */
function PathBar({ files }: { files: FilesInfo }) {
  const state = draft(files);
  if (state.path !== undefined) {
    return (
      <Row flex={1} style={{ minWidth: 0 }}>
        <TextField
          id={pathFieldId(files)}
          value={state.path}
          placeholder="/path/to/folder"
          onChange={value => { state.path = value; }}
          onSubmit={value => goTo(files, value)}
          style={{ flex: 1, minWidth: 0, height: 32, ...mono, fontSize: 12.5 }}
        />
      </Row>
    );
  }
  return (
    <Pressable
      flex={1}
      focusable
      onClick={() => editPath(files)}
      control={{ role: "button", label: `Path ${files.path}. Edit` }}
      style={{ direction: "row", align: "center", minWidth: 0, height: 32, padding: { left: 10, right: 10 }, radius: radius.control, borderColor: "transparent", borderWidth: 1, hover: { background: color.hover, borderColor: color.line } }}
    >
      <Crumbs files={files} />
    </Pressable>
  );
}

const pathFieldId = (files: FilesInfo) => `files-path-${files.id}`;

function Crumbs({ files }: { files: FilesInfo }) {
  const all = files.path.split("/").filter(Boolean);
  // A phone shows the last two folders; "…" stands for the rest.
  const hidden = compact() ? Math.max(0, all.length - 2) : 0;
  const parts = all.slice(hidden);
  const lead = [hidden ? "…" : "", ...parts.slice(0, -1)].join(" / ");
  return (
    <Row gap={6} align="center" style={{ minWidth: 0, overflow: "hidden" }}>
      <Text size={12.5} color={color.faint} style={{ ...mono, whiteSpace: "pre", shrink: 0 }}>{parts.length ? `${lead} /`.trimStart() : "/"}</Text>
      {parts.length ? <Text size={12.5} weight={600} color={color.text} style={{ ...mono, whiteSpace: "nowrap", textOverflow: "ellipsis", shrink: 1, minWidth: 0 }}>{parts[parts.length - 1]!}</Text> : null}
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
      onClick={() => { state.selected = entry.name; cancelPath(files); }}
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
      {compact() && selected ? null : <Text size={12} color={color.faint} style={{ ...mono, width: 80, shrink: 0, textAlign: "end" }}>{entry.directory ? "" : size(entry.size)}</Text>}
      {compact() ? null : <Text size={12} color={color.faint} style={{ width: 130, textAlign: "end" }}>{when(entry.modified)}</Text>}
      {/* A phone shows the actions of the selected row only, where the size column was. */}
      <Row gap={2} style={compact() ? { display: selected ? "flex" : "none", shrink: 0 } : { width: 96, justify: "end", opacity: selected ? 1 : 0.0 }}>
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
        <Text size={12.5} color={color.text} style={{ flex: 1, minWidth: 0, whiteSpace: "nowrap", textOverflow: "ellipsis" }}>{transfer.name}</Text>
      </Row>
      <Text size={11.5} color={color.faint} style={{ ...mono, whiteSpace: "nowrap" }}>{transfer.state === "error" ? "failed" : transfer.total ? `${size(transfer.done)} / ${size(transfer.total)}` : size(transfer.done)}</Text>
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
  const narrow = compact();
  return (
    <Column flex={1} style={{ minHeight: 0 }}>
      <Row flex={1} align="stretch" style={{ minHeight: 0 }}>
      <Column flex={1} style={{ minWidth: 0 }}>
        <Row gap={narrow ? 4 : 8} align="center" style={{ height: 52, padding: { left: narrow ? 8 : 16, right: narrow ? 8 : 16 }, borderColor: color.line, borderWidth: { bottom: 1 } }}>
          <IconAction icon="up" label="Up one folder" onClick={() => browse(files, joinPath(files.path, ".."))} />
          <PathBar files={files} />
          <IconAction icon="refresh" label="Refresh" onClick={() => browse(files, files.path)} />
          {narrow ? <IconAction icon="folderPlus" label="New folder" onClick={() => { state.newFolder = ""; }} /> : <Action icon="folderPlus" label="New folder" onClick={() => { state.newFolder = ""; }} />}
          {narrow ? <IconAction icon="upload" label="Upload" color={color.accent} onClick={() => pickUpload(files)} /> : <Action tone="primary" icon="upload" label="Upload" onClick={() => pickUpload(files)} />}
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
        <Row gap={12} style={{ padding: { left: 30, right: narrow ? 14 : 108, top: 10, bottom: 6 } }}>
          <Text size={11.5} weight={650} color={color.faint} style={{ flex: 1 }}>Name</Text>
          <Text size={11.5} weight={650} color={color.faint} style={{ width: 80, textAlign: "end" }}>Size</Text>
          {narrow ? null : <Text size={11.5} weight={650} color={color.faint} style={{ width: 130, textAlign: "end" }}>Modified</Text>}
        </Row>
        <Scroll flex={1}>
          <Column gap={1} style={{ padding: { left: 8, right: 8, bottom: 16 }, opacity: files.loading ? 0.6 : 1 }}>
            {files.entries.map(entry => <EntryRow key={entry.name} files={files} entry={entry} />)}
            {files.entries.length === 0 && !files.loading ? <Row style={{ padding: 16 }}><Text size={13} color={color.faint}>This folder is empty.</Text></Row> : null}
          </Column>
        </Scroll>
      </Column>
      {files.transfers.length > 0 && !narrow ? <Transfers files={files} narrow={false} /> : null}
    </Row>
    {/* A phone has no room beside the list: the transfers sit under it. */}
    {files.transfers.length > 0 && narrow ? <Transfers files={files} narrow /> : null}
    </Column>
  );
}

function Transfers({ files, narrow }: { files: FilesInfo; narrow: boolean }) {
  return (
    <Column style={narrow
      ? { height: 180, shrink: 0, overflow: "hidden", padding: 12, background: color.panel, borderColor: color.line, borderWidth: { top: 1 } }
      : { width: 280, shrink: 1, minWidth: 200, overflow: "hidden", padding: 16, background: color.panel, borderColor: color.line, borderWidth: { left: 1 } }}>
      <Text size={13} weight={650} color={color.text}>Transfers</Text>
      <Scroll flex={1}>
        <Column>{files.transfers.map(transfer => <TransferRow key={transfer.request} transfer={transfer} />)}</Column>
      </Scroll>
    </Column>
  );
}
