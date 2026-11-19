import { Column, Pressable, Row, Scroll, Text, TextArea } from "@tarve/core";
import { activeTab, broadcastSnippet, editSnippet, removeRecord, runSnippet, saveSnippet, ui, type SnippetData, type VaultRecord } from "../state/store";
import { Glyph } from "../ui/icons";
import { gutter, Action, Field, Hint, IconAction, Label, mono } from "../ui/kit";
import { color, radius } from "../ui/tokens";
import { t } from "../i18n";

function SnippetRow({ snippet, canRun }: { snippet: VaultRecord<SnippetData>; canRun: boolean }) {
  return (
    <Row gap={12} align="center" style={{ padding: { top: 10, bottom: 10, left: 14, right: 8 }, radius: radius.control, hover: { background: color.raised } }}>
      <Glyph name="code" size={15} color={color.accent} />
      <Column flex={1} gap={3} style={{ minWidth: 0 }}>
        <Text size={13.5} weight={600} color={color.text}>{snippet.data.name}</Text>
        <Text size={12} color={color.muted} style={{ ...mono, whiteSpace: "nowrap", textOverflow: "ellipsis" }}>{snippet.data.command.split("\n").join("  ⏎  ")}</Text>
      </Column>
      {canRun ? <IconAction icon="broadcast" label={t("Run {name} in every pane", { name: snippet.data.name })} onClick={() => broadcastSnippet(snippet.id)} /> : null}
      {canRun ? <IconAction icon="play" color={color.accent} label={t("Run {name}", { name: snippet.data.name })} onClick={() => runSnippet(snippet.id)} /> : null}
      <IconAction icon="pencil" label={t("Edit {name}", { name: snippet.data.name })} onClick={() => editSnippet(snippet.id)} />
      <IconAction icon="trash" label={t("Delete {name}", { name: snippet.data.name })} onClick={() => removeRecord(snippet.id)} />
    </Row>
  );
}

function Editor() {
  const editing = ui.editingSnippet!;
  return (
    <Column gap={14} style={{ padding: 18, background: color.panel, radius: radius.panel, borderColor: color.line, borderWidth: 1 }}>
      <Row align="center" justify="between">
        <Text size={14} weight={650} color={color.text}>{editing.id ? t("Edit snippet") : t("New snippet")}</Text>
        <IconAction icon="x" label={t("Close")} onClick={() => { ui.editingSnippet = undefined; ui.error = undefined; }} />
      </Row>
      <Field id="snippet-name" label={t("Name")} value={editing.data.name} placeholder={t("Tail the app log")} onChange={value => { editing.data.name = value; }} />
      <Column gap={6}>
        <Label>{t("Command")}</Label>
        <TextArea
          value={editing.data.command}
          placeholder="journalctl -u app -f"
          onChange={value => { editing.data.command = value; }}
          style={{ height: 110, background: color.canvas, borderColor: color.line, borderWidth: 1, radius: radius.control, padding: 10, foreground: color.text, fontFamily: "Cascadia Mono", fontSize: 12.5, focus: { borderColor: color.accent } }}
        />
        <Hint>{t("Each line runs as if typed, followed by Enter.")}</Hint>
      </Column>
      {ui.error ? <Hint tone="danger">{ui.error}</Hint> : null}
      <Row justify="end" gap={8}>
        <Action label={t("Cancel")} onClick={() => { ui.editingSnippet = undefined; ui.error = undefined; }} />
        <Action tone="primary" label={t("Save")} onClick={saveSnippet} />
      </Row>
    </Column>
  );
}

export function Snippets() {
  const canRun = activeTab()?.kind === "terminal" || ui.tabs.some(tab => tab.kind === "terminal");
  return (
    <Scroll flex={1}>
      <Column gap={16} style={{ padding: { top: 22, left: gutter(), right: gutter(), bottom: 28 } }}>
        <Row align="center" justify="between">
          <Row gap={10} align="center">
            <Text size={20} weight={650} color={color.text} style={{ letterSpacing: -0.3 }}>{t("Snippets")}</Text>
            <Text size={13} color={color.faint}>{String(ui.snippets.length)}</Text>
          </Row>
          {ui.editingSnippet ? null : <Action tone="primary" icon="plus" label={t("New snippet")} onClick={() => editSnippet()} />}
        </Row>
        <Text size={13} color={color.muted} style={{ lineHeight: 1.5 }}>
          {t("Commands you run often, synced with your vault. Run one from Ctrl K inside a terminal, or in every pane of a split at once.")}
        </Text>
        {ui.editingSnippet ? <Editor /> : null}
        <Column gap={2} style={{ background: color.panel, radius: radius.panel, borderColor: color.line, borderWidth: 1, padding: 6 }}>
          {ui.snippets.map(snippet => <SnippetRow key={snippet.id} snippet={snippet} canRun={canRun} />)}
          {ui.snippets.length === 0 ? (
            <Pressable focusable onClick={() => editSnippet()} style={{ padding: 14, radius: radius.control, hover: { background: color.raised } }}>
              <Text size={13} color={color.faint}>{t("No snippets yet. Save a command you type every day.")}</Text>
            </Pressable>
          ) : null}
        </Column>
      </Column>
    </Scroll>
  );
}
