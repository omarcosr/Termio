import { Column, Row, Scroll, Text, TextArea, type VNode, clipboard } from "@tarve/core";
import { generateKey, importKey, removeRecord, toast, ui } from "../state/store";
import { Glyph } from "../ui/icons";
import { compact, gutter, Action, Field, Hint, IconAction, Label, Segments, mono, relativeTime } from "../ui/kit";
import { color, radius } from "../ui/tokens";

/** Closes the new-key form; false when it was not open (Android Back). */
export function closeNewKey(): boolean {
  if (!draft.open) return false;
  draft.open = false;
  ui.error = undefined;
  return true;
}

const draft = { mode: "generate" as "generate" | "import", open: false, name: "", privateKey: "", passphrase: "" };

function copy(text: string, what: string): void {
  clipboard.writeText(text).then(() => toast(`${what} copied`), () => toast("Could not reach the clipboard", "error"));
}

function NewKey() {
  const submit = () => {
    const done = draft.mode === "generate" ? generateKey(draft.name) : importKey(draft.name, draft.privateKey, draft.passphrase);
    if (done) Object.assign(draft, { open: false, name: "", privateKey: "", passphrase: "" });
  };
  return (
    <Column gap={14} style={{ padding: 18, background: color.panel, radius: radius.panel, borderColor: color.line, borderWidth: 1 }}>
      <Row align="center" justify="between">
        <Segments value={draft.mode} options={[{ value: "generate", label: "Generate" }, { value: "import", label: "Import" }]} onChange={mode => { draft.mode = mode; ui.error = undefined; }} />
        <IconAction icon="x" label="Close" onClick={() => { draft.open = false; ui.error = undefined; }} />
      </Row>
      <Field id="key-name" label="Name" value={draft.name} placeholder={draft.mode === "generate" ? "Laptop" : "Work key"} onChange={value => { draft.name = value; }} onSubmit={draft.mode === "generate" ? submit : undefined} />
      {draft.mode === "import" ? (
        <Column gap={14}>
          <Column gap={6}>
            <Label>Private key</Label>
            <TextArea
              value={draft.privateKey}
              placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
              onChange={value => { draft.privateKey = value; }}
              style={{ height: 120, background: color.canvas, borderColor: color.line, borderWidth: 1, radius: radius.control, padding: 10, foreground: color.text, fontFamily: "Cascadia Mono", fontSize: 11.5, focus: { borderColor: color.accent } }}
            />
          </Column>
          <Field label="Passphrase" type="password" value={draft.passphrase} placeholder="Only if the key has one" onChange={value => { draft.passphrase = value; }} />
        </Column>
      ) : (
        <Hint>An Ed25519 key: short, fast, and accepted by every current OpenSSH server.</Hint>
      )}
      {ui.error ? <Hint tone="danger">{ui.error}</Hint> : null}
      <Row justify="end">
        <Action tone="primary" label={draft.mode === "generate" ? "Generate key" : "Import key"} onClick={submit} />
      </Row>
    </Column>
  );
}

function Header({ title, count, action }: { title: string; count: number; action?: VNode | null }) {
  return (
    <Row align="center" justify="between" style={{ padding: { bottom: 4 } }}>
      <Row gap={10} align="center">
        <Text size={20} weight={650} color={color.text} style={{ letterSpacing: -0.3 }}>{title}</Text>
        <Text size={13} color={color.faint}>{String(count)}</Text>
      </Row>
      {action ?? null}
    </Row>
  );
}

export function Keychain() {
  return (
    <Scroll flex={1}>
      <Column gap={16} style={{ padding: { top: 22, left: gutter(), right: gutter(), bottom: 28 } }}>
        <Header title="Keychain" count={ui.keys.length} action={draft.open ? null : <Action tone="primary" icon="plus" label="New key" onClick={() => { draft.open = true; ui.error = undefined; }} />} />
        <Text size={13} color={color.muted} style={{ lineHeight: 1.5 }}>
          Private keys stay inside the encrypted vault and are never shown again. Give servers the public half: add it to ~/.ssh/authorized_keys.
        </Text>
        {draft.open ? <NewKey /> : null}
        <Column gap={8}>
          {ui.keys.map(key => (
            <Row key={key.id} gap={14} align="center" style={{ padding: 14, background: color.panel, radius: radius.panel, borderColor: color.line, borderWidth: 1 }}>
              <Row style={{ width: 34, height: 34, radius: 9, background: color.raised, align: "center", justify: "center" }}>
                <Glyph name="key" size={16} color={color.accent} />
              </Row>
              <Column flex={1} gap={3} style={{ minWidth: 0 }}>
                <Row gap={8} align="center">
                  <Text size={13.5} weight={600} color={color.text} style={{ whiteSpace: "nowrap", textOverflow: "ellipsis", shrink: 1, minWidth: 0 }}>{key.data.name}</Text>
                  <Text size={11.5} color={color.faint} style={{ whiteSpace: "nowrap", shrink: 0 }}>{key.data.algorithm}</Text>
                </Row>
                <Text size={12} color={color.muted} style={{ ...mono, userSelect: "text", whiteSpace: "nowrap", textOverflow: "ellipsis" }}>{key.data.fingerprint}</Text>
              </Column>
              {compact()
                ? <IconAction icon="copy" label="Copy public key" onClick={() => copy(key.data.public, "Public key")} />
                : <Action icon="copy" label="Copy public key" onClick={() => copy(key.data.public, "Public key")} />}
              <IconAction icon="trash" label={`Delete ${key.data.name}`} onClick={() => removeRecord(key.id)} />
            </Row>
          ))}
          {ui.keys.length === 0 && !draft.open ? <Text size={13} color={color.faint}>No keys yet.</Text> : null}
        </Column>
      </Column>
    </Scroll>
  );
}

export function KnownHosts() {
  return (
    <Scroll flex={1}>
      <Column gap={16} style={{ padding: { top: 22, left: gutter(), right: gutter(), bottom: 28 } }}>
        <Header title="Known hosts" count={ui.known.length} />
        <Text size={13} color={color.muted} style={{ lineHeight: 1.5 }}>
          Server keys you trusted. Termio checks them on every connection and stops if one changes. Forget a key when a server is rebuilt on purpose.
        </Text>
        <Column gap={2} style={{ background: color.panel, radius: radius.panel, borderColor: color.line, borderWidth: 1, padding: 6 }}>
          {ui.known.map(known => (
            <Row key={known.id} gap={compact() ? 10 : 14} align="center" style={{ padding: { left: 10, right: 6, top: 8, bottom: 8 }, radius: radius.control, hover: { background: color.raised } }}>
              <Glyph name="shield" size={15} color={color.ok} />
              <Column flex={1} gap={2} style={{ minWidth: 0 }}>
                <Text size={13} weight={600} color={color.text} style={{ ...mono, whiteSpace: "nowrap", textOverflow: "ellipsis" }}>{known.data.port === 22 ? known.data.host : `${known.data.host}:${known.data.port}`}</Text>
                <Text size={11.5} color={color.faint} style={{ ...mono, whiteSpace: "nowrap", textOverflow: "ellipsis" }}>{`${known.data.algorithm}  ${known.data.fingerprint}`}</Text>
              </Column>
              {compact() ? null : <Text size={11.5} color={color.faint}>{relativeTime(known.updated)}</Text>}
              <IconAction icon="trash" label="Forget this key" onClick={() => removeRecord(known.id)} />
            </Row>
          ))}
          {ui.known.length === 0 ? <Row style={{ padding: 12 }}><Text size={13} color={color.faint}>None yet: they appear after your first connection.</Text></Row> : null}
        </Column>
      </Column>
    </Scroll>
  );
}
