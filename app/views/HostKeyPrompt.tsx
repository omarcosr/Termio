import { Column, Modal, Row, Text } from "@tarve/core";
import { answerHostKey, ui, type HostKeyPrompt as Prompt } from "../state/store";
import { Glyph } from "../ui/icons";
import { Action, mono } from "../ui/kit";
import { color, radius } from "../ui/tokens";

/** The server's key, asked about once; a changed key is an alarm, not a formality. */
export function HostKeyPrompt() {
  const prompt: Prompt | undefined = ui.prompts[0];
  if (!prompt) return null;
  const changed = prompt.previous !== null;
  const address = prompt.port === 22 ? prompt.host : `${prompt.host}:${prompt.port}`;
  return (
    <Modal
      open
      width={460}
      title={changed ? "This server's key changed" : "New server"}
      closeOnOverlay={false}
      onOpenChange={open => { if (!open) answerHostKey(prompt.request, false); }}
      footer={
        <Row gap={8} justify="end">
          <Action label="Cancel" onClick={() => answerHostKey(prompt.request, false)} />
          <Action tone={changed ? "danger" : "primary"} label={changed ? "Trust the new key" : "Trust and connect"} onClick={() => answerHostKey(prompt.request, true)} />
        </Row>
      }
    >
      <Column gap={14}>
        {changed ? (
          <Row gap={10} style={{ padding: 12, background: color.dangerSoft, radius: radius.control }}>
            <Glyph name="alert" size={16} color={color.danger} />
            <Text size={13} color={color.text} style={{ lineHeight: 1.45, flex: 1 }}>
              {`The key ${address} presents is not the one you trusted before. Someone may be intercepting the connection, or the server was reinstalled. Only continue if you know why it changed.`}
            </Text>
          </Row>
        ) : (
          <Text size={13} color={color.muted} style={{ lineHeight: 1.45 }}>
            {`First connection to ${address}. Check the fingerprint with the server's administrator, or against ssh-keygen -lf on the server, before you trust it.`}
          </Text>
        )}
        <Column gap={6} style={{ padding: 12, background: color.canvas, radius: radius.control, borderColor: color.line, borderWidth: 1 }}>
          <Text size={11.5} weight={600} color={color.faint}>{prompt.algorithm}</Text>
          <Text size={12.5} color={color.text} style={{ ...mono, userSelect: "text" }}>{prompt.fingerprint}</Text>
          {changed ? <Text size={12} color={color.faint} style={mono}>{`was ${prompt.previous}`}</Text> : null}
        </Column>
      </Column>
    </Modal>
  );
}
