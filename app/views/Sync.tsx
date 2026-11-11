import { Column, Row, Scroll, Text } from "@tarve/core";
import { configureSync, disableSync, syncNow, ui } from "../state/store";
import { CloudflareConnect, cf } from "./Cloudflare";
import { Glyph } from "../ui/icons";
import { gutter, Action, Field, Hint, mono, relativeTime, Segments } from "../ui/kit";
import { color, radius } from "../ui/tokens";

const form = { account: "", bucket: "", accessKey: "", secretKey: "", endpoint: "", seeded: false };

function seed(): void {
  if (form.seeded || !ui.syncSettings) return;
  Object.assign(form, { account: ui.syncSettings.account, bucket: ui.syncSettings.bucket, accessKey: ui.syncSettings.accessKey, endpoint: ui.syncSettings.endpoint ?? "", seeded: true });
}

function Status() {
  const { state, message, at } = ui.sync;
  const [tone, text] =
    state === "running" ? [color.accent, "Syncing…"]
    : state === "error" ? [color.danger, message ?? "The last sync failed"]
    : [color.ok, `Up to date · ${relativeTime(at)}`];
  return (
    <Row gap={12} align="center" style={{ padding: 16, background: color.panel, radius: radius.panel, borderColor: color.line, borderWidth: 1 }}>
      <Row style={{ width: 8, height: 8, radius: 4, background: tone }} />
      <Column flex={1} gap={3}>
        <Text size={13.5} weight={600} color={color.text}>{text}</Text>
        <Text size={12} color={color.faint} style={mono}>{`${ui.syncSettings?.bucket ?? ""} · ${ui.syncSettings?.account ?? ""}`}</Text>
      </Column>
      <Action icon="refresh" label="Sync now" onClick={syncNow} disabled={state === "running"} />
    </Row>
  );
}

export function Sync() {
  seed();
  const configured = ui.sync.configured;
  return (
    <Scroll flex={1}>
      <Column gap={18} style={{ padding: { top: 22, left: gutter(), right: gutter(), bottom: 28 } }}>
        <Text size={20} weight={650} color={color.text} style={{ letterSpacing: -0.3 }}>Sync</Text>
        <Text size={13} color={color.muted} style={{ lineHeight: 1.5 }}>
          Keep this vault the same on every device through your own Cloudflare R2 bucket. Everything is encrypted here before upload with your vault key: R2 stores opaque blobs and never sees a host, password or key.
        </Text>
        {configured ? <Status /> : null}
        <Column gap={14} style={{ padding: 20, background: color.panel, radius: radius.panel, borderColor: color.line, borderWidth: 1 }}>
          <Row gap={8} align="center">
            <Glyph name="cloud" size={16} color={color.muted} />
            <Text size={14} weight={650} color={color.text}>{configured ? "Bucket" : "Connect a bucket"}</Text>
          </Row>
          <Segments value={cf.mode} options={[{ value: "cloudflare", label: "Sign in with a token" }, { value: "manual", label: "Access keys" }] as const} onChange={mode => { cf.mode = mode; }} />
          {cf.mode === "cloudflare" ? <CloudflareConnect onPick={configureSync} selected={ui.syncSettings?.bucket} askName /> : <Column gap={14}>
          <Field label="Cloudflare account ID" value={form.account} placeholder="32-character account ID" monospace onChange={value => { form.account = value; }} />
          <Field label="Bucket" value={form.bucket} placeholder="termio-vault" monospace onChange={value => { form.bucket = value; }} />
          <Row gap={10}>
            <Field label="Access key ID" value={form.accessKey} monospace grow={1} onChange={value => { form.accessKey = value; }} />
            <Field
              label="Secret access key"
              type="password"
              value={form.secretKey}
              grow={1}
              placeholder={ui.syncSettings?.hasSecretKey ? "Saved. Type to replace it" : ""}
              onChange={value => { form.secretKey = value; }}
            />
          </Row>
          <Hint>Create an R2 API token with Object Read & Write on this bucket only.</Hint>
          {ui.error ? <Hint tone="danger">{ui.error}</Hint> : null}
          <Row gap={8} justify="end">
            {configured ? <Action tone="danger" label="Turn off sync" onClick={disableSync} /> : null}
            <Action
              tone="primary"
              label={ui.busy ? "Checking…" : configured ? "Save and sync" : "Turn on sync"}
              disabled={ui.busy || !form.account || !form.bucket || !form.accessKey || (!form.secretKey && !ui.syncSettings?.hasSecretKey)}
              onClick={() => configureSync({ account: form.account, bucket: form.bucket, accessKey: form.accessKey, secretKey: form.secretKey, endpoint: form.endpoint || undefined })}
            />
          </Row>
          </Column>}
        </Column>
        <Text size={12} color={color.faint} style={{ lineHeight: 1.5 }}>
          On another device, choose "Join from another device" when it asks for a vault, with the same bucket and master password.
        </Text>
      </Column>
    </Scroll>
  );
}
