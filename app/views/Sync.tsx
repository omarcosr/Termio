import { Column, Row, Scroll, Text } from "@tarve/core";
import { configureSync, disableSync, providerName, syncNow, ui, type SyncProvider, type SyncSettings } from "../state/store";
import { AwsSetup } from "./Aws";
import { CloudflareConnect, cf } from "./Cloudflare";
import { Glyph } from "../ui/icons";
import { gutter, Action, Field, Hint, mono, relativeTime, Segments } from "../ui/kit";
import { color, radius } from "../ui/tokens";

const r2 = { account: "", bucket: "", accessKey: "", secretKey: "", seeded: false };
const s3 = { bucket: "", region: "", accessKey: "", secretKey: "", seeded: false };
/** A connected provider shows its bucket; "Change" opens its form again. */
const editing: Record<SyncProvider, boolean> = { r2: false, s3: false };

function seed(): void {
  const saved = ui.syncTargets;
  if (!r2.seeded && saved.r2) Object.assign(r2, { account: saved.r2.account, bucket: saved.r2.bucket, accessKey: saved.r2.accessKey, seeded: true });
  if (!s3.seeded && saved.s3) Object.assign(s3, { bucket: saved.s3.bucket, region: saved.s3.region ?? "", accessKey: saved.s3.accessKey, seeded: true });
}

function where(target: SyncSettings): string {
  const vault = `${target.name || "termio"}.vault`;
  return target.provider === "s3" ? `${target.bucket} · ${target.region ?? ""} · ${vault}` : `${target.bucket} · ${vault}`;
}

function Status() {
  const { state, message, at } = ui.sync;
  const [tone, text] =
    state === "running" ? [color.accent, "Syncing…"]
    : state === "error" ? [color.danger, message ?? "The last sync failed"]
    : [color.ok, `Up to date · ${relativeTime(at)}`];
  const count = Object.keys(ui.syncTargets).length;
  return (
    <Row gap={12} align="center" style={{ padding: 16, background: color.panel, radius: radius.panel, borderColor: color.line, borderWidth: 1 }}>
      <Row style={{ width: 8, height: 8, radius: 4, background: tone }} />
      <Column flex={1} gap={3} style={{ minWidth: 0 }}>
        <Text size={13.5} weight={600} color={color.text}>{text}</Text>
        <Text size={12} color={color.faint}>{count > 1 ? "Every bucket holds the whole vault: each is a backup of the other." : "Connect a second provider below to keep a backup."}</Text>
      </Column>
      <Action icon="refresh" label="Sync now" onClick={syncNow} disabled={state === "running"} />
    </Row>
  );
}

/** One provider: its bucket when connected, the form to connect it otherwise. */
function Provider(props: { provider: SyncProvider; children: unknown }) {
  const target = ui.syncTargets[props.provider];
  const open = !target || editing[props.provider];
  return (
    <Column gap={14} style={{ padding: 20, background: color.panel, radius: radius.panel, borderColor: color.line, borderWidth: 1 }}>
      <Row gap={8} align="center">
        <Glyph name="cloud" size={16} color={target ? color.ok : color.muted} />
        <Column flex={1} gap={3} style={{ minWidth: 0 }}>
          <Text size={14} weight={650} color={color.text}>{providerName(props.provider)}</Text>
          <Text size={12} color={color.faint} style={target ? mono : {}}>{target ? where(target) : "Not connected"}</Text>
        </Column>
        {target ? <Action label={editing[props.provider] ? "Cancel" : "Change"} onClick={() => { editing[props.provider] = !editing[props.provider]; }} /> : null}
        {target ? <Action tone="danger" label="Remove" onClick={() => { editing[props.provider] = false; disableSync(props.provider); }} /> : null}
      </Row>
      {open ? (props.children as never) : null}
    </Column>
  );
}

function R2Form() {
  const target = ui.syncTargets.r2;
  const done = () => { editing.r2 = false; };
  return (
    <Column gap={14}>
      <Segments value={cf.mode} options={[{ value: "cloudflare", label: "Sign in with a token" }, { value: "manual", label: "Access keys" }] as const} onChange={mode => { cf.mode = mode; }} />
      {cf.mode === "cloudflare" ? <CloudflareConnect onPick={form => { if (configureSync({ ...form, provider: "r2" })) done(); }} selected={target?.bucket} askName /> : (
        <Column gap={14}>
          <Field label="Cloudflare account ID" value={r2.account} placeholder="32-character account ID" monospace onChange={value => { r2.account = value; }} />
          <Field label="Bucket" value={r2.bucket} placeholder="termio-vault" monospace onChange={value => { r2.bucket = value; }} />
          <Row gap={10}>
            <Field label="Access key ID" value={r2.accessKey} monospace grow={1} onChange={value => { r2.accessKey = value; }} />
            <Field label="Secret access key" type="password" value={r2.secretKey} grow={1} placeholder={target?.hasSecretKey ? "Saved. Type to replace it" : ""} onChange={value => { r2.secretKey = value; }} />
          </Row>
          <Hint>Create an R2 API token with Object Read & Write on this bucket only.</Hint>
          <Row gap={8} justify="end">
            <Action
              tone="primary"
              label={ui.busy ? "Checking…" : target ? "Save and sync" : "Connect R2"}
              disabled={ui.busy || !r2.account || !r2.bucket || !r2.accessKey || (!r2.secretKey && !target?.hasSecretKey)}
              onClick={() => { if (configureSync({ provider: "r2", account: r2.account, bucket: r2.bucket, accessKey: r2.accessKey, secretKey: r2.secretKey, name: target?.name ?? ui.syncTargets.s3?.name })) done(); }}
            />
          </Row>
        </Column>
      )}
    </Column>
  );
}

function S3Form() {
  const target = ui.syncTargets.s3;
  return (
    <Column gap={14}>
      <Row gap={10}>
        <Field label="Bucket" value={s3.bucket} placeholder="my-termio-vault" monospace grow={1} onChange={value => { s3.bucket = value; }} />
        <Field label="Region" value={s3.region} placeholder="Detected" monospace grow={1} onChange={value => { s3.region = value; }} />
      </Row>
      <Row gap={10}>
        <Field label="Access key ID" value={s3.accessKey} placeholder="AKIA…" monospace grow={1} onChange={value => { s3.accessKey = value; }} />
        <Field label="Secret access key" type="password" value={s3.secretKey} grow={1} placeholder={target?.hasSecretKey ? "Saved. Type to replace it" : ""} onChange={value => { s3.secretKey = value; }} />
      </Row>
      <AwsSetup bucket={s3.bucket} />
      <Row gap={8} justify="end">
        <Action
          tone="primary"
          label={ui.busy ? "Checking…" : target ? "Save and sync" : "Connect S3"}
          disabled={ui.busy || !s3.bucket.trim() || !s3.accessKey.trim() || (!s3.secretKey && !target?.hasSecretKey)}
          // The same vault object in every bucket: S3 takes the name the R2 bucket already uses.
          onClick={() => { if (configureSync({ provider: "s3", bucket: s3.bucket, region: s3.region || undefined, accessKey: s3.accessKey, secretKey: s3.secretKey, name: target?.name ?? ui.syncTargets.r2?.name })) editing.s3 = false; }}
        />
      </Row>
    </Column>
  );
}

export function Sync() {
  seed();
  return (
    <Scroll flex={1}>
      <Column gap={18} style={{ padding: { top: 22, left: gutter(), right: gutter(), bottom: 28 } }}>
        <Text size={20} weight={650} color={color.text} style={{ letterSpacing: -0.3 }}>Sync</Text>
        <Text size={13} color={color.muted} style={{ lineHeight: 1.5 }}>
          Keep this vault the same on every device through your own buckets: Cloudflare R2, AWS S3, or both. Each bucket holds the whole vault, so one is a backup of the other. Everything is encrypted here with your vault key before upload: the buckets store opaque blobs and never see a host, password or key.
        </Text>
        {ui.sync.configured ? <Status /> : null}
        <Provider provider="r2"><R2Form /></Provider>
        <Provider provider="s3"><S3Form /></Provider>
        {ui.error ? <Hint tone="danger">{ui.error}</Hint> : null}
        <Text size={12} color={color.faint} style={{ lineHeight: 1.5 }}>
          On another device, choose "Join a synced vault" when it asks for a vault, with either bucket and the same master password: the other bucket comes along.
        </Text>
      </Column>
    </Scroll>
  );
}
