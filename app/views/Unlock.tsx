import { Column, Pressable, Row, Scroll, Select, Text } from "@tarve/core";
import { createSyncedVault, createVault, joinVault, listVaults, refresh, ui, unlockVault, unlockWithFingerprint, type SyncForm, type SyncProvider } from "../state/store";
import { Glyph } from "../ui/icons";
import { compact, Action, Field, mono, Segments } from "../ui/kit";
import { AwsSetup } from "./Aws";
import { CloudflareConnect, cf } from "./Cloudflare";
import { color, font, radius } from "../ui/tokens";

const form = { password: "", confirm: "", provider: "r2" as SyncProvider, account: "", bucket: "", region: "", accessKey: "", secretKey: "", hasVault: undefined as boolean | undefined, vaults: undefined as string[] | undefined, name: "termio" };
const NEW = "__new__";

function r2(): SyncForm {
  const name = form.name.trim() || "termio";
  return form.provider === "s3"
    ? { provider: "s3", bucket: form.bucket, region: form.region.trim() || undefined, accessKey: form.accessKey, secretKey: form.secretKey, name }
    : { provider: "r2", account: form.account, bucket: form.bucket, accessKey: form.accessKey, secretKey: form.secretKey, name };
}

/** Another bucket or provider: the vault list has to be fetched again. */
function forget(): void {
  form.hasVault = undefined;
  form.vaults = undefined;
}

/** What the primary action is doing right now (its label while the spinner turns). */
let pending: string | undefined;
/** Counts failed actions: a new value replays the error banner's shake. */
let shake = 0;

/**
 * Core calls block the UI thread (key derivation, a bucket round trip), so the busy state is
 * drawn first and the action runs a frame later; a failure shakes the error banner.
 */
function run(label: string, action: () => void): void {
  if (pending) return;
  pending = label;
  ui.error = undefined;
  refresh();
  setTimeout(() => {
    try {
      action();
    } finally {
      pending = undefined;
      if (ui.error) shake++;
      refresh();
    }
  }, 50);
}

function actionLabel(): string {
  if (ui.phase === "create") return "Create vault";
  if (ui.phase !== "join") return "Unlock";
  return form.hasVault === false ? "Create synced vault" : form.hasVault ? "Download vault" : "Find vaults";
}

function busyLabel(): string {
  if (ui.phase === "create") return "Creating vault…";
  if (ui.phase !== "join") return "Unlocking…";
  return form.hasVault === false ? "Creating synced vault…" : form.hasVault ? "Downloading vault…" : "Finding vaults…";
}

function submit(): void {
  run(busyLabel(), () => {
    if (ui.phase === "create") createVault(form.password, form.confirm);
    else if (ui.phase === "join" && form.hasVault === undefined) manualCheck();
    else if (ui.phase === "join" && form.hasVault === false) createSyncedVault(form.password, form.confirm, r2());
    else if (ui.phase === "join") joinVault(form.password, r2());
    else unlockVault(form.password);
    if (ui.phase === "ready") Object.assign(form, { password: "", confirm: "", secretKey: "" });
  });
}

async function fingerprintUnlock(): Promise<void> {
  await unlockWithFingerprint();
  if (ui.phase !== "ready" && ui.error) {
    shake++;
    refresh();
  }
}

/** Lists the vaults in the chosen bucket: the first is preselected, an empty bucket starts a new one. */
function picked(chosen: SyncForm): void {
  ui.error = undefined;
  Object.assign(form, chosen);
  run("Finding vaults…", manualCheck);
}

function manualCheck(): void {
  form.vaults = listVaults(r2());
  if (form.vaults === undefined) return;
  chooseVault(form.vaults[0] ?? NEW);
}

function chooseVault(value: string): void {
  form.hasVault = value !== NEW;
  form.name = value === NEW ? (form.vaults?.includes("termio") ? "" : "termio") : value;
}

/** The fingerprint prompt comes up by itself once per lock screen, as banking apps do. */
let prompted = false;

function Switch({ to, label }: { to: "create" | "join" | "locked"; label: string }) {
  return (
    <Pressable focusable onClick={() => { ui.phase = to; ui.error = undefined; }} style={{ hover: { opacity: 0.8 } }}>
      <Text size={12.5} weight={600} color={color.accent}>{label}</Text>
    </Pressable>
  );
}

/** Before anything else: open the vault, create the first one, or join a synced one. */
export function Unlock() {
  const fingerprint = ui.phase === "locked" && ui.fingerprint;
  if (!fingerprint) prompted = false;
  else if (!prompted) {
    prompted = true;
    setTimeout(() => { void fingerprintUnlock(); }, 0);
  }
  const creating = ui.phase === "create";
  const joining = ui.phase === "join";
  const title = creating ? "Create your vault" : joining ? "Join a synced vault" : "Unlock Termio";
  const lead = creating
    ? "Hosts, keys and passwords live in one file encrypted with this password. It never leaves this device unencrypted, and it cannot be recovered."
    : joining
      ? "Pick the Cloudflare R2 or AWS S3 bucket that holds your vault, or name a new one to create there. A vault synced with both comes from either."
      : "Your vault is encrypted on this device.";
  return (
    <Scroll flex={1} style={{ background: color.canvas }}>
    <Column align="center" justify={joining ? "start" : "center"} style={{ minHeight: "100%", padding: { top: 32, bottom: 32, left: 16, right: 16 } }}>
      <Column
        key={`card-${ui.phase}`}
        gap={22}
        motionFrom={{ opacity: 0, transform: { y: 18, scale: 0.98 } }}
        style={{ width: joining ? 460 : 380, maxWidth: "100%", padding: compact() ? 20 : 28, background: color.panel, radius: radius.panel, borderColor: color.line, borderWidth: 1, boxShadow: { y: 18, blur: 48, color: "#00000066" }, opacity: 1, transform: { y: 0, scale: 1 }, transition: { opacity: { duration: 240, easing: "easeOut" }, transform: { duration: 420, easing: "spring" } } }}
      >
        <Row gap={10} align="center">
          <Row style={{ width: 30, height: 30, radius: 8, background: color.accent, align: "center", justify: "center" }}>
            <Glyph name="terminal" size={17} color={color.accentInk} strokeWidth={2.25} />
          </Row>
          <Text size={15} weight={700} color={color.text} style={{ fontFamily: font.display }}>Termio</Text>
        </Row>
        <Column gap={6}>
          <Text size={22} weight={650} color={color.text} style={{ fontFamily: font.display, letterSpacing: -0.4 }}>{title}</Text>
          <Text size={13} color={color.muted} style={{ lineHeight: 1.45 }}>{lead}</Text>
        </Column>
        <Column gap={14}>
          {joining ? (
            <Segments value={form.provider} options={[{ value: "r2", label: "Cloudflare R2" }, { value: "s3", label: "AWS S3" }] as const} onChange={provider => { form.provider = provider; form.bucket = ""; forget(); ui.error = undefined; }} />
          ) : null}
          {joining && form.provider === "s3" ? (
            <Column gap={14}>
              <Row gap={10}>
                <Field label="Bucket" value={form.bucket} onChange={value => { form.bucket = value; forget(); }} monospace grow={1} />
                <Field label="Region" value={form.region} placeholder="Detected" onChange={value => { form.region = value; forget(); }} monospace grow={1} />
              </Row>
              <Row gap={10}>
                <Field label="Access key ID" value={form.accessKey} onChange={value => { form.accessKey = value; }} monospace grow={1} />
                <Field label="Secret" type="password" value={form.secretKey} onChange={value => { form.secretKey = value; }} grow={1} />
              </Row>
              <AwsSetup bucket={form.bucket} />
            </Column>
          ) : null}
          {joining && form.provider === "r2" && cf.mode === "cloudflare" ? (
            <Column gap={10}>
              <CloudflareConnect onPick={picked} selected={form.bucket} />
              <Pressable focusable onClick={() => { cf.mode = "manual"; }} style={{ hover: { opacity: 0.8 } }}>
                <Text size={12} color={color.faint}>Use access keys instead</Text>
              </Pressable>
            </Column>
          ) : null}
          {joining && form.provider === "r2" && cf.mode === "manual" ? (
            <Column gap={14}>
              <Field label="Cloudflare account ID" value={form.account} onChange={value => { form.account = value; }} monospace />
              <Field label="Bucket" value={form.bucket} onChange={value => { form.bucket = value; forget(); }} monospace />
              <Row gap={10}>
                <Field label="Access key ID" value={form.accessKey} onChange={value => { form.accessKey = value; }} monospace grow={1} />
                <Field label="Secret" type="password" value={form.secretKey} onChange={value => { form.secretKey = value; }} grow={1} />
              </Row>
            </Column>
          ) : null}
          {joining && form.bucket && form.vaults ? (
            <Column gap={10} motionFrom={{ opacity: 0, transform: { y: 8 } }} style={{ opacity: 1, transform: { y: 0 }, transition: { opacity: { duration: 200, easing: "easeOut" }, transform: { duration: 320, easing: "spring" } } }}>
              {form.vaults.length ? (
                <Column gap={6}>
                  <Text size={12} weight={600} color={color.muted}>Vault</Text>
                  <Select style={{ width: "100%" }} id="vault-pick" value={form.hasVault ? form.name : NEW} options={[...form.vaults.map(name => ({ value: name, label: `${name}.vault` })), { value: NEW, label: "+ New vault…" }]} onValueChange={chooseVault} />
                </Column>
              ) : (
                <Row gap={8} align="center" style={{ padding: { top: 8, bottom: 8, left: 10, right: 10 }, background: color.raised, radius: radius.control }}>
                  <Glyph name="plus" size={14} color={color.accent} />
                  <Text size={12.5} color={color.muted}>{`${form.bucket} has no vault yet: create one.`}</Text>
                </Row>
              )}
              {form.hasVault === false ? <Field label="Vault name" value={form.name} monospace hint={`Saved as ${form.name.trim() || "termio"}.vault`} onChange={value => { form.name = value.replace(/[^A-Za-z0-9._-]/g, ""); }} /> : null}
            </Column>
          ) : null}
          {joining && !form.vaults ? null : <Field id="master-password" label="Master password" type="password" value={form.password} onChange={value => { form.password = value; }} onSubmit={creating || form.hasVault === false ? undefined : submit} />}
          {creating || (joining && form.hasVault === false) ? <Field label="Repeat it" type="password" value={form.confirm} onChange={value => { form.confirm = value; }} onSubmit={submit} hint="At least 8 characters. A passphrase of four or more words is easiest to remember." /> : null}
          {ui.error ? (
            <Row
              key={`error-${shake}`}
              gap={8}
              align="center"
              motionFrom={{ opacity: 0 }}
              style={{
                padding: { top: 8, bottom: 8, left: 10, right: 10 },
                background: color.dangerSoft,
                radius: radius.control,
                opacity: 1,
                transition: { opacity: { duration: 180, easing: "easeOut" } },
                animation: { from: { transform: { x: -7 } }, to: { transform: { x: 0 } }, duration: 70, iterations: 5, direction: "alternate", easing: "easeInOut" },
              }}
            >
              <Glyph name="alert" size={14} color={color.danger} />
              <Text size={12.5} color={color.danger}>{ui.error}</Text>
            </Row>
          ) : null}
          <Action tone="primary" label={pending ?? actionLabel()} busy={pending !== undefined} disabled={joining && (!form.bucket || (form.hasVault === false && !form.name.trim()))} onClick={submit} />
          {fingerprint ? <Action icon="shield" label="Unlock with fingerprint" disabled={pending !== undefined} onClick={() => { void fingerprintUnlock(); }} /> : null}
            {creating ? (
            <Column gap={10}>
              <Row gap={10} align="center">
                <Row flex={1} style={{ height: 1, background: color.line }} />
                <Text size={11.5} color={color.faint}>already use Termio?</Text>
                <Row flex={1} style={{ height: 1, background: color.line }} />
              </Row>
              <Action icon="cloud" label="Join a synced vault" onClick={() => { ui.phase = "join"; ui.error = undefined; cf.mode = "cloudflare"; }} />
            </Column>
          ) : null}
        </Column>
        <Row gap={14} justify="center">
          {ui.phase !== "locked" && !creating ? <Switch to="locked" label="I have a vault here" /> : null}
                    {joining ? <Switch to="create" label="Start a new vault" /> : null}
        </Row>
      </Column>
      <Row style={{ margin: { top: 14 }, maxWidth: "100%", minWidth: 0 }}>
        <Text size={11.5} color={color.faint} style={{ ...mono, whiteSpace: "nowrap", textOverflow: "ellipsis", minWidth: 0 }}>{ui.vaultPath}</Text>
      </Row>
    </Column>
    </Scroll>
  );
}
