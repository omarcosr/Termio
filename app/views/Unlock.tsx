import { Column, Pressable, Row, Scroll, Select, Text } from "@tarve/core";
import { createSyncedVault, createVault, joinVault, listVaults, ui, unlockVault, type SyncForm } from "../state/store";
import { Glyph } from "../ui/icons";
import { compact, Action, Field, mono } from "../ui/kit";
import { CloudflareConnect, cf } from "./Cloudflare";
import { color, font, radius } from "../ui/tokens";

const form = { password: "", confirm: "", account: "", bucket: "", accessKey: "", secretKey: "", hasVault: undefined as boolean | undefined, vaults: undefined as string[] | undefined, name: "termio" };
const NEW = "__new__";

function r2(): SyncForm {
  return { account: form.account, bucket: form.bucket, accessKey: form.accessKey, secretKey: form.secretKey, name: form.name.trim() || "termio" };
}

function submit(): void {
  if (ui.phase === "create") createVault(form.password, form.confirm);
  else if (ui.phase === "join" && form.hasVault === undefined) manualCheck();
  else if (ui.phase === "join" && form.hasVault === false) createSyncedVault(form.password, form.confirm, r2());
  else if (ui.phase === "join") joinVault(form.password, r2());
  else unlockVault(form.password);
  if (ui.phase === "ready") Object.assign(form, { password: "", confirm: "", secretKey: "" });
}

/** Lists the vaults in the chosen bucket: the first is preselected, an empty bucket starts a new one. */
function picked(chosen: SyncForm): void {
  ui.error = undefined;
  Object.assign(form, chosen);
  manualCheck();
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

function Switch({ to, label }: { to: "create" | "join" | "locked"; label: string }) {
  return (
    <Pressable focusable onClick={() => { ui.phase = to; ui.error = undefined; }} style={{ hover: { opacity: 0.8 } }}>
      <Text size={12.5} weight={600} color={color.accent}>{label}</Text>
    </Pressable>
  );
}

/** Before anything else: open the vault, create the first one, or join a synced one. */
export function Unlock() {
  const creating = ui.phase === "create";
  const joining = ui.phase === "join";
  const title = creating ? "Create your vault" : joining ? "Join a synced vault" : "Unlock Termio";
  const lead = creating
    ? "Hosts, keys and passwords live in one file encrypted with this password. It never leaves this device unencrypted, and it cannot be recovered."
    : joining
      ? "Sign in with Cloudflare, pick a bucket and a vault in it to download, or name a new one to create there."
      : "Your vault is encrypted on this device.";
  return (
    <Scroll flex={1} style={{ background: color.canvas }}>
    <Column align="center" justify={joining ? "start" : "center"} style={{ minHeight: "100%", padding: { top: 32, bottom: 32, left: 16, right: 16 } }}>
      <Column gap={22} style={{ width: joining ? 460 : 380, maxWidth: "100%", padding: compact() ? 20 : 28, background: color.panel, radius: radius.panel, borderColor: color.line, borderWidth: 1, boxShadow: { y: 18, blur: 48, color: "#00000066" } }}>
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
          {joining && cf.mode === "cloudflare" ? (
            <Column gap={10}>
              <CloudflareConnect onPick={picked} selected={form.bucket} />
              <Pressable focusable onClick={() => { cf.mode = "manual"; }} style={{ hover: { opacity: 0.8 } }}>
                <Text size={12} color={color.faint}>Use access keys instead</Text>
              </Pressable>
            </Column>
          ) : null}
          {joining && cf.mode === "manual" ? (
            <Column gap={14}>
              <Field label="Cloudflare account ID" value={form.account} onChange={value => { form.account = value; }} monospace />
              <Field label="Bucket" value={form.bucket} onChange={value => { form.bucket = value; form.hasVault = undefined; form.vaults = undefined; }} monospace />
              <Row gap={10}>
                <Field label="Access key ID" value={form.accessKey} onChange={value => { form.accessKey = value; }} monospace grow={1} />
                <Field label="Secret" type="password" value={form.secretKey} onChange={value => { form.secretKey = value; }} grow={1} />
              </Row>
            </Column>
          ) : null}
          {joining && form.bucket && form.vaults ? (
            <Column gap={10}>
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
            <Row gap={8} align="center" style={{ padding: { top: 8, bottom: 8, left: 10, right: 10 }, background: color.dangerSoft, radius: radius.control }}>
              <Glyph name="alert" size={14} color={color.danger} />
              <Text size={12.5} color={color.danger}>{ui.error}</Text>
            </Row>
          ) : null}
          <Action tone="primary" label={creating ? "Create vault" : joining ? (form.hasVault === false ? "Create synced vault" : form.hasVault ? "Download vault" : "Find vaults") : "Unlock"} disabled={joining && (!form.bucket || (form.hasVault === false && !form.name.trim()))} onClick={submit} />
          {creating ? (
            <Column gap={10}>
              <Row gap={10} align="center">
                <Row flex={1} style={{ height: 1, background: color.line }} />
                <Text size={11.5} color={color.faint}>already use Termio?</Text>
                <Row flex={1} style={{ height: 1, background: color.line }} />
              </Row>
              <Action icon="cloud" label="Sign in with Cloudflare" onClick={() => { ui.phase = "join"; ui.error = undefined; cf.mode = "cloudflare"; }} />
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
