import { Column, openExternal, Row, Select, Text } from "@tarve/core";
import { core } from "../core/plugin";
import { refresh, ui, type SyncForm } from "../state/store";
import { compact, Action, Field, Hint, mono } from "../ui/kit";
import { color, radius } from "../ui/tokens";

/** The token flow: one Cloudflare token, then pick an account and a bucket. */
export const cf = { bucket: "", mode: "cloudflare" as "cloudflare" | "manual", token: "", accessKey: "", secretKey: "", accounts: [] as { id: string; name: string }[], account: "", buckets: [] as string[], newBucket: "termio-vault", name: "termio", error: "" };

function cfCall<T>(request: { op: string } & Record<string, unknown>): T | undefined {
  try {
    cf.error = "";
    return core().call<T>(request);
  } catch (error) {
    cf.error = error instanceof Error ? error.message : String(error);
    return undefined;
  } finally {
    refresh();
  }
}

function pickAccount(id: string): void {
  cf.account = id;
  cf.buckets = cfCall<{ buckets: string[] }>({ op: "cloudflare.buckets", token: cf.token, account: id })?.buckets ?? [];
}

function connectToken(): void {
  const result = cfCall<{ accessKey: string; secretKey: string; accounts: { id: string; name: string }[] }>({ op: "cloudflare.connect", token: cf.token });
  if (!result) return;
  Object.assign(cf, { accessKey: result.accessKey, secretKey: result.secretKey, accounts: result.accounts, account: "", buckets: [] });
  if (result.accounts.length === 1) pickAccount(result.accounts[0]!.id);
}

const NEW = "__new__";
let pick: (form: SyncForm) => void = () => {};

function useBucket(bucket: string): void {
  cf.bucket = bucket;
  pick({ account: cf.account, bucket, accessKey: cf.accessKey, secretKey: cf.secretKey, name: cf.name.trim() || "termio" });
}

function createBucket(): void {
  const name = cf.newBucket.trim();
  if (cfCall({ op: "cloudflare.createBucket", token: cf.token, account: cf.account, name }) !== undefined) useBucket(name);
}

export function CloudflareConnect(props: { onPick: (form: SyncForm) => void; selected?: string; allowCreate?: boolean; askName?: boolean }) {
  pick = props.onPick;
  const openTokenPage = () => {
    const url = cfCall<{ url: string }>({ op: "cloudflare.tokenUrl" })?.url;
    if (url) openExternal(url);
  };
  return (
    <Column gap={14}>
      <Column gap={6} align="start">
        <Action icon="cloud" label="Create a token on Cloudflare" onClick={openTokenPage} />
        <Hint>Opens the dashboard with R2 Edit and Account Read filled in: press Create and copy the token.</Hint>
      </Column>
      <Row gap={10} align="end">
        <Field label="Cloudflare API token" type="password" value={cf.token} grow={1} placeholder="Paste the token here" onChange={value => { cf.token = value; cf.accounts = []; cf.account = ""; cf.buckets = []; }} />
        <Action tone="primary" label={cf.accounts.length ? (compact() ? "OK" : "Connected") : "Connect"} disabled={!cf.token.trim() || cf.accounts.length > 0} onClick={connectToken} />
      </Row>
      {cf.accounts.length > 1 ? (
        <Column gap={6}>
          <Text size={12} weight={600} color={color.muted}>Account</Text>
          <Select style={{ width: "100%" }} id="cf-account" value={cf.account || undefined} placeholder="Choose an account" options={cf.accounts.map(account => ({ value: account.id, label: account.name || account.id }))} onValueChange={pickAccount} />
        </Column>
      ) : null}
      {cf.account ? (
        <Column gap={6}>
          <Text size={12} weight={600} color={color.muted}>Bucket</Text>
          <Select
            style={{ width: "100%" }}
            id="cf-bucket"
            value={cf.bucket === NEW ? NEW : (props.selected || undefined)}
            placeholder={cf.buckets.length ? "Choose a bucket" : "No buckets yet"}
            options={[...cf.buckets.map(bucket => ({ value: bucket, label: bucket })), ...(props.allowCreate === false ? [] : [{ value: NEW, label: "+ New bucket…" }])]}
            onValueChange={value => { if (value === NEW) cf.bucket = NEW; else useBucket(value); }}
          />
          {cf.bucket === NEW ? (
            <Row gap={10} align="end">
              <Field label="Bucket name" value={cf.newBucket} monospace grow={1} onChange={value => { cf.newBucket = value; }} />
              <Action icon="plus" label="Create" disabled={ui.busy || !/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/.test(cf.newBucket.trim())} onClick={createBucket} />
            </Row>
          ) : null}
        </Column>
      ) : null}
      {props.askName && cf.account ? <Field label="Vault name" value={cf.name} monospace hint={`Saved in the bucket as ${(cf.name.trim() || "termio")}.vault`} onChange={value => { cf.name = value.replace(/[^A-Za-z0-9._-]/g, ""); }} /> : null}
      {cf.error ? <Hint tone="danger">{cf.error}</Hint> : null}
      {ui.error ? <Hint tone="danger">{ui.error}</Hint> : null}
    </Column>
  );
}
