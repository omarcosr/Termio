import { Column, openExternal, Pressable, Row, Text } from "@tarve/core";
import { core } from "../core/plugin";
import { refresh, ui, type SyncForm } from "../state/store";
import { Action, Field, Hint, mono } from "../ui/kit";
import { color, radius } from "../ui/tokens";

/** The token flow: one Cloudflare token, then pick an account and a bucket. */
export const cf = { mode: "cloudflare" as "cloudflare" | "manual", token: "", accessKey: "", secretKey: "", accounts: [] as { id: string; name: string }[], account: "", buckets: [] as string[], newBucket: "termio-vault", error: "" };

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

let pick: (form: SyncForm) => void = () => {};

function useBucket(bucket: string): void {
  pick({ account: cf.account, bucket, accessKey: cf.accessKey, secretKey: cf.secretKey });
}

function createBucket(): void {
  const name = cf.newBucket.trim();
  if (cfCall({ op: "cloudflare.createBucket", token: cf.token, account: cf.account, name }) !== undefined) useBucket(name);
}

function Choice(props: { label: string; selected?: boolean; onPress: () => void }) {
  return (
    <Pressable focusable onClick={props.onPress} style={{ hover: { opacity: 0.85 } }}>
      <Row gap={10} align="center" style={{ padding: { top: 9, bottom: 9, left: 12, right: 12 }, radius: radius.control, background: props.selected ? color.accentSoft : color.raised, borderColor: props.selected ? color.accent : color.line, borderWidth: 1 }}>
        <Text size={13} weight={600} color={color.text} style={mono}>{props.label}</Text>
      </Row>
    </Pressable>
  );
}

export function CloudflareConnect(props: { onPick: (form: SyncForm) => void; selected?: string; allowCreate?: boolean }) {
  pick = props.onPick;
  const openTokenPage = () => {
    const url = cfCall<{ url: string }>({ op: "cloudflare.tokenUrl" })?.url;
    if (url) openExternal(url);
  };
  return (
    <Column gap={14}>
      <Row gap={8} align="center">
        <Action icon="cloud" label="Create a token on Cloudflare" onClick={openTokenPage} />
        <Hint>Opens the dashboard with R2 Edit and Account Read filled in: press Create and copy the token.</Hint>
      </Row>
      <Row gap={10} align="end">
        <Field label="Cloudflare API token" type="password" value={cf.token} grow={1} placeholder="Paste the token here" onChange={value => { cf.token = value; cf.accounts = []; cf.account = ""; cf.buckets = []; }} />
        <Action tone="primary" label={cf.accounts.length ? "Connected" : "Connect"} disabled={!cf.token.trim() || cf.accounts.length > 0} onClick={connectToken} />
      </Row>
      {cf.accounts.length > 1 ? (
        <Column gap={8}>
          <Text size={12} weight={600} color={color.muted}>Account</Text>
          <Row gap={8}>{cf.accounts.map(account => <Choice label={account.name || account.id} selected={cf.account === account.id} onPress={() => pickAccount(account.id)} />)}</Row>
        </Column>
      ) : null}
      {cf.account ? (
        <Column gap={8}>
          <Text size={12} weight={600} color={color.muted}>Pick a bucket</Text>
          {cf.buckets.length ? <Column gap={6}>{cf.buckets.map(bucket => <Choice label={bucket} selected={props.selected === bucket} onPress={() => useBucket(bucket)} />)}</Column> : <Hint>No buckets in this account yet.</Hint>}
          {props.allowCreate === false ? null : <Row gap={10} align="end">
            <Field label="Or create one" value={cf.newBucket} monospace grow={1} onChange={value => { cf.newBucket = value; }} />
            <Action icon="plus" label="Create and use" disabled={ui.busy || !/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/.test(cf.newBucket.trim())} onClick={createBucket} />
          </Row>}
        </Column>
      ) : null}
      {cf.error ? <Hint tone="danger">{cf.error}</Hint> : null}
      {ui.error ? <Hint tone="danger">{ui.error}</Hint> : null}
    </Column>
  );
}
