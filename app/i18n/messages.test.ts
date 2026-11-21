import { afterAll, describe, expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { setLanguage } from "./index";
import { message, type Message } from "./messages";
import { messagesPt } from "./messages-pt";

const CORE = new URL("../../crates/termio-core/src/", import.meta.url);

/** Every `tr!("id", "English template", …)` of the core: id -> template. */
function coreMessages(): Map<string, string> {
  const found = new Map<string, string>();
  for (const file of readdirSync(CORE).filter(name => name.endsWith(".rs") && name !== "msg.rs")) {
    for (const match of readFileSync(new URL(file, CORE), "utf8").matchAll(/tr!\(\s*"([^"]+)",\s*"((?:[^"\\]|\\.)*)"/g)) {
      const template = JSON.parse(`"${match[2]}"`) as string;
      const before = found.get(match[1]!);
      if (before !== undefined && before !== template) throw new Error(`${match[1]} has two templates: "${before}" and "${template}"`);
      found.set(match[1]!, template);
    }
  }
  return found;
}

const placeholders = (text: string) => [...text.matchAll(/\{(\w+)\}/g)].map(match => match[1]!);

describe("core messages", () => {
  afterAll(() => setLanguage("en"));
  const core = coreMessages();

  test("every message id of the core has a Portuguese translation", () => {
    expect([...core.keys()].filter(key => !(key in messagesPt))).toEqual([]);
  });

  test("the catalog has no id the core no longer sends", () => {
    expect(Object.keys(messagesPt).filter(key => !core.has(key))).toEqual([]);
  });

  test("translations only use values their message has, and plural forms only with a count", () => {
    const broken = Object.entries(messagesPt).filter(([key, entry]) => {
      const allowed = new Set(placeholders(core.get(key) ?? ""));
      const texts = typeof entry === "string" ? [entry] : [entry.one, entry.other];
      return texts.some(text => placeholders(text).some(name => !allowed.has(name))) || (typeof entry !== "string" && !allowed.has("count"));
    });
    expect(broken).toEqual([]);
  });

  test("a message is rendered from the catalog with its values, nested messages and plurals", () => {
    const why: Message = { key: "audit.accounts.group.shadow", text: "can read password hashes" };
    const group: Message = { key: "audit.accounts.group.detail", text: "Members of shadow can read password hashes.", args: { group: "shadow", why } };
    const updates = (count: number): Message => ({ key: "audit.packages.updates.title", text: `${count} packages have updates waiting`, args: { count } });
    setLanguage("pt-BR");
    expect(message(group)).toBe(String(messagesPt["audit.accounts.group.detail"]).replace("{group}", "shadow").replace("{why}", String(messagesPt["audit.accounts.group.shadow"])));
    expect(message(updates(1))).toBe("1 pacote tem atualização pendente");
    expect(message(updates(1200))).toBe("1200 pacotes têm atualizações pendentes");
    expect(message({ text: "sudo reboot" })).toBe("sudo reboot");
    expect(message({ key: "audit.unknown", text: "Something new" })).toBe("Something new");
    expect(message("An older report")).toBe("An older report");
    setLanguage("en");
    expect(message(updates(3))).toBe("3 packages have updates waiting");
  });
});
