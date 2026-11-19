import { afterAll, describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { coreText } from "./core";
import { coreKeep, corePt } from "./core-pt";
import { setLanguage } from "./index";

const AUDIT = new URL("../../crates/termio-core/src/audit.rs", import.meta.url);

/** The sentences audit.rs can show: string literals with words, outside the shell script and the tests. */
function auditLiterals(): Set<string> {
  const lines = readFileSync(AUDIT, "utf8").split(/\r?\n/);
  const start = lines.findIndex(line => line.includes("pub fn step("));
  const end = lines.findIndex(line => line.includes("#[cfg(test)]"));
  // The two refusals before the script are errors the UI shows.
  const scanned = [...lines.slice(0, start).filter(line => line.includes("Settings > Security")), ...lines.slice(start, end)];
  const found = new Set<string>();
  for (const line of scanned) {
    if (/^\s*\/\//.test(line)) continue;
    for (const match of line.matchAll(/"((?:[^"\\]|\\.)*)"/g)) {
      const text = match[1]!.replace(/\\(.)/g, (_, char: string) => (char === "n" ? "\n" : char === "t" ? "\t" : char)).replace(/\{\{/g, "{").replace(/\}\}/g, "}");
      const words = text.replace(/\{[^{}]*\}/g, "");
      if (/[A-Za-z]{3,}/.test(words) && (/\s/.test(words.trim()) || /[….]$/.test(text))) found.add(text);
    }
  }
  return found;
}

const tokens = (text: string) => [...text.matchAll(/\{([^{}]*)\}/g)].map(match => match[1]!);

describe("core text", () => {
  afterAll(() => setLanguage("en"));

  test("every sentence of audit.rs is translated or deliberately kept", () => {
    const literals = auditLiterals();
    const missing = [...literals].filter(text => !(text in corePt) && !coreKeep.includes(text));
    expect(missing).toEqual([]);
  });

  test("no translation is left over from a sentence audit.rs no longer has", () => {
    const literals = auditLiterals();
    const bare = (key: string) => !/[A-Za-z]/.test(key.replace(/\{[^{}]*\}/g, ""));
    expect(Object.keys(corePt).filter(key => !literals.has(key) && !bare(key))).toEqual([]);
    expect(coreKeep.filter(key => !literals.has(key))).toEqual([]);
  });

  test("translations keep the placeholders of their key", () => {
    const broken = Object.entries(corePt).filter(([key, text]) => {
      const named = (list: string[]) => list.filter(token => /^[A-Za-z_]/.test(token)).sort().join();
      const positional = (list: string[]) => list.filter(token => !/^[A-Za-z_]/.test(token));
      const indexes = positional(tokens(text)).filter(token => /^\d+$/.test(token)).map(Number);
      return named(tokens(key)) !== named(tokens(text)) || positional(tokens(text)).length > positional(tokens(key)).length || indexes.some(index => index >= positional(tokens(key)).length);
    });
    expect(broken).toEqual([]);
  });

  test("findings are translated with their values", () => {
    setLanguage("pt-BR");
    expect(coreText("A reboot is pending")).toBe(corePt["A reboot is pending"]!);
    expect(coreText("OpenSSH 8.9p1 is very old")).toBe(corePt["OpenSSH {version} is very old"]!.replace("{version}", "8.9p1"));
    expect(coreText("12 packages have updates waiting")).toBe(corePt["{} packages have updates waiting"]!.replace("{}", "12"));
    // A fragment inside a sentence is translated too.
    expect(coreText("/etc/shadow is readable by every user")).toBe(`/etc/shadow ${corePt["is readable by every user"]}`);
    expect(coreText("Members of docker can start a container or VM with the host's disk mounted: equivalent to root.")).toBe(
      corePt["Members of {group} {why}."]!.replace("{group}", "docker").replace("{why}", corePt["can start a container or VM with the host's disk mounted: equivalent to root"]!),
    );
    // Positional values picked out of order, and one dropped.
    expect(coreText("openssl 3.0.2 (+2 related): 5 known vulnerabilities")).toBe(`openssl 3.0.2${corePt[" (+{} related)"]!.replace("{}", "2")}: 5 vulnerabilidade(s) conhecida(s)`);
    expect(coreText("Checking ssh…")).toBe("Verificando ssh…");
  });

  test("text without a translation, and English, pass through", () => {
    setLanguage("pt-BR");
    expect(coreText("Something the core never says")).toBe("Something the core never says");
    expect(coreText("sudo apt-get update")).toBe("sudo apt-get update");
    setLanguage("en");
    expect(coreText("A reboot is pending")).toBe("A reboot is pending");
  });
});
