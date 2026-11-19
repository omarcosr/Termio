// The core writes its reports and progress in English. Rather than teach the Rust side every
// language, the UI translates what arrives: each core sentence is a template (its format!
// string), matched here and refilled in the UI language. Reports saved in the vault or synced
// from another device follow the language switch too, and unknown text passes through as is.
import { language } from "./index";
import { corePt } from "./core-pt";

interface Template {
  pattern: RegExp;
  /** Placeholder names in key order; "" for a positional `{}`. */
  tokens: string[];
  text: string;
  /** Only placeholders (`{path} {what}`): too loose to try on a fragment. */
  bare: boolean;
  weight: number;
}

const TOKEN = /\{([^{}]*)\}/g;
const escape = (text: string) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** A clause the core glues to the end of a sentence (", reachable from this device", " (+{} related)"). */
interface Clause {
  /** Its first literal text: where it can start inside a sentence. */
  head: string;
  exact?: string;
  template?: Template;
}

let compiled: { exact: Map<string, string>; templates: Template[]; clauses: Clause[] } | undefined;

function compile(): NonNullable<typeof compiled> {
  const exact = new Map<string, string>();
  const templates: Template[] = [];
  const clauses: Clause[] = [];
  for (const [key, text] of Object.entries(corePt)) {
    const source = key.trim();
    const parts = source.split(TOKEN);
    if (parts.length === 1) {
      exact.set(source, text.trim());
      if (/^[^A-Za-z0-9{]/.test(key)) clauses.push({ head: source, exact: text.trim() });
      continue;
    }
    const literals = parts.filter((_, index) => index % 2 === 0);
    const template: Template = {
      pattern: new RegExp(`^${parts.map((part, index) => (index % 2 ? "([\\s\\S]*?)" : escape(part))).join("")}$`),
      tokens: parts.filter((_, index) => index % 2 === 1),
      text: text.trim(),
      bare: !/[A-Za-z]/.test(literals.join("")),
      weight: literals.join("").replace(/[^A-Za-z]/g, "").length,
    };
    templates.push(template);
    if (/^[^A-Za-z0-9{]/.test(key) && parts[0]) clauses.push({ head: parts[0], template });
  }
  // The most specific template wins: "OpenSSH {version} is very old" before "{path} {what}".
  templates.sort((a, b) => b.weight - a.weight);
  return { exact, templates, clauses };
}

function fill(template: Template, values: string[], depth: number): string {
  const named = new Map<string, string>();
  const positional: string[] = [];
  template.tokens.forEach((token, index) => {
    const value = translate(values[index] ?? "", depth + 1);
    if (token === "" || /^[:\d]/.test(token)) positional.push(value);
    else named.set(token.split(":")[0]!, value);
  });
  let next = 0;
  return template.text.replace(TOKEN, (whole, token: string) => {
    if (token === "") return positional[next++] ?? "";
    if (/^\d+$/.test(token)) return positional[Number(token)] ?? "";
    return named.get(token) ?? whole;
  });
}

function translate(text: string, depth: number): string {
  const { exact, templates, clauses } = (compiled ??= compile());
  const [, lead = "", core = "", trail = ""] = /^(\s*)([\s\S]*?)(\s*)$/.exec(text) ?? [];
  if (!core || depth > 3) return text;
  const known = exact.get(core);
  if (known !== undefined) return lead + known + trail;
  // Equally specific templates can both match ("Members of {group}: {members}" and "Members of
  // {group} {why}."): the one whose values are themselves known sentences is the right reading.
  let best: { text: string; weight: number; known: number } | undefined;
  for (const template of templates) {
    if (best && template.weight < best.weight) break;
    if (template.bare && depth > 0) continue;
    const match = template.pattern.exec(core);
    if (!match) continue;
    const values = match.slice(1);
    const known = values.filter(value => value.trim() && translate(value, depth + 1) !== value).length;
    if (!best || known > best.known) best = { text: fill(template, values, depth), weight: template.weight, known };
  }
  if (best) return lead + best.text + trail;
  // Sentences joined into one text (a detail made of several parts): each on its own.
  const sentences = core.split(/(?<=[.:;])\s+(?=[A-Z])/);
  if (sentences.length > 1) {
    const done = sentences.map(sentence => translate(sentence, depth + 1));
    if (done.some((sentence, index) => sentence !== sentences[index])) return lead + done.join(" ") + trail;
  }
  // A clause at the end, glued to a value the template could not tell apart (version + related).
  for (const clause of clauses) {
    for (let at = core.indexOf(clause.head, 1); at > 0; at = core.indexOf(clause.head, at + 1)) {
      const tail = core.slice(at);
      const match = clause.template?.pattern.exec(tail);
      const done = clause.exact !== undefined ? (tail === clause.head ? clause.exact : undefined) : match ? fill(clause.template!, match.slice(1), depth) : undefined;
      if (done !== undefined) return lead + translate(core.slice(0, at), depth + 1) + done + trail;
    }
  }
  return text;
}

const memo = new Map<string, string>();

/** A text the core wrote, in the UI language (as written when no translation matches). */
export function coreText(text: string | null | undefined): string {
  if (!text) return "";
  if (language() === "en") return text;
  let done = memo.get(text);
  if (done === undefined) {
    done = translate(text, 0);
    if (memo.size > 5000) memo.clear();
    memo.set(text, done);
  }
  return done;
}
