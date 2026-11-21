// Messages the core writes for people (today: the security audit). The core sends each as an
// id with its values and the English text (crates/termio-core/src/msg.rs); the UI looks the id up
// in the catalog of the chosen language and fills the values in. English, a text the core does
// not translate (a command, a path) and an id a catalog lacks show the core's English text.
import { language, locale, type Language } from "./index";
import { messagesPt } from "./messages-pt";

export interface Message {
  /** Missing for text shown as written in every language. */
  key?: string;
  /** The English rendering. */
  text: string;
  args?: Record<string, MessageArg>;
}

export type MessageArg = string | number | Message;

/** A translation: one text, or one per plural form of `{count}` (Intl.PluralRules categories). */
export type CatalogEntry = string | { one: string; other: string };

const catalogs: Record<Language, Record<string, CatalogEntry>> = { en: {}, "pt-BR": messagesPt };

function arg(value: MessageArg | undefined): string {
  if (value === undefined) return "";
  // Counts, ports and ids alike: digits as sent, no grouping ("6379", not "6.379").
  if (typeof value === "number") return String(value);
  if (typeof value === "string") return value;
  return message(value);
}

/** A core message in the UI language. A plain string (an older report) is shown as it is. */
export function message(msg: Message | string | null | undefined): string {
  if (!msg) return "";
  if (typeof msg === "string") return msg;
  const entry = msg.key ? catalogs[language()][msg.key] : undefined;
  if (entry === undefined) return msg.text;
  const count = msg.args?.count;
  const text = typeof entry === "string" ? entry : typeof count === "number" && new Intl.PluralRules(locale()).select(count) === "one" ? entry.one : entry.other;
  return text.replace(/\{(\w+)\}/g, (_, name: string) => arg(msg.args?.[name]));
}
