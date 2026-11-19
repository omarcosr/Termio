import { pt } from "./pt";

/** The languages the UI speaks. English is the source: its text is the key itself. */
export type Language = "en" | "pt-BR";
/** The setting: a fixed language, or "auto" to follow the system. */
export type LanguageChoice = "auto" | Language;
/** Every translatable text. A key missing from the Portuguese table fails the typecheck. */
export type Key = keyof typeof pt;
export type Params = Record<string, string | number | null | undefined>;

const tables: Record<Language, Partial<Record<Key, string>>> = { en: {}, "pt-BR": pt };

/** The system language as a BCP 47 tag, from Intl or the usual environment variables. */
export function systemLocale(): string {
  try {
    const locale = new Intl.DateTimeFormat().resolvedOptions().locale;
    if (locale && locale !== "und") return locale;
  } catch {
    // No Intl on this runtime: the environment decides.
  }
  const env = process.env.LC_ALL || process.env.LC_MESSAGES || process.env.LANG || "";
  return env.split(".")[0]!.replace("_", "-") || "en";
}

/** The supported language closest to a locale: any Portuguese gets pt-BR, everything else English. */
export function resolveLanguage(choice: LanguageChoice | undefined, locale = systemLocale()): Language {
  if (choice === "en" || choice === "pt-BR") return choice;
  return /^pt([-_]|$)/i.test(locale) ? "pt-BR" : "en";
}

let current: Language = resolveLanguage(process.env.TERMIO_LANG as LanguageChoice | undefined);

export function language(): Language {
  return current;
}

/** Switches the language; callers re-render. */
export function setLanguage(choice: LanguageChoice | undefined): void {
  current = resolveLanguage((process.env.TERMIO_LANG as LanguageChoice | undefined) || choice);
}

/** The BCP 47 tag for dates and numbers in the current language. */
export function locale(): string {
  return current;
}

/** The text of `key` in the current language, with each `{name}` replaced by `params.name`. */
export function t(key: Key, params?: Params): string {
  const text = tables[current][key] ?? key;
  return params ? text.replace(/\{(\w+)\}/g, (whole, name: string) => (name in params ? String(params[name] ?? "") : whole)) : text;
}

/** One of two texts by count: `plural(n, "{count} host", "{count} hosts")`. */
export function plural(count: number, one: Key, many: Key, params?: Params): string {
  return t(count === 1 ? one : many, { count, ...params });
}
