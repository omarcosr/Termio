import { describe, expect, test } from "bun:test";
import { resolveLanguage, setLanguage, t } from "./index";
import { pt } from "./pt";

const placeholders = (text: string) => [...text.matchAll(/\{(\w+)\}/g)].map(match => match[1]).sort();

describe("i18n", () => {
  test("every Portuguese text keeps the placeholders of its key", () => {
    const broken = Object.entries(pt).filter(([key, text]) => placeholders(key).join() !== placeholders(text).join());
    expect(broken).toEqual([]);
  });

  test("no Portuguese text is empty", () => {
    expect(Object.entries(pt).filter(([, text]) => !text.trim())).toEqual([]);
  });

  test("the system locale picks the language", () => {
    expect(resolveLanguage("auto", "pt-BR")).toBe("pt-BR");
    expect(resolveLanguage(undefined, "pt_PT")).toBe("pt-BR");
    expect(resolveLanguage("auto", "en-US")).toBe("en");
    expect(resolveLanguage("en", "pt-BR")).toBe("en");
    expect(resolveLanguage("pt-BR", "de-DE")).toBe("pt-BR");
  });

  test("t translates and fills placeholders", () => {
    setLanguage("pt-BR");
    expect(t("Delete {name}", { name: "web" })).toBe("Excluir web");
    setLanguage("en");
    expect(t("Delete {name}", { name: "web" })).toBe("Delete web");
  });
});
