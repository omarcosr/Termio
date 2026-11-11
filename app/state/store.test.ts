import { describe, expect, test } from "bun:test";
import { joinPath, parseQuickConnect, shortTitle } from "./store";
import { size } from "../views/Files";

describe("quick connect", () => {
  test("reads user, host and port", () => {
    expect(parseQuickConnect("deploy@10.0.0.5:2222")).toEqual({ user: "deploy", address: "10.0.0.5", port: 2222 });
    expect(parseQuickConnect("host.example.com")).toEqual({ user: "", address: "host.example.com", port: 22 });
    expect(parseQuickConnect("root@[2001:db8::1]:22")).toEqual({ user: "root", address: "2001:db8::1", port: 22 });
  });

  test("refuses text that is not an address", () => {
    expect(parseQuickConnect("two words")).toBeUndefined();
    expect(parseQuickConnect("")).toBeUndefined();
  });
});

describe("remote paths", () => {
  test("go into and out of folders", () => {
    expect(joinPath("/home/ops", "logs")).toBe("/home/ops/logs");
    expect(joinPath("/home/ops/", "logs")).toBe("/home/ops/logs");
    expect(joinPath("/home/ops", "..")).toBe("/home");
    expect(joinPath("/home", "..")).toBe("/");
    expect(joinPath("/", "..")).toBe("/");
  });
});

describe("labels", () => {
  test("tab titles drop a shell's full path", () => {
    expect(shortTitle("C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")).toBe("powershell");
    expect(shortTitle("/usr/bin/zsh")).toBe("zsh");
    expect(shortTitle("vim notes.md")).toBe("vim notes.md");
  });

  test("file sizes read at a glance", () => {
    expect(size(412)).toBe("412 B");
    expect(size(2310)).toBe("2.3 KB");
    expect(size(21_004_288)).toBe("20 MB");
    expect(size(5 * 1024 ** 4)).toBe("5.0 TB");
  });
});
