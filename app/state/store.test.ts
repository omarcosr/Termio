import { describe, expect, test } from "bun:test";
import { dropOnNewTab, dropOnPane, dropOnTab, joinPath, parseQuickConnect, shortTitle, startDrag, ui } from "./store";
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

describe("dragging terminals", () => {
  const layout = () => ui.tabs.map(tab => `${tab.id}:${tab.direction}:${tab.panes.join(",")}`);
  const reset = () => {
    ui.tabs = [
      { id: 101, kind: "terminal", panes: [10, 11], direction: "row", focus: 10 },
      { id: 102, kind: "terminal", panes: [20], direction: "row", focus: 20 },
    ];
    ui.active = 101;
  };

  test("a pane dropped on an edge goes beside that pane, and its old tab closes when empty", () => {
    reset();
    startDrag({ kind: "pane", session: 20 });
    dropOnPane(11, "left");
    expect(layout()).toEqual(["101:row:10,20,11"]);
    startDrag({ kind: "pane", session: 10 });
    dropOnNewTab();
    startDrag({ kind: "pane", session: 11 });
    dropOnPane(20, "bottom");
    expect(layout()).toEqual(["101:column:20,11", `${ui.tabs[1]!.id}:row:10`]);
  });

  test("the centre swaps two panes and tabs reorder on the bar", () => {
    reset();
    startDrag({ kind: "pane", session: 10 });
    dropOnPane(20, "center");
    expect(layout()).toEqual(["101:row:20,11", "102:row:10"]);
    startDrag({ kind: "tab", id: 102 });
    dropOnTab(101);
    expect(layout()).toEqual(["102:row:10", "101:row:20,11"]);
    startDrag({ kind: "tab", id: 102 });
    dropOnPane(11, "right");
    expect(layout()).toEqual(["101:row:20,11,10"]);
    expect(ui.active).toBe(101);
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
