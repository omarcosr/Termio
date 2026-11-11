/**
 * Builds, signs and publishes a Termio release on GitHub, which the app's updater reads
 * (app/state/updates.ts).
 *
 *   bun run release                    Windows executable
 *   bun run release --android          also the Android APK
 *   bun run release --notes "…"        release notes (shown in the app and on GitHub)
 *   bun run release --dry              build and sign into dist/updates, publish nothing
 *   bun run release --allow-dirty      publish with uncommitted changes in the tree
 *
 * The version is package.json `version` (keep `tarve.version` equal). Signing needs the private key
 * from `tarve keygen`: ./tarve-update.key or TARVE_UPDATE_PRIVATE_KEY. The release is created as a
 * draft, `latest.json` goes up last, and only then it is published, so an app never sees a manifest
 * whose files are missing.
 */
import { existsSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { parseArgs } from "node:util";
import pkg from "../package.json";

const { values } = parseArgs({
  args: process.argv.slice(2),
  options: {
    android: { type: "boolean", default: false },
    dry: { type: "boolean", default: false },
    "allow-dirty": { type: "boolean", default: false },
    notes: { type: "string" },
  },
});

const version = pkg.version;
const tag = `v${version}`;
const repo = pkg.updates.repo;
const publicKey = pkg.updates.publicKey.trim();
const build = join("dist", "release");
const out = join("dist", "updates");

function fail(message: string): never {
  console.error(`release: ${message}`);
  process.exit(1);
}

function run(command: string[], options: { quiet?: boolean; allowFail?: boolean } = {}): string {
  if (!options.quiet) console.log(`> ${command.join(" ")}`);
  const result = Bun.spawnSync(command, { stdout: options.quiet ? "pipe" : "inherit", stderr: options.quiet ? "pipe" : "inherit" });
  if (!result.success && !options.allowFail) fail(`${command[0]} exited with ${result.exitCode}`);
  return result.success ? (result.stdout?.toString() ?? "").trim() : "";
}

const tarve = (...args: string[]) => run(["bun", "x", "tarve", ...args]);

if (pkg.tarve.version !== version) fail(`package.json version ${version} and tarve.version ${pkg.tarve.version} differ`);
if (!publicKey) fail("package.json updates.publicKey is empty: run `bun x tarve keygen` once and paste the public key there");
if (!process.env.TARVE_UPDATE_PRIVATE_KEY && !existsSync("tarve-update.key")) fail("no signing key: ./tarve-update.key or TARVE_UPDATE_PRIVATE_KEY");

let commit = "";
if (!values.dry) {
  if (!values["allow-dirty"] && run(["git", "status", "--porcelain"], { quiet: true })) fail("uncommitted changes: commit them or pass --allow-dirty");
  commit = run(["git", "rev-parse", "HEAD"], { quiet: true });
  if (!run(["git", "branch", "-r", "--contains", commit], { quiet: true })) fail(`commit ${commit.slice(0, 7)} is not pushed`);
  if (run(["gh", "release", "view", tag, "--repo", repo, "--json", "tagName"], { quiet: true, allowFail: true })) fail(`${tag} is already released: bump package.json version`);
}

rmSync(build, { recursive: true, force: true });
rmSync(out, { recursive: true, force: true });

const artifacts: string[] = [];
run(["cargo", "build", "--release", "-p", "termio-core"]);
tarve("build", "app/main.tsx", "--runtime", "txiki", "--version", version, "--outfile", join(build, "Termio.exe"));
artifacts.push(`win32-x64=${join(build, "Termio.exe")}`);

if (values.android) {
  // Android only installs an update signed with the same key as the installed APK.
  if (!process.env.TARVE_ANDROID_KEYSTORE) console.warn("release: TARVE_ANDROID_KEYSTORE is unset, the APK is signed with this machine's debug keystore");
  run(["cargo", "ndk", "-t", "arm64-v8a", "build", "--release", "-p", "termio-core"]);
  tarve("build", "app/main.tsx", "--target", "android-arm64", "--version", version, "--outfile", join(build, "Termio.apk"));
  artifacts.push(`android-arm64=${join(build, "Termio.apk")}`);
}

tarve(
  "release",
  "--version", version,
  ...artifacts.flatMap(artifact => ["--artifact", artifact]),
  "--public-key", publicKey,
  // Absolute URLs: the manifest is fetched through a redirect, so relative ones would resolve against GitHub's storage host.
  "--base-url", `https://github.com/${repo}/releases/download/${tag}/`,
  "--out", out,
  ...(values.notes ? ["--notes", values.notes] : []),
);

const files = readdirSync(out).filter(name => name !== "latest.json").map(name => join(out, name));
if (values.dry) {
  console.log(`release: ${tag} built and signed in ${out}; nothing published (--dry)`);
  process.exit(0);
}

run(["gh", "release", "create", tag, "--repo", repo, "--draft", "--target", commit, "--title", `Termio ${version}`, "--notes", values.notes ?? `Termio ${version}`, ...files]);
run(["gh", "release", "upload", tag, "--repo", repo, join(out, "latest.json")]);
run(["gh", "release", "edit", tag, "--repo", repo, "--draft=false", "--latest"]);
console.log(`release: ${tag} published: https://github.com/${repo}/releases/tag/${tag}`);
