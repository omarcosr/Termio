// Runs scripts/ui-check.tsx at phone sizes with touch controls; fails on any layout fault.
const sizes = ["360x740", "320x640"];
let failed = false;
for (const size of sizes) {
  const run = Bun.spawnSync([process.execPath, "scripts/ui-check.tsx"], { env: { ...process.env, UI_SIZE: size, TERMIO_TOUCH: "1" }, stdout: "inherit", stderr: "inherit" });
  if (run.exitCode !== 0) failed = true;
}
process.exit(failed ? 1 : 0);
