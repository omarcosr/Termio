# Step 2 spike: surface, FFI events, input

Measured on Windows x64, `@tarve/core` 0.10.0, Bun 1.4.4, display scale 1.25, with
`bun scripts/spike.tsx` (default renderer) and `SPIKE_RENDERER=cpu bun scripts/spike.tsx`.

## Measured

| Question | Result | Evidence |
|---|---|---|
| Surface handle on the D3D11 renderer | `ISwapChainPanelNative` | `surface` event, `ready` |
| Surface handle on the CPU renderer | `TarveFrames` | `surface` event, `ready` |
| DXGI presenter (`crates/termio-render/src/dxgi.rs`) | `SetSwapChain`, `UpdateSubresource`, `Present` return success | frame counter 1 then 2, no `surface.error` |
| Frames presenter (`crates/termio-render/src/frames.rs`) | finds `tarve_surface_present` in the loaded runtime and presents | frame counter, and the capture below |
| Pixels on the `TarveFrames` path | "hello from rust" and a caret, drawn by the Rust rasterizer | Tarve `capture` of the CPU-renderer window |
| Core thread to JS events | a thread-safe `JSCallback` wake plus a drain call delivers `surface.ready` from the render thread | `coreEvents` in the spike output |
| Repaint on change | text sent to the session presents exactly one more frame | counter 1 to 2 |
| Idle | 0 frames over 1.5 s | counter unchanged |
| Pointer events | a scripted click arrives as `pointer` down and up naming `terminal-<id>` | `pointers` in the spike output |

## Not verified

- **D3D11 pixels on screen.** The API calls succeed, but nothing here shows the swap chain
  composited. Tarve's `capture` reads its own render target, where a composition surface is a
  hole (the D3D11 capture is a blank dark frame), so it cannot answer this either way.
  To check: `SPIKE_HOLD_MS=20000 bun scripts/spike.tsx` and look at the window. It should show
  "hello from rust" on a dark background.
- **Real keyboard and wheel.** Tarve's scripted input only synthesizes pointer down/up
  (`native/src/runtime.rs`, `Command::Input`); `keyboard` and wheel events come from real window
  events only. Repeat, AltGr, dead keys, IME composition, paste and the wheel are untested.
  To check: the same hold run; type, hold a key, use AltGr and a dead key, paste, scroll. The
  output lists every `keyboard` event received and how many frames were presented meanwhile.
- **Linux.** Nothing ran there. On the Vulkan renderer Tarve hands out `TarveGL` surfaces, which
  `TerminalPane` reports as unsupported: there is no presenter for it yet.

## Consequences for the next steps

- Two presenters are needed on Windows and both exist; which one runs follows the surface's
  `handleType`, so `renderer: "cpu"` keeps working as a fallback.
- Keyboard events carry DOM `key` and `code` with modifiers and `repeat`, and no composed text or
  IME state. If the hold run shows dead keys or IME arriving wrong, the fix belongs in Tarve (a
  text-input event for a focused surface), not in a workaround here.
