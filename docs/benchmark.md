# Plain SSH vs termio-agent

`TERMIO_BENCH_PASSWORD=… cargo run --release -p termio-transport --example bench -- user@host[:port]`

The example connects to a real server with both transports, one after the other, and measures from
the client: time to a usable prompt, keystroke echo (30 keys), a 200 000-line `seq` flood, and how
long Ctrl+C takes to bring the prompt back during an endless flood. It installs the agent into
`~/.termio/bin` first when the server lacks it.

## Results (2026-11-11)

Server: OpenSSH on Ubuntu (WSL2), reached over its virtual network. The slow link is shaped on the
server with `tc netem delay 128ms 10ms rate 2mbit`, about a Brazil to Europe path on a weak line.

| metric | ssh, 130 ms + 2 Mbit/s | agent, 130 ms + 2 Mbit/s | ssh, LAN | agent, LAN |
|---|---|---|---|---|
| prompt ready (ms) | 1025 | 1382 | 152 | 135 |
| echo p50 (ms) | 132.1 | 128.5 | 2.4 | 2.4 |
| echo p95 (ms) | 138.8 | 140.4 | 2.5 | 2.6 |
| flood 200 000 lines (ms) | 2994 | **264** | 50 | 69 |
| flood bytes to the terminal | 1454 KB | **1 KB** | 1454 KB | 5 KB |
| Ctrl+C during a flood, prompt back (ms) | 3738 | **177** | | |

Reading it:

- Echo is the link's round trip for both: the agent adds nothing to typing.
- The agent's prompt takes one more round trip to appear: SSH starts it, then QUIC connects.
- On a slow link the difference is output. Plain SSH must deliver every byte a program writes, so
  a flood takes as long as the line needs and Ctrl+C waits behind it. The agent sends the screen as
  it is now, so it finishes in a fraction of the time, sends a thousandth of the bytes, and an
  interrupt answers in about one round trip.

Not measured yet: a second remote server (its SSH port refused connections from this machine), packet
loss, and resuming after the link drops (covered by `crates/termio-agent/tests/drops.rs`).
