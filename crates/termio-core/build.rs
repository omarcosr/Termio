//! Embeds the Linux agent in the core when one was built (`bun run agent:linux`, or CI's
//! agent-linux job), so an installed app can install it on servers without shipping a loose file.

use std::path::PathBuf;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(agent_embedded)");
    println!("cargo::rerun-if-env-changed=TERMIO_AGENT_EMBED");
    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("set by cargo")).join("../..");
    let agent = std::env::var_os("TERMIO_AGENT_EMBED").map(PathBuf::from).unwrap_or_else(|| root.join("dist/agent/termio-agent-linux-x64"));
    println!("cargo::rerun-if-changed={}", agent.display());
    if agent.is_file() {
        println!("cargo::rustc-cfg=agent_embedded");
        println!("cargo::rustc-env=TERMIO_AGENT_PATH={}", agent.canonicalize().unwrap_or(agent).display());
    }
}
