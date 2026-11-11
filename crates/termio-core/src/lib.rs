//! Termio's native core, loaded by the Tarve app as a plugin library: sessions, rendering,
//! vault and transports live here; the UI talks to it through the C ABI in [`ffi`].

mod app;
mod clipboard;
mod echo;
mod events;
mod importers;
mod leveldb;
pub mod ffi;
mod session;
mod sshconfig;
mod surface;
mod terminal;
mod termius;
mod v8;
