//! Termio's native core, loaded by the Tarve app as a plugin library: sessions, rendering,
//! vault and transports live here; the UI talks to it through the C ABI in [`ffi`].

mod app;
mod clipboard;
mod echo;
mod events;
pub mod ffi;
mod session;
mod surface;
mod terminal;
