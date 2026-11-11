//! Core → UI events. Events queue here as JSON lines; a notifier thread calls the UI's wake
//! callback once per batch and the UI drains the queue on its own thread, so no pointer
//! crosses threads and nothing polls.

use serde_json::Value;
use std::collections::VecDeque;
use std::sync::mpsc::{Sender, channel};
use std::sync::{Mutex, OnceLock};

pub type WakeFn = unsafe extern "C" fn();

struct Queue(Mutex<VecDeque<String>>);

static QUEUE: Queue = Queue(Mutex::new(VecDeque::new()));
static NOTIFIER: OnceLock<Sender<()>> = OnceLock::new();

/// Starts the notifier; `wake` must be callable from any thread. Later calls are ignored.
pub fn init(wake: WakeFn) {
    NOTIFIER.get_or_init(|| {
        let (tx, rx) = channel::<()>();
        std::thread::Builder::new()
            .name("termio-events".into())
            .spawn(move || {
                while rx.recv().is_ok() {
                    // One wake covers everything queued so far.
                    while rx.try_recv().is_ok() {}
                    // SAFETY: the UI registered a thread-safe callback that stays alive for the process.
                    unsafe { wake() };
                }
            })
            .expect("spawn the event notifier");
        tx
    });
}

impl Queue {
    /// Appends an event; true when the queue was empty, so the UI needs a wake.
    fn push(&self, event: String) -> bool {
        let mut events = self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let was_empty = events.is_empty();
        events.push_back(event);
        was_empty
    }

    fn drain(&self, buffer: &mut [u8]) -> i32 {
        let mut events = self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut written = 0;
        while let Some(event) = events.front() {
            let needed = event.len() + 1;
            if written + needed > buffer.len() {
                if written == 0 {
                    return -(needed as i32);
                }
                break;
            }
            buffer[written..written + event.len()].copy_from_slice(event.as_bytes());
            buffer[written + event.len()] = b'\n';
            written += needed;
            events.pop_front();
        }
        written as i32
    }
}

pub fn emit(event: Value) {
    if QUEUE.push(event.to_string()) && let Some(notifier) = NOTIFIER.get() {
        let _ = notifier.send(());
    }
}

/// Moves whole events into `buffer`, one JSON document per line. Returns the bytes written, 0
/// when the queue is empty, or minus the size the next event needs when it does not fit.
pub fn drain(buffer: &mut [u8]) -> i32 {
    QUEUE.drain(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn events_drain_whole_and_in_order() {
        // A queue of its own: sessions in other tests emit to the shared one.
        let queue = Queue(Mutex::new(VecDeque::new()));
        assert!(queue.push(json!({ "type": "a" }).to_string()));
        assert!(!queue.push(json!({ "type": "b", "text": "x".repeat(40) }).to_string()));
        let mut small = [0u8; 16];
        assert_eq!(queue.drain(&mut small), 13);
        assert_eq!(&small[..13], b"{\"type\":\"a\"}\n");
        assert!(queue.drain(&mut small) < 0);
        let mut large = [0u8; 256];
        let written = queue.drain(&mut large) as usize;
        assert!(std::str::from_utf8(&large[..written]).unwrap().starts_with("{\"text\":"));
        assert_eq!(queue.drain(&mut large), 0);
    }
}
