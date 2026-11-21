//! Text the core writes for people, as a message: a stable id, its values, and the English
//! rendering. The UI looks the id up in its catalog for the chosen language and fills in the
//! values; the English text is what an older app or an id missing from a catalog shows.
//!
//! `tr!` is the only way to make a translatable message, so every id and its English template
//! sit side by side in the source, where the UI's catalog test reads them.

use serde_json::{Map, Value, json};
use std::fmt;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Msg {
    /// Empty for text that is not translated (commands, config lines, data).
    key: &'static str,
    text: String,
    args: Vec<(&'static str, Arg)>,
}

/// A value inside a message: shown as is, or itself a message the UI translates.
#[derive(Clone, Debug, PartialEq)]
pub enum Arg {
    Text(String),
    Number(Value),
    Msg(Msg),
}

impl Msg {
    /// Built by `tr!`.
    pub fn new(key: &'static str, text: String, args: Vec<(&'static str, Arg)>) -> Self {
        Self { key, text, args }
    }

    /// Text shown as written in every language: a command, a config line, a name.
    pub fn raw(text: impl Into<String>) -> Self {
        Self { key: "", text: text.into(), args: Vec::new() }
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// `{ key, text, args }`, the shape the UI renders.
    pub fn json(&self) -> Value {
        let mut out = Map::new();
        if !self.key.is_empty() {
            out.insert("key".into(), json!(self.key));
        }
        out.insert("text".into(), json!(self.text));
        if !self.args.is_empty() {
            let args: Map<String, Value> = self
                .args
                .iter()
                .map(|(name, arg)| {
                    let value = match arg {
                        Arg::Text(text) => json!(text),
                        Arg::Number(number) => number.clone(),
                        Arg::Msg(msg) => msg.json(),
                    };
                    ((*name).to_owned(), value)
                })
                .collect();
            out.insert("args".into(), Value::Object(args));
        }
        Value::Object(out)
    }
}

impl fmt::Display for Msg {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

impl From<Msg> for Arg {
    fn from(msg: Msg) -> Self {
        Arg::Msg(msg)
    }
}

impl From<&Msg> for Arg {
    fn from(msg: &Msg) -> Self {
        Arg::Msg(msg.clone())
    }
}

macro_rules! text_arg {
    ($($kind:ty),*) => {$(
        impl From<$kind> for Arg {
            fn from(text: $kind) -> Self {
                Arg::Text(text.to_string())
            }
        }
    )*};
}
text_arg!(&str, String, &String, &&str, char);

macro_rules! number_arg {
    ($($kind:ty),*) => {$(
        impl From<$kind> for Arg {
            fn from(number: $kind) -> Self {
                Arg::Number(json!(number))
            }
        }
        impl From<&$kind> for Arg {
            fn from(number: &$kind) -> Self {
                Arg::Number(json!(*number))
            }
        }
    )*};
}
number_arg!(usize, u8, u16, u32, u64, i32, i64);

/// `tr!("audit.system.eol.title", "{pretty} no longer gets security updates", pretty = name)`:
/// a message with its id, English template and named values (every placeholder is named, so a
/// translation can put them in any order).
macro_rules! tr {
    // Every value is evaluated before any is bound, so `count = list.len()` cannot shadow
    // `list` for a later value.
    ($key:literal, $text:literal $(, $name:ident = $value:expr)* $(,)?) => {
        match ($($value,)*) {
            ($($name,)*) => $crate::msg::Msg::new($key, format!($text $(, $name = $name)*), vec![$((stringify!($name), $crate::msg::Arg::from($name))),*]),
        }
    };
}
pub(crate) use tr;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_message_keeps_its_id_values_and_english_text() {
        let why = tr!("test.why", "can read password hashes");
        let msg = tr!("test.group", "Members of {group} {why}.", group = "shadow", why = why);
        assert_eq!(msg.text(), "Members of shadow can read password hashes.");
        assert_eq!(msg.json(), json!({ "key": "test.group", "text": "Members of shadow can read password hashes.", "args": { "group": "shadow", "why": { "key": "test.why", "text": "can read password hashes" } } }));
        assert_eq!(Msg::raw("sudo reboot").json(), json!({ "text": "sudo reboot" }));
        assert_eq!(tr!("test.count", "{count} keys", count = 3usize).json()["args"]["count"], json!(3));
    }
}
