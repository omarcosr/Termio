//! The part of V8's structured-clone format an IndexedDB record uses: objects, arrays, strings and
//! numbers. Chromium serialises every object store value with it, so a record cannot be read any
//! other way; the tags below are the ones a host list is built from.

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(f64),
    Text(String),
    Bytes(Vec<u8>),
    List(Vec<Value>),
    Object(Vec<(String, Value)>),
}

impl Value {
    pub fn get(&self, name: &str) -> Option<&Value> {
        match self {
            Value::Object(fields) => fields.iter().find(|(key, _)| key == name).map(|(_, value)| value),
            _ => None,
        }
    }

    pub fn text(&self) -> Option<&str> {
        match self {
            Value::Text(text) => Some(text),
            _ => None,
        }
    }

    pub fn number(&self) -> Option<f64> {
        match self {
            Value::Number(number) => Some(*number),
            _ => None,
        }
    }
}

const PADDING: u8 = 0x00;
const VERSION: u8 = 0xff;
const UNDEFINED: u8 = b'_';
const HOLE: u8 = b'-';
const NULL: u8 = b'0';
const TRUE: u8 = b'T';
const FALSE: u8 = b'F';
const INT32: u8 = b'I';
const UINT32: u8 = b'U';
const DOUBLE: u8 = b'N';
const DATE: u8 = b'D';
const ONE_BYTE: u8 = b'"';
const UTF8: u8 = b'S';
const TWO_BYTE: u8 = b'c';
const OBJECT: u8 = b'o';
const END_OBJECT: u8 = b'{';
const DENSE: u8 = b'A';
const END_DENSE: u8 = b'$';
const SPARSE: u8 = b'a';
const END_SPARSE: u8 = b'@';
const MAP: u8 = b';';
const END_MAP: u8 = b':';
const SET: u8 = b'\'';
const END_SET: u8 = b',';
const REFERENCE: u8 = b'^';
const BUFFER: u8 = b'B';

pub struct Decoder<'a> {
    data: &'a [u8],
    at: usize,
    objects: Vec<Value>,
}

impl<'a> Decoder<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, at: 0, objects: Vec::new() }
    }

    /// The record's value, if the whole of it can be read.
    pub fn read(mut self) -> Option<Value> {
        self.value()
    }

    fn byte(&mut self) -> Option<u8> {
        let byte = *self.data.get(self.at)?;
        self.at += 1;
        Some(byte)
    }

    fn peek(&mut self) -> Option<u8> {
        let at = self.at;
        let byte = self.byte();
        self.at = at;
        byte
    }

    fn bytes(&mut self, length: usize) -> Option<&'a [u8]> {
        let bytes = self.data.get(self.at..self.at + length)?;
        self.at += length;
        Some(bytes)
    }

    fn varint(&mut self) -> Option<u64> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = self.byte()?;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Some(value);
            }
        }
        None
    }

    fn length(&mut self) -> Option<usize> {
        usize::try_from(self.varint()?).ok()
    }

    fn value(&mut self) -> Option<Value> {
        loop {
            match self.byte()? {
                PADDING => continue,
                VERSION => {
                    self.varint()?;
                }
                UNDEFINED | HOLE | NULL => return Some(Value::Null),
                TRUE => return Some(Value::Bool(true)),
                FALSE => return Some(Value::Bool(false)),
                INT32 => {
                    let raw = self.varint()?;
                    let value = ((raw >> 1) as i64) ^ -((raw & 1) as i64);
                    return Some(Value::Number(value as f64));
                }
                UINT32 => return Some(Value::Number(self.varint()? as f64)),
                DOUBLE | DATE => {
                    let bytes = self.bytes(8)?;
                    return Some(Value::Number(f64::from_le_bytes(bytes.try_into().ok()?)));
                }
                ONE_BYTE => {
                    let length = self.length()?;
                    let bytes = self.bytes(length)?;
                    return Some(Value::Text(bytes.iter().map(|byte| char::from(*byte)).collect()));
                }
                UTF8 => {
                    let length = self.length()?;
                    let bytes = self.bytes(length)?;
                    return Some(Value::Text(String::from_utf8_lossy(bytes).into_owned()));
                }
                TWO_BYTE => {
                    let length = self.length()?;
                    let bytes = self.bytes(length.checked_mul(2)?)?;
                    let units: Vec<u16> = bytes.chunks(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
                    return Some(Value::Text(String::from_utf16_lossy(&units)));
                }
                OBJECT => return self.object(),
                DENSE => return self.dense(),
                SPARSE => return self.sparse(),
                MAP => return self.map(),
                SET => return self.set(),
                REFERENCE => {
                    let index = self.length()?;
                    return self.objects.get(index).cloned();
                }
                BUFFER => {
                    let length = self.length()?;
                    return Some(Value::Bytes(self.bytes(length)?.to_vec()));
                }
                _ => return None,
            }
        }
    }

    /// A key as text: V8 writes property names as strings, but a number is possible.
    fn key(&mut self) -> Option<String> {
        match self.value()? {
            Value::Text(text) => Some(text),
            Value::Number(number) => Some(if number.fract() == 0.0 { format!("{}", number as i64) } else { format!("{number}") }),
            _ => None,
        }
    }

    /// The properties written before an end tag, then the property count V8 states.
    fn properties(&mut self, end: u8) -> Option<Vec<(String, Value)>> {
        let mut fields = Vec::new();
        while self.peek()? != end {
            let key = self.key()?;
            let value = self.value()?;
            fields.push((key, value));
        }
        self.byte()?;
        Some(fields)
    }

    fn remember(&mut self) -> usize {
        self.objects.push(Value::Null);
        self.objects.len() - 1
    }

    fn object(&mut self) -> Option<Value> {
        let slot = self.remember();
        let fields = self.properties(END_OBJECT)?;
        self.varint()?;
        let value = Value::Object(fields);
        self.objects[slot] = value.clone();
        Some(value)
    }

    fn dense(&mut self) -> Option<Value> {
        let slot = self.remember();
        let length = self.length()?;
        let mut items = Vec::with_capacity(length);
        for _ in 0..length {
            items.push(self.value()?);
        }
        for (key, value) in self.properties(END_DENSE)? {
            if let Ok(index) = key.parse::<usize>()
                && let Some(item) = items.get_mut(index)
            {
                *item = value;
            }
        }
        self.varint()?;
        self.varint()?;
        let value = Value::List(items);
        self.objects[slot] = value.clone();
        Some(value)
    }

    fn sparse(&mut self) -> Option<Value> {
        let slot = self.remember();
        let length = self.length()?;
        let mut items = vec![Value::Null; length];
        for (key, value) in self.properties(END_SPARSE)? {
            if let Ok(index) = key.parse::<usize>()
                && let Some(item) = items.get_mut(index)
            {
                *item = value;
            }
        }
        self.varint()?;
        self.varint()?;
        let value = Value::List(items);
        self.objects[slot] = value.clone();
        Some(value)
    }

    fn map(&mut self) -> Option<Value> {
        let slot = self.remember();
        let mut fields = Vec::new();
        while self.peek()? != END_MAP {
            let key = self.key()?;
            let value = self.value()?;
            fields.push((key, value));
        }
        self.byte()?;
        self.varint()?;
        let value = Value::Object(fields);
        self.objects[slot] = value.clone();
        Some(value)
    }

    fn set(&mut self) -> Option<Value> {
        let slot = self.remember();
        let mut items = Vec::new();
        while self.peek()? != END_SET {
            items.push(self.value()?);
        }
        self.byte()?;
        self.varint()?;
        let value = Value::List(items);
        self.objects[slot] = value.clone();
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_object_of_strings_and_numbers_reads_back() {
        // ff 10, o, "id" I 2c (zigzag 22), "name" "\x04" "host", { , count 2
        let mut bytes = vec![VERSION, 0x10, OBJECT, ONE_BYTE, 2, b'i', b'd', INT32, 22];
        bytes.extend([ONE_BYTE, 4, b'n', b'a', b'm', b'e', ONE_BYTE, 4, b'h', b'o', b's', b't', END_OBJECT, 2]);
        let value = Decoder::new(&bytes).read().unwrap();
        assert_eq!(value.get("id").and_then(Value::number), Some(11.0));
        assert_eq!(value.get("name").and_then(Value::text), Some("host"));
    }

    #[test]
    fn padding_before_a_value_is_skipped() {
        let bytes = [PADDING, PADDING, VERSION, 0x10, TRUE];
        assert_eq!(Decoder::new(&bytes).read(), Some(Value::Bool(true)));
    }
}
