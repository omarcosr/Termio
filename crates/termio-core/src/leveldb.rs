//! A read-only reader for the LevelDB Chromium keeps an IndexedDB in, so a host list saved by an
//! Electron app can be read without the app. Chromium writes plain LevelDB: sorted string tables
//! (.ldb) plus a write-ahead log (.log), both hiding keys the modules above decode further.

use std::collections::HashMap;
use std::path::Path;

const FOOTER: usize = 48;
const MAGIC: u64 = 0xdb47_7524_8b80_fb57;
const LOG_BLOCK: usize = 32 * 1024;

fn varint(data: &[u8], at: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = *data.get(*at)?;
        *at += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

fn fixed(data: &[u8], at: &mut usize, width: usize) -> Option<u64> {
    let bytes = data.get(*at..*at + width)?;
    *at += width;
    Some(bytes.iter().rev().fold(0u64, |value, byte| (value << 8) | u64::from(*byte)))
}

#[derive(Clone, Copy)]
struct Handle {
    offset: usize,
    size: usize,
}

fn handle(data: &[u8], at: &mut usize) -> Option<Handle> {
    let offset = usize::try_from(varint(data, at)?).ok()?;
    let size = usize::try_from(varint(data, at)?).ok()?;
    Some(Handle { offset, size })
}

/// The contents of a block, decompressed. Its five-byte trailer (compression kind, checksum) sits
/// in the file right after it.
fn block(file: &[u8], handle: Handle) -> Option<Vec<u8>> {
    let end = handle.offset.checked_add(handle.size)?;
    let contents = file.get(handle.offset..end)?;
    match *file.get(end)? {
        0 => Some(contents.to_vec()),
        1 => snap::raw::Decoder::new().decompress_vec(contents).ok(),
        _ => None,
    }
}

/// The prefix-compressed key/value pairs of a block: shared length, unshared length, value length,
/// the key tail, the value. A restart array closes the block.
fn entries(data: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    let Some(tail) = data.len().checked_sub(4) else { return out };
    let restarts = (u32::from_le_bytes(data[tail..].try_into().unwrap_or([0; 4])) as usize).saturating_mul(4) + 4;
    let Some(limit) = data.len().checked_sub(restarts) else { return out };
    let mut key: Vec<u8> = Vec::new();
    let mut at = 0;
    while at < limit {
        let (Some(shared), Some(unshared), Some(length)) = (varint(data, &mut at), varint(data, &mut at), varint(data, &mut at)) else { break };
        let (shared, unshared, length) = (shared as usize, unshared as usize, length as usize);
        let (Some(tail), Some(value)) = (data.get(at..at + unshared), data.get(at..at + unshared + length)) else { break };
        if shared > key.len() {
            break;
        }
        key.truncate(shared);
        key.extend_from_slice(tail);
        out.push((key.clone(), value[unshared..].to_vec()));
        at += unshared + length;
    }
    out
}

fn table(file: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    let Some(footer) = file.len().checked_sub(FOOTER).and_then(|at| file.get(at..)) else { return out };
    let mut magic = 40;
    if fixed(footer, &mut magic, 8) != Some(MAGIC) {
        return out;
    }
    let mut at = 8;
    let Some(index) = handle(footer, &mut at).and_then(|index| block(file, index)) else { return out };
    for (_, value) in entries(&index) {
        let mut at = 0;
        let Some(data) = handle(&value, &mut at).and_then(|data| block(file, data)) else { continue };
        out.extend(entries(&data));
    }
    out
}

/// The write-ahead log: 32 KiB blocks of records with a seven-byte header each. A record longer
/// than the space left is split across blocks, its pieces marked first, middle and last.
fn log(file: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut partial: Option<Vec<u8>> = None;
    let mut at = 0;
    while at + 7 <= file.len() {
        let left = LOG_BLOCK - at % LOG_BLOCK;
        if left < 7 {
            at += left;
            continue;
        }
        let length = u16::from_le_bytes([file[at + 4], file[at + 5]]) as usize;
        let kind = file[at + 6];
        let Some(data) = file.get(at + 7..at + 7 + length) else { break };
        match kind {
            1 => out.push(data.to_vec()),
            2 => partial = Some(data.to_vec()),
            3 => partial.get_or_insert_with(Vec::new).extend_from_slice(data),
            4 => {
                let mut record = partial.take().unwrap_or_default();
                record.extend_from_slice(data);
                out.push(record);
            }
            _ => partial = None,
        }
        at += 7 + length;
    }
    out
}

/// One write batch: the sequence number of its first entry, how many it holds, then the entries as
/// kind, key length, key and, for a write, value length and value.
fn batch(record: &[u8]) -> Vec<(u64, u8, Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    let mut at = 0;
    let (Some(sequence), Some(count)) = (fixed(record, &mut at, 8), fixed(record, &mut at, 4)) else { return out };
    for index in 0..count {
        let Some(kind) = record.get(at).copied() else { break };
        at += 1;
        let Some(length) = varint(record, &mut at).and_then(|length| usize::try_from(length).ok()) else { break };
        let Some(key) = record.get(at..at + length) else { break };
        at += length;
        let mut value = Vec::new();
        if kind == 1 {
            let Some(length) = varint(record, &mut at).and_then(|length| usize::try_from(length).ok()) else { break };
            let Some(bytes) = record.get(at..at + length) else { break };
            at += length;
            value = bytes.to_vec();
        }
        out.push((sequence + index, kind, key.to_vec(), value));
    }
    out
}

/// A key and the value the newest write gave it.
pub type Pair = (Vec<u8>, Vec<u8>);

/// Every live key of the database in `dir`, its newest generation winning. A store keeps what
/// earlier sessions wrote — one host can appear five times — so a key reads as its highest
/// sequence number, and a key deleted by a later batch is gone.
pub fn read(dir: &Path) -> Result<Vec<Pair>, String> {
    let listing = std::fs::read_dir(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    let mut best: HashMap<Vec<u8>, (u64, u8, Vec<u8>)> = HashMap::new();
    let mut keep = |sequence: u64, kind: u8, key: Vec<u8>, value: Vec<u8>| {
        if best.get(&key).is_none_or(|(seen, _, _)| sequence >= *seen) {
            best.insert(key, (sequence, kind, value));
        }
    };
    let mut files = 0;
    for path in listing.flatten().map(|entry| entry.path()) {
        let name = path.file_name().unwrap_or_default().to_string_lossy().to_ascii_lowercase();
        let Ok(file) = std::fs::read(&path) else { continue };
        if name.ends_with(".log") {
            files += 1;
            for record in log(&file) {
                for (sequence, kind, key, value) in batch(&record) {
                    keep(sequence, kind, key, value);
                }
            }
        } else if name.ends_with(".ldb") || name.ends_with(".sst") {
            files += 1;
            for (key, value) in table(&file) {
                if key.len() < 8 {
                    continue;
                }
                let (user, trailer) = key.split_at(key.len() - 8);
                let trailer = u64::from_le_bytes(trailer.try_into().unwrap_or([0; 8]));
                keep(trailer >> 8, trailer as u8, user.to_vec(), value);
            }
        }
    }
    if files == 0 {
        return Err(format!("{} holds no LevelDB files", dir.display()));
    }
    let mut live: Vec<Pair> = best.into_iter().filter(|(_, (_, kind, _))| *kind == 1).map(|(key, (_, _, value))| (key, value)).collect();
    live.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(live)
}
