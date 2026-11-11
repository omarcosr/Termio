//! Hosts saved by other programs, as hosts to import: OpenSSH's `~/.ssh/config`, FileZilla's
//! Site Manager (`sitemanager.xml`, its SFTP sites). Passwords found on the way stay in the core
//! until the import saves them; Termius' own data, which has no export, is read in [`crate::termius`].

use crate::sshconfig;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Host {
    pub name: String,
    pub address: String,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub identity_file: Option<String>,
    pub jump: Option<String>,
    pub group: Option<String>,
    pub password: Option<String>,
    /// A private key that lives in another program's data rather than in a file.
    pub private_key: Option<String>,
    pub passphrase: Option<String>,
    pub key_name: Option<String>,
}

/// What a scan found, and how many entries it left out because they are not SSH.
#[derive(Debug, Default)]
pub struct Scan {
    pub source: &'static str,
    pub hosts: Vec<Host>,
    pub skipped: usize,
}

fn home() -> Option<PathBuf> {
    std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")).ok().map(PathBuf::from)
}

/// FileZilla's Site Manager file of this user, if there is one.
pub fn filezilla_path() -> Option<PathBuf> {
    let windows = std::env::var("APPDATA").ok().map(|base| PathBuf::from(base).join("FileZilla").join("sitemanager.xml"));
    let xdg = std::env::var("XDG_CONFIG_HOME").ok().map(|base| PathBuf::from(base).join("filezilla").join("sitemanager.xml"));
    let config = home().map(|home| home.join(".config").join("filezilla").join("sitemanager.xml"));
    let legacy = home().map(|home| home.join(".filezilla").join("sitemanager.xml"));
    [windows, xdg, config, legacy].into_iter().flatten().find(|path| path.is_file())
}

pub fn from_ssh_config(text: &str) -> Scan {
    let hosts = sshconfig::parse(text)
        .into_iter()
        .map(|entry| Host { name: entry.name, address: entry.address, user: entry.user, port: entry.port, identity_file: entry.identity_file, jump: entry.jump, group: None, password: None, private_key: None, passphrase: None, key_name: None })
        .collect();
    Scan { source: "ssh config", hosts, skipped: 0 }
}

/// Reads a FileZilla `sitemanager.xml`.
pub fn from_filezilla_file(path: &Path) -> Result<Scan, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let text = String::from_utf8_lossy(&bytes);
    let text = text.trim_start_matches('\u{feff}');
    if !text.contains("<FileZilla3") {
        return Err(format!("{} is not a FileZilla sitemanager.xml", path.display()));
    }
    Ok(from_filezilla(text))
}

// --- FileZilla -----------------------------------------------------------------------------

fn unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('&') {
        out.push_str(&rest[..start]);
        let tail = &rest[start..];
        let Some(end) = tail.find(';').filter(|end| *end <= 10) else {
            out.push('&');
            rest = &tail[1..];
            continue;
        };
        let entity = &tail[1..end];
        let decoded = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => entity
                .strip_prefix("#x")
                .and_then(|hex| u32::from_str_radix(hex, 16).ok())
                .or_else(|| entity.strip_prefix('#').and_then(|dec| dec.parse().ok()))
                .and_then(char::from_u32),
        };
        match decoded {
            Some(ch) => {
                out.push(ch);
                rest = &tail[end + 1..];
            }
            None => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

pub(crate) fn unbase64(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut buffer, mut bits) = (0u32, 0u32);
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            b' ' | b'\n' | b'\r' | b'\t' => continue,
            _ => return None,
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

/// The sites of a `sitemanager.xml`. Only SFTP sites (protocol 1) are SSH servers; folders become
/// groups (`Work/Clients`). A password FileZilla encrypted with its master password is left out.
pub fn from_filezilla(xml: &str) -> Scan {
    let mut scan = Scan { source: "FileZilla", ..Scan::default() };
    let mut folders: Vec<String> = Vec::new();
    // Inside a <Folder>, the text before its first child element is the folder's name.
    let mut naming_folder = false;
    // The fields of the <Server> being read: (element, text, attributes).
    let mut server: Option<Vec<(String, String, String)>> = None;
    let mut field: Option<(String, String, String)> = None;
    let mut rest = xml;
    while let Some(open) = rest.find('<') {
        let text = &rest[..open];
        if naming_folder && let Some(name) = folders.last_mut() {
            name.push_str(text);
        }
        if let Some((_, value, _)) = field.as_mut() {
            value.push_str(text);
        }
        let Some(close) = rest[open..].find('>') else { break };
        let tag = &rest[open + 1..open + close];
        rest = &rest[open + close + 1..];
        if tag.starts_with('?') || tag.starts_with('!') {
            continue;
        }
        if naming_folder {
            naming_folder = false;
            if let Some(last) = folders.last_mut() {
                *last = unescape(last.trim());
            }
        }
        let closing = tag.starts_with('/');
        let self_closing = tag.ends_with('/');
        let body = tag.trim_start_matches('/').trim_end_matches('/');
        let name = body.split_whitespace().next().unwrap_or("");
        let attributes = &body[name.len()..];
        match (name, closing) {
            ("Folder", false) if server.is_none() && !self_closing => {
                folders.push(String::new());
                naming_folder = true;
            }
            ("Folder", true) if server.is_none() => {
                folders.pop();
            }
            ("Server", false) if !self_closing => server = Some(Vec::new()),
            ("Server", true) => {
                if let Some(fields) = server.take() {
                    match filezilla_site(&fields, &folders) {
                        Some(host) => scan.hosts.push(host),
                        None => scan.skipped += 1,
                    }
                }
            }
            (_, false) if server.is_some() && !self_closing => field = Some((name.to_owned(), String::new(), attributes.to_owned())),
            (_, true) if server.is_some() => {
                if let (Some((key, value, attributes)), Some(fields)) = (field.take(), server.as_mut())
                    && key == name
                {
                    fields.push((key, unescape(value.trim()), attributes));
                }
            }
            _ => {}
        }
    }
    scan
}

fn filezilla_site(fields: &[(String, String, String)], folders: &[String]) -> Option<Host> {
    let get = |key: &str| fields.iter().find(|(name, _, _)| name == key).map(|(_, value, attributes)| (value.as_str(), attributes.as_str()));
    if get("Protocol").map(|(value, _)| value) != Some("1") {
        return None;
    }
    let address = get("Host")?.0.to_owned();
    if address.is_empty() {
        return None;
    }
    let port = get("Port").and_then(|(value, _)| value.parse().ok());
    let user = get("User").map(|(value, _)| value.to_owned()).filter(|user| !user.is_empty());
    let password = get("Pass").and_then(|(value, attributes)| {
        if attributes.contains("crypt") {
            None
        } else if attributes.contains("base64") {
            unbase64(value).and_then(|bytes| String::from_utf8(bytes).ok())
        } else {
            Some(value.to_owned())
        }
    });
    let identity_file = get("Keyfile").map(|(value, _)| value.to_owned()).filter(|file| !file.is_empty());
    let name = get("Name").map(|(value, _)| value.to_owned()).filter(|name| !name.is_empty()).unwrap_or_else(|| address.clone());
    let folders: Vec<&str> = folders.iter().map(String::as_str).filter(|folder| !folder.is_empty()).collect();
    Some(Host {
        name,
        address,
        user,
        port,
        identity_file,
        jump: None,
        group: if folders.is_empty() { None } else { Some(folders.join("/")) },
        password: password.filter(|password| !password.is_empty()),
        private_key: None,
        passphrase: None,
        key_name: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filezilla_sftp_sites_come_with_folder_and_password() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<FileZilla3 version="3.66.0">
  <Servers>
    <Folder expanded="1">Work
      <Server>
        <Host>10.0.0.5</Host><Port>2222</Port><Protocol>1</Protocol><Type>0</Type>
        <User>deploy</User><Pass encoding="base64">aHVudGVyMg==</Pass><Logontype>1</Logontype>
        <Name>Prod &amp; co</Name>
      </Server>
      <Server><Host>ftp.example.com</Host><Port>21</Port><Protocol>0</Protocol><Name>Old FTP</Name></Server>
    </Folder>
    <Server><Host>box</Host><Port>22</Port><Protocol>1</Protocol><User>me</User><Pass encoding="crypt" pubkey="x">zzz</Pass><Keyfile>C:\keys\id</Keyfile><Name>Box</Name></Server>
  </Servers>
</FileZilla3>"#;
        let scan = from_filezilla(xml);
        assert_eq!(scan.skipped, 1);
        assert_eq!(scan.hosts.len(), 2);
        assert_eq!(scan.hosts[0], Host { name: "Prod & co".into(), address: "10.0.0.5".into(), user: Some("deploy".into()), port: Some(2222), identity_file: None, jump: None, group: Some("Work".into()), password: Some("hunter2".into()), private_key: None, passphrase: None, key_name: None });
        assert_eq!(scan.hosts[1].group, None);
        assert_eq!(scan.hosts[1].password, None, "a master-password-encrypted password is not readable");
        assert_eq!(scan.hosts[1].identity_file.as_deref(), Some("C:\\keys\\id"));
    }
}
