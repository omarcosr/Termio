//! `~/.ssh/config` as hosts to import: `Host` blocks with HostName, User, Port, IdentityFile and
//! ProxyJump. Patterns (`*`, `?`, `!`) are defaults for other hosts, not hosts, and are skipped.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub address: String,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub identity_file: Option<String>,
    pub jump: Option<String>,
}

fn home() -> Option<String> {
    std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")).ok()
}

fn expand(path: &str) -> String {
    match (path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")), home()) {
        (Some(rest), Some(home)) => format!("{home}/{rest}"),
        _ => path.to_owned(),
    }
}

/// The config file of this user, if there is one.
pub fn default_path() -> Option<std::path::PathBuf> {
    home().map(|home| std::path::Path::new(&home).join(".ssh").join("config"))
}

pub fn parse(text: &str) -> Vec<Entry> {
    let mut entries: Vec<Entry> = Vec::new();
    // Indexes of the entries the current `Host` line opened (one line may name several).
    let mut open: Vec<usize> = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = match line.split_once(|ch: char| ch.is_whitespace() || ch == '=') {
            Some((key, value)) => (key.trim().to_ascii_lowercase(), value.trim().trim_start_matches('=').trim().trim_matches('"').to_owned()),
            None => continue,
        };
        match key.as_str() {
            "host" => {
                open.clear();
                for name in value.split_whitespace() {
                    if name.contains(['*', '?', '!']) {
                        continue;
                    }
                    entries.push(Entry { name: name.to_owned(), address: name.to_owned(), user: None, port: None, identity_file: None, jump: None });
                    open.push(entries.len() - 1);
                }
            }
            "match" => open.clear(),
            _ => {
                for &index in &open {
                    let entry = &mut entries[index];
                    match key.as_str() {
                        "hostname" => entry.address = value.clone(),
                        "user" => entry.user = Some(value.clone()),
                        "port" => entry.port = value.parse().ok(),
                        "identityfile" if entry.identity_file.is_none() => entry.identity_file = Some(expand(&value)),
                        "proxyjump" if value != "none" => entry.jump = Some(value.split(',').next().unwrap_or(&value).split('@').next_back().unwrap_or(&value).split(':').next().unwrap_or(&value).to_owned()),
                        _ => {}
                    }
                }
            }
        }
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_take_their_options_and_patterns_are_skipped() {
        let entries = parse("Host *\n  User nobody\n\nHost web prod\n  HostName 10.0.0.5\n  User deploy\n  Port 2222\n  IdentityFile /keys/id\n\nHost db\n  HostName db.internal\n  ProxyJump admin@web:22\n");
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0], Entry { name: "web".into(), address: "10.0.0.5".into(), user: Some("deploy".into()), port: Some(2222), identity_file: Some("/keys/id".into()), jump: None });
        assert_eq!(entries[1].address, "10.0.0.5");
        assert_eq!(entries[2].jump.as_deref(), Some("web"));
        assert_eq!(entries[2].user, None);
    }
}
