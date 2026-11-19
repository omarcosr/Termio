//! Security audit of a server with nothing installed on it.
//!
//! The checks the user enabled become one POSIX shell script fed to `sh -s` over SSH. It only
//! reads: no file is written, no package installed, password hashes and file contents never
//! leave the server (only their kind, counts and paths do). Each check prints under an `@@name`
//! line and the output is judged here. Optionally the installed package versions are matched
//! against OSV.dev (names and versions leave this device, nothing else) and the ports the server
//! listens on are tried from this device.

use serde_json::{Value, json};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering as Atomic};
use std::time::Duration;

/// The groups of checks the user turns on and off, in the order they run.
pub const CATEGORIES: &[&str] = &["system", "packages", "ssh", "accounts", "files", "network", "services", "containers", "logs", "secrets"];

/// Off unless asked for: it lists where keys and credentials lie on the server.
const OFF_BY_DEFAULT: &[&str] = &["secrets"];

/// What one audit runs, from the `audit` settings record.
pub struct Options {
    pub categories: HashSet<&'static str>,
    /// Privileged reads through `sudo -n` (passwordless sudo only: never prompts).
    pub sudo: bool,
    /// Match package versions against OSV.dev.
    pub cve: bool,
    /// Try the ports the server exposes from this device.
    pub probe: bool,
}

impl Options {
    pub fn from_settings(settings: &Value) -> Result<Self, String> {
        if settings["enabled"].as_bool() != Some(true) {
            return Err("the security audit is turned off: enable it in Settings > Security".into());
        }
        let categories: HashSet<&'static str> = CATEGORIES.iter().copied().filter(|name| settings["categories"][*name].as_bool().unwrap_or(!OFF_BY_DEFAULT.contains(name))).collect();
        if categories.is_empty() {
            return Err("every audit check is turned off in Settings > Security".into());
        }
        Ok(Self { categories, sudo: settings["sudo"].as_bool() == Some(true), cve: settings["cve"].as_bool() == Some(true), probe: settings["probe"].as_bool() == Some(true) })
    }

    fn has(&self, category: &str) -> bool {
        self.categories.contains(category)
    }
}

// --- The script ---------------------------------------------------------------------------------

const PRELUDE: &str = r#"export LC_ALL=C
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH
S() { printf '\n@@%s\n' "$1"; }
has() { command -v "$1" >/dev/null 2>&1; }
T() { t=$1; shift; if has timeout; then timeout "$t" "$@"; else "$@"; fi; }
SUDO=""
ROOT=0
[ "$(id -u)" = 0 ] && ROOT=1
"#;

const SUDO: &str = r#"if [ "$ROOT" = 0 ] && has sudo && sudo -n true 2>/dev/null; then SUDO="sudo -n"; ROOT=1; fi
"#;

const BASE: &str = r#"S base.meta
echo "uid=$(id -u)"
echo "user=$(id -un 2>/dev/null)"
echo "root=$ROOT"
echo "sudo=${SUDO:+yes}"
echo "host=$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null)"
echo "now=$(date +%s)"
S base.os
cat /etc/os-release 2>/dev/null
S base.uname
uname -r 2>/dev/null
uname -m 2>/dev/null
S base.container
[ -f /.dockerenv ] && echo docker
grep -qa 'container=' /proc/1/environ 2>/dev/null && echo container
has systemd-detect-virt && systemd-detect-virt 2>/dev/null
"#;

const SYSTEM: &str = r#"S system.reboot
[ -f /var/run/reboot-required ] && echo required && cat /var/run/reboot-required.pkgs 2>/dev/null
[ "$ROOT" = 1 ] && has needs-restarting && { $SUDO needs-restarting -r >/dev/null 2>&1 || echo "needs-restarting: reboot required"; }
S system.kernels
ls /lib/modules 2>/dev/null
S system.uptime
cut -d' ' -f1 /proc/uptime 2>/dev/null
S system.cpu
for f in /sys/devices/system/cpu/vulnerabilities/*; do [ -f "$f" ] && echo "${f##*/}: $(cat "$f" 2>/dev/null)"; done
S system.sysctl
for k in kernel.randomize_va_space kernel.kptr_restrict kernel.dmesg_restrict kernel.yama.ptrace_scope kernel.unprivileged_bpf_disabled fs.protected_symlinks fs.protected_hardlinks fs.protected_fifos fs.protected_regular fs.suid_dumpable net.ipv4.ip_forward net.ipv4.conf.all.accept_redirects net.ipv6.conf.all.accept_redirects net.ipv4.conf.all.send_redirects net.ipv4.conf.all.accept_source_route net.ipv4.tcp_syncookies net.ipv4.conf.all.rp_filter; do v=$(sysctl -n "$k" 2>/dev/null) && echo "$k=$v"; done
S system.mac
has getenforce && echo "selinux=$(getenforce 2>/dev/null)"
[ -r /sys/module/apparmor/parameters/enabled ] && echo "apparmor=$(cat /sys/module/apparmor/parameters/enabled)"
S system.time
has timedatectl && echo "ntp=$(timedatectl show -p NTPSynchronized --value 2>/dev/null)"
S system.mounts
awk '$2=="/tmp"||$2=="/dev/shm"||$2=="/var/tmp" {print $2" "$4}' /proc/mounts 2>/dev/null
"#;

const INVENTORY: &str = r#"S packages.dpkg
has dpkg-query && dpkg-query -W -f='${db:Status-Abbrev}\t${Package}\t${Version}\t${source:Package}\t${source:Version}\n' 2>/dev/null | awk -F'\t' '$1 ~ /^ii/ {print $2"\t"$3"\t"$4"\t"$5}'
S packages.rpm
has rpm && rpm -qa --qf '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n' 2>/dev/null
S packages.apk
has apk && apk list -I 2>/dev/null
"#;

const PACKAGES: &str = r#"S packages.pending
if has apt-get; then T 120 apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | grep '^Inst '; elif has dnf; then T 180 dnf -q -C check-update 2>/dev/null | grep -E '^[A-Za-z0-9_.+-]+\.[a-z0-9_]+ '; elif has yum; then T 180 yum -q -C check-update 2>/dev/null | grep -E '^[A-Za-z0-9_.+-]+\.[a-z0-9_]+ '; elif has apk; then apk version -l '<' 2>/dev/null | grep -v '^Installed'; fi
S packages.security
if has dnf; then T 180 dnf -q -C updateinfo list --security 2>/dev/null; elif has yum; then T 180 yum -q -C updateinfo list security 2>/dev/null; fi
S packages.advisories
if has dnf && dnf --version 2>/dev/null | grep -q '^dnf5'; then T 180 $SUDO dnf -q -C advisory list --security --with-cve 2>/dev/null; elif has dnf; then T 180 $SUDO dnf -q -C updateinfo list --security --with-cve 2>/dev/null; elif has yum; then T 180 $SUDO yum -q -C updateinfo list cves 2>/dev/null; elif has zypper; then T 180 $SUDO zypper -q --non-interactive --no-refresh list-patches --cve --category security 2>/dev/null; fi
S packages.refreshed
for f in /var/lib/apt/periodic/update-success-stamp /var/lib/apt/lists/partial /var/cache/dnf /var/cache/yum /var/cache/apk; do [ -e "$f" ] && echo "$(stat -c %Y "$f" 2>/dev/null) $f"; done
S packages.auto
cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null
has systemctl && echo "dnf-automatic=$(systemctl is-enabled dnf-automatic.timer dnf-automatic-install.timer 2>/dev/null | grep -c enabled)"
"#;

const SSH: &str = r#"S ssh.effective
$SUDO sshd -T 2>/dev/null
S ssh.config
cat /etc/ssh/sshd_config.d/*.conf 2>/dev/null
cat /etc/ssh/sshd_config 2>/dev/null
S ssh.version
ssh -V 2>&1 | head -1
S ssh.hostkeys
ls -l /etc/ssh/ssh_host_*_key 2>/dev/null
"#;

const ACCOUNTS: &str = r#"S accounts.passwd
cat /etc/passwd 2>/dev/null
S accounts.perms
ls -l /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers 2>/dev/null
ls -ld /root /etc/sudoers.d 2>/dev/null
S accounts.shadow
$SUDO cat /etc/shadow 2>/dev/null | awk -F: '{ s = $2; if (s == "") t = "empty"; else if (s ~ /^[!*]/) t = "locked"; else if (s ~ /^\$1\$/) t = "md5"; else if (s ~ /^\$5\$/) t = "sha256"; else if (s ~ /^\$6\$/) t = "sha512"; else if (length(s) == 13) t = "des"; else t = "strong"; print $1 ":" t ":" $3 ":" $5 }'
S accounts.sudoers
$SUDO cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -vE '^[[:space:]]*(#|$)'
S accounts.self
sudo -n -l 2>/dev/null
S accounts.groups
for g in sudo wheel admin docker lxd libvirt disk shadow; do getent group "$g" 2>/dev/null || grep "^$g:" /etc/group 2>/dev/null; done
S accounts.keys
awk -F: '$7 !~ /(nologin|false|sync|halt|shutdown)$/ {print $1" "$6}' /etc/passwd 2>/dev/null | while read u h; do
  for f in "$h/.ssh/authorized_keys" "$h/.ssh/authorized_keys2"; do
    if $SUDO test -f "$f"; then
      echo "file $u $($SUDO stat -c '%a' "$f" 2>/dev/null) $f"
      $SUDO cat "$f" 2>/dev/null | awk -v u="$u" '!/^[ \t]*(#|$)/ { for (i = 1; i <= NF; i++) if ($i ~ /^(ssh-|ecdsa-|sk-)/) { print "key " u " " $i " " length($(i+1)) " " (i > 1 ? "options" : "-") " " $(i+2); break } }'
    fi
  done
done
S accounts.policy
grep -E '^[[:space:]]*(PASS_MAX_DAYS|PASS_MIN_LEN|ENCRYPT_METHOD|UMASK)' /etc/login.defs 2>/dev/null
"#;

const FILES: &str = r#"S files.suid
T 180 $SUDO find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -exec ls -ld {} + 2>/dev/null | head -500
S files.writable
T 180 $SUDO find /etc /usr /bin /sbin /opt /boot /root /var/www /srv -xdev -type f -perm -0002 2>/dev/null | head -200
S files.dirs
T 180 $SUDO find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | head -100
S files.unowned
T 180 $SUDO find / -xdev \( -nouser -o -nogroup \) 2>/dev/null | grep -vE '^/(proc|sys|dev|run)/' | head -100
S files.caps
has getcap && T 180 $SUDO getcap -r /usr /bin /sbin /opt /home 2>/dev/null | head -100
S files.homes
ls -ld /home/* /root 2>/dev/null
"#;

const NETWORK: &str = r#"S network.listen
if has ss; then $SUDO ss -H -tulpn 2>/dev/null || ss -tuln 2>/dev/null; elif has netstat; then $SUDO netstat -tulpn 2>/dev/null || netstat -tuln 2>/dev/null; fi
S network.firewall
has ufw && $SUDO ufw status 2>/dev/null
has firewall-cmd && echo "firewalld=$($SUDO firewall-cmd --state 2>/dev/null)"
has nft && $SUDO nft list ruleset 2>/dev/null | head -400
has iptables && $SUDO iptables -S 2>/dev/null | head -300
S network.interfaces
ip -br addr 2>/dev/null || ip addr 2>/dev/null | grep -E 'inet6? '
"#;

const SERVICES: &str = r#"S services.running
has systemctl && systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null | awk '{print $1}'
S services.failed
has systemctl && systemctl list-units --state=failed --no-legend --no-pager 2>/dev/null | sed 's/^[^a-zA-Z0-9]*//' | awk '{print $1}'
S services.versions
for c in "sudo -V" "openssl version" "nginx -v" "apache2 -v" "httpd -v" "php -v" "node --version" "python3 --version" "mysqld --version" "mariadbd --version" "postgres --version" "redis-server --version" "mongod --version" "docker --version" "containerd --version" "haproxy -v" "named -v" "exim -bV" "postconf mail_version" "java -version" "git --version" "curl --version"; do b=${c%% *}; has "$b" && echo "$b: $($c 2>&1 | head -1)"; done
S services.cron
grep -vE '^[[:space:]]*(#|$)' /etc/crontab 2>/dev/null
ls /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly 2>/dev/null
$SUDO ls /var/spool/cron/crontabs /var/spool/cron 2>/dev/null
S services.cronwritable
for f in /etc/crontab /etc/cron.d /etc/cron.d/* /etc/cron.daily/* /etc/cron.hourly/* /etc/cron.weekly/* /etc/cron.monthly/* /etc/rc.local; do [ -e "$f" ] && find "$f" -maxdepth 0 -perm -0002 2>/dev/null; done
S services.unitwritable
T 60 find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system -type f -perm -0002 2>/dev/null | head -50
S services.timers
has systemctl && systemctl list-timers --all --no-legend --no-pager 2>/dev/null | head -40
"#;

const CONTAINERS: &str = r#"S containers.sockets
ls -l /var/run/docker.sock /run/docker.sock /run/containerd/containerd.sock /run/podman/podman.sock 2>/dev/null
S containers.docker
if has docker; then D=docker; T 20 docker info >/dev/null 2>&1 || D="$SUDO docker"; for id in $(T 20 $D ps -q 2>/dev/null); do $D inspect --format '{{.Name}}|{{.Config.Image}}|{{.HostConfig.Privileged}}|{{.HostConfig.NetworkMode}}|{{.HostConfig.PidMode}}|{{range .Mounts}}{{.Source}}:{{.Destination}}:{{.RW}},{{end}}|{{.HostConfig.CapAdd}}|{{.Config.User}}|{{range $p, $b := .NetworkSettings.Ports}}{{range $b}}{{.HostIp}}:{{.HostPort}}->{{$p}} {{end}}{{end}}|{{.HostConfig.SecurityOpt}}' "$id" 2>/dev/null; done; fi
S containers.daemon
cat /etc/docker/daemon.json 2>/dev/null
S containers.images
has docker && { docker images --format '{{.Repository}}:{{.Tag}} {{.CreatedSince}}' 2>/dev/null || $SUDO docker images --format '{{.Repository}}:{{.Tag}} {{.CreatedSince}}' 2>/dev/null; } | head -50
"#;

const LOGS: &str = r#"S logs.failures
has journalctl && echo "journal $($SUDO journalctl -q --no-pager -S -7d _COMM=sshd 2>/dev/null | grep -cE 'Failed password|Invalid user|authentication failure')"
for f in /var/log/auth.log /var/log/secure; do [ -e "$f" ] && echo "file $($SUDO grep -cE 'sshd.*(Failed password|Invalid user)' "$f" 2>/dev/null) $f"; done
S logs.sources
{ has journalctl && $SUDO journalctl -q --no-pager -S -7d _COMM=sshd 2>/dev/null; $SUDO cat /var/log/auth.log /var/log/secure 2>/dev/null; } | grep -E 'Failed password|Invalid user' | grep -oE 'from [0-9a-fA-F.:]+' | sort | uniq -c | sort -rn | head -10
S logs.defenses
has systemctl && for s in fail2ban crowdsec auditd rsyslog syslog-ng; do echo "$s=$(systemctl is-active "$s" 2>/dev/null)"; done
S logs.logins
last -n 20 -w 2>/dev/null | grep -vE '^(wtmp|$)' | head -20
"#;

const SECRETS: &str = r#"S secrets.files
T 180 $SUDO find /home /root /var/www /srv /opt -xdev \( -name node_modules -o -name .cargo -o -name .rustup -o -name .git -o -name site-packages -o -name .npm -o -name .cache -o -name vendor -o -name tests -o -name testdata \) -prune -o -type f \( -name '.env' -o -name '*.pem' -o -name 'id_rsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' -o -name 'id_dsa' -o -name '*.key' -o -name '.git-credentials' -o -name '.pgpass' -o -name '.my.cnf' -o -name '.netrc' -o -name 'credentials' -o -name '*.kdbx' -o -name '*.p12' -o -name '*.pfx' \) -exec ls -ld {} + 2>/dev/null | head -300
S secrets.history
for h in /root /home/*; do for f in "$h/.bash_history" "$h/.zsh_history" "$h/.mysql_history" "$h/.psql_history"; do $SUDO test -f "$f" && echo "$($SUDO grep -ciE '(password|passwd|secret|token|api[_-]?key)[[:space:]]*[=:]|IDENTIFIED BY|sshpass' "$f" 2>/dev/null) $f"; done; done
S secrets.web
for d in /var/www /srv /usr/share/nginx/html; do [ -d "$d" ] && T 60 find "$d" -maxdepth 5 \( -name '.git' -o -name '.env' -o -name '*.sql' -o -name '*.sql.gz' -o -name '*.bak' -o -name '*.old' -o -name 'phpinfo.php' -o -name 'info.php' -o -name '*.swp' \) 2>/dev/null | head -60; done
"#;

/// The script for `sh -s`: only the enabled checks. It runs as one function, so the shell has
/// read all of it before any command could read standard input, and every command reads
/// /dev/null.
pub fn script(options: &Options) -> String {
    let mut script = String::from("main() {\n");
    script.push_str(PRELUDE);
    if options.sudo {
        script.push_str(SUDO);
    }
    script.push_str(BASE);
    let blocks: [(&str, &str); 10] = [("system", SYSTEM), ("packages", PACKAGES), ("ssh", SSH), ("accounts", ACCOUNTS), ("files", FILES), ("network", NETWORK), ("services", SERVICES), ("containers", CONTAINERS), ("logs", LOGS), ("secrets", SECRETS)];
    if options.has("packages") || options.cve {
        script.push_str(INVENTORY);
    }
    for (name, block) in blocks {
        if options.has(name) {
            script.push_str(block);
        }
    }
    script.push_str("S end\n}\nmain </dev/null 2>/dev/null\n");
    script
}

/// What the UI shows while a section runs.
pub fn step(section: &str) -> String {
    let category = section.split('.').next().unwrap_or(section);
    match category {
        "base" => "Reading the system…".into(),
        "end" => "Analysing…".into(),
        "timeout" => "Out of time".into(),
        other => format!("Checking {other}…"),
    }
}

// --- Findings ----------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

use Severity::{Critical, High, Info, Low, Medium};

impl Severity {
    fn name(self) -> &'static str {
        match self {
            Info => "info",
            Low => "low",
            Medium => "medium",
            High => "high",
            Critical => "critical",
        }
    }

    fn from_word(word: &str) -> Option<Self> {
        match word.trim().to_ascii_lowercase().as_str() {
            "critical" => Some(Critical),
            "high" | "important" => Some(High),
            "medium" | "moderate" => Some(Medium),
            "low" => Some(Low),
            "negligible" | "unimportant" => Some(Info),
            _ => None,
        }
    }

    fn from_score(score: f64) -> Self {
        match score {
            s if s >= 9.0 => Critical,
            s if s >= 7.0 => High,
            s if s >= 4.0 => Medium,
            s if s > 0.0 => Low,
            _ => Info,
        }
    }

    fn lower(self) -> Self {
        match self {
            Critical => High,
            High => Medium,
            Medium => Low,
            _ => Info,
        }
    }

    fn weight(self) -> u32 {
        match self {
            Critical => 15,
            High => 5,
            Medium => 2,
            Low => 1,
            Info => 0,
        }
    }
}

struct Finding {
    id: String,
    category: &'static str,
    /// Where it comes from: "rule" (judged here), "osv", "osv-approx" or "vendor".
    source: &'static str,
    severity: Severity,
    title: String,
    detail: String,
    evidence: String,
    fix: String,
}

impl Finding {
    fn source(&mut self, source: &'static str) -> &mut Self {
        self.source = source;
        self
    }

    fn detail(&mut self, text: impl Into<String>) -> &mut Self {
        self.detail = text.into();
        self
    }

    fn evidence(&mut self, text: impl AsRef<str>) -> &mut Self {
        self.evidence = clip(text.as_ref());
        self
    }

    fn fix(&mut self, text: impl Into<String>) -> &mut Self {
        self.fix = text.into();
        self
    }

    fn json(&self) -> Value {
        json!({ "id": self.id, "category": self.category, "source": self.source, "severity": self.severity.name(), "title": self.title, "detail": self.detail, "evidence": self.evidence, "fix": self.fix })
    }
}

#[derive(Default)]
struct Findings(Vec<Finding>);

impl Findings {
    fn add(&mut self, category: &'static str, severity: Severity, id: &str, title: impl Into<String>) -> &mut Finding {
        self.0.push(Finding { id: format!("{category}.{id}"), category, source: "rule", severity, title: title.into(), detail: String::new(), evidence: String::new(), fix: String::new() });
        self.0.last_mut().expect("just pushed")
    }
}

/// Evidence stays short enough to read and to sync.
fn clip(text: &str) -> String {
    const LINES: usize = 60;
    const CHARS: usize = 6000;
    let lines: Vec<&str> = text.trim_matches('\n').lines().collect();
    let mut out = lines.iter().take(LINES).copied().collect::<Vec<_>>().join("\n");
    if out.len() > CHARS {
        let mut cut = CHARS;
        while !out.is_char_boundary(cut) {
            cut -= 1;
        }
        out.truncate(cut);
        out.push_str("\n…");
    } else if lines.len() > LINES {
        out.push_str(&format!("\n… and {} more lines", lines.len() - LINES));
    }
    out
}

// --- Reading the output --------------------------------------------------------------------------

struct Data(HashMap<String, String>);

impl Data {
    fn parse(output: &str) -> Self {
        let mut sections = HashMap::new();
        let mut current: Option<String> = None;
        let mut body = String::new();
        for line in output.lines() {
            if let Some(name) = line.strip_prefix("@@").map(str::trim).filter(|name| !name.is_empty() && !name.contains(' ')) {
                if let Some(previous) = current.take() {
                    sections.insert(previous, std::mem::take(&mut body));
                }
                current = Some(name.to_owned());
                continue;
            }
            body.push_str(line.trim_end_matches('\r'));
            body.push('\n');
        }
        if let Some(previous) = current {
            sections.insert(previous, body);
        }
        Self(sections)
    }

    fn get(&self, name: &str) -> &str {
        self.0.get(name).map_or("", String::as_str)
    }

    fn has(&self, name: &str) -> bool {
        self.0.contains_key(name)
    }

    fn lines<'a>(&'a self, name: &str) -> impl Iterator<Item = &'a str> + 'a {
        self.get(name).lines().map(str::trim).filter(|line| !line.is_empty())
    }
}

fn pairs(text: &str) -> HashMap<String, String> {
    text.lines().filter_map(|line| line.split_once('=')).map(|(key, value)| (key.trim().to_owned(), value.trim().trim_matches('"').to_owned())).collect()
}

fn numbers(text: &str) -> Vec<u64> {
    text.split(|c: char| !c.is_ascii_digit()).filter(|part| !part.is_empty()).filter_map(|part| part.parse().ok()).take(6).collect()
}

fn version_cmp(a: &str, b: &str) -> Ordering {
    numbers(a).cmp(&numbers(b))
}

fn below(version: &str, limit: &str) -> bool {
    version_cmp(version, limit) == Ordering::Less
}

/// `ls -l` lines as (mode, owner, path).
fn ls_entries(text: &str) -> Vec<(String, String, String)> {
    text.lines()
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 9 || !cols[0].starts_with(['-', 'd', 's', 'l', 'c', 'b', 'p']) || cols[0].len() < 10 {
                return None;
            }
            Some((cols[0].to_owned(), cols[2].to_owned(), cols[8..].join(" ")))
        })
        .collect()
}

/// Whether `others` (or `group`) may do `what` ('r', 'w') per an `ls -l` mode.
fn others_may(mode: &str, what: char) -> bool {
    let index = if what == 'r' { 7 } else { 8 };
    mode.chars().nth(index) == Some(what)
}

fn group_may(mode: &str, what: char) -> bool {
    let index = if what == 'r' { 4 } else { 5 };
    mode.chars().nth(index) == Some(what)
}

fn manager(d: &Data) -> &'static str {
    if d.lines("packages.dpkg").next().is_some() {
        "dpkg"
    } else if d.lines("packages.rpm").next().is_some() {
        "rpm"
    } else if d.lines("packages.apk").next().is_some() {
        "apk"
    } else {
        ""
    }
}

fn upgrade_command(manager: &str, security: bool) -> &'static str {
    match (manager, security) {
        ("dpkg", true) => "sudo apt-get update && sudo apt-get upgrade (or sudo unattended-upgrade for security updates only)",
        ("dpkg", false) => "sudo apt-get update && sudo apt-get upgrade",
        ("rpm", true) => "sudo dnf upgrade --security",
        ("rpm", false) => "sudo dnf upgrade",
        ("apk", _) => "apk update && apk upgrade",
        _ => "Install the pending updates with the system's package manager.",
    }
}

// --- The analysis ----------------------------------------------------------------------------------

/// Judges the script's output: the report the UI shows and the vault keeps.
pub fn analyze(output: &str, options: &Options, address: Option<&str>, progress: &dyn Fn(&str)) -> Value {
    let d = Data::parse(output);
    let meta = pairs(d.get("base.meta"));
    let os = pairs(d.get("base.os"));
    let root = meta.get("root").is_some_and(|value| value == "1");
    let mut f = Findings::default();
    if d.has("timeout") {
        f.add("base", Medium, "timeout", "The audit ran out of time")
            .detail("The server took too long to answer every check: the sections after the last one received are missing.")
            .fix("Run it again, or turn off the slow checks (Files, Secrets) in Settings > Security.");
    } else if !d.has("end") {
        f.add("base", Medium, "incomplete", "The audit ended early").detail("The connection closed before every check ran: the report is partial.").evidence(output.lines().rev().take(5).collect::<Vec<_>>().join("\n"));
    }
    if !d.has("base.meta") {
        f.add("base", High, "no-shell", "The server did not run the audit script").detail("No POSIX shell answered: the account may be limited to SFTP or a restricted shell.").evidence(clip(output));
    } else if !root {
        f.add("base", Info, "partial", "Checked without root")
            .detail("Password hashes, sudoers, firewall rules, other users' files and the programs behind open ports need root: those checks were skipped or are partial.")
            .evidence(format!("user {}", meta.get("user").map_or("?", String::as_str)))
            .fix(if options.sudo { "This user cannot run sudo without a password: allow it (NOPASSWD) for a complete audit, or connect as root." } else { "Turn on \"Use sudo\" in Settings > Security (needs passwordless sudo) or connect as root." });
    }
    let reach = match address {
        Some(address) if options.probe && options.has("network") => {
            progress("Trying the open ports from this device…");
            probe(address, &listeners(&d))
        }
        _ => HashMap::new(),
    };
    if options.has("system") {
        system(&d, &os, &mut f);
    }
    if options.has("packages") {
        packages(&d, &meta, &mut f);
    }
    if options.has("ssh") {
        ssh(&d, options.cve, &mut f);
    }
    if options.has("accounts") {
        accounts(&d, root, &mut f);
    }
    if options.has("files") {
        files(&d, &mut f);
    }
    if options.has("network") {
        network(&d, root, &reach, &mut f);
    }
    if options.has("services") {
        services(&d, options.cve, &mut f);
    }
    if options.has("containers") {
        containers(&d, &mut f);
    }
    if options.has("logs") {
        logs(&d, &mut f);
    }
    if options.has("secrets") {
        secrets(&d, &mut f);
    }
    let (mut cve, covered) = if options.cve { cves(&d, &os, &mut f, progress) } else { (json!({ "status": "off" }), HashSet::new()) };
    if options.has("packages") {
        cve["vendor"] = json!(vendor(&d, &covered, &mut f));
    }
    let order = |category: &str| CATEGORIES.iter().position(|name| *name == category).unwrap_or(usize::MAX);
    f.0.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| order(a.category).cmp(&order(b.category))));
    let mut counts = serde_json::Map::new();
    for severity in [Critical, High, Medium, Low, Info] {
        counts.insert(severity.name().into(), json!(f.0.iter().filter(|finding| finding.severity == severity).count()));
    }
    // Each severity costs up to a cap, so a hundred CVEs do not hide what else is wrong.
    let count = |severity: Severity| f.0.iter().filter(|finding| finding.severity == severity).count() as u32;
    let penalty = (count(Critical) * Critical.weight()).min(45) + (count(High) * High.weight()).min(30) + (count(Medium) * Medium.weight()).min(15) + (count(Low) * Low.weight()).min(10);
    let mut uname = d.lines("base.uname");
    let installed = d.lines("packages.dpkg").count() + d.lines("packages.rpm").count() + d.lines("packages.apk").count();
    json!({
        "facts": {
            "host": meta.get("host"),
            "user": meta.get("user"),
            "root": root,
            "sudo": meta.get("sudo").is_some_and(|value| value == "yes"),
            "os": os.get("PRETTY_NAME").or(os.get("NAME")),
            "kernel": uname.next(),
            "arch": uname.next(),
            "virtualization": d.lines("base.container").collect::<Vec<_>>().join(", "),
            "packages": installed,
            "manager": manager(&d),
        },
        "categories": CATEGORIES.iter().filter(|name| options.has(name)).collect::<Vec<_>>(),
        "options": { "sudo": options.sudo, "cve": options.cve, "probe": options.probe },
        "score": 100u32.saturating_sub(penalty),
        "counts": counts,
        "cve": cve,
        "findings": f.0.iter().map(Finding::json).collect::<Vec<_>>(),
    })
}

const SYSCTL: &[(&str, &[&str], Severity, &str)] = &[
    ("kernel.randomize_va_space", &["2"], High, "Address space layout randomisation is not fully on"),
    ("kernel.kptr_restrict", &["1", "2"], Low, "Kernel pointers are visible to every user"),
    ("kernel.dmesg_restrict", &["1"], Low, "Every user can read the kernel log"),
    ("kernel.yama.ptrace_scope", &["1", "2", "3"], Low, "Any process can trace the other processes of its user"),
    ("kernel.unprivileged_bpf_disabled", &["1", "2"], Medium, "Unprivileged users can load BPF programs"),
    ("fs.protected_symlinks", &["1"], Medium, "Symlink protection in shared directories is off"),
    ("fs.protected_hardlinks", &["1"], Medium, "Hardlink protection is off"),
    ("fs.protected_fifos", &["1", "2"], Low, "FIFO protection in shared directories is off"),
    ("fs.protected_regular", &["1", "2"], Low, "File protection in shared directories is off"),
    ("fs.suid_dumpable", &["0"], Low, "SUID programs may write core dumps"),
    ("net.ipv4.conf.all.accept_redirects", &["0"], Low, "ICMP redirects are accepted"),
    ("net.ipv6.conf.all.accept_redirects", &["0"], Low, "IPv6 ICMP redirects are accepted"),
    ("net.ipv4.conf.all.send_redirects", &["0"], Low, "ICMP redirects are sent"),
    ("net.ipv4.conf.all.accept_source_route", &["0"], Medium, "Source-routed packets are accepted"),
    ("net.ipv4.tcp_syncookies", &["1"], Low, "SYN cookies (SYN flood protection) are off"),
    ("net.ipv4.conf.all.rp_filter", &["1", "2"], Low, "Reverse path filtering is off"),
];

fn system(d: &Data, os: &HashMap<String, String>, f: &mut Findings) {
    const C: &str = "system";
    let id = os.get("ID").map_or("", String::as_str);
    let version = os.get("VERSION_ID").map_or("", String::as_str);
    let pretty = os.get("PRETTY_NAME").map_or(id, String::as_str);
    let ended = match id {
        "debian" => below(version, "11"),
        "ubuntu" => below(version, "22.04"),
        "centos" => !os.get("NAME").is_some_and(|name| name.contains("Stream")) || below(version, "9"),
        "alpine" => below(version, "3.19"),
        "fedora" => below(version, "40"),
        "rhel" | "rocky" | "almalinux" | "ol" => below(version, "8"),
        "opensuse-leap" => below(version, "15.6"),
        _ => false,
    };
    if ended {
        f.add(C, High, "eol", format!("{pretty} no longer gets security updates"))
            .detail("This release reached its end of life: new vulnerabilities in the kernel and packages stay unfixed (unless it has paid extended support, such as Ubuntu Pro or Debian ELTS).")
            .evidence(format!("ID={id}\nVERSION_ID={version}"))
            .fix("Upgrade to a supported release of the distribution.");
    }
    if d.lines("system.reboot").next().is_some() {
        f.add(C, Medium, "reboot", "A reboot is pending")
            .detail("Installed updates (often the kernel, libc or OpenSSL) only take effect after a restart.")
            .evidence(d.get("system.reboot"))
            .fix("Plan a restart: sudo reboot");
    }
    let running = d.lines("base.uname").next().unwrap_or("");
    let flavour = |kernel: &str| kernel.trim_start_matches(|c: char| c.is_ascii_digit() || c == '.' || c == '-').to_owned();
    let newest = d.lines("system.kernels").filter(|kernel| kernel.starts_with(|c: char| c.is_ascii_digit()) && flavour(kernel) == flavour(running)).max_by(|a, b| version_cmp(a, b));
    if let Some(newest) = newest
        && !running.is_empty()
        && version_cmp(newest, running) == Ordering::Greater
    {
        f.add(C, Medium, "kernel", format!("The running kernel {running} is older than the installed {newest}"))
            .detail("A newer kernel, usually with security fixes, is installed but the server has not restarted into it.")
            .evidence(d.get("system.kernels"))
            .fix("Restart the server to boot the new kernel (or use a live patch service).");
    }
    if let Some(seconds) = d.lines("system.uptime").next().and_then(|text| text.parse::<f64>().ok()) {
        let days = (seconds / 86400.0) as u64;
        if days > 180 {
            f.add(C, Low, "uptime", format!("Up for {days} days")).detail("A server that has not restarted in months most likely runs a kernel without recent security fixes.").fix("Restart it after installing updates, or use a live patch service.");
        }
    }
    let vulnerable: Vec<&str> = d.lines("system.cpu").filter(|line| line.split_once(": ").is_some_and(|(_, state)| state.starts_with("Vulnerable"))).collect();
    if !vulnerable.is_empty() {
        f.add(C, Medium, "cpu", format!("The CPU is open to {} side-channel attack(s)", vulnerable.len()))
            .detail("The kernel reports CPU flaws it does not mitigate (microcode or kernel too old, or mitigations turned off).")
            .evidence(vulnerable.join("\n"))
            .fix("Update the kernel and the CPU microcode (intel-microcode / amd64-microcode), and do not boot with mitigations=off.");
    }
    let sysctl = pairs(d.get("system.sysctl"));
    for (key, good, severity, title) in SYSCTL {
        if let Some(value) = sysctl.get(*key)
            && !good.contains(&value.as_str())
        {
            f.add(C, *severity, key, *title).evidence(format!("{key} = {value}")).fix(format!("echo '{key} = {}' | sudo tee /etc/sysctl.d/90-hardening.conf -a && sudo sysctl --system", good[good.len() - 1]));
        }
    }
    if sysctl.get("net.ipv4.ip_forward").is_some_and(|value| value == "1") {
        f.add(C, Info, "forwarding", "The server routes packets between networks").detail("IP forwarding is on: expected for a router, VPN or container host, otherwise not needed.").evidence("net.ipv4.ip_forward = 1");
    }
    if d.has("system.mac") {
        let mac = pairs(d.get("system.mac"));
        let selinux = mac.get("selinux").is_some_and(|value| value.eq_ignore_ascii_case("enforcing"));
        let apparmor = mac.get("apparmor").is_some_and(|value| value == "Y");
        if !selinux && !apparmor {
            f.add(C, Low, "mac", "No mandatory access control is enforcing")
                .detail("Neither SELinux nor AppArmor confines services: a compromised daemon reaches everything its user can.")
                .evidence(d.get("system.mac"))
                .fix("Enable AppArmor (Debian/Ubuntu) or set SELinux to enforcing (RHEL family).");
        }
    }
    if pairs(d.get("system.time")).get("ntp").is_some_and(|value| value == "no") {
        f.add(C, Low, "ntp", "The clock is not synchronised").detail("A drifting clock breaks TLS and token checks and makes logs useless for an investigation.").fix("sudo timedatectl set-ntp true");
    }
    let weak_mounts: Vec<String> = d
        .lines("system.mounts")
        .filter_map(|line| {
            let (path, options) = line.split_once(' ')?;
            let missing: Vec<&str> = ["noexec", "nosuid", "nodev"].into_iter().filter(|flag| !options.split(',').any(|option| option == *flag)).collect();
            (!missing.is_empty()).then(|| format!("{path}: no {}", missing.join(", ")))
        })
        .collect();
    if !weak_mounts.is_empty() {
        f.add(C, Low, "mounts", "Shared temporary directories allow running programs")
            .detail("Attackers drop and run their tools in /tmp or /dev/shm; mounting them noexec,nosuid,nodev stops most of that.")
            .evidence(weak_mounts.join("\n"))
            .fix("Add noexec,nosuid,nodev to these mounts in /etc/fstab and remount.");
    }
}

fn packages(d: &Data, meta: &HashMap<String, String>, f: &mut Findings) {
    const C: &str = "packages";
    let manager = manager(d);
    let pending: Vec<&str> = d.lines("packages.pending").collect();
    let security: Vec<&str> = if manager == "dpkg" { pending.iter().filter(|line| line.to_ascii_lowercase().contains("security")).copied().collect() } else { d.lines("packages.security").collect() };
    if !security.is_empty() {
        f.add(C, High, "security-updates", format!("{} security updates are not installed", security.len()))
            .detail("The distribution has already published fixes for vulnerabilities in these packages.")
            .evidence(security.join("\n"))
            .fix(upgrade_command(manager, true));
    }
    if !pending.is_empty() {
        f.add(C, if security.is_empty() { Medium } else { Low }, "updates", format!("{} packages have updates waiting", pending.len())).evidence(pending.join("\n")).fix(upgrade_command(manager, false));
    }
    let now: u64 = meta.get("now").and_then(|now| now.parse().ok()).unwrap_or(0);
    let refreshed = d.lines("packages.refreshed").filter_map(|line| line.split_whitespace().next()?.parse::<u64>().ok()).max();
    if let Some(refreshed) = refreshed
        && now > refreshed
        && (now - refreshed) / 86400 > 7
    {
        f.add(C, Low, "stale", format!("The package lists were last refreshed {} days ago", (now - refreshed) / 86400))
            .detail("With old lists the server does not know about recent updates, and this audit cannot list them either.")
            .fix(if manager == "dpkg" { "sudo apt-get update" } else { "sudo dnf makecache" });
    }
    let auto = d.get("packages.auto");
    let automatic = match manager {
        "dpkg" => Some(auto.contains("Unattended-Upgrade \"1\"")),
        "rpm" => Some(pairs(auto).get("dnf-automatic").is_some_and(|count| count != "0")),
        _ => None,
    };
    if automatic == Some(false) {
        f.add(C, Low, "auto", "Security updates are not installed automatically")
            .detail("Fixes wait until someone logs in and upgrades by hand.")
            .fix(if manager == "dpkg" { "sudo apt-get install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades" } else { "sudo dnf install dnf-automatic && sudo systemctl enable --now dnf-automatic-install.timer" });
    }
    let installed = d.lines("packages.dpkg").count() + d.lines("packages.rpm").count() + d.lines("packages.apk").count();
    if installed > 0 {
        f.add(C, Info, "inventory", format!("{installed} packages installed ({manager})")).detail("Turn on the CVE lookup to match each version against known vulnerabilities.");
    }
}

fn sshd_effective(text: &str) -> HashMap<String, String> {
    let mut values = HashMap::new();
    for line in text.lines() {
        if let Some((key, value)) = line.trim().split_once(' ') {
            values.entry(key.to_ascii_lowercase()).or_insert_with(|| value.trim().to_owned());
        }
    }
    values
}

/// sshd_config the way sshd reads it: the first value wins, `Match` blocks are left out.
fn sshd_file(text: &str) -> HashMap<String, String> {
    let mut values = HashMap::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line.split_once(|c: char| c.is_whitespace() || c == '=').unwrap_or((line, ""));
        let key = key.to_ascii_lowercase();
        if key == "match" {
            break;
        }
        values.entry(key).or_insert_with(|| value.trim().trim_start_matches('=').trim().to_ascii_lowercase());
    }
    values
}

fn ssh(d: &Data, cve: bool, f: &mut Findings) {
    const C: &str = "ssh";
    let effective = d.get("ssh.effective");
    let exact = effective.lines().count() > 10;
    let config = if exact { sshd_effective(effective) } else { sshd_file(d.get("ssh.config")) };
    if config.is_empty() && !exact {
        f.add(C, Info, "unread", "The SSH server configuration could not be read").detail("No sshd_config was readable: the rules below were skipped.");
    } else {
        let source = if exact { "sshd -T" } else { "sshd_config, where unset values fall back to OpenSSH defaults; turn on sudo for the effective ones" };
        let value = |key: &str, default: &str| config.get(key).cloned().unwrap_or_else(|| default.to_owned()).to_ascii_lowercase();
        let evidence = |key: &str, value: &str| format!("{key} {value}   # {source}");
        let rules: [(&str, &str, &str, Severity, &str, &str); 7] = [
            ("permitrootlogin", "prohibit-password", "yes", High, "root can log in with a password", "PermitRootLogin prohibit-password (or no)"),
            ("passwordauthentication", "yes", "yes", Medium, "Password logins are allowed", "PasswordAuthentication no, after every user has a key"),
            ("permitemptypasswords", "no", "yes", Critical, "Accounts with an empty password can log in", "PermitEmptyPasswords no"),
            ("x11forwarding", "no", "yes", Low, "X11 forwarding is on", "X11Forwarding no"),
            ("permituserenvironment", "no", "yes", Medium, "Users can set environment variables for sshd", "PermitUserEnvironment no"),
            ("gatewayports", "no", "yes", Low, "Forwarded ports listen on every interface", "GatewayPorts no"),
            ("loglevel", "info", "quiet", Low, "sshd logs nothing", "LogLevel VERBOSE"),
        ];
        for (key, default, bad, severity, title, fix) in rules {
            let current = value(key, default);
            if current == bad {
                f.add(C, severity, key, title).evidence(evidence(key, &current)).fix(format!("Set {fix} in /etc/ssh/sshd_config, then sudo systemctl reload ssh"));
            }
        }
        if let Ok(tries) = value("maxauthtries", "6").parse::<u32>()
            && tries > 4
        {
            f.add(C, Low, "maxauthtries", format!("{tries} password attempts per connection")).evidence(evidence("maxauthtries", &tries.to_string())).fix("Set MaxAuthTries 3 in /etc/ssh/sshd_config");
        }
        if value("pubkeyauthentication", "yes") == "no" {
            f.add(C, Medium, "pubkey", "Key logins are turned off").detail("Only passwords remain, which can be guessed.").fix("Set PubkeyAuthentication yes");
        }
        let weak = |key: &str, bad: &[&str]| -> Vec<String> { config.get(key).map(|list| list.split(',').filter(|item| bad.iter().any(|bad| item.contains(bad))).map(str::to_owned).collect()).unwrap_or_default() };
        let checks: [(&str, &[&str], Severity, &str, &str); 4] = [
            ("ciphers", &["cbc", "3des", "arcfour", "blowfish"], Medium, "Weak ciphers are offered", "Ciphers"),
            ("macs", &["hmac-md5", "hmac-sha1", "umac-64", "ripemd"], Low, "Weak MACs are offered", "MACs"),
            ("kexalgorithms", &["group1-sha1", "group14-sha1", "exchange-sha1", "gss-gex-sha1", "gss-group1"], Medium, "Weak key exchanges are offered", "KexAlgorithms"),
            ("hostkeyalgorithms", &["ssh-dss"], Medium, "DSA host keys are offered", "HostKeyAlgorithms"),
        ];
        for (key, bad, severity, title, directive) in checks {
            let found = weak(key, bad);
            if !found.is_empty() {
                f.add(C, severity, key, title).evidence(found.join("\n")).fix(format!("Remove them from {directive} in /etc/ssh/sshd_config (prefix the list with - to drop items)."));
            }
        }
    }
    let version_line = d.lines("ssh.version").next().unwrap_or("");
    if let Some(version) = version_line.split("OpenSSH_").nth(1).and_then(|rest| rest.split([' ', ',']).next()) {
        if below(version, "7.4") {
            f.add(C, High, "old", format!("OpenSSH {version} is very old")).detail("Many vulnerabilities were fixed since; this version is long out of support.").evidence(version_line).fix("Upgrade the distribution or OpenSSH.");
        } else if !cve && !below(version, "8.5") && below(version, "9.8") {
            f.add(C, Medium, "regresshion", format!("OpenSSH {version} may be open to regreSSHion (CVE-2024-6387)"))
                .detail("Versions 8.5p1 to 9.7p1 allow remote code execution as root unless the distribution backported the fix. Turn on the CVE lookup for a definite answer.")
                .evidence(version_line)
                .fix("Install the latest openssh-server update from the distribution.");
        } else if !cve && below(version, "9.6") {
            f.add(C, Low, "terrapin", format!("OpenSSH {version} may be open to Terrapin (CVE-2023-48795)")).detail("Unless patched by the distribution; turn on the CVE lookup for a definite answer.").evidence(version_line).fix("Update openssh-server.");
        }
    }
    let exposed: Vec<String> = ls_entries(d.get("ssh.hostkeys")).into_iter().filter(|(mode, _, _)| others_may(mode, 'r') || group_may(mode, 'r') && !mode.is_empty()).map(|(mode, owner, path)| format!("{mode} {owner} {path}")).collect();
    if !exposed.is_empty() {
        f.add(C, High, "hostkeys", "SSH host private keys are readable by other users")
            .detail("Anyone who reads them can impersonate this server.")
            .evidence(exposed.join("\n"))
            .fix("sudo chmod 600 /etc/ssh/ssh_host_*_key");
    }
}

fn accounts(d: &Data, root: bool, f: &mut Findings) {
    const C: &str = "accounts";
    let users: Vec<Vec<&str>> = d.lines("accounts.passwd").map(|line| line.split(':').collect::<Vec<_>>()).filter(|fields| fields.len() >= 7).collect();
    let roots: Vec<&str> = users.iter().filter(|fields| fields[2] == "0" && fields[0] != "root").map(|fields| fields[0]).collect();
    if !roots.is_empty() {
        f.add(C, Critical, "uid0", format!("{} has user id 0 (root)", roots.join(", "))).detail("Any account with id 0 is root. A second one is a classic backdoor.").evidence(roots.join("\n")).fix("Remove the account or give it its own id.");
    }
    let shell = |fields: &Vec<&str>| !["nologin", "false", "sync", "halt", "shutdown"].iter().any(|end| fields[6].ends_with(end)) && !fields[6].is_empty();
    let login: Vec<String> = users.iter().filter(|fields| shell(fields)).map(|fields| format!("{} (uid {}, {})", fields[0], fields[2], fields[6])).collect();
    if !login.is_empty() {
        f.add(C, Info, "login", format!("{} accounts have a login shell", login.len())).evidence(login.join("\n"));
    }
    let services: Vec<&str> = users.iter().filter(|fields| shell(fields) && fields[0] != "root" && fields[2].parse::<u32>().is_ok_and(|id| id > 0 && id < 1000)).map(|fields| fields[0]).collect();
    if !services.is_empty() {
        f.add(C, Low, "service-shells", "System accounts have a login shell").detail("Service accounts should not be able to log in.").evidence(services.join("\n")).fix("sudo usermod -s /usr/sbin/nologin <account>");
    }
    for (mode, _, path) in ls_entries(d.get("accounts.perms")) {
        let issue = match path.as_str() {
            "/etc/shadow" | "/etc/gshadow" if others_may(&mode, 'r') => Some((Critical, "is readable by every user", "chmod 640")),
            "/etc/passwd" | "/etc/group" | "/etc/shadow" | "/etc/gshadow" | "/etc/sudoers" if others_may(&mode, 'w') => Some((Critical, "is writable by every user", "chmod o-w")),
            "/etc/sudoers" if others_may(&mode, 'r') => Some((Medium, "is readable by every user", "chmod 440")),
            "/root" if others_may(&mode, 'r') => Some((Medium, "is readable by every user", "chmod 700")),
            "/etc/sudoers.d" if others_may(&mode, 'w') => Some((Critical, "is writable by every user", "chmod 750")),
            _ => None,
        };
        if let Some((severity, what, fix)) = issue {
            f.add(C, severity, &format!("perm{}", path.replace('/', "-")), format!("{path} {what}")).evidence(format!("{mode} {path}")).fix(format!("sudo {fix} {path}"));
        }
    }
    if root {
        let shadow: Vec<Vec<&str>> = d.lines("accounts.shadow").map(|line| line.split(':').collect::<Vec<_>>()).filter(|fields| fields.len() >= 2).collect();
        let empty: Vec<&str> = shadow.iter().filter(|fields| fields[1] == "empty").map(|fields| fields[0]).collect();
        if !empty.is_empty() {
            f.add(C, Critical, "empty-password", "Accounts without a password").detail("Anyone can log in as these accounts wherever passwords are accepted (console, su, maybe SSH).").evidence(empty.join("\n")).fix("sudo passwd -l <account>, or set a password.");
        }
        let weak: Vec<String> = shadow.iter().filter(|fields| fields[1] == "md5" || fields[1] == "des").map(|fields| format!("{} ({})", fields[0], fields[1])).collect();
        if !weak.is_empty() {
            f.add(C, Medium, "weak-hash", "Passwords stored with a weak hash").detail("MD5 and DES hashes crack in minutes if /etc/shadow leaks.").evidence(weak.join("\n")).fix("Set ENCRYPT_METHOD SHA512 (or YESCRYPT) in /etc/login.defs and change these passwords.");
        }
    }
    let sudoers: Vec<&str> = d.lines("accounts.sudoers").collect();
    let all_nopasswd: Vec<&str> = sudoers.iter().filter(|line| line.contains("NOPASSWD") && line.trim_end().ends_with("ALL")).copied().collect();
    if !all_nopasswd.is_empty() {
        f.add(C, Medium, "nopasswd", "sudo grants root without a password").detail("Whoever gets into these accounts becomes root at once.").evidence(all_nopasswd.join("\n")).fix("Remove NOPASSWD or limit it to the commands needed.");
    }
    let everyone: Vec<&str> = sudoers.iter().filter(|line| line.starts_with("ALL ") || line.contains("!authenticate")).copied().collect();
    if !everyone.is_empty() {
        f.add(C, High, "sudo-everyone", "sudo is open to everyone or skips authentication").evidence(everyone.join("\n")).fix("Limit sudo to an admin group and remove !authenticate.");
    }
    for line in d.lines("accounts.groups") {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 4 || fields[3].is_empty() {
            continue;
        }
        let (group, members) = (fields[0], fields[3]);
        let (severity, why) = match group {
            "docker" | "lxd" | "libvirt" => (Medium, "can start a container or VM with the host's disk mounted: equivalent to root"),
            "disk" => (Medium, "can read and write raw disks: equivalent to root"),
            "shadow" => (Medium, "can read password hashes"),
            _ => (Info, "can run commands as root through sudo"),
        };
        f.add(C, severity, &format!("group-{group}"), format!("Members of {group}: {members}")).detail(format!("Members of {group} {why}.")).evidence(line).fix(if severity == Info { "Keep this list to the people who administer the server." } else { "Remove whoever does not need it: sudo gpasswd -d <user> <group>" });
    }
    let mut weak_keys = Vec::new();
    let mut loose_files = Vec::new();
    let mut all_keys = Vec::new();
    for line in d.lines("accounts.keys") {
        let fields: Vec<&str> = line.split_whitespace().collect();
        match fields.first() {
            Some(&"file") if fields.len() >= 4 => {
                let mode = fields[2];
                let group_or_other_write = mode.len() >= 3 && mode[mode.len() - 2..].chars().any(|digit| matches!(digit, '2' | '3' | '6' | '7'));
                if group_or_other_write {
                    loose_files.push(format!("{mode} {}", fields[3..].join(" ")));
                }
            }
            Some(&"key") if fields.len() >= 4 => {
                let (user, kind, length) = (fields[1], fields[2], fields[3].parse::<usize>().unwrap_or(0));
                let comment = fields.get(5).copied().unwrap_or("");
                all_keys.push(format!("{user}: {kind} {comment}"));
                if kind == "ssh-dss" {
                    weak_keys.push(format!("{user}: DSA key {comment}"));
                } else if kind == "ssh-rsa" && length < 300 {
                    weak_keys.push(format!("{user}: RSA key of 1024 bits or less {comment}"));
                }
            }
            _ => {}
        }
    }
    if !loose_files.is_empty() {
        f.add(C, High, "authorized-keys-perms", "authorized_keys files writable by others").detail("Anyone who can write them can add a key and log in as that user.").evidence(loose_files.join("\n")).fix("chmod 600 ~/.ssh/authorized_keys");
    }
    if !weak_keys.is_empty() {
        f.add(C, High, "weak-keys", "Weak keys can log in").evidence(weak_keys.join("\n")).fix("Replace them with ed25519 keys (ssh-keygen -t ed25519) and remove the old ones.");
    }
    if !all_keys.is_empty() {
        f.add(C, Info, "keys", format!("{} keys can log in", all_keys.len())).detail("Check that you recognise every one of them.").evidence(all_keys.join("\n"));
    }
    let policy = d.get("accounts.policy");
    let setting = |key: &str| policy.lines().find_map(|line| line.trim().strip_prefix(key).map(|rest| rest.trim().to_owned()));
    if setting("ENCRYPT_METHOD").is_some_and(|method| method == "MD5" || method == "DES") {
        f.add(C, Medium, "encrypt-method", "New passwords are hashed with a weak method").evidence(policy).fix("Set ENCRYPT_METHOD SHA512 (or YESCRYPT) in /etc/login.defs");
    }
    if setting("UMASK").is_some_and(|umask| umask.ends_with('0') || umask.ends_with('2') && umask.len() >= 3 && !umask.ends_with("22") && !umask.ends_with("27")) {
        f.add(C, Low, "umask", "New files are writable by other users").evidence(policy).fix("Set UMASK 027 in /etc/login.defs");
    }
}

/// SUID programs that hand out a root shell (GTFOBins).
const ESCALATE: &[&str] = &[
    "bash", "sh", "dash", "zsh", "ksh", "csh", "fish", "find", "vim", "vi", "vim.basic", "nano", "less", "more", "nmap", "python", "python2", "python3", "perl", "ruby", "php", "node", "lua", "awk", "gawk", "mawk", "cp", "mv", "tar", "zip", "env", "tee", "dd", "socat", "nc", "netcat", "wget", "curl", "docker", "systemctl", "git", "gdb", "strace", "busybox", "cat", "base64", "chmod", "chown", "rsync", "openssl", "expect", "sed", "ed", "xxd", "sqlite3", "journalctl", "taskset", "nice", "timeout", "stdbuf", "xargs", "flock", "ionice", "setarch", "install", "make", "pip", "head", "tail", "sort", "cut", "diff", "date",
];

/// SUID programs a normal system ships.
const USUAL_SUID: &[&str] = &[
    "passwd", "chsh", "chfn", "newgrp", "gpasswd", "su", "sudo", "sudoedit", "mount", "umount", "ping", "ping6", "pkexec", "fusermount", "fusermount3", "ntfs-3g", "dbus-daemon-launch-helper", "ssh-keysign", "Xorg.wrap", "Xorg", "polkit-agent-helper-1", "chage", "expiry", "unix_chkpwd", "pam_timestamp_check", "crontab", "at", "ssh-agent", "wall", "write", "bsd-write", "mount.nfs", "mount.cifs", "umount.nfs", "newuidmap", "newgidmap", "snap-confine", "chrome-sandbox", "traceroute6.iputils", "sg", "lockdev", "utempter", "dotlockfile", "mlocate", "plocate", "locate", "usernetctl", "userhelper", "mail-lock", "mail-unlock", "mail-touchlock", "doas", "pppd", "exim4", "postdrop", "postqueue", "lxc-user-nic", "cockpit-session", "staprun", "screen", "mount.ecryptfs_private", "vmware-user-suid-wrapper", "gnome-keyring-daemon", "Xorg.bin", "grub2-set-bootflag", "pam_extrausers_chkpwd", "suexec", "ssh-keysign",
];

fn files(d: &Data, f: &mut Findings) {
    const C: &str = "files";
    let mut escalate = Vec::new();
    let mut odd_place = Vec::new();
    let mut unusual = Vec::new();
    let suid = ls_entries(d.get("files.suid"));
    for (mode, owner, path) in &suid {
        let name = path.rsplit('/').next().unwrap_or(path);
        let line = format!("{mode} {owner} {path}");
        if ESCALATE.contains(&name) || name.starts_with("python") || name.starts_with("perl") || name.starts_with("php") {
            escalate.push(line);
        } else if ["/tmp/", "/var/tmp/", "/dev/shm/", "/home/"].iter().any(|place| path.starts_with(place)) {
            odd_place.push(line);
        } else if !USUAL_SUID.contains(&name) {
            unusual.push(line);
        }
    }
    if !escalate.is_empty() {
        f.add(C, Critical, "suid-escalate", "SUID programs that give a root shell").detail("Any user can become root through these (see GTFOBins).").evidence(escalate.join("\n")).fix("sudo chmod u-s,g-s <path>");
    }
    if !odd_place.is_empty() {
        f.add(C, High, "suid-odd", "SUID programs in user-writable places").detail("A SUID program in /tmp or a home folder is a common backdoor.").evidence(odd_place.join("\n")).fix("Find out who put them there, then remove them.");
    }
    if !unusual.is_empty() {
        f.add(C, Low, "suid-unusual", format!("{} SUID/SGID programs outside the usual set", unusual.len())).detail("Check that each one is expected: every SUID program is a way to root if it has a bug.").evidence(unusual.join("\n")).fix("Remove the bit where not needed: sudo chmod u-s <path>");
    }
    if !suid.is_empty() {
        f.add(C, Info, "suid", format!("{} SUID/SGID programs", suid.len())).evidence(suid.iter().map(|(mode, owner, path)| format!("{mode} {owner} {path}")).collect::<Vec<_>>().join("\n"));
    }
    let writable: Vec<&str> = d.lines("files.writable").collect();
    if !writable.is_empty() {
        f.add(C, High, "world-writable", format!("{} system files are writable by every user", writable.len())).detail("Any user can change these, and through them what root runs.").evidence(writable.join("\n")).fix("sudo chmod o-w <path>");
    }
    let dirs: Vec<&str> = d.lines("files.dirs").collect();
    if !dirs.is_empty() {
        f.add(C, Medium, "world-writable-dirs", "Directories writable by everyone without the sticky bit").detail("Any user can delete or replace the files of others in them.").evidence(dirs.join("\n")).fix("sudo chmod +t <dir> (or o-w)");
    }
    let unowned: Vec<&str> = d.lines("files.unowned").collect();
    if !unowned.is_empty() {
        f.add(C, Low, "unowned", format!("{} files belong to no user or group", unowned.len())).detail("Left by deleted accounts: a new account with the same id would own them.").evidence(unowned.join("\n")).fix("sudo chown root:root <path>, or delete them.");
    }
    let risky_caps = ["cap_setuid", "cap_setgid", "cap_sys_admin", "cap_dac_override", "cap_dac_read_search", "cap_sys_ptrace", "cap_sys_module", "cap_chown", "cap_fowner"];
    let caps: Vec<&str> = d.lines("files.caps").filter(|line| risky_caps.iter().any(|cap| line.contains(cap))).collect();
    if !caps.is_empty() {
        f.add(C, High, "capabilities", "Programs with root-level capabilities").detail("These capabilities let a program bypass file permissions or change its user: often a way to root.").evidence(caps.join("\n")).fix("sudo setcap -r <path>");
    }
    let homes: Vec<String> = ls_entries(d.get("files.homes")).into_iter().filter(|(mode, _, _)| others_may(mode, 'r')).map(|(mode, owner, path)| format!("{mode} {owner} {path}")).collect();
    if !homes.is_empty() {
        f.add(C, Low, "homes", "Home folders readable by every user").evidence(homes.join("\n")).fix("chmod 750 <home>");
    }
}

struct Listener {
    proto: String,
    address: String,
    port: u16,
    process: String,
}

impl Listener {
    fn exposed(&self) -> bool {
        !(self.address.starts_with("127.") || self.address == "::1" || self.address.eq_ignore_ascii_case("localhost"))
    }

    fn line(&self) -> String {
        format!("{} {}:{} {}", self.proto, self.address, self.port, self.process)
    }
}

/// `ss -tulpn` or `netstat -tulpn` lines.
fn listeners(d: &Data) -> Vec<Listener> {
    let mut found = Vec::new();
    let mut seen = HashSet::new();
    for line in d.lines("network.listen") {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 5 || !(cols[0].starts_with("tcp") || cols[0].starts_with("udp")) {
            continue;
        }
        let netstat = cols[1].chars().all(|c| c.is_ascii_digit());
        let (local, process) = if netstat { (cols[3], cols.last().and_then(|last| last.split_once('/')).map(|(_, name)| name.to_owned()).unwrap_or_default()) } else { (cols[4], cols[6..].join(" ").split("((\"").nth(1).and_then(|rest| rest.split('"').next()).unwrap_or("").to_owned()) };
        let Some((address, port)) = local.rsplit_once(':') else { continue };
        let Ok(port) = port.parse::<u16>() else { continue };
        let address = address.trim_matches(['[', ']']).split('%').next().unwrap_or("").to_owned();
        let proto = if cols[0].starts_with("tcp") { "tcp" } else { "udp" }.to_owned();
        if seen.insert((proto.clone(), address.clone(), port)) {
            found.push(Listener { proto, address, port, process });
        }
    }
    found.sort_by(|a, b| a.proto.cmp(&b.proto).then(a.port.cmp(&b.port)));
    found
}

fn risky(proto: &str, port: u16) -> Option<(&'static str, Severity)> {
    Some(match (proto, port) {
        ("tcp", 23) => ("Telnet (unencrypted remote login)", Critical),
        ("tcp", 2375) => ("The Docker API without TLS (root on the host)", Critical),
        ("tcp", 2379 | 2380) => ("etcd", Critical),
        ("tcp", 512..=514) => ("r-services (rexec, rlogin, rsh)", Critical),
        ("tcp", 21) => ("FTP (unencrypted)", Medium),
        ("udp", 69) => ("TFTP", High),
        ("tcp" | "udp", 111) => ("rpcbind", Medium),
        ("tcp", 139 | 445) => ("SMB file sharing", High),
        ("tcp", 873) => ("The rsync daemon", Medium),
        ("tcp", 1433) => ("Microsoft SQL Server", High),
        ("tcp", 1521) => ("Oracle database", High),
        ("tcp", 2049) => ("NFS", Medium),
        ("tcp", 2376) => ("The Docker API (TLS)", Medium),
        ("tcp", 3306) => ("MySQL/MariaDB", High),
        ("tcp", 3389) => ("RDP", High),
        ("tcp", 5432) => ("PostgreSQL", High),
        ("tcp", 5672) => ("AMQP (RabbitMQ)", Medium),
        ("tcp", 5900..=5910) => ("VNC", High),
        ("tcp", 5984) => ("CouchDB", High),
        ("tcp", 6379) => ("Redis", High),
        ("tcp", 6443) => ("The Kubernetes API", Medium),
        ("tcp", 8086) => ("InfluxDB", Medium),
        ("tcp", 9090) => ("An admin panel (Prometheus, Cockpit)", Medium),
        ("tcp", 9200 | 9300) => ("Elasticsearch", High),
        ("tcp", 10250) => ("The Kubelet API", High),
        ("tcp" | "udp", 11211) => ("Memcached", High),
        ("tcp", 15672) => ("RabbitMQ management", Medium),
        ("tcp", 27017 | 27018) => ("MongoDB", High),
        ("udp", 161) => ("SNMP", Medium),
        _ => return None,
    })
}

/// Which of the exposed TCP ports this device can connect to.
fn probe(address: &str, listeners: &[Listener]) -> HashMap<u16, bool> {
    let ports: BTreeSet<u16> = listeners.iter().filter(|listener| listener.proto == "tcp" && listener.exposed()).map(|listener| listener.port).collect();
    let Some(ip) = (address, 0).to_socket_addrs().ok().and_then(|mut addresses| addresses.next()).map(|address| address.ip()) else {
        return HashMap::new();
    };
    std::thread::scope(|scope| {
        let tries: Vec<_> = ports.iter().take(64).map(|&port| scope.spawn(move || (port, TcpStream::connect_timeout(&SocketAddr::new(ip, port), Duration::from_millis(1500)).is_ok()))).collect();
        tries.into_iter().filter_map(|attempt| attempt.join().ok()).collect()
    })
}

fn network(d: &Data, root: bool, reach: &HashMap<u16, bool>, f: &mut Findings) {
    const C: &str = "network";
    let all = listeners(d);
    let mark = |listener: &Listener| match (listener.proto.as_str(), reach.get(&listener.port)) {
        ("tcp", Some(true)) => "  [reachable from this device]",
        ("tcp", Some(false)) => "  [not reachable from this device]",
        _ => "",
    };
    if all.is_empty() {
        if d.has("network.listen") {
            f.add(C, Info, "listen-unread", "The listening ports could not be listed").detail("Neither ss nor netstat answered.");
        }
    } else {
        let exposed: Vec<&Listener> = all.iter().filter(|listener| listener.exposed()).collect();
        f.add(C, Info, "listening", format!("{} services listen on the network, {} only on this machine", exposed.len(), all.len() - exposed.len()))
            .detail("Everything that listens beyond 127.0.0.1 can be reached by whoever reaches the server, unless a firewall stops it.")
            .evidence(all.iter().map(|listener| format!("{}{}", listener.line(), mark(listener))).collect::<Vec<_>>().join("\n"))
            .fix("Bind what is only used locally to 127.0.0.1 and stop what is not used.");
        for listener in &exposed {
            let Some((what, severity)) = risky(&listener.proto, listener.port) else { continue };
            let reachable = if listener.proto == "tcp" { reach.get(&listener.port).copied() } else { None };
            let severity = if reachable == Some(false) { severity.lower() } else { severity };
            let suffix = if reachable == Some(true) { ", reachable from this device" } else { "" };
            f.add(C, severity, &format!("port-{}-{}", listener.proto, listener.port), format!("{what} listens on {}:{}{suffix}", listener.address, listener.port))
                .detail("This service is often attacked when exposed: it should only listen on 127.0.0.1 or a private network, behind a firewall.")
                .evidence(format!("{}{}", listener.line(), mark(listener)))
                .fix("Bind it to 127.0.0.1 (or a private address) in its configuration, or allow only known addresses in the firewall.");
        }
        let reachable: Vec<String> = all.iter().filter(|listener| listener.proto == "tcp" && reach.get(&listener.port) == Some(&true)).map(Listener::line).collect();
        if !reachable.is_empty() {
            f.add(C, Info, "reachable", format!("{} ports answer from this device", reachable.len())).evidence(reachable.join("\n"));
        }
    }
    if d.has("network.firewall") {
        let rules = d.get("network.firewall");
        let lower = rules.to_ascii_lowercase();
        let active = lower.contains("status: active")
            || lower.contains("firewalld=running")
            || lower.contains("policy drop")
            || (lower.contains("hook input") && (lower.contains(" drop") || lower.contains(" reject")))
            || rules.lines().any(|line| line.starts_with("-P INPUT DROP") || (line.starts_with("-A INPUT") && (line.contains("DROP") || line.contains("REJECT"))));
        if !active {
            if root {
                f.add(C, Medium, "firewall", "No firewall filters incoming traffic")
                    .detail("Every port that listens is reachable by whoever reaches the server.")
                    .evidence(rules)
                    .fix("Turn on a firewall that only lets in what is needed, e.g. sudo ufw allow OpenSSH && sudo ufw enable");
            } else {
                f.add(C, Info, "firewall-unread", "The firewall could not be checked").detail("Reading the firewall rules needs root.");
            }
        }
    }
}

fn first_version(text: &str) -> Option<&str> {
    text.split(|c: char| c.is_whitespace() || c == ',' || c == '(' || c == '/' || c == '"')
        .map(|token| token.trim_start_matches('v'))
        .find(|token| token.starts_with(|c: char| c.is_ascii_digit()) && token.contains('.'))
}

fn services(d: &Data, cve: bool, f: &mut Findings) {
    const C: &str = "services";
    let running: Vec<&str> = d.lines("services.running").collect();
    let legacy: Vec<&str> = running.iter().filter(|unit| ["telnet", "rsh", "rlogin", "rexec", "tftp", "xinetd", "vsftpd", "proftpd", "pure-ftpd", "nis", "ypbind", "talk"].iter().any(|name| unit.starts_with(name))).copied().collect();
    if !legacy.is_empty() {
        f.add(C, Medium, "legacy", "Legacy cleartext services are running").detail("These send passwords and data unencrypted.").evidence(legacy.join("\n")).fix("Stop and disable them (sudo systemctl disable --now <unit>), use SSH/SFTP instead.");
    }
    let failed: Vec<&str> = d.lines("services.failed").collect();
    if !failed.is_empty() {
        f.add(C, Low, "failed", format!("{} services failed", failed.len())).detail("A failed service can be a security tool that stopped (firewall, fail2ban, backups).").evidence(failed.join("\n")).fix("Check each with systemctl status <unit>.");
    }
    if !running.is_empty() {
        f.add(C, Info, "running", format!("{} services running", running.len())).evidence(running.join("\n"));
    }
    let versions: Vec<(&str, &str, Option<&str>)> = d.lines("services.versions").filter_map(|line| line.split_once(": ").map(|(name, text)| (name, text, first_version(text)))).collect();
    for (name, text, version) in &versions {
        let Some(version) = version else { continue };
        let eol = match *name {
            "php" => below(version, "8.2").then_some((Medium, "PHP before 8.2 no longer gets security fixes from php.net")),
            "node" => below(version, "20").then_some((Medium, "Node.js before 20 no longer gets security fixes")),
            "python3" => below(version, "3.10").then_some((Low, "Python before 3.10 no longer gets security fixes from python.org")),
            "openssl" => below(version, "3").then_some((Low, "OpenSSL 1.x is out of upstream support (some distributions still patch it)")),
            "sudo" if !cve && !text.contains("sudo-rs") => below(version, "1.9.5p2").then_some((High, "sudo before 1.9.5p2 may allow any user to become root (Baron Samedit, CVE-2021-3156) unless the distribution backported the fix")),
            _ => None,
        };
        if let Some((severity, why)) = eol {
            f.add(C, severity, &format!("old-{name}"), format!("{name} {version} is outdated")).detail(why).evidence(*text).fix(format!("Upgrade {name}."));
        }
    }
    if !versions.is_empty() {
        f.add(C, Info, "versions", "Software versions").evidence(versions.iter().map(|(name, text, _)| format!("{name}: {text}")).collect::<Vec<_>>().join("\n"));
    }
    let cron: Vec<&str> = d.lines("services.cronwritable").collect();
    if !cron.is_empty() {
        f.add(C, Critical, "cron-writable", "Jobs that root runs are writable by every user").detail("Any user can add commands that run as root.").evidence(cron.join("\n")).fix("sudo chmod o-w <path>");
    }
    let units: Vec<&str> = d.lines("services.unitwritable").collect();
    if !units.is_empty() {
        f.add(C, Critical, "unit-writable", "systemd units writable by every user").detail("Any user can change what these services run as root.").evidence(units.join("\n")).fix("sudo chmod o-w <path>");
    }
    let jobs = format!("{}\n{}", d.get("services.cron").trim(), d.get("services.timers").trim());
    if !jobs.trim().is_empty() {
        f.add(C, Info, "scheduled", "Scheduled jobs").detail("Check that you recognise every job: attackers hide their persistence here.").evidence(jobs.trim());
    }
}

fn containers(d: &Data, f: &mut Findings) {
    const C: &str = "containers";
    for (mode, owner, path) in ls_entries(d.get("containers.sockets")) {
        if others_may(&mode, 'w') {
            f.add(C, Critical, "socket", format!("{path} is open to every user")).detail("Whoever talks to the container engine is root on the host.").evidence(format!("{mode} {owner} {path}")).fix(format!("sudo chmod 660 {path}"));
        }
    }
    let ufw = d.get("network.firewall").contains("Status: active");
    let mut published = Vec::new();
    let mut as_root = Vec::new();
    for line in d.lines("containers.docker") {
        let fields: Vec<&str> = line.split('|').collect();
        if fields.len() < 10 {
            continue;
        }
        let name = fields[0].trim_start_matches('/');
        let image = fields[1];
        let mut issue = |severity: Severity, id: &str, title: String, detail: &str, fix: &str| {
            f.add(C, severity, &format!("{id}-{name}"), title).detail(detail).evidence(line).fix(fix);
        };
        if fields[2] == "true" {
            issue(High, "privileged", format!("Container {name} runs privileged"), "A privileged container can take over the host.", "Drop --privileged and add only the capabilities it needs.");
        }
        if fields[3] == "host" {
            issue(Low, "host-network", format!("Container {name} shares the host network"), "It sees and binds every interface of the host.", "Use a bridge network and publish only the ports needed.");
        }
        if fields[4] == "host" {
            issue(Medium, "host-pid", format!("Container {name} shares the host processes"), "It can see and signal every process of the host.", "Remove --pid=host.");
        }
        let mounts: Vec<&str> = fields[5].split(',').filter(|mount| !mount.is_empty()).collect();
        if mounts.iter().any(|mount| mount.contains("docker.sock") || mount.contains("containerd.sock")) {
            issue(High, "socket-mount", format!("Container {name} has the container engine socket"), "Whoever controls the container controls the host.", "Remove the socket mount or use a filtering proxy.");
        }
        if mounts.iter().any(|mount| {
            let parts: Vec<&str> = mount.split(':').collect();
            parts.len() >= 3 && ["/", "/etc", "/root", "/boot", "/usr"].contains(&parts[0]) && parts[2] == "true"
        }) {
            issue(High, "host-mount", format!("Container {name} can write system folders of the host"), "A writable /, /etc or /root mount lets it take over the host.", "Mount these read-only or not at all.");
        }
        if fields[6].contains("SYS_ADMIN") || fields[6].contains("ALL") {
            issue(High, "caps", format!("Container {name} has SYS_ADMIN or every capability"), "That is almost as strong as --privileged.", "Remove --cap-add SYS_ADMIN/ALL.");
        }
        if fields[9].contains("unconfined") {
            issue(Medium, "unconfined", format!("Container {name} runs without seccomp or AppArmor"), "Its kernel attack surface is unfiltered.", "Remove the unconfined security options.");
        }
        if fields[7].is_empty() || fields[7] == "root" || fields[7] == "0" {
            as_root.push(format!("{name} ({image})"));
        }
        for binding in fields[8].split_whitespace() {
            if binding.starts_with("0.0.0.0:") || binding.starts_with(":::") || binding.starts_with("::") || binding.starts_with(':') {
                published.push(format!("{name}: {binding}"));
            }
        }
    }
    if !as_root.is_empty() {
        f.add(C, Low, "root-user", format!("{} containers run as root", as_root.len())).detail("An escape from a root container lands as root on the host.").evidence(as_root.join("\n")).fix("Set USER in the image or --user when starting it.");
    }
    if !published.is_empty() {
        let (severity, detail) = if ufw { (Medium, "Docker writes its own iptables rules: these ports are reachable even though ufw would block them.") } else { (Info, "These ports are published on every interface of the host.") };
        f.add(C, severity, "published", format!("{} container ports are published on every interface", published.len())).detail(detail).evidence(published.join("\n")).fix("Publish on 127.0.0.1 (-p 127.0.0.1:port:port) what only a local proxy uses.");
    }
    let daemon = d.get("containers.daemon");
    if daemon.contains("tcp://") && !daemon.contains("tlsverify") {
        f.add(C, Critical, "daemon-tcp", "The Docker daemon listens on TCP without TLS verification").evidence(daemon).fix("Remove the tcp:// host or turn on tlsverify.");
    }
    let images: Vec<&str> = d.lines("containers.images").filter(|line| line.contains("months") || line.contains("years")).collect();
    if !images.is_empty() {
        f.add(C, Low, "old-images", format!("{} images are months or years old", images.len())).detail("Old images carry old libraries with known vulnerabilities.").evidence(images.join("\n")).fix("Rebuild or pull them again and recreate the containers.");
    }
}

fn logs(d: &Data, f: &mut Findings) {
    const C: &str = "logs";
    let failures: u64 = d.lines("logs.failures").filter_map(|line| line.split_whitespace().nth(1)?.parse::<u64>().ok()).max().unwrap_or(0);
    let defenses = pairs(d.get("logs.defenses"));
    let active = |name: &str| defenses.get(name).is_some_and(|state| state == "active");
    let protected = active("fail2ban") || active("crowdsec");
    if failures > 50 {
        let severity = if protected { Info } else { Medium };
        f.add(C, severity, "brute-force", format!("{failures} failed SSH logins recently"))
            .detail(if protected { "Login guessing is going on; fail2ban or CrowdSec is blocking the sources." } else { "Login guessing is going on and nothing blocks the sources." })
            .evidence(d.get("logs.sources"))
            .fix("Use keys only (PasswordAuthentication no) and install fail2ban or CrowdSec.");
    } else if !protected && d.has("logs.defenses") {
        f.add(C, Low, "no-blocking", "Nothing blocks login guessing").detail("Neither fail2ban nor CrowdSec is running.").fix("sudo apt-get install fail2ban (or CrowdSec)");
    }
    if d.has("logs.defenses") && !active("auditd") {
        f.add(C, Info, "auditd", "auditd is not running").detail("Without it, who changed which file and ran what is not recorded for an investigation.").fix("sudo apt-get install auditd (or dnf install audit) and enable it.");
    }
    let logins: Vec<&str> = d.lines("logs.logins").collect();
    if !logins.is_empty() {
        f.add(C, Info, "logins", "Recent logins").detail("Check that you recognise every source.").evidence(logins.join("\n"));
    }
}

fn secrets(d: &Data, f: &mut Findings) {
    const C: &str = "secrets";
    let found = ls_entries(d.get("secrets.files"));
    // A .pem is often only a certificate: listed, not flagged.
    let open: Vec<String> = found.iter().filter(|(mode, _, path)| others_may(mode, 'r') && !path.ends_with(".pem")).map(|(mode, owner, path)| format!("{mode} {owner} {path}")).collect();
    if !open.is_empty() {
        f.add(C, High, "readable", format!("{} key or credential files are readable by every user", open.len())).evidence(open.join("\n")).fix("chmod 600 <file>");
    }
    if !found.is_empty() {
        f.add(C, Info, "files", format!("{} key or credential files", found.len())).detail("Only their paths were read. Check that each one needs to be on this server.").evidence(found.iter().map(|(mode, owner, path)| format!("{mode} {owner} {path}")).collect::<Vec<_>>().join("\n"));
    }
    let history: Vec<&str> = d.lines("secrets.history").filter(|line| line.split_whitespace().next().and_then(|count| count.parse::<u32>().ok()).is_some_and(|count| count > 0)).collect();
    if !history.is_empty() {
        f.add(C, Medium, "history", "Shell histories hold what looks like passwords or tokens").detail("Lines that match password=, token=, IDENTIFIED BY and similar (counted here, not read).").evidence(history.join("\n")).fix("Rotate those credentials and clear the lines from the history files.");
    }
    let web: Vec<&str> = d.lines("secrets.web").collect();
    if !web.is_empty() {
        f.add(C, High, "web", "Sensitive files inside web folders").detail("Repositories, .env files, dumps and backups under a web root are often downloadable.").evidence(web.join("\n")).fix("Move them out of the web root or deny them in the web server.");
    }
}

// --- CVE matching (OSV.dev) ------------------------------------------------------------------------

struct Package {
    name: String,
    version: String,
}

fn inventory(d: &Data) -> Vec<Package> {
    let mut packages = Vec::new();
    let mut seen = HashSet::new();
    let mut push = |name: &str, version: &str| {
        if !name.is_empty() && !version.is_empty() && seen.insert((name.to_owned(), version.to_owned())) {
            packages.push(Package { name: name.to_owned(), version: version.to_owned() });
        }
    };
    for line in d.lines("packages.dpkg") {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() >= 2 {
            let source = fields.get(2).copied().filter(|name| !name.is_empty()).unwrap_or(fields[0]);
            let version = fields.get(3).copied().filter(|version| !version.is_empty()).unwrap_or(fields[1]);
            push(source, version);
        }
    }
    for line in d.lines("packages.rpm") {
        if let Some((name, version)) = line.split_once('\t')
            && name != "gpg-pubkey"
        {
            push(name, version.strip_prefix("0:").unwrap_or(version));
        }
    }
    for line in d.lines("packages.apk") {
        let token = line.split_whitespace().next().unwrap_or("");
        let parts: Vec<&str> = token.rsplitn(3, '-').collect();
        let origin = line.split('{').nth(1).and_then(|rest| rest.split('}').next());
        if parts.len() == 3 {
            push(origin.unwrap_or(parts[2]), &format!("{}-{}", parts[1], parts[0]));
        }
    }
    packages
}

/// Where a system's advisories come from on OSV.dev. CentOS and Oracle Linux rebuild RHEL and
/// have no feed of their own there: they are matched with RHEL's, marked as approximate.
struct Source {
    ecosystems: Vec<String>,
    approximate: Option<&'static str>,
}

fn rhel(major: &str) -> Vec<String> {
    if major == "7" { vec!["Red Hat:enterprise_linux:7::server".into()] } else { vec![format!("Red Hat:enterprise_linux:{major}::baseos"), format!("Red Hat:enterprise_linux:{major}::appstream")] }
}

fn source(os: &HashMap<String, String>) -> Option<Source> {
    let id = os.get("ID").map_or("", String::as_str);
    let version = os.get("VERSION_ID").map_or("", String::as_str);
    let major = version.split('.').next().unwrap_or("");
    let exact = |ecosystems: Vec<String>| Some(Source { ecosystems, approximate: None });
    match id {
        "wolfi" => return exact(vec!["Wolfi".into()]),
        "chainguard" => return exact(vec!["Chainguard".into()]),
        "opensuse-tumbleweed" => return exact(vec!["openSUSE:Tumbleweed".into()]),
        _ if version.is_empty() => return None,
        _ => {}
    }
    match id {
        "debian" => exact(vec![format!("Debian:{major}")]),
        "ubuntu" => exact(vec![if os.get("VERSION").is_some_and(|text| text.contains("LTS")) { format!("Ubuntu:{version}:LTS") } else { format!("Ubuntu:{version}") }]),
        "alpine" => {
            let minor: Vec<&str> = version.split('.').take(2).collect();
            if minor.len() == 2 { exact(vec![format!("Alpine:v{}", minor.join("."))]) } else { None }
        }
        "rocky" => exact(vec![format!("Rocky Linux:{major}")]),
        "almalinux" => exact(vec![format!("AlmaLinux:{major}")]),
        "rhel" => exact(rhel(major)),
        "centos" | "ol" => Some(Source { ecosystems: rhel(major), approximate: Some("Red Hat Enterprise Linux") }),
        "opensuse-leap" => exact(vec![format!("openSUSE:Leap {version}")]),
        "sles" | "sled" => {
            let release = match version.split_once('.') {
                Some((major, pack)) if pack != "0" => format!("{major} SP{pack}"),
                Some((major, _)) => major.to_owned(),
                None => version.to_owned(),
            };
            exact(["Linux Enterprise Server", "Linux Enterprise Module for Basesystem", "Linux Enterprise Module for Server Applications"].iter().map(|product| format!("SUSE:{product} {release}")).collect())
        }
        "azurelinux" => exact(vec![format!("Azure Linux:{major}")]),
        "openEuler" | "openeuler" => {
            // VERSION="22.03 (LTS-SP3)" names the service pack the ecosystem carries.
            let tag = os.get("VERSION").and_then(|text| text.split('(').nth(1)).and_then(|rest| rest.split(')').next()).filter(|tag| !tag.is_empty());
            exact(vec![tag.map_or_else(|| format!("openEuler:{version}"), |tag| format!("openEuler:{version}-{tag}"))])
        }
        "mageia" => exact(vec![format!("Mageia:{major}")]),
        _ => None,
    }
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder().http_status_as_error(false).timeout_global(Some(Duration::from_secs(30))).build().into()
}

fn answer(response: Result<ureq::http::Response<ureq::Body>, ureq::Error>) -> Result<Value, String> {
    let mut response = response.map_err(|error| format!("OSV.dev: {error}"))?;
    let status = response.status();
    let text = response.body_mut().read_to_string().map_err(|error| format!("OSV.dev: {error}"))?;
    if !status.is_success() {
        return Err(format!("OSV.dev answered {status}"));
    }
    serde_json::from_str(&text).map_err(|error| format!("OSV.dev: {error}"))
}

/// The advisories that affect each package, by index into `packages`, from every ecosystem.
fn query(agent: &ureq::Agent, ecosystems: &[String], packages: &[Package]) -> Result<Vec<(usize, Vec<String>)>, String> {
    const BATCH: usize = 500;
    let pairs: Vec<(usize, &str)> = (0..packages.len()).flat_map(|index| ecosystems.iter().map(move |ecosystem| (index, ecosystem.as_str()))).collect();
    let mut found: BTreeMap<usize, BTreeSet<String>> = BTreeMap::new();
    for chunk in pairs.chunks(BATCH) {
        let queries: Vec<Value> = chunk.iter().map(|(index, ecosystem)| json!({ "package": { "name": packages[*index].name, "ecosystem": ecosystem }, "version": packages[*index].version })).collect();
        let reply = answer(agent.post("https://api.osv.dev/v1/querybatch").header("Content-Type", "application/json").send(json!({ "queries": queries }).to_string()))?;
        for ((index, _), result) in chunk.iter().zip(reply["results"].as_array().into_iter().flatten()) {
            let ids = result["vulns"].as_array().into_iter().flatten().filter_map(|vuln| vuln["id"].as_str().map(str::to_owned));
            found.entry(*index).or_default().extend(ids);
        }
    }
    Ok(found.into_iter().filter(|(_, ids)| !ids.is_empty()).map(|(index, ids)| (index, ids.into_iter().collect())).collect())
}

fn details(agent: &ureq::Agent, ids: &[String]) -> HashMap<String, Value> {
    let found = Mutex::new(HashMap::new());
    let next = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                while let Some(id) = ids.get(next.fetch_add(1, Atomic::Relaxed)) {
                    if let Ok(value) = answer(agent.get(&format!("https://api.osv.dev/v1/vulns/{id}")).call()) {
                        found.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(id.clone(), value);
                    }
                }
            });
        }
    });
    found.into_inner().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The CVSS 3.x base score of a vector.
fn cvss3(vector: &str) -> Option<f64> {
    let metrics: HashMap<&str, &str> = vector.split('/').filter_map(|part| part.split_once(':')).collect();
    let changed = *metrics.get("S")? == "C";
    let av = match *metrics.get("AV")? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return None,
    };
    let ac = match *metrics.get("AC")? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    let pr = match (*metrics.get("PR")?, changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return None,
    };
    let ui = match *metrics.get("UI")? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let impact_of = |key: &str| -> Option<f64> {
        match *metrics.get(key)? {
            "H" => Some(0.56),
            "L" => Some(0.22),
            "N" => Some(0.0),
            _ => None,
        }
    };
    let iss = 1.0 - (1.0 - impact_of("C")?) * (1.0 - impact_of("I")?) * (1.0 - impact_of("A")?);
    let impact = if changed { 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15) } else { 6.42 * iss };
    if impact <= 0.0 {
        return Some(0.0);
    }
    let exploitability = 8.22 * av * ac * pr * ui;
    let base = if changed { (1.08 * (impact + exploitability)).min(10.0) } else { (impact + exploitability).min(10.0) };
    Some((base * 10.0 - 1e-9).ceil() / 10.0)
}

struct Vuln {
    name: String,
    /// What two records about the same flaw share: the CVE when there is one, else the id.
    key: String,
    cves: Vec<String>,
    severity: Severity,
    summary: String,
    fixed: Option<String>,
}

fn vuln(id: &str, value: Option<&Value>, package: &str) -> Vuln {
    let own = id.find("CVE-").map(|start| id[start..].to_owned());
    let Some(value) = value else {
        return Vuln { name: id.to_owned(), key: own.clone().unwrap_or_else(|| id.to_owned()), cves: own.into_iter().collect(), severity: Medium, summary: "(details unavailable)".into(), fixed: None };
    };
    let mut severity = None;
    for entry in value["severity"].as_array().into_iter().flatten() {
        let score = entry["score"].as_str().unwrap_or("");
        if entry["type"].as_str() == Some("CVSS_V3") {
            if let Some(number) = cvss3(score) {
                severity = Some(Severity::from_score(number));
            }
        } else if severity.is_none() {
            severity = Severity::from_word(score);
        }
    }
    let mut fixed = None;
    for affected in value["affected"].as_array().into_iter().flatten().filter(|affected| affected["package"]["name"].as_str() == Some(package)) {
        if severity.is_none() {
            severity = affected["ecosystem_specific"]["urgency"].as_str().or(affected["database_specific"]["severity"].as_str()).and_then(Severity::from_word);
        }
        for range in affected["ranges"].as_array().into_iter().flatten() {
            for event in range["events"].as_array().into_iter().flatten() {
                if let Some(version) = event["fixed"].as_str() {
                    fixed = Some(version.to_owned());
                }
            }
        }
    }
    let severity = severity.or_else(|| value["database_specific"]["severity"].as_str().and_then(Severity::from_word)).unwrap_or(Medium);
    let mut cves: Vec<String> = value["aliases"].as_array().into_iter().flatten().filter_map(Value::as_str).filter(|alias| alias.starts_with("CVE-")).map(str::to_owned).collect();
    if let Some(own) = &own
        && !cves.contains(own)
    {
        cves.insert(0, own.clone());
    }
    // A distribution advisory (RHSA, ALSA, DSA…) often fixes several CVEs at once.
    let name = match (&own, cves.len()) {
        (Some(_), _) | (None, 0) => id.to_owned(),
        (None, 1) => format!("{} ({id})", cves[0]),
        (None, count) => format!("{id} ({}{})", cves[..count.min(3)].join(", "), if count > 3 { format!(" +{}", count - 3) } else { String::new() }),
    };
    let key = if cves.len() == 1 { cves[0].clone() } else { id.to_owned() };
    let summary = value["summary"].as_str().filter(|text| !text.is_empty()).or_else(|| value["details"].as_str()).unwrap_or("").lines().next().unwrap_or("").chars().take(180).collect();
    Vuln { name, key, cves, severity, summary, fixed }
}

/// Matches the installed packages against OSV.dev; also returns every CVE it reported, so the
/// server's own advisories do not repeat them.
fn cves(d: &Data, os: &HashMap<String, String>, f: &mut Findings, progress: &dyn Fn(&str)) -> (Value, HashSet<String>) {
    const C: &str = "cve";
    let mut covered = HashSet::new();
    let packages = inventory(d);
    if packages.is_empty() {
        f.add(C, Info, "none", "No package list to match against CVEs").detail("No dpkg, rpm or apk database could be read.");
        return (json!({ "status": "no packages" }), covered);
    }
    let pretty = os.get("PRETTY_NAME").map_or("this system", String::as_str);
    let Some(source) = source(os) else {
        f.add(C, Info, "unsupported", format!("OSV.dev has no advisories for {pretty}"))
            .detail("OSV.dev covers Debian, Ubuntu, Alpine, RHEL, AlmaLinux, Rocky Linux, CentOS and Oracle Linux (through RHEL), SUSE, openSUSE, Azure Linux, openEuler, Mageia, Wolfi and Chainguard. The server's own security advisories (dnf, yum, zypper) are still used when the Packages check is on.");
        return (json!({ "status": "unsupported" }), covered);
    };
    let ecosystems = source.ecosystems.join(", ");
    progress(&format!("Matching {} packages against OSV.dev…", packages.len()));
    let agent = agent();
    let hits = match query(&agent, &source.ecosystems, &packages) {
        Ok(hits) => hits,
        Err(error) => {
            f.add(C, Info, "failed", "The CVE lookup failed").detail(error.clone()).fix("Check this device's internet connection and run the audit again.");
            return (json!({ "status": "failed", "error": error, "ecosystem": ecosystems }), covered);
        }
    };
    const LIMIT: usize = 1500;
    let ids: Vec<String> = hits.iter().flat_map(|(_, ids)| ids.iter().cloned()).collect::<BTreeSet<_>>().into_iter().take(LIMIT).collect();
    progress(&format!("Reading {} advisories…", ids.len()));
    let known = details(&agent, &ids);
    let manager = manager(d);
    let origin = if source.approximate.is_some() { "osv-approx" } else { "osv" };
    let note = source.approximate.map_or(String::new(), |base| format!(" Matched with {base} advisories: {pretty} rebuilds it, so versions usually line up, but check before acting."));
    // Subpackages built from one source (glibc, glibc-common, glibc-langpack-en) share their
    // advisories: one finding for all of them.
    let mut groups: BTreeMap<String, (Vec<&Package>, Vec<Vuln>)> = BTreeMap::new();
    let mut total = 0;
    for (index, ids) in &hits {
        let package = &packages[*index];
        let mut seen = HashSet::new();
        let mut vulns: Vec<Vuln> = ids.iter().map(|id| vuln(id, known.get(id), &package.name)).filter(|vuln| seen.insert(vuln.key.clone())).collect();
        vulns.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.key.cmp(&b.key)));
        let signature = vulns.iter().map(|vuln| vuln.key.as_str()).collect::<Vec<_>>().join(",");
        let group = groups.entry(signature).or_insert_with(|| (Vec::new(), Vec::new()));
        if group.0.is_empty() {
            total += vulns.len();
            covered.extend(vulns.iter().flat_map(|vuln| vuln.cves.iter().cloned()));
            group.1 = vulns;
        }
        group.0.push(package);
    }
    for (members, vulns) in groups.values() {
        let package = members[0];
        let names: Vec<&str> = members.iter().map(|member| member.name.as_str()).collect();
        // What has no fix yet cannot be acted on today: it weighs one step less.
        let worst = vulns.iter().map(|vuln| if vuln.fixed.is_some() { vuln.severity } else { vuln.severity.lower() }).max().unwrap_or(Info);
        let fixed = vulns.iter().filter_map(|vuln| vuln.fixed.as_deref()).max_by(|a, b| version_cmp(a, b));
        let fixable = vulns.iter().filter(|vuln| vuln.fixed.is_some()).count();
        let lines: Vec<String> = vulns
            .iter()
            .map(|vuln| format!("{:<8} {} — {}{}", vuln.severity.name(), vuln.name, vuln.summary, vuln.fixed.as_deref().map_or(" [no fix yet]".to_owned(), |fixed| format!(" [fixed in {fixed}]"))))
            .collect();
        let related = if names.len() > 1 { format!(" (+{} related)", names.len() - 1) } else { String::new() };
        let affected = if names.len() > 1 { format!(" Affects {}.", names.join(", ")) } else { String::new() };
        f.add(C, worst, &package.name, format!("{} {}{related}: {} known vulnerabilit{}", package.name, package.version, vulns.len(), if vulns.len() == 1 { "y" } else { "ies" }))
            .source(origin)
            .detail(format!("{fixable} of them have a fixed version.{}{affected}{note}", vulns.first().map_or(String::new(), |vuln| format!(" Worst: {} — {}", vuln.name, vuln.summary))))
            .evidence(lines.join("\n"))
            .fix(match fixed {
                Some(fixed) => format!("Upgrade {} to {fixed} or later: {}", names.join(" "), upgrade_command(manager, false)),
                None => "No fixed version is published yet: limit exposure of what uses it and watch for updates.".to_owned(),
            });
    }
    let status = json!({ "status": "done", "ecosystem": ecosystems, "approximate": source.approximate, "packages": packages.len(), "affected": hits.len(), "vulnerabilities": total, "truncated": ids.len() >= LIMIT });
    (status, covered)
}

const ARCHES: &[&str] = &["x86_64", "noarch", "aarch64", "i686", "i386", "ppc64le", "s390x", "armv7hl"];

/// The server's own security advisories (dnf, yum, zypper), read from its package cache: CVEs
/// with the vendor's severity for updates it can already install. No network from this device,
/// and they cover distributions OSV.dev does not (Oracle Linux, Amazon Linux, Fedora…).
fn vendor(d: &Data, covered: &HashSet<String>, f: &mut Findings) -> usize {
    const C: &str = "cve";
    let mut by_package: BTreeMap<String, (String, Vec<(Severity, String)>)> = BTreeMap::new();
    let mut seen = HashSet::new();
    for line in d.lines("packages.advisories") {
        let tokens: Vec<&str> = line.split(|c: char| c.is_whitespace() || c == '|').filter(|token| !token.is_empty()).collect();
        let Some(cve) = tokens.iter().find(|token| token.starts_with("CVE-")) else { continue };
        if covered.contains(*cve) || !seen.insert(cve.to_string()) {
            continue;
        }
        let severity = tokens.iter().find_map(|token| Severity::from_word(token.split('/').next().unwrap_or(token))).unwrap_or(Medium);
        let is_date = |token: &str| token.len() == 10 && token.chars().filter(|c| *c == '-').count() == 2 && token.starts_with(|c: char| c.is_ascii_digit());
        let Some(package) = tokens.iter().skip_while(|token| !token.starts_with("CVE-")).skip(1).find(|token| token.contains('-') && token.chars().any(|c| c.is_ascii_digit()) && !is_date(token) && !token.starts_with("CVE-")) else { continue };
        // dnf and yum name the update (name-epoch:version-release.arch); zypper names the patch.
        let bare = package.rsplit_once('.').filter(|(_, arch)| ARCHES.contains(arch)).map_or(*package, |(rest, _)| rest);
        let parts: Vec<&str> = bare.rsplitn(3, '-').collect();
        let (name, fixed) = if line.contains('|') || parts.len() < 3 { (bare.to_owned(), String::new()) } else { (parts[2].to_owned(), format!("{}-{}", parts[1], parts[0])) };
        let entry = by_package.entry(name).or_insert_with(|| (fixed.clone(), Vec::new()));
        if version_cmp(&fixed, &entry.0) == Ordering::Greater {
            entry.0 = fixed;
        }
        entry.1.push((severity, cve.to_string()));
    }
    let zypper = d.lines("packages.advisories").any(|line| line.contains('|'));
    let mut total = 0;
    for (name, (fixed, mut list)) in by_package {
        list.sort_by_key(|(severity, _)| std::cmp::Reverse(*severity));
        total += list.len();
        let worst = list.first().map_or(Medium, |(severity, _)| *severity);
        f.add(C, worst, &format!("vendor-{name}"), format!("{name}: {} CVE{} fixed by an update not installed yet", list.len(), if list.len() == 1 { "" } else { "s" }))
            .source("vendor")
            .detail("From the distribution's own security advisories, read from the server's package cache.")
            .evidence(list.iter().map(|(severity, cve)| format!("{:<8} {cve}", severity.name())).collect::<Vec<_>>().join("\n"))
            .fix(if zypper { "sudo zypper patch --category security".to_owned() } else if fixed.is_empty() { "sudo dnf upgrade --security".to_owned() } else { format!("Upgrade {name} to {fixed}: sudo dnf upgrade --security (yum on older systems)") });
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(categories: &[&'static str]) -> Options {
        Options { categories: categories.iter().copied().collect(), sudo: false, cve: false, probe: false }
    }

    #[test]
    fn the_audit_is_off_until_turned_on_and_runs_only_the_chosen_checks() {
        assert!(Options::from_settings(&Value::Null).is_err());
        let chosen = Options::from_settings(&json!({ "enabled": true, "categories": { "files": false } })).unwrap();
        assert!(chosen.has("ssh") && !chosen.has("files") && !chosen.has("secrets"));
        let script = script(&chosen);
        assert!(script.contains("S ssh.effective") && !script.contains("S files.suid") && !script.contains("S secrets.files") && !script.contains("sudo -n true"));
        assert!(script.trim_end().ends_with("main </dev/null 2>/dev/null"));
    }

    #[test]
    fn output_becomes_findings() {
        let output = "noise\n@@base.meta\nroot=1\nuser=root\nnow=100\n@@base.os\nID=ubuntu\nVERSION_ID=\"18.04\"\nPRETTY_NAME=\"Ubuntu 18.04\"\n@@base.uname\n5.4.0-1-generic\nx86_64\n@@system.sysctl\nkernel.randomize_va_space=0\n@@ssh.effective\n@@ssh.config\nPermitRootLogin yes\nPasswordAuthentication no\nMatch User x\nPasswordAuthentication yes\n@@accounts.passwd\nroot:x:0:0::/root:/bin/bash\ntoor:x:0:0::/root:/bin/sh\n@@network.listen\ntcp LISTEN 0 128 0.0.0.0:6379 0.0.0.0:* users:((\"redis-server\",pid=1,fd=6))\ntcp LISTEN 0 128 127.0.0.1:5432 0.0.0.0:*\n@@end\n";
        let report = analyze(output, &options(&["system", "ssh", "accounts", "network"]), None, &|_| {});
        let ids: Vec<&str> = report["findings"].as_array().unwrap().iter().map(|finding| finding["id"].as_str().unwrap()).collect();
        for id in ["system.eol", "system.kernel.randomize_va_space", "ssh.permitrootlogin", "accounts.uid0", "network.port-tcp-6379"] {
            assert!(ids.contains(&id), "{id} missing from {ids:?}");
        }
        assert!(!ids.contains(&"ssh.passwordauthentication"), "a Match block does not count");
        assert!(!ids.contains(&"network.port-tcp-5432"), "localhost only");
        assert_eq!(report["findings"][0]["severity"], "critical");
    }

    /// `TERMIO_AUDIT_SCRIPT=<file> cargo test -p termio-core print_script -- --ignored` writes the
    /// full script, to try it on a server by hand: `sh -s < file`.
    #[test]
    #[ignore]
    fn print_script() {
        let all = Options { categories: CATEGORIES.iter().copied().collect(), sudo: true, cve: true, probe: false };
        std::fs::write(std::env::var("TERMIO_AUDIT_SCRIPT").unwrap(), script(&all)).unwrap();
    }

    /// `TERMIO_AUDIT_OUTPUT=<file>` (what the script printed) prints the report, CVE lookup included.
    #[test]
    #[ignore]
    fn analyze_output() {
        let output = std::fs::read_to_string(std::env::var("TERMIO_AUDIT_OUTPUT").unwrap()).unwrap();
        let all = Options { categories: CATEGORIES.iter().copied().collect(), sudo: true, cve: true, probe: false };
        println!("{}", serde_json::to_string_pretty(&analyze(&output, &all, None, &|step| println!("> {step}"))).unwrap());
    }

    #[test]
    fn cvss_scores_match_the_calculator() {
        assert_eq!(cvss3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), Some(9.8));
        assert_eq!(cvss3("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"), Some(7.8));
        assert_eq!(cvss3("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), Some(6.1));
    }

    #[test]
    fn packages_map_to_osv_names() {
        let d = Data::parse("@@packages.dpkg\nlibssl3\t3.0.2-0ubuntu1.10\topenssl\t3.0.2-0ubuntu1.10\nopenssl\t3.0.2-0ubuntu1.10\topenssl\t3.0.2-0ubuntu1.10\n@@packages.apk\nbusybox-1.36.1-r15 x86_64 {busybox} (GPL-2.0-only) [installed]\n");
        let packages = inventory(&d);
        assert_eq!(packages.len(), 2);
        assert_eq!((packages[1].name.as_str(), packages[1].version.as_str()), ("busybox", "1.36.1-r15"));
        let os = pairs("ID=ubuntu\nVERSION_ID=\"22.04\"\nVERSION=\"22.04.3 LTS (Jammy Jellyfish)\"");
        assert_eq!(source(&os).unwrap().ecosystems, ["Ubuntu:22.04:LTS"]);
        let centos = source(&pairs("ID=centos\nVERSION_ID=\"9\"")).unwrap();
        assert_eq!((centos.ecosystems.len(), centos.approximate.is_some()), (2, true));
        assert_eq!(source(&pairs("ID=sles\nVERSION_ID=\"15.5\"")).unwrap().ecosystems[0], "SUSE:Linux Enterprise Server 15 SP5");
        assert_eq!(source(&pairs("ID=openEuler\nVERSION_ID=\"22.03\"\nVERSION=\"22.03 (LTS-SP3)\"")).unwrap().ecosystems, ["openEuler:22.03-LTS-SP3"]);
    }

    #[test]
    fn server_advisories_become_findings_without_repeating_osv() {
        let d = Data::parse("@@packages.advisories\nCVE-2024-0001 Important/Sec. openssl-libs-1:3.0.7-25.el9_3.x86_64\nCVE-2024-0002 Moderate/Sec. openssl-libs-1:3.0.7-27.el9.x86_64\nCVE-2024-0003 Critical/Sec. kernel-5.14.0-427.el9.x86_64\n");
        let mut f = Findings::default();
        let covered: HashSet<String> = ["CVE-2024-0003".to_owned()].into();
        assert_eq!(vendor(&d, &covered, &mut f), 2);
        assert_eq!(f.0.len(), 1);
        assert_eq!((f.0[0].title.as_str(), f.0[0].severity, f.0[0].source), ("openssl-libs: 2 CVEs fixed by an update not installed yet", High, "vendor"));
        assert!(f.0[0].fix.contains("1:3.0.7-27.el9"));
    }
}
