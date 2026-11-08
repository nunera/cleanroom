//! The acme-fs ransomware scenario: seeding the victim share, the per-asset baseline, the
//! integrity check after a detonation, and the incident record and brief the daemon publishes.
//!
//! Seeding hashes every share file. After the ransomware runs, comparing the share with those
//! hashes is cleanroomd's own detection: it flips `locked` and `modified` for the assets it saw
//! change and leaves `exfiltrated` unknown for the agents to establish.

use std::collections::BTreeMap;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context as _, Result, bail};
use cleanroom_proto::{
    DataClass, Digest, IncidentRecord, IncidentStatus, Principal, ScopeFlags, ScopeRecord,
    Severity, TimelineEntry, Tri, Triggers,
};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use walkdir::WalkDir;

use crate::layout::Layout;
use crate::lock;
use crate::strata::{self, VICTIM_BIN, VICTIM_DROP, VICTIM_LOGS, VICTIM_SHARE};

/// Name of the ransomware binary inside the victim stratum.
const RANSOM: &str = "cleanroom-ransom";
/// The scenario this daemon runs; `ransomware-<variant>` runs one of the ransomware's variants.
const RANSOMWARE: &str = "ransomware";
/// How sure the integrity check is about what it flags.
const INTEGRITY_CONFIDENCE: u8 = 90;
/// Evidence paths listed per asset at most.
const EVIDENCE_LIMIT: usize = 4;

/// One data asset on the share, from `scenario/assets.json`.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Asset {
    /// Stable id.
    #[serde(rename = "asset_id")]
    id: String,
    /// Human-readable name.
    name: String,
    /// Path relative to the share root; a trailing `/` makes it a directory.
    path: String,
    /// Kinds of data.
    data_classes: Vec<DataClass>,
    /// Records (rows, people).
    record_count: u64,
    /// Texas residents among them.
    texas_residents: u64,
    /// Encrypted at rest before the incident.
    encrypted_at_rest: bool,
}

impl Asset {
    /// True when the share-relative `file` belongs to this asset.
    fn holds(&self, file: &str) -> bool {
        if self.path.ends_with('/') {
            file.starts_with(&self.path)
        } else {
            file == self.path
        }
    }
}

/// Read `scenario/assets.json`.
///
/// # Errors
/// Fails if the file is missing or not a JSON array of assets.
pub(crate) fn load_assets(path: &Path) -> Result<Vec<Asset>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("{} is not a list of assets", path.display()))
}

/// Scenario state shared by the request handlers.
#[derive(Debug)]
pub(crate) struct Scenario {
    /// Assets from `scenario/assets.json`.
    assets: Vec<Asset>,
    /// Hash of every share file at the last seeding, by share-relative path.
    baseline: Mutex<BTreeMap<String, Digest>>,
    /// The detonated incident's id; held across a whole detonation or reset.
    incident: tokio::sync::Mutex<Option<String>>,
}

impl Scenario {
    /// No seeding yet.
    pub(crate) fn new(assets: Vec<Asset>) -> Self {
        Self {
            assets,
            baseline: Mutex::default(),
            incident: tokio::sync::Mutex::new(None),
        }
    }

    /// The assets.
    pub(crate) fn assets(&self) -> &[Asset] {
        &self.assets
    }

    /// Exclusive access to the detonation state.
    pub(crate) async fn incident(&self) -> tokio::sync::MutexGuard<'_, Option<String>> {
        self.incident.lock().await
    }

    /// Replace the seeding hashes.
    pub(crate) fn set_baseline(&self, baseline: BTreeMap<String, Digest>) {
        *lock(&self.baseline) = baseline;
    }

    /// The seeding hashes.
    pub(crate) fn baseline(&self) -> BTreeMap<String, Digest> {
        lock(&self.baseline).clone()
    }
}

/// An asset as it stands before any incident: every flag `no`.
pub(crate) fn baseline(asset: &Asset, at: &str) -> ScopeRecord {
    ScopeRecord {
        asset_id: asset.id.clone(),
        name: asset.name.clone(),
        data_classes: asset.data_classes.clone(),
        record_count: asset.record_count,
        texas_residents: asset.texas_residents,
        flags: ScopeFlags {
            locked: Tri::No,
            exfiltrated: Tri::No,
            accessed: Tri::No,
            destroyed: Tri::No,
            modified: Tri::No,
        },
        encrypted_at_rest: asset.encrypted_at_rest,
        key_exposed: Tri::No,
        confidence_pct: 100,
        evidence: Vec::new(),
        updated_by: Principal::System,
        updated_at: at.to_owned(),
    }
}

/// Re-seed the share from `scenario/acme-fs`, empty the drop box, logs and scratch
/// directories, and return the share's hashes.
///
/// # Errors
/// Fails if the seed is missing or a directory cannot be rebuilt.
pub(crate) fn reseed(layout: &Layout) -> Result<BTreeMap<String, Digest>> {
    let seed = layout.seed();
    if !seed.is_dir() {
        bail!("no seed share at {}", seed.display());
    }
    let share = layout.share();
    for dir in [
        share.clone(),
        layout.dropbox(),
        layout.logs(),
        layout.scratch_root(),
    ] {
        empty_dir(&dir)?;
    }
    for role in [
        cleanroom_proto::Role::Hunter,
        cleanroom_proto::Role::Forensics,
    ] {
        let scratch = layout.scratch(role);
        fs::create_dir_all(&scratch)
            .with_context(|| format!("cannot create {}", scratch.display()))?;
    }
    copy_tree(&seed, &share)?;
    fingerprint(&share)
}

/// Remove `dir` and create it again, empty.
///
/// # Errors
/// Fails if the directory cannot be removed or created.
fn empty_dir(dir: &Path) -> Result<()> {
    match fs::remove_dir_all(dir) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("cannot remove {}", dir.display()));
        }
    }
    fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))
}

/// Copy the directories and regular files under `from` into `to`.
///
/// # Errors
/// Fails if an entry cannot be read or written.
fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    for entry in WalkDir::new(from).min_depth(1).follow_links(false) {
        let entry = entry.with_context(|| format!("cannot walk {}", from.display()))?;
        let relative = entry
            .path()
            .strip_prefix(from)
            .unwrap_or_else(|_| entry.path());
        let target = to.join(relative);
        let file_type = entry.file_type();
        if file_type.is_dir() {
            fs::create_dir_all(&target)
                .with_context(|| format!("cannot create {}", target.display()))?;
        } else if file_type.is_symlink() {
            tracing::warn!(path = %entry.path().display(), "seed symlinks are not copied");
        } else {
            fs::copy(entry.path(), &target).with_context(|| {
                format!(
                    "cannot copy {} to {}",
                    entry.path().display(),
                    target.display()
                )
            })?;
        }
    }
    Ok(())
}

/// Hash of every regular file under `share`, by share-relative path.
///
/// # Errors
/// Fails if the share cannot be read.
fn fingerprint(share: &Path) -> Result<BTreeMap<String, Digest>> {
    let mut files = BTreeMap::new();
    for (relative, path) in files_under(share)? {
        let bytes = fs::read(&path).with_context(|| format!("cannot read {}", path.display()))?;
        files.insert(
            relative,
            format!("sha256:{}", hex::encode(Sha256::digest(&bytes))),
        );
    }
    Ok(files)
}

/// Regular files under `root` as `(share-relative path, full path)`.
///
/// # Errors
/// Fails if the tree cannot be walked.
fn files_under(root: &Path) -> Result<Vec<(String, PathBuf)>> {
    let mut files = Vec::new();
    for entry in WalkDir::new(root).min_depth(1).sort_by_file_name() {
        let entry = entry.with_context(|| format!("cannot walk {}", root.display()))?;
        if entry.file_type().is_dir() || entry.file_type().is_symlink() {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(root)
            .unwrap_or_else(|_| entry.path())
            .to_string_lossy()
            .into_owned();
        files.push((relative, entry.path().to_owned()));
    }
    Ok(files)
}

/// The ransomware's own account of the run (its stdout), used for the operator's status line.
#[derive(Debug, Deserialize)]
pub(crate) struct Summary {
    /// Share-relative paths it encrypted.
    pub(crate) locked: Vec<String>,
    /// Share-relative paths it copied to the drop box.
    pub(crate) exfiltrated: Vec<String>,
    /// The ransom note's file name.
    pub(crate) note: String,
}

/// Parse the summary line `cleanroom-ransom detonate` prints.
///
/// # Errors
/// Fails if no output line is a summary.
pub(crate) fn parse_summary(stdout: &str) -> Result<Summary> {
    stdout
        .lines()
        .rev()
        .find(|line| line.trim_start().starts_with('{'))
        .context("the ransomware printed no summary")
        .and_then(|line| serde_json::from_str(line).context("the ransomware summary is malformed"))
}

/// Where the ransomware binary comes from: `CLEANROOM_RANSOM_BIN`, else the static musl build
/// in the repository's `target/`.
///
/// # Errors
/// Fails if no binary is found.
pub(crate) fn find_ransom(layout: &Layout) -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("CLEANROOM_RANSOM_BIN").filter(|value| !value.is_empty()) {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
        bail!("CLEANROOM_RANSOM_BIN={} is not a file", path.display());
    }
    let target = layout.repo.join("target/x86_64-unknown-linux-musl");
    ["release", "debug"]
        .into_iter()
        .map(|profile| target.join(profile).join(RANSOM))
        .find(|path| path.is_file())
        .with_context(|| {
            format!(
                "no static {RANSOM} under {}; build it for x86_64-unknown-linux-musl (see \
                 crates/ransom/Cargo.toml) or set CLEANROOM_RANSOM_BIN",
                target.display()
            )
        })
}

/// Copy the ransomware into `run/bin`, the directory bound at `/opt/cleanroom/bin`.
///
/// # Errors
/// Fails if the copy cannot be made.
pub(crate) fn install_ransom(layout: &Layout, binary: &Path) -> Result<()> {
    let bin = layout.bin();
    fs::create_dir_all(&bin).with_context(|| format!("cannot create {}", bin.display()))?;
    let installed = bin.join(RANSOM);
    fs::copy(binary, &installed).with_context(|| {
        format!(
            "cannot copy {} to {}",
            binary.display(),
            installed.display()
        )
    })?;
    Ok(())
}

/// The detonation command inside the victim stratum for `scenario`: `ransomware`, or
/// `ransomware-<variant>`, which passes `--variant=<variant>` (the ransomware checks the name).
///
/// # Errors
/// Fails for any other scenario name.
pub(crate) fn detonation_argv(scenario: &str) -> Result<Vec<String>> {
    let variant = scenario
        .strip_prefix(RANSOMWARE)
        .and_then(|rest| match rest.strip_prefix('-') {
            None if rest.is_empty() => Some(None),
            Some(name) if !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_lowercase()) => {
                Some(Some(name))
            }
            Some(_) | None => None,
        })
        .with_context(|| {
            format!("unknown scenario {scenario}; this cleanroomd runs {RANSOMWARE} and {RANSOMWARE}-<variant>")
        })?;
    let mut argv: Vec<String> = [
        &format!("{VICTIM_BIN}/{RANSOM}"),
        "detonate",
        "--share",
        VICTIM_SHARE,
        "--drop",
        VICTIM_DROP,
        "--logs",
        VICTIM_LOGS,
    ]
    .map(str::to_owned)
    .into();
    argv.extend(variant.map(|name| format!("--variant={name}")));
    Ok(argv)
}

/// How a seeded file looks after a detonation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Change {
    /// Same bytes.
    Intact,
    /// Different bytes.
    Modified,
    /// Gone, with a `.locked` copy beside it.
    Locked,
    /// Gone.
    Deleted,
}

/// The share compared with the seeding hashes.
#[derive(Debug)]
pub(crate) struct Integrity {
    /// Every seeded file and what happened to it.
    changes: BTreeMap<String, Change>,
    /// Files that were not seeded (ransom note, `.locked` copies).
    new_files: Vec<String>,
}

impl Integrity {
    /// Seeded files that are no longer intact.
    fn damaged(&self) -> usize {
        self.changes
            .values()
            .filter(|change| **change != Change::Intact)
            .count()
    }

    /// New files other than `.locked` copies, such as a ransom note.
    fn notes(&self) -> impl Iterator<Item = &str> {
        self.new_files
            .iter()
            .map(String::as_str)
            .filter(|file| !file.ends_with(".locked"))
    }
}

/// Compare the share with the seeding hashes.
///
/// # Errors
/// Fails if the share cannot be read.
pub(crate) fn check(share: &Path, baseline: &BTreeMap<String, Digest>) -> Result<Integrity> {
    let current = fingerprint(share)?;
    let changes = baseline
        .iter()
        .map(|(file, seeded)| {
            let change = match current.get(file) {
                Some(now) if now == seeded => Change::Intact,
                Some(_) => Change::Modified,
                None if current.contains_key(&format!("{file}.locked")) => Change::Locked,
                None => Change::Deleted,
            };
            (file.clone(), change)
        })
        .collect();
    let new_files = current
        .into_keys()
        .filter(|file| !baseline.contains_key(file))
        .collect();
    Ok(Integrity { changes, new_files })
}

/// Scope records for the assets the integrity check saw change.
pub(crate) fn affected(assets: &[Asset], integrity: &Integrity, at: &str) -> Vec<ScopeRecord> {
    assets
        .iter()
        .filter_map(|asset| {
            let changed: Vec<(&str, Change)> = integrity
                .changes
                .iter()
                .filter(|(file, change)| asset.holds(file) && **change != Change::Intact)
                .map(|(file, change)| (file.as_str(), *change))
                .collect();
            (!changed.is_empty()).then(|| affected_scope(asset, &changed, at))
        })
        .collect()
}

/// One asset's record after the integrity check found `changed` files.
fn affected_scope(asset: &Asset, changed: &[(&str, Change)], at: &str) -> ScopeRecord {
    let any = |kind: Change| changed.iter().any(|(_, change)| *change == kind);
    let locked = any(Change::Locked);
    let mut evidence: Vec<String> = changed
        .iter()
        .take(EVIDENCE_LIMIT)
        .map(|(file, change)| match change {
            Change::Locked => format!("{}/{file}.locked", strata::EVIDENCE_SHARE),
            Change::Intact | Change::Modified | Change::Deleted => {
                format!("{}/{file}", strata::EVIDENCE_SHARE)
            }
        })
        .collect();
    if changed.len() > EVIDENCE_LIMIT {
        evidence.push(format!(
            "and {} more files of this asset",
            changed.len() - EVIDENCE_LIMIT
        ));
    }
    evidence.push("cleanroomd integrity check against the hashes taken at seeding".to_owned());
    ScopeRecord {
        flags: ScopeFlags {
            locked: if locked { Tri::Yes } else { Tri::Unknown },
            exfiltrated: Tri::Unknown,
            // Encrypting a file means reading it first.
            accessed: if locked { Tri::Yes } else { Tri::Unknown },
            destroyed: if any(Change::Deleted) {
                Tri::Yes
            } else {
                Tri::Unknown
            },
            modified: Tri::Yes,
        },
        key_exposed: if asset.encrypted_at_rest {
            Tri::Unknown
        } else {
            Tri::No
        },
        confidence_pct: INTEGRITY_CONFIDENCE,
        evidence,
        ..baseline(asset, at)
    }
}

/// `INC-<yyyymmdd>-<hhmmss>` from an RFC 3339 timestamp.
pub(crate) fn incident_id(at: &str) -> String {
    let digits: String = at.chars().filter(char::is_ascii_digit).take(14).collect();
    let (date, time) = digits.split_at_checked(8).unwrap_or((&digits, ""));
    format!("INC-{date}-{time}")
}

/// The incident record cleanroomd opens after a detonation.
pub(crate) fn incident(id: &str, at: &str, integrity: &Integrity, receipt: u64) -> IncidentRecord {
    let damaged = integrity.damaged();
    let seeded = integrity.changes.len();
    let notes: Vec<&str> = integrity.notes().collect();
    let summary = format!(
        "cleanroomd's integrity check found {damaged} of {seeded} seeded files on the acme-fs share \
         replaced or changed after the ransomware scenario ran in the acme-fs stratum{}.",
        if notes.is_empty() {
            String::new()
        } else {
            format!("; new files: {}", notes.join(", "))
        }
    );
    IncidentRecord {
        id: id.to_owned(),
        title: "Ransomware on the acme-fs file share".to_owned(),
        status: IncidentStatus::Detected,
        severity: Severity::High,
        category: "ransomware".to_owned(),
        detected_at: at.to_owned(),
        reported_by: Principal::System,
        summary: summary.clone(),
        affected_systems: vec![strata::VICTIM.to_owned()],
        triggers: Triggers::default(),
        timeline: vec![TimelineEntry {
            at: at.to_owned(),
            by: Principal::System,
            text: summary,
            evidence: notes
                .iter()
                .map(|note| format!("{}/{note}", strata::EVIDENCE_SHARE))
                .chain(std::iter::once(format!("receipt #{receipt} (detonate)")))
                .collect(),
        }],
    }
}

/// The brief for the agent team: what happened and where the evidence is.
pub(crate) fn brief(at: &str, integrity: &Integrity) -> String {
    let notes: Vec<&str> = integrity.notes().collect();
    format!(
        "Ransomware hit the acme-fs file share. At {at} cleanroomd's integrity check found {} \
         seeded files replaced or changed{}. Evidence, read-only in your stratum: the share at \
         {}, the host's logs at {}, and {}, a directory found on the host. YARA rules are under \
         {}. Establish how the attacker got in, what ran, and which data assets were locked, \
         accessed or copied out, with evidence for each.",
        integrity.damaged(),
        if notes.is_empty() {
            String::new()
        } else {
            format!(" and new files: {}", notes.join(", "))
        },
        strata::EVIDENCE_SHARE,
        strata::EVIDENCE_LOGS,
        strata::EVIDENCE_DROP,
        strata::RULES,
    )
}
