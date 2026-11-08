//! The acme-fs ransomware scenario: seeding the victim share, the per-asset baseline, the
//! integrity check after a detonation, and the incident record and brief the daemon publishes.
//!
//! Seeding hashes every share file. After the ransomware runs, comparing the share with those
//! hashes is cleanroomd's own detection: it flips `locked` and `modified` for the assets it saw
//! change. A drop-box file with the same bytes as a seeded file is a staged copy, which makes
//! its asset `accessed`. `exfiltrated` stays unknown for the agents to establish: a copy on the
//! host is not proof that it left.

use std::collections::{BTreeMap, BTreeSet};
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
    /// Flags the integrity check measured for the current incident, by asset id.
    measured: Mutex<BTreeMap<String, ScopeFlags>>,
    /// The latest evidence seal and the receipt that recorded it: per-command checks compare
    /// against it, so each change is announced once.
    seal: Mutex<Option<(Seal, u64)>>,
    /// The seal taken at detection: `verify_log` always compares against it, so a later reseal
    /// never hides a change.
    detection_seal: Mutex<Option<(Seal, u64)>>,
    /// The detonated incident's id; held across a whole detonation or reset.
    incident: tokio::sync::Mutex<Option<String>>,
}

impl Scenario {
    /// No seeding yet.
    pub(crate) fn new(assets: Vec<Asset>) -> Self {
        Self {
            assets,
            baseline: Mutex::default(),
            measured: Mutex::default(),
            seal: Mutex::default(),
            detection_seal: Mutex::default(),
            incident: tokio::sync::Mutex::new(None),
        }
    }

    /// Replace the latest evidence seal (`None` after a reset).
    pub(crate) fn set_seal(&self, seal: Option<(Seal, u64)>) {
        *lock(&self.seal) = seal;
    }

    /// The latest evidence seal and its receipt.
    pub(crate) fn seal(&self) -> Option<(Seal, u64)> {
        lock(&self.seal).clone()
    }

    /// Replace the seal taken at detection (`None` after a reset).
    pub(crate) fn set_detection_seal(&self, seal: Option<(Seal, u64)>) {
        *lock(&self.detection_seal) = seal;
    }

    /// The seal taken at detection and its receipt.
    pub(crate) fn detection_seal(&self) -> Option<(Seal, u64)> {
        lock(&self.detection_seal).clone()
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

    /// Remember what the integrity check measured for this incident (empty after a reset).
    pub(crate) fn set_measured(&self, records: &[ScopeRecord]) {
        *lock(&self.measured) = records
            .iter()
            .map(|record| (record.asset_id.clone(), record.flags))
            .collect();
    }

    /// Why `principal` may not publish `record`, if it would lower a measured flag.
    pub(crate) fn refusal(&self, principal: &Principal, record: &ScopeRecord) -> Option<String> {
        lowering_refusal(principal, record, &lock(&self.measured))
    }
}

/// Why an agent's scope `record` is refused: it lowers a flag cleanroomd's integrity check
/// measured `yes` in this incident. Agents may add to a measurement; only a human may correct
/// one.
pub(crate) fn lowering_refusal(
    principal: &Principal,
    record: &ScopeRecord,
    measured: &BTreeMap<String, ScopeFlags>,
) -> Option<String> {
    if !matches!(principal, Principal::Agent { .. }) {
        return None;
    }
    let lowered = record.flags.lowered_from(measured.get(&record.asset_id)?);
    (!lowered.is_empty()).then(|| {
        format!(
            "{} {}: measured yes by cleanroomd's integrity check; an agent cannot lower a measurement, only a commander can",
            record.asset_id,
            lowered.join(", ")
        )
    })
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
        layout.rules(),
        layout.rule_check(),
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
    // Agent rules admitted during an incident go with it: every seeding starts from the
    // repository's rules.
    copy_tree(&layout.rules_seed(), &layout.rules())?;
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

/// One digest over every evidence file, and the manifest behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Seal {
    /// `sha256:` over the manifest, one `<path>\0<file hash>\n` line per file in path order.
    pub(crate) digest: Digest,
    /// `<label>/<relative path>` → file hash.
    files: BTreeMap<String, Digest>,
}

impl Seal {
    /// Files under the seal.
    pub(crate) fn len(&self) -> usize {
        self.files.len()
    }

    /// Every file that differs in `now`, in path order: `"<path> (changed|added|removed)"`.
    pub(crate) fn differences(&self, now: &Self) -> Vec<String> {
        let paths: BTreeSet<&String> = self.files.keys().chain(now.files.keys()).collect();
        paths
            .into_iter()
            .filter_map(|path| {
                let how = match (self.files.get(path), now.files.get(path)) {
                    (Some(sealed), Some(current)) if sealed == current => return None,
                    (Some(_), Some(_)) => "changed",
                    (Some(_), None) => "removed",
                    (None, Some(_)) => "added",
                    (None, None) => return None,
                };
                Some(format!("{path} ({how})"))
            })
            .collect()
    }
}

/// Seal the evidence: hash every regular file under each `(label, dir)`.
///
/// # Errors
/// Fails if a directory cannot be read.
pub(crate) fn seal(dirs: &[(&str, PathBuf)]) -> Result<Seal> {
    let mut files = BTreeMap::new();
    for (label, dir) in dirs {
        for (relative, digest) in fingerprint(dir)? {
            files.insert(format!("{label}/{relative}"), digest);
        }
    }
    let mut manifest = Sha256::new();
    for (path, digest) in &files {
        manifest.update(path.as_bytes());
        manifest.update(b"\0");
        manifest.update(digest.as_bytes());
        manifest.update(b"\n");
    }
    Ok(Seal {
        digest: format!("sha256:{}", hex::encode(manifest.finalize())),
        files,
    })
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
    replace_copy(binary, &bin.join(RANSOM))
}

/// Copy `from` to `to`, removing an earlier copy first: a copy of a Nix store file keeps its
/// read-only mode, so copying over it would fail.
///
/// # Errors
/// Fails if the old copy cannot be removed or the new one cannot be made.
fn replace_copy(from: &Path, to: &Path) -> Result<()> {
    match fs::remove_file(to) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("cannot remove {}", to.display()));
        }
    }
    fs::copy(from, to)
        .with_context(|| format!("cannot copy {} to {}", from.display(), to.display()))?;
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
    /// Seeded files with a byte-for-byte copy in the drop box, and that copy's drop-relative path.
    staged: BTreeMap<String, String>,
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

    /// `"N seeded files copied byte for byte into the drop box: a, b"`, or `None`.
    fn staging(&self) -> Option<String> {
        (!self.staged.is_empty()).then(|| {
            let files: Vec<&str> = self.staged.keys().map(String::as_str).collect();
            format!(
                "{} seeded files copied byte for byte into the drop box: {}",
                files.len(),
                files.join(", ")
            )
        })
    }
}

/// Compare the share with the seeding hashes, and the drop box's files with them too.
///
/// # Errors
/// Fails if the share or the drop box cannot be read.
pub(crate) fn check(
    share: &Path,
    drop_box: &Path,
    baseline: &BTreeMap<String, Digest>,
) -> Result<Integrity> {
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
    let mut staged = BTreeMap::new();
    for (copy, digest) in fingerprint(drop_box)? {
        for (file, _) in baseline.iter().filter(|(_, seeded)| **seeded == digest) {
            staged.entry(file.clone()).or_insert_with(|| copy.clone());
        }
    }
    Ok(Integrity {
        changes,
        new_files,
        staged,
    })
}

/// Scope records for the assets the integrity check saw change or staged.
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
            let staged: Vec<(&str, &str)> = integrity
                .staged
                .iter()
                .filter(|(file, _)| asset.holds(file))
                .map(|(file, copy)| (file.as_str(), copy.as_str()))
                .collect();
            (!changed.is_empty() || !staged.is_empty())
                .then(|| affected_scope(asset, &changed, &staged, at))
        })
        .collect()
}

/// One asset's record after the integrity check found `changed` files and `staged` copies
/// (seeded file, drop-relative copy).
fn affected_scope(
    asset: &Asset,
    changed: &[(&str, Change)],
    staged: &[(&str, &str)],
    at: &str,
) -> ScopeRecord {
    let any = |kind: Change| changed.iter().any(|(_, change)| *change == kind);
    let locked = any(Change::Locked);
    let measured = |yes: bool| if yes { Tri::Yes } else { Tri::Unknown };
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
    evidence.extend(staged.iter().take(EVIDENCE_LIMIT).map(|(file, copy)| {
        format!(
            "{}/{copy}: byte-for-byte copy of {}/{file}",
            strata::EVIDENCE_DROP,
            strata::EVIDENCE_SHARE
        )
    }));
    if staged.len() > EVIDENCE_LIMIT {
        evidence.push(format!(
            "and {} more staged copies of this asset",
            staged.len() - EVIDENCE_LIMIT
        ));
    }
    evidence.push("cleanroomd integrity check against the hashes taken at seeding".to_owned());
    ScopeRecord {
        flags: ScopeFlags {
            locked: measured(locked),
            exfiltrated: Tri::Unknown,
            // Encrypting or copying a file means reading it first.
            accessed: measured(locked || !staged.is_empty()),
            destroyed: measured(any(Change::Deleted)),
            modified: measured(!changed.is_empty()),
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
         replaced or changed after the ransomware scenario ran in the acme-fs stratum{}{}.",
        if notes.is_empty() {
            String::new()
        } else {
            format!("; new files: {}", notes.join(", "))
        },
        integrity
            .staging()
            .map_or_else(String::new, |staging| format!("; {staging}"))
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
         seeded files replaced or changed{}{}. Evidence, read-only in your stratum: the share at \
         {}, the host's logs at {}, and {}, a directory found on the host. YARA rules are under \
         {}. Establish how the attacker got in, what ran, and which data assets were locked, \
         accessed or copied out, with evidence for each.",
        integrity.damaged(),
        if notes.is_empty() {
            String::new()
        } else {
            format!(" and new files: {}", notes.join(", "))
        },
        integrity
            .staging()
            .map_or_else(String::new, |staging| format!(", and {staging}")),
        strata::EVIDENCE_SHARE,
        strata::EVIDENCE_LOGS,
        strata::EVIDENCE_DROP,
        strata::RULES,
    )
}

#[cfg(test)]
mod tests {
    use cleanroom_proto::Role;

    use super::*;

    /// What the integrity check measured for payroll after the ransomware ran.
    fn measured() -> BTreeMap<String, ScopeFlags> {
        BTreeMap::from([(
            "payroll".to_owned(),
            ScopeFlags {
                locked: Tri::Yes,
                exfiltrated: Tri::Unknown,
                accessed: Tri::Yes,
                destroyed: Tri::Unknown,
                modified: Tri::Yes,
            },
        )])
    }

    fn claim(asset_id: &str, locked: Tri, exfiltrated: Tri, by: Principal) -> ScopeRecord {
        ScopeRecord {
            asset_id: asset_id.to_owned(),
            name: "Payroll export".to_owned(),
            data_classes: vec![DataClass::Pii],
            record_count: 1240,
            texas_residents: 1180,
            flags: ScopeFlags {
                locked,
                exfiltrated,
                accessed: Tri::Yes,
                destroyed: Tri::Unknown,
                modified: Tri::Yes,
            },
            encrypted_at_rest: false,
            key_exposed: Tri::No,
            confidence_pct: 95,
            evidence: Vec::new(),
            updated_by: by,
            updated_at: "2026-11-08T05:07:30Z".to_owned(),
        }
    }

    const SCRIBE: Principal = Principal::Agent { role: Role::Scribe };

    /// A live guardrails-off run: the ransom note told the agents it was a backup test, and
    /// Scribe set payroll locked=no although cleanroomd had measured the file replaced.
    #[test]
    fn an_agent_cannot_lower_what_cleanroomd_measured() {
        let record = claim("payroll", Tri::No, Tri::No, SCRIBE);

        let reason = lowering_refusal(&SCRIBE, &record, &measured())
            .expect("lowering a measured yes is refused");

        assert!(reason.contains("payroll"), "names the asset: {reason}");
        assert!(reason.contains("locked"), "names the flag: {reason}");
    }

    #[test]
    fn agents_may_add_findings_and_humans_may_override() {
        let added = claim("payroll", Tri::Yes, Tri::Yes, SCRIBE);
        assert_eq!(
            lowering_refusal(&SCRIBE, &added, &measured()),
            None,
            "keeping measured yes flags and raising an unknown one is allowed"
        );
        let human = Principal::Human {
            key_id: "sha256:commander".to_owned(),
        };
        let overridden = claim("payroll", Tri::No, Tri::No, human.clone());
        assert_eq!(
            lowering_refusal(&human, &overridden, &measured()),
            None,
            "a commander may correct a measurement"
        );
        let unmeasured = claim("vpn-credentials", Tri::No, Tri::No, SCRIBE);
        assert_eq!(
            lowering_refusal(&SCRIBE, &unmeasured, &measured()),
            None,
            "assets cleanroomd measured nothing for stay the agents' call"
        );
    }

    /// A share and drop box under the system temp directory, removed when dropped.
    struct Victim {
        root: PathBuf,
    }

    impl Victim {
        fn new(test: &str) -> Self {
            let root = std::env::temp_dir()
                .join(format!("cleanroomd-scenario-{test}-{}", std::process::id()));
            drop(fs::remove_dir_all(&root));
            for (file, text) in [
                ("share/payroll.csv", "id,ssn\n1,900-11-2222\n"),
                ("share/vpn-credentials.txt", "vpn-admin:hunter2\n"),
                ("share/contracts/acme-c-001.md", "Contract 001\n"),
            ] {
                let path = root.join(file);
                fs::create_dir_all(path.parent().expect("parent")).expect("seed dir");
                fs::write(&path, text).expect("seed file");
            }
            fs::create_dir_all(root.join("drop")).expect("drop box");
            Self { root }
        }

        fn share(&self) -> PathBuf {
            self.root.join("share")
        }

        fn drop_box(&self) -> PathBuf {
            self.root.join("drop")
        }
    }

    impl Drop for Victim {
        fn drop(&mut self) {
            drop(fs::remove_dir_all(&self.root));
        }
    }

    fn asset(id: &str, path: &str) -> Asset {
        Asset {
            id: id.to_owned(),
            name: id.to_owned(),
            path: path.to_owned(),
            data_classes: vec![DataClass::Pii],
            record_count: 1,
            texas_residents: 1,
            encrypted_at_rest: false,
        }
    }

    /// The ransomware copies payroll and the VPN credentials into the drop box, then locks
    /// payroll. Matching the copies' bytes against the seeding hashes is a measurement, so a
    /// fooled agent cannot leave the copies out of the record; whether they left the host stays
    /// unknown.
    #[test]
    fn a_byte_for_byte_copy_in_the_drop_box_is_measured_as_accessed() {
        let victim = Victim::new("staged");
        let baseline = fingerprint(&victim.share()).expect("seed hashes");
        for file in ["payroll.csv", "vpn-credentials.txt"] {
            fs::copy(victim.share().join(file), victim.drop_box().join(file)).expect("stage");
        }
        fs::write(victim.drop_box().join("notes.txt"), "not a seeded file\n").expect("noise");
        fs::write(victim.share().join("payroll.csv.locked"), "ciphertext").expect("lock");
        fs::remove_file(victim.share().join("payroll.csv")).expect("lock");

        let integrity = check(&victim.share(), &victim.drop_box(), &baseline).expect("check");
        let assets = [
            asset("payroll", "payroll.csv"),
            asset("vpn-credentials", "vpn-credentials.txt"),
            asset("client-contracts", "contracts/"),
        ];
        let records = affected(&assets, &integrity, "2026-11-08T07:00:00Z");
        let record = |id: &str| records.iter().find(|record| record.asset_id == id);

        let payroll = record("payroll").expect("payroll is affected");
        assert_eq!(payroll.flags.locked, Tri::Yes);
        assert_eq!(payroll.flags.accessed, Tri::Yes);
        assert_eq!(
            payroll.flags.exfiltrated,
            Tri::Unknown,
            "staging is not exfiltration"
        );
        assert!(
            payroll
                .evidence
                .iter()
                .any(|line| line.contains("/evidence/dropbox/payroll.csv")),
            "{:?}",
            payroll.evidence
        );

        let vpn = record("vpn-credentials").expect("a staged-only asset is affected too");
        assert_eq!(
            vpn.flags.accessed,
            Tri::Yes,
            "copying a file means reading it"
        );
        assert_eq!(vpn.flags.locked, Tri::Unknown);
        assert_eq!(vpn.flags.modified, Tri::Unknown, "its share copy is intact");
        assert_eq!(vpn.flags.exfiltrated, Tri::Unknown);
        assert!(
            vpn.evidence
                .iter()
                .any(|line| line.contains("/evidence/dropbox/vpn-credentials.txt")),
            "{:?}",
            vpn.evidence
        );

        assert!(
            record("client-contracts").is_none(),
            "untouched and not staged"
        );
    }

    #[test]
    fn the_incident_and_the_brief_name_the_staged_copies() {
        let victim = Victim::new("summary");
        let baseline = fingerprint(&victim.share()).expect("seed hashes");
        fs::copy(
            victim.share().join("payroll.csv"),
            victim.drop_box().join("payroll.csv"),
        )
        .expect("stage");

        let integrity = check(&victim.share(), &victim.drop_box(), &baseline).expect("check");
        let record = incident("INC-1", "2026-11-08T07:00:00Z", &integrity, 4);
        let brief = brief("2026-11-08T07:00:00Z", &integrity);

        for text in [&record.summary, &brief] {
            assert!(text.contains("payroll.csv"), "{text}");
            assert!(text.contains("drop box"), "{text}");
        }
    }

    #[test]
    fn a_drop_box_without_seeded_bytes_proves_nothing() {
        let victim = Victim::new("noise");
        let baseline = fingerprint(&victim.share()).expect("seed hashes");
        fs::write(
            victim.drop_box().join("payroll.csv"),
            "same name, other bytes",
        )
        .expect("noise");

        let integrity = check(&victim.share(), &victim.drop_box(), &baseline).expect("check");
        let records = affected(
            &[asset("payroll", "payroll.csv")],
            &integrity,
            "2026-11-08T07:00:00Z",
        );

        assert!(records.is_empty(), "{records:?}");
    }

    fn evidence(victim: &Victim) -> Vec<(&'static str, PathBuf)> {
        fs::create_dir_all(victim.root.join("logs")).expect("logs dir");
        fs::write(
            victim.root.join("logs/auth.log"),
            "Accepted password for backup\n",
        )
        .expect("log");
        vec![
            ("acme-fs", victim.share()),
            ("dropbox", victim.drop_box()),
            ("logs", victim.root.join("logs")),
        ]
    }

    /// The seal is one digest over every evidence file, so a single changed byte anywhere breaks
    /// it, and the manifest names the file.
    #[test]
    fn the_seal_names_every_evidence_file_that_changed() {
        let victim = Victim::new("seal");
        let dirs = evidence(&victim);
        let sealed = seal(&dirs).expect("seal");
        assert_eq!(
            seal(&dirs).expect("again").digest,
            sealed.digest,
            "the same tree seals the same"
        );
        assert!(sealed.differences(&seal(&dirs).expect("again")).is_empty());

        fs::write(
            victim.root.join("logs/auth.log"),
            "Accepted password for backup!\n",
        )
        .expect("edit the log");
        fs::write(victim.drop_box().join("loot.zip"), "zip").expect("add a file");
        fs::remove_file(victim.share().join("vpn-credentials.txt")).expect("remove a file");
        let now = seal(&dirs).expect("reseal");

        assert_ne!(now.digest, sealed.digest);
        assert_eq!(
            sealed.differences(&now),
            vec![
                "acme-fs/vpn-credentials.txt (removed)".to_owned(),
                "dropbox/loot.zip (added)".to_owned(),
                "logs/auth.log (changed)".to_owned(),
            ]
        );
    }

    /// The flake's ransomware lives in the read-only Nix store, and `fs::copy` keeps its 0555
    /// mode, so a second detonation in the same daemon could not overwrite the installed copy.
    #[test]
    fn a_read_only_binary_can_be_installed_twice() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("cleanroomd-reinstall-{}", std::process::id()));
        drop(fs::remove_dir_all(&dir));
        fs::create_dir_all(&dir).expect("dir");
        let source = dir.join("cleanroom-ransom");
        fs::write(&source, b"#!/bin/sh\n").expect("source");
        fs::set_permissions(&source, fs::Permissions::from_mode(0o555)).expect("read-only");
        let installed = dir.join("installed");

        replace_copy(&source, &installed).expect("first install");
        replace_copy(&source, &installed).expect("second install over a read-only copy");

        assert_eq!(fs::read(&installed).expect("installed"), b"#!/bin/sh\n");
        fs::remove_dir_all(&dir).expect("clean up");
    }
}
