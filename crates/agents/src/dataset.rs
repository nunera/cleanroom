//! Training-ready tags: one JSON line per agent step, written by the runner (never the model)
//! to `$XDG_STATE_HOME/cleanroom/dataset/<incident>.jsonl`.
//!
//! A tag records the step's shape (long-context read, needle lookup, listing, record writing,
//! planning), what it read and who could have written that (attacker-writable evidence,
//! Cleanroom's own rules, an agent's claim), the model and route, the receipt that proves the
//! command ran, and whether the step is safe to train on. Nothing is trained here: the tags are
//! the data a fine-tune, or a hybrid Mamba/Transformer model whose allocation the agents steer,
//! would learn from. A step is trainable only with guardrails on, when the OS did not deny it
//! and the safety model did not flag what it read.

use std::fs::{DirBuilder, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::PathBuf;

use anyhow::{Context as _, Result};
use serde::Serialize;

use crate::tools::Tool;

/// Output size from which a read counts as long-context (about 2k tokens).
const LONG_CONTEXT_CHARS: usize = 8_000;
/// Cleanroom's own read-only YARA rules.
const RULES_DIR: &str = "/rules";

/// What kind of work a step was.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Shape {
    /// A large file or log read: long-sequence work.
    LongContext,
    /// A small, precise lookup: a short read, a hash, a YARA match.
    NeedleLookup,
    /// A directory listing.
    Listing,
    /// Asking cleanroomd for a tool.
    ToolRequest,
    /// A finding, scope or incident update.
    RecordWriting,
    /// A containment proposal.
    Planning,
    /// Declining an instruction found in untrusted data.
    Refusal,
    /// Reading the live incident summary from the bus.
    Briefing,
    /// Asking a specialist or answering the commander.
    Conversation,
    /// Writing a detection rule for the OS to check and deploy.
    DetectionRule,
}

/// Who could have written what the step read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Provenance {
    /// Evidence on the victim: the attacker could have written it.
    AttackerWritable,
    /// Cleanroom's own read-only inputs.
    Cleanroom,
    /// An agent's claim: written by the step, or read back from agents' records and answers.
    AgentClaim,
}

/// The shape of one step.
pub(crate) const fn shape(tool: Tool, output_chars: usize) -> Shape {
    match tool {
        Tool::ReadFile | Tool::GrepLogs | Tool::Exec if output_chars >= LONG_CONTEXT_CHARS => {
            Shape::LongContext
        }
        Tool::ReadFile | Tool::GrepLogs | Tool::Exec | Tool::HashFile | Tool::YaraScan => {
            Shape::NeedleLookup
        }
        Tool::ListFiles => Shape::Listing,
        Tool::RequestAdmission => Shape::ToolRequest,
        Tool::ReportFinding | Tool::UpdateScope | Tool::UpdateIncident => Shape::RecordWriting,
        Tool::ProposeAction => Shape::Planning,
        Tool::ReportRefusal => Shape::Refusal,
        Tool::GetSituation => Shape::Briefing,
        Tool::AskAgent | Tool::Reply => Shape::Conversation,
        Tool::SubmitRule => Shape::DetectionRule,
    }
}

/// Who could have written what `tool` read at `subject`.
pub(crate) fn provenance(tool: Tool, subject: &str) -> Provenance {
    let ours = subject == RULES_DIR || subject.starts_with(&format!("{RULES_DIR}/"));
    match tool {
        Tool::ReadFile | Tool::GrepLogs | Tool::ListFiles | Tool::HashFile | Tool::YaraScan
            if ours =>
        {
            Provenance::Cleanroom
        }
        Tool::ReadFile
        | Tool::GrepLogs
        | Tool::ListFiles
        | Tool::HashFile
        | Tool::YaraScan
        | Tool::Exec => Provenance::AttackerWritable,
        Tool::RequestAdmission
        | Tool::ReportFinding
        | Tool::ReportRefusal
        | Tool::ProposeAction
        | Tool::UpdateScope
        | Tool::UpdateIncident
        | Tool::GetSituation
        | Tool::AskAgent
        | Tool::Reply
        | Tool::SubmitRule => Provenance::AgentClaim,
    }
}

/// Whether a step may be trained on: guardrails on, not denied by the OS, not flagged by the
/// safety model.
pub(crate) const fn trainable(guardrails: bool, denied: bool, flagged: bool) -> bool {
    guardrails && !denied && !flagged
}

/// One tagged step.
#[derive(Debug, Serialize)]
pub(crate) struct Tag {
    /// Incident id.
    pub(crate) incident: String,
    /// When the step finished.
    pub(crate) at: String,
    /// Agent role.
    pub(crate) role: String,
    /// Model call number in the loop.
    pub(crate) step: u32,
    /// The model that chose the step.
    pub(crate) model: String,
    /// `hosted` or `local`.
    pub(crate) route: String,
    /// Tool name.
    pub(crate) tool: String,
    /// What it read or ran.
    pub(crate) subject: String,
    /// Kind of work.
    pub(crate) shape: Shape,
    /// Who could have written its input.
    pub(crate) provenance: Provenance,
    /// Characters of output.
    pub(crate) output_chars: usize,
    /// The cleanroomd receipt of the command, when it ran one.
    pub(crate) receipt: Option<u64>,
    /// The stratum grant denied it.
    pub(crate) denied: bool,
    /// The safety model flagged its input.
    pub(crate) flagged: bool,
    /// Guardrails were on.
    pub(crate) guardrails: bool,
    /// Safe to train on.
    pub(crate) trainable: bool,
    /// `sha256:` of the model request that chose this step (the record/replay cache key), so an
    /// export can find the exact request and response.
    pub(crate) request: String,
}

/// The dataset directory.
#[derive(Debug)]
pub(crate) struct Dataset {
    /// Where the incident files go.
    dir: PathBuf,
}

impl Dataset {
    /// A dataset rooted at `dir` (created on first write, mode 0700).
    pub(crate) const fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// Append `tag` to its incident's file (mode 0600).
    ///
    /// # Errors
    /// Fails if the directory or file cannot be written.
    pub(crate) fn append(&self, tag: &Tag) -> Result<()> {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dir)
            .with_context(|| format!("cannot create {}", self.dir.display()))?;
        let path = self.dir.join(format!("{}.jsonl", file_stem(&tag.incident)));
        let mut line = serde_json::to_vec(tag).context("cannot encode a tag")?;
        line.push(b'\n');
        OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)
            .and_then(|mut file| file.write_all(&line))
            .with_context(|| format!("cannot write {}", path.display()))
    }
}

/// A file name for an incident id that came off the bus: letters, digits, `-` and `_` only.
pub(crate) fn file_stem(incident: &str) -> String {
    let stem: String = incident
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if stem.is_empty() {
        "unnamed".to_owned()
    } else {
        stem
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn steps_are_shaped_by_what_the_tool_does_and_how_much_it_read() {
        assert_eq!(
            shape(Tool::ReadFile, 40_000),
            Shape::LongContext,
            "a big file read"
        );
        assert_eq!(
            shape(Tool::GrepLogs, 30_000),
            Shape::LongContext,
            "a big log sweep"
        );
        assert_eq!(
            shape(Tool::ReadFile, 900),
            Shape::NeedleLookup,
            "a small file read"
        );
        assert_eq!(shape(Tool::HashFile, 80), Shape::NeedleLookup);
        assert_eq!(shape(Tool::ListFiles, 2_000), Shape::Listing);
        assert_eq!(shape(Tool::UpdateScope, 0), Shape::RecordWriting);
        assert_eq!(shape(Tool::ProposeAction, 0), Shape::Planning);
        assert_eq!(
            shape(Tool::GetSituation, 20_000),
            Shape::Briefing,
            "not long-context evidence"
        );
        assert_eq!(shape(Tool::AskAgent, 0), Shape::Conversation);
        assert_eq!(shape(Tool::Reply, 0), Shape::Conversation);
    }

    #[test]
    fn provenance_says_who_could_have_written_what_the_step_read() {
        assert_eq!(
            provenance(Tool::ReadFile, "/evidence/acme-fs/README_RESTORE_FILES.txt"),
            Provenance::AttackerWritable
        );
        assert_eq!(
            provenance(Tool::Exec, "cat /evidence/logs/auth.log"),
            Provenance::AttackerWritable,
            "a shell reads whatever it is pointed at"
        );
        assert_eq!(
            provenance(Tool::ReadFile, "/rules/cleanroom-ransomware.yar"),
            Provenance::Cleanroom
        );
        assert_eq!(provenance(Tool::ReportFinding, ""), Provenance::AgentClaim);
    }

    /// Never train on an action the kernel had to block, on a context the safety model
    /// flagged, or on a run where the guardrails were off.
    #[test]
    fn only_clean_guarded_steps_are_trainable() {
        assert!(trainable(true, false, false));
        assert!(!trainable(true, true, false), "denied by the OS");
        assert!(!trainable(true, false, true), "flagged by the safety model");
        assert!(!trainable(false, false, false), "guardrails off");
    }

    fn scratch() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        std::env::temp_dir().join(format!("cleanroom-dataset-{}-{nanos}", std::process::id()))
    }

    fn tag(incident: &str) -> Tag {
        Tag {
            incident: incident.to_owned(),
            at: "2026-11-08T07:20:00Z".to_owned(),
            role: "hunter".to_owned(),
            step: 3,
            model: "nvidia/nemotron-3.5-lightning-30b-a3b".to_owned(),
            route: "hosted".to_owned(),
            tool: "read_file".to_owned(),
            subject: "/evidence/logs/auth.log".to_owned(),
            shape: Shape::LongContext,
            provenance: Provenance::AttackerWritable,
            output_chars: 30_000,
            receipt: Some(14),
            denied: false,
            flagged: true,
            guardrails: true,
            trainable: false,
            request: "sha256:request".to_owned(),
        }
    }

    #[test]
    fn tags_append_as_json_lines_per_incident_and_stay_inside_the_dataset() {
        let dir = scratch();
        let dataset = Dataset::new(dir.clone());
        dataset
            .append(&tag("INC-20261108-072000"))
            .expect("first line");
        dataset
            .append(&tag("INC-20261108-072000"))
            .expect("second line");
        dataset
            .append(&tag("../../escape"))
            .expect("a hostile id still lands inside");

        let text = fs::read_to_string(dir.join("INC-20261108-072000.jsonl")).expect("file");
        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).expect("each line is JSON"))
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["shape"], "long_context");
        assert_eq!(lines[0]["provenance"], "attacker_writable");
        assert_eq!(lines[0]["receipt"], 14);
        let names: Vec<String> = fs::read_dir(&dir)
            .expect("dataset dir")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert!(
            names
                .iter()
                .all(|name| !name.contains('/') && !name.starts_with('.')),
            "{names:?}"
        );
        assert!(!dir.parent().expect("parent").join("escape.jsonl").exists());
        fs::remove_dir_all(&dir).expect("clean up");
    }
}
