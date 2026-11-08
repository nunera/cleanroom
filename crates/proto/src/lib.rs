//! Wire types shared by `cleanroomd` (OS core), the Nemotron agents and the TUI.
//!
//! Every value here crosses a process boundary as JSON. Frames travel over one
//! Unix socket as newline-delimited JSON; see `docs/interfaces.md` for the
//! transport, signing rules and examples.
//!
//! Field-level meaning lives in `docs/interfaces.md`; names here mirror the JSON keys one-to-one.
#![allow(
    missing_docs,
    reason = "wire contract; docs/interfaces.md documents fields and the names mirror JSON keys. \
              `allow`, not `expect`: missing_docs is only enabled under the strict Clippy profile"
)]

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Protocol version carried in every [`Envelope`].
pub const WIRE_VERSION: u32 = 1;

/// `sha256:` followed by 64 lowercase hex digits.
pub type Digest = String;
/// [`Digest`] of the raw 32-byte Ed25519 public key.
pub type KeyId = String;
/// RFC 3339 UTC timestamp, for example `2026-11-08T01:23:45Z`.
pub type Timestamp = String;

/// Signing domains. A signature covers `domain || "\n" || sha256(JCS(body))`
/// as lowercase hex, so a signature for one record kind cannot be replayed as another.
pub mod domain {
    pub const BUS: &str = "cleanroom/v1/bus";
    pub const RECEIPT: &str = "cleanroom/v1/receipt";
    pub const ENROLL: &str = "cleanroom/v1/enroll";
    pub const APPROVAL: &str = "cleanroom/v1/approval";
    pub const ROOT_LOCK: &str = "cleanroom/v1/root-lock";
}

/// A record plus its Ed25519 signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed<T> {
    /// One of the [`domain`] constants.
    pub domain: String,
    pub body: T,
    pub signer: KeyId,
    /// 64-byte Ed25519 signature, lowercase hex.
    pub sig: String,
}

/// Agent roles. Each role runs in its own stratum with its own [`Grant`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Hunter,
    Forensics,
    Scribe,
    Containment,
}

/// Who did or said something.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Principal {
    Agent {
        role: Role,
    },
    Human {
        key_id: KeyId,
    },
    /// `cleanroomd` itself (admission, scenario runner, log verifier).
    System,
}

// ---------- Strata and grants ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MountMode {
    ReadOnly,
    ReadWrite,
    /// Writes only through `cleanroomd` (incident record, evidence log).
    AppendOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mount {
    pub host: String,
    pub guest: String,
    pub mode: MountMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Network {
    None,
    /// Host names or `host:port` the stratum may reach. Only the model router gets this.
    Egress {
        allow: Vec<String>,
    },
}

/// Everything a stratum may touch. Anything not granted is denied by the kernel sandbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub stratum: String,
    pub role: Option<Role>,
    /// Manifest digest of the admitted root filesystem.
    pub root: Digest,
    pub mounts: Vec<Mount>,
    pub network: Network,
    /// Tool names materialized into this stratum.
    pub tools: Vec<String>,
}

// ---------- Tool admission ----------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ToolSource {
    /// Pinned flake reference, for example `github:NixOS/nixpkgs/<rev>#yara`.
    Nix {
        flake_ref: String,
    },
    Oci {
        image: String,
        manifest: Digest,
    },
}

/// An agent asking for a tool it doesn't have.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolRequest {
    pub id: String,
    pub from: Role,
    pub stratum: String,
    pub tool: String,
    pub source: ToolSource,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum ToolDecision {
    /// Matched an allowlist rule; no human needed.
    AutoAllowed {
        rule: String,
    },
    Approved {
        approver: KeyId,
    },
    Denied {
        reason: String,
    },
    /// Outside policy; waiting for a commander signature.
    Pending,
}

// ---------- Command execution ----------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecRequest {
    pub from: Role,
    pub stratum: String,
    pub argv: Vec<String>,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExecOutcome {
    Exited {
        code: i32,
    },
    TimedOut,
    /// Blocked by the grant before or during execution.
    Denied {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecResult {
    pub outcome: ExecOutcome,
    pub stdout: String,
    pub stderr: String,
    /// True when either stream hit the output cap.
    pub truncated: bool,
    /// Sequence number of the receipt that records this execution.
    pub receipt_seq: u64,
}

// ---------- Receipts (hash-chained, signed action log) ----------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Action {
    AdmitRoot { name: String, manifest: Digest },
    Exec { stratum: String, argv: Vec<String> },
    Write { stratum: String, path: String },
    ToolGrant { request_id: String, tool: String },
    Approval { subject_id: String },
    Enroll { member: KeyId },
    RecordUpdate { incident_id: String, field: String },
    Detonate { scenario: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Outcome {
    Allowed,
    Denied { reason: String },
}

/// One log entry. `prev` is the digest of the previous signed receipt (`sha256:` of 64 zeros for the first).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub seq: u64,
    pub prev: Digest,
    pub at: Timestamp,
    pub actor: Principal,
    pub action: Action,
    pub outcome: Outcome,
}

// ---------- Incident record (NIST SP 800-61r3 aligned subset) ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    Detected,
    Analyzing,
    Contained,
    Eradicated,
    Recovered,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Moderate,
    High,
    Critical,
}

/// Start events for legal notification clocks. Each regime counts from a different trigger.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[allow(
    clippy::struct_field_names,
    reason = "each field names a legal trigger event; `allow` because this pedantic lint only runs under the strict profile"
)]
pub struct Triggers {
    /// GDPR Art. 33: 72 hours from awareness.
    pub aware_at: Option<Timestamp>,
    /// HIPAA §164.404: 60 days from discovery.
    pub discovered_at: Option<Timestamp>,
    /// Texas §521.053: 60 days (individuals), 30 days (AG, ≥250 Texans) from breach determination.
    pub breach_determined_at: Option<Timestamp>,
    /// SEC 8-K Item 1.05: 4 business days from materiality determination.
    pub materiality_determined_at: Option<Timestamp>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub at: Timestamp,
    pub by: Principal,
    pub text: String,
    /// Evidence paths or receipt references.
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentRecord {
    pub id: String,
    pub title: String,
    pub status: IncidentStatus,
    pub severity: Severity,
    /// For example `ransomware`, `data_exfiltration`.
    pub category: String,
    pub detected_at: Timestamp,
    pub reported_by: Principal,
    pub summary: String,
    pub affected_systems: Vec<String>,
    pub triggers: Triggers,
    pub timeline: Vec<TimelineEntry>,
}

// ---------- Scope of compromised data ----------

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tri {
    Yes,
    No,
    #[default]
    Unknown,
}

/// Independent flags: one asset can be both locked and exfiltrated.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeFlags {
    pub locked: Tri,
    pub exfiltrated: Tri,
    pub accessed: Tri,
    pub destroyed: Tri,
    pub modified: Tri,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    Pii,
    Phi,
    Financial,
    Contracts,
    Credentials,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeRecord {
    pub asset_id: String,
    pub name: String,
    pub data_classes: Vec<DataClass>,
    pub record_count: u64,
    /// Drives the Texas AG 30-day notice (≥250 residents).
    pub texas_residents: u64,
    pub flags: ScopeFlags,
    pub encrypted_at_rest: bool,
    pub key_exposed: Tri,
    /// 0–100. Integer on purpose: canonical JSON avoids floats.
    pub confidence_pct: u8,
    pub evidence: Vec<String>,
    pub updated_by: Principal,
    pub updated_at: Timestamp,
}

// ---------- Members ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberRole {
    Admin,
    Commander,
    Responder,
    Observer,
}

/// Signed by an admin under [`domain::ENROLL`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    pub key_id: KeyId,
    /// Raw Ed25519 public key, lowercase hex.
    pub public_key: String,
    pub name: String,
    pub role: MemberRole,
    pub enrolled_at: Timestamp,
}

// ---------- Bus ----------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Audience {
    All,
    Role { role: Role },
    Humans,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelRoute {
    /// Self-hosted Nemotron (laptop or Brev). Used for sensitive evidence.
    Local,
    Hosted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BusBody {
    Chat {
        text: String,
    },
    Finding {
        summary: String,
        evidence: Vec<String>,
        confidence_pct: u8,
    },
    /// Containment proposal; needs a commander [`BusBody::Approval`].
    Proposal {
        proposal_id: String,
        action: String,
        rationale: String,
    },
    Approval {
        subject_id: String,
        approved: bool,
    },
    ToolRequest(ToolRequest),
    ToolDecision {
        request_id: String,
        decision: ToolDecision,
    },
    /// One step of an agent's tool-calling loop, for the live trace pane.
    Trace {
        step: u32,
        tool: String,
        args: Value,
        result_preview: String,
    },
    /// Verdict from a Nemotron safety model on an untrusted artifact.
    SafetyVerdict {
        artifact: String,
        model: String,
        safe: bool,
        categories: Vec<String>,
    },
    Route {
        route: ModelRoute,
        reason: String,
    },
    Scope(ScopeRecord),
    Incident(IncidentRecord),
    Status {
        text: String,
    },
}

/// Signed under [`domain::BUS`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BusMessage {
    pub id: String,
    pub at: Timestamp,
    pub from: Principal,
    pub to: Audience,
    pub body: BusBody,
}

// ---------- Daemon requests ----------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum CoreRequest {
    Exec(ExecRequest),
    RequestTool(ToolRequest),
    /// Commander signs a pending tool request or containment proposal.
    Approve {
        subject_id: String,
        approval: Signed<String>,
    },
    Enroll(Signed<Member>),
    Detonate {
        scenario: String,
    },
    /// Corrupts one byte of a staged root copy for the tamper demo.
    Tamper {
        root: String,
    },
    Admit {
        root: String,
    },
    VerifyLog,
    Reset,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum CoreResponse {
    Exec(ExecResult),
    Tool {
        request_id: String,
        decision: ToolDecision,
    },
    Admitted {
        root: String,
        manifest: Digest,
    },
    /// Admission failed; names the first layer whose bytes don't match the lock.
    AdmitRejected {
        root: String,
        layer: Digest,
        expected: Digest,
        actual: Digest,
    },
    LogVerified {
        entries: u64,
        first_break: Option<u64>,
    },
    Ok,
    Error {
        message: String,
    },
}

// ---------- Socket framing ----------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "frame", rename_all = "snake_case")]
pub enum Frame {
    /// First frame from every client.
    Hello {
        principal: Principal,
        subscribe: Vec<Audience>,
    },
    /// Client → daemon: publish to the bus.
    Publish(Signed<BusMessage>),
    /// Daemon → subscribers: a bus message, after signature check.
    Event(Signed<BusMessage>),
    Request {
        id: u64,
        request: CoreRequest,
    },
    Response {
        id: u64,
        response: CoreResponse,
    },
}

/// One line on the socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub v: u32,
    #[serde(flatten)]
    pub frame: Frame,
}
