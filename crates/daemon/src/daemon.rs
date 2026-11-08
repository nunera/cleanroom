//! The daemon's shared state and its operations: every `request` op, checked publishes, and the
//! bus messages cleanroomd signs itself.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, bail};
use cleanroom_proto::sign::{self, key_id, verifying_key_from_hex};
use cleanroom_proto::{
    Action, ApprovalDecision, Audience, BusBody, BusMessage, CoreRequest, CoreResponse,
    ExecOutcome, ExecRequest, ExecResult, KeyId, Member, MemberRole, ModelCall, Outcome, Principal,
    Revocation, Role, RuleSubmission, ScopeRecord, Signed, ToolDecision, ToolRequest, ToolSource,
    domain,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};
use tokio::task::spawn_blocking;

use crate::bus::{Bus, Outbox, Subject};
use crate::citations;
use crate::layout::Layout;
use crate::members::Members;
use crate::reasoning;
use crate::roots::{self, Admitted, Roots, Verdict};
use crate::rules;
use crate::scenario::{self, Scenario};
use crate::strata::{self, Captured, Launch, Placement};
use crate::tools::{self, Granted, Grants, Policy};
use crate::{keys, lock, now, receipts};

/// How long one scan of a submitted rule may run.
const RULE_CHECK_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest reasoning trace stored per model call.
const REASONING_MAX: usize = 256 * 1024;
/// Longest the ransomware may run.
const DETONATION_TIMEOUT: Duration = Duration::from_mins(1);

/// A connected client, as established by its `hello`.
#[derive(Debug)]
pub(crate) struct Peer {
    /// Who it speaks for.
    principal: Principal,
    /// The key that signs its publishes (and a human's approvals and enrollments).
    key: VerifyingKey,
    /// `sha256:` of `key`.
    key_id: KeyId,
}

impl Peer {
    /// Check a `hello`: nobody speaks as cleanroomd, and a human names the key they present.
    ///
    /// # Errors
    /// Fails on a malformed key, a `system` principal, or a human key id that is not the key's.
    pub(crate) fn new(principal: Principal, public_key: &str) -> Result<Self> {
        let key = verifying_key_from_hex(public_key).context("hello carries a malformed key")?;
        let key_id = key_id(&key);
        match &principal {
            Principal::System => bail!("clients cannot speak as cleanroomd"),
            Principal::Human { key_id: claimed } if *claimed != key_id => {
                bail!("hello names human {claimed} but presents key {key_id}")
            }
            Principal::Human { .. } | Principal::Agent { .. } => {}
        }
        Ok(Self {
            principal,
            key,
            key_id,
        })
    }

    /// Short name for logs and status lines.
    pub(crate) fn name(&self) -> String {
        describe(&self.principal)
    }

    /// The agent role this connection speaks for, when it matches `claimed`.
    ///
    /// # Errors
    /// Fails for humans and for agents claiming another role.
    fn role(&self, claimed: Role) -> Result<Role> {
        match self.principal {
            Principal::Agent { role } if role == claimed => Ok(role),
            Principal::Agent { role } => bail!(
                "this connection speaks for {}, not {}",
                strata::stratum_of(role),
                strata::stratum_of(claimed)
            ),
            Principal::Human { .. } | Principal::System => {
                bail!(
                    "only agent runners call this; {} is not an agent",
                    self.name()
                )
            }
        }
    }

    /// Succeeds for humans.
    ///
    /// # Errors
    /// Fails for agents.
    fn human(&self, op: &str) -> Result<()> {
        match self.principal {
            Principal::Human { .. } => Ok(()),
            Principal::Agent { .. } | Principal::System => {
                bail!("{op} is for humans; {} cannot call it", self.name())
            }
        }
    }
}

/// Everything the connections share.
#[derive(Debug)]
pub(crate) struct Daemon {
    /// Paths.
    layout: Layout,
    /// Signs receipts and the daemon's own bus messages.
    key: SigningKey,
    /// Distinguishes this run's message ids from earlier runs.
    session: String,
    /// Next bus message number.
    next_message: AtomicU64,
    /// Subscribers and replay state.
    bus: Bus,
    /// The receipt log.
    receipts: Mutex<receipts::Log>,
    /// Admitted roots.
    roots: Roots,
    /// Which root each stratum runs on.
    placement: Placement,
    /// Tool admission policy.
    policy: Policy,
    /// Tools each role holds.
    grants: Grants,
    /// The acme-fs scenario.
    scenario: Scenario,
    /// Enrolled members.
    members: Mutex<Members>,
    /// The incident agents may write records for: declared by a detonation or a human's
    /// `investigate`, cleared by a reset.
    open_incident: Mutex<Option<String>>,
    /// Every command cleanroomd ran for each investigator in this incident, for citation checks;
    /// cleared by a reset.
    commands: Mutex<HashMap<Role, Vec<String>>>,
}

impl Daemon {
    /// Load keys, the receipt log, the scenario and the tool policy; seed the victim and publish
    /// the baseline; start provisioning standing tool grants in the background.
    ///
    /// # Errors
    /// Fails if a key, the receipt log, `scenario/assets.json`, the seed share or the nixpkgs
    /// pin is unusable.
    pub(crate) async fn start(layout: Layout) -> Result<Arc<Self>> {
        let key = keys::load_or_create(&layout.keys().join("cleanroomd.key"))?;
        let receipts = receipts::Log::open(&layout.receipts())?;
        let assets = scenario::load_assets(&layout.assets())?;
        let policy = Policy::load(&layout.repo)?;
        let members = Members::load(&layout.keys().join("members.ndjson"))?;
        let placement = Placement::from_env()?;
        for root in placement.roots() {
            roots::check_lock(&layout, root)?;
        }
        tracing::info!(%placement, "strata roots");
        let daemon = Arc::new(Self {
            roots: Roots::new(layout.clone()),
            placement,
            layout,
            session: session_tag(),
            next_message: AtomicU64::new(1),
            bus: Bus::default(),
            receipts: Mutex::new(receipts),
            policy,
            grants: Grants::default(),
            scenario: Scenario::new(assets),
            members: Mutex::new(members),
            open_incident: Mutex::default(),
            commands: Mutex::default(),
            key,
        });
        tracing::info!(
            key = %key_id(&daemon.key.verifying_key()),
            state = %daemon.layout.state.display(),
            repo = %daemon.layout.repo.display(),
            "cleanroomd starting"
        );
        daemon.restore(&Principal::System).await?;
        tokio::spawn(Arc::clone(&daemon).provision());
        Ok(daemon)
    }

    /// Register a client on the bus and queue the current state for it.
    pub(crate) fn subscribe(&self, audiences: Vec<Audience>, outbox: Outbox) -> u64 {
        self.bus.subscribe(audiences, outbox)
    }

    /// Remove a client from the bus.
    pub(crate) fn unsubscribe(&self, id: u64) {
        self.bus.unsubscribe(id);
    }

    /// Check a client's publish and fan it out, sender included.
    pub(crate) fn accept_publish(&self, peer: &Peer, signed: Signed<BusMessage>) {
        if let Err(error) = sign::verify(&signed, &peer.key, domain::BUS) {
            tracing::warn!(peer = %peer.name(), "dropping a publish: {error}");
            return;
        }
        if signed.body.from != peer.principal {
            tracing::warn!(
                peer = %peer.name(),
                "dropping a publish that claims to be from {}",
                describe(&signed.body.from)
            );
            return;
        }
        let body = &signed.body.body;
        let measured = if let BusBody::Scope(record) = body {
            self.scenario.refusal(&peer.principal, record).or_else(|| {
                exfiltration_refusal(
                    &peer.principal,
                    record,
                    self.bus.scope_flags(&record.asset_id),
                )
            })
        } else {
            None
        };
        let stale = stale_refusal(&peer.principal, body, lock(&self.open_incident).as_deref());
        let verdict = may_publish(&peer.principal, body)
            .map_err(str::to_owned)
            .and_then(|()| stale.map_or(Ok(()), Err))
            .and_then(|()| measured.clone().map_or(Ok(()), Err));
        if let Some(action) = self.record_update(body) {
            let outcome = match &verdict {
                Ok(()) => Outcome::Allowed,
                Err(reason) => Outcome::Denied {
                    reason: reason.clone(),
                },
            };
            match self.receipt(peer.principal.clone(), action, outcome) {
                Ok(seq) => {
                    if let Some(reason) = measured {
                        self.status(format!(
                            "OS kept the record: {} tried to lower {reason} (receipt #{seq})",
                            peer.name()
                        ));
                    }
                }
                Err(error) => {
                    tracing::error!("cannot record a record update: {error:#}");
                    return;
                }
            }
        }
        if let Err(reason) = verdict {
            tracing::warn!(peer = %peer.name(), "dropping a publish: {reason}");
            return;
        }
        if let BusBody::Investigate { incident_id, .. } = body {
            *lock(&self.open_incident) = Some(incident_id.clone());
        }
        let cites = match (&signed.body.from, &signed.body.body) {
            (Principal::Agent { role }, BusBody::Finding { evidence, .. }) => {
                Some((*role, evidence.clone()))
            }
            _ => None,
        };
        self.bus.fan_out(signed);
        if let Some((role, evidence)) = cites {
            self.check_citations(role, &evidence);
        }
    }

    /// Check every evidence path `role`'s finding cites: it must exist in the evidence, and a
    /// command cleanroomd ran for `role` must have touched it or a directory above it. The result
    /// is a status line; the finding is already on the bus either way.
    fn check_citations(&self, role: Role, evidence: &[String]) {
        let commands = lock(&self.commands).get(&role).cloned().unwrap_or_default();
        let checked: Vec<citations::Citation> = citations::cited_paths(evidence)
            .into_iter()
            .map(|path| citations::Citation {
                exists: self.evidence_exists(&path),
                touched: citations::touched(&path, &commands),
                path,
            })
            .collect();
        if let Some(line) = citations::status(&describe(&Principal::Agent { role }), &checked) {
            self.status(line);
        }
    }

    /// Whether the investigator's path `guest` (under `/evidence`) exists on the host. A path
    /// with `..` never does, so a citation cannot point outside the evidence.
    fn evidence_exists(&self, guest: &str) -> bool {
        if guest.split('/').any(|part| part == "..") {
            return false;
        }
        [
            (strata::EVIDENCE_SHARE, self.layout.share()),
            (strata::EVIDENCE_DROP, self.layout.dropbox()),
            (strata::EVIDENCE_LOGS, self.layout.logs()),
        ]
        .into_iter()
        .any(|(mount, host)| {
            guest.strip_prefix(mount).is_some_and(|rest| {
                (rest.is_empty() || rest.starts_with('/'))
                    && host.join(rest.trim_start_matches('/')).exists()
            })
        })
    }

    /// Answer one request.
    pub(crate) async fn handle(
        self: &Arc<Self>,
        peer: &Peer,
        request: CoreRequest,
    ) -> CoreResponse {
        let op = op_name(&request);
        tracing::info!(peer = %peer.name(), op, "request");
        let result = match request {
            CoreRequest::Exec(exec) => Box::pin(self.exec(peer, exec)).await,
            CoreRequest::RequestTool(ask) => Box::pin(self.request_tool(peer, ask)).await,
            CoreRequest::ModelCall(call) => self.model_call(peer, call),
            CoreRequest::SubmitRule(submission) => {
                Box::pin(self.submit_rule(peer, submission)).await
            }
            CoreRequest::Approve(decision) => self.approve(peer, decision),
            CoreRequest::Enroll(member) => self.enroll(peer, member),
            CoreRequest::Revoke(revocation) => self.revoke(peer, revocation),
            CoreRequest::Detonate { scenario } => Box::pin(self.detonate(peer, &scenario)).await,
            CoreRequest::Tamper { root } => self.tamper(peer, &root).await,
            CoreRequest::Admit { root } => self.admit(peer, &root).await,
            CoreRequest::VerifyLog => self.verify_log(peer).await,
            CoreRequest::Reset => self.reset(peer).await,
        };
        result.unwrap_or_else(|error| {
            tracing::warn!(peer = %peer.name(), op, "{error:#}");
            CoreResponse::Error {
                message: format!("{error:#}"),
            }
        })
    }

    /// `model_call`: chain an agent's model call into the receipt log, as that agent. A
    /// reasoning trace is stored in `reasoning.ndjson` under the receipt's number, and the
    /// receipt carries its digest.
    ///
    /// # Errors
    /// Fails if the caller is not the agent it names, the trace is too large, or the receipt or
    /// trace cannot be written.
    fn model_call(&self, peer: &Peer, call: ModelCall) -> Result<CoreResponse> {
        let role = peer.role(call.from)?;
        if call
            .reasoning
            .as_ref()
            .is_some_and(|text| text.len() > REASONING_MAX)
        {
            bail!("a reasoning trace is at most {REASONING_MAX} bytes");
        }
        let actor = Principal::Agent { role };
        let model = call.model.clone();
        let action = Action::ModelCall {
            purpose: call.purpose,
            model: call.model,
            endpoint: call.endpoint,
            request: call.request,
            response: call.response,
            replayed: call.replayed,
            reasoning: call.reasoning.as_deref().map(reasoning::digest),
            reasoning_tokens: call.reasoning_tokens,
        };
        let seq = self.receipt(actor.clone(), action, Outcome::Allowed)?;
        if let Some(text) = call.reasoning {
            let trace = reasoning::Trace {
                receipt: seq,
                role: describe(&actor),
                model,
                tokens: call.reasoning_tokens,
                text,
            };
            reasoning::append(&self.layout.reasoning(), &trace)?;
        }
        Ok(CoreResponse::Ok)
    }

    /// `submit_rule`: check an investigator's YARA rule in a sandbox (`yara` over the clean seed
    /// files, then over the evidence) and admit it into `/rules` only if it compiles, matches no
    /// clean file and matches some evidence. Either way the verdict is a receipt and a status
    /// line; a rejection comes back as an error the agent can fix.
    ///
    /// # Errors
    /// Fails for a caller that is not an investigator, a bad name or size, no open incident, a
    /// rejected rule, or a sandbox or receipt failure.
    async fn submit_rule(&self, peer: &Peer, submission: RuleSubmission) -> Result<CoreResponse> {
        let role = peer.role(submission.from)?;
        if !matches!(role, Role::Hunter | Role::Forensics) {
            bail!("only hunter and forensics write detection rules");
        }
        rules::check_name(&submission.name).map_err(anyhow::Error::msg)?;
        if submission.source.trim().is_empty() || submission.source.len() > rules::SOURCE_MAX {
            bail!("a rule has 1 to {} bytes", rules::SOURCE_MAX);
        }
        if lock(&self.open_incident).is_none() {
            bail!("no incident is open; detection rules are written for one");
        }
        let actor = Principal::Agent { role };
        let root = self.launchable_root(&actor, strata::RULE_CHECK).await?;
        let yara = self
            .grants
            .of(Role::Hunter)
            .into_iter()
            .find(|tool| tool.name == "yara")
            .context("yara is not built yet; submit the rule again shortly")?;
        let file = format!("agent-{}.yar", submission.name);
        let check_dir = self.layout.rule_check();
        let candidate = check_dir.join(&file);
        drop(std::fs::remove_dir_all(&check_dir));
        std::fs::create_dir_all(&check_dir)
            .and_then(|()| std::fs::write(&candidate, &submission.source))
            .with_context(|| format!("cannot stage {}", candidate.display()))?;
        let grant = strata::rule_check(&self.layout, &root)?;
        let rule = format!("{}/{file}", strata::RULE_CHECK_RULES);
        let mut scans = Vec::with_capacity(2);
        for target in [strata::RULE_CHECK_SEED, "/evidence"] {
            let argv = ["yara", "-r", rule.as_str(), target].map(str::to_owned);
            scans.push(
                strata::run(&Launch {
                    rootfs: &root.rootfs,
                    grant: &grant,
                    bins: &yara.bins,
                    argv: &argv,
                    timeout: RULE_CHECK_TIMEOUT,
                })
                .await?,
            );
        }
        let who = describe(&actor);
        let name = submission.name;
        let action = Action::YaraRule {
            name: name.clone(),
            digest: format!(
                "sha256:{}",
                hex::encode(Sha256::digest(submission.source.as_bytes()))
            ),
        };
        match rules::judge(&scans[0], &scans[1]) {
            Err(reason) => {
                let seq = self.receipt(
                    actor,
                    action,
                    Outcome::Denied {
                        reason: reason.clone(),
                    },
                )?;
                self.status(format!(
                    "OS rejected {who}'s YARA rule {name}: {reason} (receipt #{seq})"
                ));
                bail!("rule rejected: {reason} (receipt #{seq}); fix it and submit it again")
            }
            Ok(hits) => {
                let deployed = self.layout.rules().join(&file);
                std::fs::copy(&candidate, &deployed)
                    .with_context(|| format!("cannot deploy {}", deployed.display()))?;
                let seq = self.receipt(actor, action, Outcome::Allowed)?;
                self.status(format!(
                    "{who}'s YARA rule {name} admitted to {}/{file}: it compiles, matches none of the clean files from before the attack, and matches {} evidence file(s) (receipt #{seq})",
                    strata::RULES,
                    hits.len()
                ));
                Ok(CoreResponse::Ok)
            }
        }
    }

    /// Run a command in the caller's stratum under its grant.
    ///
    /// # Errors
    /// Fails if the caller is not the agent it names, the command is empty, or the sandbox or
    /// receipt log fails.
    async fn exec(&self, peer: &Peer, request: ExecRequest) -> Result<CoreResponse> {
        let role = peer.role(request.from)?;
        if request.argv.is_empty() {
            bail!("exec needs a program to run");
        }
        let actor = Principal::Agent { role };
        let action = Action::Exec {
            stratum: request.stratum.clone(),
            argv: request.argv.clone(),
        };
        if let Some(reason) = strata::refusal(role, &request.stratum) {
            return self.exec_result(
                actor,
                action,
                ExecOutcome::Denied { reason },
                Captured::default(),
                None,
            );
        }
        let root = match self.launchable_root(&actor, &request.stratum).await {
            Ok(root) => root,
            Err(error) => {
                let reason = format!("{error:#}");
                return self.exec_result(
                    actor,
                    action,
                    ExecOutcome::Denied { reason },
                    Captured::default(),
                    None,
                );
            }
        };
        let tools = self.grants.of(role);
        let grant = strata::investigator(&self.layout, role, &root, &tools)?;
        let bins: Vec<PathBuf> = tools.into_iter().flat_map(|tool| tool.bins).collect();
        let launch = Launch {
            rootfs: &root.rootfs,
            grant: &grant,
            bins: &bins,
            argv: &request.argv,
            timeout: Duration::from_millis(request.timeout_ms).min(strata::MAX_TIMEOUT),
        };
        let captured = strata::run(&launch).await?;
        lock(&self.commands)
            .entry(role)
            .or_default()
            .push(request.argv.join(" "));
        let outcome = strata::classify(strata::stratum_of(role), &captured);
        let evidence = self
            .recheck_evidence(&describe(&actor), &request.argv.join(" "))
            .await;
        self.exec_result(actor, action, outcome, captured, evidence)
    }

    /// Record an exec and build its response; a denial also goes on the bus as a status line,
    /// with `evidence` (what the post-command evidence check found) appended.
    ///
    /// # Errors
    /// Fails if the receipt cannot be written.
    fn exec_result(
        &self,
        actor: Principal,
        action: Action,
        outcome: ExecOutcome,
        captured: Captured,
        evidence: Option<String>,
    ) -> Result<CoreResponse> {
        let receipt_outcome = match &outcome {
            ExecOutcome::Denied { reason } => Outcome::Denied {
                reason: reason.clone(),
            },
            ExecOutcome::Exited { .. } | ExecOutcome::TimedOut => Outcome::Allowed,
        };
        let who = describe(&actor);
        let command = match &action {
            Action::Exec { argv, .. } => argv.join(" "),
            Action::AdmitRoot { .. }
            | Action::Write { .. }
            | Action::ToolGrant { .. }
            | Action::Approval { .. }
            | Action::Enroll { .. }
            | Action::Revoke { .. }
            | Action::RecordUpdate { .. }
            | Action::Detonate { .. }
            | Action::EvidenceSeal { .. }
            | Action::ModelCall { .. }
            | Action::YaraRule { .. } => String::new(),
        };
        let seq = self.receipt(actor, action, receipt_outcome)?;
        if let ExecOutcome::Denied { reason } = &outcome {
            let evidence = evidence.map_or_else(String::new, |note| format!("; {note}"));
            self.status(format!(
                "OS denied {who}: `{command}`: {reason} (receipt #{seq}){evidence}"
            ));
        }
        Ok(CoreResponse::Exec(ExecResult {
            outcome,
            stdout: captured.stdout,
            stderr: captured.stderr,
            truncated: captured.truncated,
            receipt_seq: seq,
        }))
    }

    /// The evidence directories under their investigator names (`/evidence/<label>`).
    fn evidence_dirs(&self) -> Vec<(&'static str, PathBuf)> {
        vec![
            ("acme-fs", self.layout.share()),
            ("dropbox", self.layout.dropbox()),
            ("logs", self.layout.logs()),
        ]
    }

    /// Hash every evidence file now.
    ///
    /// # Errors
    /// Fails if an evidence directory cannot be read.
    async fn seal_evidence(&self) -> Result<scenario::Seal> {
        let dirs = self.evidence_dirs();
        spawn_blocking(move || scenario::seal(&dirs))
            .await
            .context("sealing the evidence panicked")?
    }

    /// Write an evidence seal receipt for `seal` and make it the current seal.
    ///
    /// # Errors
    /// Fails if the receipt cannot be written.
    fn record_seal(&self, seal: scenario::Seal) -> Result<u64> {
        let action = Action::EvidenceSeal {
            digest: seal.digest.clone(),
            files: u64::try_from(seal.len()).unwrap_or(u64::MAX),
        };
        let seq = self.receipt(Principal::System, action, Outcome::Allowed)?;
        self.scenario.set_seal(Some((seal, seq)));
        Ok(seq)
    }

    /// After `who` ran `command`: re-hash the evidence against the latest seal. A change is
    /// sealed again with a new receipt and announced (the check only finds it; agents' strata
    /// mount the evidence read-only, so it came from elsewhere); either way returns a note for a
    /// denial's status line. `None` when no incident is sealed or the evidence cannot be read.
    async fn recheck_evidence(&self, who: &str, command: &str) -> Option<String> {
        let (sealed, seq) = self.scenario.seal()?;
        let now = match self.seal_evidence().await {
            Ok(now) => now,
            Err(error) => {
                tracing::warn!("cannot re-check the evidence after {who}'s command: {error:#}");
                return None;
            }
        };
        let changed = sealed.differences(&now);
        if changed.is_empty() {
            return Some(format!(
                "evidence unchanged: still matches the seal from receipt #{seq}"
            ));
        }
        let digest = now.digest.clone();
        let changed = changed.join(", ");
        match self.record_seal(now) {
            Ok(new_seq) => {
                self.status(format!(
                    "EVIDENCE CHANGED since the seal from receipt #{seq}: {changed} under /evidence (found by the check after {who} ran `{command}`); resealed as {digest} (receipt #{new_seq})"
                ));
                Some(format!("evidence CHANGED since receipt #{seq}: {changed}"))
            }
            Err(error) => {
                tracing::warn!("cannot record the changed evidence: {error:#}");
                Some(format!("evidence CHANGED since receipt #{seq}: {changed}"))
            }
        }
    }

    /// The root `stratum` runs on.
    ///
    /// # Errors
    /// Fails for a stratum that launches no commands.
    fn root_of(&self, stratum: &str) -> Result<&str> {
        self.placement
            .root(stratum)
            .with_context(|| format!("the {stratum} stratum launches no commands"))
    }

    /// The admitted root `stratum` runs on, admitting it first if this run has not, and
    /// re-checking its tree.
    ///
    /// # Errors
    /// Fails for a stratum that launches no commands, if admission fails or rejects the root,
    /// or if the tree changed since admission.
    async fn launchable_root(&self, actor: &Principal, stratum: &str) -> Result<Admitted> {
        let name = self.root_of(stratum)?;
        let root = match self.roots.admitted(name) {
            Some(root) => root,
            None => match self.admit_root(actor, name).await? {
                Verdict::Admitted(root) => root,
                Verdict::Rejected(mismatch) => bail!(
                    "root {name} failed admission: layer {} does not match its lock",
                    mismatch.layer
                ),
            },
        };
        if !self.roots.intact(&root).await? {
            self.status(format!(
                "root {name} changed on disk since admission (tree digest mismatch); launches refused until it is re-admitted"
            ));
            bail!("root {name} changed on disk since admission; re-admit it");
        }
        Ok(root)
    }

    /// Admit a root, recording a receipt and a status line either way.
    ///
    /// # Errors
    /// Fails if admission cannot run or the receipt cannot be written.
    async fn admit_root(&self, actor: &Principal, name: &str) -> Result<Verdict> {
        let verdict = self.roots.admit(name).await?;
        match &verdict {
            Verdict::Admitted(root) => {
                let action = Action::AdmitRoot {
                    name: name.to_owned(),
                    manifest: root.manifest.clone(),
                };
                let seq = self.receipt(actor.clone(), action, Outcome::Allowed)?;
                self.status(format!(
                    "root {name} admitted: manifest {}, unpacked tree {} (receipt #{seq})",
                    root.manifest, root.tree
                ));
            }
            Verdict::Rejected(mismatch) => {
                let reason = format!(
                    "layer {} does not match its lock: expected {}, actual {}",
                    mismatch.layer, mismatch.expected, mismatch.actual
                );
                let action = Action::AdmitRoot {
                    name: name.to_owned(),
                    manifest: mismatch.manifest.clone(),
                };
                let seq = self.receipt(
                    actor.clone(),
                    action,
                    Outcome::Denied {
                        reason: reason.clone(),
                    },
                )?;
                self.status(format!("root {name} REJECTED: {reason} (receipt #{seq})"));
            }
        }
        Ok(verdict)
    }

    /// `admit {root}`.
    ///
    /// # Errors
    /// Fails for agents, or if admission cannot run.
    async fn admit(&self, peer: &Peer, root: &str) -> Result<CoreResponse> {
        peer.human("admit")?;
        Ok(match self.admit_root(&peer.principal, root).await? {
            Verdict::Admitted(admitted) => CoreResponse::Admitted {
                root: root.to_owned(),
                manifest: admitted.manifest,
            },
            Verdict::Rejected(mismatch) => CoreResponse::AdmitRejected {
                root: root.to_owned(),
                layer: mismatch.layer,
                expected: mismatch.expected,
                actual: mismatch.actual,
            },
        })
    }

    /// `tamper {root}`: corrupt a staged copy for the next admission to catch.
    ///
    /// # Errors
    /// Fails for agents, or if the root cannot be staged or rewritten.
    async fn tamper(&self, peer: &Peer, root: &str) -> Result<CoreResponse> {
        peer.human("tamper")?;
        let tampered = self.roots.tamper(root).await?;
        let action = Action::Write {
            stratum: "store".to_owned(),
            path: tampered.path.display().to_string(),
        };
        let seq = self.receipt(peer.principal.clone(), action, Outcome::Allowed)?;
        self.status(format!(
            "{} flipped byte {} of layer {} in the staged copy of {root}; the next admission checks it (receipt #{seq})",
            peer.name(),
            tampered.offset,
            tampered.layer
        ));
        Ok(CoreResponse::Ok)
    }

    /// `request_tool`: publish the request, decide it, and materialize it when allowed.
    ///
    /// # Errors
    /// Fails if the caller is not the agent it names or the receipt cannot be written.
    async fn request_tool(&self, peer: &Peer, request: ToolRequest) -> Result<CoreResponse> {
        let role = peer.role(request.from)?;
        let decision = strata::refusal(role, &request.stratum).map_or_else(
            || self.policy.decide(&request),
            |reason| ToolDecision::Denied { reason },
        );
        self.publish(BusBody::ToolRequest(request.clone()));
        let decision = match decision {
            ToolDecision::AutoAllowed { rule } => match self.grant_tool(&request).await {
                Ok(()) => ToolDecision::AutoAllowed { rule },
                Err(error) => ToolDecision::Denied {
                    reason: format!("allowed by {rule}, but it could not be built: {error:#}"),
                },
            },
            ToolDecision::Pending => {
                self.status(format!(
                    "{} asks for {}: outside policy, waiting for a commander's signature on {}",
                    describe(&Principal::Agent { role }),
                    request.tool,
                    request.id
                ));
                return Ok(CoreResponse::Tool {
                    request_id: request.id,
                    decision: ToolDecision::Pending,
                });
            }
            decided @ (ToolDecision::Approved { .. } | ToolDecision::Denied { .. }) => decided,
        };
        self.settle_tool(Principal::System, &request, &decision)?;
        Ok(CoreResponse::Tool {
            request_id: request.id,
            decision,
        })
    }

    /// Build a requested tool and add it to the requester's grant.
    ///
    /// # Errors
    /// Fails for non-nix sources or a failed build.
    async fn grant_tool(&self, request: &ToolRequest) -> Result<()> {
        let ToolSource::Nix { flake_ref } = &request.source else {
            bail!("only nix tool sources can be materialized");
        };
        let bins = tools::materialize(flake_ref).await?;
        self.grants.add(
            request.from,
            Granted {
                name: request.tool.clone(),
                bins,
                baseline: false,
            },
        );
        Ok(())
    }

    /// Record a final tool decision and publish it.
    ///
    /// # Errors
    /// Fails if the receipt cannot be written.
    fn settle_tool(
        &self,
        actor: Principal,
        request: &ToolRequest,
        decision: &ToolDecision,
    ) -> Result<()> {
        let outcome = match decision {
            ToolDecision::AutoAllowed { .. } | ToolDecision::Approved { .. } => Outcome::Allowed,
            ToolDecision::Denied { reason } => Outcome::Denied {
                reason: reason.clone(),
            },
            ToolDecision::Pending => return Ok(()),
        };
        let action = Action::ToolGrant {
            request_id: request.id.clone(),
            tool: request.tool.clone(),
        };
        self.receipt(actor, action, outcome)?;
        self.publish(BusBody::ToolDecision {
            request_id: request.id.clone(),
            decision: decision.clone(),
        });
        Ok(())
    }

    /// `approve`: a commander's signed decision on an open tool request or proposal.
    ///
    /// # Errors
    /// Fails for agents, a signature that does not verify against this connection's key, an
    /// unenrolled approver, or a subject that is not open.
    fn approve(
        self: &Arc<Self>,
        peer: &Peer,
        signed: Signed<ApprovalDecision>,
    ) -> Result<CoreResponse> {
        peer.human("approve")?;
        sign::verify(&signed, &peer.key, domain::APPROVAL)
            .context("the approval is not signed by this connection's key")?;
        if !lock(&self.members).may_approve(&peer.key_id) {
            bail!("{} is not an enrolled commander", peer.key_id);
        }
        let ApprovalDecision {
            subject_id,
            approved,
            ..
        } = signed.body;
        let subject = self
            .bus
            .take_subject(&subject_id)
            .with_context(|| format!("no open tool request or proposal is called {subject_id}"))?;
        let outcome = if approved {
            Outcome::Allowed
        } else {
            Outcome::Denied {
                reason: format!("the commander rejected {subject_id}"),
            }
        };
        let action = Action::Approval {
            subject_id: subject_id.clone(),
        };
        let seq = self.receipt(peer.principal.clone(), action, outcome)?;
        let verb = if approved { "approved" } else { "rejected" };
        match subject {
            Subject::Proposal { action } => {
                self.publish(BusBody::Approval {
                    subject_id: subject_id.clone(),
                    approved,
                });
                self.status(format!(
                    "{} {verb} proposal {subject_id}: {action} (receipt #{seq})",
                    peer.name()
                ));
            }
            Subject::Tool(request) => {
                self.status(format!(
                    "{} {verb} tool request {subject_id} ({}) (receipt #{seq})",
                    peer.name(),
                    request.tool
                ));
                let daemon = Arc::clone(self);
                let commander = peer.key_id.clone();
                let actor = peer.principal.clone();
                tokio::spawn(async move {
                    daemon
                        .decide_tool(request, approved, commander, actor)
                        .await;
                });
            }
        }
        Ok(CoreResponse::Ok)
    }

    /// Carry out a commander's decision on a tool request.
    async fn decide_tool(
        self: Arc<Self>,
        request: ToolRequest,
        approved: bool,
        commander: KeyId,
        actor: Principal,
    ) {
        let decision = if approved {
            match self.grant_tool(&request).await {
                Ok(()) => ToolDecision::Approved {
                    approver: commander,
                },
                Err(error) => ToolDecision::Denied {
                    reason: format!("approved, but it could not be built: {error:#}"),
                },
            }
        } else {
            ToolDecision::Denied {
                reason: "denied by the commander".to_owned(),
            }
        };
        if let Err(error) = self.settle_tool(actor, &request, &decision) {
            tracing::error!("cannot record the decision on {}: {error:#}", request.id);
        }
    }

    /// `enroll`: an admin-signed member record.
    ///
    /// # Errors
    /// Fails for agents, a signature that does not verify against this connection's key, or an
    /// enrollment the members policy refuses.
    fn enroll(&self, peer: &Peer, signed: Signed<Member>) -> Result<CoreResponse> {
        peer.human("enroll")?;
        sign::verify(&signed, &peer.key, domain::ENROLL)
            .context("the enrollment is not signed by this connection's key")?;
        let member = signed.body.key_id.clone();
        let role = match signed.body.role {
            MemberRole::Admin => "admin",
            MemberRole::Commander => "commander",
            MemberRole::Responder => "responder",
            MemberRole::Observer => "observer",
        };
        let label = format!("{} ({role})", signed.body.name);
        let action = Action::Enroll {
            member: member.clone(),
        };
        let enrolled = {
            let mut members = lock(&self.members);
            members.enroll(&peer.key_id, signed)
        };
        match enrolled {
            Ok(()) => {
                let seq = self.receipt(peer.principal.clone(), action, Outcome::Allowed)?;
                self.status(format!("enrolled {label}: {member} (receipt #{seq})"));
                Ok(CoreResponse::Ok)
            }
            Err(error) => {
                let reason = format!("{error:#}");
                self.receipt(peer.principal.clone(), action, Outcome::Denied { reason })?;
                Err(error)
            }
        }
    }

    /// `revoke`: an admin-signed revocation of a member's key.
    ///
    /// # Errors
    /// Fails for agents, a signature that does not verify against this connection's key, or a
    /// revocation the members policy refuses.
    fn revoke(&self, peer: &Peer, signed: Signed<Revocation>) -> Result<CoreResponse> {
        peer.human("revoke")?;
        sign::verify(&signed, &peer.key, domain::REVOKE)
            .context("the revocation is not signed by this connection's key")?;
        let member = signed.body.key_id.clone();
        let reason = signed.body.reason.clone();
        let action = Action::Revoke {
            member: member.clone(),
        };
        let revoked = lock(&self.members).revoke(&peer.key_id, signed);
        match revoked {
            Ok(()) => {
                let seq = self.receipt(peer.principal.clone(), action, Outcome::Allowed)?;
                self.status(format!("revoked {member}: {reason} (receipt #{seq})"));
                Ok(CoreResponse::Ok)
            }
            Err(error) => {
                let reason = format!("{error:#}");
                self.receipt(peer.principal.clone(), action, Outcome::Denied { reason })?;
                Err(error)
            }
        }
    }

    /// `detonate {scenario}`: run the ransomware in the victim stratum, then declare the
    /// incident and start the agents.
    ///
    /// # Errors
    /// Fails for agents, an unknown scenario, a share that was already detonated, a missing
    /// ransomware binary, a root that cannot be admitted, or a failed run.
    #[allow(
        clippy::significant_drop_tightening,
        reason = "the scenario guard is held for the whole run so a reset cannot interleave with \
                  a detonation. `allow`, not `expect`: nursery lints only run under the strict profile"
    )]
    async fn detonate(&self, peer: &Peer, name: &str) -> Result<CoreResponse> {
        peer.human("detonate")?;
        let argv = scenario::detonation_argv(name)?;
        let mut incident = self.scenario.incident().await;
        if let Some(id) = incident.as_ref() {
            bail!("acme-fs was already detonated ({id}); reset first");
        }
        let ransom = scenario::find_ransom(&self.layout)?;
        let root_name = self.root_of(strata::VICTIM)?;
        let root = self
            .launchable_root(&peer.principal, strata::VICTIM)
            .await?;
        let action = Action::Detonate {
            scenario: name.to_owned(),
        };
        let seq = self.receipt(peer.principal.clone(), action, Outcome::Allowed)?;
        self.status(format!(
            "{} detonated {name} in the acme-fs stratum: {root_name} root read-only, share read-write, no network (receipt #{seq})",
            peer.name()
        ));
        let summary = self.run_ransomware(&root, &ransom, argv).await?;
        self.status(format!(
            "ransomware finished in acme-fs: {} files locked, {} files copied into a staging directory, ransom note {}",
            summary.locked.len(),
            summary.exfiltrated.len(),
            summary.note
        ));
        let id = self.declare(seq).await?;
        *incident = Some(id);
        Ok(CoreResponse::Ok)
    }

    /// Launch `argv` (`cleanroom-ransom detonate`) in the victim stratum and read its summary.
    ///
    /// # Errors
    /// Fails if the binary cannot be installed, the sandbox fails, or the run does not succeed.
    async fn run_ransomware(
        &self,
        root: &Admitted,
        ransom: &Path,
        argv: Vec<String>,
    ) -> Result<scenario::Summary> {
        let layout = self.layout.clone();
        let binary = ransom.to_owned();
        spawn_blocking(move || scenario::install_ransom(&layout, &binary))
            .await
            .context("installing the ransomware panicked")??;
        let grant = strata::victim(&self.layout, root)?;
        let launch = Launch {
            rootfs: &root.rootfs,
            grant: &grant,
            bins: &[],
            argv: &argv,
            timeout: DETONATION_TIMEOUT,
        };
        let captured = strata::run(&launch).await?;
        let outcome = strata::classify(strata::VICTIM, &captured);
        let receipt_outcome = match &outcome {
            ExecOutcome::Exited { code: 0 } => Outcome::Allowed,
            ExecOutcome::Exited { code } => Outcome::Denied {
                reason: format!("exited {code}"),
            },
            ExecOutcome::TimedOut => Outcome::Denied {
                reason: "timed out".to_owned(),
            },
            ExecOutcome::Denied { reason } => Outcome::Denied {
                reason: reason.clone(),
            },
        };
        let action = Action::Exec {
            stratum: strata::VICTIM.to_owned(),
            argv: argv.clone(),
        };
        let seq = self.receipt(Principal::System, action, receipt_outcome)?;
        match outcome {
            ExecOutcome::Exited { code: 0 } => scenario::parse_summary(&captured.stdout),
            ExecOutcome::Exited { .. } | ExecOutcome::TimedOut | ExecOutcome::Denied { .. } => {
                let detail = captured
                    .stderr
                    .lines()
                    .rev()
                    .find(|line| !line.trim().is_empty())
                    .unwrap_or("no error output")
                    .to_owned();
                self.status(format!(
                    "the ransomware run failed (receipt #{seq}): {detail}"
                ));
                bail!("the ransomware run failed: {detail}")
            }
        }
    }

    /// Compare the share with its seeding hashes, publish the changed assets' scope, open the
    /// incident and start the agents. Returns the incident id.
    ///
    /// # Errors
    /// Fails if the share cannot be read.
    async fn declare(&self, receipt: u64) -> Result<String> {
        let share = self.layout.share();
        let drop_box = self.layout.dropbox();
        let baseline = self.scenario.baseline();
        let integrity = spawn_blocking(move || scenario::check(&share, &drop_box, &baseline))
            .await
            .context("the integrity check panicked")??;
        let at = now();
        let seal = self.seal_evidence().await?;
        let (digest, files) = (seal.digest.clone(), seal.len());
        let sealed = self.record_seal(seal)?;
        self.scenario.set_detection_seal(self.scenario.seal());
        self.status(format!(
            "evidence sealed at detection: {digest} over {files} files in {}, {} and {} (receipt #{sealed}); every agent command is checked against it",
            strata::EVIDENCE_SHARE,
            strata::EVIDENCE_DROP,
            strata::EVIDENCE_LOGS
        ));
        let measured = scenario::affected(self.scenario.assets(), &integrity, &at);
        self.scenario.set_measured(&measured);
        for record in measured {
            self.publish(BusBody::Scope(record));
        }
        let id = scenario::incident_id(&at);
        *lock(&self.open_incident) = Some(id.clone());
        self.publish(BusBody::Incident(scenario::incident(
            &id, &at, &integrity, receipt,
        )));
        self.publish(BusBody::Investigate {
            incident_id: id.clone(),
            brief: scenario::brief(&at, &integrity),
        });
        Ok(id)
    }

    /// `verify_log`.
    ///
    /// # Errors
    /// Fails for agents or if the log cannot be read.
    async fn verify_log(&self, peer: &Peer) -> Result<CoreResponse> {
        peer.human("verify_log")?;
        let report = lock(&self.receipts).verify(&self.key.verifying_key())?;
        match report.first_break {
            None => self.status(format!(
                "receipt log verified: {} receipts, chain intact",
                report.entries
            )),
            Some(entry) => self.status(format!(
                "receipt log BROKEN at receipt {entry} of {}",
                report.entries
            )),
        }
        if let Some((sealed, seq)) = self.scenario.detection_seal() {
            let now = self.seal_evidence().await?;
            let changed = sealed.differences(&now);
            if changed.is_empty() {
                self.status(format!(
                    "evidence verified: {} files match the seal taken at detection (receipt #{seq}, {})",
                    now.len(),
                    sealed.digest
                ));
            } else {
                self.status(format!(
                    "evidence DIFFERS from the seal taken at detection (receipt #{seq}): {}",
                    changed.join(", ")
                ));
            }
        }
        Ok(CoreResponse::LogVerified {
            entries: report.entries,
            first_break: report.first_break,
        })
    }

    /// `reset`.
    ///
    /// # Errors
    /// Fails for agents or if the victim cannot be restored.
    async fn reset(&self, peer: &Peer) -> Result<CoreResponse> {
        peer.human("reset")?;
        self.restore(&peer.principal).await?;
        Ok(CoreResponse::Ok)
    }

    /// Re-seed the victim, drop staged copies and incident grants, clear the incident, and
    /// publish every asset's baseline.
    ///
    /// # Errors
    /// Fails if the seed cannot be copied or the receipt cannot be written.
    #[allow(
        clippy::significant_drop_tightening,
        reason = "the scenario guard is held for the whole restore so a detonation cannot \
                  interleave with it. `allow`, not `expect`: nursery lints only run under the strict profile"
    )]
    async fn restore(&self, actor: &Principal) -> Result<()> {
        let mut incident = self.scenario.incident().await;
        // Before re-seeding: a command still running must not compare a fresh share with the
        // old incident's seal.
        self.scenario.set_seal(None);
        self.scenario.set_detection_seal(None);
        self.roots.discard_staging().await?;
        let layout = self.layout.clone();
        let baseline = spawn_blocking(move || scenario::reseed(&layout))
            .await
            .context("re-seeding panicked")??;
        self.scenario.set_baseline(baseline);
        self.scenario.set_measured(&[]);
        *lock(&self.open_incident) = None;
        lock(&self.commands).clear();
        self.grants.reset();
        self.bus.clear_incident();
        *incident = None;
        let action = Action::Write {
            stratum: strata::VICTIM.to_owned(),
            path: format!(
                "{} re-seeded from scenario/acme-fs; drop box, logs and scratch emptied",
                strata::VICTIM_SHARE
            ),
        };
        let seq = self.receipt(actor.clone(), action, Outcome::Allowed)?;
        let at = now();
        for asset in self.scenario.assets() {
            self.publish(BusBody::Scope(scenario::baseline(asset, &at)));
        }
        self.status(format!(
            "acme-fs restored to its seed: {} assets at baseline, no incident (receipt #{seq})",
            self.scenario.assets().len()
        ));
        Ok(())
    }

    /// Standing grants (Hunter's YARA), then warm the Nix store with every allowlisted tool so
    /// later grants are instant and work offline.
    async fn provision(self: Arc<Self>) {
        for (role, tool) in tools::BASELINE {
            let flake_ref = self.policy.pinned(tool);
            match tools::materialize(&flake_ref).await {
                Ok(bins) => {
                    self.grants.add(
                        role,
                        Granted {
                            name: tool.to_owned(),
                            bins,
                            baseline: true,
                        },
                    );
                    let action = Action::ToolGrant {
                        request_id: format!("standing-{}-{tool}", strata::stratum_of(role)),
                        tool: tool.to_owned(),
                    };
                    if let Err(error) = self.receipt(Principal::System, action, Outcome::Allowed) {
                        tracing::error!("cannot record a standing grant: {error:#}");
                    }
                    tracing::info!(
                        "{tool} granted to {} ({flake_ref})",
                        strata::stratum_of(role)
                    );
                }
                Err(error) => tracing::warn!(
                    "cannot provision {tool} for {}: {error:#}; it runs without {tool} until a tool request admits it",
                    strata::stratum_of(role)
                ),
            }
        }
        for tool in tools::ALLOWLIST {
            match tools::materialize(&self.policy.pinned(tool)).await {
                Ok(_) => tracing::info!("{tool} is in the Nix store"),
                Err(error) => tracing::warn!("cannot pre-build {tool}: {error:#}"),
            }
        }
    }

    /// The incident-record receipt for a `scope` or `incident` publish.
    fn record_update(&self, body: &BusBody) -> Option<Action> {
        match body {
            BusBody::Incident(record) => Some(Action::RecordUpdate {
                incident_id: record.id.clone(),
                field: "incident".to_owned(),
            }),
            BusBody::Scope(record) => Some(Action::RecordUpdate {
                incident_id: self.bus.incident_id().unwrap_or_else(|| "none".to_owned()),
                field: format!("scope:{}", record.asset_id),
            }),
            BusBody::Chat { .. }
            | BusBody::Finding { .. }
            | BusBody::Proposal { .. }
            | BusBody::Approval { .. }
            | BusBody::ToolRequest(_)
            | BusBody::ToolDecision { .. }
            | BusBody::Trace { .. }
            | BusBody::Refusal { .. }
            | BusBody::Counters { .. }
            | BusBody::SafetyVerdict { .. }
            | BusBody::Route { .. }
            | BusBody::Status { .. }
            | BusBody::Investigate { .. }
            | BusBody::AgentControl { .. } => None,
        }
    }

    /// Sign `body` as cleanroomd and fan it out to everyone.
    fn publish(&self, body: BusBody) {
        let number = self.next_message.fetch_add(1, Ordering::Relaxed);
        let message = BusMessage {
            id: format!("cleanroomd-{}-{number}", self.session),
            at: now(),
            from: Principal::System,
            to: Audience::All,
            body,
        };
        match sign::sign(&self.key, domain::BUS, message) {
            Ok(signed) => self.bus.fan_out(signed),
            Err(error) => tracing::error!("cannot sign a bus message: {error}"),
        }
    }

    /// Publish a status line for humans and log it.
    fn status(&self, text: String) {
        tracing::info!("{text}");
        self.publish(BusBody::Status { text });
    }

    /// Append a receipt and return its sequence number.
    ///
    /// # Errors
    /// Fails if the receipt cannot be signed or written.
    fn receipt(&self, actor: Principal, action: Action, outcome: Outcome) -> Result<u64> {
        lock(&self.receipts).append(&self.key, actor, action, outcome)
    }
}

/// Whether `principal` may publish `body` (the bus side of the grants table).
///
/// Tool requests, tool decisions and approvals come only from cleanroomd (through
/// `request_tool` and `approve`); `investigate` and `agent_control` only from humans; incident
/// and scope records only from Scribe or a human; proposals only from Containment.
///
/// # Errors
/// Returns the reason when the publish is not allowed.
fn may_publish(principal: &Principal, body: &BusBody) -> Result<(), &'static str> {
    let human = matches!(principal, Principal::Human { .. });
    let agent = |wanted: Role| matches!(principal, Principal::Agent { role } if *role == wanted);
    match body {
        BusBody::ToolRequest(_) | BusBody::ToolDecision { .. } | BusBody::Approval { .. } => Err(
            "only cleanroomd publishes tool requests, tool decisions and approvals; use the request_tool and approve operations",
        ),
        BusBody::Investigate { .. } | BusBody::AgentControl { .. } if !human => {
            Err("only a human may start an investigation or toggle agent guardrails")
        }
        BusBody::Scope(_) | BusBody::Incident(_) if !human && !agent(Role::Scribe) => {
            Err("only scribe or a human may update the incident and scope records")
        }
        BusBody::Proposal { .. } if !agent(Role::Containment) => {
            Err("only containment proposes actions")
        }
        BusBody::Investigate { .. }
        | BusBody::AgentControl { .. }
        | BusBody::Scope(_)
        | BusBody::Incident(_)
        | BusBody::Proposal { .. }
        | BusBody::Chat { .. }
        | BusBody::Finding { .. }
        | BusBody::Trace { .. }
        | BusBody::Refusal { .. }
        | BusBody::Counters { .. }
        | BusBody::SafetyVerdict { .. }
        | BusBody::Route { .. }
        | BusBody::Status { .. } => Ok(()),
    }
}

/// Why an agent's scope `record` is refused because it would clear exfiltration that the bus
/// holds as unknown or yes. cleanroomd cannot measure exfiltration, so only a human may say no.
fn exfiltration_refusal(
    principal: &Principal,
    record: &ScopeRecord,
    current: Option<cleanroom_proto::ScopeFlags>,
) -> Option<String> {
    if !matches!(principal, Principal::Agent { .. }) {
        return None;
    }
    current
        .filter(|current| record.flags.clears_exfiltration(current))
        .map(|_| {
            format!(
                "{} exfiltrated: cleanroomd cannot measure exfiltration, so only a commander can clear it",
                record.asset_id
            )
        })
}

/// Why an agent's record, proposal or finding is refused because it doesn't belong to the open
/// incident: none is open (a reset cleared it), or an incident record names another incident.
/// Humans may always write; chat, traces and status lines always flow.
fn stale_refusal(principal: &Principal, body: &BusBody, open: Option<&str>) -> Option<String> {
    if !matches!(principal, Principal::Agent { .. }) {
        return None;
    }
    let record = matches!(
        body,
        BusBody::Scope(_)
            | BusBody::Incident(_)
            | BusBody::Proposal { .. }
            | BusBody::Finding { .. }
    );
    match (open, body) {
        (None, _) if record => Some(
            "no incident is open (a reset cleared it); records, findings and proposals wait for the next investigation"
                .to_owned(),
        ),
        (Some(open), BusBody::Incident(incident)) if incident.id != open => Some(format!(
            "incident {} is not the open incident {open}",
            incident.id
        )),
        _ => None,
    }
}

/// A principal for logs and status lines.
fn describe(principal: &Principal) -> String {
    match principal {
        Principal::Agent { role } => strata::stratum_of(*role).to_owned(),
        Principal::Human { key_id } => {
            let short = key_id
                .strip_prefix("sha256:")
                .and_then(|hex| hex.get(..12))
                .unwrap_or(key_id);
            format!("commander {short}")
        }
        Principal::System => "cleanroomd".to_owned(),
    }
}

/// The wire name of a request op.
const fn op_name(request: &CoreRequest) -> &'static str {
    match request {
        CoreRequest::Exec(_) => "exec",
        CoreRequest::RequestTool(_) => "request_tool",
        CoreRequest::ModelCall(_) => "model_call",
        CoreRequest::SubmitRule(_) => "submit_rule",
        CoreRequest::Approve(_) => "approve",
        CoreRequest::Enroll(_) => "enroll",
        CoreRequest::Revoke(_) => "revoke",
        CoreRequest::Detonate { .. } => "detonate",
        CoreRequest::Tamper { .. } => "tamper",
        CoreRequest::Admit { .. } => "admit",
        CoreRequest::VerifyLog => "verify_log",
        CoreRequest::Reset => "reset",
    }
}

/// Process start time and pid, in hex.
fn session_tag() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis());
    format!("{millis:x}{:x}", std::process::id())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use cleanroom_proto::{ScopeFlags, Tri};

    use super::*;

    fn body(value: &serde_json::Value) -> BusBody {
        serde_json::from_value(value.clone()).expect("well-formed bus body")
    }

    fn agent(role: Role) -> Principal {
        Principal::Agent { role }
    }

    fn scope() -> BusBody {
        body(&json!({
            "type": "scope", "asset_id": "payroll", "name": "Payroll export",
            "data_classes": ["pii"], "record_count": 1240, "texas_residents": 1180,
            "flags": {"locked": "yes", "exfiltrated": "unknown", "accessed": "yes", "destroyed": "unknown", "modified": "yes"},
            "encrypted_at_rest": false, "key_exposed": "no", "confidence_pct": 90, "evidence": [],
            "updated_by": {"kind": "agent", "role": "scribe"}, "updated_at": "2026-11-08T05:30:10Z"
        }))
    }

    fn incident(id: &str) -> BusBody {
        body(&json!({
            "type": "incident", "id": id, "title": "Ransomware on acme-fs", "status": "analyzing",
            "severity": "critical", "category": "ransomware", "detected_at": "2026-11-08T05:29:40Z",
            "reported_by": {"kind": "system"}, "summary": "", "affected_systems": ["acme-fs"],
            "triggers": {"aware_at": null, "discovered_at": null, "breach_determined_at": null, "materiality_determined_at": null},
            "timeline": []
        }))
    }

    /// A live run: the commander reset mid-investigation, and within seconds the agents wrote
    /// the cleared incident, four red scope rows and two proposals back onto the bus.
    #[test]
    fn after_a_reset_agents_cannot_write_records_or_propose() {
        let proposal = body(
            &json!({"type": "proposal", "proposal_id": "INC-1-proposal-1", "action": "isolate acme-fs", "rationale": "encrypting"}),
        );
        let finding = body(
            &json!({"type": "finding", "summary": "encryptor ran", "evidence": ["/evidence/logs/syslog"], "confidence_pct": 90}),
        );
        for (who, what) in [
            (agent(Role::Scribe), scope()),
            (agent(Role::Scribe), incident("INC-1")),
            (agent(Role::Containment), proposal),
            (agent(Role::Hunter), finding),
        ] {
            let reason = stale_refusal(&who, &what, None).unwrap_or_else(|| {
                panic!("{} must be refused with no open incident", describe(&who))
            });
            assert!(reason.contains("no incident is open"), "{reason}");
        }
        let chat = body(&json!({"type": "chat", "text": "standing by"}));
        assert_eq!(
            stale_refusal(&agent(Role::Hunter), &chat, None),
            None,
            "chat still flows"
        );
        let human = Principal::Human {
            key_id: "sha256:commander".to_owned(),
        };
        assert_eq!(
            stale_refusal(&human, &scope(), None),
            None,
            "a commander may still write"
        );
    }

    #[test]
    fn during_an_incident_only_its_own_record_is_accepted() {
        let reason = stale_refusal(&agent(Role::Scribe), &incident("INC-1"), Some("INC-2"))
            .expect("an earlier incident's record is refused");
        assert!(
            reason.contains("INC-1") && reason.contains("INC-2"),
            "{reason}"
        );
        assert_eq!(
            stale_refusal(&agent(Role::Scribe), &incident("INC-2"), Some("INC-2")),
            None,
            "the open incident's record is accepted"
        );
        assert_eq!(
            stale_refusal(&agent(Role::Scribe), &scope(), Some("INC-2")),
            None,
            "scope records are accepted while an incident is open"
        );
    }

    fn flags(exfiltrated: Tri) -> ScopeFlags {
        ScopeFlags {
            locked: Tri::Yes,
            exfiltrated,
            accessed: Tri::Yes,
            destroyed: Tri::Unknown,
            modified: Tri::Yes,
        }
    }

    /// A live guardrails-off run: a fooled Scribe wrote exfiltrated=no for payroll, which had
    /// been copied out. Exfiltration isn't measured, so an agent alone may not clear it.
    #[test]
    fn an_agent_cannot_clear_exfiltration_but_a_commander_can() {
        let BusBody::Scope(mut record) = scope() else {
            panic!("scope() is a scope record");
        };
        record.flags = flags(Tri::No);
        let reason = exfiltration_refusal(&agent(Role::Scribe), &record, Some(flags(Tri::Unknown)))
            .expect("unknown → no by an agent is refused");
        assert!(
            reason.contains("payroll") && reason.contains("exfiltrated"),
            "{reason}"
        );
        let human = Principal::Human {
            key_id: "sha256:commander".to_owned(),
        };
        assert_eq!(
            exfiltration_refusal(&human, &record, Some(flags(Tri::Yes))),
            None
        );
        assert_eq!(
            exfiltration_refusal(&agent(Role::Scribe), &record, Some(flags(Tri::No))),
            None,
            "an asset that was never touched keeps its no"
        );
    }
}
