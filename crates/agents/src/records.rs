//! Scribe's incident and scope records. The model decides what changed; this module applies the
//! change, stamps the time, and enforces what an agent may not decide alone.

use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;

use cleanroom_proto::{
    DataClass, IncidentRecord, IncidentStatus, Principal, Role, ScopeFlags, ScopeRecord, Severity,
    TimelineEntry, Timestamp, Tri, Triggers,
};

use crate::tools::{IncidentUpdate, ScopeUpdate, Trigger};

/// The incident being investigated, as announced by `investigate`.
#[derive(Debug)]
pub(crate) struct Case {
    /// Incident id from the event.
    pub(crate) incident_id: String,
    /// What the declarer said.
    pub(crate) brief: String,
    /// When the incident was declared (the event time).
    pub(crate) declared_at: Timestamp,
    /// Who declared it.
    pub(crate) declared_by: Principal,
}

/// Scribe's state for one investigation.
#[derive(Debug, Default)]
pub(crate) struct Records {
    /// The incident record, once opened.
    incident: Option<IncidentRecord>,
    /// Scope records by asset id, starting from the assets already on the bus.
    scopes: BTreeMap<String, ScopeRecord>,
    /// Scope updates Scribe made in this investigation.
    scope_updates: usize,
    /// Containment proposals the commander approved.
    approved: HashSet<String>,
    /// Flags cleanroomd itself published (its measurement), by asset id.
    measured: BTreeMap<String, ScopeFlags>,
}

impl Records {
    /// Records that start from the known scope records (the daemon's baseline or earlier
    /// updates), so Scribe updates those assets instead of inventing new ids. Records
    /// cleanroomd published are its measurement, which Scribe may add to but never lower.
    pub(crate) fn with_scopes(scopes: BTreeMap<String, ScopeRecord>) -> Self {
        let measured = scopes
            .values()
            .filter(|record| record.updated_by == Principal::System)
            .map(|record| (record.asset_id.clone(), record.flags))
            .collect();
        Self {
            scopes,
            measured,
            ..Self::default()
        }
    }

    /// Remember that the commander approved `proposal_id`.
    pub(crate) fn approve(&mut self, proposal_id: String) {
        self.approved.insert(proposal_id);
    }

    /// How many scope updates Scribe made.
    pub(crate) const fn scope_updates(&self) -> usize {
        self.scope_updates
    }

    /// Open or update the incident record. Returns the full record to publish and a result
    /// line for the model.
    ///
    /// # Errors
    /// Returns a message for the model when the update is not allowed or incomplete.
    pub(crate) fn apply_incident(
        &mut self,
        case: &Case,
        update: IncidentUpdate,
        at: &str,
    ) -> Result<(IncidentRecord, String), String> {
        if update.status == Some(IncidentStatus::Contained) && self.approved.is_empty() {
            return Err(
                "status contained needs a containment proposal the commander approved; none is approved yet"
                    .to_owned(),
            );
        }
        if !update.triggers.is_empty() && update.timeline_note.is_none() {
            return Err("give the basis for the triggers in timeline_note".to_owned());
        }
        let opened = self.incident.is_none();
        let record = match self.incident.as_mut() {
            Some(record) => record,
            None => self.incident.insert(open(case, &update)?),
        };
        let mut changes = apply_incident_fields(record, update, at);
        if opened {
            changes.insert(0, format!("opened incident record {}", record.id));
        }
        if changes.is_empty() {
            return Err("nothing to update: name at least one field".to_owned());
        }
        Ok((record.clone(), changes.join("; ")))
    }

    /// Create or update one scope record. Returns the record to publish and a result line.
    ///
    /// # Errors
    /// Returns a message for the model when a new record has no name or no evidence, or when
    /// the update would lower a flag cleanroomd measured. A new asset needs evidence so Scribe
    /// updates the known assets instead of inventing look-alike ids; the message lists them.
    pub(crate) fn apply_scope(
        &mut self,
        mut update: ScopeUpdate,
        at: &str,
    ) -> Result<(ScopeRecord, String), String> {
        let record = if let Some(record) = self.scopes.get_mut(&update.asset_id) {
            record
        } else {
            if update.evidence.is_empty() {
                let known: Vec<&str> = self.scopes.keys().map(String::as_str).collect();
                return Err(format!(
                    "scope record {} does not exist; known assets: {}. Update a known asset by its asset_id, or add a new asset only with evidence that shows it",
                    update.asset_id,
                    if known.is_empty() {
                        "none".to_owned()
                    } else {
                        known.join(", ")
                    }
                ));
            }
            let Some(name) = update.name.take() else {
                return Err(format!(
                    "scope record {} does not exist yet: include name",
                    update.asset_id
                ));
            };
            let asset_id = std::mem::take(&mut update.asset_id);
            self.scopes
                .entry(asset_id.clone())
                .or_insert_with(|| new_scope(asset_id, name, at))
        };
        let mut candidate = record.clone();
        apply_scope_fields(&mut candidate, update);
        if let Some(measured) = self.measured.get(&candidate.asset_id) {
            let lowered = candidate.flags.lowered_from(measured);
            if !lowered.is_empty() {
                return Err(format!(
                    "{} {} measured yes by cleanroomd's integrity check; you cannot lower a measurement (only the commander can). Keep those flags and record what the evidence adds",
                    candidate.asset_id,
                    lowered.join(", ")
                ));
            }
        }
        if candidate.flags.clears_exfiltration(&record.flags) {
            return Err(format!(
                "{} exfiltrated: cleanroomd cannot measure exfiltration, so an agent cannot clear it; keep it unknown (or yes with evidence) and the commander can decide no",
                candidate.asset_id
            ));
        }
        *record = candidate;
        record.updated_by = Principal::Agent { role: Role::Scribe };
        at.clone_into(&mut record.updated_at);
        self.scope_updates += 1;
        let summary = scope_line(record);
        Ok((record.clone(), format!("saved scope record {summary}")))
    }

    /// A deterministic text view for Scribe's prompt (no timestamps, so replays match).
    pub(crate) fn view(&self) -> String {
        let mut text = String::new();
        match &self.incident {
            None => text.push_str("Incident record: not opened yet.\n"),
            Some(record) => describe_incident(&mut text, record),
        }
        if self.scopes.is_empty() {
            text.push_str("Scope records: none yet.\n");
        } else {
            text.push_str("Scope records:\n");
            for record in self.scopes.values() {
                text.push_str("- ");
                text.push_str(&scope_line(record));
                text.push('\n');
            }
        }
        if !self.approved.is_empty() {
            let mut approved: Vec<&str> = self.approved.iter().map(String::as_str).collect();
            approved.sort_unstable();
            text.push_str("Commander-approved proposals: ");
            text.push_str(&approved.join(", "));
            text.push('\n');
        }
        text
    }
}

/// A new incident record from the opening update.
///
/// # Errors
/// Returns a message for the model when title, severity, category or summary is missing.
fn open(case: &Case, update: &IncidentUpdate) -> Result<IncidentRecord, String> {
    let (Some(title), Some(severity), Some(category), Some(summary)) = (
        &update.title,
        update.severity,
        &update.category,
        &update.summary,
    ) else {
        return Err(
            "the incident record is not open yet: include title, severity, category and summary"
                .to_owned(),
        );
    };
    Ok(IncidentRecord {
        id: case.incident_id.clone(),
        title: title.clone(),
        status: IncidentStatus::Analyzing,
        severity,
        category: category.clone(),
        detected_at: case.declared_at.clone(),
        reported_by: case.declared_by.clone(),
        summary: summary.clone(),
        affected_systems: Vec::new(),
        triggers: Triggers::default(),
        timeline: vec![TimelineEntry {
            at: case.declared_at.clone(),
            by: case.declared_by.clone(),
            text: format!(
                "Incident declared: {}",
                case.brief.lines().next().unwrap_or_default()
            ),
            evidence: Vec::new(),
        }],
    })
}

/// Apply every provided field; returns what changed.
fn apply_incident_fields(
    record: &mut IncidentRecord,
    update: IncidentUpdate,
    at: &str,
) -> Vec<String> {
    let mut changes = Vec::new();
    if let Some(title) = update.title.filter(|title| *title != record.title) {
        record.title = title;
        changes.push("title".to_owned());
    }
    if let Some(severity) = update
        .severity
        .filter(|severity| *severity != record.severity)
    {
        record.severity = severity;
        changes.push(format!("severity {}", severity_name(severity)));
    }
    if let Some(category) = update
        .category
        .filter(|category| *category != record.category)
    {
        record.category = category;
        changes.push(format!("category {}", record.category));
    }
    if let Some(status) = update.status.filter(|status| *status != record.status) {
        record.status = status;
        changes.push(format!("status {}", status_name(status)));
    }
    if let Some(summary) = update.summary.filter(|summary| *summary != record.summary) {
        record.summary = summary;
        changes.push("summary".to_owned());
    }
    if let Some(systems) = update
        .affected_systems
        .filter(|systems| *systems != record.affected_systems)
    {
        record.affected_systems = systems;
        changes.push(format!(
            "affected systems {}",
            record.affected_systems.join(", ")
        ));
    }
    for trigger in update.triggers {
        // Awareness and discovery run from first knowledge, the detection; a determination is
        // a decision, stamped when it is made.
        let (stamp, from) = match trigger {
            Trigger::Aware | Trigger::Discovered => (record.detected_at.clone(), " (detection)"),
            Trigger::BreachDetermined => (at.to_owned(), ""),
        };
        let (slot, clock) = match trigger {
            Trigger::Aware => (
                &mut record.triggers.aware_at,
                "GDPR awareness (72-hour clock)",
            ),
            Trigger::Discovered => (
                &mut record.triggers.discovered_at,
                "HIPAA discovery (60-day clock)",
            ),
            Trigger::BreachDetermined => (
                &mut record.triggers.breach_determined_at,
                "Texas breach determination (60-day clock; AG within 30 days at 250+ Texans)",
            ),
        };
        if let Some(stamped) = slot {
            changes.push(format!("{clock} already started at {stamped}"));
        } else {
            changes.push(format!("{clock} started at {stamp}{from}"));
            *slot = Some(stamp);
        }
    }
    if let Some(note) = update.timeline_note {
        record.timeline.push(TimelineEntry {
            at: at.to_owned(),
            by: Principal::Agent { role: Role::Scribe },
            text: note,
            evidence: update.evidence,
        });
        changes.push("timeline entry added".to_owned());
    }
    changes
}

/// An empty scope record: every flag unknown.
fn new_scope(asset_id: String, name: String, at: &str) -> ScopeRecord {
    ScopeRecord {
        asset_id,
        name,
        data_classes: Vec::new(),
        record_count: 0,
        texas_residents: 0,
        flags: ScopeFlags::default(),
        encrypted_at_rest: false,
        key_exposed: Tri::Unknown,
        confidence_pct: 0,
        evidence: Vec::new(),
        updated_by: Principal::Agent { role: Role::Scribe },
        updated_at: at.to_owned(),
    }
}

/// Apply every provided scope field; evidence is appended without duplicates.
fn apply_scope_fields(record: &mut ScopeRecord, update: ScopeUpdate) {
    let ScopeUpdate {
        name,
        data_classes,
        record_count,
        texas_residents,
        locked,
        exfiltrated,
        accessed,
        destroyed,
        modified,
        encrypted_at_rest,
        key_exposed,
        confidence_pct,
        evidence,
        asset_id: _,
    } = update;
    let flags = &mut record.flags;
    for (slot, value) in [
        (&mut flags.locked, locked),
        (&mut flags.exfiltrated, exfiltrated),
        (&mut flags.accessed, accessed),
        (&mut flags.destroyed, destroyed),
        (&mut flags.modified, modified),
        (&mut record.key_exposed, key_exposed),
    ] {
        if let Some(value) = value {
            *slot = value;
        }
    }
    if let Some(name) = name {
        record.name = name;
    }
    if let Some(classes) = data_classes {
        record.data_classes = classes;
    }
    if let Some(count) = record_count {
        record.record_count = count;
    }
    if let Some(count) = texas_residents {
        record.texas_residents = count;
    }
    if let Some(encrypted) = encrypted_at_rest {
        record.encrypted_at_rest = encrypted;
    }
    if let Some(confidence) = confidence_pct {
        record.confidence_pct = confidence.min(100);
    }
    for item in evidence {
        if !record.evidence.contains(&item) {
            record.evidence.push(item);
        }
    }
}

/// The incident part of [`Records::view`].
fn describe_incident(text: &mut String, record: &IncidentRecord) {
    let triggers: Vec<&str> = [
        (record.triggers.aware_at.is_some(), "aware"),
        (record.triggers.discovered_at.is_some(), "discovered"),
        (
            record.triggers.breach_determined_at.is_some(),
            "breach_determined",
        ),
        (
            record.triggers.materiality_determined_at.is_some(),
            "materiality_determined (human)",
        ),
    ]
    .into_iter()
    .filter_map(|(set, name)| set.then_some(name))
    .collect();
    let triggers = if triggers.is_empty() {
        "none".to_owned()
    } else {
        triggers.join(", ")
    };
    // Writing to a String cannot fail, so the results carry no information.
    let written = writeln!(
        text,
        "Incident record {}: \"{}\" | status {} | severity {} | category {}\n\
         Summary: {}\n\
         Affected systems: {}\n\
         Legal triggers recorded: {triggers}\n\
         Timeline:",
        record.id,
        record.title,
        status_name(record.status),
        severity_name(record.severity),
        record.category,
        record.summary,
        list_or_none(&record.affected_systems),
    )
    .and_then(|()| {
        record
            .timeline
            .iter()
            .try_for_each(|entry| writeln!(text, "- {}", entry.text))
    });
    if let Err(error) = written {
        tracing::debug!(%error, "cannot format the incident view");
    }
}

/// One-line description of a scope record.
fn scope_line(record: &ScopeRecord) -> String {
    let classes: Vec<&str> = record
        .data_classes
        .iter()
        .copied()
        .map(class_name)
        .collect();
    let flags = record.flags;
    format!(
        "{} \"{}\": classes {}; records {} (Texas residents {}); locked={} exfiltrated={} accessed={} destroyed={} modified={}; encrypted_at_rest={} key_exposed={}; confidence {}%",
        record.asset_id,
        record.name,
        if classes.is_empty() {
            "none".to_owned()
        } else {
            classes.join(", ")
        },
        record.record_count,
        record.texas_residents,
        tri_name(flags.locked),
        tri_name(flags.exfiltrated),
        tri_name(flags.accessed),
        tri_name(flags.destroyed),
        tri_name(flags.modified),
        record.encrypted_at_rest,
        tri_name(record.key_exposed),
        record.confidence_pct,
    )
}

/// `a, b` or `none`.
fn list_or_none(items: &[String]) -> String {
    if items.is_empty() {
        "none".to_owned()
    } else {
        items.join(", ")
    }
}

/// Wire name of a [`Tri`].
const fn tri_name(value: Tri) -> &'static str {
    match value {
        Tri::Yes => "yes",
        Tri::No => "no",
        Tri::Unknown => "unknown",
    }
}

/// Wire name of a [`DataClass`].
const fn class_name(class: DataClass) -> &'static str {
    match class {
        DataClass::Pii => "pii",
        DataClass::Phi => "phi",
        DataClass::Financial => "financial",
        DataClass::Contracts => "contracts",
        DataClass::Credentials => "credentials",
        DataClass::Other => "other",
    }
}

/// Wire name of a [`Severity`].
const fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "low",
        Severity::Moderate => "moderate",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

/// Wire name of an [`IncidentStatus`].
const fn status_name(status: IncidentStatus) -> &'static str {
    match status {
        IncidentStatus::Detected => "detected",
        IncidentStatus::Analyzing => "analyzing",
        IncidentStatus::Contained => "contained",
        IncidentStatus::Eradicated => "eradicated",
        IncidentStatus::Recovered => "recovered",
        IncidentStatus::Closed => "closed",
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const AT: &str = "2026-11-08T04:48:01Z";

    fn update(args: &serde_json::Value) -> ScopeUpdate {
        serde_json::from_value(args.clone()).expect("well-formed update_scope arguments")
    }

    /// The daemon's baseline: the organization's known asset, every flag no.
    fn known_payroll() -> Records {
        let mut payroll = new_scope("payroll".into(), "Payroll export".into(), AT);
        payroll.flags = ScopeFlags {
            locked: Tri::No,
            exfiltrated: Tri::No,
            accessed: Tri::No,
            destroyed: Tri::No,
            modified: Tri::No,
        };
        payroll.updated_by = Principal::System;
        Records::with_scopes(BTreeMap::from([("payroll".to_owned(), payroll)]))
    }

    /// A live run created `payroll-2026q3` next to the real `payroll` with no evidence; the
    /// scope table then showed the same data twice with contradicting flags.
    #[test]
    fn a_new_asset_needs_evidence_and_the_error_names_the_known_ones() {
        let mut records = known_payroll();

        let reason = records
            .apply_scope(
                update(&json!({"asset_id": "payroll-2026q3", "name": "Payroll data", "locked": "unknown"})),
                AT,
            )
            .expect_err("an asset no evidence shows is refused");

        assert!(
            reason.contains("payroll"),
            "names the known asset id: {reason}"
        );
        assert!(
            !records.view().contains("payroll-2026q3"),
            "the refused asset is not recorded"
        );
        assert_eq!(records.scope_updates(), 0, "a refusal is not an update");
    }

    #[test]
    fn a_new_asset_with_evidence_is_recorded() {
        let mut records = known_payroll();

        records
            .apply_scope(
                update(&json!({"asset_id": "backup-tapes", "name": "Backup tapes", "locked": "yes", "evidence": ["/evidence/logs/syslog:9"]})),
                AT,
            )
            .expect("evidence shows a new asset");

        assert!(
            records.view().contains("backup-tapes"),
            "the new asset is recorded"
        );
    }

    #[test]
    fn a_known_asset_updates_without_new_evidence() {
        let mut records = known_payroll();

        let (record, _) = records
            .apply_scope(
                update(&json!({"asset_id": "payroll", "accessed": "unknown"})),
                AT,
            )
            .expect("known assets keep updating as before");

        assert_eq!(record.flags.accessed, Tri::Unknown, "the flag changed");
    }

    /// A live guardrails-off run: the ransom note's "backup test" story reached Scribe, which
    /// set payroll locked=no although cleanroomd's integrity check had measured it locked.
    #[test]
    fn scribe_cannot_lower_a_flag_cleanroomd_measured() {
        let mut payroll = new_scope("payroll".into(), "Payroll export".into(), AT);
        payroll.flags = ScopeFlags {
            locked: Tri::Yes,
            exfiltrated: Tri::Unknown,
            accessed: Tri::Yes,
            destroyed: Tri::Unknown,
            modified: Tri::Yes,
        };
        payroll.updated_by = Principal::System;
        let mut records = Records::with_scopes(BTreeMap::from([("payroll".to_owned(), payroll)]));

        let reason = records
            .apply_scope(
                update(&json!({"asset_id": "payroll", "locked": "no", "modified": "no"})),
                AT,
            )
            .expect_err("a measured yes cannot be lowered");

        assert!(reason.contains("locked"), "names the flag: {reason}");
        assert!(
            reason.contains("cleanroomd"),
            "says who measured it: {reason}"
        );
        assert!(
            records.view().contains("locked=yes"),
            "the record is unchanged"
        );
        records
            .apply_scope(
                update(&json!({"asset_id": "payroll", "exfiltrated": "yes", "evidence": ["/evidence/dropbox/payroll.csv"]})),
                AT,
            )
            .expect("adding a finding to a measured record still works");
        assert!(
            records.view().contains("exfiltrated=yes"),
            "the finding is recorded"
        );
    }

    fn incident_update(args: &serde_json::Value) -> IncidentUpdate {
        serde_json::from_value(args.clone()).expect("well-formed update_incident arguments")
    }

    /// A live run: cleanroomd detected the ransomware at 04:48, and Scribe recorded GDPR
    /// awareness and HIPAA discovery when it got to them, 14 minutes later. The clocks run from
    /// first knowledge, which is the detection; a later write must not push them back.
    #[test]
    fn awareness_and_discovery_clocks_start_at_detection() {
        let detected = "2026-11-08T04:48:01Z";
        let case = Case {
            incident_id: "INC-20261108-044801".to_owned(),
            brief: "Ransomware hit the acme-fs file share.".to_owned(),
            declared_at: detected.to_owned(),
            declared_by: Principal::System,
        };
        let mut records = Records::default();
        records
            .apply_incident(
                &case,
                incident_update(&json!({"title": "Ransomware on acme-fs", "severity": "high", "category": "ransomware", "summary": "encrypted share"})),
                detected,
            )
            .expect("opens the record");

        let written = "2026-11-08T05:02:22Z";
        let (record, _) = records
            .apply_incident(
                &case,
                incident_update(&json!({"triggers": ["aware", "discovered", "breach_determined"], "timeline_note": "payroll and patient intake copied out"})),
                written,
            )
            .expect("records the triggers");

        assert_eq!(
            record.triggers.aware_at.as_deref(),
            Some(detected),
            "GDPR from detection"
        );
        assert_eq!(
            record.triggers.discovered_at.as_deref(),
            Some(detected),
            "HIPAA from detection"
        );
        assert_eq!(
            record.triggers.breach_determined_at.as_deref(),
            Some(written),
            "a determination is a decision, stamped when it is made"
        );
    }

    /// A live guardrails-off run: the ransom note's "backup test" story made Scribe write
    /// exfiltrated=no for payroll, which had been copied out. cleanroomd can't measure
    /// exfiltration, so an agent alone may not clear it.
    #[test]
    fn scribe_cannot_clear_exfiltration_on_its_own() {
        let mut payroll = new_scope("payroll".into(), "Payroll export".into(), AT);
        payroll.flags = ScopeFlags {
            locked: Tri::Yes,
            exfiltrated: Tri::Unknown,
            accessed: Tri::Yes,
            destroyed: Tri::Unknown,
            modified: Tri::Yes,
        };
        payroll.updated_by = Principal::System;
        let mut vpn = new_scope("vpn-credentials".into(), "VPN credentials".into(), AT);
        vpn.flags = ScopeFlags {
            locked: Tri::No,
            exfiltrated: Tri::No,
            accessed: Tri::No,
            destroyed: Tri::No,
            modified: Tri::No,
        };
        vpn.updated_by = Principal::System;
        let mut records = Records::with_scopes(BTreeMap::from([
            ("payroll".to_owned(), payroll),
            ("vpn-credentials".to_owned(), vpn),
        ]));

        let reason = records
            .apply_scope(
                update(&json!({"asset_id": "payroll", "exfiltrated": "no"})),
                AT,
            )
            .expect_err("unknown cannot become no on an agent's word");
        assert!(reason.contains("exfiltrat"), "names the flag: {reason}");
        assert!(records.view().contains("exfiltrated=unknown"), "unchanged");

        records
            .apply_scope(
                update(&json!({"asset_id": "vpn-credentials", "accessed": "unknown"})),
                AT,
            )
            .expect("a baseline no that nobody touches is not a clearing");
        records
            .apply_scope(
                update(&json!({"asset_id": "payroll", "exfiltrated": "yes", "evidence": ["/evidence/dropbox/payroll.csv"]})),
                AT,
            )
            .expect("raising exfiltration is allowed");
    }
}
