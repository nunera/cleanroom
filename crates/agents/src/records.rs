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
    /// Scope records by asset id.
    scopes: BTreeMap<String, ScopeRecord>,
    /// Containment proposals the commander approved.
    approved: HashSet<String>,
}

impl Records {
    /// Remember that the commander approved `proposal_id`.
    pub(crate) fn approve(&mut self, proposal_id: String) {
        self.approved.insert(proposal_id);
    }

    /// How many scope records exist.
    pub(crate) fn scope_count(&self) -> usize {
        self.scopes.len()
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
    /// Returns a message for the model when a new record has no name.
    pub(crate) fn apply_scope(
        &mut self,
        mut update: ScopeUpdate,
        at: &str,
    ) -> Result<(ScopeRecord, String), String> {
        let record = if let Some(record) = self.scopes.get_mut(&update.asset_id) {
            record
        } else {
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
        apply_scope_fields(record, update);
        at.clone_into(&mut record.updated_at);
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
            *slot = Some(at.to_owned());
            changes.push(format!("{clock} started at {at}"));
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
