//! The Lead's proactive narration: one or two templated sentences per notable event, written
//! without a model call and rate-limited so the commander's chat stays readable.
//!
//! Lines wait in a short queue and go out at most one per [`GAP`], the most urgent first.
//! Proposals that arrive close together become one line, as do scope changes by the same
//! author. A waiting finding or scope line older than [`STALE`] is dropped; detonations, OS
//! denials and proposals always go out. A new investigation clears the queue.

use std::time::Duration;

use cleanroom_proto::Principal;
use tokio::time::Instant;

use crate::roles;
use crate::situation::{Blocked, LastRead, Notable, Opening};
use crate::text::preview;

/// Least time between two lines.
const GAP: Duration = Duration::from_secs(4);
/// Age at which a waiting routine line is no longer worth saying.
const STALE: Duration = Duration::from_secs(45);
/// Lines waiting at most; beyond it the least urgent, oldest line is dropped.
const MAX_WAITING: usize = 8;
/// The command center's decision keys, as the commander reads them.
const DECIDE: &str = "press a to approve or x to deny";

/// How much a line matters, least first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Urgency {
    /// First findings and scope changes: dropped when stale.
    Routine,
    /// Proposals waiting for the commander.
    Decision,
    /// The kernel stopped an agent.
    Alarm,
    /// A new investigation.
    Opening,
}

/// A line waiting to be said.
#[derive(Debug)]
enum Line {
    /// Finished text.
    Said {
        /// How much it matters.
        urgency: Urgency,
        /// The sentences.
        text: String,
    },
    /// Proposed actions waiting for the commander, said as one line.
    Proposals(Vec<String>),
    /// Scope changes by one author, said as one line.
    Scope {
        /// Who changed the records.
        by: &'static str,
        /// One change per asset.
        changes: Vec<String>,
    },
}

/// A line and when it was offered.
#[derive(Debug)]
struct Waiting {
    /// When it was offered.
    since: Instant,
    /// What to say.
    line: Line,
}

/// The queue of lines and the time of the last one said.
#[derive(Debug, Default)]
pub(crate) struct Narrator {
    /// Lines not said yet, in the order offered.
    waiting: Vec<Waiting>,
    /// When the Lead last said something.
    last: Option<Instant>,
}

impl Narrator {
    /// Queue what `notable` calls for.
    pub(crate) fn offer(&mut self, notable: Notable, now: Instant) {
        let line = match notable {
            Notable::Investigation(opening) => {
                self.waiting.clear();
                Line::Said {
                    urgency: Urgency::Opening,
                    text: opening_line(&opening),
                }
            }
            Notable::FirstDenial(blocked) => Line::Said {
                urgency: Urgency::Alarm,
                text: blocked_line(&blocked),
            },
            Notable::FirstFinding {
                role,
                summary,
                confidence,
            } => Line::Said {
                urgency: Urgency::Routine,
                text: sentence(&format!(
                    "{} first finding ({confidence}%): {}",
                    possessive(roles::title(role)),
                    preview(&summary, 160)
                )),
            },
            Notable::ProposalWaiting { action } => {
                let Some(line) = self.merge_proposal(action) else {
                    return;
                };
                line
            }
            Notable::ScopeFlip {
                by,
                asset,
                raised,
                cleared,
            } => {
                let change = scope_change(&asset, &raised, &cleared);
                let Some(line) = self.merge_scope(author(&by), change) else {
                    return;
                };
                line
            }
        };
        self.waiting.push(Waiting { since: now, line });
        if self.waiting.len() > MAX_WAITING
            && let Some(index) = self
                .waiting
                .iter()
                .enumerate()
                .min_by(|(_, a), (_, b)| {
                    a.line
                        .urgency()
                        .cmp(&b.line.urgency())
                        .then(a.since.cmp(&b.since))
                })
                .map(|(index, _)| index)
        {
            self.waiting.remove(index);
        }
    }

    /// Add `action` to the waiting proposals line; a new line when none waits.
    fn merge_proposal(&mut self, action: String) -> Option<Line> {
        for waiting in &mut self.waiting {
            if let Line::Proposals(actions) = &mut waiting.line {
                actions.push(action);
                return None;
            }
        }
        Some(Line::Proposals(vec![action]))
    }

    /// Add `change` to the waiting scope line by the same author; a new line when none waits.
    fn merge_scope(&mut self, by: &'static str, change: String) -> Option<Line> {
        for waiting in &mut self.waiting {
            if let Line::Scope {
                by: author,
                changes,
            } = &mut waiting.line
                && *author == by
            {
                changes.push(change);
                return None;
            }
        }
        Some(Line::Scope {
            by,
            changes: vec![change],
        })
    }

    /// When the next line may go out; `None` when nothing waits.
    pub(crate) fn due(&self) -> Option<Instant> {
        let first = self.waiting.iter().map(|waiting| waiting.since).min()?;
        let ready = self.last.and_then(|last| last.checked_add(GAP));
        Some(ready.map_or(first, |ready| ready.max(first)))
    }

    /// The next line to say at `now`: the most urgent, oldest first, at most one per [`GAP`].
    pub(crate) fn take(&mut self, now: Instant) -> Option<String> {
        if self
            .last
            .and_then(|last| last.checked_add(GAP))
            .is_some_and(|ready| now < ready)
        {
            return None;
        }
        self.waiting.retain(|waiting| {
            waiting.line.urgency() > Urgency::Routine
                || now.saturating_duration_since(waiting.since) <= STALE
        });
        let index = self
            .waiting
            .iter()
            .enumerate()
            .rev()
            .max_by(|(_, a), (_, b)| {
                a.line
                    .urgency()
                    .cmp(&b.line.urgency())
                    .then(b.since.cmp(&a.since))
            })
            .map(|(index, _)| index)?;
        let waiting = self.waiting.remove(index);
        self.last = Some(now);
        Some(waiting.line.into_text())
    }

    /// The Lead said something else at `now` (an answer); the next line waits a full gap.
    pub(crate) const fn spoke(&mut self, now: Instant) {
        self.last = Some(now);
    }
}

impl Line {
    /// How much the line matters.
    const fn urgency(&self) -> Urgency {
        match self {
            Self::Said { urgency, .. } => *urgency,
            Self::Proposals(_) => Urgency::Decision,
            Self::Scope { .. } => Urgency::Routine,
        }
    }

    /// The words.
    fn into_text(self) -> String {
        match self {
            Self::Said { text, .. } => text,
            Self::Proposals(actions) => proposals_line(&actions),
            Self::Scope { by, changes } => {
                format!("{by} updated the scope: {}.", changes.join("; "))
            }
        }
    }
}

/// The team starts: where it happened and who is on it.
fn opening_line(opening: &Opening) -> String {
    if opening.restarted {
        return format!(
            "Restarting the team on {}: Hunter and Forensics are back on it.",
            opening.incident_id
        );
    }
    let team = "I've put Hunter and Forensics on it; Scribe keeps the record and Containment will propose next steps.";
    if !opening.detonated {
        return format!("Investigation {} is open. {team}", opening.incident_id);
    }
    let place = if opening.systems.is_empty() {
        "the file share".to_owned()
    } else {
        join_and(&opening.systems)
    };
    if opening.locked == 0 {
        format!("Detonation on {place}. {team}")
    } else {
        format!(
            "Detonation on {place}: cleanroomd measured {} of {} data assets locked. {team}",
            opening.locked, opening.assets
        )
    }
}

/// The kernel stopped an agent: what it tried, what it had just read, and the receipt.
fn blocked_line(blocked: &Blocked) -> String {
    let who = roles::title(blocked.role);
    let command = preview(&blocked.command, 60);
    let receipt = blocked
        .receipt
        .map_or_else(String::new, |seq| format!(" Receipt #{seq}."));
    match &blocked.after {
        Some(LastRead {
            file,
            flagged: true,
        }) => format!(
            "The kernel just blocked {who} from running `{command}` after it read {file}, which the safety model had flagged.{receipt}"
        ),
        Some(LastRead {
            file,
            flagged: false,
        }) => format!(
            "The kernel just blocked {who} from running `{command}` after it read {file}.{receipt}"
        ),
        None => format!(
            "The kernel just blocked {who} from running `{command}`: {}.{receipt}",
            preview(blocked.reason.trim_end_matches('.'), 100)
        ),
    }
}

/// Proposals waiting for the commander's decision.
fn proposals_line(actions: &[String]) -> String {
    if let [action] = actions {
        return format!(
            "Containment wants to {}; select it and {DECIDE}.",
            lowercase_first(&preview(action.trim_end_matches('.'), 120))
        );
    }
    let listed: Vec<String> = actions
        .iter()
        .map(|action| preview(action.trim_end_matches('.'), 80))
        .collect();
    format!(
        "Containment has {} proposals waiting for you: {}. Select one and {DECIDE}.",
        actions.len(),
        listed.join("; ")
    )
}

/// One asset's flag changes: `Payroll export now exfiltrated, no longer modified`.
fn scope_change(asset: &str, raised: &[&str], cleared: &[&str]) -> String {
    let mut change = asset.to_owned();
    if !raised.is_empty() {
        change.push_str(" now ");
        change.push_str(&raised.join(" and "));
    }
    if !cleared.is_empty() {
        change.push_str(if raised.is_empty() {
            " no longer "
        } else {
            ", no longer "
        });
        change.push_str(&cleared.join(" or "));
    }
    change
}

/// Who changed a record, for the start of a sentence.
const fn author(principal: &Principal) -> &'static str {
    match principal {
        Principal::Agent { role } => roles::title(*role),
        Principal::Human { .. } => "A commander",
        Principal::System => "cleanroomd",
    }
}

/// `Hunter's`, `Forensics'`.
fn possessive(name: &str) -> String {
    if name.ends_with('s') {
        format!("{name}'")
    } else {
        format!("{name}'s")
    }
}

/// `a`, `a and b`, `a, b and c`.
fn join_and(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [only] => only.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// `Isolate the host` becomes `isolate the host`; an acronym such as `SSH` keeps its case.
fn lowercase_first(text: &str) -> String {
    let mut chars = text.chars();
    match (chars.next(), chars.next()) {
        (Some(first), Some(second)) if first.is_uppercase() && second.is_lowercase() => {
            first.to_lowercase().chain(text.chars().skip(1)).collect()
        }
        (Some(_) | None, _) => text.to_owned(),
    }
}

/// End `text` with a full stop unless it already ends a sentence.
fn sentence(text: &str) -> String {
    if text.ends_with(['.', '!', '?', '…']) {
        text.to_owned()
    } else {
        format!("{text}.")
    }
}

#[cfg(test)]
mod tests {
    use cleanroom_proto::Role;

    use super::*;

    fn opening() -> Notable {
        Notable::Investigation(Opening {
            incident_id: "INC-1".to_owned(),
            detonated: true,
            restarted: false,
            systems: vec!["acme-fs".to_owned()],
            locked: 4,
            assets: 4,
        })
    }

    fn denial(role: Role) -> Notable {
        Notable::FirstDenial(Blocked {
            role,
            command: "rm -rf /evidence/*".to_owned(),
            reason: "evidence is mounted read_only for hunter".to_owned(),
            receipt: Some(42),
            after: Some(LastRead {
                file: "README_RESTORE_FILES.txt".to_owned(),
                flagged: true,
            }),
        })
    }

    fn finding(role: Role) -> Notable {
        Notable::FirstFinding {
            role,
            summary: "SSH brute force from 203.0.113.45, then a login as svc-backup".to_owned(),
            confidence: 90,
        }
    }

    fn proposal(action: &str) -> Notable {
        Notable::ProposalWaiting {
            action: action.to_owned(),
        }
    }

    #[test]
    fn lines_go_out_one_per_gap_most_urgent_first() {
        let start = Instant::now();
        let mut narrator = Narrator::default();
        narrator.offer(opening(), start);
        assert_eq!(
            narrator.take(start).as_deref(),
            Some(
                "Detonation on acme-fs: cleanroomd measured 4 of 4 data assets locked. I've put Hunter and Forensics on it; Scribe keeps the record and Containment will propose next steps."
            ),
            "the opening goes out at once"
        );

        narrator.offer(finding(Role::Forensics), start);
        narrator.offer(denial(Role::Hunter), start);
        assert_eq!(narrator.take(start), None, "nothing within the gap");
        assert_eq!(
            narrator.due(),
            Some(start + GAP),
            "due one gap after the last line"
        );
        assert_eq!(
            narrator.take(start + GAP).as_deref(),
            Some(
                "The kernel just blocked Hunter from running `rm -rf /evidence/*` after it read README_RESTORE_FILES.txt, which the safety model had flagged. Receipt #42."
            ),
            "the OS denial jumps the finding"
        );
        assert_eq!(
            narrator.take(start + GAP + Duration::from_secs(1)),
            None,
            "the gap holds again"
        );
        assert_eq!(
            narrator.take(start + GAP * 2).as_deref(),
            Some(
                "Forensics' first finding (90%): SSH brute force from 203.0.113.45, then a login as svc-backup."
            ),
            "then the finding"
        );
        assert_eq!(narrator.due(), None, "nothing left");
    }

    #[test]
    fn proposals_close_together_become_one_line() {
        let start = Instant::now();
        let mut narrator = Narrator::default();
        narrator.offer(proposal("Isolate host acme-fs from the network."), start);
        assert_eq!(
            narrator.take(start).as_deref(),
            Some(
                "Containment wants to isolate host acme-fs from the network; select it and press a to approve or x to deny."
            ),
            "a lone proposal"
        );
        for action in [
            "Disable account svc-backup",
            "Block 203.0.113.45 at the firewall",
            "Preserve memory of acme-fs",
        ] {
            narrator.offer(proposal(action), start + Duration::from_secs(1));
        }
        assert_eq!(
            narrator.take(start + GAP).as_deref(),
            Some(
                "Containment has 3 proposals waiting for you: Disable account svc-backup; Block 203.0.113.45 at the firewall; Preserve memory of acme-fs. Select one and press a to approve or x to deny."
            ),
            "the burst is one line"
        );
        assert_eq!(narrator.due(), None, "and nothing else waits");
    }

    #[test]
    fn stale_routine_lines_are_dropped_but_alarms_wait() {
        let start = Instant::now();
        let mut narrator = Narrator::default();
        narrator.offer(denial(Role::Hunter), start);
        narrator.offer(denial(Role::Forensics), start);
        narrator.offer(finding(Role::Hunter), start);
        assert!(
            narrator
                .take(start)
                .is_some_and(|line| line.contains("blocked Hunter")),
            "first alarm"
        );

        let later = start + STALE + Duration::from_secs(1);
        let second = narrator.take(later);
        assert!(
            second
                .as_deref()
                .is_some_and(|line| line.contains("blocked Forensics")),
            "an alarm never goes stale: {second:?}"
        );
        assert_eq!(
            narrator.take(later + GAP),
            None,
            "the stale finding was dropped"
        );
    }

    #[test]
    fn a_new_investigation_clears_what_waits() {
        let start = Instant::now();
        let mut narrator = Narrator::default();
        narrator.spoke(start);
        narrator.offer(denial(Role::Hunter), start);
        narrator.offer(proposal("isolate acme-fs"), start);
        narrator.offer(opening(), start + Duration::from_secs(1));
        let opening_line = narrator.take(start + GAP);
        assert!(
            opening_line
                .as_deref()
                .is_some_and(|line| line.starts_with("Detonation on acme-fs")),
            "{opening_line:?}"
        );
        assert_eq!(
            narrator.due(),
            None,
            "the previous incident's lines are gone"
        );
    }

    #[test]
    fn scope_changes_by_one_author_are_merged() {
        let start = Instant::now();
        let mut narrator = Narrator::default();
        narrator.spoke(start);
        let flip = |asset: &str, raised: Vec<&'static str>, cleared: Vec<&'static str>| {
            Notable::ScopeFlip {
                by: Principal::Agent { role: Role::Scribe },
                asset: asset.to_owned(),
                raised,
                cleared,
            }
        };
        narrator.offer(
            flip("Payroll export", vec!["exfiltrated"], vec!["modified"]),
            start,
        );
        narrator.offer(
            flip(
                "Clinic patient intake",
                vec!["exfiltrated", "accessed"],
                Vec::new(),
            ),
            start,
        );
        assert_eq!(
            narrator.take(start + GAP).as_deref(),
            Some(
                "Scribe updated the scope: Payroll export now exfiltrated, no longer modified; Clinic patient intake now exfiltrated and accessed."
            ),
            "one line for Scribe's burst"
        );
    }
}
