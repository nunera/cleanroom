//! The agent team as the command center sees it: each role's live status, last action and model,
//! and which Lead↔specialist links are open. Built from bus events alone, at the console's clock.

use cleanroom_proto::{ModelRoute, Role};
use jiff::{SignedDuration, Timestamp};

/// The four specialists under the Lead, in card order.
pub(crate) const SPECIALISTS: [Role; 4] = [
    Role::Hunter,
    Role::Forensics,
    Role::Scribe,
    Role::Containment,
];

/// `Lead`, `Hunter`, …: a role's name in a sentence.
pub(crate) const fn title(role: Role) -> &'static str {
    match role {
        Role::Lead => "Clean",
        Role::Hunter => "Hunter",
        Role::Forensics => "Forensics",
        Role::Scribe => "Scribe",
        Role::Containment => "Containment",
    }
}

/// The role an `@name` addresses: a role's name or any prefix of it (`@h`, `@hunt`, `@hunter`),
/// case-insensitive. Every role starts with a different letter, so one letter is enough.
pub(crate) fn mention(name: &str) -> Option<Role> {
    let name = name.to_lowercase();
    if name.is_empty() {
        return None;
    }
    [
        Role::Lead,
        Role::Hunter,
        Role::Forensics,
        Role::Scribe,
        Role::Containment,
    ]
    .into_iter()
    .find(|role| title(*role).to_lowercase().starts_with(&name))
}

/// How long "BLOCKED BY OS" stays on a card after the denial arrives.
const BLOCKED_FOR: SignedDuration = SignedDuration::from_secs(6);
/// How long "refused" stays on a card.
const REFUSED_FOR: SignedDuration = SignedDuration::from_secs(6);
/// How long "running <tool>" shows after a step's trace arrives.
const RUNNING_FOR: SignedDuration = SignedDuration::from_millis(2500);
/// A question nobody answered stops counting as open; the Lead itself waits about 45 s.
pub(crate) const LINK_TIMEOUT: SignedDuration = SignedDuration::from_secs(60);
/// The Lead always answers a human; after this long without an answer it counts as idle.
const ANSWER_TIMEOUT: SignedDuration = SignedDuration::from_secs(120);
/// A loop that published nothing for this long counts as idle, even without a final answer.
const STALE_AFTER: SignedDuration = SignedDuration::from_secs(120);

/// Who asked a role a question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Asker {
    /// The Lead delegated it.
    Lead,
    /// A human asked directly.
    Human,
}

/// One role's live facts.
#[derive(Debug, Clone, Default)]
pub(crate) struct Desk {
    /// Model id, when the agent runtime announced it.
    pub(crate) model: Option<String>,
    /// Latest routing decision (local or hosted model).
    pub(crate) route: Option<ModelRoute>,
    /// The last thing it did, as one line.
    pub(crate) last: Option<String>,
    /// When its loop last showed it was working; `None` once it gave its final answer.
    working: Option<Timestamp>,
    /// Latest tool step and when its trace arrived.
    step: Option<(String, Timestamp)>,
    /// When the OS last denied one of its commands.
    blocked: Option<Timestamp>,
    /// When it last refused an instruction found in untrusted data.
    refused: Option<Timestamp>,
    /// An open question to it: who asked and when.
    asked: Option<(Asker, Timestamp)>,
}

/// What a card says right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Status {
    /// Nothing in flight.
    Idle,
    /// Its loop is running or it is composing an answer.
    Thinking,
    /// The Lead is waiting on these specialists.
    Asking(Vec<Role>),
    /// A tool step just ran.
    Running(String),
    /// The OS denied one of its commands moments ago.
    Blocked,
    /// It just declined an instruction found in untrusted data.
    Refused,
    /// It is waiting for the commander's signature.
    Waiting,
}

/// The Lead and the four specialists.
#[derive(Debug, Clone, Default)]
pub(crate) struct Team {
    /// The commander's point of contact.
    lead: Desk,
    /// Logs and YARA.
    hunter: Desk,
    /// Memory and packets.
    forensics: Desk,
    /// The incident record.
    scribe: Desk,
    /// Containment proposals.
    containment: Desk,
}

impl Team {
    /// The desk of `role`.
    pub(crate) const fn desk(&self, role: Role) -> &Desk {
        match role {
            Role::Lead => &self.lead,
            Role::Hunter => &self.hunter,
            Role::Forensics => &self.forensics,
            Role::Scribe => &self.scribe,
            Role::Containment => &self.containment,
        }
    }

    /// The desk of `role`, to change it.
    const fn desk_mut(&mut self, role: Role) -> &mut Desk {
        match role {
            Role::Lead => &mut self.lead,
            Role::Hunter => &mut self.hunter,
            Role::Forensics => &mut self.forensics,
            Role::Scribe => &mut self.scribe,
            Role::Containment => &mut self.containment,
        }
    }

    /// The team was started on an incident: Hunter, Forensics and Scribe begin at once
    /// (Containment waits for findings).
    pub(crate) fn investigate(&mut self, now: Timestamp) {
        for role in [Role::Hunter, Role::Forensics, Role::Scribe] {
            self.desk_mut(role).working = Some(now);
        }
    }

    /// The investigation ended or the agents went offline.
    pub(crate) fn finished(&mut self) {
        for role in SPECIALISTS {
            let desk = self.desk_mut(role);
            desk.working = None;
            desk.step = None;
        }
    }

    /// One step of `role`'s loop. `answer` is its final answer, which ends the loop.
    pub(crate) fn step(&mut self, role: Role, tool: &str, line: String, now: Timestamp) {
        let desk = self.desk_mut(role);
        desk.last = Some(line);
        if tool == "answer" {
            desk.working = None;
            desk.step = None;
        } else {
            desk.working = Some(now);
            desk.step = Some((tool.to_owned(), now));
        }
    }

    /// The OS denied one of `role`'s commands.
    pub(crate) const fn blocked(&mut self, role: Role, now: Timestamp) {
        self.desk_mut(role).blocked = Some(now);
    }

    /// `role` declined an injected instruction.
    pub(crate) fn refused(&mut self, role: Role, line: String, now: Timestamp) {
        let desk = self.desk_mut(role);
        desk.refused = Some(now);
        desk.last = Some(line);
    }

    /// `role` did something worth a line on its card (a finding, a proposal, a tool request).
    pub(crate) fn noted(&mut self, role: Role, line: String) {
        self.desk_mut(role).last = Some(line);
    }

    /// A human asked `role` something directly (the Lead included).
    pub(crate) const fn asked_by_human(&mut self, role: Role, now: Timestamp) {
        self.desk_mut(role).asked = Some((Asker::Human, now));
    }

    /// The Lead delegated a question to `role`.
    pub(crate) fn delegated(&mut self, role: Role, line: String, now: Timestamp) {
        self.desk_mut(role).asked = Some((Asker::Lead, now));
        self.lead.last = Some(line);
    }

    /// `role` said something on the bus: any open question to it is answered.
    pub(crate) fn spoke(&mut self, role: Role, line: String) {
        let desk = self.desk_mut(role);
        desk.asked = None;
        desk.last = Some(line);
    }

    /// The agent runtime announced the models it runs.
    pub(crate) fn models(&mut self, models: Vec<(Role, String)>) {
        for (role, model) in models {
            self.desk_mut(role).model = Some(model);
        }
    }

    /// `role`'s conversation moved to the local or the hosted model.
    pub(crate) const fn route(&mut self, role: Role, route: ModelRoute) {
        self.desk_mut(role).route = Some(route);
    }

    /// Forget everything about the last incident; models and routes belong to the runtime.
    pub(crate) fn clear(&mut self) {
        for role in std::iter::once(Role::Lead).chain(SPECIALISTS) {
            let desk = self.desk_mut(role);
            *desk = Desk {
                model: desk.model.take(),
                route: desk.route,
                ..Desk::default()
            };
        }
    }

    /// Whether the Lead↔`role` link is lit: the Lead asked `role` and is still waiting.
    pub(crate) fn link(&self, role: Role, now: Timestamp) -> bool {
        matches!(self.desk(role).asked, Some((Asker::Lead, at)) if within(at, now, LINK_TIMEOUT))
    }

    /// What `role`'s card says at `now`. `waiting` is true when something of its waits for the
    /// commander's signature.
    pub(crate) fn status(&self, role: Role, waiting: bool, now: Timestamp) -> Status {
        if role == Role::Lead {
            return self.lead_status(now);
        }
        let desk = self.desk(role);
        let recent = |at: Option<Timestamp>, window| at.is_some_and(|at| within(at, now, window));
        if recent(desk.blocked, BLOCKED_FOR) {
            return Status::Blocked;
        }
        if waiting {
            return Status::Waiting;
        }
        if recent(desk.refused, REFUSED_FOR) {
            return Status::Refused;
        }
        if let Some((tool, at)) = &desk.step
            && within(*at, now, RUNNING_FOR)
        {
            return Status::Running(tool.clone());
        }
        let asked = desk
            .asked
            .is_some_and(|(_, at)| within(at, now, LINK_TIMEOUT));
        if asked || recent(desk.working, STALE_AFTER) {
            Status::Thinking
        } else {
            Status::Idle
        }
    }

    /// The Lead's card: a running step, then open delegations, then an unanswered human.
    fn lead_status(&self, now: Timestamp) -> Status {
        if let Some((tool, at)) = &self.lead.step
            && within(*at, now, RUNNING_FOR)
        {
            return Status::Running(tool.clone());
        }
        let asking: Vec<Role> = SPECIALISTS
            .into_iter()
            .filter(|role| self.link(*role, now))
            .collect();
        if !asking.is_empty() {
            return Status::Asking(asking);
        }
        match self.lead.asked {
            Some((_, at)) if within(at, now, ANSWER_TIMEOUT) => Status::Thinking,
            Some(_) | None => Status::Idle,
        }
    }
}

/// Whether `at` is less than `window` before `now` (and not in the future by more than it).
fn within(at: Timestamp, now: Timestamp, window: SignedDuration) -> bool {
    now.duration_since(at) < window
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: i64) -> Timestamp {
        Timestamp::from_second(1_800_000_000 + seconds).expect("fixed test time")
    }

    #[test]
    fn a_delegation_lights_its_link_until_the_specialist_answers() {
        let mut team = Team::default();
        team.delegated(Role::Hunter, "asked Hunter".to_owned(), at(0));

        assert!(team.link(Role::Hunter, at(5)), "open while Hunter thinks");
        assert!(!team.link(Role::Forensics, at(5)), "only Hunter was asked");
        assert_eq!(team.status(Role::Hunter, false, at(5)), Status::Thinking);
        assert_eq!(
            team.status(Role::Lead, false, at(5)),
            Status::Asking(vec![Role::Hunter])
        );

        team.spoke(Role::Hunter, "→ Lead: found the note".to_owned());
        assert!(!team.link(Role::Hunter, at(6)), "the reply closes the link");
        assert_eq!(team.status(Role::Lead, false, at(6)), Status::Idle);
    }

    #[test]
    fn an_unanswered_delegation_times_out() {
        let mut team = Team::default();
        team.delegated(Role::Scribe, "asked Scribe".to_owned(), at(0));
        assert!(
            team.link(Role::Scribe, at(59)),
            "still open just inside the timeout"
        );
        assert!(
            !team.link(Role::Scribe, at(61)),
            "closed once the timeout passes"
        );
    }

    #[test]
    fn a_human_question_is_not_a_lead_link() {
        let mut team = Team::default();
        team.asked_by_human(Role::Forensics, at(0));
        assert!(!team.link(Role::Forensics, at(1)), "no Lead↔Forensics link");
        assert_eq!(team.status(Role::Forensics, false, at(1)), Status::Thinking);
    }

    #[test]
    fn a_block_flashes_on_the_card_then_the_loop_shows_again() {
        let mut team = Team::default();
        team.investigate(at(0));
        team.step(
            Role::Hunter,
            "exec",
            "#5 exec rm -rf /evidence/*".to_owned(),
            at(10),
        );
        team.blocked(Role::Hunter, at(10));

        assert_eq!(team.status(Role::Hunter, false, at(11)), Status::Blocked);
        assert_eq!(
            team.status(Role::Hunter, true, at(12)),
            Status::Blocked,
            "the block outranks waiting while it shows"
        );
        assert_eq!(team.status(Role::Hunter, false, at(17)), Status::Thinking);

        team.step(Role::Hunter, "answer", "done".to_owned(), at(20));
        assert_eq!(team.status(Role::Hunter, false, at(21)), Status::Idle);
    }
}
