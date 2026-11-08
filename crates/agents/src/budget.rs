//! Reasoning budgets: how many tokens each agent's Nemotron model may spend reasoning per step,
//! from `policy/reasoning.json` (compiled in, like the egress policy). The router sends the
//! budget as `reasoning_budget`; the `model_call` receipts record what was actually spent.

use anyhow::{Context as _, Result, bail};
use cleanroom_proto::Role;
use serde::Deserialize;

/// The policy shipped with this build.
const SHIPPED: &str = include_str!("../../../policy/reasoning.json");
/// Tokens of a step's `max_tokens` kept for the answer (tool call or text) after reasoning.
pub(crate) const ANSWER_ROOM: u32 = 512;
/// A step's `max_tokens`.
pub(crate) const STEP_MAX_TOKENS: u32 = crate::llm::AGENT_MAX_TOKENS;

/// `policy/reasoning.json`.
#[derive(Debug, Deserialize)]
struct File {
    /// Budgets per role.
    budgets: Budgets,
}

/// Reasoning tokens per step, per role.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Budgets {
    /// Lead.
    lead: u32,
    /// Hunter.
    hunter: u32,
    /// Forensics.
    forensics: u32,
    /// Scribe.
    scribe: u32,
    /// Containment.
    containment: u32,
}

impl Budgets {
    /// The budgets shipped in `policy/reasoning.json`.
    ///
    /// # Errors
    /// Fails if the shipped file is malformed or a budget is out of range.
    pub(crate) fn shipped() -> Result<Self> {
        Self::parse(SHIPPED)
    }

    /// Parse and check a policy: every role has a budget above zero that leaves
    /// [`ANSWER_ROOM`] tokens of [`STEP_MAX_TOKENS`] for the answer.
    ///
    /// # Errors
    /// Fails if `text` is not a policy or a budget is out of range.
    pub(crate) fn parse(text: &str) -> Result<Self> {
        let File { budgets } = serde_json::from_str(text)
            .context("policy/reasoning.json is not a reasoning policy")?;
        for role in crate::roles::ALL {
            let budget = budgets.for_role(role);
            let limit = STEP_MAX_TOKENS - ANSWER_ROOM;
            if budget == 0 || budget > limit {
                bail!(
                    "{}'s reasoning budget is {budget}; it must be 1 to {limit} so {ANSWER_ROOM} of the step's {STEP_MAX_TOKENS} tokens are left for the answer",
                    crate::roles::name(role)
                );
            }
        }
        Ok(budgets)
    }

    /// `role`'s reasoning budget per step.
    pub(crate) const fn for_role(self, role: Role) -> u32 {
        match role {
            Role::Lead => self.lead,
            Role::Hunter => self.hunter,
            Role::Forensics => self.forensics,
            Role::Scribe => self.scribe,
            Role::Containment => self.containment,
        }
    }

    /// `lead 1024, hunter 1024, …` for the status line.
    pub(crate) fn summary(self) -> String {
        crate::roles::ALL
            .iter()
            .map(|&role| format!("{} {}", crate::roles::name(role), self.for_role(role)))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A model that spends its whole step reasoning answers nothing (a live run did exactly
    /// that), so every shipped budget must leave room for the answer.
    #[test]
    fn every_shipped_budget_leaves_room_for_the_answer() {
        let budgets = Budgets::shipped().expect("policy/reasoning.json is valid");
        for role in crate::roles::ALL {
            let budget = budgets.for_role(role);
            assert!(budget > 0, "{role:?}");
            assert!(
                budget + ANSWER_ROOM <= STEP_MAX_TOKENS,
                "{role:?}: {budget}"
            );
        }
    }

    #[test]
    fn a_budget_that_crowds_out_the_answer_is_refused() {
        let greedy = r#"{"budgets": {"lead": 1024, "hunter": 2000, "forensics": 1024, "scribe": 1024, "containment": 768}}"#;
        let error = Budgets::parse(greedy).expect_err("hunter's budget leaves no room");
        assert!(format!("{error:#}").contains("hunter"), "{error:#}");
        let missing = r#"{"budgets": {"lead": 1024}}"#;
        assert!(
            Budgets::parse(missing).is_err(),
            "every role needs a budget"
        );
    }
}
