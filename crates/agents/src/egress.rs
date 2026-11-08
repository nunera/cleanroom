//! The egress policy, `policy/egress.json`: deny by default; the model router may reach only
//! the declared model endpoints. It is compiled into this binary, so swapping a file at run time
//! cannot widen it.
//!
//! Agent strata get no network at all (cleanroomd gives every stratum an empty network
//! namespace), and in replay mode the router builds no network client, so this policy is the
//! only egress the agent team has.

use anyhow::{Context as _, Result};
use reqwest::Url;
use serde::Deserialize;

/// The policy shipped with this build.
const SHIPPED: &str = include_str!("../../../policy/egress.json");

/// `policy/egress.json`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    /// What is not listed.
    default: Default,
    /// Origins the model router may reach.
    model_router: Vec<Rule>,
}

/// The only default there is.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Default {
    /// Everything not listed is denied.
    Deny,
}

/// One allowed origin.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    /// `scheme://host[:port]`, no path.
    origin: String,
    /// Why it is allowed, for people reading the file and the status line.
    why: String,
}

/// The parsed policy: allowed origins in serialized form, with their reasons.
#[derive(Debug)]
pub(crate) struct Policy {
    /// `(origin, why)`.
    allowed: Vec<(String, String)>,
}

impl Policy {
    /// The policy compiled into this binary.
    ///
    /// # Errors
    /// Fails if the shipped file is malformed or lists something that is not an origin.
    pub(crate) fn shipped() -> Result<Self> {
        let file: File =
            serde_json::from_str(SHIPPED).context("policy/egress.json is not an egress policy")?;
        let File {
            default: Default::Deny,
            model_router,
        } = file;
        let allowed = model_router
            .into_iter()
            .map(|rule| {
                let origin = origin(&rule.origin)
                    .filter(|origin| *origin == rule.origin)
                    .with_context(|| {
                        format!(
                            "policy/egress.json: `{}` is not an origin (scheme://host[:port])",
                            rule.origin
                        )
                    })?;
                Ok((origin, rule.why))
            })
            .collect::<Result<_>>()?;
        Ok(Self { allowed })
    }

    /// Why the model router may reach `url`.
    ///
    /// # Errors
    /// Returns the denial, naming what is allowed, when `url`'s origin is not listed.
    pub(crate) fn check(&self, url: &str) -> Result<&str, String> {
        let Some(origin) = origin(url) else {
            return Err(format!("egress policy: `{url}` is not a URL"));
        };
        self.allowed
            .iter()
            .find(|(allowed, _)| *allowed == origin)
            .map(|(_, why)| why.as_str())
            .ok_or_else(|| {
                let allowed: Vec<&str> = self.allowed.iter().map(|(o, _)| o.as_str()).collect();
                format!(
                    "egress policy (policy/egress.json) denies {origin}: the model router may reach only {}",
                    allowed.join(", ")
                )
            })
    }
}

/// `scheme://host[:port]` of an HTTP(S) URL; `None` for anything else.
fn origin(url: &str) -> Option<String> {
    let url = Url::parse(url).ok()?;
    matches!(url.scheme(), "http" | "https").then(|| url.origin().ascii_serialization())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_policy_allows_only_the_model_endpoints() {
        let policy = Policy::shipped().expect("policy/egress.json parses");

        for allowed in [
            "https://integrate.api.nvidia.com/v1",
            "http://127.0.0.1:8000/v1",
        ] {
            assert!(
                policy.check(allowed).is_ok(),
                "{allowed} is a model endpoint"
            );
        }
        for denied in [
            "https://evil.example/v1",
            "https://integrate.api.nvidia.com.evil.example/v1",
            "http://integrate.api.nvidia.com/v1",
            "https://integrate.api.nvidia.com:8443/v1",
            "http://127.0.0.1:9000/v1",
            "not a url",
        ] {
            let reason = policy.check(denied).expect_err("outside the policy");
            assert!(reason.contains("egress policy"), "{denied}: {reason}");
        }
    }
}
