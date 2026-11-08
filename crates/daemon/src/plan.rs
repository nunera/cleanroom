//! Declarative host plans (`plans/*.json`): which init would run the responder host and the
//! service graph it would start. `cleanroomd plan validate FILE` checks a plan offline: names
//! are unique, every dependency is declared, and the graph has no cycle (reported with a
//! witness path). A valid plan prints its boot order. Booting a host from a plan is roadmap;
//! the output says so.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context as _, Result};
use serde::Deserialize;

/// A host plan.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Plan {
    /// Host name.
    host: String,
    /// The init that would supervise the services.
    init: Init,
    /// Services, in declaration order.
    services: Vec<Service>,
}

/// The selectable inits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Init {
    /// dinit.
    Dinit,
    /// s6-rc.
    S6Rc,
}

impl Init {
    /// Its name.
    const fn name(self) -> &'static str {
        match self {
            Self::Dinit => "dinit",
            Self::S6Rc => "s6-rc",
        }
    }
}

/// One service.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Service {
    /// Unique name.
    name: String,
    /// Long-running or run-once.
    kind: Kind,
    /// What it runs.
    command: String,
    /// Services that must be up first.
    #[serde(default)]
    depends_on: Vec<String>,
}

/// Service kinds, common to both inits (dinit process/scripted, s6-rc longrun/oneshot).
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    /// Supervised and restarted.
    Process,
    /// Runs to completion once.
    Oneshot,
}

impl Kind {
    /// Its name.
    const fn name(self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::Oneshot => "oneshot",
        }
    }
}

/// Why a plan is invalid.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Problem {
    /// Two services share a name.
    Duplicate(String),
    /// A service depends on a name no service has.
    UnknownDependency {
        /// The dependent service.
        service: String,
        /// The undeclared name.
        missing: String,
    },
    /// A dependency loop: each name depends on the next, and the last equals the first.
    Cycle(Vec<String>),
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Duplicate(name) => write!(f, "two services are named {name}"),
            Self::UnknownDependency { service, missing } => {
                write!(
                    f,
                    "{service} depends on {missing}, which no service declares"
                )
            }
            Self::Cycle(path) => write!(f, "dependency cycle: {}", path.join(" → ")),
        }
    }
}

/// Parse a plan strictly.
///
/// # Errors
/// Fails on malformed JSON, unknown fields, or an init other than dinit or s6-rc.
pub(crate) fn parse(text: &str) -> Result<Plan> {
    serde_json::from_str(text)
        .context("not a host plan (host, init: dinit or s6-rc, services with name, kind, command, depends_on)")
}

/// The boot order (every service after its dependencies, ties in declaration order).
///
/// # Errors
/// Returns the first problem: a duplicate name, an undeclared dependency, or a cycle.
pub(crate) fn validate(plan: &Plan) -> Result<Vec<String>, Problem> {
    let mut index = HashMap::new();
    for (position, service) in plan.services.iter().enumerate() {
        if index.insert(service.name.as_str(), position).is_some() {
            return Err(Problem::Duplicate(service.name.clone()));
        }
    }
    let mut edges = Vec::with_capacity(plan.services.len());
    for service in &plan.services {
        let mut targets = Vec::with_capacity(service.depends_on.len());
        for dependency in &service.depends_on {
            let Some(&target) = index.get(dependency.as_str()) else {
                return Err(Problem::UnknownDependency {
                    service: service.name.clone(),
                    missing: dependency.clone(),
                });
            };
            targets.push(target);
        }
        edges.push(targets);
    }
    let mut walk = Walk {
        edges: &edges,
        state: vec![Mark::New; plan.services.len()],
        path: Vec::new(),
        order: Vec::with_capacity(plan.services.len()),
    };
    for start in 0..plan.services.len() {
        if let Some(cycle) = walk.visit(start) {
            let names = cycle
                .into_iter()
                .filter_map(|at| plan.services.get(at).map(|service| service.name.clone()))
                .collect();
            return Err(Problem::Cycle(names));
        }
    }
    Ok(walk
        .order
        .into_iter()
        .filter_map(|at| plan.services.get(at).map(|service| service.name.clone()))
        .collect())
}

/// Depth-first walk state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mark {
    /// Not visited.
    New,
    /// On the current path.
    Open,
    /// Finished; already in the order.
    Done,
}

/// A depth-first walk along "depends on" edges: post-order is a boot order, and an edge back
/// to the current path is a cycle.
struct Walk<'a> {
    /// Dependencies by service index.
    edges: &'a [Vec<usize>],
    /// Per-service mark.
    state: Vec<Mark>,
    /// The current path.
    path: Vec<usize>,
    /// Finished services, dependencies first.
    order: Vec<usize>,
}

impl Walk<'_> {
    /// Visit `at`; returns a cycle (closed path of indices) if one is reachable.
    fn visit(&mut self, at: usize) -> Option<Vec<usize>> {
        match self.state.get(at) {
            Some(Mark::New) => {}
            Some(Mark::Open | Mark::Done) | None => return None,
        }
        self.state[at] = Mark::Open;
        self.path.push(at);
        for &next in self.edges.get(at).map_or(&[][..], Vec::as_slice) {
            if self.state.get(next) == Some(&Mark::Open) {
                let from = self.path.iter().position(|&on| on == next).unwrap_or(0);
                let mut cycle = self.path.get(from..).unwrap_or_default().to_vec();
                cycle.push(next);
                return Some(cycle);
            }
            if let Some(cycle) = self.visit(next) {
                return Some(cycle);
            }
        }
        self.path.pop();
        self.state[at] = Mark::Done;
        self.order.push(at);
        None
    }
}

/// `cleanroomd plan validate FILE`: print the boot order or the problem. Exits 0 valid, 1
/// invalid, 2 when the file is unreadable or not a plan.
pub(crate) fn validate_file(path: &Path) -> ExitCode {
    let plan = match fs::read_to_string(path)
        .with_context(|| format!("cannot read {}", path.display()))
        .and_then(|text| parse(&text))
    {
        Ok(plan) => plan,
        Err(error) => {
            println!("plan {}: {error:#}", path.display());
            return ExitCode::from(2);
        }
    };
    match validate(&plan) {
        Ok(order) => {
            println!("{}", report(path, &plan, &order));
            ExitCode::SUCCESS
        }
        Err(problem) => {
            println!(
                "plan {}: host {}, init {}: INVALID\n  {problem}",
                path.display(),
                plan.host,
                plan.init.name()
            );
            ExitCode::from(1)
        }
    }
}

/// The screen-ready boot order of a valid plan.
fn report(path: &Path, plan: &Plan, order: &[String]) -> String {
    let width = order.iter().map(String::len).max().unwrap_or(0);
    let commands = plan
        .services
        .iter()
        .map(|service| service.command.len())
        .max()
        .unwrap_or(0);
    let mut text = format!(
        "plan {}: host {}, init {}\n",
        path.display(),
        plan.host,
        plan.init.name()
    );
    for (step, name) in order.iter().enumerate() {
        let Some(service) = plan.services.iter().find(|service| service.name == *name) else {
            continue;
        };
        let after = if service.depends_on.is_empty() {
            String::new()
        } else {
            format!("  after {}", service.depends_on.join(", "))
        };
        let line = format!(
            "  {:>2}. {name:<width$}  {:<7}  {:<commands$}{after}",
            step + 1,
            service.kind.name(),
            service.command
        );
        text.push_str(line.trim_end());
        text.push('\n');
    }
    text.push_str(&format!(
        "valid: {} services, every dependency declared, no cycles.\ndeclared and validated; booting the host with {} is roadmap.",
        order.len(),
        plan.init.name()
    ));
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(services: &str) -> String {
        format!(r#"{{"host": "test", "init": "dinit", "services": [{services}]}}"#)
    }

    fn service(name: &str, depends_on: &[&str]) -> String {
        format!(
            r#"{{"name": "{name}", "kind": "process", "command": "{name}", "depends_on": {}}}"#,
            serde_json::to_string(depends_on).expect("names serialize")
        )
    }

    fn checked(text: &str) -> Result<Vec<String>, Problem> {
        validate(&parse(text).expect("well-formed plan"))
    }

    #[test]
    fn the_boot_order_starts_every_service_after_its_dependencies() {
        let text = plan(
            &[
                service("tui", &["admit"]),
                service("agents", &["cleanroomd"]),
                service("admit", &["cleanroomd"]),
                service("cleanroomd", &[]),
            ]
            .join(","),
        );
        let order = checked(&text).expect("acyclic");
        let position = |name: &str| order.iter().position(|s| s == name).expect("in order");
        for (service, dependency) in [
            ("tui", "admit"),
            ("agents", "cleanroomd"),
            ("admit", "cleanroomd"),
        ] {
            assert!(
                position(dependency) < position(service),
                "{dependency} before {service}: {order:?}"
            );
        }
        assert_eq!(order.len(), 4, "every service starts once");
    }

    #[test]
    fn a_cycle_is_reported_with_a_witness_path() {
        let text = plan(
            &[
                service("cleanroomd", &["router"]),
                service("agents", &["cleanroomd"]),
                service("router", &["agents"]),
                service("tui", &["cleanroomd"]),
            ]
            .join(","),
        );
        let Err(Problem::Cycle(path)) = checked(&text) else {
            panic!("a cycle must be found");
        };
        let edges = [
            ("cleanroomd", "router"),
            ("agents", "cleanroomd"),
            ("router", "agents"),
        ];
        assert_eq!(path.first(), path.last(), "the witness closes: {path:?}");
        assert!(path.len() >= 3, "a real loop: {path:?}");
        for pair in path.windows(2) {
            assert!(
                edges.contains(&(pair[0].as_str(), pair[1].as_str())),
                "{} → {} is a declared dependency: {path:?}",
                pair[0],
                pair[1]
            );
        }
        assert!(
            !path.contains(&"tui".to_owned()),
            "tui is not on the loop: {path:?}"
        );
    }

    #[test]
    fn a_self_dependency_is_a_cycle() {
        let Err(Problem::Cycle(path)) = checked(&plan(&service("cleanroomd", &["cleanroomd"])))
        else {
            panic!("a self loop is a cycle");
        };
        assert_eq!(path, ["cleanroomd", "cleanroomd"]);
    }

    #[test]
    fn missing_dependencies_and_duplicate_names_are_named() {
        let missing = checked(&plan(&service("agents", &["cleanroomd"])));
        assert_eq!(
            missing,
            Err(Problem::UnknownDependency {
                service: "agents".to_owned(),
                missing: "cleanroomd".to_owned()
            })
        );
        let twice = plan(&[service("cleanroomd", &[]), service("cleanroomd", &[])].join(","));
        assert_eq!(
            checked(&twice),
            Err(Problem::Duplicate("cleanroomd".to_owned()))
        );
    }

    #[test]
    fn only_dinit_and_s6_rc_are_inits() {
        let text = r#"{"host": "test", "init": "systemd", "services": []}"#;
        let error = parse(text).expect_err("systemd is not a choice here");
        assert!(format!("{error:#}").contains("init"), "{error:#}");
    }

    /// The plans shipped in `plans/`, read through the real parser and validator.
    #[test]
    fn the_shipped_plans_validate_as_documented() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../plans");
        let responder = fs::read_to_string(root.join("responder.json")).expect("example plan");
        let order = checked(&responder).expect("the example plan is valid");
        assert_eq!(
            order.first().map(String::as_str),
            Some("cleanroomd"),
            "the OS core starts first"
        );
        let broken = fs::read_to_string(root.join("cycle.json")).expect("broken example plan");
        assert!(
            matches!(checked(&broken), Err(Problem::Cycle(_))),
            "the broken example shows a cycle witness"
        );
    }
}
