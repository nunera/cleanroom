//! Declarative host plans (`plans/*.json`): which init runs the responder host and the service
//! graph it starts. `cleanroomd plan validate FILE` checks a plan offline: names are unique,
//! every dependency is declared, and the graph has no cycle (reported with a witness path). A
//! valid plan prints its boot order. `cleanroomd plan render FILE OUT [--init dinit|s6-rc]`
//! turns a valid plan into that init's own configuration: dinit service files plus a `boot`
//! target, or an s6-rc source tree plus a `default` bundle. `nix run .#vm` boots
//! `plans/vm.json` that way, with the init chosen at boot.

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Init {
    /// dinit.
    Dinit,
    /// s6-rc.
    S6Rc,
}

impl Init {
    /// Its name.
    pub(crate) const fn name(self) -> &'static str {
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
    /// Runs on the console (the command center), so its output isn't logged to a file.
    #[serde(default)]
    console: bool,
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
    /// A service takes the name the init reserves for its own boot target.
    Reserved(String),
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
            Self::Reserved(name) => write!(
                f,
                "{name} is the name the init uses for its boot target; rename the service"
            ),
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

/// One rendered file: a path relative to the output directory, and its contents.
pub(crate) type File = (String, String);

/// The plan's services as `init`'s configuration, after validating the plan.
///
/// # Errors
/// Returns the plan's problem, or [`Problem::Reserved`] when a service is named like the
/// init's boot target (`boot` for dinit, `default` for s6-rc).
pub(crate) fn render(plan: &Plan, init: Init) -> Result<Vec<File>, Problem> {
    validate(plan)?;
    let target = match init {
        Init::Dinit => "boot",
        Init::S6Rc => "default",
    };
    if plan.services.iter().any(|service| service.name == target) {
        return Err(Problem::Reserved(target.to_owned()));
    }
    Ok(match init {
        Init::Dinit => dinit(plan),
        Init::S6Rc => s6_rc(plan),
    })
}

/// The header every rendered service carries.
fn origin(plan: &Plan, service: &Service) -> String {
    format!(
        "service {} of host plan {}, rendered by cleanroomd plan render",
        service.name, plan.host
    )
}

/// dinit: one file per service, and an internal `boot` service that depends on all of them.
fn dinit(plan: &Plan) -> Vec<File> {
    let mut files = Vec::with_capacity(plan.services.len() + 1);
    for service in &plan.services {
        let kind = match service.kind {
            Kind::Process => "process",
            Kind::Oneshot => "scripted",
        };
        let command = words(&service.command, dinit_word);
        let mut body = format!(
            "# {}\ntype = {kind}\ncommand = {command}\n",
            origin(plan, service)
        );
        for dependency in &service.depends_on {
            body.push_str(&format!("depends-on = {dependency}\n"));
        }
        if service.console {
            body.push_str("options = runs-on-console\n");
        } else if matches!(service.kind, Kind::Process) {
            body.push_str(&format!("logfile = /var/log/{}.log\n", service.name));
        }
        files.push((service.name.clone(), body));
    }
    let mut boot = format!(
        "# boot target of host plan {}, rendered by cleanroomd plan render\ntype = internal\n",
        plan.host
    );
    for service in &plan.services {
        boot.push_str(&format!("depends-on = {}\n", service.name));
    }
    files.push(("boot".to_owned(), boot));
    files
}

/// s6-rc: a source directory per service (`type`, `run` or `up`, `dependencies.d/`), and a
/// `default` bundle holding every service. `s6-rc-compile` turns it into a database.
fn s6_rc(plan: &Plan) -> Vec<File> {
    let mut files = Vec::new();
    for service in &plan.services {
        let name = &service.name;
        match service.kind {
            Kind::Process => {
                files.push((format!("{name}/type"), "longrun\n".to_owned()));
                let log = if service.console {
                    String::new()
                } else {
                    format!("exec >>/var/log/{name}.log 2>&1\n")
                };
                let command = words(&service.command, shell_word);
                files.push((
                    format!("{name}/run"),
                    format!(
                        "#!/bin/sh\n# {}\n{log}exec {command}\n",
                        origin(plan, service)
                    ),
                ));
            }
            Kind::Oneshot => {
                files.push((format!("{name}/type"), "oneshot\n".to_owned()));
                let command = words(&service.command, execline_word);
                files.push((format!("{name}/up"), format!("{command}\n")));
            }
        }
        for dependency in &service.depends_on {
            files.push((format!("{name}/dependencies.d/{dependency}"), String::new()));
        }
    }
    files.push(("default/type".to_owned(), "bundle\n".to_owned()));
    for service in &plan.services {
        files.push((
            format!("default/contents.d/{}", service.name),
            String::new(),
        ));
    }
    files
}

/// A command's whitespace-separated words, each quoted by `quote`, joined by spaces. Plan
/// commands are word lists, not shell: no expansion, no globbing.
fn words(command: &str, quote: fn(&str) -> String) -> String {
    command
        .split_whitespace()
        .map(quote)
        .collect::<Vec<_>>()
        .join(" ")
}

/// A dinit token: double-quoted, with `\`, `"`, `#` and `$` escaped so dinit takes it as is.
fn dinit_word(word: &str) -> String {
    let mut quoted = String::with_capacity(word.len() + 2);
    quoted.push('"');
    for character in word.chars() {
        if matches!(character, '\\' | '"' | '#' | '$') {
            quoted.push('\\');
        }
        quoted.push(character);
    }
    quoted.push('"');
    quoted
}

/// An execline word: double-quoted, with `\` and `"` escaped.
fn execline_word(word: &str) -> String {
    let mut quoted = String::with_capacity(word.len() + 2);
    quoted.push('"');
    for character in word.chars() {
        if matches!(character, '\\' | '"') {
            quoted.push('\\');
        }
        quoted.push(character);
    }
    quoted.push('"');
    quoted
}

/// A POSIX shell word: single-quoted, with each `'` closed, escaped and reopened.
fn shell_word(word: &str) -> String {
    format!("'{}'", word.replace('\'', r"'\''"))
}

/// `cleanroomd plan render FILE OUT [--init]`: write the init configuration of a valid plan
/// into `out`, which must not exist yet. `init` defaults to the plan's own. Exits 0 rendered,
/// 1 invalid, 2 unreadable or unwritable.
pub(crate) fn render_file(path: &Path, out: &Path, init: Option<Init>) -> ExitCode {
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
    let init = init.unwrap_or(plan.init);
    let files = match render(&plan, init) {
        Ok(files) => files,
        Err(problem) => {
            println!(
                "plan {}: host {}, init {}: INVALID\n  {problem}",
                path.display(),
                plan.host,
                init.name()
            );
            return ExitCode::from(1);
        }
    };
    if let Err(error) = write_tree(out, &files) {
        println!("plan {}: {error:#}", path.display());
        return ExitCode::from(2);
    }
    println!(
        "plan {}: host {}: {} services rendered for {} into {}",
        path.display(),
        plan.host,
        plan.services.len(),
        init.name(),
        out.display()
    );
    ExitCode::SUCCESS
}

/// Create `out` and write `files` under it; `run` scripts are executable.
fn write_tree(out: &Path, files: &[File]) -> Result<()> {
    fs::create_dir(out).with_context(|| format!("cannot create {}", out.display()))?;
    for (relative, body) in files {
        let path = out.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
        fs::write(&path, body).with_context(|| format!("cannot write {}", path.display()))?;
        if path.file_name().is_some_and(|name| name == "run") {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
                .with_context(|| format!("cannot make {} executable", path.display()))?;
        }
    }
    Ok(())
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
        "valid: {} services, every dependency declared, no cycles.\nrender it for {} (or the other init) with `cleanroomd plan render`; `nix run .#vm` boots plans/vm.json.",
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

    fn rendered(text: &str, init: Init) -> Result<Vec<(String, String)>, Problem> {
        render(&parse(text).expect("well-formed plan"), init)
    }

    fn file<'a>(files: &'a [(String, String)], name: &str) -> &'a str {
        files
            .iter()
            .find(|(file, _)| file == name)
            .map(|(_, body)| body.as_str())
            .unwrap_or_else(|| panic!("no file {name}: {files:?}"))
    }

    /// A daemon, a run-once admission after it, and a console service after that.
    fn three() -> String {
        plan(
            r#"{"name": "cleanroomd", "kind": "process", "command": "cleanroomd --state /var/lib/x", "depends_on": []},
               {"name": "admit", "kind": "oneshot", "command": "cleanroomd admit debian", "depends_on": ["cleanroomd"]},
               {"name": "tui", "kind": "process", "command": "cleanroom-tui", "depends_on": ["admit"], "console": true}"#,
        )
    }

    #[test]
    fn dinit_gets_one_service_file_per_service_and_a_boot_target() {
        let files = rendered(&three(), Init::Dinit).expect("a valid plan renders");
        let daemon = file(&files, "cleanroomd");
        assert!(daemon.contains("type = process\n"), "{daemon}");
        assert!(
            daemon.contains("command = \"cleanroomd\" \"--state\" \"/var/lib/x\"\n"),
            "each word is its own token: {daemon}"
        );
        assert!(
            daemon.contains("logfile = /var/log/cleanroomd.log\n"),
            "{daemon}"
        );
        assert!(!daemon.contains("depends-on"), "{daemon}");
        let admit = file(&files, "admit");
        assert!(admit.contains("type = scripted\n"), "{admit}");
        assert!(admit.contains("depends-on = cleanroomd\n"), "{admit}");
        let tui = file(&files, "tui");
        assert!(tui.contains("options = runs-on-console\n"), "{tui}");
        assert!(
            !tui.contains("logfile"),
            "the console service writes to the console: {tui}"
        );
        let boot = file(&files, "boot");
        assert!(boot.contains("type = internal\n"), "{boot}");
        for name in ["cleanroomd", "admit", "tui"] {
            assert!(boot.contains(&format!("depends-on = {name}\n")), "{boot}");
        }
        assert_eq!(files.len(), 4, "three services and the boot target");
    }

    #[test]
    fn s6_rc_gets_a_source_tree_with_a_default_bundle() {
        let files = rendered(&three(), Init::S6Rc).expect("a valid plan renders");
        assert_eq!(file(&files, "cleanroomd/type"), "longrun\n");
        let run = file(&files, "cleanroomd/run");
        assert!(run.starts_with("#!/bin/sh\n"), "{run}");
        assert!(
            run.contains("exec >>/var/log/cleanroomd.log 2>&1\n"),
            "{run}"
        );
        assert!(
            run.contains("exec 'cleanroomd' '--state' '/var/lib/x'\n"),
            "{run}"
        );
        assert_eq!(file(&files, "admit/type"), "oneshot\n");
        assert_eq!(
            file(&files, "admit/up"),
            "\"cleanroomd\" \"admit\" \"debian\"\n"
        );
        assert_eq!(file(&files, "admit/dependencies.d/cleanroomd"), "");
        let tui = file(&files, "tui/run");
        assert!(
            !tui.contains("/var/log"),
            "the console service writes to the console: {tui}"
        );
        assert_eq!(file(&files, "tui/dependencies.d/admit"), "");
        assert_eq!(file(&files, "default/type"), "bundle\n");
        for name in ["cleanroomd", "admit", "tui"] {
            assert_eq!(file(&files, &format!("default/contents.d/{name}")), "");
        }
    }

    #[test]
    fn commands_are_escaped_for_each_init() {
        let text = plan(
            r#"{"name": "say", "kind": "oneshot", "command": "echo \"a#b\" $HOME it's \\x", "depends_on": []}"#,
        );
        let dinit = rendered(&text, Init::Dinit).expect("renders");
        assert!(
            file(&dinit, "say").contains(r#"command = "echo" "\"a\#b\"" "\$HOME" "it's" "\\x""#),
            "{dinit:?}"
        );
        let s6 = rendered(&text, Init::S6Rc).expect("renders");
        assert_eq!(
            file(&s6, "say/up"),
            "\"echo\" \"\\\"a#b\\\"\" \"$HOME\" \"it's\" \"\\\\x\"\n"
        );
        let longrun = text.replace("oneshot", "process");
        let s6 = rendered(&longrun, Init::S6Rc).expect("renders");
        assert!(
            file(&s6, "say/run").contains(r#"exec 'echo' '"a#b"' '$HOME' 'it'\''s' '\x'"#),
            "{s6:?}"
        );
    }

    #[test]
    fn rendering_refuses_invalid_plans_and_each_inits_reserved_name() {
        let cycle = plan(&service("cleanroomd", &["cleanroomd"]));
        assert!(matches!(
            rendered(&cycle, Init::Dinit),
            Err(Problem::Cycle(_))
        ));
        assert!(matches!(
            rendered(&cycle, Init::S6Rc),
            Err(Problem::Cycle(_))
        ));
        assert_eq!(
            rendered(&plan(&service("boot", &[])), Init::Dinit),
            Err(Problem::Reserved("boot".to_owned()))
        );
        assert_eq!(
            rendered(&plan(&service("default", &[])), Init::S6Rc),
            Err(Problem::Reserved("default".to_owned()))
        );
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

    /// The plan the VM boots renders for both inits, admits both distro roots before the
    /// command center starts, and puts only the command center on the console.
    #[test]
    fn the_vm_plan_boots_under_either_init() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../plans");
        let text = fs::read_to_string(root.join("vm.json")).expect("the VM plan");
        let order = checked(&text).expect("the VM plan is valid");
        let position = |name: &str| order.iter().position(|s| s == name).expect("in order");
        for admit in ["admit-debian", "admit-alpine"] {
            assert!(position("cleanroomd") < position(admit), "{order:?}");
            assert!(position(admit) < position("cleanroom-tui"), "{order:?}");
        }
        let dinit = rendered(&text, Init::Dinit).expect("renders for dinit");
        let consoles: Vec<&str> = dinit
            .iter()
            .filter(|(_, body)| body.contains("runs-on-console"))
            .map(|(name, _)| name.as_str())
            .collect();
        assert_eq!(consoles, ["cleanroom-tui"]);
        let s6 = rendered(&text, Init::S6Rc).expect("renders for s6-rc");
        assert_eq!(
            file(&s6, "admit-alpine/up"),
            "\"cleanroomd\" \"admit\" \"alpine\"\n"
        );
    }
}
