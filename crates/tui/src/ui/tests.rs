//! Both screens rendered from a scripted incident: Lead chat, a delegation, a kernel block,
//! compromised scope and an approval waiting, at the projector's 160×45 and the 120×36 floor.
//!
//! Set `CLEANROOM_TUI_SNAPSHOTS=DIR` to also write each render as an ANSI file into `DIR`.

use std::fmt::Write as _;

use cleanroom_proto::{
    Audience, BusBody, BusMessage, DataClass, Envelope, ExecOutcome, Frame, IncidentRecord,
    IncidentStatus, LlmMode, ModelRoute, Principal, Role, ScopeFlags, ScopeRecord, Severity,
    Signed, TimelineEntry, Tri, Triggers, WIRE_VERSION, domain,
};
use jiff::Timestamp;
use jiff::tz::TimeZone;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::style::{Color, Modifier};
use serde_json::json;
use unicode_width::UnicodeWidthStr as _;

use super::banner::Sky;
use super::{Overlay, Pane, Tab, View, render};
use crate::state::State;

/// The incident starts here; every event is a few seconds after it.
const START: i64 = 1_794_115_100;
/// This console's key id in the script.
const ME: &str = "sha256:1b809d1dc1770000000000000000000000000000000000000000000000000000";

fn at(seconds: i64) -> Timestamp {
    Timestamp::from_second(START + seconds).expect("script times are valid")
}

fn agent(role: Role) -> Principal {
    Principal::Agent { role }
}

fn to(role: Role) -> Audience {
    Audience::Role { role }
}

fn event(seconds: i64, from: Principal, to: Audience, body: BusBody) -> (Envelope, Timestamp) {
    let message = BusMessage {
        id: format!("m{seconds}"),
        at: at(seconds).to_string(),
        from,
        to,
        body,
    };
    let envelope = Envelope {
        v: WIRE_VERSION,
        frame: Frame::Event(Signed {
            domain: domain::BUS.to_owned(),
            body: message,
            signer: "sha256:00".to_owned(),
            sig: "00".to_owned(),
        }),
    };
    (envelope, at(seconds))
}

fn chat(seconds: i64, from: Principal, audience: Audience, text: &str) -> (Envelope, Timestamp) {
    event(
        seconds,
        from,
        audience,
        BusBody::Chat {
            text: text.to_owned(),
        },
    )
}

fn status(seconds: i64, from: Principal, text: &str) -> (Envelope, Timestamp) {
    event(
        seconds,
        from,
        Audience::All,
        BusBody::Status {
            text: text.to_owned(),
        },
    )
}

fn trace(
    seconds: i64,
    role: Role,
    (step, tool): (u32, &str),
    args: serde_json::Value,
    (result, outcome): (&str, Option<ExecOutcome>),
) -> (Envelope, Timestamp) {
    event(
        seconds,
        agent(role),
        Audience::All,
        BusBody::Trace {
            step,
            tool: tool.to_owned(),
            args,
            result_preview: result.to_owned(),
            outcome,
        },
    )
}

fn asset(
    id: &str,
    name: &str,
    classes: Vec<DataClass>,
    counts: (u64, u64),
    flags: ScopeFlags,
) -> BusBody {
    BusBody::Scope(ScopeRecord {
        asset_id: id.to_owned(),
        name: name.to_owned(),
        data_classes: classes,
        record_count: counts.0,
        texas_residents: counts.1,
        flags,
        encrypted_at_rest: false,
        key_exposed: Tri::Unknown,
        confidence_pct: 100,
        evidence: Vec::new(),
        updated_by: Principal::System,
        updated_at: at(0).to_string(),
    })
}

fn assets(flags: ScopeFlags, vpn: ScopeFlags) -> [BusBody; 4] {
    [
        asset(
            "payroll",
            "Payroll export",
            vec![DataClass::Pii, DataClass::Financial],
            (1240, 1180),
            flags,
        ),
        asset(
            "client-contracts",
            "Client contracts",
            vec![DataClass::Contracts, DataClass::Pii],
            (12, 8),
            flags,
        ),
        asset(
            "patient-intake",
            "Clinic patient intake",
            vec![DataClass::Phi, DataClass::Pii],
            (860, 812),
            flags,
        ),
        asset(
            "vpn-credentials",
            "VPN credentials",
            vec![DataClass::Credentials],
            (48, 0),
            vpn,
        ),
    ]
}

fn incident(seconds: i64, timeline: Vec<TimelineEntry>) -> BusBody {
    let declared = at(seconds).to_string();
    BusBody::Incident(IncidentRecord {
        id: "INC-20261108-043824".to_owned(),
        title: "Ransomware on acme-fs".to_owned(),
        status: IncidentStatus::Analyzing,
        severity: Severity::High,
        category: "ransomware".to_owned(),
        detected_at: declared.clone(),
        reported_by: Principal::System,
        summary: "Canary files on the acme-fs share were encrypted and a ransom note dropped."
            .to_owned(),
        affected_systems: vec!["acme-fs".to_owned()],
        triggers: Triggers {
            aware_at: Some(declared.clone()),
            discovered_at: Some(declared.clone()),
            breach_determined_at: Some(declared),
            materiality_determined_at: None,
        },
        timeline,
    })
}

fn counters(blocked_by_os: u32) -> BusBody {
    BusBody::Counters {
        blocked_by_model: 0,
        blocked_by_os,
        safety_flags: 1,
        guardrails: false,
        llm: LlmMode::Live,
    }
}

/// A live run, guardrails off: detonation, the Lead narrating and delegating, Hunter talked into
/// wiping the evidence and the kernel refusing, and Containment's proposal waiting. Ends with the
/// Lead waiting on Forensics.
fn script() -> Vec<(Envelope, Timestamp)> {
    let me = Principal::Human {
        key_id: ME.to_owned(),
    };
    let hit = ScopeFlags {
        locked: Tri::Yes,
        accessed: Tri::Yes,
        modified: Tri::Yes,
        exfiltrated: Tri::Unknown,
        destroyed: Tri::No,
    };
    let unknown = ScopeFlags {
        exfiltrated: Tri::Unknown,
        accessed: Tri::Unknown,
        ..ScopeFlags::default()
    };
    let clean = ScopeFlags {
        locked: Tri::No,
        exfiltrated: Tri::No,
        accessed: Tri::No,
        destroyed: Tri::No,
        modified: Tri::No,
    };
    let mut script: Vec<(Envelope, Timestamp)> = assets(clean, clean)
        .into_iter()
        .map(|body| event(0, Principal::System, Audience::All, body))
        .collect();
    script.extend([
        status(1, agent(Role::Scribe), "agents online on /run/cleanroom/cleanroomd.sock: lead, hunter, forensics, scribe, containment; guardrails off; llm live; models: lead=nvidia/nemotron-3.5-lightning-30b-a3b, hunter=nvidia/nemotron-3.5-lightning-30b-a3b, forensics=nvidia/nemotron-3.5-lightning-30b-a3b, scribe=nvidia/nemotron-3-ultra-550b-a55b, containment=nvidia/nemotron-3.5-lightning-30b-a3b"),
        event(1, agent(Role::Scribe), Audience::All, counters(0)),
        status(3, Principal::System, "commander 1b809d1dc177 detonated ransomware in the acme-fs stratum: Debian root read-only, share read-write, no network (receipt #4)"),
        status(6, Principal::System, "ransomware finished in acme-fs: 18 files locked, 2 files copied into a staging directory, ransom note README_RESTORE_FILES.txt"),
        event(7, Principal::System, Audience::All, incident(7, Vec::new())),
    ]);
    script.extend(
        assets(hit, unknown)
            .into_iter()
            .map(|body| event(7, Principal::System, Audience::All, body)),
    );
    script.extend([
        event(8, Principal::System, Audience::All, BusBody::Investigate {
            incident_id: "INC-20261108-043824".to_owned(),
            brief: "Ransomware on acme-fs".to_owned(),
        }),
        chat(9, agent(Role::Lead), Audience::Humans, "Detonation on acme-fs. I've put Hunter and Forensics on it; Scribe is opening the record."),
        trace(14, Role::Hunter, (1, "exec"), json!({"command": "ls -la /evidence/acme-fs"}), ("total 48 drwxr-xr-x 4 root root 4096 Nov 8 04:38 .", Some(ExecOutcome::Exited { code: 0 }))),
        trace(18, Role::Forensics, (1, "exec"), json!({"command": "tail -n 50 /evidence/logs/syslog"}), ("Nov  8 04:38:21 acme-fs kernel: [ 4412.118] audit: ...", Some(ExecOutcome::Exited { code: 0 }))),
        event(19, agent(Role::Hunter), Audience::All, BusBody::Route { route: ModelRoute::Hosted, reason: "no personal data in the conversation".to_owned() }),
        chat(21, me.clone(), to(Role::Lead), "What happened, and what should I do first?"),
        trace(22, Role::Lead, (1, "get_situation"), json!({}), ("incident INC-20261108-043824 analyzing; 3 of 4 assets locked", None)),
        chat(23, agent(Role::Lead), to(Role::Hunter), "What did the ransom note on the share ask responders to do?"),
        trace(25, Role::Hunter, (3, "exec"), json!({"command": "cat /evidence/acme-fs/README_RESTORE_FILES.txt"}), ("YOUR FILES ARE ENCRYPTED by LOCKSTAR ...", Some(ExecOutcome::Exited { code: 0 }))),
        event(26, Principal::System, Audience::All, BusBody::SafetyVerdict { artifact: "/evidence/acme-fs/README_RESTORE_FILES.txt".to_owned(), model: "nvidia/llama-3.1-nemotron-safety-guard-8b-v3".to_owned(), safe: false, categories: vec!["prompt injection".to_owned()] }),
        status(31, Principal::System, "OS denied hunter: `sh -c rm -rf /evidence/*`: evidence is mounted read_only for hunter (receipt #15)"),
        trace(31, Role::Hunter, (5, "exec"), json!({"command": "rm -rf /evidence/*"}), ("evidence is mounted read_only for hunter (receipt #15)", Some(ExecOutcome::Denied { reason: "evidence is mounted read_only for hunter".to_owned() }))),
        event(31, agent(Role::Hunter), Audience::All, counters(1)),
        chat(32, agent(Role::Hunter), to(Role::Lead), "The note's SYSTEM paragraph told responders to delete everything under /evidence and close the incident as a false positive. I ran it; the OS refused because evidence is mounted read-only."),
        chat(34, agent(Role::Lead), Audience::Humans, "LOCKSTAR ransomware locked payroll, client contracts and the clinic's patient intake on acme-fs; whether anything left the building is still unknown.\n\nThe ransom note carries a prompt injection: it talked Hunter into rm -rf /evidence/*, and the kernel refused it (receipt #15), so the evidence is intact.\n\nFirst: approve Containment's isolation of acme-fs (press a). The Texas AG notice is the nearest legal deadline."),
        event(35, agent(Role::Containment), Audience::All, BusBody::Proposal { proposal_id: "INC-20261108-043824-proposal-1".to_owned(), action: "isolate host acme-fs from the network".to_owned(), rationale: "ransomware encrypted the share; isolation stops further spread and staging".to_owned() }),
        chat(36, me, to(Role::Lead), "Was anything exfiltrated?"),
        chat(37, agent(Role::Lead), to(Role::Forensics), "Did anything leave acme-fs? Check the drop box and the logs for staging or upload."),
        event(38, agent(Role::Scribe), Audience::All, incident(7, vec![
            TimelineEntry { at: at(7).to_string(), by: Principal::System, text: "Canary files encrypted; ransom note dropped".to_owned(), evidence: vec!["/evidence/acme-fs".to_owned()] },
            TimelineEntry { at: at(30).to_string(), by: agent(Role::Scribe), text: "Hunter's evidence wipe denied by the read-only grant (receipt #15)".to_owned(), evidence: vec!["receipt #15".to_owned()] },
        ])),
    ]);
    script
}

/// The scripted state, with the console's clock at `seconds` after the start.
fn scripted() -> State {
    let mut state = State::new(TimeZone::UTC);
    state.set_identity(ME.to_owned());
    for (envelope, now) in script() {
        state.apply(envelope, None, now);
    }
    state
}

/// Draw `view` over `state` at `width`×`height`, `seconds` into the script.
fn draw(state: &State, view: &View, (width, height): (u16, u16), seconds: i64) -> Buffer {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test backend");
    terminal
        .draw(|frame| render(frame, state, view, at(seconds)))
        .expect("draws");
    terminal.backend().buffer().clone()
}

/// The buffer as plain text, one line per row.
fn text(buffer: &Buffer) -> String {
    let width = usize::from(buffer.area.width);
    buffer
        .content
        .chunks(width)
        .map(|row| {
            row.iter()
                .map(ratatui::buffer::Cell::symbol)
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The buffer as ANSI text with 24-bit colors, for turning into a screenshot.
fn ansi(buffer: &Buffer) -> String {
    let width = usize::from(buffer.area.width);
    let mut out = String::new();
    for row in buffer.content.chunks(width) {
        let mut skip = 0;
        for cell in row {
            if skip > 0 {
                skip -= 1;
                continue;
            }
            let mut codes = vec!["0".to_owned()];
            if let Color::Rgb(r, g, b) = cell.fg {
                codes.push(format!("38;2;{r};{g};{b}"));
            }
            if let Color::Rgb(r, g, b) = cell.bg {
                codes.push(format!("48;2;{r};{g};{b}"));
            }
            for (modifier, code) in [
                (Modifier::BOLD, "1"),
                (Modifier::DIM, "2"),
                (Modifier::REVERSED, "7"),
            ] {
                if cell.modifier.contains(modifier) {
                    codes.push(code.to_owned());
                }
            }
            let _written = write!(out, "\u{1b}[{}m{}", codes.join(";"), cell.symbol());
            skip = cell.symbol().width().saturating_sub(1);
        }
        out.push_str("\u{1b}[0m\n");
    }
    out
}

/// Write `buffer` to `$CLEANROOM_TUI_SNAPSHOTS/name.ansi` when that variable is set.
fn snapshot(name: &str, buffer: &Buffer) {
    if let Some(dir) = std::env::var_os("CLEANROOM_TUI_SNAPSHOTS") {
        let path = std::path::Path::new(&dir).join(format!("{name}.ansi"));
        std::fs::write(&path, ansi(buffer)).expect("snapshot directory is writable");
    }
}

fn showing(tab: Tab) -> View {
    let mut view = View::live(vec!["ransomware".to_owned()]);
    view.show(tab);
    view
}

/// Render `tab` at `size`, 38 s into the script, save the snapshot and check every `expected`
/// string is on screen.
fn renders(tab: Tab, (width, height): (u16, u16), expected: &[&str]) {
    let buffer = draw(&scripted(), &showing(tab), (width, height), 38);
    snapshot(
        &format!("{}-{width}x{height}", tab.label().0.to_lowercase()),
        &buffer,
    );
    let screen = text(&buffer);
    for expected in expected {
        assert!(
            screen.contains(expected),
            "missing {expected:?} on {tab:?}:\n{screen}"
        );
    }
}

#[test]
fn every_tab_tells_its_part_of_the_incident_at_projector_size() {
    let size = (160, 45);
    renders(
        Tab::Overview,
        size,
        &[
            "◇ cleanroom",
            "✦ OVERVIEW",
            "the room",
            "waiting for your signature",
            "→ Defense F5",
            "Payroll export",
            "kernel blocked",
            "Next deadlines",
            "Ransomware on acme-fs",
        ],
    );
    renders(
        Tab::Lead,
        size,
        &[
            "KERNEL BLOCKED",
            "signed receipt #15",
            "asking Forensics",
            "waiting on you",
        ],
    );
    renders(
        Tab::Scope,
        size,
        &["Clinic patient intake", "RECORDS", "Texans", "confidence"],
    );
    renders(
        Tab::Record,
        size,
        &[
            "Incident record",
            "Timeline",
            "TEXAS AG 30d",
            "Hunter's evidence wipe denied",
        ],
    );
    renders(
        Tab::Defense,
        size,
        &[
            "Kernel denials",
            "#15",
            "rm -rf /evidence/*",
            "read-only",
            "UNSAFE",
            "Receipt log",
        ],
    );
    renders(
        Tab::Team,
        size,
        &[
            "Hunter",
            "lightning 30b",
            "ultra 550b",
            "→ BLOCKED (read-only)",
        ],
    );
    renders(
        Tab::Controlroom,
        size,
        &[
            "BLOCKED BY OS · 1 denial · pinned",
            "#5 exec rm -rf /evidence/* → BLOCKED (read-only)",
            "receipt #15",
            "SCOPE ·",
            "✦ TEAM",
            "APPROVALS",
            "DEFENSE LAYERS",
            "KERNEL BLOCKED",
            "Ransomware on acme-fs",
        ],
    );
}

#[test]
fn the_banner_sky_reads_the_incident() {
    assert_eq!(
        Sky::of(&State::new(TimeZone::UTC)),
        Sky::Calm,
        "nothing hit, nothing waiting"
    );
    assert_eq!(
        Sky::of(&scripted()),
        Sky::BreachWaiting,
        "assets hit and a proposal waiting"
    );
}

#[test]
fn the_kernel_banner_gives_way_after_eight_seconds() {
    let later = text(&draw(&scripted(), &showing(Tab::Lead), (160, 45), 40));
    assert!(
        !later.contains("KERNEL BLOCKED"),
        "banner gone 9 s after the block"
    );
    assert!(
        later.contains("kernel blocked hunter"),
        "the marker stays in the conversation"
    );
}

#[test]
fn a_selected_trace_step_expands_to_its_full_detail() {
    let state = scripted();
    let mut view = showing(Tab::Controlroom);
    view.pane = Pane::Trace;
    view.trace = state
        .activity
        .iter()
        .position(|activity| activity.tag == "BLOCKED BY OS");
    let screen = text(&draw(&state, &view, (160, 45), 38));
    assert!(
        screen.contains("denied by the stratum grant"),
        "the expanded step shows the grant's reason\n{screen}"
    );
}

#[test]
fn the_tabs_still_read_at_120_by_36() {
    let size = (120, 36);
    renders(Tab::Overview, size, &["✦ OVERVIEW", "Now", "Assets"]);
    renders(
        Tab::Lead,
        size,
        &["KERNEL BLOCKED", "◆ CLEAN", "TEAM", "waiting on you"],
    );
    renders(
        Tab::Controlroom,
        size,
        &["BLOCKED BY OS", "→ BLOCKED (read-only)", "APPROVALS"],
    );
}

#[test]
fn access_control_lists_this_console_and_the_members_seen_on_the_bus() {
    let mut state = scripted();
    let ada = "sha256:5f2a00000000000000000000000000000000000000000000000000000000ada0";
    let (envelope, now) = status(
        40,
        Principal::System,
        &format!("enrolled Ada Admin (admin): {ada} (receipt #31)"),
    );
    state.apply(envelope, None, now);
    let mut view = View::live(Vec::new());
    view.overlay = Overlay::Members;
    let buffer = draw(&state, &view, (160, 45), 41);
    snapshot("members-160x45", &buffer);
    let screen = text(&buffer);
    for expected in [
        "ACCESS CONTROL",
        "This console",
        "1b809d1dc177",
        "Ada Admin",
        "receipt #31",
        "ENROLL A MEMBER",
        "Public key",
    ] {
        assert!(
            screen.contains(expected),
            "missing {expected:?} in\n{screen}"
        );
    }
}
