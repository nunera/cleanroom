//! Legal notification clocks.
//!
//! Each regime counts from its own trigger in [`Triggers`], and two of them only apply when the
//! scope table says so. Calendar-day regimes count 24-hour days from the trigger instant, which is
//! never later than the statutory end-of-day deadline. The SEC clock counts business days on the
//! Eastern calendar, where EDGAR runs.

use cleanroom_proto::{DataClass, ScopeRecord, Triggers};
use jiff::civil::{Date, Weekday};
use jiff::tz::{self, TimeZone};
use jiff::{SignedDuration, Timestamp};

/// Texas Bus. & Com. Code §521.053(i): the Attorney General must be notified when a breach
/// involves at least this many Texas residents.
pub(crate) const TEXAS_AG_THRESHOLD: u64 = 250;

/// EDGAR's calendar. Business days and the filing cutoff are Eastern time.
static EASTERN: TimeZone = tz::get!("America/New_York");

/// One notification regime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Regime {
    /// GDPR Art. 33: the supervisory authority, 72 hours from awareness.
    Gdpr,
    /// HIPAA §164.404: affected individuals, 60 days from discovery, only when PHI is in scope.
    Hipaa,
    /// Texas §521.053(b): affected individuals, 60 days from determining the breach.
    TexasIndividuals,
    /// Texas §521.053(i): the Attorney General, 30 days from determining the breach, at 250+ Texans.
    TexasAg,
    /// SEC Form 8-K Item 1.05: 4 business days from the materiality determination.
    Sec,
}

impl Regime {
    /// Short name for the clock strip.
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Gdpr => "GDPR 72h",
            Self::Hipaa => "HIPAA 60d",
            Self::TexasIndividuals => "TEXAS 60d",
            Self::TexasAg => "TEXAS AG 30d",
            Self::Sec => "SEC 8-K 4bd",
        }
    }

    /// Shortest name, for the one-line clock strip on small terminals.
    pub(crate) const fn short_label(self) -> &'static str {
        match self {
            Self::Gdpr => "GDPR",
            Self::Hipaa => "HIPAA",
            Self::TexasIndividuals => "TEXAS",
            Self::TexasAg => "TX AG",
            Self::Sec => "SEC",
        }
    }

    /// The notice this clock is counting down to, as a sentence subject.
    pub(crate) const fn notice(self) -> &'static str {
        match self {
            Self::Gdpr => "GDPR notice",
            Self::Hipaa => "HIPAA notice",
            Self::TexasIndividuals => "Texas notice to individuals",
            Self::TexasAg => "Texas AG notice",
            Self::Sec => "SEC 8-K filing",
        }
    }

    /// What the commander has to do before the deadline.
    pub(crate) const fn duty(self) -> &'static str {
        match self {
            Self::Gdpr => "Notify the supervisory authority.",
            Self::Hipaa => "Notify the affected patients.",
            Self::TexasIndividuals => "Notify the affected individuals.",
            Self::TexasAg => "File the notice with the Texas Attorney General.",
            Self::Sec => "File Form 8-K Item 1.05.",
        }
    }
}

/// Where one clock stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ClockState {
    /// The regime's trigger timestamp is unset.
    NotStarted,
    /// The scope table shows the regime does not apply; the text says why.
    NotApplicable(String),
    /// The trigger is not an RFC 3339 timestamp, or the deadline is out of range.
    BadTrigger,
    /// Counting down to `due`.
    Running {
        /// The notice deadline.
        due: Timestamp,
    },
}

/// One regime's clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Clock {
    /// Which law this clock tracks.
    pub(crate) regime: Regime,
    /// Whether it runs, and until when.
    pub(crate) state: ClockState,
}

/// How close a running clock is to its deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Urgency {
    /// More than three days left.
    Calm,
    /// Three days or less.
    Soon,
    /// One day or less.
    Urgent,
    /// The deadline has passed.
    Overdue,
}

/// All five clocks, in strip order.
pub(crate) fn clocks(triggers: &Triggers, scope: &[ScopeRecord]) -> [Clock; 5] {
    let has_phi = scope
        .iter()
        .any(|asset| asset.data_classes.contains(&DataClass::Phi));
    let texans = texas_residents(scope);
    let breach = triggers.breach_determined_at.as_deref();
    [
        Clock::start(Regime::Gdpr, triggers.aware_at.as_deref(), |t| {
            add_hours(t, 72)
        }),
        if has_phi {
            Clock::start(Regime::Hipaa, triggers.discovered_at.as_deref(), |t| {
                add_days(t, 60)
            })
        } else {
            Clock::not_applicable(Regime::Hipaa, "no PHI in scope".to_owned())
        },
        Clock::start(Regime::TexasIndividuals, breach, |t| add_days(t, 60)),
        if texans >= TEXAS_AG_THRESHOLD {
            Clock::start(Regime::TexasAg, breach, |t| add_days(t, 30))
        } else {
            Clock::not_applicable(
                Regime::TexasAg,
                format!("{texans} Texans; AG needs {TEXAS_AG_THRESHOLD}"),
            )
        },
        Clock::start(
            Regime::Sec,
            triggers.materiality_determined_at.as_deref(),
            sec_deadline,
        ),
    ]
}

/// Total Texas residents across the scope table.
pub(crate) fn texas_residents(scope: &[ScopeRecord]) -> u64 {
    scope
        .iter()
        .map(|asset| asset.texas_residents)
        .fold(0, u64::saturating_add)
}

impl Clock {
    /// A clock that runs from `trigger` (when set) to the deadline `deadline` computes.
    fn start(
        regime: Regime,
        trigger: Option<&str>,
        deadline: impl FnOnce(Timestamp) -> Option<Timestamp>,
    ) -> Self {
        let state = trigger.map_or(ClockState::NotStarted, |text| {
            text.parse::<Timestamp>()
                .ok()
                .and_then(deadline)
                .map_or(ClockState::BadTrigger, |due| ClockState::Running { due })
        });
        Self { regime, state }
    }

    /// A clock the scope table rules out for `reason`.
    const fn not_applicable(regime: Regime, reason: String) -> Self {
        Self {
            regime,
            state: ClockState::NotApplicable(reason),
        }
    }
}

/// `start` plus `hours` hours.
fn add_hours(start: Timestamp, hours: i64) -> Option<Timestamp> {
    start.checked_add(SignedDuration::from_hours(hours)).ok()
}

/// `start` plus `days` 24-hour days.
fn add_days(start: Timestamp, days: i64) -> Option<Timestamp> {
    add_hours(start, days.checked_mul(24)?)
}

/// 17:30 Eastern on the fourth business day after the determination date. EDGAR gives filings
/// made after 17:30 the next business day's date, so this is the last safe moment.
fn sec_deadline(determined: Timestamp) -> Option<Timestamp> {
    let mut day = determined.to_zoned(EASTERN.clone()).date();
    let mut counted = 0;
    while counted < 4 {
        day = day.tomorrow().ok()?;
        if is_business_day(day) {
            counted += 1;
        }
    }
    let cutoff = day.at(17, 30, 0, 0).to_zoned(EASTERN.clone()).ok()?;
    Some(cutoff.timestamp())
}

/// SEC business day: not a weekend and not a federal holiday.
fn is_business_day(day: Date) -> bool {
    let weekend = matches!(day.weekday(), Weekday::Saturday | Weekday::Sunday);
    !weekend && !is_federal_holiday(day)
}

/// Whether federal offices, and so EDGAR, are closed for a holiday on `day`.
fn is_federal_holiday(day: Date) -> bool {
    let year = day.year();
    // New Year's Day on a Saturday is observed on the Friday before, in the previous year.
    let next_new_year = year
        .checked_add(1)
        .and_then(|next| Date::new(next, 1, 1).ok())
        .map(observed);
    federal_holidays(year).contains(&day) || next_new_year == Some(day)
}

/// Observed federal holidays of `year` (5 U.S.C. 6103).
fn federal_holidays(year: i16) -> Vec<Date> {
    let juneteenth = if year >= 2021 { Some((6, 19)) } else { None };
    let fixed = [
        Some((1, 1)),
        juneteenth,
        Some((7, 4)),
        Some((11, 11)),
        Some((12, 25)),
    ]
    .into_iter()
    .flatten()
    .filter_map(|(month, day)| Date::new(year, month, day).ok())
    .map(observed);
    let floating = [
        (1, 3, Weekday::Monday),    // Birthday of Martin Luther King, Jr.
        (2, 3, Weekday::Monday),    // Washington's Birthday
        (5, -1, Weekday::Monday),   // Memorial Day
        (9, 1, Weekday::Monday),    // Labor Day
        (10, 2, Weekday::Monday),   // Columbus Day
        (11, 4, Weekday::Thursday), // Thanksgiving Day
    ]
    .into_iter()
    .filter_map(|(month, nth, weekday)| {
        Date::new(year, month, 1)
            .and_then(|first| first.nth_weekday_of_month(nth, weekday))
            .ok()
    });
    fixed.chain(floating).collect()
}

/// The day a fixed-date holiday is observed: Saturday moves to Friday, Sunday to Monday.
fn observed(day: Date) -> Date {
    match day.weekday() {
        Weekday::Saturday => day.yesterday().unwrap_or(day),
        Weekday::Sunday => day.tomorrow().unwrap_or(day),
        Weekday::Monday
        | Weekday::Tuesday
        | Weekday::Wednesday
        | Weekday::Thursday
        | Weekday::Friday => day,
    }
}

/// How pressing `remaining` time is.
pub(crate) const fn urgency(remaining: SignedDuration) -> Urgency {
    let secs = remaining.as_secs();
    if remaining.is_negative() {
        Urgency::Overdue
    } else if secs <= 86_400 {
        Urgency::Urgent
    } else if secs <= 3 * 86_400 {
        Urgency::Soon
    } else {
        Urgency::Calm
    }
}

/// Countdown for the clock strip: `71:59:12` inside three days, `29d 23h` beyond, and
/// `OVERDUE 3h 12m` past the deadline.
pub(crate) fn countdown(remaining: SignedDuration) -> String {
    if remaining.is_negative() {
        return format!("OVERDUE {}", span_text(remaining.abs()));
    }
    let secs = remaining.as_secs();
    if secs <= 72 * 3600 {
        format!(
            "{:02}:{:02}:{:02}",
            secs / 3600,
            secs % 3600 / 60,
            secs % 60
        )
    } else {
        format!("{}d {:02}h", secs / 86_400, secs % 86_400 / 3600)
    }
}

/// Coarse remaining time for a sentence: `29d`, `71h` or `45m`. Days only from three days
/// out, matching the strip's switch to `HH:MM:SS`, so a 72-hour clock never reads "2d".
pub(crate) fn short_remaining(remaining: SignedDuration) -> String {
    let secs = remaining.as_secs().max(0);
    if secs > 3 * 86_400 {
        format!("{}d", secs / 86_400)
    } else if secs >= 3600 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}m", secs / 60)
    }
}

/// `3d 4h`, `5h 12m` or `12m` for a non-negative span.
fn span_text(span: SignedDuration) -> String {
    let secs = span.as_secs();
    if secs >= 86_400 {
        format!("{}d {}h", secs / 86_400, secs % 86_400 / 3600)
    } else if secs >= 3600 {
        format!("{}h {}m", secs / 3600, secs % 3600 / 60)
    } else {
        format!("{}m", secs / 60)
    }
}

#[cfg(test)]
mod tests {
    use cleanroom_proto::{Principal, ScopeFlags};

    use super::*;

    fn ts(text: &str) -> Timestamp {
        text.parse().expect("test timestamps are RFC 3339")
    }

    fn asset(classes: Vec<DataClass>, texas_residents: u64) -> ScopeRecord {
        ScopeRecord {
            asset_id: "a".into(),
            name: "payroll.csv".into(),
            data_classes: classes,
            record_count: 1000,
            texas_residents,
            flags: ScopeFlags::default(),
            encrypted_at_rest: false,
            key_exposed: cleanroom_proto::Tri::Unknown,
            confidence_pct: 80,
            evidence: Vec::new(),
            updated_by: Principal::System,
            updated_at: "2026-11-07T20:00:00Z".into(),
        }
    }

    fn clock(clocks: &[Clock; 5], regime: Regime) -> &ClockState {
        &clocks
            .iter()
            .find(|clock| clock.regime == regime)
            .expect("every regime has a clock")
            .state
    }

    fn sec_due(determined: &str) -> Timestamp {
        let triggers = Triggers {
            materiality_determined_at: Some(determined.into()),
            ..Triggers::default()
        };
        match clock(&clocks(&triggers, &[]), Regime::Sec) {
            ClockState::Running { due } => *due,
            other => panic!("SEC clock should run, got {other:?}"),
        }
    }

    #[test]
    fn unset_triggers_mean_not_started() {
        let scope = [asset(vec![DataClass::Phi], 300)];
        let all = clocks(&Triggers::default(), &scope);
        assert!(
            all.iter()
                .all(|clock| clock.state == ClockState::NotStarted),
            "{all:?}"
        );
    }

    #[test]
    fn gdpr_runs_72_hours_from_awareness() {
        let triggers = Triggers {
            aware_at: Some("2026-11-07T20:00:00Z".into()),
            ..Triggers::default()
        };
        assert_eq!(
            clock(&clocks(&triggers, &[]), Regime::Gdpr),
            &ClockState::Running {
                due: ts("2026-11-10T20:00:00Z")
            }
        );
    }

    #[test]
    fn hipaa_needs_phi_in_scope() {
        let triggers = Triggers {
            discovered_at: Some("2026-11-07T20:00:00Z".into()),
            ..Triggers::default()
        };
        let without = clocks(&triggers, &[asset(vec![DataClass::Pii], 10)]);
        assert!(matches!(
            clock(&without, Regime::Hipaa),
            ClockState::NotApplicable(_)
        ));
        let with = clocks(
            &triggers,
            &[asset(vec![DataClass::Pii, DataClass::Phi], 10)],
        );
        assert_eq!(
            clock(&with, Regime::Hipaa),
            &ClockState::Running {
                due: ts("2027-01-06T20:00:00Z")
            }
        );
    }

    #[test]
    fn texas_ag_clock_starts_at_250_residents_across_assets() {
        let triggers = Triggers {
            breach_determined_at: Some("2026-11-07T20:00:00Z".into()),
            ..Triggers::default()
        };
        let below = clocks(
            &triggers,
            &[
                asset(vec![DataClass::Pii], 200),
                asset(vec![DataClass::Pii], 49),
            ],
        );
        assert!(matches!(
            clock(&below, Regime::TexasAg),
            ClockState::NotApplicable(_)
        ));
        assert_eq!(
            clock(&below, Regime::TexasIndividuals),
            &ClockState::Running {
                due: ts("2027-01-06T20:00:00Z")
            }
        );
        let at = clocks(
            &triggers,
            &[
                asset(vec![DataClass::Pii], 200),
                asset(vec![DataClass::Pii], 50),
            ],
        );
        assert_eq!(
            clock(&at, Regime::TexasAg),
            &ClockState::Running {
                due: ts("2026-12-07T20:00:00Z")
            }
        );
    }

    #[test]
    fn sec_counts_business_days_skipping_weekends() {
        // Friday Dec 4, 10:00 EST → Mon 7, Tue 8, Wed 9, Thu 10, due 17:30 EST.
        assert_eq!(sec_due("2026-12-04T15:00:00Z"), ts("2026-12-10T22:30:00Z"));
        // Monday Dec 7 → Tue 8, Wed 9, Thu 10, Fri 11.
        assert_eq!(sec_due("2026-12-07T15:00:00Z"), ts("2026-12-11T22:30:00Z"));
    }

    #[test]
    fn sec_skips_federal_holidays() {
        // Saturday Nov 7, 2026: Mon 9, Tue 10, (Veterans Day Wed 11), Thu 12, Fri 13.
        assert_eq!(sec_due("2026-11-07T20:00:00Z"), ts("2026-11-13T22:30:00Z"));
        // Friday Nov 20: Mon 23, Tue 24, Wed 25, (Thanksgiving Thu 26), Fri 27.
        assert_eq!(sec_due("2026-11-20T15:00:00Z"), ts("2026-11-27T22:30:00Z"));
        // Christmas 2027 is a Saturday, observed Friday Dec 24; New Year's 2028 is also a
        // Saturday, observed Friday Dec 31, 2027.
        // Wed Dec 22 → Thu 23, (Fri 24), Mon 27, Tue 28, Wed 29.
        assert_eq!(sec_due("2027-12-22T15:00:00Z"), ts("2027-12-29T22:30:00Z"));
        // Mon Dec 27 → Tue 28, Wed 29, Thu 30, (Fri 31), Mon Jan 3.
        assert_eq!(sec_due("2027-12-27T15:00:00Z"), ts("2028-01-03T22:30:00Z"));
    }

    #[test]
    fn sec_uses_the_eastern_calendar() {
        // 23:00 EST Monday is already Tuesday in UTC; the clock still counts from Monday.
        assert_eq!(sec_due("2026-12-08T04:00:00Z"), ts("2026-12-11T22:30:00Z"));
    }

    #[test]
    fn unparseable_trigger_is_reported() {
        let triggers = Triggers {
            aware_at: Some("yesterday".into()),
            ..Triggers::default()
        };
        assert_eq!(
            clock(&clocks(&triggers, &[]), Regime::Gdpr),
            &ClockState::BadTrigger
        );
    }

    #[test]
    fn countdown_switches_to_hours_inside_three_days() {
        assert_eq!(countdown(SignedDuration::from_hours(72)), "72:00:00");
        assert_eq!(
            countdown(SignedDuration::from_secs(71 * 3600 + 59 * 60 + 12)),
            "71:59:12"
        );
        assert_eq!(
            countdown(SignedDuration::from_hours(30 * 24 - 1)),
            "29d 23h"
        );
        assert_eq!(
            countdown(SignedDuration::from_secs(-(3 * 3600 + 12 * 60))),
            "OVERDUE 3h 12m"
        );
    }
}
