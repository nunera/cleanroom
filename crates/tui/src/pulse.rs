//! What happened when: agent steps, OS denials and safety flags over time, for the activity chart
//! and the team sparklines. Every beat is stamped with the console's clock when it arrived.

use cleanroom_proto::Role;
use jiff::Timestamp;

/// Beats kept in memory.
const LIMIT: usize = 4000;

/// One thing that happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Beat {
    /// An agent ran a step of its loop.
    Step(Role),
    /// The OS denied a command (or kept a record).
    Denial,
    /// The safety model flagged an artifact unsafe.
    Flag,
}

/// The beats of this incident, oldest first.
#[derive(Debug, Default)]
pub(crate) struct Pulse {
    /// Every beat and when it arrived.
    beats: Vec<(Timestamp, Beat)>,
    /// When the investigation started, if it did.
    origin: Option<Timestamp>,
}

/// Steps, denials and flags per bucket, as chart points.
pub(crate) type Series = [Vec<(f64, f64)>; 3];

impl Pulse {
    /// The investigation started at `at`; the chart counts from the first start.
    pub(crate) fn start(&mut self, at: Timestamp) {
        self.origin.get_or_insert(at);
    }

    /// Record a beat at `at`.
    pub(crate) fn beat(&mut self, at: Timestamp, beat: Beat) {
        if self.beats.len() >= LIMIT {
            self.beats.remove(0);
        }
        self.beats.push((at, beat));
    }

    /// Forget the incident (reset).
    pub(crate) fn clear(&mut self) {
        self.beats.clear();
        self.origin = None;
    }

    /// Whether anything happened yet.
    pub(crate) fn is_empty(&self) -> bool {
        self.beats.is_empty()
    }

    /// When the chart starts: the investigation, else the first beat.
    pub(crate) fn origin(&self) -> Option<Timestamp> {
        self.origin
            .or_else(|| self.beats.first().map(|(at, _)| *at))
    }

    /// Steps, denials and flags per `bucket` seconds from the origin to `now`, one point per
    /// bucket (x = seconds since the origin).
    pub(crate) fn series(&self, bucket: i64, now: Timestamp) -> Series {
        let Some(origin) = self.origin() else {
            return [Vec::new(), Vec::new(), Vec::new()];
        };
        let bucket = bucket.max(1);
        let span = now.duration_since(origin).as_secs().max(0);
        let count = usize::try_from(span / bucket + 1).unwrap_or(1).min(720);
        let mut counts = vec![[0_u32; 3]; count];
        for (at, beat) in &self.beats {
            let offset = at.duration_since(origin).as_secs();
            let Ok(index) = usize::try_from(offset / bucket) else {
                continue;
            };
            let lane = match beat {
                Beat::Step(_) => 0,
                Beat::Denial => 1,
                Beat::Flag => 2,
            };
            if let Some(slot) = counts.get_mut(index).and_then(|row| row.get_mut(lane)) {
                *slot += 1;
            }
        }
        let point = |index: usize, value: u32| {
            let seconds = u32::try_from(index)
                .unwrap_or(u32::MAX)
                .saturating_mul(u32::try_from(bucket).unwrap_or(1));
            (f64::from(seconds), f64::from(value))
        };
        let lane = |lane: usize| {
            counts
                .iter()
                .enumerate()
                .map(|(index, row)| point(index, row.get(lane).copied().unwrap_or(0)))
                .collect::<Vec<_>>()
        };
        [lane(0), lane(1), lane(2)]
    }

    /// Steps `role` ran in each of the last `count` buckets of `bucket` seconds up to `now`,
    /// oldest first.
    pub(crate) fn sparkline(
        &self,
        role: Role,
        bucket: i64,
        count: usize,
        now: Timestamp,
    ) -> Vec<u64> {
        let bucket = bucket.max(1);
        let mut bars = vec![0_u64; count];
        for (at, beat) in &self.beats {
            if *beat != Beat::Step(role) {
                continue;
            }
            let age = now.duration_since(*at).as_secs();
            let Ok(back) = usize::try_from(age / bucket) else {
                continue;
            };
            if back < count
                && let Some(slot) = bars.get_mut(count - 1 - back)
            {
                *slot += 1;
            }
        }
        bars
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: i64) -> Timestamp {
        Timestamp::from_second(1_800_000_000 + seconds).expect("fixed test time")
    }

    #[test]
    fn beats_land_in_their_bucket_from_the_start_of_the_investigation() {
        let mut pulse = Pulse::default();
        pulse.start(at(0));
        pulse.beat(at(1), Beat::Step(Role::Hunter));
        pulse.beat(at(6), Beat::Step(Role::Hunter));
        pulse.beat(at(7), Beat::Denial);
        let [steps, denials, flags] = pulse.series(5, at(12));
        assert_eq!(steps, [(0.0, 1.0), (5.0, 1.0), (10.0, 0.0)]);
        assert_eq!(denials, [(0.0, 0.0), (5.0, 1.0), (10.0, 0.0)]);
        assert!(flags.iter().all(|(_, count)| *count == 0.0), "no flags");
        assert_eq!(pulse.sparkline(Role::Hunter, 5, 3, at(12)), [1, 1, 0]);
    }
}
