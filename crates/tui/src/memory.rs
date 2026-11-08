//! Each agent's working context as its evidence pager holds it, from `memory` bus messages, and
//! what that context costs inside the model that reads it.
//!
//! The reducer calls [`MemoryBoard::observe`] for every `memory` message and
//! [`MemoryBoard::clear`] on reset; `ui::memory::render` draws the board. The layer pattern and
//! the cache sizes below come from the model's `config.json`: they are computed, never measured.

use cleanroom_proto::{MemoryMap, MemorySpan, Role, SpanSource, Tier};
use jiff::Timestamp;

use crate::team::SPECIALISTS;

/// Tier moves kept in memory.
const MOVE_LIMIT: usize = 200;

/// The layers of the model behind `nvidia/nemotron-3.5-lightning-30b-a3b`, first to last, one
/// character each: `M` Mamba-2, `E` mixture of experts, `*` attention.
///
/// Source: `layers_block_type` in the `config.json` of
/// `nvidia/NVIDIA-Nemotron-3.5-Lightning-30B-A3B-NVFP4` (Hugging Face snapshot
/// `bee7596271d1495f6992ae224aefde4410e816b8`), the checkpoint vLLM serves on the Brev box
/// (`deploy/brev/serve.sh`), read there on 2026-11-08. It is, character for character, the
/// `hybrid_override_pattern` of NVIDIA Nemotron 3 Nano 30B-A3B:
/// <https://huggingface.co/nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B-BF16/blob/main/config.json>.
pub(crate) const PATTERN: &str = "MEMEM*EMEMEM*EMEMEM*EMEMEM*EMEMEM*EMEMEMEM*EMEMEMEME";

/// Attention layers: the only layers that keep every token exactly, as a KV cache entry.
pub(crate) const ATTENTION_LAYERS: u64 = count(b'*');
/// Mamba-2 layers: a fixed-size state per conversation, however long it grows.
pub(crate) const MAMBA_LAYERS: u64 = count(b'M');
/// Mixture-of-experts layers: no per-token state at all.
pub(crate) const EXPERT_LAYERS: u64 = count(b'E');

/// `num_key_value_heads`: grouped-query attention, 32 query heads sharing 2 K/V heads.
pub(crate) const KV_HEADS: u64 = 2;
/// `head_dim` (`k_proj.weight` is `[256, 2688]` in the checkpoint: 2 heads of 128).
pub(crate) const HEAD_DIM: u64 = 128;
/// Bytes per cached K or V value: vLLM serves the model with `--kv-cache-dtype fp8`.
pub(crate) const KV_VALUE_BYTES: u64 = 1;
/// `mamba_num_heads`.
pub(crate) const MAMBA_HEADS: u64 = 64;
/// `mamba_head_dim`.
pub(crate) const MAMBA_HEAD_DIM: u64 = 64;
/// `ssm_state_size`.
pub(crate) const SSM_STATE_SIZE: u64 = 128;
/// Bytes per SSM state value: `mamba_ssm_cache_dtype` is `float32`.
pub(crate) const SSM_VALUE_BYTES: u64 = 4;
/// `n_groups`: heads share B and C in groups.
pub(crate) const GROUPS: u64 = 8;
/// `conv_kernel`; the conv state keeps the last `conv_kernel - 1` inputs.
pub(crate) const CONV_KERNEL: u64 = 4;
/// Bytes per conv state value: the model's `bfloat16`.
pub(crate) const CONV_VALUE_BYTES: u64 = 2;
/// Channels of the causal conv, x then B and C (`conv1d.weight` is `[6144, 1, 4]`).
pub(crate) const CONV_CHANNELS: u64 = MAMBA_HEADS * MAMBA_HEAD_DIM + 2 * GROUPS * SSM_STATE_SIZE;

/// KV cache per token in context: K and V of both KV heads in each attention layer (3 KiB).
pub(crate) const KV_BYTES_PER_TOKEN: u64 =
    ATTENTION_LAYERS * KV_HEADS * HEAD_DIM * 2 * KV_VALUE_BYTES;
/// SSM state per conversation (46.0 MiB).
pub(crate) const SSM_STATE_BYTES: u64 =
    MAMBA_LAYERS * MAMBA_HEADS * MAMBA_HEAD_DIM * SSM_STATE_SIZE * SSM_VALUE_BYTES;
/// Conv state per conversation (0.8 MiB).
pub(crate) const CONV_STATE_BYTES: u64 =
    MAMBA_LAYERS * CONV_CHANNELS * (CONV_KERNEL - 1) * CONV_VALUE_BYTES;
/// All Mamba-2 state per conversation, the same at ten tokens or a hundred thousand (46.8 MiB).
pub(crate) const MAMBA_STATE_BYTES: u64 = SSM_STATE_BYTES + CONV_STATE_BYTES;

/// Layers whose [`PATTERN`] character is `symbol`.
const fn count(symbol: u8) -> u64 {
    let mut rest = PATTERN.as_bytes();
    let mut found = 0;
    while let [first, tail @ ..] = rest {
        if *first == symbol {
            found += 1;
        }
        rest = tail;
    }
    found
}

/// What one layer of the model is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Layer {
    /// Mamba-2: a fixed-size state, no exact copy of past tokens.
    Mamba,
    /// Mixture of experts: 6 of 128 routed experts plus a shared one per token, no state.
    Experts,
    /// Attention: a KV cache entry for every token, the only exact recall.
    Attention,
}

/// The model's layers, first to last.
pub(crate) fn layers() -> impl Iterator<Item = Layer> {
    PATTERN.bytes().filter_map(|symbol| match symbol {
        b'M' => Some(Layer::Mamba),
        b'E' => Some(Layer::Experts),
        b'*' => Some(Layer::Attention),
        _ => None,
    })
}

/// What one agent's context costs, from its map: computed, not measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Cost {
    /// Tokens in context now: exact spans in full, compressed spans as their handles.
    pub(crate) tokens: u64,
    /// Tokens the same spans would cost if every one were exact.
    pub(crate) exact_tokens: u64,
}

impl Cost {
    /// The cost of `spans`.
    pub(crate) fn of(spans: &[MemorySpan]) -> Self {
        spans.iter().fold(Self::default(), |cost, span| Self {
            tokens: cost.tokens + u64::from(span.tokens),
            exact_tokens: cost.exact_tokens + u64::from(span.exact_tokens),
        })
    }

    /// Tokens compression keeps out of context: the sum of `exact_tokens - tokens`.
    pub(crate) const fn saved(self) -> u64 {
        self.exact_tokens.saturating_sub(self.tokens)
    }

    /// Attention KV cache for the context now, in bytes: it grows with every token held.
    pub(crate) const fn kv_bytes(self) -> u64 {
        self.tokens * KV_BYTES_PER_TOKEN
    }

    /// The KV cache the same spans would take with no tiers, every span exact.
    pub(crate) const fn kv_bytes_untiered(self) -> u64 {
        self.exact_tokens * KV_BYTES_PER_TOKEN
    }
}

/// One agent's latest context map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Context {
    /// Whose context.
    pub(crate) role: Role,
    /// Every span in context order.
    pub(crate) spans: Vec<MemorySpan>,
}

impl Context {
    /// What this context costs.
    pub(crate) fn cost(&self) -> Cost {
        Cost::of(&self.spans)
    }
}

/// One tier move, as the board logged it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Move {
    /// When the map that carried it reached this console.
    pub(crate) at: Timestamp,
    /// Whose context.
    pub(crate) role: Role,
    /// The span's handle, for example `ev-3`.
    pub(crate) span_id: String,
    /// What the span is, from the map; the handle when the map lacks the span.
    pub(crate) label: String,
    /// Who wrote the span, when the map has it.
    pub(crate) source: Option<SpanSource>,
    /// The tier it moved to.
    pub(crate) to: Tier,
    /// Why, in the agent's words.
    pub(crate) reason: String,
    /// Tokens the span cost before the move, when this console saw the map before it.
    pub(crate) before: Option<u32>,
    /// Tokens the span costs after the move, when the map has it.
    pub(crate) after: Option<u32>,
    /// Tokens of the span's exact bytes, when the map has it. An exact span that costs fewer is a
    /// verbatim window (`page_in` of some lines), not the whole span.
    pub(crate) exact_tokens: Option<u32>,
}

/// Every agent's latest context map and the tier moves so far.
#[derive(Debug, Default)]
pub(crate) struct MemoryBoard {
    /// One context per role that published a map: the Lead, then the specialists in card order.
    contexts: Vec<Context>,
    /// Tier moves, oldest first, at most [`MOVE_LIMIT`].
    moves: Vec<Move>,
}

impl MemoryBoard {
    /// Fold in `map`, which reached this console at `at`: it replaces the role's previous map,
    /// and the move it carries joins the log. A map delivered again unchanged (cleanroomd replays
    /// the latest map per role to a console that joins late) logs nothing new.
    pub(crate) fn observe(&mut self, at: &Timestamp, map: &MemoryMap) {
        let slot = self
            .contexts
            .iter()
            .position(|context| context.role == map.role);
        if let Some(moved) = &map.moved {
            let previous = slot.and_then(|index| self.contexts.get(index));
            let repeated = previous.is_some_and(|context| context.spans == map.spans)
                && self.last_move(map.role).is_some_and(|last| {
                    last.span_id == moved.span_id
                        && last.to == moved.to
                        && last.reason == moved.reason
                });
            if !repeated {
                let span = map.spans.iter().find(|span| span.id == moved.span_id);
                let before = previous
                    .and_then(|context| context.spans.iter().find(|old| old.id == moved.span_id))
                    .map(|old| old.tokens);
                let entry = Move {
                    at: *at,
                    role: map.role,
                    span_id: moved.span_id.clone(),
                    label: span.map_or_else(|| moved.span_id.clone(), |span| span.label.clone()),
                    source: span.map(|span| span.source),
                    to: moved.to,
                    reason: moved.reason.clone(),
                    before,
                    after: span.map(|span| span.tokens),
                    exact_tokens: span.map(|span| span.exact_tokens),
                };
                self.moves.push(entry);
                if self.moves.len() > MOVE_LIMIT {
                    self.moves.remove(0);
                }
            }
        }
        let context = Context {
            role: map.role,
            spans: map.spans.clone(),
        };
        if let Some(existing) = slot.and_then(|index| self.contexts.get_mut(index)) {
            *existing = context;
        } else {
            self.contexts.push(context);
            self.contexts.sort_by_key(|context| seat(context.role));
        }
    }

    /// Forget every map and move (reset).
    pub(crate) fn clear(&mut self) {
        self.contexts.clear();
        self.moves.clear();
    }

    /// Whether no agent has published a map yet.
    pub(crate) const fn is_empty(&self) -> bool {
        self.contexts.is_empty()
    }

    /// Every agent's latest context, the Lead first.
    pub(crate) fn contexts(&self) -> &[Context] {
        &self.contexts
    }

    /// The tier moves kept, oldest first.
    pub(crate) fn moves(&self) -> &[Move] {
        &self.moves
    }

    /// The newest move in `role`'s context.
    pub(crate) fn last_move(&self, role: Role) -> Option<&Move> {
        self.moves.iter().rev().find(|entry| entry.role == role)
    }
}

/// Where `role` sits on the board: the Lead, then the specialists in card order.
fn seat(role: Role) -> usize {
    std::iter::once(Role::Lead)
        .chain(SPECIALISTS)
        .position(|seat| seat == role)
        .unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use cleanroom_proto::{MemoryMap, MemorySpan, Role, SpanSource, Tier, TierMove};
    use jiff::Timestamp;

    use super::{
        ATTENTION_LAYERS, CONV_STATE_BYTES, Cost, EXPERT_LAYERS, KV_BYTES_PER_TOKEN, Layer,
        MAMBA_LAYERS, MAMBA_STATE_BYTES, MOVE_LIMIT, MemoryBoard, PATTERN, SSM_STATE_BYTES, layers,
    };

    /// `seconds` after a fixed start.
    fn at(seconds: i64) -> Timestamp {
        Timestamp::from_second(1_794_115_100 + seconds).expect("test times are valid")
    }

    /// A span of `exact_tokens` from `source`, costing `tokens` now.
    fn span(
        id: &str,
        source: SpanSource,
        tier: Tier,
        (tokens, exact_tokens): (u32, u32),
    ) -> MemorySpan {
        MemorySpan {
            id: id.to_owned(),
            source,
            tier,
            tokens,
            exact_tokens,
            digest: format!("sha256:{id}"),
            label: format!("label of {id}"),
        }
    }

    /// `role`'s map of `spans`, published for `moved`.
    fn map(role: Role, spans: Vec<MemorySpan>, moved: Option<(&str, Tier, &str)>) -> MemoryMap {
        MemoryMap {
            role,
            spans,
            moved: moved.map(|(span_id, to, reason)| TierMove {
                span_id: span_id.to_owned(),
                to,
                reason: reason.to_owned(),
            }),
        }
    }

    /// Hunter's context with the ransom note as a 40-token handle of a 1,200-token file.
    fn note_compressed() -> Vec<MemorySpan> {
        vec![
            span("sys", SpanSource::Commander, Tier::Exact, (900, 900)),
            span("ev-1", SpanSource::Evidence, Tier::Compressed, (40, 1_200)),
        ]
    }

    /// The same context after `page_in ev-1`.
    fn note_exact() -> Vec<MemorySpan> {
        vec![
            span("sys", SpanSource::Commander, Tier::Exact, (900, 900)),
            span("ev-1", SpanSource::Evidence, Tier::Exact, (1_200, 1_200)),
        ]
    }

    #[test]
    fn maps_replace_per_role_and_sit_lead_first() {
        let mut board = MemoryBoard::default();
        board.observe(&at(1), &map(Role::Hunter, note_compressed(), None));
        board.observe(
            &at(2),
            &map(
                Role::Lead,
                vec![span("q1", SpanSource::Commander, Tier::Exact, (30, 30))],
                None,
            ),
        );
        board.observe(&at(3), &map(Role::Hunter, note_exact(), None));

        let roles: Vec<Role> = board
            .contexts()
            .iter()
            .map(|context| context.role)
            .collect();
        assert_eq!(
            roles,
            [Role::Lead, Role::Hunter],
            "one context per role, Lead first"
        );
        let hunter = board.contexts().get(1).expect("Hunter's context");
        assert_eq!(
            hunter.spans,
            note_exact(),
            "the newer map replaced the older one"
        );
        assert!(board.moves().is_empty(), "maps without a move log nothing");
    }

    #[test]
    fn moves_are_logged_with_the_cost_before_and_after() {
        let mut board = MemoryBoard::default();
        board.observe(&at(1), &map(Role::Hunter, note_compressed(), None));
        board.observe(
            &at(5),
            &map(
                Role::Hunter,
                note_exact(),
                Some(("ev-1", Tier::Exact, "need the note's exact wording")),
            ),
        );

        let logged = board.moves().first().expect("the page_in is logged");
        assert_eq!(logged.at, at(5), "stamped with the console's clock");
        assert_eq!(logged.role, Role::Hunter, "whose context");
        assert_eq!(logged.span_id, "ev-1", "which span");
        assert_eq!(logged.label, "label of ev-1", "label from the map");
        assert_eq!(
            logged.source,
            Some(SpanSource::Evidence),
            "source from the map"
        );
        assert_eq!(logged.to, Tier::Exact, "where it went");
        assert_eq!(
            logged.reason, "need the note's exact wording",
            "the agent's reason"
        );
        assert_eq!(
            (logged.before, logged.after),
            (Some(40), Some(1_200)),
            "handle then exact"
        );
        assert_eq!(logged.exact_tokens, Some(1_200), "the span's exact size");
        assert_eq!(
            board.last_move(Role::Hunter),
            Some(logged),
            "the newest move per role"
        );
        assert_eq!(
            board.last_move(Role::Lead),
            None,
            "no move in the Lead's context"
        );
    }

    #[test]
    fn a_map_delivered_again_logs_its_move_once() {
        let mut board = MemoryBoard::default();
        let paged_out = map(
            Role::Hunter,
            note_compressed(),
            Some(("ev-1", Tier::Compressed, "done reading")),
        );
        board.observe(&at(1), &map(Role::Hunter, note_exact(), None));
        board.observe(&at(2), &paged_out);
        board.observe(&at(9), &paged_out);
        assert_eq!(board.moves().len(), 1, "the replayed map is the same move");
        let only = board.moves().first().expect("one move");
        assert_eq!(
            (only.at, only.before, only.after),
            (at(2), Some(1_200), Some(40)),
            "first sighting kept"
        );

        board.observe(
            &at(10),
            &map(
                Role::Hunter,
                note_exact(),
                Some(("ev-1", Tier::Exact, "done reading")),
            ),
        );
        assert_eq!(
            board.moves().len(),
            2,
            "a real move with the same reason still logs"
        );
    }

    #[test]
    fn a_late_joiner_logs_the_move_without_a_before() {
        let mut board = MemoryBoard::default();
        board.observe(
            &at(1),
            &map(
                Role::Forensics,
                note_exact(),
                Some(("ev-1", Tier::Exact, "read it")),
            ),
        );
        let logged = board.moves().first().expect("logged");
        assert_eq!(
            (logged.before, logged.after),
            (None, Some(1_200)),
            "no earlier map to compare"
        );
    }

    #[test]
    fn the_log_keeps_the_newest_moves() {
        let mut board = MemoryBoard::default();
        for second in 0..=i64::try_from(MOVE_LIMIT).expect("small limit") {
            let (spans, to) = if second % 2 == 0 {
                (note_exact(), Tier::Exact)
            } else {
                (note_compressed(), Tier::Compressed)
            };
            board.observe(
                &at(second),
                &map(Role::Hunter, spans, Some(("ev-1", to, "flip"))),
            );
        }
        assert_eq!(board.moves().len(), MOVE_LIMIT, "capped");
        assert_eq!(
            board.moves().first().map(|entry| entry.at),
            Some(at(1)),
            "oldest dropped"
        );
    }

    #[test]
    fn clear_forgets_maps_and_moves() {
        let mut board = MemoryBoard::default();
        board.observe(&at(1), &map(Role::Hunter, note_compressed(), None));
        board.observe(
            &at(2),
            &map(
                Role::Hunter,
                note_exact(),
                Some(("ev-1", Tier::Exact, "why")),
            ),
        );
        board.clear();
        assert!(board.is_empty(), "no maps after a reset");
        assert!(board.moves().is_empty(), "no moves after a reset");
    }

    #[test]
    fn the_pattern_is_23_mamba_23_moe_and_6_attention_layers() {
        assert_eq!(PATTERN.len(), 52, "52 layers");
        assert_eq!(
            (MAMBA_LAYERS, EXPERT_LAYERS, ATTENTION_LAYERS),
            (23, 23, 6),
            "layer counts"
        );
        let attention: Vec<usize> = layers()
            .enumerate()
            .filter(|(_, layer)| *layer == Layer::Attention)
            .map(|(index, _)| index)
            .collect();
        assert_eq!(
            attention,
            [5, 12, 19, 26, 33, 42],
            "attention layer indices"
        );
    }

    #[test]
    fn the_computed_caches_match_the_formulas() {
        assert_eq!(
            KV_BYTES_PER_TOKEN,
            6 * 2 * 128 * 2,
            "6 attn × 2 KV heads × 128 × K,V × 1 B fp8"
        );
        assert_eq!(KV_BYTES_PER_TOKEN, 3 * 1024, "3 KiB per token");
        assert_eq!(
            SSM_STATE_BYTES,
            23 * 64 * 64 * 128 * 4,
            "23 layers × 64 heads × 64 × 128 × 4 B fp32"
        );
        assert_eq!(SSM_STATE_BYTES, 48_234_496, "46.0 MiB");
        assert_eq!(
            CONV_STATE_BYTES,
            23 * (64 * 64 + 2 * 8 * 128) * 3 * 2,
            "23 × 6,144 × 3 × 2 B bf16"
        );
        assert_eq!(
            MAMBA_STATE_BYTES, 49_082_368,
            "46.8 MiB, whatever the context length"
        );

        let cost = Cost::of(&note_compressed());
        assert_eq!(
            (cost.tokens, cost.exact_tokens, cost.saved()),
            (940, 2_100, 1_160),
            "tokens"
        );
        assert_eq!(
            cost.kv_bytes(),
            940 * 3_072,
            "KV grows with tokens in context"
        );
        assert_eq!(
            cost.kv_bytes_untiered(),
            2_100 * 3_072,
            "and would with every span exact"
        );
        assert_eq!(
            Cost::of(&note_exact()).saved(),
            0,
            "nothing saved when all is exact"
        );
    }
}
