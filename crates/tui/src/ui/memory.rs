//! The MEMORY tab, "the stacks": each agent's working context span by span, set against the
//! layers of the model that reads it.
//!
//! On top, the model's 52 layers as one row of cells: the Mamba-2 (`M`) and mixture-of-experts
//! (`E`) layers keep no exact copy of the context; the six attention layers (`✱`) do, in their
//! KV cache. Under it, one track per agent: every span a block as wide as the tokens it costs in
//! context now, solid when exact, a hatched handle when compressed, colored by who wrote it (the
//! attacker's evidence in red), and a dashed outline for what compression keeps out. A move
//! flashes while its block grows (`page_in`) or shrinks (`page_out`). Beside the tracks, the KV
//! cache and Mamba-2 state each context takes, computed from the model's config and labelled so;
//! below, every tier move, each one receipted by cleanroomd. Glyphs carry every distinction the
//! colors make.

use cleanroom_proto::{MemorySpan, SpanSource, Tier};
use jiff::tz::TimeZone;
use jiff::{SignedDuration, Timestamp};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize as _};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Padding, Paragraph, Row, Table};

use super::{View, due_label, fit, grouped, pad, role_label, tail_fit, width_of};
use crate::memory::{
    self, ATTENTION_LAYERS, CONV_CHANNELS, CONV_KERNEL, CONV_STATE_BYTES, CONV_VALUE_BYTES,
    Context, EXPERT_LAYERS, HEAD_DIM, KV_BYTES_PER_TOKEN, KV_HEADS, KV_VALUE_BYTES, Layer,
    MAMBA_HEAD_DIM, MAMBA_HEADS, MAMBA_LAYERS, MAMBA_STATE_BYTES, MemoryBoard, Move,
    SSM_STATE_BYTES, SSM_STATE_SIZE, SSM_VALUE_BYTES,
};
use crate::state::State;
use crate::theme::{Theme, blend, glyph, tint};

/// How long a moved block takes to grow or shrink.
const ANIMATE: SignedDuration = SignedDuration::from_millis(1200);
/// How long a move stays lit on its agent's track and in the log.
const RECENT: SignedDuration = SignedDuration::from_secs(10);
/// Columns of an agent's name: `▣ CONTAINMENT`.
const NAME_WIDTH: usize = 13;
/// Columns of the figures after a track: `123,456 tok`.
const FIGURE_WIDTH: usize = 11;
/// Rows the move log keeps at the least: its border, the header and three moves.
const LOG_MIN: u16 = 6;
/// Bytes in a MiB.
const MIB: u64 = 1024 * 1024;

/// How the stacks fit the rows there are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Fit {
    /// Rows per agent: 2 draws each block two rows tall with its handle written in, 1 a single row.
    per_agent: u16,
    /// Rows under the agents for the legend and the formulas, 0 to 3.
    footer: u16,
}

impl Fit {
    /// The roomiest fit for `board` that leaves the move log [`LOG_MIN`] of `height` rows.
    fn for_rows(board: &MemoryBoard, height: u16) -> Self {
        [(2, 3), (1, 3), (1, 1), (1, 0)]
            .into_iter()
            .map(|(per_agent, footer)| Self { per_agent, footer })
            .find(|fit| fit.height(board).saturating_add(1 + LOG_MIN) <= height)
            .unwrap_or(Self {
                per_agent: 1,
                footer: 0,
            })
    }

    /// Rows of the stacks and cache panels: borders, the header row, the agents and the footer.
    fn height(self, board: &MemoryBoard) -> u16 {
        let agents = u16::try_from(board.contexts().len()).unwrap_or(u16::MAX);
        agents
            .saturating_mul(self.per_agent)
            .saturating_add(3)
            .saturating_add(self.footer)
    }
}

/// How tokens map to columns on the tracks: the biggest context, tiered or not, fills a track.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Scale {
    /// Columns of a track.
    width: usize,
    /// Tokens a full track stands for.
    most: u64,
}

impl Scale {
    /// The scale for `board`'s contexts on tracks `width` columns wide.
    fn of(board: &MemoryBoard, width: usize) -> Self {
        let most = board
            .contexts()
            .iter()
            .map(|context| {
                let cost = context.cost();
                cost.tokens.max(cost.exact_tokens)
            })
            .max()
            .unwrap_or(0)
            .max(1);
        Self { width, most }
    }

    /// Columns for `tokens`, rounded.
    fn columns(self, tokens: u64) -> usize {
        scaled(tokens, self.width, self.most)
    }

    /// Tokens one column stands for, rounded up.
    fn per_column(self) -> u64 {
        self.most
            .div_ceil(u64::try_from(self.width.max(1)).unwrap_or(u64::MAX))
    }
}

/// A recent move on a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Mark {
    /// Where the span went.
    to: Tier,
    /// How far its animation has run, in thousandths, while it runs.
    permille: Option<u64>,
}

/// The console's clock as the tab reads it, and whether blocks may move (`--no-motion` and
/// `NO_COLOR` say they may not).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Clock {
    /// Now, on the console's clock.
    now: Timestamp,
    /// Whether a moved block grows, shrinks and flashes.
    motion: bool,
}

impl Clock {
    /// Time from `at` to now.
    fn since(self, at: Timestamp) -> SignedDuration {
        self.now.duration_since(at)
    }

    /// How far a move made at `at` has animated, in thousandths; `None` outside [`ANIMATE`] and
    /// without motion.
    fn progress(self, at: Timestamp) -> Option<u64> {
        let elapsed = self.since(at);
        if !self.motion || elapsed < SignedDuration::ZERO || elapsed >= ANIMATE {
            return None;
        }
        u64::try_from(elapsed.as_millis() * 1000 / ANIMATE.as_millis()).ok()
    }
}

/// Draw `state`'s memory board into `area` at `now`.
pub(super) fn render(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &State,
    view: &View,
    now: Timestamp,
) {
    let theme = view.palette();
    let board = &state.memory;
    let clock = Clock {
        now,
        motion: view.motion,
    };
    let area = area.inner(Margin::new(1, u16::from(area.height >= 30)));
    let [strip, caption, rest] = Layout::vertical([
        Constraint::Length(5),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .areas(area);
    frame.render_widget(layer_panel(theme, strip), strip);
    frame.render_widget(
        Paragraph::new(caption_line(theme, usize::from(caption.width))),
        caption,
    );
    if board.is_empty() {
        frame.render_widget(empty_panel(theme, rest), rest);
        return;
    }
    let fit = Fit::for_rows(board, rest.height);
    let [stacks, _, log] = Layout::vertical([
        Constraint::Length(fit.height(board)),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .areas(rest);
    let side = match stacks.width {
        150.. => 60,
        110.. => 46,
        _ => 0,
    };
    let [left, _, right] = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(if side > 0 { 2 } else { 0 }),
        Constraint::Length(side),
    ])
    .areas(stacks);
    frame.render_widget(stacks_panel(board, theme, clock, left, fit), left);
    if side > 0 {
        frame.render_widget(cache_panel(board, theme, right, fit), right);
    }
    frame.render_widget(
        moves_panel(board, theme, &state.display_tz, clock, log),
        log,
    );
}

// ---------- The layers ----------

/// The model's layers as one row of cells under the attention layers' numbers, and a legend.
fn layer_panel(theme: &Theme, area: Rect) -> Paragraph<'static> {
    let block = theme
        .panel(
            &format!(
                "Nemotron 3 Nano 30B-A3B · {} layers",
                memory::layers().count()
            ),
            false,
        )
        .title(
            Line::from(" lightning-30b-a3b · config.json ")
                .fg(theme.dim)
                .right_aligned(),
        )
        .padding(Padding::ZERO);
    let width = usize::from(block.inner(area).width);
    Paragraph::new(layer_lines(theme, width)).block(block)
}

/// Three lines `width` columns wide: the attention layers' numbers, a cell per layer, the legend.
fn layer_lines(theme: &Theme, width: usize) -> Vec<Line<'static>> {
    let count = memory::layers().count().max(1);
    let cell = (width / count).clamp(1, 3);
    let left = width.saturating_sub(cell * count) / 2;
    let mut numbers = vec![Span::raw(" ".repeat(left))];
    let mut cells = vec![Span::raw(" ".repeat(left))];
    let mut written = 0;
    for (index, layer) in memory::layers().enumerate() {
        let (symbol, style) = cell_look(layer, theme);
        let text = match cell {
            1 => symbol.to_owned(),
            2 => format!("{symbol} "),
            _ => format!(" {symbol} "),
        };
        cells.push(Span::styled(text, style));
        if layer == Layer::Attention {
            let label = index.to_string();
            let start = index * cell + cell.saturating_sub(label.len()) / 2;
            if start >= written {
                numbers.push(Span::raw(" ".repeat(start - written)));
                written = start + label.len();
                numbers.push(Span::raw(label).fg(theme.accent).bold());
            }
        }
    }
    vec![
        Line::from(numbers),
        Line::from(cells),
        layer_legend(theme, width),
    ]
}

/// The symbol and style of a cell for `layer`.
const fn cell_look(layer: Layer, theme: &Theme) -> (&'static str, Style) {
    match layer {
        Layer::Mamba => ("M", Style::new().fg(theme.mamba).bg(theme.mamba_bg)),
        Layer::Experts => ("E", Style::new().fg(theme.expert).bg(theme.expert_bg)),
        Layer::Attention => (
            "✱",
            Style::new()
                .fg(theme.ink)
                .bg(theme.accent)
                .add_modifier(Modifier::BOLD),
        ),
    }
}

/// Each kind of layer's cell, name and count, and what it remembers, centered in `width`.
fn layer_legend(theme: &Theme, width: usize) -> Line<'static> {
    let entries = [
        (
            Layer::Mamba,
            format!("Mamba-2 ×{MAMBA_LAYERS}"),
            "fixed-size state, no exact recall",
        ),
        (
            Layer::Experts,
            format!("MoE ×{EXPERT_LAYERS}"),
            "routed experts, no state",
        ),
        (
            Layer::Attention,
            format!("attention ×{ATTENTION_LAYERS}"),
            "KV cache: the only exact recall",
        ),
    ];
    let build = |notes: bool| {
        let mut spans = Vec::new();
        for (index, (layer, name, note)) in entries.iter().enumerate() {
            if index > 0 {
                spans.push(Span::raw("    "));
            }
            let (symbol, style) = cell_look(*layer, theme);
            let attention = *layer == Layer::Attention;
            spans.push(Span::styled(format!(" {symbol} "), style));
            spans.push(
                Span::raw(format!(" {name}"))
                    .fg(if attention {
                        theme.accent
                    } else {
                        theme.bright
                    })
                    .bold(),
            );
            if notes || attention {
                spans.push(Span::raw(format!("  {note}")).fg(if attention {
                    theme.text
                } else {
                    theme.muted
                }));
            }
        }
        spans
    };
    let full = build(true);
    let spans = if line_width(&full) <= width {
        full
    } else {
        build(false)
    };
    let mut line = vec![Span::raw(
        " ".repeat(width.saturating_sub(line_width(&spans)) / 2),
    )];
    line.extend(spans);
    Line::from(line)
}

/// The caption under the layers: where the tiers apply today, and where they could.
fn caption_line(theme: &Theme, width: usize) -> Line<'static> {
    let lead =
        "Tiers applied by Cleanroom today; a trained retention router would apply them inside ";
    let layers = format!("Nemotron's {ATTENTION_LAYERS} attention layers");
    let full = format!(" ↳ {lead}{layers}.");
    if width_of(&full) <= width {
        Line::from(vec![
            Span::raw(" ↳ ").fg(theme.dim),
            Span::raw(lead).fg(theme.muted).italic(),
            Span::raw(layers).fg(theme.accent).italic(),
            Span::raw(".").fg(theme.muted).italic(),
        ])
    } else {
        Line::from(Span::raw(fit(&full, width)).fg(theme.muted).italic())
    }
}

// ---------- The stacks ----------

/// One track per agent, the source legend on top and what the shapes mean below.
fn stacks_panel(
    board: &MemoryBoard,
    theme: &Theme,
    clock: Clock,
    area: Rect,
    fit: Fit,
) -> Paragraph<'static> {
    let block = theme.panel("Context, span by span", false);
    let width = usize::from(block.inner(area).width);
    let scale = Scale::of(board, track_width(width));
    let block = block.title(
        Line::from(format!(" 1 col ≈ {} tok ", grouped(scale.per_column())))
            .fg(theme.dim)
            .right_aligned(),
    );
    let mut lines = vec![source_legend(theme, width)];
    for context in board.contexts() {
        let last = board.last_move(context.role);
        let [top, bottom] = track(context, last, scale, theme, clock);
        let mut first = vec![
            Span::raw(pad(
                &format!("{} {}", glyph(context.role), role_label(context.role)),
                NAME_WIDTH,
            ))
            .fg(tint(context.role))
            .bold(),
            Span::raw(" "),
        ];
        first.extend(top);
        first.push(Span::raw(" "));
        first.extend(token_figure(context.cost().tokens, theme));
        lines.push(Line::from(first));
        if fit.per_agent > 1 {
            let mut second = vec![
                Span::raw(pad(&format!("  {} spans", context.spans.len()), NAME_WIDTH))
                    .fg(theme.dim),
                Span::raw(" "),
            ];
            second.extend(bottom);
            second.push(Span::raw(" "));
            second.push(move_figure(last, theme, clock));
            lines.push(Line::from(second));
        }
    }
    lines.extend(
        stack_footer(theme, width)
            .into_iter()
            .take(usize::from(fit.footer)),
    );
    Paragraph::new(lines).block(block)
}

/// Columns of a track in a stacks panel `width` wide.
const fn track_width(width: usize) -> usize {
    width.saturating_sub(NAME_WIDTH + FIGURE_WIDTH + 2)
}

/// One agent's track, `scale.width` columns wide, as two rows.
///
/// Every span is a block as wide as the tokens it costs now (exact solid, compressed hatched),
/// then a dashed outline is as wide as the tokens compression keeps out. The bottom row writes
/// each exact span's handle into its block.
fn track(
    context: &Context,
    last: Option<&Move>,
    scale: Scale,
    theme: &Theme,
    clock: Clock,
) -> [Vec<Span<'static>>; 2] {
    let lit = last.filter(|entry| clock.since(entry.at) < RECENT);
    let moving = lit.and_then(|entry| clock.progress(entry.at).map(|permille| (entry, permille)));
    let weights: Vec<u64> = context
        .spans
        .iter()
        .map(|span| shown_tokens(span, moving))
        .collect();
    let count = weights.len();
    let cut = count > scale.width;
    let columns = if cut {
        scale.width.saturating_sub(1)
    } else {
        scale
            .columns(weights.iter().sum())
            .clamp(count, scale.width)
    };
    let mut rows = TrackRows {
        top: Vec::new(),
        bottom: Vec::new(),
        theme: *theme,
    };
    let widths = allocate(&weights, columns);
    let mut blocks = context.spans.iter().zip(widths).peekable();
    while let Some((span, width)) = blocks.next() {
        if width == 0 {
            continue;
        }
        let joined = blocks.peek().is_some_and(|(next, next_width)| {
            *next_width > 0 && next.source == span.source && next.tier == span.tier
        });
        let mark = lit
            .filter(|entry| entry.span_id == span.id)
            .map(|entry| Mark {
                to: entry.to,
                permille: clock.progress(entry.at),
            });
        rows.block(span, width, mark, joined);
    }
    let mut used = columns;
    if cut {
        rows.both("…", theme.dim);
        used += 1;
    }
    let exact: u64 = context
        .spans
        .iter()
        .map(|span| u64::from(span.exact_tokens))
        .sum();
    let ghost = scale
        .columns(exact)
        .saturating_sub(used)
        .min(scale.width.saturating_sub(used));
    rows.both(&"┄".repeat(ghost), saved_color(theme));
    rows.both(
        &" ".repeat(scale.width.saturating_sub(used + ghost)),
        theme.ink,
    );
    [rows.top, rows.bottom]
}

/// The dashed outline of tokens compression keeps out: a quiet accent, since it is the safe part.
fn saved_color(theme: &Theme) -> Color {
    blend(theme.accent, theme.ink, 150)
}

/// Tokens `span` takes on its track now: what it costs, or, while it moves, a cost on the way
/// from the old one to the new.
fn shown_tokens(span: &MemorySpan, moving: Option<(&Move, u64)>) -> u64 {
    if let Some((entry, permille)) = moving
        && entry.span_id == span.id
    {
        let from = entry.before.map_or_else(
            || match entry.to {
                Tier::Exact => 0,
                Tier::Compressed => u64::from(span.exact_tokens),
            },
            u64::from,
        );
        tween(from, u64::from(span.tokens), permille)
    } else {
        u64::from(span.tokens)
    }
}

/// The two rows of one agent's track, built block by block.
#[derive(Debug)]
struct TrackRows {
    /// The blocks.
    top: Vec<Span<'static>>,
    /// The blocks again, with each exact span's handle written in.
    bottom: Vec<Span<'static>>,
    /// The palette.
    theme: Theme,
}

impl TrackRows {
    /// `text` in `color` on both rows.
    fn both(&mut self, text: &str, color: Color) {
        self.top.push(Span::raw(text.to_owned()).fg(color));
        self.bottom.push(Span::raw(text.to_owned()).fg(color));
    }

    /// `span` as a block `width` columns wide. A block `joined` to a neighbour that looks the same
    /// ends in a thin gap, so the two stay apart.
    fn block(&mut self, span: &MemorySpan, width: usize, mark: Option<Mark>, joined: bool) {
        let theme = self.theme;
        let flash = |color: Color| {
            mark.and_then(|mark| mark.permille)
                .map_or(color, |permille| {
                    blend(
                        theme.bright,
                        color,
                        u16::try_from(permille.min(1000) * 256 / 1000).unwrap_or(256),
                    )
                })
        };
        let body = if joined { width - 1 } else { width };
        let base = source_color(span.source, &theme);
        match span.tier {
            Tier::Exact => {
                let evidence = span.source == SpanSource::Evidence;
                let color = flash(base);
                let (fill, surface, ink) = if evidence {
                    ("▓", flash(theme.red_bg), theme.bright)
                } else {
                    ("█", color, theme.ink)
                };
                let fill_style = if evidence {
                    Style::new().fg(blend(color, surface, 120)).bg(surface)
                } else {
                    Style::new().fg(color)
                };
                self.top.push(Span::styled(fill.repeat(body), fill_style));
                let arrow = mark.map_or("", |mark| arrow(mark.to));
                let id = format!("{arrow}{}", span.id);
                let name = if span.tokens < span.exact_tokens {
                    format!("{id} window")
                } else {
                    id.clone()
                };
                let text = if width_of(&name) + 4 <= body {
                    fit(&format!("{name} {}", span.label), body)
                } else if width_of(&name) <= body {
                    name
                } else if width_of(&id) <= body {
                    id
                } else {
                    String::new()
                };
                self.bottom.push(Span::styled(
                    pad(&text, body),
                    Style::new()
                        .fg(ink)
                        .bg(surface)
                        .add_modifier(Modifier::BOLD),
                ));
                if joined {
                    self.top.push(Span::raw("▊").fg(surface));
                    self.bottom.push(Span::raw("▊").fg(surface));
                }
            }
            Tier::Compressed => {
                let hatch = flash(blend(base, theme.ink, 100));
                let gap = if joined { " " } else { "" };
                let body = format!("{}{gap}", "╱".repeat(body));
                self.top.push(Span::raw(body.clone()).fg(hatch));
                self.bottom.push(Span::raw(body).fg(hatch));
            }
        }
    }
}

/// The color of a span from `source`: the attacker's evidence in red.
const fn source_color(source: SpanSource, theme: &Theme) -> Color {
    match source {
        SpanSource::Commander => theme.commander,
        SpanSource::Agent => theme.agent,
        SpanSource::Tool => theme.tool,
        SpanSource::Evidence => theme.red,
    }
}

/// `↑` for a span paged in to exact, `↓` for one paged out to a handle.
const fn arrow(to: Tier) -> &'static str {
    match to {
        Tier::Exact => "↑",
        Tier::Compressed => "↓",
    }
}

/// `12,480 tok`, right-aligned in [`FIGURE_WIDTH`].
fn token_figure(tokens: u64, theme: &Theme) -> [Span<'static>; 3] {
    let number = grouped(tokens);
    let used = width_of(&number) + 4;
    [
        Span::raw(" ".repeat(FIGURE_WIDTH.saturating_sub(used))),
        Span::raw(number).fg(theme.bright).bold(),
        Span::raw(" tok").fg(theme.dim),
    ]
}

/// `↑ ev-6 4s`: the agent's newest move and its age, lit while recent.
fn move_figure(last: Option<&Move>, theme: &Theme, clock: Clock) -> Span<'static> {
    let Some(entry) = last else {
        return Span::raw(" ".repeat(FIGURE_WIDTH));
    };
    let age = clock.since(entry.at);
    let text = format!("{} {} {}", arrow(entry.to), entry.span_id, short_age(age));
    let color = if age < RECENT {
        theme.bright
    } else {
        theme.dim
    };
    Span::raw(right(&text, FIGURE_WIDTH)).fg(color)
}

/// Who wrote what, and the shapes a span takes, as many as fit in `width` columns.
fn source_legend(theme: &Theme, width: usize) -> Line<'static> {
    let entries = [
        ("█", theme.commander, "commander"),
        ("█", theme.agent, "agent"),
        ("█", theme.tool, "tool"),
        ("▓", theme.red, "evidence (attacker)"),
        ("╱", theme.muted, "compressed handle"),
        ("┄", saved_color(theme), "saved"),
    ];
    let mut spans = Vec::new();
    let mut used = 0;
    for (symbol, color, name) in entries {
        let item = [
            Span::raw(format!("{symbol}{symbol} ")).fg(color),
            Span::raw(format!("{name}   ")).fg(theme.muted),
        ];
        let item_width = line_width(&item);
        if used + item_width > width + 3 {
            break;
        }
        used += item_width;
        spans.extend(item);
    }
    Line::from(spans)
}

/// What the shapes mean, one line each.
fn stack_footer(theme: &Theme, width: usize) -> [Line<'static>; 3] {
    let room = width.saturating_sub(3);
    let line = |symbol: &str, color: Color, long: String, short: &str| {
        let text = if width_of(&long) <= room {
            long
        } else {
            fit(short, room)
        };
        Line::from(vec![
            Span::raw(format!("{symbol}{symbol} ")).fg(color),
            Span::raw(text).fg(theme.dim),
        ])
    };
    [
        line(
            "█",
            theme.text,
            format!(
                "exact: the bytes verbatim; only the {ATTENTION_LAYERS} attention layers recall them exactly"
            ),
            "exact: verbatim; only attention recalls it exactly",
        ),
        line(
            "╱",
            theme.muted,
            "compressed: a handle (digest, size, one line); page_in brings the bytes back"
                .to_owned(),
            "compressed: digest, size, one line; page_in for bytes",
        ),
        line(
            "┄",
            saved_color(theme),
            "saved: tokens compression keeps out of context; evidence enters compressed".to_owned(),
            "saved: kept out of context; evidence enters compressed",
        ),
    ]
}

// ---------- The cache ----------

/// Per agent the attention KV cache its context takes, and would take with every span exact, and
/// the Mamba-2 state, which stays flat; then the formulas. Computed from the config, not measured.
fn cache_panel(board: &MemoryBoard, theme: &Theme, area: Rect, fit: Fit) -> Paragraph<'static> {
    let block = theme.panel("Cache · computed, not measured", false);
    let width = usize::from(block.inner(area).width);
    let most = board
        .contexts()
        .iter()
        .map(|context| context.cost().kv_bytes_untiered())
        .max()
        .unwrap_or(0)
        .max(MAMBA_STATE_BYTES);
    let saved: Vec<String> = board
        .contexts()
        .iter()
        .map(|context| format!("{} tok saved", grouped(context.cost().saved())))
        .collect();
    let tail = saved.iter().map(|text| width_of(text)).max().unwrap_or(0);
    let bar = width.saturating_sub(4 + 1 + 8 + 2 + tail);
    let crossover = format!(
        "per conversation · KV passes Mamba-2 at {} tok",
        grouped(MAMBA_STATE_BYTES.div_ceil(KV_BYTES_PER_TOKEN))
    );
    let mut lines = vec![if fit.per_agent == 1 {
        Line::from(format!(
            "Mamba-2 state {} per agent, flat",
            mib(MAMBA_STATE_BYTES)
        ))
        .fg(theme.muted)
    } else if width_of(&crossover) <= width {
        Line::from(crossover).fg(theme.dim)
    } else {
        Line::from("per conversation, from config.json").fg(theme.dim)
    }];
    for (context, saved) in board.contexts().iter().zip(saved) {
        let cost = context.cost();
        let held = scaled(cost.kv_bytes(), bar, most);
        let untiered = scaled(cost.kv_bytes_untiered(), bar, most).max(held);
        lines.push(Line::from(vec![
            Span::raw("KV  ").fg(theme.muted),
            Span::raw("▰".repeat(held)).fg(theme.accent),
            Span::raw("▱".repeat(untiered - held)).fg(blend(theme.accent, theme.ink, 120)),
            Span::raw(" ".repeat(bar.saturating_sub(untiered) + 1)),
            Span::raw(right(&mib(cost.kv_bytes()), 8))
                .fg(theme.bright)
                .bold(),
            Span::raw("  "),
            Span::raw(saved).fg(if cost.saved() > 0 {
                theme.accent
            } else {
                theme.dim
            }),
        ]));
        if fit.per_agent > 1 {
            let state = scaled(MAMBA_STATE_BYTES, bar, most);
            lines.push(Line::from(vec![
                Span::raw("SSM ").fg(theme.muted),
                Span::raw("▰".repeat(state)).fg(theme.mamba),
                Span::raw(" ".repeat(bar.saturating_sub(state) + 1)),
                Span::raw(right(&mib(MAMBA_STATE_BYTES), 8)).fg(theme.text),
                Span::raw("  flat").fg(theme.dim),
            ]));
        }
    }
    lines.extend(
        formulas(width)
            .into_iter()
            .take(usize::from(fit.footer))
            .map(|text| Line::from(text).fg(theme.muted)),
    );
    Paragraph::new(lines).block(block)
}

/// The three formulas behind the bars, spelled out when `width` allows.
fn formulas(width: usize) -> [String; 3] {
    let pick = |long: String, short: String| {
        if width_of(&long) <= width {
            long
        } else {
            fit(&short, width)
        }
    };
    [
        pick(
            format!(
                "KV/tok = {ATTENTION_LAYERS} attn × {KV_HEADS} KV × {HEAD_DIM} × 2 (K,V) × {KV_VALUE_BYTES} B fp8 = {} KiB",
                KV_BYTES_PER_TOKEN / 1024
            ),
            format!(
                "KV/tok = {ATTENTION_LAYERS}×{KV_HEADS}×{HEAD_DIM}×2×{KV_VALUE_BYTES} B = {} KiB",
                KV_BYTES_PER_TOKEN / 1024
            ),
        ),
        pick(
            format!(
                "SSM = {MAMBA_LAYERS} × {MAMBA_HEADS} × {MAMBA_HEAD_DIM} × {SSM_STATE_SIZE} × {SSM_VALUE_BYTES} B fp32 = {}",
                mib(SSM_STATE_BYTES)
            ),
            format!(
                "SSM = {MAMBA_LAYERS}×{MAMBA_HEADS}×{MAMBA_HEAD_DIM}×{SSM_STATE_SIZE}×{SSM_VALUE_BYTES} B = {}",
                mib(SSM_STATE_BYTES)
            ),
        ),
        pick(
            format!(
                "conv = {MAMBA_LAYERS} × {} × {} × {CONV_VALUE_BYTES} B bf16 = {} · flat",
                grouped(CONV_CHANNELS),
                CONV_KERNEL - 1,
                mib(CONV_STATE_BYTES)
            ),
            format!(
                "conv = {MAMBA_LAYERS}×{}×{}×{CONV_VALUE_BYTES} B = {}",
                grouped(CONV_CHANNELS),
                CONV_KERNEL - 1,
                mib(CONV_STATE_BYTES)
            ),
        ),
    ]
}

// ---------- The moves ----------

/// Every tier move that fits, newest last, as a zebra table under an accent header.
fn moves_panel(
    board: &MemoryBoard,
    theme: &Theme,
    tz: &TimeZone,
    clock: Clock,
    area: Rect,
) -> Table<'static> {
    let moves = board.moves();
    let block = theme
        .panel("Tier moves · each one receipted by cleanroomd", false)
        .title(
            Line::from(format!(" {} moves · v verifies the log ", moves.len()))
                .fg(theme.dim)
                .right_aligned(),
        );
    if moves.is_empty() {
        let message = "No tier moves yet: evidence enters compressed, as a handle; page_in and page_out move spans, and cleanroomd receipts each move.";
        return Table::new(
            [Row::new([Cell::from(message)]).style(Style::new().fg(theme.dim))],
            [Constraint::Fill(1)],
        )
        .block(block);
    }
    let inner = block.inner(area);
    let room = usize::from(inner.height.saturating_sub(1));
    let free = usize::from(inner.width).saturating_sub(8 + NAME_WIDTH + 14 + 8 + 5 * 2);
    let widths = (free * 2 / 5, free - free * 2 / 5);
    let first = moves.len().saturating_sub(room);
    let rows = moves.iter().enumerate().skip(first).map(|(index, entry)| {
        let lit = index + 1 == moves.len() && clock.since(entry.at) < RECENT;
        let surface = if lit {
            Style::new().bg(theme.raised_hi)
        } else if (index - first) % 2 == 0 {
            Style::new().bg(theme.raised)
        } else {
            Style::new()
        };
        move_row(entry, theme, tz, lit, widths).style(surface)
    });
    let header = Row::new([
        "TIME",
        "AGENT",
        "SPAN",
        "TO",
        "TOKENS",
        "WHY, IN THE AGENT'S WORDS",
    ])
    .style(Style::new().fg(theme.ink).bg(theme.accent).bold());
    let length = |columns: usize| Constraint::Length(u16::try_from(columns).unwrap_or(u16::MAX));
    Table::new(
        rows,
        [
            length(8),
            length(NAME_WIDTH),
            length(widths.0),
            length(14),
            length(8),
            length(widths.1),
        ],
    )
    .header(header)
    .column_spacing(2)
    .block(block)
}

/// One move: when, whose, which span, where to, the change in tokens and the agent's reason, the
/// span and the reason cut to `(span, why)` columns.
fn move_row(
    entry: &Move,
    theme: &Theme,
    tz: &TimeZone,
    lit: bool,
    (span_width, why_width): (usize, usize),
) -> Row<'static> {
    let source = entry
        .source
        .map_or(theme.text, |source| source_color(source, theme));
    let window = entry
        .after
        .zip(entry.exact_tokens)
        .is_some_and(|(after, exact)| after < exact);
    let (to, to_style) = match entry.to {
        Tier::Exact if window => ("→ exact window", Style::new().fg(theme.bright).bold()),
        Tier::Exact => ("→ exact", Style::new().fg(theme.bright).bold()),
        Tier::Compressed => ("→ compressed", Style::new().fg(theme.muted)),
    };
    let delta = if let (Some(before), Some(after)) = (entry.before, entry.after) {
        match after.cmp(&before) {
            std::cmp::Ordering::Greater => format!("+{}", grouped(u64::from(after - before))),
            std::cmp::Ordering::Less => format!("−{}", grouped(u64::from(before - after))),
            std::cmp::Ordering::Equal => "±0".to_owned(),
        }
    } else {
        String::new()
    };
    let delta_color = match entry.to {
        Tier::Exact => theme.text,
        Tier::Compressed => theme.accent,
    };
    let label_width = span_width.saturating_sub(width_of(&entry.span_id) + 1);
    Row::new([
        Cell::from(due_label(entry.at, tz, "%H:%M:%S")).style(Style::new().fg(if lit {
            theme.bright
        } else {
            theme.dim
        })),
        Cell::from(format!("{} {}", glyph(entry.role), role_label(entry.role)))
            .style(Style::new().fg(tint(entry.role)).bold()),
        Cell::from(Line::from(vec![
            Span::raw(entry.span_id.clone()).fg(source).bold(),
            Span::raw(" "),
            Span::raw(squeeze(&entry.label, label_width)).fg(theme.text),
        ])),
        Cell::from(to).style(to_style),
        Cell::from(right(&delta, 8)).style(Style::new().fg(delta_color)),
        Cell::from(fit(&entry.reason, why_width)).style(Style::new().fg(theme.text).italic()),
    ])
}

// ---------- No maps yet ----------

/// The hatched placeholder for a board with no maps: what fills it, and how to start it.
fn empty_panel(theme: &Theme, area: Rect) -> Paragraph<'static> {
    let block = theme.panel("Context, span by span", false);
    let inner = block.inner(area);
    Paragraph::new(empty_lines(
        theme,
        usize::from(inner.width),
        usize::from(inner.height),
    ))
    .block(block)
}

/// `rows` hatched lines `width` wide with the message boxed in the middle.
fn empty_lines(theme: &Theme, width: usize, rows: usize) -> Vec<Line<'static>> {
    let message: [Vec<Span<'static>>; 7] = [
        Vec::new(),
        vec![Span::raw("No memory maps yet").fg(theme.bright).bold()],
        Vec::new(),
        vec![
            Span::raw("Start the agents with ").fg(theme.text),
            Span::raw("cleanroom-agents run --memory-tiers")
                .fg(theme.accent)
                .bold(),
        ],
        vec![
            Span::raw(
                "Each agent then publishes its context span by span; evidence enters compressed, as a handle.",
            )
            .fg(theme.muted),
        ],
        vec![
            Span::raw(
                "page_in and page_out move spans between tiers, and cleanroomd receipts every move.",
            )
            .fg(theme.muted),
        ],
        Vec::new(),
    ];
    let boxed = (message
        .iter()
        .map(|spans| line_width(spans))
        .max()
        .unwrap_or(0)
        + 6)
    .min(width);
    let left = width.saturating_sub(boxed) / 2;
    let top = rows.saturating_sub(message.len()) / 2;
    (0..rows)
        .map(|row| {
            let hatch = |from: usize, to: usize| -> String {
                (from..to)
                    .map(|column| if (column + row) % 2 == 0 { '/' } else { ' ' })
                    .collect()
            };
            row.checked_sub(top)
                .and_then(|index| message.get(index))
                .map_or_else(
                    || Line::from(Span::raw(hatch(0, width)).fg(theme.line)),
                    |spans| {
                        let used = line_width(spans);
                        let before = boxed.saturating_sub(used) / 2;
                        let after = boxed.saturating_sub(used + before);
                        let mut line = vec![
                            Span::raw(hatch(0, left)).fg(theme.line),
                            Span::raw(" ".repeat(before)),
                        ];
                        line.extend(spans.iter().cloned());
                        line.push(Span::raw(" ".repeat(after)));
                        line.push(Span::raw(hatch(left + boxed, width)).fg(theme.line));
                        Line::from(line)
                    },
                )
        })
        .collect()
}

// ---------- Numbers ----------

/// Split `total` columns among `weights`: each gets one, and the rest go in proportion to the
/// weights, largest remainder first. With fewer columns than weights, the first `total` get one.
fn allocate(weights: &[u64], total: usize) -> Vec<usize> {
    let count = weights.len();
    if total <= count {
        return (0..count).map(|index| usize::from(index < total)).collect();
    }
    let extra = u64::try_from(total - count).unwrap_or(u64::MAX);
    let even = weights.iter().all(|weight| *weight == 0);
    let weight_of = |value: u64| if even { 1 } else { value };
    let sum: u64 = weights.iter().map(|value| weight_of(*value)).sum();
    let mut widths = Vec::with_capacity(count);
    let mut remainders = Vec::with_capacity(count);
    let mut given = 0;
    for (index, value) in weights.iter().enumerate() {
        let portion = weight_of(*value).saturating_mul(extra);
        given += portion / sum;
        widths.push(1 + usize::try_from(portion / sum).unwrap_or(0));
        remainders.push((portion % sum, index));
    }
    remainders.sort_by(|left, right| right.0.cmp(&left.0).then(left.1.cmp(&right.1)));
    let left_over = usize::try_from(extra.saturating_sub(given)).unwrap_or(0);
    for (_, index) in remainders.into_iter().take(left_over) {
        if let Some(width) = widths.get_mut(index) {
            *width += 1;
        }
    }
    widths
}

/// `value` out of `max` as columns of `width`, rounded to the nearest.
fn scaled(value: u64, width: usize, max: u64) -> usize {
    let max = max.max(1);
    let width = u64::try_from(width).unwrap_or(u64::MAX);
    usize::try_from(value.saturating_mul(width).saturating_add(max / 2) / max).unwrap_or(usize::MAX)
}

/// `permille` thousandths of the way from `from` to `to`.
fn tween(from: u64, to: u64, permille: u64) -> u64 {
    let permille = permille.min(1000);
    if to >= from {
        from + (to - from) * permille / 1000
    } else {
        from - (from - to) * permille / 1000
    }
}

/// `4s`, `2m`, `1h`.
fn short_age(age: SignedDuration) -> String {
    let seconds = age.as_secs().max(0);
    match seconds {
        0..60 => format!("{seconds}s"),
        60..3600 => format!("{}m", seconds / 60),
        _ => format!("{}h", seconds / 3600),
    }
}

/// `46.8 MiB`.
fn mib(bytes: u64) -> String {
    let tenths = bytes.saturating_mul(10).saturating_add(MIB / 2) / MIB;
    format!("{}.{} MiB", tenths / 10, tenths % 10)
}

/// `text` cut to `width` columns and pushed right.
fn right(text: &str, width: usize) -> String {
    let text = fit(text, width);
    format!(
        "{}{text}",
        " ".repeat(width.saturating_sub(width_of(&text)))
    )
}

/// Columns `spans` take.
fn line_width(spans: &[Span<'_>]) -> usize {
    spans.iter().map(Span::width).sum()
}

/// `text` in `width` columns: whole when it fits, else its start and its end around `…`, so a
/// path keeps its file name.
fn squeeze(text: &str, width: usize) -> String {
    if width_of(text) <= width || width < 12 {
        return fit(text, width);
    }
    let tail = width * 3 / 5;
    format!("{}{}", fit(text, width - tail), tail_fit(text, tail))
}

#[cfg(test)]
mod tests {
    use cleanroom_proto::{
        Audience, BusBody, BusMessage, Envelope, Frame as Wire, MemoryMap, MemorySpan, Principal,
        Role, Signed, SpanSource, Tier, TierMove, WIRE_VERSION, domain,
    };
    use jiff::tz::TimeZone;
    use jiff::{SignedDuration, Timestamp};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;
    use ratatui::text::Span;

    use super::{Clock, Scale, allocate, mib, short_age, track, tween};
    use crate::memory::{MAMBA_STATE_BYTES, MemoryBoard};
    use crate::state::State;
    use crate::theme::Name;
    use crate::ui::{Tab, View, render};

    /// `seconds` after the start of the script.
    fn at(seconds: i64) -> Timestamp {
        Timestamp::from_second(1_794_115_100 + seconds).expect("script times are valid")
    }

    /// A span: `(tokens, exact_tokens)` and whether it is exact.
    fn span(
        id: &str,
        source: SpanSource,
        label: &str,
        (tokens, exact_tokens): (u32, u32),
    ) -> MemorySpan {
        MemorySpan {
            id: id.to_owned(),
            source,
            tier: if tokens < exact_tokens {
                Tier::Compressed
            } else {
                Tier::Exact
            },
            tokens,
            exact_tokens,
            digest: format!("sha256:{id}"),
            label: label.to_owned(),
        }
    }

    /// The system prompt and the task every agent starts with.
    fn opening(task: u32) -> Vec<MemorySpan> {
        vec![
            span("cmd-1", SpanSource::Commander, "system prompt", (37, 37)),
            span("cmd-2", SpanSource::Commander, "task", (task, task)),
        ]
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

    /// `map` as the bus event an agent publishes `seconds` into the script.
    fn event(seconds: i64, map: MemoryMap) -> (Envelope, Timestamp) {
        let message = BusMessage {
            id: format!("m{seconds}-{:?}", map.role),
            at: at(seconds).to_string(),
            from: Principal::Agent { role: map.role },
            to: Audience::All,
            body: BusBody::Memory(map),
        };
        let envelope = Envelope {
            v: WIRE_VERSION,
            frame: Wire::Event(Signed {
                domain: domain::BUS.to_owned(),
                body: message,
                signer: "sha256:00".to_owned(),
                sig: "00".to_owned(),
            }),
        };
        (envelope, at(seconds))
    }

    /// Hunter's context: the listing paged in, the ransom note compressed or exact.
    fn hunter(note_exact: bool, listing_exact: bool) -> Vec<MemorySpan> {
        let mut spans = opening(902);
        spans.extend([
            span("ag-1", SpanSource::Agent, "calls exec", (88, 88)),
            span(
                "ev-1",
                SpanSource::Evidence,
                "exec ls -la /evidence/acme-fs",
                if listing_exact {
                    (1_206, 1_206)
                } else {
                    (38, 1_206)
                },
            ),
            span("ag-2", SpanSource::Agent, "calls read_file", (95, 95)),
            span(
                "ev-2",
                SpanSource::Evidence,
                "read_file /evidence/acme-fs/README_RESTORE_FILES.txt",
                if note_exact {
                    (1_630, 1_630)
                } else {
                    (41, 1_630)
                },
            ),
            span("ag-3", SpanSource::Agent, "calls exec", (90, 90)),
            span(
                "ev-3",
                SpanSource::Evidence,
                "exec tail -n 50 /evidence/logs/syslog",
                (44, 3_120),
            ),
            span("tool-1", SpanSource::Tool, "hash_file", (61, 61)),
        ]);
        spans
    }

    /// Forensics' context: a long run of small turns, the ransom note paged in or not.
    fn forensics(note_exact: bool) -> Vec<MemorySpan> {
        let mut spans = opening(1_193);
        for turn in 1..=9 {
            spans.push(span(
                &format!("ag-{turn}"),
                SpanSource::Agent,
                "calls read_file",
                (91, 91),
            ));
            if turn % 3 == 0 {
                spans.push(span(
                    &format!("tool-{turn}"),
                    SpanSource::Tool,
                    "list_rules",
                    (58, 58),
                ));
            } else {
                spans.push(span(
                    &format!("ev-{turn}"),
                    SpanSource::Evidence,
                    "read_file /evidence/logs/auth.log",
                    (40, 420),
                ));
            }
        }
        spans.push(span(
            "ev-10",
            SpanSource::Evidence,
            "read_file /evidence/acme-fs/README_RESTORE_FILES.txt",
            if note_exact {
                (1_630, 1_630)
            } else {
                (41, 1_630)
            },
        ));
        spans
    }

    /// A run modelled on a live `--memory-tiers` run: every agent's context, three page_ins and a
    /// page_out, the last page_in 0.4 s before the screen is drawn.
    fn script() -> Vec<(Envelope, Timestamp)> {
        let mut lead = opening(1_193);
        lead.extend([
            span(
                "cmd-3",
                SpanSource::Commander,
                "commander question",
                (24, 24),
            ),
            span(
                "ag-1",
                SpanSource::Agent,
                "calls ask_specialist",
                (120, 120),
            ),
            span(
                "tool-1",
                SpanSource::Tool,
                "ask_specialist hunter",
                (210, 210),
            ),
        ]);
        let mut scribe = opening(1_193);
        scribe.extend([
            span(
                "ag-1",
                SpanSource::Agent,
                "calls update_incident",
                (294, 294),
            ),
            span("tool-1", SpanSource::Tool, "update_incident", (48, 48)),
            span("ag-2", SpanSource::Agent, "calls update_scope", (91, 91)),
            span("tool-2", SpanSource::Tool, "update_scope", (46, 46)),
        ]);
        let mut containment = opening(480);
        containment.push(span("ag-1", SpanSource::Agent, "calls propose", (130, 130)));
        vec![
            event(3, map(Role::Lead, lead, None)),
            event(6, map(Role::Hunter, hunter(false, false), None)),
            event(8, map(Role::Forensics, forensics(false), None)),
            event(9, map(Role::Scribe, scribe, None)),
            event(12, map(Role::Containment, containment, None)),
            event(
                20,
                map(
                    Role::Hunter,
                    hunter(false, true),
                    Some(("ev-1", Tier::Exact, "listing of /evidence/acme-fs")),
                ),
            ),
            event(
                38,
                map(
                    Role::Hunter,
                    hunter(true, true),
                    Some(("ev-2", Tier::Exact, "reading README_RESTORE_FILES.txt")),
                ),
            ),
            event(
                41,
                map(
                    Role::Hunter,
                    hunter(true, false),
                    Some(("ev-1", Tier::Compressed, "done with the listing")),
                ),
            ),
            event(
                44,
                map(
                    Role::Forensics,
                    forensics(true),
                    Some(("ev-10", Tier::Exact, "read full ransom note")),
                ),
            ),
        ]
    }

    /// The console after `script`, drawn on the Memory tab at `size`, `millis` after the last move.
    fn draw(
        script: Vec<(Envelope, Timestamp)>,
        (width, height): (u16, u16),
        millis: i64,
    ) -> Buffer {
        let mut state = State::new(TimeZone::UTC);
        for (envelope, now) in script {
            state.apply(envelope, None, now);
        }
        let mut view = View::live(Vec::new()).with_motion(true);
        view.show(Tab::Memory);
        let now = at(44) + SignedDuration::from_millis(millis);
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test backend");
        terminal
            .draw(|frame| render(frame, &state, &view, now))
            .expect("draws");
        terminal.backend().buffer().clone()
    }

    /// Every row of `buffer` as text.
    fn rows(buffer: &Buffer) -> Vec<String> {
        buffer
            .content
            .chunks(usize::from(buffer.area.width))
            .map(|row| row.iter().map(ratatui::buffer::Cell::symbol).collect())
            .collect()
    }

    #[test]
    fn the_tab_draws_the_layers_the_stacks_the_cache_and_the_moves() {
        let buffer = draw(script(), (160, 45), 400);
        let rows = rows(&buffer);
        let screen = rows.join("\n");
        for expected in [
            "Nemotron 3 Nano 30B-A3B · 52 layers",
            "Tiers applied by Cleanroom today; a trained retention router would apply them inside Nemotron's 6 attention layers.",
            "attention ×6",
            "KV cache: the only exact recall",
            "Context, span by span",
            "◆ CLEAN",
            "● FORENSICS",
            "▣ CONTAINMENT",
            "Cache · computed, not measured",
            "KV/tok = 6 attn × 2 KV × 128 × 2 (K,V) × 1 B fp8 = 3 KiB",
            "SSM = 23 × 64 × 64 × 128 × 4 B fp32 = 46.0 MiB",
            "46.8 MiB",
            "Tier moves · each one receipted by cleanroomd",
            "reading README_RESTORE_FILES.txt",
            "→ compressed",
            "done with the listing",
        ] {
            assert!(
                screen.contains(expected),
                "missing {expected:?} in\n{screen}"
            );
        }
        let (cells, row) = rows
            .iter()
            .enumerate()
            .find(|(_, row)| row.matches('✱').count() == 6)
            .expect("one row holds the six attention cells");
        let accent: Vec<u16> = (0..buffer.area.width)
            .filter(|column| {
                let cell = &buffer[(*column, u16::try_from(cells).expect("small screen"))];
                cell.symbol() == "✱" && cell.bg == Name::Cleanroom.theme().accent
            })
            .collect();
        assert_eq!(accent.len(), 6, "every attention cell is lit: {row}");
    }

    #[test]
    fn the_tab_fits_the_smallest_screen() {
        let screen = rows(&draw(script(), (120, 36), 5_000)).join("\n");
        for expected in [
            "attention ×6",
            "● FORENSICS",
            "▣ CONTAINMENT",
            "KV  ",
            "read full ransom note",
        ] {
            assert!(
                screen.contains(expected),
                "missing {expected:?} in\n{screen}"
            );
        }
    }

    #[test]
    fn with_no_maps_the_tab_says_how_to_start_them() {
        let screen = rows(&draw(Vec::new(), (160, 45), 0)).join("\n");
        for expected in [
            "No memory maps yet",
            "cleanroom-agents run --memory-tiers",
            "cleanroomd receipts every move",
            "/ / / /",
            "attention ×6",
        ] {
            assert!(
                screen.contains(expected),
                "missing {expected:?} in\n{screen}"
            );
        }
    }

    /// Columns of `glyph` in the top row of Hunter's track, `millis` after a move at second 10.
    fn columns_after(board: &MemoryBoard, glyph: char, millis: i64, motion: bool) -> usize {
        let context = board.contexts().first().expect("Hunter's context");
        let clock = Clock {
            now: at(10) + SignedDuration::from_millis(millis),
            motion,
        };
        let scale = Scale {
            width: 40,
            most: 2_000,
        };
        let [top, _] = track(
            context,
            board.last_move(Role::Hunter),
            scale,
            Name::Cleanroom.theme(),
            clock,
        );
        top.iter()
            .map(|span: &Span<'_>| span.content.chars().filter(|ch| *ch == glyph).count())
            .sum()
    }

    #[test]
    fn a_page_in_grows_its_block_and_a_page_out_shrinks_it() {
        let exact = vec![
            span("cmd-2", SpanSource::Commander, "task", (1_000, 1_000)),
            span("ev-1", SpanSource::Evidence, "the note", (1_000, 1_000)),
        ];
        let compressed = vec![
            span("cmd-2", SpanSource::Commander, "task", (1_000, 1_000)),
            span("ev-1", SpanSource::Evidence, "the note", (40, 1_000)),
        ];
        let mut board = MemoryBoard::default();
        board.observe(&at(0), &map(Role::Hunter, compressed.clone(), None));
        board.observe(
            &at(10),
            &map(
                Role::Hunter,
                exact.clone(),
                Some(("ev-1", Tier::Exact, "read it")),
            ),
        );
        let growing: Vec<usize> = [0, 600, 1_500]
            .map(|millis| columns_after(&board, '▓', millis, true))
            .into();
        assert!(
            growing.windows(2).all(|pair| pair.first() < pair.get(1)),
            "page_in grows: {growing:?}"
        );
        assert_eq!(
            columns_after(&board, '▓', 0, false),
            growing.last().copied().unwrap_or(0),
            "no motion, no tween"
        );

        let mut board = MemoryBoard::default();
        board.observe(&at(0), &map(Role::Hunter, exact, None));
        board.observe(
            &at(10),
            &map(
                Role::Hunter,
                compressed,
                Some(("ev-1", Tier::Compressed, "done")),
            ),
        );
        let shrinking: Vec<usize> = [0, 600, 1_500]
            .map(|millis| columns_after(&board, '╱', millis, true))
            .into();
        assert!(
            shrinking.windows(2).all(|pair| pair.first() > pair.get(1)),
            "page_out shrinks: {shrinking:?}"
        );
    }

    #[test]
    fn columns_split_by_tokens_with_one_each_at_least() {
        assert_eq!(
            allocate(&[100, 0, 300], 10),
            [3, 1, 6],
            "1 each, then 7 by weight"
        );
        assert_eq!(
            allocate(&[5, 5, 5], 2),
            [1, 1, 0],
            "too few columns: the first get one"
        );
        let even = allocate(&[0, 0, 0], 8);
        assert_eq!(even.iter().sum::<usize>(), 8, "all columns used");
        assert!(
            even.iter().all(|width| (2..=3).contains(width)),
            "spread evenly: {even:?}"
        );
        let real = allocate(&[37, 902, 88, 38, 95, 1_630, 90, 44, 61], 60);
        assert_eq!(
            real.iter().sum::<usize>(),
            60,
            "a real track fills its columns"
        );
        assert_eq!(
            real.iter().max(),
            real.get(5),
            "the paged-in note is the widest block"
        );
    }

    #[test]
    fn the_figures_round_as_shown() {
        assert_eq!(tween(40, 1_000, 500), 520, "half way up");
        assert_eq!(tween(1_000, 40, 500), 520, "half way down");
        assert_eq!(tween(0, 100, 5_000), 100, "never past the end");
        assert_eq!(mib(MAMBA_STATE_BYTES), "46.8 MiB", "Mamba-2 state");
        assert_eq!(mib(1_273 * 3_072), "3.7 MiB", "KV for 1,273 tokens");
        assert_eq!(short_age(SignedDuration::from_secs(4)), "4s", "seconds");
        assert_eq!(short_age(SignedDuration::from_secs(150)), "2m", "minutes");
        assert_eq!(short_age(SignedDuration::from_secs(7_300)), "2h", "hours");
    }
}
