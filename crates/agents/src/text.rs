//! Text helpers for trace previews, model-bound output and receipt citations.

use std::fmt::{self, Write as _};

/// One-line preview: whitespace collapsed to single spaces, at most `max_chars` characters,
/// with `…` when something was cut.
pub(crate) fn preview(text: &str, max_chars: usize) -> String {
    let mut out = String::with_capacity(max_chars.min(text.len()) + 4);
    let mut used = 0_usize;
    for word in text.split_whitespace() {
        if used > 0 {
            if used >= max_chars {
                out.push('…');
                return out;
            }
            out.push(' ');
            used += 1;
        }
        for c in word.chars() {
            if used >= max_chars {
                out.push('…');
                return out;
            }
            out.push(c);
            used += 1;
        }
    }
    out
}

/// Keep the first `max_chars` characters of `text` and say how much was hidden.
pub(crate) fn clip(mut text: String, max_chars: usize) -> String {
    if let Some((cut, _)) = text.char_indices().nth(max_chars) {
        let hidden = text.get(cut..).map_or(0, |rest| rest.chars().count());
        text.truncate(cut);
        if let Err(error) = write!(text, "\n[… {hidden} more characters not shown]") {
            tracing::debug!(%error, "cannot format a clip marker");
        }
    }
    text
}

/// Append formatted text to `text`. Writing to a `String` cannot fail.
pub(crate) fn append(text: &mut String, args: fmt::Arguments<'_>) {
    if let Err(error) = text.write_fmt(args) {
        tracing::debug!(%error, "cannot format text");
    }
}

/// Cite the receipt of a denied command at the end of a trace preview: ` (receipt #42)`.
pub(crate) fn cite_receipt(text: &mut String, seq: u64) {
    append(text, format_args!(" (receipt #{seq})"));
}

/// The receipt a preview cites with [`cite_receipt`].
pub(crate) fn cited_receipt(text: &str) -> Option<u64> {
    let (_, cited) = text.rsplit_once("(receipt #")?;
    cited.split(')').next()?.parse().ok()
}
