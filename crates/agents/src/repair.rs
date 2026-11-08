//! Minimal repair for tool-call arguments that a model truncated or wrapped.
//!
//! Hosted models occasionally stop mid-argument (timeouts, `max_tokens`) or wrap the JSON in a
//! Markdown fence. The repair closes what the model opened and nothing more: unterminated
//! strings, unbalanced objects and arrays, a dangling comma or key separator, and stray closers
//! after the top-level value. Anything still invalid goes back to the model as an error.

use serde_json::{Map, Value};

/// Tool-call arguments after parsing.
#[derive(Debug)]
pub(crate) struct Arguments {
    /// The parsed JSON value.
    pub(crate) value: Value,
    /// True when the raw text needed a repair before it parsed.
    pub(crate) repaired: bool,
}

/// Parse a model's `function.arguments` string, repairing it when it is truncated.
///
/// An empty string means "no arguments" and parses as `{}`.
///
/// # Errors
/// Returns a message for the model when the text is not JSON even after repair.
pub(crate) fn parse_arguments(raw: &str) -> Result<Arguments, String> {
    let trimmed = raw.trim();
    let unfenced = strip_fence(trimmed);
    if unfenced.is_empty() {
        return Ok(Arguments {
            value: Value::Object(Map::new()),
            repaired: false,
        });
    }
    let first_error = match serde_json::from_str::<Value>(unfenced) {
        Ok(value) => {
            return Ok(Arguments {
                value,
                repaired: unfenced.len() != trimmed.len(),
            });
        }
        Err(error) => error,
    };
    close_unbalanced(unfenced)
        .and_then(|candidate| serde_json::from_str::<Value>(&candidate).ok())
        .map(|value| Arguments {
            value,
            repaired: true,
        })
        .ok_or_else(|| format!("arguments are not valid JSON ({first_error})"))
}

/// Remove a surrounding Markdown code fence such as `` ```json ... ``` ``.
fn strip_fence(text: &str) -> &str {
    let Some(rest) = text.strip_prefix("```") else {
        return text;
    };
    let body = rest.trim_start_matches(|c: char| c.is_ascii_alphanumeric());
    body.strip_suffix("```").unwrap_or(body).trim()
}

/// Close unterminated strings and unbalanced brackets; drop stray closers after the top-level value.
///
/// Returns `None` when the brackets cross (for example `{"a": [1}`), which is not truncation.
fn close_unbalanced(text: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len() + 8);
    let mut open: Vec<char> = Vec::new();
    let mut in_string = false;
    let mut escaped = false;
    let mut started = false;
    for c in text.chars() {
        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        if started && open.is_empty() {
            // The top-level value already closed: tolerate only stray closers and whitespace.
            if matches!(c, '}' | ']') || c.is_whitespace() {
                continue;
            }
            return None;
        }
        match c {
            '"' => in_string = true,
            '{' => open.push('}'),
            '[' => open.push(']'),
            '}' | ']' if open.pop() != Some(c) => return None,
            _ => {}
        }
        started = true;
        out.push(c);
    }
    if in_string {
        if escaped {
            out.pop();
        }
        out.push('"');
    }
    while let Some(closer) = open.pop() {
        finish_dangling(&mut out);
        out.push(closer);
    }
    Some(out)
}

/// Drop a trailing comma and give a dangling `"key":` a `null` value before closing a container.
fn finish_dangling(out: &mut String) {
    let kept = out.trim_end().len();
    out.truncate(kept);
    if out.ends_with(',') {
        out.pop();
    } else if out.ends_with(':') {
        out.push_str("null");
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn repaired(raw: &str) -> Value {
        let parsed = parse_arguments(raw).expect("fixture is repairable");
        assert!(parsed.repaired, "fixture {raw:?} needed a repair");
        parsed.value
    }

    #[test]
    fn valid_arguments_parse_without_repair() {
        let parsed = parse_arguments(r#"{"path": "/evidence"}"#).expect("valid JSON");
        assert_eq!(parsed.value, json!({"path": "/evidence"}), "value is kept");
        assert!(!parsed.repaired, "valid JSON is not marked repaired");
    }

    #[test]
    fn empty_arguments_mean_no_arguments() {
        let parsed = parse_arguments("  ").expect("empty is allowed");
        assert_eq!(parsed.value, json!({}), "empty parses as an empty object");
    }

    #[test]
    fn truncated_string_and_object_are_closed() {
        assert_eq!(
            repaired(r#"{"path": "/evidence/acme-fs"#),
            json!({"path": "/evidence/acme-fs"}),
            "unterminated string and object"
        );
    }

    #[test]
    fn nested_containers_close_in_order() {
        assert_eq!(
            repaired(r#"{"summary": "ransom note", "evidence": ["/evidence/a", "/evidence/b"#),
            json!({"summary": "ransom note", "evidence": ["/evidence/a", "/evidence/b"]}),
            "array closes before the object"
        );
    }

    #[test]
    fn dangling_comma_and_key_separator_are_finished() {
        assert_eq!(
            repaired(r#"{"pattern": "Accepted", "#),
            json!({"pattern": "Accepted"}),
            "trailing comma dropped"
        );
        assert_eq!(
            repaired(r#"{"pattern": "Accepted", "path":"#),
            json!({"pattern": "Accepted", "path": null}),
            "dangling key gets null so the schema check can name it"
        );
    }

    #[test]
    fn escapes_inside_strings_are_respected() {
        assert_eq!(
            repaired(r#"{"pattern": "say \"hi\" {not a brace"#),
            json!({"pattern": "say \"hi\" {not a brace"}),
            "escaped quotes and braces inside strings do not count"
        );
        assert_eq!(
            repaired(r#"{"pattern": "C:\"#),
            json!({"pattern": "C:"}),
            "a dangling escape is dropped"
        );
    }

    #[test]
    fn fences_and_stray_closers_are_removed() {
        assert_eq!(
            repaired("```json\n{\"path\": \"/evidence\"}\n```"),
            json!({"path": "/evidence"}),
            "Markdown fence"
        );
        assert_eq!(
            repaired(r#"{"path": "/evidence"}}"#),
            json!({"path": "/evidence"}),
            "extra closing brace"
        );
    }

    #[test]
    fn unrepairable_text_is_an_error_for_the_model() {
        assert!(
            parse_arguments("list the evidence please").is_err(),
            "prose is not JSON"
        );
        assert!(
            parse_arguments(r#"{"a": [1}"#).is_err(),
            "crossed brackets are not truncation"
        );
        assert!(
            parse_arguments(r#"{"a": 1} trailing words"#).is_err(),
            "text after the value is not repaired"
        );
    }
}
