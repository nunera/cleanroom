//! A JSON Schema subset for tool-call arguments: lenient conforming, then strict validation.
//!
//! The schemas the models see are the contract, so arguments are checked against exactly those
//! schemas before the runner acts. Supported keywords: `type`, `enum`, `properties`, `required`,
//! `additionalProperties: false`, `items`, `minItems`, `maxItems`, `minLength`, `maxLength`,
//! `minimum`, `maximum` and `pattern`. A `null` for an optional property counts as absent,
//! because models often send `null` for parameters they mean to leave out.
//!
//! Before validating, [`conform`] fixes the near misses models make that carry no ambiguity: a
//! number sent as a string or a fraction, a single string where a list is expected, a list or
//! free text longer than allowed, an enum value in the wrong case. Anything it cannot fix
//! confidently is left for [`validate`] to reject with a message the model can act on.

use regex::Regex;
use serde_json::{Map, Number, Value};

/// Bring `value` into the shape `schema` describes where the fix is unambiguous.
pub(crate) fn conform(schema: &Value, value: &mut Value) {
    let Some(kind) = schema.get("type").and_then(Value::as_str) else {
        return;
    };
    match kind {
        "integer" => conform_integer(schema, value),
        "boolean" => {
            if let Some(flag) = value.as_str().and_then(parse_bool) {
                *value = Value::Bool(flag);
            }
        }
        "string" => conform_string(schema, value),
        "array" => conform_array(schema, value),
        "object" => {
            if let (Some(properties), Some(fields)) = (
                schema.get("properties").and_then(Value::as_object),
                value.as_object_mut(),
            ) {
                for (name, field) in fields.iter_mut() {
                    if let Some(property) = properties.get(name) {
                        conform(property, field);
                    }
                }
            }
        }
        _ => {}
    }
}

/// Numbers sent as floats or strings become integers; a percentage (bounds 0 and 100) also
/// accepts a fraction (`0.85`) or a `%` suffix. Values outside the bounds are clamped.
fn conform_integer(schema: &Value, value: &mut Value) {
    let min = schema.get("minimum").and_then(Value::as_f64);
    let max = schema.get("maximum").and_then(Value::as_f64);
    let percent = min == Some(0.0) && max == Some(100.0);
    let number = if value.is_i64() || value.is_u64() {
        value.as_f64()
    } else if let Some(float) = value.as_f64() {
        Some(if percent && float <= 1.0 {
            float * 100.0
        } else {
            float
        })
    } else if let Some(text) = value.as_str() {
        parse_number(text, percent)
    } else {
        None
    };
    let Some(mut number) = number.filter(|number| number.is_finite()) else {
        return;
    };
    if let Some(min) = min {
        number = number.max(min);
    }
    if let Some(max) = max {
        number = number.min(max);
    }
    if let Some(whole) = whole_to_i64(number.round()) {
        *value = Value::Number(Number::from(whole));
    }
}

/// `"95"`, `"95%"`, `"0.95"` (a fraction when `percent`), `" 12 "`.
fn parse_number(text: &str, percent: bool) -> Option<f64> {
    let text = text.trim();
    let (digits, has_percent_sign) = text
        .strip_suffix('%')
        .map_or((text, false), |digits| (digits.trim_end(), true));
    let number: f64 = digits.parse().ok()?;
    let fraction = percent && !has_percent_sign && digits.contains('.') && number <= 1.0;
    Some(if fraction { number * 100.0 } else { number })
}

/// A whole `f64` as `i64` when it fits; out-of-range values stay unconverted for validation to
/// report (going through text avoids a silently saturating `as` cast).
fn whole_to_i64(number: f64) -> Option<i64> {
    format!("{number:.0}").parse().ok()
}

/// `"true"` / `"false"` in any case.
fn parse_bool(text: &str) -> Option<bool> {
    match text.trim().to_ascii_lowercase().as_str() {
        "true" | "yes" => Some(true),
        "false" | "no" => Some(false),
        _ => None,
    }
}

/// Numbers become text, a list becomes one line, an object becomes its single text field or
/// JSON, an enum value is matched case-insensitively, and free text is clipped to `maxLength`.
fn conform_string(schema: &Value, value: &mut Value) {
    if value.is_number() || value.is_boolean() {
        *value = Value::String(value.to_string());
    } else if let Some(items) = value.as_array() {
        let parts: Vec<String> = items.iter().map(text_of).collect();
        *value = Value::String(parts.join("; "));
    } else if value.is_object() {
        *value = Value::String(text_of(value));
    }
    let Some(text) = value.as_str() else {
        return;
    };
    if let Some(allowed) = schema.get("enum").and_then(Value::as_array) {
        let lowered = text.trim().to_ascii_lowercase();
        if let Some(canonical) = allowed
            .iter()
            .find(|option| option.as_str() == Some(lowered.as_str()))
        {
            *value = canonical.clone();
        }
        return;
    }
    let free_text = schema.get("pattern").is_none();
    if let Some(max) = schema
        .get("maxLength")
        .and_then(Value::as_u64)
        .and_then(|max| usize::try_from(max).ok())
        && free_text
        && text.chars().count() > max
    {
        let mut clipped: String = text.chars().take(max.saturating_sub(1)).collect();
        clipped.push('…');
        *value = Value::String(clipped);
    }
}

/// One value as text: strings as they are, an object with a single text field as that text,
/// anything else as compact JSON (so no detail is dropped).
fn text_of(value: &Value) -> String {
    if let Some(text) = value.as_str() {
        return text.to_owned();
    }
    if let Some(fields) = value.as_object()
        && fields.len() == 1
        && let Some(text) = fields.values().next().and_then(Value::as_str)
    {
        return text.to_owned();
    }
    value.to_string()
}

/// A single value where a list is expected becomes a one-item list; items are conformed and the
/// list is cut to `maxItems`.
fn conform_array(schema: &Value, value: &mut Value) {
    if !value.is_array() && !value.is_null() {
        let single = std::mem::take(value);
        *value = Value::Array(vec![single]);
    }
    let Some(items) = value.as_array_mut() else {
        return;
    };
    if let Some(item_schema) = schema.get("items") {
        for item in items.iter_mut() {
            conform(item_schema, item);
        }
    }
    if let Some(max) = schema
        .get("maxItems")
        .and_then(Value::as_u64)
        .and_then(|max| usize::try_from(max).ok())
    {
        items.truncate(max);
    }
}

/// Remove the top-level properties `schema` does not declare.
pub(crate) fn drop_unknown(schema: &Value, value: &mut Value) {
    let (Some(known), Some(fields)) = (
        schema.get("properties").and_then(Value::as_object),
        value.as_object_mut(),
    ) else {
        return;
    };
    fields.retain(|name, _| known.contains_key(name));
}

/// Check `value` against `schema`.
///
/// # Errors
/// Returns every violation, each naming the offending argument, joined into one message.
pub(crate) fn validate(schema: &Value, value: &Value) -> Result<(), String> {
    let mut problems = Vec::new();
    check(schema, value, "", &mut problems);
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}

/// Validate one value and recurse into arrays and objects.
fn check(schema: &Value, value: &Value, path: &str, problems: &mut Vec<String>) {
    if let Some(expected) = schema.get("type").and_then(Value::as_str)
        && !type_matches(expected, value)
    {
        problems.push(format!(
            "{} must be {}, not {}",
            label(path),
            with_article(expected),
            kind_of(value)
        ));
        return;
    }
    if let Some(allowed) = schema.get("enum").and_then(Value::as_array)
        && !allowed.contains(value)
    {
        let options: Vec<String> = allowed.iter().map(Value::to_string).collect();
        problems.push(format!(
            "{} must be one of {}",
            label(path),
            options.join(", ")
        ));
    }
    if let Some(text) = value.as_str() {
        check_string(schema, text, path, problems);
    }
    if let Some(number) = value.as_f64() {
        check_number(schema, number, path, problems);
    }
    if let Some(items) = value.as_array() {
        check_array(schema, items, path, problems);
    }
    if let Some(fields) = value.as_object() {
        check_object(schema, fields, path, problems);
    }
}

/// `minLength`, `maxLength` (in characters) and `pattern`.
fn check_string(schema: &Value, text: &str, path: &str, problems: &mut Vec<String>) {
    let length = u64::try_from(text.chars().count()).unwrap_or(u64::MAX);
    if let Some(min) = schema.get("minLength").and_then(Value::as_u64)
        && length < min
    {
        problems.push(format!("{} must be at least {min} characters", label(path)));
    }
    if let Some(max) = schema.get("maxLength").and_then(Value::as_u64)
        && length > max
    {
        problems.push(format!("{} must be at most {max} characters", label(path)));
    }
    if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
        match Regex::new(pattern) {
            Ok(regex) if regex.is_match(text) => {}
            Ok(_) => problems.push(format!("{} must match {pattern}", label(path))),
            Err(error) => problems.push(format!(
                "schema pattern for {} is invalid: {error}",
                label(path)
            )),
        }
    }
}

/// `minimum` and `maximum`.
fn check_number(schema: &Value, number: f64, path: &str, problems: &mut Vec<String>) {
    if let Some(min) = schema.get("minimum").and_then(Value::as_f64)
        && number < min
    {
        problems.push(format!("{} must be at least {min}", label(path)));
    }
    if let Some(max) = schema.get("maximum").and_then(Value::as_f64)
        && number > max
    {
        problems.push(format!("{} must be at most {max}", label(path)));
    }
}

/// `minItems`, `maxItems` and `items`.
fn check_array(schema: &Value, items: &[Value], path: &str, problems: &mut Vec<String>) {
    let count = u64::try_from(items.len()).unwrap_or(u64::MAX);
    if let Some(min) = schema.get("minItems").and_then(Value::as_u64)
        && count < min
    {
        problems.push(format!("{} needs at least {min} items", label(path)));
    }
    if let Some(max) = schema.get("maxItems").and_then(Value::as_u64)
        && count > max
    {
        problems.push(format!("{} allows at most {max} items", label(path)));
    }
    if let Some(item_schema) = schema.get("items") {
        for (index, item) in items.iter().enumerate() {
            check(item_schema, item, &format!("{path}[{index}]"), problems);
        }
    }
}

/// `required`, `properties` and `additionalProperties: false`.
fn check_object(
    schema: &Value,
    fields: &Map<String, Value>,
    path: &str,
    problems: &mut Vec<String>,
) {
    let required: Vec<&str> = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|names| names.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    for name in &required {
        if fields.get(*name).is_none_or(Value::is_null) {
            problems.push(format!("{} is required", label(&child(path, name))));
        }
    }
    let properties = schema.get("properties").and_then(Value::as_object);
    let closed = schema.get("additionalProperties").and_then(Value::as_bool) == Some(false);
    for (name, value) in fields {
        let child_path = child(path, name);
        match properties.and_then(|known| known.get(name)) {
            Some(_) if value.is_null() && !required.contains(&name.as_str()) => {}
            Some(property) => check(property, value, &child_path, problems),
            None if closed => {
                let allowed: Vec<&str> = properties
                    .map(|known| known.keys().map(String::as_str).collect())
                    .unwrap_or_default();
                problems.push(format!(
                    "unknown argument {}; allowed: {}",
                    label(&child_path),
                    allowed.join(", ")
                ));
            }
            None => {}
        }
    }
}

/// Whether `value` has the JSON Schema `type` named `expected`.
fn type_matches(expected: &str, value: &Value) -> bool {
    match expected {
        "string" => value.is_string(),
        "integer" => value.is_i64() || value.is_u64(),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "array" => value.is_array(),
        "object" => value.is_object(),
        "null" => value.is_null(),
        _ => false,
    }
}

/// A schema type name with its indefinite article, for messages.
fn with_article(expected: &str) -> String {
    let article = if expected.starts_with(['a', 'e', 'i', 'o', 'u']) {
        "an"
    } else {
        "a"
    };
    format!("{article} {expected}")
}

/// The JSON kind of `value`, for messages.
fn kind_of(value: &Value) -> &'static str {
    if value.is_null() {
        "null"
    } else if value.is_boolean() {
        "a boolean"
    } else if value.is_number() {
        "a number"
    } else if value.is_string() {
        "a string"
    } else if value.is_array() {
        "an array"
    } else {
        "an object"
    }
}

/// Path of a property below `parent`.
fn child(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_owned()
    } else {
        format!("{parent}.{name}")
    }
}

/// How a path appears in a message.
fn label(path: &str) -> String {
    if path.is_empty() {
        "the arguments".to_owned()
    } else {
        format!("`{path}`")
    }
}
