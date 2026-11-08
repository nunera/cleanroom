//! A JSON Schema subset validator for tool-call arguments.
//!
//! The schemas the models see are the contract, so arguments are checked against exactly those
//! schemas before the runner acts. Supported keywords: `type`, `enum`, `properties`, `required`,
//! `additionalProperties: false`, `items`, `minItems`, `maxItems`, `minLength`, `maxLength`,
//! `minimum`, `maximum` and `pattern`. A `null` for an optional property counts as absent,
//! because models often send `null` for parameters they mean to leave out.

use regex::Regex;
use serde_json::{Map, Value};

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
