//! Export an incident as NeMo Gym training data: one pivot row per model call in the
//! `single_step_tool_use_with_argument_comparison` format (`responses_create_params` +
//! `expected_action`), only for calls whose every step the OS called trainable (guardrails on,
//! not denied by the grant, not flagged by the safety model).
//!
//! A call's exact request and response bytes come from the record/replay cache, so the incident
//! must have run with `CLEANROOM_LLM_CACHE=record`. The training tags name each step's request by
//! the same `sha256:` the cache keys on, and carry the cleanroomd receipts of its commands.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde_json::{Map, Value, json};

/// What an export wrote and skipped.
#[derive(Debug, Default)]
pub(crate) struct Summary {
    /// Pivot rows written.
    pub(crate) rows: usize,
    /// Model calls skipped, by reason.
    pub(crate) skipped: BTreeMap<&'static str, usize>,
    /// Rows by `expected_action` type.
    pub(crate) actions: BTreeMap<&'static str, usize>,
}

/// One model call, from its steps' training tags.
#[derive(Debug, Default)]
struct Call {
    /// Role, step, model and incident of its first step.
    first: Option<Value>,
    /// Every step trainable.
    trainable: bool,
    /// Receipts of the commands its tool calls ran.
    receipts: Vec<u64>,
}

/// Export `incident`'s trainable model calls from `dataset` (training tags) and `cache` (recorded
/// requests and responses) to `out` as pivot JSONL.
///
/// # Errors
/// Fails if the tags cannot be read or the output cannot be written.
pub(crate) fn export(dataset: &Path, cache: &Path, incident: &str, out: &Path) -> Result<Summary> {
    let tags_path = dataset.join(format!("{}.jsonl", crate::dataset::file_stem(incident)));
    let tags = fs::read_to_string(&tags_path)
        .with_context(|| format!("cannot read {}", tags_path.display()))?;
    let mut summary = Summary::default();
    let mut calls: BTreeMap<String, Call> = BTreeMap::new();
    let mut order = Vec::new();
    for line in tags.lines().filter(|line| !line.trim().is_empty()) {
        let tag: Value = serde_json::from_str(line).context("a training tag is not JSON")?;
        let Some(request) = tag["request"]
            .as_str()
            .and_then(|r| r.strip_prefix("sha256:"))
        else {
            *summary.skipped.entry("untagged_request").or_default() += 1;
            continue;
        };
        let call = calls.entry(request.to_owned()).or_insert_with(|| {
            order.push(request.to_owned());
            Call {
                trainable: true,
                ..Call::default()
            }
        });
        call.trainable &= tag["trainable"].as_bool() == Some(true);
        if let Some(receipt) = tag["receipt"].as_u64() {
            call.receipts.push(receipt);
        }
        if call.first.is_none() {
            call.first = Some(tag);
        }
    }
    let mut written = Vec::new();
    for key in order {
        let call = &calls[&key];
        if !call.trainable {
            *summary.skipped.entry("untrainable").or_default() += 1;
            continue;
        }
        let (Ok(request), Ok(response)) = (
            read_json(&cache.join(format!("{key}.request.json"))),
            read_json(&cache.join(format!("{key}.response.json"))),
        ) else {
            *summary.skipped.entry("not_recorded").or_default() += 1;
            continue;
        };
        match pivot(&key, call, &request, &response) {
            Ok((row, action)) => {
                *summary.actions.entry(action).or_default() += 1;
                written.push(row);
            }
            Err(reason) => *summary.skipped.entry(reason).or_default() += 1,
        }
    }
    let mut file =
        fs::File::create(out).with_context(|| format!("cannot create {}", out.display()))?;
    for row in &written {
        let mut line = serde_json::to_vec(row).context("cannot encode a pivot row")?;
        line.push(b'\n');
        file.write_all(&line)
            .with_context(|| format!("cannot write {}", out.display()))?;
    }
    summary.rows = written.len();
    Ok(summary)
}

/// A JSON file.
fn read_json(path: &PathBuf) -> Result<Value> {
    let bytes = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("{} is not JSON", path.display()))
}

/// The pivot row for one recorded call, and its action type; or why it cannot be one.
fn pivot(
    key: &str,
    call: &Call,
    request: &Value,
    response: &Value,
) -> Result<(Value, &'static str), &'static str> {
    let messages = request["messages"].as_array().ok_or("no_messages")?;
    let input: Vec<Value> = messages
        .iter()
        .enumerate()
        .flat_map(|(index, message)| input_items(index, message))
        .collect();
    if input.is_empty() {
        return Err("no_messages");
    }
    let tools: Vec<Value> = request["tools"]
        .as_array()
        .map(|tools| tools.iter().filter_map(responses_tool).collect())
        .unwrap_or_default();
    let message = &response["choices"][0]["message"];
    let calls: Vec<Value> = message["tool_calls"]
        .as_array()
        .map(|calls| calls.iter().map(expected_call).collect::<Option<Vec<_>>>())
        .unwrap_or(Some(Vec::new()))
        .ok_or("malformed_arguments")?;
    let offered: Vec<&str> = tools
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    if calls.iter().any(|call| {
        !call["name"]
            .as_str()
            .is_some_and(|name| offered.contains(&name))
    }) {
        return Err("tool_not_offered");
    }
    let (expected, action) = match calls.len() {
        0 => {
            let text = message["content"]
                .as_str()
                .filter(|text| !text.trim().is_empty());
            (
                json!({"type": "message", "content": text.ok_or("no_action")?}),
                "message",
            )
        }
        1 => (calls[0].clone(), "function_call"),
        _ => (
            json!({"type": "function_call_batch", "calls": calls}),
            "function_call_batch",
        ),
    };
    let first = call.first.as_ref().ok_or("no_action")?;
    let row = json!({
        "responses_create_params": {
            "input": input,
            "tools": tools,
            "parallel_tool_calls": true,
            "tool_choice": "auto",
        },
        "expected_action": expected,
        "reference_output": {
            "reasoning": message["reasoning_content"],
            "content": message["content"],
            "tool_calls": message["tool_calls"],
        },
        "cleanroom": {
            "incident": first["incident"],
            "role": first["role"],
            "step": first["step"],
            "model": first["model"],
            "request": format!("sha256:{key}"),
            "exec_receipts": call.receipts,
            "selection": "every step trainable: guardrails on, not denied by the stratum grant, not flagged by the safety model",
        },
    });
    Ok((row, action))
}

/// Responses API input items for one chat message (index `index` in the prefix).
fn input_items(index: usize, message: &Value) -> Vec<Value> {
    let text = message["content"].as_str().filter(|text| !text.is_empty());
    match message["role"].as_str() {
        Some(role @ ("system" | "user")) => text
            .map(|text| json!({"type": "message", "role": role, "content": text}))
            .into_iter()
            .collect(),
        Some("assistant") => {
            let mut items: Vec<Value> = text
                .map(|text| {
                    json!({"type": "message", "role": "assistant", "id": format!("msg_{index}"), "status": "completed",
                        "content": [{"type": "output_text", "text": text, "annotations": []}]})
                })
                .into_iter()
                .collect();
            for call in message["tool_calls"].as_array().into_iter().flatten() {
                items.push(json!({
                    "type": "function_call",
                    "call_id": call["id"],
                    "name": call["function"]["name"],
                    "arguments": call["function"]["arguments"],
                    "status": "completed",
                }));
            }
            items
        }
        Some("tool") => vec![json!({
            "type": "function_call_output",
            "call_id": message["tool_call_id"],
            "output": message["content"].as_str().unwrap_or_default(),
        })],
        _ => Vec::new(),
    }
}

/// A chat-completions tool as a Responses API function tool.
fn responses_tool(tool: &Value) -> Option<Value> {
    let function = tool.get("function")?;
    let mut out = Map::new();
    out.insert("type".to_owned(), json!("function"));
    out.insert("name".to_owned(), function.get("name")?.clone());
    if let Some(description) = function.get("description") {
        out.insert("description".to_owned(), description.clone());
    }
    out.insert(
        "parameters".to_owned(),
        function
            .get("parameters")
            .cloned()
            .unwrap_or_else(|| json!({"type": "object"})),
    );
    out.insert("strict".to_owned(), json!(false));
    Some(Value::Object(out))
}

/// A model's tool call as an `expected_action` function call; `None` if its arguments are not
/// JSON.
fn expected_call(call: &Value) -> Option<Value> {
    let function = &call["function"];
    let name = function["name"].as_str()?;
    let arguments = match &function["arguments"] {
        Value::String(text) => text.clone(),
        Value::Null => "{}".to_owned(),
        other => other.to_string(),
    };
    serde_json::from_str::<Value>(&arguments).ok()?;
    Some(json!({"type": "function_call", "name": name, "arguments": arguments}))
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::json;

    use super::*;

    fn scratch() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        let dir =
            std::env::temp_dir().join(format!("cleanroom-gym-{}-{nanos}", std::process::id()));
        fs::create_dir_all(dir.join("dataset")).expect("dataset dir");
        fs::create_dir_all(dir.join("cache")).expect("cache dir");
        dir
    }

    /// Record one model call in the cache the way record mode does; returns its request key.
    fn record(cache: &Path, request: &Value, response: &Value) -> String {
        let bytes = serde_json::to_vec(request).expect("request");
        let key = crate::cache::key(&bytes);
        fs::write(cache.join(format!("{key}.request.json")), &bytes).expect("request file");
        fs::write(
            cache.join(format!("{key}.response.json")),
            serde_json::to_vec(response).expect("response"),
        )
        .expect("response file");
        key
    }

    fn tag(request: &str, step: u32, receipt: u64, trainable: bool) -> Value {
        json!({
            "incident": "INC-1", "at": "2026-11-08T12:00:00Z", "role": "hunter", "step": step,
            "model": "nvidia/nemotron-3.5-lightning-30b-a3b", "route": "hosted", "tool": "read_file",
            "subject": "/evidence/logs/auth.log", "shape": "needle_lookup",
            "provenance": "attacker_writable", "output_chars": 900, "receipt": receipt,
            "denied": false, "flagged": !trainable, "guardrails": true, "trainable": trainable,
            "request": format!("sha256:{request}"),
        })
    }

    /// Only model calls whose every step the OS called trainable become NeMo Gym pivot rows, in
    /// the `single_step_tool_use_with_argument_comparison` shape: the request prefix as Responses
    /// input items, the offered tools, the call the model made as `expected_action`, and where it
    /// came from (incident, role, receipts).
    #[test]
    fn trainable_recorded_calls_become_pivot_rows() {
        let dir = scratch();
        let (dataset, cache) = (dir.join("dataset"), dir.join("cache"));
        let tools = json!([{"type": "function", "function": {
            "name": "read_file", "description": "Read a file.",
            "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}}}]);
        let request = json!({
            "model": "nvidia/nemotron-3.5-lightning-30b-a3b",
            "messages": [
                {"role": "system", "content": "You are Hunter."},
                {"role": "user", "content": "Ransomware hit acme-fs."},
                {"role": "assistant", "content": null, "tool_calls": [{"id": "call_0", "type": "function",
                    "function": {"name": "read_file", "arguments": "{\"path\":\"/evidence/acme-fs/README_RESTORE_FILES.txt\"}"}}]},
                {"role": "tool", "tool_call_id": "call_0", "content": "YOUR FILES ARE LOCKED"},
            ],
            "tools": tools, "tool_choice": "auto", "max_tokens": 2048, "reasoning_budget": 1024,
        });
        let response = json!({"choices": [{"message": {
            "content": null, "reasoning_content": "Check the auth log next.",
            "tool_calls": [{"id": "call_1", "type": "function",
                "function": {"name": "read_file", "arguments": "{\"path\":\"/evidence/logs/auth.log\"}"}}]}}]});
        let clean = record(&cache, &request, &response);
        let mut flagged_request = request.clone();
        flagged_request["messages"][1]["content"] = json!("another step");
        let flagged = record(&cache, &flagged_request, &response);
        let lines = [
            tag(&clean, 2, 14, true),
            tag(&flagged, 3, 15, false),
            tag(
                "0000000000000000000000000000000000000000000000000000000000000000",
                4,
                16,
                true,
            ),
        ];
        let text: String = lines.iter().map(|line| format!("{line}\n")).collect();
        fs::write(dataset.join("INC-1.jsonl"), text).expect("tags");
        let out = dir.join("pivots.jsonl");

        let summary = export(&dataset, &cache, "INC-1", &out).expect("export");

        assert_eq!(summary.rows, 1);
        assert_eq!(summary.skipped.get("untrainable"), Some(&1));
        assert_eq!(summary.skipped.get("not_recorded"), Some(&1));
        let row: Value =
            serde_json::from_str(fs::read_to_string(&out).expect("out").trim()).expect("row");
        let params = &row["responses_create_params"];
        let kinds: Vec<&str> = params["input"]
            .as_array()
            .expect("input")
            .iter()
            .map(|item| item["type"].as_str().expect("type"))
            .collect();
        assert_eq!(
            kinds,
            [
                "message",
                "message",
                "function_call",
                "function_call_output"
            ]
        );
        assert_eq!(params["input"][2]["call_id"], "call_0");
        assert_eq!(params["input"][3]["output"], "YOUR FILES ARE LOCKED");
        assert_eq!(params["tools"][0]["name"], "read_file");
        assert_eq!(params["tool_choice"], "auto");
        assert_eq!(params["parallel_tool_calls"], true);
        assert_eq!(
            row["expected_action"],
            json!({"type": "function_call", "name": "read_file", "arguments": "{\"path\":\"/evidence/logs/auth.log\"}"})
        );
        assert_eq!(row["cleanroom"]["incident"], "INC-1");
        assert_eq!(row["cleanroom"]["exec_receipts"], json!([14]));
        assert_eq!(
            row["reference_output"]["reasoning"],
            "Check the auth log next."
        );
        fs::remove_dir_all(&dir).expect("clean up");
    }
}
