//! Model router: `OpenAI`-compatible `/chat/completions` over HTTPS (rustls with ring), to the
//! hosted Nemotron API or a local endpoint, with retries, the record/replay store, and the
//! safety model.
//!
//! Tool-call replies often carry `content: null` and a `reasoning_content` chain of thought;
//! both are normal. Every call asks for at least 1024 tokens because the reasoning models spend
//! small budgets on reasoning and return nothing.

use std::error::Error as StdError;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use bytes::Bytes;
use cleanroom_proto::{ModelRoute, Role};
use reqwest::StatusCode;
use reqwest::header::{CONTENT_TYPE, RETRY_AFTER};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::cache::{self, Hit, Store, Stream};
use crate::config::{CacheMode, Endpoint, LocalRoute, Models, Settings};
use crate::roles;
use crate::safety::{self, Verdict};
use crate::text::preview;
use crate::tools::ToolSpec;

/// Token budget for an agent step.
const AGENT_MAX_TOKENS: u32 = 2048;
/// Token budget for a safety verdict (the verdict itself is about 40 tokens).
const SAFETY_MAX_TOKENS: u32 = 1024;
/// Retries after the first attempt on 408, 429, 5xx, timeouts and transport errors.
const MAX_RETRIES: u32 = 4;
/// Whole-request timeout per attempt.
const REQUEST_TIMEOUT: Duration = Duration::from_mins(2);
/// TCP and TLS connect timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest wait between attempts, including a server's `Retry-After`.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// A conversation message, serialized in the chat-completions shape.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "role", rename_all = "snake_case")]
pub(crate) enum Message {
    /// System prompt.
    System {
        /// Prompt text.
        content: String,
    },
    /// Task from the runner.
    User {
        /// Task text.
        content: String,
    },
    /// The model's earlier turn.
    Assistant {
        /// Text, often `null` when the turn only calls tools.
        content: Option<String>,
        /// Calls the model made, with arguments normalized to valid JSON.
        #[serde(skip_serializing_if = "Vec::is_empty")]
        tool_calls: Vec<ToolCall>,
    },
    /// A tool result.
    Tool {
        /// The call this answers.
        tool_call_id: String,
        /// Result text.
        content: String,
    },
}

/// A tool call as kept in the conversation history.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ToolCall {
    /// Call id from the model.
    id: String,
    /// Always `function`.
    #[serde(rename = "type")]
    kind: &'static str,
    /// Name and arguments.
    function: FunctionCall,
}

impl ToolCall {
    /// A function call entry.
    pub(crate) const fn new(id: String, name: String, arguments: String) -> Self {
        Self {
            id,
            kind: "function",
            function: FunctionCall { name, arguments },
        }
    }
}

/// The `function` member of a [`ToolCall`].
#[derive(Debug, Clone, Serialize)]
struct FunctionCall {
    /// Tool name.
    name: String,
    /// JSON-encoded arguments.
    arguments: String,
}

/// A tool call the model asked for, before any checking.
#[derive(Debug, Clone)]
pub(crate) struct RequestedCall {
    /// Call id (synthesized when the server omits it).
    pub(crate) id: String,
    /// Tool name as the model wrote it.
    pub(crate) name: String,
    /// Raw arguments text, possibly invalid JSON.
    pub(crate) arguments: String,
}

/// Where a reply came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Origin {
    /// A live model call.
    Live,
    /// The replay store.
    Replayed(Hit),
}

/// A model reply.
#[derive(Debug)]
pub(crate) struct Reply {
    /// Text, if any.
    pub(crate) content: Option<String>,
    /// Requested tool calls, in order.
    pub(crate) tool_calls: Vec<RequestedCall>,
    /// The model that answered.
    pub(crate) model: String,
    /// Live or replayed.
    pub(crate) origin: Origin,
}

/// Why a model is called; part of the replay stream name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Purpose {
    /// An agent step.
    Agent,
    /// A safety verdict.
    Safety,
}

impl Purpose {
    /// Stream suffix.
    const fn label(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Safety => "safety",
        }
    }
}

/// The request body.
#[derive(Serialize)]
struct Body<'a> {
    /// Model id.
    model: &'a str,
    /// Conversation so far.
    messages: &'a [Message],
    /// Offered tools.
    #[serde(skip_serializing_if = "<[ToolSpec]>::is_empty")]
    tools: &'a [ToolSpec],
    /// `auto` whenever tools are offered.
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_choice: Option<&'static str>,
    /// Token budget.
    max_tokens: u32,
}

/// Serialize a chat-completions request. The bytes are both what is sent and what the cache keys on.
///
/// # Errors
/// Fails only if a message cannot be serialized.
pub(crate) fn request_body(
    model: &str,
    messages: &[Message],
    tools: &[ToolSpec],
    max_tokens: u32,
) -> serde_json::Result<Vec<u8>> {
    serde_json::to_vec(&Body {
        model,
        messages,
        tools,
        tool_choice: (!tools.is_empty()).then_some("auto"),
        max_tokens,
    })
}

/// The response subset the runner reads.
#[derive(Deserialize)]
struct ChatResponse {
    /// Completions; the first one is used.
    #[serde(default)]
    choices: Vec<Choice>,
}

/// One completion.
#[derive(Deserialize)]
struct Choice {
    /// The assistant message.
    message: ResponseMessage,
    /// `stop`, `tool_calls`, `length`...
    #[serde(default)]
    finish_reason: Option<String>,
}

/// The assistant message of a completion.
#[derive(Deserialize)]
struct ResponseMessage {
    /// Text; `null` on most tool-call turns.
    #[serde(default)]
    content: Option<String>,
    /// Chain of thought from reasoning models; logged by size only.
    #[serde(default)]
    reasoning_content: Option<String>,
    /// Requested tool calls; `null` or `[]` when none.
    #[serde(default)]
    tool_calls: Option<Vec<WireCall>>,
}

/// A tool call on the wire.
#[derive(Deserialize)]
struct WireCall {
    /// Call id.
    #[serde(default)]
    id: Option<String>,
    /// Name and arguments.
    function: WireFunction,
}

/// The `function` member of a wire tool call.
#[derive(Deserialize)]
struct WireFunction {
    /// Tool name.
    name: String,
    /// Usually a JSON string; some servers send an object.
    #[serde(default)]
    arguments: Value,
}

/// Live calls, live calls that are recorded, or replay.
#[derive(Debug)]
enum Cache {
    /// No store.
    Off,
    /// Store every live response.
    Record(Store),
    /// Answer from the store only.
    Replay(Store),
}

/// One outcome of an HTTP attempt.
enum Attempt {
    /// The response body.
    Done(Bytes),
    /// A retryable failure, with the server's requested wait if any.
    Retry {
        /// What went wrong.
        reason: String,
        /// `Retry-After`, if given.
        wait: Option<Duration>,
    },
}

/// Routes model calls to the hosted or local endpoint.
#[derive(Debug)]
pub(crate) struct Router {
    /// Shared HTTPS client.
    http: reqwest::Client,
    /// Hosted API.
    hosted: Endpoint,
    /// Optional local route.
    local: Option<LocalRoute>,
    /// Hosted models per role.
    models: Models,
    /// Record/replay store.
    cache: Cache,
}

impl Router {
    /// Build the HTTPS client and the cache.
    ///
    /// # Errors
    /// Fails if the TLS client cannot be built.
    pub(crate) fn new(settings: &Settings) -> Result<Self> {
        if rustls::crypto::ring::default_provider()
            .install_default()
            .is_err()
        {
            tracing::debug!("a rustls crypto provider was already installed");
        }
        let http = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .user_agent(concat!("cleanroom-agents/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("cannot build the HTTPS client")?;
        let cache = match settings.cache_mode {
            CacheMode::Off => Cache::Off,
            CacheMode::Record => Cache::Record(Store::new(settings.cache_dir.clone())),
            CacheMode::Replay => Cache::Replay(Store::new(settings.cache_dir.clone())),
        };
        Ok(Self {
            http,
            hosted: settings.hosted.clone(),
            local: settings.local.clone(),
            models: settings.models.clone(),
            cache,
        })
    }

    /// The cache mode, for status labels.
    pub(crate) const fn mode(&self) -> CacheMode {
        match self.cache {
            Cache::Off => CacheMode::Off,
            Cache::Record(_) => CacheMode::Record,
            Cache::Replay(_) => CacheMode::Replay,
        }
    }

    /// The cache directory, when recording or replaying.
    pub(crate) fn cache_dir(&self) -> Option<&std::path::Path> {
        match &self.cache {
            Cache::Off => None,
            Cache::Record(store) | Cache::Replay(store) => Some(store.dir()),
        }
    }

    /// The local agent model, when a local endpoint is configured.
    pub(crate) fn local_model(&self) -> Option<&str> {
        self.local.as_ref().map(|local| local.model.as_str())
    }

    /// The hosted agent model for `role`.
    pub(crate) fn hosted_model(&self, role: Role) -> &str {
        self.models.for_role(role)
    }

    /// The hosted endpoint's base URL, for status lines.
    pub(crate) fn hosted_url(&self) -> &str {
        &self.hosted.base_url
    }

    /// A new investigation: replay positions start over.
    pub(crate) fn restart_streams(&self) {
        match &self.cache {
            Cache::Off => {}
            Cache::Record(store) | Cache::Replay(store) => store.restart(),
        }
    }

    /// One agent step for `role` on `route`.
    ///
    /// # Errors
    /// Fails if the endpoint keeps failing after retries, answers with a non-retryable error or
    /// malformed JSON, or (in replay mode) the store has no answer.
    pub(crate) async fn chat(
        &self,
        role: Role,
        route: ModelRoute,
        messages: &[Message],
        tools: &[ToolSpec],
    ) -> Result<Reply> {
        let model = self.model(role, Purpose::Agent, route);
        let body = request_body(model, messages, tools, AGENT_MAX_TOKENS)
            .context("cannot encode the model request")?;
        self.complete(role, Purpose::Agent, route, Bytes::from(body))
            .await
    }

    /// Score `text` with the safety model on `route`. Returns the verdict and the model used.
    ///
    /// # Errors
    /// Fails like [`Router::chat`], or when the reply holds no recognizable verdict.
    pub(crate) async fn screen(
        &self,
        role: Role,
        route: ModelRoute,
        text: &str,
    ) -> Result<(Verdict, String)> {
        let model = self.model(role, Purpose::Safety, route);
        let messages = [Message::User {
            content: text.to_owned(),
        }];
        let body = request_body(model, &messages, &[], SAFETY_MAX_TOKENS)
            .context("cannot encode the safety request")?;
        let reply = self
            .complete(role, Purpose::Safety, route, Bytes::from(body))
            .await?;
        let content = reply.content.unwrap_or_default();
        let verdict = safety::parse_verdict(&content)
            .with_context(|| format!("safety model gave no verdict: {}", preview(&content, 120)))?;
        Ok((verdict, reply.model))
    }

    /// The model `purpose` uses for `role` on `route`.
    fn model(&self, role: Role, purpose: Purpose, route: ModelRoute) -> &str {
        match (route, &self.local, purpose) {
            (ModelRoute::Local, Some(local), Purpose::Agent) => &local.model,
            (ModelRoute::Local, Some(local), Purpose::Safety) => &local.safety_model,
            (ModelRoute::Local | ModelRoute::Hosted, _, Purpose::Agent) => {
                self.models.for_role(role)
            }
            (ModelRoute::Local | ModelRoute::Hosted, _, Purpose::Safety) => &self.models.safety,
        }
    }

    /// The endpoint for `route`.
    ///
    /// # Errors
    /// Fails for the local route when no local endpoint is configured.
    fn endpoint(&self, route: ModelRoute) -> Result<&Endpoint> {
        match route {
            ModelRoute::Hosted => Ok(&self.hosted),
            ModelRoute::Local => self
                .local
                .as_ref()
                .map(|local| &local.endpoint)
                .context("no local endpoint is configured (CLEANROOM_LOCAL_BASE_URL)"),
        }
    }

    /// Get a reply live, live-and-recorded, or from the replay store.
    ///
    /// # Errors
    /// See [`Router::chat`].
    async fn complete(
        &self,
        role: Role,
        purpose: Purpose,
        route: ModelRoute,
        body: Bytes,
    ) -> Result<Reply> {
        let stream = Stream {
            role: roles::name(role),
            purpose: purpose.label(),
        };
        let key = cache::key(&body);
        let (raw, origin) = match &self.cache {
            Cache::Replay(store) => {
                let replayed = store.replay(store.next_slot(stream), &key).await?;
                tokio::time::sleep(replayed.latency).await;
                (Bytes::from(replayed.body), Origin::Replayed(replayed.hit))
            }
            Cache::Record(store) => {
                let slot = store.next_slot(stream);
                let started = Instant::now();
                let raw = self.post(self.endpoint(route)?, body.clone()).await?;
                let exchange = (body.as_ref(), raw.as_ref());
                if let Err(error) = store.record(slot, &key, exchange, started.elapsed()).await {
                    tracing::warn!("cannot record {slot}: {error:#}");
                }
                (raw, Origin::Live)
            }
            Cache::Off => (self.post(self.endpoint(route)?, body).await?, Origin::Live),
        };
        parse_reply(&raw, self.model(role, purpose, route), origin)
    }

    /// POST with retries on 408, 429, 5xx, timeouts and transport errors.
    ///
    /// # Errors
    /// Fails on a non-retryable status, or when every attempt failed.
    async fn post(&self, endpoint: &Endpoint, body: Bytes) -> Result<Bytes> {
        let url = format!("{}/chat/completions", endpoint.base_url);
        let mut retries = 0_u32;
        loop {
            let (reason, wait) = match self.attempt(&url, endpoint, body.clone()).await? {
                Attempt::Done(bytes) => return Ok(bytes),
                Attempt::Retry { reason, wait } => (reason, wait),
            };
            if retries == MAX_RETRIES {
                bail!("model endpoint still failing after {MAX_RETRIES} retries: {reason}");
            }
            retries += 1;
            let wait = wait.unwrap_or_else(|| backoff(retries)).min(MAX_BACKOFF);
            tracing::warn!(
                retry = retries,
                wait_ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX),
                "model call failed: {reason}"
            );
            tokio::time::sleep(wait).await;
        }
    }

    /// One HTTP attempt.
    ///
    /// # Errors
    /// Fails on a request that cannot be built or a non-retryable HTTP status.
    async fn attempt(&self, url: &str, endpoint: &Endpoint, body: Bytes) -> Result<Attempt> {
        let mut request = self
            .http
            .post(url)
            .header(CONTENT_TYPE, "application/json")
            .body(body);
        if let Some(key) = &endpoint.api_key {
            request = request.bearer_auth(key.expose());
        }
        let response = match request.send().await {
            Ok(response) => response,
            Err(error) if error.is_builder() => {
                return Err(error).context("cannot build the model request");
            }
            Err(error) => {
                return Ok(Attempt::Retry {
                    reason: chain(&error),
                    wait: None,
                });
            }
        };
        let status = response.status();
        if status.is_success() {
            return Ok(match response.bytes().await {
                Ok(bytes) => Attempt::Done(bytes),
                Err(error) => Attempt::Retry {
                    reason: format!("reading the reply failed: {}", chain(&error)),
                    wait: None,
                },
            });
        }
        let wait = retry_after(response.headers());
        let detail = response.text().await.unwrap_or_default();
        if status == StatusCode::TOO_MANY_REQUESTS
            || status == StatusCode::REQUEST_TIMEOUT
            || status.is_server_error()
        {
            Ok(Attempt::Retry {
                reason: format!("HTTP {status}"),
                wait,
            })
        } else {
            bail!(
                "model endpoint returned HTTP {status}: {}",
                preview(&detail, 300)
            )
        }
    }
}

/// Parse a chat-completions response.
///
/// # Errors
/// Fails on malformed JSON or a reply without choices.
fn parse_reply(raw: &[u8], model: &str, origin: Origin) -> Result<Reply> {
    let response: ChatResponse =
        serde_json::from_slice(raw).context("model endpoint returned malformed JSON")?;
    let choice = response
        .choices
        .into_iter()
        .next()
        .context("model reply has no choices")?;
    let message = choice.message;
    if let Some(reasoning) = &message.reasoning_content {
        tracing::debug!(
            model,
            chars = reasoning.len(),
            "model returned reasoning_content"
        );
    }
    if choice.finish_reason.as_deref() == Some("length") {
        tracing::warn!(
            model,
            "model hit max_tokens; tool arguments may be truncated"
        );
    }
    let tool_calls = message
        .tool_calls
        .unwrap_or_default()
        .into_iter()
        .enumerate()
        .map(|(index, call)| RequestedCall {
            id: call
                .id
                .filter(|id| !id.is_empty())
                .unwrap_or_else(|| format!("call_{index}")),
            name: call.function.name,
            arguments: arguments_text(call.function.arguments),
        })
        .collect();
    Ok(Reply {
        content: message.content.filter(|text| !text.trim().is_empty()),
        tool_calls,
        model: model.to_owned(),
        origin,
    })
}

/// Tool arguments as text, whether the server sent a JSON string or an object.
fn arguments_text(arguments: Value) -> String {
    if let Value::String(text) = arguments {
        text
    } else if arguments.is_null() {
        String::new()
    } else {
        arguments.to_string()
    }
}

/// Exponential backoff: 1 s, 2 s, 4 s, 8 s...
const fn backoff(retry: u32) -> Duration {
    Duration::from_millis(500_u64.saturating_mul(2_u64.saturating_pow(retry)))
}

/// A `Retry-After` header in seconds.
fn retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    let seconds = headers
        .get(RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()?;
    Some(Duration::from_secs(seconds))
}

/// An error with its sources, `outer: inner: innermost`.
fn chain(error: &dyn StdError) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}
