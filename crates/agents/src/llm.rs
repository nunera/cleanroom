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
use cleanroom_proto::{LlmMode, ModelRoute, Role};
use reqwest::StatusCode;
use reqwest::header::{CONTENT_TYPE, RETRY_AFTER};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::budget::Budgets;
use crate::cache::{self, Hit, Store, Stream};
use crate::config::{Endpoint, LocalRoute, Models, Settings};
use crate::egress;
use crate::roles;
use crate::safety::{self, Verdict};
use crate::text::preview;
use crate::tools::ToolSpec;

/// Token budget for an agent step.
pub(crate) const AGENT_MAX_TOKENS: u32 = 2048;
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
    /// `sha256:` of the request body (the record/replay cache key).
    pub(crate) request: String,
}

/// Why a model is called; part of the replay stream name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Purpose {
    /// An agent step.
    Agent,
    /// A conversational turn: the Lead talking with the commander, or a specialist answering a
    /// question.
    Chat,
    /// A safety verdict.
    Safety,
}

impl Purpose {
    /// Stream suffix.
    const fn label(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Chat => "chat",
            Self::Safety => "safety",
        }
    }
}

/// Chat-template switches the Nemotron endpoints accept as `chat_template_kwargs`.
#[derive(Debug, Clone, Copy, Serialize)]
struct TemplateKwargs {
    /// Whether the model writes a reasoning trace before it answers.
    enable_thinking: bool,
}

/// A specialist's answer to a question skips the reasoning trace.
///
/// The answer summarizes work already done: hosted Lightning then answers in about a second, and
/// the token budget goes to the answer (in a live run a specialist spent all of its tokens
/// reasoning and answered nothing). The Lead keeps its reasoning: without it, it answered "ask
/// Hunter" from the situation instead of asking Hunter.
const NO_THINKING: TemplateKwargs = TemplateKwargs {
    enable_thinking: false,
};

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
    /// Chat-template switches. Only conversational turns set them, so agent steps and safety
    /// requests, and the cache keys of their recordings, stay as they were.
    #[serde(skip_serializing_if = "Option::is_none")]
    chat_template_kwargs: Option<TemplateKwargs>,
    /// Reasoning tokens the model may spend before answering, from `policy/reasoning.json`.
    #[serde(skip_serializing_if = "Option::is_none")]
    reasoning_budget: Option<u32>,
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
    body(model, messages, tools, max_tokens, None, None)
}

/// Serialize a request with optional chat-template switches.
///
/// # Errors
/// Fails only if a message cannot be serialized.
fn body(
    model: &str,
    messages: &[Message],
    tools: &[ToolSpec],
    max_tokens: u32,
    chat_template_kwargs: Option<TemplateKwargs>,
    reasoning_budget: Option<u32>,
) -> serde_json::Result<Vec<u8>> {
    serde_json::to_vec(&Body {
        model,
        messages,
        tools,
        tool_choice: (!tools.is_empty()).then_some("auto"),
        max_tokens,
        chat_template_kwargs,
        reasoning_budget,
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

/// One model call as reported to cleanroomd: which model at which endpoint answered whom, with
/// digests of the exact bytes sent and received.
#[derive(Debug, Clone)]
pub(crate) struct CallRecord {
    /// The role the call was for.
    pub(crate) role: Role,
    /// `agent`, `chat` or `safety`.
    pub(crate) purpose: &'static str,
    /// The model asked.
    pub(crate) model: String,
    /// The endpoint's base URL (`none` when replaying a route that has no endpoint).
    pub(crate) endpoint: String,
    /// `sha256:` of the request body.
    pub(crate) request: String,
    /// `sha256:` of the response body.
    pub(crate) response: String,
    /// The answer came from the replay store, not a live model.
    pub(crate) replayed: bool,
    /// Time from request to response, including any recorded pace in replay.
    pub(crate) latency_ms: u64,
    /// The model's reasoning trace (`reasoning_content`), clipped to [`REASONING_LIMIT`] bytes.
    pub(crate) reasoning: Option<String>,
    /// Reasoning tokens the endpoint reported (`usage.completion_tokens_details`).
    pub(crate) reasoning_tokens: Option<u64>,
}

/// Reasoning trace bytes reported per call at most (cleanroomd stores up to 256 KiB).
const REASONING_LIMIT: usize = 200_000;

/// The response parts reasoning custody reads.
#[derive(Deserialize)]
struct Thought {
    /// Completions; the first one is used.
    #[serde(default)]
    choices: Vec<ThoughtChoice>,
    /// Token accounting.
    #[serde(default)]
    usage: Option<Usage>,
}

/// One completion's message.
#[derive(Deserialize)]
struct ThoughtChoice {
    /// The assistant message.
    message: ThoughtMessage,
}

/// The reasoning part of an assistant message.
#[derive(Deserialize)]
struct ThoughtMessage {
    /// Chain of thought.
    #[serde(default)]
    reasoning_content: Option<String>,
}

/// Token accounting.
#[derive(Deserialize)]
struct Usage {
    /// Per-kind completion tokens.
    #[serde(default)]
    completion_tokens_details: Option<TokenDetails>,
}

/// Completion tokens by kind.
#[derive(Deserialize)]
struct TokenDetails {
    /// Tokens spent reasoning.
    #[serde(default)]
    reasoning_tokens: Option<u64>,
}

/// The reasoning trace (clipped at a character boundary) and reasoning-token count in `raw`.
fn reasoning_of(raw: &[u8]) -> (Option<String>, Option<u64>) {
    let Ok(thought) = serde_json::from_slice::<Thought>(raw) else {
        return (None, None);
    };
    let tokens = thought
        .usage
        .and_then(|usage| usage.completion_tokens_details)
        .and_then(|details| details.reasoning_tokens);
    let trace = thought
        .choices
        .into_iter()
        .next()
        .and_then(|choice| choice.message.reasoning_content)
        .filter(|text| !text.trim().is_empty())
        .map(|mut text| {
            if text.len() > REASONING_LIMIT {
                let mut end = REASONING_LIMIT;
                while !text.is_char_boundary(end) {
                    end -= 1;
                }
                text.truncate(end);
            }
            text
        });
    (trace, tokens)
}

/// Routes model calls to the hosted or local endpoint.
#[derive(Debug)]
pub(crate) struct Router {
    /// Shared HTTPS client; `None` in replay mode, which never connects.
    http: Option<reqwest::Client>,
    /// Hosted API.
    hosted: Endpoint,
    /// Optional local route.
    local: Option<LocalRoute>,
    /// Hosted models per role.
    models: Models,
    /// Record/replay store.
    cache: Cache,
    /// What egress this router has, for the status line.
    egress: String,
    /// Where every call is reported, when someone listens.
    calls: Option<tokio::sync::mpsc::UnboundedSender<CallRecord>>,
    /// Reasoning budgets per role.
    budgets: Budgets,
}

impl Router {
    /// Check the endpoints against the egress policy, then build the HTTPS client and the
    /// cache. Replay builds no client at all.
    ///
    /// # Errors
    /// Fails if an endpoint is outside `policy/egress.json`, `policy/reasoning.json` is invalid,
    /// or the TLS client cannot be built.
    pub(crate) fn new(settings: &Settings) -> Result<Self> {
        let budgets = Budgets::shipped()?;
        if rustls::crypto::ring::default_provider()
            .install_default()
            .is_err()
        {
            tracing::debug!("a rustls crypto provider was already installed");
        }
        let (http, egress) = if settings.llm_mode == LlmMode::Replay {
            (
                None,
                "egress none (replay builds no network client)".to_owned(),
            )
        } else {
            let policy = egress::Policy::shipped()?;
            let mut allowed = Vec::new();
            for endpoint in std::iter::once(&settings.hosted)
                .chain(settings.local.as_ref().map(|local| &local.endpoint))
            {
                let why = policy
                    .check(&endpoint.base_url)
                    .map_err(anyhow::Error::msg)?;
                allowed.push(format!("{} ({why})", endpoint.base_url));
            }
            // Redirects and proxy variables could carry a request past the policy.
            let http = reqwest::Client::builder()
                .connect_timeout(CONNECT_TIMEOUT)
                .timeout(REQUEST_TIMEOUT)
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .user_agent(concat!("cleanroom-agents/", env!("CARGO_PKG_VERSION")))
                .build()
                .context("cannot build the HTTPS client")?;
            let egress = format!(
                "egress only {} per policy/egress.json",
                allowed.join(" and ")
            );
            (Some(http), egress)
        };
        let cache = match settings.llm_mode {
            LlmMode::Live => Cache::Off,
            LlmMode::Record => Cache::Record(Store::new(settings.cache_dir.clone())),
            LlmMode::Replay => Cache::Replay(Store::new(settings.cache_dir.clone())),
        };
        Ok(Self {
            http,
            hosted: settings.hosted.clone(),
            local: settings.local.clone(),
            models: settings.models.clone(),
            cache,
            egress,
            calls: None,
            budgets,
        })
    }

    /// Report every call to `calls`.
    pub(crate) fn with_call_log(
        mut self,
        calls: tokio::sync::mpsc::UnboundedSender<CallRecord>,
    ) -> Self {
        self.calls = Some(calls);
        self
    }

    /// The reasoning budgets, for the status line.
    pub(crate) const fn budgets(&self) -> Budgets {
        self.budgets
    }

    /// The request bytes for `role`'s `purpose` call on `route`: agent steps and the Lead's turns
    /// carry the role's reasoning budget; a specialist's answer turns thinking off; a safety
    /// verdict carries neither. The bytes are both what is sent and what the cache keys on.
    ///
    /// # Errors
    /// Fails only if a message cannot be serialized.
    fn request(
        &self,
        role: Role,
        purpose: Purpose,
        route: ModelRoute,
        messages: &[Message],
        tools: &[ToolSpec],
    ) -> Result<Vec<u8>> {
        let model = self.model(role, purpose, route);
        let budget = Some(self.budgets.for_role(role));
        let encoded = match purpose {
            Purpose::Agent => body(model, messages, tools, AGENT_MAX_TOKENS, None, budget),
            Purpose::Chat if role == Role::Lead => {
                body(model, messages, tools, AGENT_MAX_TOKENS, None, budget)
            }
            Purpose::Chat => body(
                model,
                messages,
                tools,
                AGENT_MAX_TOKENS,
                Some(NO_THINKING),
                None,
            ),
            Purpose::Safety => request_body(model, messages, &[], SAFETY_MAX_TOKENS),
        };
        encoded.context("cannot encode the model request")
    }

    /// Whether this router can open network connections at all.
    #[cfg(test)]
    pub(crate) const fn can_connect(&self) -> bool {
        self.http.is_some()
    }

    /// What egress this router has, for the status line.
    pub(crate) fn egress(&self) -> &str {
        &self.egress
    }

    /// Where responses come from, for counters and status labels.
    pub(crate) const fn mode(&self) -> LlmMode {
        match self.cache {
            Cache::Off => LlmMode::Live,
            Cache::Record(_) => LlmMode::Record,
            Cache::Replay(_) => LlmMode::Replay,
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
        let body = self.request(role, Purpose::Agent, route, messages, tools)?;
        self.complete(role, Purpose::Agent, route, Bytes::from(body))
            .await
    }

    /// One conversational turn for `role` on `route`: the Lead talking with the commander, or a
    /// specialist answering a question ([`NO_THINKING`]). It replays from its own stream, so
    /// questions never shift the positions of an investigation's recorded steps.
    ///
    /// # Errors
    /// Fails like [`Router::chat`].
    pub(crate) async fn talk(
        &self,
        role: Role,
        route: ModelRoute,
        messages: &[Message],
        tools: &[ToolSpec],
    ) -> Result<Reply> {
        let request = self.request(role, Purpose::Chat, route, messages, tools)?;
        self.complete(role, Purpose::Chat, route, Bytes::from(request))
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
        let messages = [Message::User {
            content: text.to_owned(),
        }];
        let body = self.request(role, Purpose::Safety, route, &messages, &[])?;
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
            (ModelRoute::Local, Some(local), Purpose::Agent | Purpose::Chat) => &local.model,
            (ModelRoute::Local, Some(local), Purpose::Safety) => &local.safety_model,
            (ModelRoute::Local | ModelRoute::Hosted, _, Purpose::Agent | Purpose::Chat) => {
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
        let started = Instant::now();
        let (raw, origin) = match &self.cache {
            Cache::Replay(store) => {
                let replayed = store.replay(store.next_slot(stream), &key).await?;
                tokio::time::sleep(replayed.latency).await;
                (Bytes::from(replayed.body), Origin::Replayed(replayed.hit))
            }
            Cache::Record(store) => {
                let slot = store.next_slot(stream);
                let raw = self.post(self.endpoint(route)?, body.clone()).await?;
                let exchange = (body.as_ref(), raw.as_ref());
                if let Err(error) = store.record(slot, &key, exchange, started.elapsed()).await {
                    tracing::warn!("cannot record {slot}: {error:#}");
                }
                (raw, Origin::Live)
            }
            Cache::Off => (self.post(self.endpoint(route)?, body).await?, Origin::Live),
        };
        if let Some(calls) = &self.calls {
            let (reasoning, reasoning_tokens) = reasoning_of(&raw);
            let record = CallRecord {
                role,
                purpose: purpose.label(),
                model: self.model(role, purpose, route).to_owned(),
                endpoint: self
                    .endpoint(route)
                    .map_or_else(|_| "none".to_owned(), |endpoint| endpoint.base_url.clone()),
                request: format!("sha256:{key}"),
                response: format!("sha256:{}", cache::key(&raw)),
                replayed: matches!(origin, Origin::Replayed(_)),
                latency_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                reasoning,
                reasoning_tokens,
            };
            if calls.send(record).is_err() {
                tracing::debug!("nobody listens for model-call records any more");
            }
        }
        parse_reply(&raw, self.model(role, purpose, route), origin, &key)
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
        let http = self
            .http
            .as_ref()
            .context("replay mode has no network client")?;
        let mut request = http
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
fn parse_reply(raw: &[u8], model: &str, origin: Origin, key: &str) -> Result<Reply> {
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
        request: format!("sha256:{key}"),
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn settings(hosted: &str, llm_mode: LlmMode) -> Settings {
        let model = |name: &str| name.to_owned();
        Settings {
            hosted: Endpoint {
                base_url: hosted.to_owned(),
                api_key: None,
            },
            local: None,
            models: Models {
                lead: model("nvidia/nemotron-3.5-lightning-30b-a3b"),
                hunter: model("nvidia/nemotron-3.5-lightning-30b-a3b"),
                forensics: model("nvidia/nemotron-3.5-lightning-30b-a3b"),
                scribe: model("nvidia/nemotron-3-ultra-550b-a55b"),
                containment: model("nvidia/nemotron-3.5-lightning-30b-a3b"),
                safety: model("nvidia/llama-3.1-nemotron-safety-guard-8b-v3"),
            },
            llm_mode,
            cache_dir: PathBuf::from("/nonexistent/cleanroom-llm-cache"),
            keys_dir: PathBuf::from("/nonexistent/cleanroom-keys"),
            dataset_dir: PathBuf::from("/nonexistent/cleanroom-dataset"),
            nixpkgs: "github:NixOS/nixpkgs/rev".to_owned(),
        }
    }

    /// `NVIDIA_BASE_URL` comes from the environment; pointing it elsewhere must not move the
    /// agents' evidence-bearing prompts off the declared endpoint.
    #[test]
    fn the_router_refuses_an_endpoint_the_egress_policy_denies() {
        let error = Router::new(&settings("https://evil.example/v1", LlmMode::Live))
            .expect_err("a live router to an undeclared endpoint is refused");
        assert!(format!("{error:#}").contains("egress policy"), "{error:#}");

        Router::new(&settings(
            "https://integrate.api.nvidia.com/v1",
            LlmMode::Live,
        ))
        .expect("the declared hosted endpoint is allowed");
        let offline = Router::new(&settings("https://evil.example/v1", LlmMode::Replay))
            .expect("replay makes no connections, so no endpoint is checked");
        assert!(!offline.can_connect(), "replay builds no network client");
    }

    /// Every model call is reported with the model, the endpoint and digests of the exact bytes
    /// sent and received, so cleanroomd can chain a receipt of which model said what. A replayed
    /// answer says so.
    #[tokio::test]
    async fn every_model_call_is_reported_with_digests_of_what_was_sent_and_received() {
        let dir = std::env::temp_dir().join(format!("cleanroom-llm-calls-{}", std::process::id()));
        drop(std::fs::remove_dir_all(&dir));
        let mut settings = settings("https://integrate.api.nvidia.com/v1", LlmMode::Replay);
        settings.cache_dir = dir.clone();
        let messages = [Message::User {
            content: "list /evidence".to_owned(),
        }];
        let model = settings.models.for_role(Role::Hunter).to_owned();
        let (calls, mut reported) = tokio::sync::mpsc::unbounded_channel();
        let router = Router::new(&settings).expect("router").with_call_log(calls);
        let body = router
            .request(
                Role::Hunter,
                Purpose::Agent,
                ModelRoute::Hosted,
                &messages,
                &[],
            )
            .expect("body");
        let response: &[u8] =
            br#"{"choices":[{"message":{"content":"done"},"finish_reason":"stop"}]}"#;
        let store = Store::new(dir.clone());
        let slot = store.next_slot(Stream {
            role: "hunter",
            purpose: "agent",
        });
        store
            .record(
                slot,
                &cache::key(&body),
                (&body, response),
                Duration::from_millis(5),
            )
            .await
            .expect("record");

        router
            .chat(Role::Hunter, ModelRoute::Hosted, &messages, &[])
            .await
            .expect("replayed");

        let call = reported.try_recv().expect("the call is reported");
        assert_eq!(call.role, Role::Hunter);
        assert_eq!(call.purpose, "agent");
        assert_eq!(call.model, model);
        assert_eq!(call.endpoint, "https://integrate.api.nvidia.com/v1");
        assert_eq!(call.request, format!("sha256:{}", cache::key(&body)));
        assert_eq!(call.response, format!("sha256:{}", cache::key(response)));
        assert!(call.replayed, "a replayed answer is not passed off as live");
        assert!(reported.try_recv().is_err(), "one call, one report");
        drop(std::fs::remove_dir_all(&dir));
    }

    /// Nemotron returns its chain of thought beside the answer; the report carries it and the
    /// reasoning-token count so cleanroomd can keep it under the call's receipt.
    #[tokio::test]
    async fn a_call_reports_the_reasoning_trace_and_its_token_count() {
        let dir =
            std::env::temp_dir().join(format!("cleanroom-llm-reasoning-{}", std::process::id()));
        drop(std::fs::remove_dir_all(&dir));
        let mut settings = settings("https://integrate.api.nvidia.com/v1", LlmMode::Replay);
        settings.cache_dir = dir.clone();
        let messages = [Message::User {
            content: "what happened on the share?".to_owned(),
        }];
        let model = settings.models.for_role(Role::Hunter).to_owned();
        let body = request_body(&model, &messages, &[], AGENT_MAX_TOKENS).expect("body");
        let response: &[u8] = br#"{"choices":[{"message":{"content":"ransomware","reasoning_content":"18 .locked files and a bitcoin note: encryption."},"finish_reason":"stop"}],"usage":{"completion_tokens":40,"completion_tokens_details":{"reasoning_tokens":31}}}"#;
        let store = Store::new(dir.clone());
        let slot = store.next_slot(Stream {
            role: "hunter",
            purpose: "agent",
        });
        store
            .record(
                slot,
                &cache::key(&body),
                (&body, response),
                Duration::from_millis(5),
            )
            .await
            .expect("record");
        let (calls, mut reported) = tokio::sync::mpsc::unbounded_channel();
        let router = Router::new(&settings).expect("router").with_call_log(calls);

        router
            .chat(Role::Hunter, ModelRoute::Hosted, &messages, &[])
            .await
            .expect("replayed");

        let call = reported.try_recv().expect("the call is reported");
        assert_eq!(
            call.reasoning.as_deref(),
            Some("18 .locked files and a bitcoin note: encryption.")
        );
        assert_eq!(call.reasoning_tokens, Some(31));
        drop(std::fs::remove_dir_all(&dir));
    }

    /// The OS sets how long each agent's Nemotron model may think: an agent step and the Lead's
    /// turn carry the role's `reasoning_budget` from policy/reasoning.json; a specialist's answer
    /// (thinking off) and a safety verdict carry none.
    #[test]
    fn requests_carry_the_roles_reasoning_budget() {
        let router = Router::new(&settings(
            "https://integrate.api.nvidia.com/v1",
            LlmMode::Replay,
        ))
        .expect("router");
        let budgets = crate::budget::Budgets::shipped().expect("policy");
        let messages = [Message::User {
            content: "list /evidence".to_owned(),
        }];
        let sent = |role, purpose| -> Value {
            let bytes = router
                .request(role, purpose, ModelRoute::Hosted, &messages, &[])
                .expect("request");
            serde_json::from_slice(&bytes).expect("json")
        };

        assert_eq!(
            sent(Role::Hunter, Purpose::Agent)["reasoning_budget"],
            budgets.for_role(Role::Hunter)
        );
        assert_eq!(
            sent(Role::Lead, Purpose::Chat)["reasoning_budget"],
            budgets.for_role(Role::Lead)
        );
        let answer = sent(Role::Hunter, Purpose::Chat);
        assert!(answer.get("reasoning_budget").is_none());
        assert_eq!(answer["chat_template_kwargs"]["enable_thinking"], false);
        assert!(
            sent(Role::Hunter, Purpose::Safety)
                .get("reasoning_budget")
                .is_none()
        );
    }
}
