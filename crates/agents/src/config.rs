//! Runner settings from the environment: model endpoints, models per role, the LLM cache, and
//! where keys live.
//!
//! The hosted API key and base URL come from `~/.config/cleanroom/nemotron.env`
//! (`NVIDIA_API_KEY`, `NVIDIA_BASE_URL`); variables set in the process environment win.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use cleanroom_proto::{LlmMode, Role};

/// Hosted API used when `NVIDIA_BASE_URL` is unset.
const DEFAULT_HOSTED_URL: &str = "https://integrate.api.nvidia.com/v1";
/// Tool-loop roles (Hunter, Forensics, Containment) and the Lead's chat: fast, 4/4 valid tool
/// calls in the smoke test.
const LIGHTNING: &str = "nvidia/nemotron-3.5-lightning-30b-a3b";
/// Scribe: the strongest writer our key reaches.
const ULTRA: &str = "nvidia/nemotron-3-ultra-550b-a55b";
/// Default model on the local endpoint.
const BOLT: &str = "nvidia/nemotron-3.5-bolt-e4b";
/// Safety layer 1.
const SAFETY_GUARD: &str = "nvidia/llama-3.1-nemotron-safety-guard-8b-v3";
/// nixpkgs pin for tool requests: the `rev` in this repository's `flake.lock`.
const DEFAULT_NIXPKGS: &str = "github:NixOS/nixpkgs/c56a87d8e41ce69bd2af57eb35dcc117a9dfca33";

/// A bearer token that never appears in logs or debug output.
#[derive(Clone)]
pub(crate) struct ApiKey(String);

impl ApiKey {
    /// The token, for the `Authorization` header only.
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApiKey(<redacted>)")
    }
}

/// An `OpenAI`-compatible `/chat/completions` server.
#[derive(Debug, Clone)]
pub(crate) struct Endpoint {
    /// Base URL without a trailing slash, for example `https://integrate.api.nvidia.com/v1`.
    pub(crate) base_url: String,
    /// Bearer token, if the server needs one.
    pub(crate) api_key: Option<ApiKey>,
}

/// The self-hosted route for sensitive evidence (Brev, vLLM, Ollama).
#[derive(Debug, Clone)]
pub(crate) struct LocalRoute {
    /// Where it listens.
    pub(crate) endpoint: Endpoint,
    /// Model for agent steps.
    pub(crate) model: String,
    /// Model for safety checks of sensitive output.
    pub(crate) safety_model: String,
}

/// Hosted model per role.
#[derive(Debug, Clone)]
pub(crate) struct Models {
    /// Lead.
    pub(crate) lead: String,
    /// Hunter.
    pub(crate) hunter: String,
    /// Forensics.
    pub(crate) forensics: String,
    /// Scribe.
    pub(crate) scribe: String,
    /// Containment.
    pub(crate) containment: String,
    /// Safety layer 1.
    pub(crate) safety: String,
}

impl Models {
    /// The hosted agent model for `role`.
    pub(crate) fn for_role(&self, role: Role) -> &str {
        match role {
            Role::Lead => &self.lead,
            Role::Hunter => &self.hunter,
            Role::Forensics => &self.forensics,
            Role::Scribe => &self.scribe,
            Role::Containment => &self.containment,
        }
    }
}

/// Everything the runner reads from the environment.
#[derive(Debug, Clone)]
pub(crate) struct Settings {
    /// Hosted API.
    pub(crate) hosted: Endpoint,
    /// Optional local route.
    pub(crate) local: Option<LocalRoute>,
    /// Hosted models.
    pub(crate) models: Models,
    /// `CLEANROOM_LLM_CACHE`: live (unset), record or replay.
    pub(crate) llm_mode: LlmMode,
    /// Cache directory.
    pub(crate) cache_dir: PathBuf,
    /// Signing keys directory.
    pub(crate) keys_dir: PathBuf,
    /// Training-ready tags, `<incident>.jsonl` per incident.
    pub(crate) dataset_dir: PathBuf,
    /// Pinned flake reference prefix for tool requests.
    pub(crate) nixpkgs: String,
}

impl Settings {
    /// Read the environment and `nemotron.env`.
    ///
    /// # Errors
    /// Fails if `HOME` is unset, the env file is unreadable, `CLEANROOM_LLM_CACHE` has an
    /// unknown value, or no API key is available outside replay mode.
    pub(crate) fn from_env() -> Result<Self> {
        let env =
            Env::load(&xdg_dir("XDG_CONFIG_HOME", ".config")?.join("cleanroom/nemotron.env"))?;
        let llm_mode = match env.get("CLEANROOM_LLM_CACHE").as_deref() {
            None | Some("off") => LlmMode::Live,
            Some("record") => LlmMode::Record,
            Some("replay") => LlmMode::Replay,
            Some(other) => bail!("CLEANROOM_LLM_CACHE must be record or replay, not `{other}`"),
        };
        let api_key = env.get("NVIDIA_API_KEY").map(ApiKey);
        if api_key.is_none() && llm_mode != LlmMode::Replay {
            bail!(
                "NVIDIA_API_KEY is not set: put it in ~/.config/cleanroom/nemotron.env, or use CLEANROOM_LLM_CACHE=replay"
            );
        }
        let hosted = Endpoint {
            base_url: base_url(
                env.get("NVIDIA_BASE_URL")
                    .as_deref()
                    .unwrap_or(DEFAULT_HOSTED_URL),
            ),
            api_key,
        };
        let models = Models {
            lead: env.model("CLEANROOM_MODEL_LEAD", LIGHTNING),
            hunter: env.model("CLEANROOM_MODEL_HUNTER", LIGHTNING),
            forensics: env.model("CLEANROOM_MODEL_FORENSICS", LIGHTNING),
            scribe: env.model("CLEANROOM_MODEL_SCRIBE", ULTRA),
            containment: env.model("CLEANROOM_MODEL_CONTAINMENT", LIGHTNING),
            safety: env.model("CLEANROOM_MODEL_SAFETY", SAFETY_GUARD),
        };
        let local = env.get("CLEANROOM_LOCAL_BASE_URL").map(|url| LocalRoute {
            endpoint: Endpoint {
                base_url: base_url(&url),
                api_key: env.get("CLEANROOM_LOCAL_API_KEY").map(ApiKey),
            },
            model: env.model("CLEANROOM_LOCAL_MODEL", BOLT),
            safety_model: env.model("CLEANROOM_LOCAL_SAFETY_MODEL", &models.safety),
        });
        let cache_dir = match env.get("CLEANROOM_LLM_CACHE_DIR") {
            Some(dir) => PathBuf::from(dir),
            None => xdg_dir("XDG_CACHE_HOME", ".cache")?.join("cleanroom/llm"),
        };
        Ok(Self {
            hosted,
            local,
            models,
            llm_mode,
            cache_dir,
            keys_dir: xdg_dir("XDG_STATE_HOME", ".local/state")?.join("cleanroom/keys"),
            dataset_dir: xdg_dir("XDG_STATE_HOME", ".local/state")?.join("cleanroom/dataset"),
            nixpkgs: env.model("CLEANROOM_NIXPKGS", DEFAULT_NIXPKGS),
        })
    }
}

/// `$XDG_RUNTIME_DIR/cleanroom/cleanroomd.sock`.
///
/// # Errors
/// Fails if `XDG_RUNTIME_DIR` is unset.
pub(crate) fn default_socket() -> Result<PathBuf> {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|dir| !dir.is_empty())
        .context("XDG_RUNTIME_DIR is not set; pass --socket")?;
    Ok(PathBuf::from(runtime).join("cleanroom/cleanroomd.sock"))
}

/// Process environment first, then the values from `nemotron.env`.
struct Env {
    /// Parsed `KEY=VALUE` lines of the env file.
    file: HashMap<String, String>,
}

impl Env {
    /// Read the env file; a missing file is fine.
    ///
    /// # Errors
    /// Fails if the file exists but cannot be read.
    fn load(path: &Path) -> Result<Self> {
        let file = match std::fs::read_to_string(path) {
            Ok(text) => parse_env_file(&text),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(error) => {
                return Err(error).with_context(|| format!("cannot read {}", path.display()));
            }
        };
        Ok(Self { file })
    }

    /// A non-empty value for `key`.
    fn get(&self, key: &str) -> Option<String> {
        std::env::var(key)
            .ok()
            .or_else(|| self.file.get(key).cloned())
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    }

    /// A model id, or `default`.
    fn model(&self, key: &str, default: &str) -> String {
        self.get(key).unwrap_or_else(|| default.to_owned())
    }
}

/// Parse `KEY=VALUE` lines, allowing comments, `export` and quotes.
fn parse_env_file(text: &str) -> HashMap<String, String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| {
            let line = line.strip_prefix("export ").unwrap_or(line);
            let (key, value) = line.split_once('=')?;
            Some((key.trim().to_owned(), unquote(value.trim()).to_owned()))
        })
        .collect()
}

/// Strip one pair of matching quotes.
fn unquote(value: &str) -> &str {
    ['"', '\'']
        .into_iter()
        .find_map(|quote| value.strip_prefix(quote)?.strip_suffix(quote))
        .unwrap_or(value)
}

/// Normalize a base URL: no trailing slash.
fn base_url(url: &str) -> String {
    url.trim_end_matches('/').to_owned()
}

/// `$VAR`, or `$HOME/<fallback>` when unset.
///
/// # Errors
/// Fails if both `VAR` and `HOME` are unset.
pub(crate) fn xdg_dir(var: &str, fallback: &str) -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os(var).filter(|dir| !dir.is_empty()) {
        return Ok(PathBuf::from(dir));
    }
    let home = std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .context("HOME is not set")?;
    Ok(PathBuf::from(home).join(fallback))
}
