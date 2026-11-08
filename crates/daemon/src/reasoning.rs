//! Reasoning custody: the chain of thought a Nemotron model returned with each answer
//! (`reasoning_content`), kept by cleanroomd in `reasoning.ndjson` (append-only, mode 0600) and
//! bound to the signed `model_call` receipt by its digest. `cleanroomd reasoning SEQ` shows the
//! reasoning behind a receipt and whether it still matches what was signed.

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use cleanroom_proto::sign;
use cleanroom_proto::{Action, Digest, Receipt, Signed, domain};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// One stored reasoning trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Trace {
    /// The `model_call` receipt it belongs to.
    pub(crate) receipt: u64,
    /// The agent role.
    pub(crate) role: String,
    /// The model that reasoned.
    pub(crate) model: String,
    /// Reasoning tokens the endpoint reported.
    pub(crate) tokens: Option<u64>,
    /// The trace.
    pub(crate) text: String,
}

/// A trace and whether it still matches its signed receipt.
#[derive(Debug)]
pub(crate) struct Shown {
    /// The stored trace.
    pub(crate) trace: Trace,
    /// Its digest equals the one in the signed receipt.
    pub(crate) intact: bool,
}

/// `sha256:` of a trace.
pub(crate) fn digest(text: &str) -> Digest {
    format!("sha256:{}", hex::encode(Sha256::digest(text.as_bytes())))
}

/// Append `trace` to the store at `path` (created with mode 0600).
///
/// # Errors
/// Fails if the store cannot be written.
pub(crate) fn append(path: &Path, trace: &Trace) -> Result<()> {
    let mut line = serde_json::to_vec(trace).context("cannot encode a reasoning trace")?;
    line.push(b'\n');
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut file| file.write_all(&line))
        .with_context(|| format!("cannot append to {}", path.display()))
}

/// The reasoning behind receipt `seq`: the receipt must be signed by `key` and record a
/// reasoning digest, and the store must hold a trace for it.
///
/// # Errors
/// Fails if a file cannot be read, the receipt is missing, not signed by `key` or records no
/// reasoning, or no trace is stored for it.
pub(crate) fn show(receipts: &Path, traces: &Path, key: &VerifyingKey, seq: u64) -> Result<Shown> {
    let log = fs::read_to_string(receipts)
        .with_context(|| format!("cannot read {}", receipts.display()))?;
    let signed = log
        .lines()
        .filter_map(|line| serde_json::from_str::<Signed<Receipt>>(line).ok())
        .find(|signed| signed.body.seq == seq)
        .with_context(|| format!("no receipt #{seq} in {}", receipts.display()))?;
    sign::verify(&signed, key, domain::RECEIPT).map_err(|error| {
        anyhow::anyhow!("receipt #{seq} is not signed by this cleanroomd: {error}")
    })?;
    let Action::ModelCall {
        reasoning: Some(signed_digest),
        ..
    } = &signed.body.action
    else {
        bail!("receipt #{seq} records no reasoning (it is not a model call that returned a trace)");
    };
    let stored = match fs::read_to_string(traces) {
        Ok(text) => text,
        Err(error) if error.kind() == ErrorKind::NotFound => String::new(),
        Err(error) => {
            return Err(error).with_context(|| format!("cannot read {}", traces.display()));
        }
    };
    let trace = stored
        .lines()
        .rev()
        .filter_map(|line| serde_json::from_str::<Trace>(line).ok())
        .find(|trace| trace.receipt == seq)
        .with_context(|| format!("no reasoning trace is stored for receipt #{seq}"))?;
    let intact = digest(&trace.text) == *signed_digest;
    Ok(Shown { trace, intact })
}

/// `cleanroomd reasoning SEQ`: print the reasoning behind receipt `seq` from the state directory
/// `state`, offline, and whether it still matches the digest the daemon signed. Exits 0 when it
/// matches, 1 when the stored trace was changed.
///
/// # Errors
/// Fails like [`show`], or if the daemon key is missing.
pub(crate) fn command(state: &Path, seq: u64) -> Result<std::process::ExitCode> {
    let key_path = state.join("keys/cleanroomd.key");
    if !key_path.exists() {
        bail!("no daemon key at {}; pass --state", key_path.display());
    }
    let key = crate::keys::load_or_create(&key_path)?.verifying_key();
    let shown = show(
        &state.join("receipts.ndjson"),
        &state.join("reasoning.ndjson"),
        &key,
        seq,
    )?;
    let Trace {
        role,
        model,
        tokens,
        text,
        ..
    } = &shown.trace;
    let tokens = tokens.map_or_else(|| "unreported".to_owned(), |tokens| tokens.to_string());
    let verdict = if shown.intact {
        "matches the digest in signed receipt"
    } else {
        "DOES NOT MATCH the digest in signed receipt"
    };
    let mut out = std::io::stdout().lock();
    writeln!(
        out,
        "receipt #{seq}: {role} on {model}, {tokens} reasoning tokens\n\n{text}\n\nthis trace {verdict} #{seq}"
    )
    .context("cannot write to stdout")?;
    Ok(if shown.intact {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::from(1)
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use cleanroom_proto::{Action, Outcome, Principal, Role};
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::receipts::Log;

    fn scratch() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        let dir = std::env::temp_dir().join(format!(
            "cleanroomd-reasoning-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn model_call(reasoning: Option<Digest>) -> Action {
        Action::ModelCall {
            purpose: "agent".to_owned(),
            model: "nvidia/nemotron-3.5-lightning-30b-a3b".to_owned(),
            endpoint: "https://integrate.api.nvidia.com/v1".to_owned(),
            request: "sha256:req".to_owned(),
            response: "sha256:resp".to_owned(),
            replayed: false,
            reasoning,
            reasoning_tokens: Some(306),
        }
    }

    /// The reasoning behind a receipt is shown with proof it is what the model returned: the
    /// signed receipt holds its digest, so an edited trace no longer matches.
    #[test]
    fn a_stored_trace_is_checked_against_its_signed_receipt() {
        let dir = scratch();
        let (receipts, traces) = (dir.join("receipts.ndjson"), dir.join("reasoning.ndjson"));
        let key = SigningKey::from_bytes(&[7; 32]);
        let hunter = Principal::Agent { role: Role::Hunter };
        let text =
            "The note demands bitcoin; the .locked files mean encryption. List /evidence first.";
        let mut log = Log::open(&receipts).expect("log");
        let seq = log
            .append(
                &key,
                hunter.clone(),
                model_call(Some(digest(text))),
                Outcome::Allowed,
            )
            .expect("receipt");
        append(
            &traces,
            &Trace {
                receipt: seq,
                role: "hunter".to_owned(),
                model: "nvidia/nemotron-3.5-lightning-30b-a3b".to_owned(),
                tokens: Some(306),
                text: text.to_owned(),
            },
        )
        .expect("trace");
        let plain = log
            .append(&key, hunter, model_call(None), Outcome::Allowed)
            .expect("receipt without reasoning");

        let shown = show(&receipts, &traces, &key.verifying_key(), seq).expect("shown");
        assert!(shown.intact);
        assert_eq!(shown.trace.text, text);
        assert!(
            show(&receipts, &traces, &key.verifying_key(), plain)
                .is_err_and(|error| format!("{error:#}").contains("no reasoning")),
            "a call without a trace says so"
        );

        let edited = fs::read_to_string(&traces)
            .expect("traces")
            .replace("List /evidence first", "Delete /evidence first");
        fs::write(&traces, edited).expect("tamper");
        let tampered = show(&receipts, &traces, &key.verifying_key(), seq).expect("still shown");
        assert!(
            !tampered.intact,
            "an edited trace no longer matches its receipt"
        );

        let stranger = SigningKey::from_bytes(&[9; 32]);
        assert!(
            show(&receipts, &traces, &stranger.verifying_key(), seq).is_err(),
            "a receipt that is not the daemon's proves nothing"
        );
        fs::remove_dir_all(&dir).expect("clean up");
    }
}
