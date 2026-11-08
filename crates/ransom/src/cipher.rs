//! The lock format: `CLEANROOM-LOCKED-v1\n`, a 32-byte nonce, then the file combined by XOR
//! with a SHA-256 counter-mode keystream under a fixed key. Anyone with this source can undo it.

use sha2::{Digest as _, Sha256};

/// First bytes of every locked file; the YARA rules key on it.
pub(crate) const MAGIC: &[u8] = b"CLEANROOM-LOCKED-v1\n";

/// The demo key. Fixed and published on purpose so `restore` always works.
const KEY: &[u8; 32] = b"cleanroom-demo-key-not-a-secret!";

/// Nonce length: one SHA-256 digest.
const NONCE_LEN: usize = 32;

/// Lock `plain`. The nonce is the SHA-256 of `name` (the file's path on the share), so
/// identical files lock to different bytes and the same input always locks to the same output.
pub(crate) fn lock(name: &str, plain: &[u8]) -> Vec<u8> {
    let nonce = Sha256::digest(name.as_bytes());
    let mut locked = Vec::with_capacity(MAGIC.len() + NONCE_LEN + plain.len());
    locked.extend_from_slice(MAGIC);
    locked.extend_from_slice(&nonce);
    locked.extend(keystream_xor(&nonce, plain));
    locked
}

/// Unlock a file produced by [`lock`], or `None` when it lacks the header.
pub(crate) fn unlock(locked: &[u8]) -> Option<Vec<u8>> {
    let rest = locked.strip_prefix(MAGIC)?;
    let (nonce, body) = rest.split_at_checked(NONCE_LEN)?;
    Some(keystream_xor(nonce, body).collect())
}

/// `data` XOR `SHA-256(KEY || nonce || counter_le)` blocks, byte by byte.
fn keystream_xor<'a>(nonce: &'a [u8], data: &'a [u8]) -> impl Iterator<Item = u8> + 'a {
    (0_u64..)
        .zip(data.chunks(32))
        .flat_map(move |(counter, chunk)| {
            let block = Sha256::new()
                .chain_update(KEY)
                .chain_update(nonce)
                .chain_update(counter.to_le_bytes())
                .finalize();
            chunk.iter().zip(block).map(|(byte, key)| byte ^ key)
        })
}

#[cfg(test)]
#[allow(
    clippy::missing_panics_doc,
    reason = "tests panic on failure by design. `allow`, not `expect`: the lint only runs under \
              the strict Clippy profile"
)]
mod tests {
    use super::{MAGIC, lock, unlock};

    #[test]
    fn lock_writes_header_and_round_trips() {
        let plain = b"employee_id,ssn\nACME-10001,900-12-3456\n".repeat(5);
        let locked = lock("payroll.csv", &plain);
        assert!(
            locked.starts_with(MAGIC),
            "locked file starts with the magic header"
        );
        assert!(
            !locked.windows(11).any(|w| w == b"900-12-3456"),
            "plaintext does not survive"
        );
        assert_eq!(unlock(&locked).as_deref(), Some(plain.as_slice()));
        assert_eq!(locked, lock("payroll.csv", &plain), "deterministic");
        assert_ne!(
            locked,
            lock("copy.csv", &plain),
            "nonce depends on the name"
        );
    }

    #[test]
    fn unlock_rejects_files_without_header() {
        assert_eq!(unlock(b"not locked"), None);
        assert_eq!(unlock(MAGIC), None, "truncated nonce");
    }
}
