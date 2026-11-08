//! Root admission.
//!
//! A root is an OCI image pinned by a lock file in `roots/` (`<name>.lock.json` or
//! `<name>-<anything>.lock.json`) to one platform manifest digest. Admission fetches the image
//! once with skopeo into `store/oci` (later admissions run offline), stages a copy, checks the
//! staged manifest against the lock and every staged blob against the manifest, unpacks the
//! verified copy rootless with umoci, and records a digest of the unpacked tree (path, mode,
//! content) that every stratum launch re-checks. `tamper` flips one byte of the first layer in a
//! staged copy, so the next admission rejects that layer; the rejection discards the copy, so
//! the admission after it starts clean again.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Read as _, Seek as _, SeekFrom, Write as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::RwLock;

use anyhow::{Context as _, Result, bail};
use cleanroom_proto::Digest;
use cleanroom_proto::sign::hash_bytes;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest as _, Sha256};
use tokio::process::Command;
use tokio::task::spawn_blocking;
use walkdir::WalkDir;

use crate::layout::Layout;
use crate::strata::MOUNT_POINTS;

/// Default manifest media type when a manifest omits it.
const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";

/// A root lock: which image, pinned to which platform manifest.
#[derive(Debug, Clone, Deserialize)]
struct Lock {
    /// Image reference, for example `docker.io/library/debian:bookworm-slim`.
    image: String,
    /// Digest of the platform manifest (not the index).
    manifest_digest: Digest,
}

/// The parts of an OCI image manifest that admission checks.
#[derive(Debug, Deserialize)]
struct Manifest {
    /// The manifest's own media type.
    #[serde(rename = "mediaType", default)]
    media_type: Option<String>,
    /// Image configuration blob.
    config: Descriptor,
    /// Filesystem layers, base first.
    layers: Vec<Descriptor>,
}

impl Manifest {
    /// Every referenced blob: layers in order, then the config.
    fn blobs(&self) -> impl Iterator<Item = &Descriptor> {
        self.layers.iter().chain(std::iter::once(&self.config))
    }
}

/// A content descriptor.
#[derive(Debug, Deserialize)]
struct Descriptor {
    /// `sha256:<hex>` of the blob.
    digest: Digest,
    /// Blob size in bytes.
    size: u64,
}

/// An admitted root.
#[derive(Debug, Clone)]
pub(crate) struct Admitted {
    /// Manifest digest from the lock, verified.
    pub(crate) manifest: Digest,
    /// Digest of the unpacked tree, re-checked at every launch.
    pub(crate) tree: Digest,
    /// The unpacked tree.
    pub(crate) rootfs: PathBuf,
}

/// The first blob whose bytes don't match.
#[derive(Debug, Clone)]
pub(crate) struct Mismatch {
    /// Manifest digest the lock pins.
    pub(crate) manifest: Digest,
    /// The blob (layer, config or manifest) that failed.
    pub(crate) layer: Digest,
    /// What its bytes should hash to.
    pub(crate) expected: Digest,
    /// What they hash to.
    pub(crate) actual: Digest,
}

/// The result of an admission.
#[derive(Debug)]
pub(crate) enum Verdict {
    /// Every blob matched; the root is unpacked and usable.
    Admitted(Admitted),
    /// A blob did not match its digest.
    Rejected(Mismatch),
}

/// Where a tamper flipped a byte.
#[derive(Debug)]
pub(crate) struct Tampered {
    /// The layer.
    pub(crate) layer: Digest,
    /// Byte offset in the layer blob.
    pub(crate) offset: u64,
    /// The staged blob file.
    pub(crate) path: PathBuf,
}

/// Admission state.
#[derive(Debug)]
pub(crate) struct Roots {
    /// Paths.
    layout: Layout,
    /// Serializes fetching, staging, unpacking and tampering.
    busy: tokio::sync::Mutex<()>,
    /// Roots admitted during this run, by name.
    admitted: RwLock<HashMap<String, Admitted>>,
}

impl Roots {
    /// Nothing admitted yet.
    pub(crate) fn new(layout: Layout) -> Self {
        Self {
            layout,
            busy: tokio::sync::Mutex::new(()),
            admitted: RwLock::default(),
        }
    }

    /// The admitted root called `name`, if this run admitted it.
    pub(crate) fn admitted(&self, name: &str) -> Option<Admitted> {
        self.admitted
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(name)
            .cloned()
    }

    /// Admit `name`: fetch if needed, verify a staged copy, unpack it, record the tree digest.
    /// A tampered staged copy is checked as is; the staged copy is discarded either way.
    ///
    /// # Errors
    /// Fails if the lock is missing or malformed, the image cannot be fetched, or staging or
    /// unpacking fails. A digest mismatch is a [`Verdict::Rejected`], not an error.
    pub(crate) async fn admit(&self, name: &str) -> Result<Verdict> {
        let _busy = self.busy.lock().await;
        let lock = read_lock(&self.layout, name)?;
        self.fetch(name, &lock).await?;
        let staged = self.layout.staging().join(name);
        if !staged.join("index.json").is_file() {
            self.stage(name, &lock).await?;
        }
        let checked = {
            let staged = staged.clone();
            let lock = lock.clone();
            spawn_blocking(move || verify(&staged, &lock))
                .await
                .context("verification panicked")??
        };
        let verdict = match checked {
            Err(mismatch) => Verdict::Rejected(mismatch),
            Ok(()) => Verdict::Admitted(self.unpack(name, &lock, &staged).await?),
        };
        discard(&staged).await?;
        Ok(verdict)
    }

    /// Flip one byte in the middle of the first layer of a freshly staged copy of `name`.
    ///
    /// # Errors
    /// Fails if the lock is unusable, the image cannot be fetched or staged, or the blob cannot
    /// be rewritten.
    pub(crate) async fn tamper(&self, name: &str) -> Result<Tampered> {
        let _busy = self.busy.lock().await;
        let lock = read_lock(&self.layout, name)?;
        self.fetch(name, &lock).await?;
        let manifest = self.stage(name, &lock).await?;
        let layer = manifest
            .layers
            .first()
            .with_context(|| format!("root {name} has no layers"))?;
        let path = blob_path(&self.layout.staging().join(name), &layer.digest)?;
        let offset = layer.size / 2;
        let blob = path.clone();
        spawn_blocking(move || flip_byte(&blob, offset))
            .await
            .context("tampering panicked")??;
        Ok(Tampered {
            layer: layer.digest.clone(),
            offset,
            path,
        })
    }

    /// Discard every staged copy (reset).
    ///
    /// # Errors
    /// Fails if the staging directory cannot be removed.
    pub(crate) async fn discard_staging(&self) -> Result<()> {
        let _busy = self.busy.lock().await;
        discard(&self.layout.staging()).await
    }

    /// True when `root`'s unpacked tree still has the digest it was admitted with.
    ///
    /// # Errors
    /// Fails if the tree cannot be read.
    pub(crate) async fn intact(&self, root: &Admitted) -> Result<bool> {
        let rootfs = root.rootfs.clone();
        let tree = spawn_blocking(move || tree_digest(&rootfs))
            .await
            .context("tree digest panicked")??;
        Ok(tree == root.tree)
    }

    /// Fetch the pinned image into the OCI store unless every blob is already there.
    ///
    /// # Errors
    /// Fails if skopeo fails.
    async fn fetch(&self, name: &str, lock: &Lock) -> Result<()> {
        let oci = self.layout.oci();
        let present = {
            let oci = oci.clone();
            let manifest = lock.manifest_digest.clone();
            spawn_blocking(move || complete(&oci, &manifest))
                .await
                .context("store check panicked")?
        };
        if present {
            return Ok(());
        }
        fs::create_dir_all(&oci).with_context(|| format!("cannot create {}", oci.display()))?;
        let source = format!(
            "docker://{}@{}",
            repository(&lock.image),
            lock.manifest_digest
        );
        let destination = format!("oci:{}:{name}", oci.display());
        tracing::info!(%source, "fetching root {name} with skopeo");
        let output = Command::new("skopeo")
            .args([
                "copy",
                "--quiet",
                "--preserve-digests",
                &source,
                &destination,
            ])
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output()
            .await
            .context("cannot run skopeo (is it on PATH?)")?;
        if !output.status.success() {
            bail!("skopeo copy {source} failed: {}", last_line(&output.stderr));
        }
        Ok(())
    }

    /// Copy the pinned manifest and its blobs from the store into a fresh staged layout.
    ///
    /// # Errors
    /// Fails if the store lacks a blob or the copy cannot be written.
    async fn stage(&self, name: &str, lock: &Lock) -> Result<Manifest> {
        let oci = self.layout.oci();
        let staged = self.layout.staging().join(name);
        discard(&staged).await?;
        let name = name.to_owned();
        let manifest_digest = lock.manifest_digest.clone();
        spawn_blocking(move || stage(&oci, &staged, &name, &manifest_digest))
            .await
            .context("staging panicked")?
    }

    /// Unpack the verified staged copy, add the mount points, take the tree digest, and swap it
    /// in. A re-admission of the same manifest whose tree is still intact keeps the tree.
    ///
    /// # Errors
    /// Fails if umoci fails or the tree cannot be prepared or moved into place.
    async fn unpack(&self, name: &str, lock: &Lock, staged: &Path) -> Result<Admitted> {
        let rootfs = self.layout.roots().join(name).join("rootfs");
        if let Some(previous) = self.admitted(name)
            && previous.manifest == lock.manifest_digest
            && self.intact(&previous).await?
        {
            return Ok(previous);
        }
        let fresh = self.layout.roots().join(name).join("rootfs.new");
        discard(&fresh).await?;
        if let Some(parent) = fresh.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
        let image = format!("{}:{name}", staged.display());
        let output = Command::new("umoci")
            .args(["raw", "unpack", "--rootless", "--image", &image])
            .arg(&fresh)
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output()
            .await
            .context("cannot run umoci (is it on PATH?)")?;
        if !output.status.success() {
            bail!(
                "umoci unpack of {name} failed: {}",
                last_line(&output.stderr)
            );
        }
        let tree = {
            let fresh = fresh.clone();
            let rootfs = rootfs.clone();
            spawn_blocking(move || settle(&fresh, &rootfs))
                .await
                .context("unpacking panicked")??
        };
        let admitted = Admitted {
            manifest: lock.manifest_digest.clone(),
            tree,
            rootfs,
        };
        self.admitted
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(name.to_owned(), admitted.clone());
        Ok(admitted)
    }
}

/// Find and parse the lock for `name`.
///
/// # Errors
/// Fails if `name` is not a plain root name, no single lock file matches, or it doesn't parse.
fn read_lock(layout: &Layout, name: &str) -> Result<Lock> {
    let plain = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !plain {
        bail!("`{name}` is not a root name");
    }
    let dir = layout.locks();
    let exact = dir.join(format!("{name}.lock.json"));
    let path = if exact.is_file() {
        exact
    } else {
        let prefix = format!("{name}-");
        let mut found = fs::read_dir(&dir)
            .with_context(|| format!("cannot list {}", dir.display()))?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| {
                path.file_name()
                    .and_then(|file| file.to_str())
                    .is_some_and(|file| file.starts_with(&prefix) && file.ends_with(".lock.json"))
            });
        let first = found
            .next()
            .with_context(|| format!("no lock for root {name} in {}", dir.display()))?;
        if found.next().is_some() {
            bail!("more than one lock for root {name} in {}", dir.display());
        }
        first
    };
    let text =
        fs::read_to_string(&path).with_context(|| format!("cannot read {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("{} is not a root lock", path.display()))
}

/// The repository part of an image reference: no tag, no digest.
fn repository(image: &str) -> &str {
    let without_digest = image.split_once('@').map_or(image, |(name, _)| name);
    match without_digest.rsplit_once(':') {
        Some((name, tag)) if !tag.contains('/') => name,
        Some(_) | None => without_digest,
    }
}

/// `<layout>/blobs/sha256/<hex>` for a well-formed digest.
///
/// # Errors
/// Fails if `digest` is not `sha256:` and 64 lowercase hex digits.
fn blob_path(layout: &Path, digest: &str) -> Result<PathBuf> {
    let hex = digest
        .strip_prefix("sha256:")
        .filter(|hex| {
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .with_context(|| format!("`{digest}` is not a sha256 digest"))?;
    Ok(layout.join("blobs/sha256").join(hex))
}

/// Read and parse the manifest blob `digest` from `layout`.
///
/// # Errors
/// Fails if the blob is missing or not a manifest.
fn read_manifest(layout: &Path, digest: &str) -> Result<(Vec<u8>, Manifest)> {
    let path = blob_path(layout, digest)?;
    let bytes = fs::read(&path).with_context(|| format!("cannot read {}", path.display()))?;
    let manifest = serde_json::from_slice(&bytes)
        .with_context(|| format!("{} is not an image manifest", path.display()))?;
    Ok((bytes, manifest))
}

/// True when the store holds the manifest and every blob it references, at the right sizes.
fn complete(oci: &Path, manifest_digest: &str) -> bool {
    let Ok((_, manifest)) = read_manifest(oci, manifest_digest) else {
        return false;
    };
    manifest.blobs().all(|blob| {
        blob_path(oci, &blob.digest)
            .ok()
            .and_then(|path| fs::metadata(path).ok())
            .is_some_and(|metadata| metadata.len() == blob.size)
    })
}

/// Build a one-image OCI layout at `staged` from the store's copy of the manifest and blobs.
///
/// # Errors
/// Fails if a blob is missing or the layout cannot be written.
fn stage(oci: &Path, staged: &Path, name: &str, manifest_digest: &str) -> Result<Manifest> {
    let (bytes, manifest) = read_manifest(oci, manifest_digest)?;
    fs::create_dir_all(staged.join("blobs/sha256"))
        .with_context(|| format!("cannot create {}", staged.display()))?;
    for digest in manifest
        .blobs()
        .map(|blob| blob.digest.as_str())
        .chain(std::iter::once(manifest_digest))
    {
        let from = blob_path(oci, digest)?;
        let to = blob_path(staged, digest)?;
        fs::copy(&from, &to)
            .with_context(|| format!("cannot copy {} to {}", from.display(), to.display()))?;
    }
    let index = json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{
            "mediaType": manifest.media_type.as_deref().unwrap_or(OCI_MANIFEST),
            "digest": manifest_digest,
            "size": bytes.len(),
            "annotations": {"org.opencontainers.image.ref.name": name},
        }],
    });
    fs::write(staged.join("index.json"), index.to_string())
        .with_context(|| format!("cannot write {}/index.json", staged.display()))?;
    fs::write(
        staged.join("oci-layout"),
        r#"{"imageLayoutVersion":"1.0.0"}"#,
    )
    .with_context(|| format!("cannot write {}/oci-layout", staged.display()))?;
    Ok(manifest)
}

/// Check the staged manifest against the lock, then every layer and the config against the
/// manifest. `Ok(Err(_))` names the first blob that does not match.
///
/// # Errors
/// Fails if a blob cannot be read or the manifest does not parse.
fn verify(staged: &Path, lock: &Lock) -> Result<Result<(), Mismatch>> {
    let mismatch = |layer: &str, actual: Digest| Mismatch {
        manifest: lock.manifest_digest.clone(),
        layer: layer.to_owned(),
        expected: layer.to_owned(),
        actual,
    };
    let manifest_path = blob_path(staged, &lock.manifest_digest)?;
    let bytes = fs::read(&manifest_path)
        .with_context(|| format!("cannot read {}", manifest_path.display()))?;
    let actual = hash_bytes(&bytes);
    if actual != lock.manifest_digest {
        return Ok(Err(mismatch(&lock.manifest_digest, actual)));
    }
    let manifest: Manifest = serde_json::from_slice(&bytes)
        .with_context(|| format!("{} is not an image manifest", manifest_path.display()))?;
    for blob in manifest.blobs() {
        let actual = hash_file(&blob_path(staged, &blob.digest)?)?;
        if actual != blob.digest {
            return Ok(Err(mismatch(&blob.digest, actual)));
        }
    }
    Ok(Ok(()))
}

/// `sha256:<hex>` of a file's bytes.
///
/// # Errors
/// Fails if the file cannot be read.
fn hash_file(path: &Path) -> Result<Digest> {
    let mut file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher).with_context(|| format!("cannot read {}", path.display()))?;
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

/// XOR one byte of `path` at `offset` with `0xff`.
///
/// # Errors
/// Fails if the file cannot be read or written.
fn flip_byte(path: &Path, offset: u64) -> Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    let mut byte = [0_u8; 1];
    file.seek(SeekFrom::Start(offset))
        .and_then(|_| file.read_exact(&mut byte))
        .with_context(|| format!("cannot read byte {offset} of {}", path.display()))?;
    byte[0] ^= 0xff;
    file.seek(SeekFrom::Start(offset))
        .and_then(|_| file.write_all(&byte))
        .and_then(|()| file.sync_data())
        .with_context(|| format!("cannot write byte {offset} of {}", path.display()))
}

/// Add the mount points to a fresh tree, take its digest, and move it to `rootfs`.
///
/// # Errors
/// Fails if a directory cannot be created, the tree cannot be read, or the swap fails.
fn settle(fresh: &Path, rootfs: &Path) -> Result<Digest> {
    for point in MOUNT_POINTS {
        let dir = fresh.join(point.trim_start_matches('/'));
        fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
    }
    let tree = tree_digest(fresh)?;
    remove_tree(rootfs)?;
    fs::rename(fresh, rootfs)
        .with_context(|| format!("cannot move {} to {}", fresh.display(), rootfs.display()))?;
    Ok(tree)
}

/// Digest of a tree: for every entry in file-name order, its relative path, its `st_mode`
/// (type and permission bits) and its content (file bytes, or the symlink target).
///
/// # Errors
/// Fails if an entry cannot be read.
pub(crate) fn tree_digest(root: &Path) -> Result<Digest> {
    let mut tree = Sha256::new();
    for entry in WalkDir::new(root).follow_links(false).sort_by_file_name() {
        let entry = entry.with_context(|| format!("cannot walk {}", root.display()))?;
        let path = entry.path();
        let metadata = entry
            .metadata()
            .with_context(|| format!("cannot stat {}", path.display()))?;
        let file_type = metadata.file_type();
        let content = if file_type.is_symlink() {
            let target =
                fs::read_link(path).with_context(|| format!("cannot read {}", path.display()))?;
            hash_bytes(target.as_os_str().as_bytes())
        } else if metadata.is_file() {
            hash_file(path)?
        } else {
            String::new()
        };
        let relative = path.strip_prefix(root).unwrap_or(path);
        tree.update(relative.as_os_str().as_bytes());
        tree.update(b"\0");
        tree.update(metadata.mode().to_be_bytes());
        tree.update(content.as_bytes());
        tree.update(b"\n");
    }
    Ok(format!("sha256:{}", hex::encode(tree.finalize())))
}

/// Remove a directory tree off the async runtime; a missing tree is fine.
///
/// # Errors
/// Fails if the tree exists and cannot be removed.
async fn discard(path: &Path) -> Result<()> {
    let path = path.to_owned();
    spawn_blocking(move || remove_tree(&path))
        .await
        .context("removal panicked")?
}

/// Remove a directory tree; a missing tree is fine.
///
/// # Errors
/// Fails if the tree exists and cannot be removed.
fn remove_tree(path: &Path) -> Result<()> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("cannot remove {}", path.display())),
    }
}

/// The last non-empty line of a tool's error output.
fn last_line(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    text.lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("no error output")
        .trim()
        .to_owned()
}
