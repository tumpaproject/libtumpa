//! Keystore open + key resolution helpers.
//!
//! Lifted from `tumpa-cli/src/store.rs`.

use std::path::{Path, PathBuf};

use wecanencrypt::{KeyInfo, KeyStore, KeyType, SubkeyInfo};

use crate::error::{Error, Result};
use crate::paths;

#[cfg(unix)]
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
#[cfg(unix)]
const PRIVATE_DATABASE_MODE: u32 = 0o600;

/// Prepare and validate the persistent keystore path on Unix.
///
/// An explicitly named immediate database directory and the database file must
/// be inaccessible to group/other users. A keystore named directly in the
/// current directory retains the previous behavior of validating only the
/// database file. Existing symlinks are rejected during validation, while
/// exclusive file creation avoids following a symlink at creation time.
#[cfg(unix)]
fn prepare_keystore_path(db_path: &Path) -> Result<()> {
    use std::fs::{DirBuilder, OpenOptions};
    use std::io::ErrorKind;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

    if let Some(parent) = explicit_keystore_parent(db_path) {
        let mut builder = DirBuilder::new();
        builder.recursive(true).mode(PRIVATE_DIRECTORY_MODE);
        match builder.create(parent) {
            Ok(()) => {}
            // Another opener may have created the path concurrently. Accept
            // that only after the same type, symlink, and mode validation.
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        validate_private_keystore_directory(parent)?;
    }

    // Pre-create the database privately rather than letting SQLite use the
    // ambient umask. Exclusive creation is atomic; a concurrent winner is
    // accepted only after validating the path it created.
    match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(PRIVATE_DATABASE_MODE)
        .open(db_path)
    {
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    validate_private_keystore_database(db_path)?;

    Ok(())
}

/// Return a parent only when the caller named a directory other than the CWD.
#[cfg(unix)]
fn explicit_keystore_parent(db_path: &Path) -> Option<&Path> {
    db_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty() && *path != Path::new("."))
}

/// Preserve the existing platform-native creation behavior where Unix mode
/// metadata is unavailable.
#[cfg(not(unix))]
fn prepare_keystore_path(db_path: &Path) -> Result<()> {
    if let Some(parent) = db_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            log::debug!("open_keystore: creating parent dir {:?}", parent);
            std::fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}

/// Validate that `path` is a private directory.
#[cfg(unix)]
fn validate_private_keystore_directory(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(unsafe_keystore_path(path, "directory is a symbolic link"));
    }
    if !metadata.is_dir() {
        return Err(unsafe_keystore_path(path, "parent is not a directory"));
    }
    validate_private_keystore_metadata(path, &metadata, "directory")
}

/// Validate that `path` is a private regular file.
#[cfg(unix)]
fn validate_private_keystore_database(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(unsafe_keystore_path(path, "database is a symbolic link"));
    }
    if !metadata.is_file() {
        return Err(unsafe_keystore_path(path, "database is not a regular file"));
    }
    validate_private_keystore_metadata(path, &metadata, "database")
}

/// Validate the absence of group/other access.
#[cfg(unix)]
fn validate_private_keystore_metadata(
    path: &Path,
    metadata: &std::fs::Metadata,
    kind: &str,
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(unsafe_keystore_path(
            path,
            &format!("{kind} has unsafe permissions {mode:03o}; group/other access is forbidden"),
        ));
    }

    Ok(())
}

#[cfg(unix)]
fn unsafe_keystore_path(path: &Path, reason: &str) -> Error {
    Error::KeyStore(format!(
        "refusing unsafe keystore path {:?}: {reason}",
        path
    ))
}

/// Open the tumpa keystore at the given path or fall back to
/// [`paths::default_keystore_path`].
///
/// Creates the parent directory and database file if they don't exist.
/// On Unix, newly created explicitly named parent directories use `0700` and
/// database files use `0600`; unsafe existing paths, permissions, or symlinks
/// are rejected. A database named directly in the current directory validates
/// only the database file, preserving the library's existing behavior.
///
/// Ownership is intentionally not enforced here. The legitimate owner can be
/// deployment-specific for service accounts, containers, and managed mounts,
/// and process-identity checks are not portable. Applications that require an
/// owner policy should validate it before calling this function.
///
/// # Errors
///
/// Returns an error when the path cannot be created or opened, or when Unix
/// type/mode validation fails.
pub fn open_keystore(path: Option<&Path>) -> Result<KeyStore> {
    let db_path: PathBuf = match path {
        Some(p) => p.to_path_buf(),
        None => paths::default_keystore_path()?,
    };

    let preexisting = db_path.exists();
    log::debug!(
        "open_keystore: path={:?} preexisting={} size={:?}",
        db_path,
        preexisting,
        db_path.metadata().ok().map(|m| m.len()),
    );

    prepare_keystore_path(&db_path)?;

    let ks = KeyStore::open(&db_path)
        .map_err(|e| Error::KeyStore(format!("Failed to open {:?}: {e}", db_path)))?;
    #[cfg(unix)]
    validate_private_keystore_database(&db_path)?;
    log::debug!("open_keystore: opened OK ({:?})", db_path);
    Ok(ks)
}

/// Resolve a signer ID (fingerprint, key ID, subkey fingerprint, or email)
/// to key data + info.
///
/// Accepts:
/// - 40-char primary fingerprint (optionally `0x`-prefixed)
/// - 16-char key ID (optionally `0x`-prefixed)
/// - 40-char subkey fingerprint (optionally `0x`-prefixed)
/// - exact email (case-insensitive) — anything containing `@`
///
/// The wecanencrypt keystore stores fingerprints and key IDs in
/// uppercase, so the input is normalized.
///
/// **Email semantics:** matches every UID's email portion exactly
/// (case-insensitive). Non-revoked, non-expired, signing-capable keys
/// are considered — including public-only certs, since tumpa is
/// card-first and a cert whose secret lives on a connected smartcard
/// is a valid signing candidate. If multiple keys match, returns
/// [`Error::InvalidInput`] listing them so the caller can disambiguate
/// with a fingerprint.
pub fn resolve_signer(store: &KeyStore, id: &str) -> Result<(Vec<u8>, KeyInfo)> {
    let id = id.strip_prefix("0x").unwrap_or(id);

    if id.contains('@') {
        return resolve_signer_by_email(store, id);
    }

    resolve_by_key_material_id(store, id)
}

fn resolve_by_key_material_id(store: &KeyStore, id: &str) -> Result<(Vec<u8>, KeyInfo)> {
    let id_upper = id.to_uppercase();

    if id.len() == 40 {
        if let Ok((data, info)) = store.get_key(&id_upper) {
            return Ok((data, info));
        }
    }

    if id.len() == 16 {
        if let Ok(Some(data)) = store.find_by_key_id(&id_upper) {
            let info = wecanencrypt::parse_key_bytes(&data, true)?;
            return Ok((data, info));
        }
    }

    if id.len() == 40 {
        if let Ok(Some(data)) = store.find_by_subkey_fingerprint(&id_upper) {
            let info = wecanencrypt::parse_key_bytes(&data, true)?;
            return Ok((data, info));
        }
    }

    Err(Error::KeyNotFound(id.to_string()))
}

/// Resolve an encryption recipient ID (fingerprint, key ID, subkey
/// fingerprint, or email) to key data + info.
///
/// For email addresses, matches every UID's email portion exactly
/// (case-insensitive) and returns the unique non-revoked,
/// encryption-usable key, whether public-only or secret. If multiple
/// usable keys match, returns [`Error::InvalidInput`] so the caller can
/// disambiguate with a fingerprint.
pub fn resolve_recipient(store: &KeyStore, id: &str) -> Result<(Vec<u8>, KeyInfo)> {
    let id = id.strip_prefix("0x").unwrap_or(id);

    if id.contains('@') {
        return resolve_recipient_by_email(store, id);
    }

    resolve_by_key_material_id(store, id)
}

/// Look up signer keys by exact email (case-insensitive), filter to those
/// usable for signing (not revoked/expired, signing capability), and
/// return the unique match. Errors with a list of candidates if more than
/// one key matches.
///
/// Public-only entries are accepted: tumpa is card-first, so a cert
/// whose secret lives on a connected smartcard is a valid signing
/// candidate even when the keystore holds no secret bytes. The actual
/// sign path (`libtumpa::sign`) tries the card first and only falls
/// back to a software secret if `is_secret`.
fn resolve_signer_by_email(store: &KeyStore, email: &str) -> Result<(Vec<u8>, KeyInfo)> {
    // `email` is untrusted user input. Sanitize before embedding it in
    // any error string: a newline in `email` would let the caller's log
    // or status-stream consumer see attacker-controlled lines.
    let safe_email = sanitize_for_error(email);

    let candidates = store
        .search_by_email(email)
        .map_err(|e| Error::KeyStore(format!("search_by_email({safe_email}): {e}")))?;

    let mut usable: Vec<(Vec<u8>, KeyInfo)> = Vec::new();
    for info in candidates {
        if ensure_key_usable_for_signing(&info).is_err() {
            continue;
        }
        // Re-fetch the key bytes via the canonical fingerprint lookup to
        // get the same `(Vec<u8>, KeyInfo)` shape the other branches return.
        match store.get_key(&info.fingerprint) {
            Ok((data, info)) => usable.push((data, info)),
            Err(e) => {
                return Err(Error::KeyStore(format!(
                    "resolve_signer_by_email({safe_email}): get_key({}) failed after search hit: {e}",
                    info.fingerprint
                )));
            }
        }
    }

    match usable.len() {
        0 => Err(Error::KeyNotFound(format!(
            "no usable signing key found for email {safe_email}"
        ))),
        1 => Ok(usable.into_iter().next().unwrap()),
        _ => {
            let mut msg = format!("multiple signing keys match email {safe_email}:\n");
            for (_, info) in &usable {
                msg.push_str(&format!(
                    "  {}  {}\n",
                    info.fingerprint,
                    sanitized_primary_uid(info)
                ));
            }
            msg.push_str("disambiguate by specifying the desired fingerprint");
            Err(Error::InvalidInput(msg))
        }
    }
}

/// Look up encryption recipient keys by exact email (case-insensitive),
/// filter to those usable for encryption (public or secret,
/// non-revoked/non-expired, encryption capability), and return the unique
/// match. Errors with a list of candidates if more than one key matches.
fn resolve_recipient_by_email(store: &KeyStore, email: &str) -> Result<(Vec<u8>, KeyInfo)> {
    // See `resolve_signer_by_email` for why we sanitize `email`.
    let safe_email = sanitize_for_error(email);

    let candidates = store
        .search_by_email(email)
        .map_err(|e| Error::KeyStore(format!("search_by_email({safe_email}): {e}")))?;

    let mut usable: Vec<KeyInfo> = Vec::new();
    for info in candidates {
        if ensure_key_usable_for_encryption(&info).is_err() {
            continue;
        }
        usable.push(info);
    }

    match usable.len() {
        0 => Err(Error::KeyNotFound(format!(
            "no usable encryption key found for email {safe_email}"
        ))),
        1 => {
            let info = usable.into_iter().next().unwrap();
            store.get_key(&info.fingerprint).map_err(|e| {
                Error::KeyStore(format!(
                    "resolve_recipient_by_email: get_key({}) failed after search hit: {e}",
                    info.fingerprint
                ))
            })
        }
        _ => {
            let mut msg = format!("multiple usable encryption keys match email {safe_email}:\n");
            for info in &usable {
                msg.push_str(&format!(
                    "  {}  {}\n",
                    info.fingerprint,
                    sanitized_primary_uid(info)
                ));
            }
            msg.push_str("disambiguate by specifying the desired fingerprint");
            Err(Error::InvalidInput(msg))
        }
    }
}

/// Pick the primary (or first non-revoked) UID from a `KeyInfo` and strip
/// control characters before embedding it in an error message.
///
/// Raw OpenPGP UIDs may contain newlines and other control characters,
/// which would let a malicious key inject lines into log files, terminal
/// output, or status streams of any caller that prints our errors. The
/// caller is responsible for sanitizing UIDs in line-based output (per the
/// `verify` module docs); we apply the same rule to library-emitted error
/// strings so the contract holds end to end.
fn sanitized_primary_uid(key_info: &KeyInfo) -> String {
    let raw = key_info
        .user_ids
        .iter()
        .find(|u| u.is_primary && !u.revoked)
        .or_else(|| key_info.user_ids.iter().find(|u| !u.revoked))
        .map(|u| u.value.as_str())
        .unwrap_or("<no UID>");
    sanitize_for_error(raw)
}

/// Strip ASCII/Unicode control characters from `s` before embedding it in
/// an error message.
///
/// Both raw OpenPGP UIDs and user-supplied email arguments may contain
/// newlines and other control characters. Embedding them unsanitized
/// would let attackers inject extra lines into log files, terminal
/// output, or status streams of any caller that prints our errors.
fn sanitize_for_error(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

/// Extract the issuer fingerprint or key ID from a parsed signature config.
///
/// Returns a list of possible identifiers (fingerprints first, then key IDs).
pub fn extract_issuer_ids(sig: &pgp::packet::SignatureConfig) -> Vec<String> {
    let mut ids = Vec::new();
    for fp in sig.issuer_fingerprint() {
        ids.push(hex::encode(fp.as_bytes()));
    }
    for kid in sig.issuer_key_id() {
        ids.push(hex::encode(kid));
    }
    ids
}

/// Look up a key in the keystore by issuer info extracted from a signature.
///
/// Iterates `issuer_ids` and returns the first match. A `KeyNotFound` for
/// any individual id is treated as "not in this store, try the next" and
/// resolves to `Ok(None)` when no id hits. Any other error (DB/IO,
/// corrupt stored cert, …) propagates immediately so callers can
/// distinguish "signer unknown" from "keystore lookup failed" — the
/// software/card decrypt-and-verify paths rely on this distinction to
/// avoid silently flattening keystore failures into `UnknownKey`.
pub fn resolve_from_issuer_ids(
    store: &KeyStore,
    issuer_ids: &[String],
) -> Result<Option<(Vec<u8>, KeyInfo)>> {
    for id in issuer_ids {
        match resolve_signer(store, id) {
            Ok(result) => return Ok(Some(result)),
            Err(Error::KeyNotFound(_)) => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(None)
}

fn current_unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

pub fn key_is_expired(key_info: &KeyInfo) -> bool {
    key_info
        .expiration_time
        .map(|time| time.timestamp() <= current_unix_timestamp())
        .unwrap_or(false)
}

pub fn subkey_is_expired(subkey: &SubkeyInfo) -> bool {
    subkey
        .expiration_time
        .map(|time| time.timestamp() <= current_unix_timestamp())
        .unwrap_or(false)
}

fn has_usable_subkey(key_info: &KeyInfo, key_type: KeyType) -> bool {
    key_info.subkeys.iter().any(|subkey| {
        subkey.key_type == key_type && !subkey.is_revoked && !subkey_is_expired(subkey)
    })
}

pub fn ensure_key_usable_for_signing(key_info: &KeyInfo) -> Result<()> {
    if key_info.is_revoked {
        return Err(Error::unusable(&key_info.fingerprint, "revoked"));
    }
    if key_is_expired(key_info) {
        return Err(Error::unusable(&key_info.fingerprint, "expired"));
    }
    if key_info.can_primary_sign || has_usable_subkey(key_info, KeyType::Signing) {
        return Ok(());
    }
    Err(Error::unusable(
        &key_info.fingerprint,
        "no usable signing-capable key material",
    ))
}

pub fn ensure_key_usable_for_encryption(key_info: &KeyInfo) -> Result<()> {
    if key_info.is_revoked {
        return Err(Error::unusable(&key_info.fingerprint, "revoked"));
    }
    if key_is_expired(key_info) {
        return Err(Error::unusable(&key_info.fingerprint, "expired"));
    }
    if has_usable_subkey(key_info, KeyType::Encryption) {
        return Ok(());
    }
    Err(Error::unusable(
        &key_info.fingerprint,
        "no usable encryption-capable subkey",
    ))
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(unix)]
    use std::path::Path;
    #[cfg(unix)]
    use std::sync::{Arc, Barrier};
    #[cfg(unix)]
    use std::thread;

    use chrono::{Duration, Utc};
    use wecanencrypt::{
        create_key, create_key_simple, parse_key_bytes, revoke_key, CipherSuite, KeyStore,
        SubkeyFlags,
    };

    use super::{
        ensure_key_usable_for_encryption, ensure_key_usable_for_signing, open_keystore,
        resolve_recipient, resolve_signer,
    };
    #[cfg(unix)]
    use super::{
        explicit_keystore_parent, prepare_keystore_path, PRIVATE_DATABASE_MODE,
        PRIVATE_DIRECTORY_MODE,
    };
    use crate::error::Error;

    const TEST_PASSWORD: &str = "test-password";

    /// Basename and explicit-CWD paths must not impose a private-mode policy
    /// on the process's current working directory.
    #[cfg(unix)]
    #[test]
    fn current_directory_keystore_has_no_explicit_parent() {
        assert_eq!(explicit_keystore_parent(Path::new("keys.db")), None);
        assert_eq!(explicit_keystore_parent(Path::new("./keys.db")), None);
        assert_eq!(
            explicit_keystore_parent(Path::new("private/keys.db")),
            Some(Path::new("private"))
        );
    }

    /// Multiple openers racing to create the same private paths must accept a
    /// valid winner rather than failing with `AlreadyExists`.
    #[cfg(unix)]
    #[test]
    fn prepare_keystore_path_tolerates_concurrent_creation() {
        const WORKERS: usize = 16;

        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("private-keystore");
        let database = parent.join("keys.db");
        let barrier = Arc::new(Barrier::new(WORKERS));

        let handles: Vec<_> = (0..WORKERS)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                let database = database.clone();
                thread::spawn(move || {
                    barrier.wait();
                    prepare_keystore_path(&database)
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap().unwrap();
        }

        let parent_mode = fs::metadata(&parent).unwrap().permissions().mode() & 0o777;
        let database_mode = fs::metadata(&database).unwrap().permissions().mode() & 0o777;
        assert_eq!(parent_mode, PRIVATE_DIRECTORY_MODE);
        assert_eq!(database_mode, PRIVATE_DATABASE_MODE);
    }

    /// Persistent keystores must not inherit group/world access from the
    /// process umask or their surrounding filesystem layout.
    #[cfg(unix)]
    #[test]
    fn open_keystore_creates_private_directory_and_database() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("private-keystore");
        let database = parent.join("keys.db");

        drop(open_keystore(Some(&database)).unwrap());

        let parent_mode = fs::metadata(&parent).unwrap().permissions().mode() & 0o777;
        let database_mode = fs::metadata(&database).unwrap().permissions().mode() & 0o777;
        assert_eq!(parent_mode, 0o700);
        assert_eq!(database_mode, 0o600);

        drop(open_keystore(Some(&database)).unwrap());
    }

    /// Opening an existing database must fail closed instead of silently
    /// accepting key material exposed to other local users.
    #[cfg(unix)]
    #[test]
    fn open_keystore_rejects_unsafe_existing_database_permissions() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("private-keystore");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let database = parent.join("keys.db");
        fs::write(&database, []).unwrap();
        fs::set_permissions(&database, fs::Permissions::from_mode(0o644)).unwrap();

        let error = match open_keystore(Some(&database)) {
            Ok(_) => panic!("unsafe database permissions must be rejected"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("unsafe permissions"),
            "unexpected error: {error}"
        );
    }

    /// A private database inside a traversable/listable directory still
    /// exposes keystore metadata, so the parent must also be private.
    #[cfg(unix)]
    #[test]
    fn open_keystore_rejects_unsafe_existing_parent_permissions() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("shared-keystore");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).unwrap();
        let database = parent.join("keys.db");

        let error = match open_keystore(Some(&database)) {
            Ok(_) => panic!("unsafe parent permissions must be rejected"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("unsafe permissions"),
            "unexpected error: {error}"
        );
    }

    /// Symlinks make the checked path differ from the database SQLite opens.
    #[cfg(unix)]
    #[test]
    fn open_keystore_rejects_database_symlink() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("private-keystore");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let target = parent.join("target.db");
        fs::write(&target, []).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let database = parent.join("keys.db");
        symlink(&target, &database).unwrap();

        let error = match open_keystore(Some(&database)) {
            Ok(_) => panic!("database symlinks must be rejected"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("symbolic link"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rejects_revoked_keys_for_signing_and_encryption() {
        let key = create_key_simple(TEST_PASSWORD, &["Alice <alice@example.com>"]).unwrap();
        let revoked = revoke_key(&key.secret_key, TEST_PASSWORD).unwrap();
        let key_info = parse_key_bytes(&revoked, true).unwrap();

        assert!(ensure_key_usable_for_signing(&key_info).is_err());
        assert!(ensure_key_usable_for_encryption(&key_info).is_err());
    }

    #[test]
    fn rejects_expired_keys_for_signing_and_encryption() {
        let creation_time = Utc::now() - Duration::days(3);
        let primary_expiry = Utc::now() - Duration::days(1);
        let subkey_expiry = Utc::now() - Duration::days(1);
        let key = create_key(
            TEST_PASSWORD,
            &["Alice <alice@example.com>"],
            CipherSuite::Cv25519,
            Some(creation_time),
            Some(primary_expiry),
            Some(subkey_expiry),
            SubkeyFlags::all(),
            false,
            true,
        )
        .unwrap();
        let key_info = parse_key_bytes(&key.secret_key, true).unwrap();

        assert!(ensure_key_usable_for_signing(&key_info).is_err());
        assert!(ensure_key_usable_for_encryption(&key_info).is_err());
    }

    #[test]
    fn rejects_keys_with_only_expired_subkeys() {
        let creation_time = Utc::now() - Duration::days(3);
        let subkey_expiry = Utc::now() - Duration::days(1);
        let key = create_key(
            TEST_PASSWORD,
            &["Alice <alice@example.com>"],
            CipherSuite::Cv25519,
            Some(creation_time),
            None,
            Some(subkey_expiry),
            SubkeyFlags::all(),
            false,
            true,
        )
        .unwrap();
        let key_info = parse_key_bytes(&key.secret_key, true).unwrap();

        assert!(ensure_key_usable_for_signing(&key_info).is_err());
        assert!(ensure_key_usable_for_encryption(&key_info).is_err());
    }

    #[test]
    fn accepts_non_revoked_non_expired_keys() {
        let key = create_key_simple(TEST_PASSWORD, &["Alice <alice@example.com>"]).unwrap();
        let key_info = parse_key_bytes(&key.secret_key, true).unwrap();

        ensure_key_usable_for_signing(&key_info).unwrap();
        ensure_key_usable_for_encryption(&key_info).unwrap();
    }

    #[test]
    fn resolve_signer_by_email_unique_match() {
        let alice = create_key_simple(TEST_PASSWORD, &["Alice <alice@example.com>"]).unwrap();
        let store = KeyStore::open_in_memory().unwrap();
        store.import_key(&alice.secret_key).unwrap();

        let (data, info) = resolve_signer(&store, "alice@example.com").unwrap();
        assert!(!data.is_empty());
        assert!(info.is_secret);
        assert!(info
            .user_ids
            .iter()
            .any(|u| u.value.contains("alice@example.com")));
    }

    #[test]
    fn resolve_signer_by_email_is_case_insensitive() {
        let alice = create_key_simple(TEST_PASSWORD, &["Alice <alice@example.com>"]).unwrap();
        let store = KeyStore::open_in_memory().unwrap();
        store.import_key(&alice.secret_key).unwrap();

        let (_, info) = resolve_signer(&store, "ALICE@EXAMPLE.COM").unwrap();
        assert!(info.is_secret);
    }

    #[test]
    fn resolve_signer_by_email_no_match_errors() {
        let store = KeyStore::open_in_memory().unwrap();
        let err = resolve_signer(&store, "nobody@example.com").unwrap_err();
        match err {
            Error::KeyNotFound(msg) => assert!(msg.contains("nobody@example.com")),
            other => panic!("expected KeyNotFound, got {other:?}"),
        }
    }

    #[test]
    fn resolve_signer_by_email_accepts_public_only_keys() {
        // Public-only copy in the store. tumpa is card-first: a cert
        // whose secret lives on a smartcard is a valid signing candidate
        // even when the keystore holds only public material. The actual
        // sign path tries the card first, so resolution must not reject
        // public-only entries up front.
        let alice = create_key_simple(TEST_PASSWORD, &["Alice <alice@example.com>"]).unwrap();
        let store = KeyStore::open_in_memory().unwrap();
        store.import_key(alice.public_key.as_bytes()).unwrap();

        let (data, info) = resolve_signer(&store, "alice@example.com").unwrap();
        assert!(!data.is_empty());
        assert!(!info.is_secret);
        assert!(info
            .user_ids
            .iter()
            .any(|u| u.value.contains("alice@example.com")));
    }

    #[test]
    fn resolve_signer_by_email_skips_revoked_keys() {
        let alice = create_key_simple(TEST_PASSWORD, &["Alice <alice@example.com>"]).unwrap();
        let revoked = revoke_key(&alice.secret_key, TEST_PASSWORD).unwrap();
        let store = KeyStore::open_in_memory().unwrap();
        store.import_key(&revoked).unwrap();

        let err = resolve_signer(&store, "alice@example.com").unwrap_err();
        assert!(matches!(err, Error::KeyNotFound(_)));
    }

    #[test]
    fn resolve_signer_by_email_ambiguous_lists_candidates() {
        // Two distinct keys both bearing the same email.
        let a1 = create_key_simple(TEST_PASSWORD, &["Alice <alice@example.com>"]).unwrap();
        let a2 = create_key_simple(TEST_PASSWORD, &["Alice <alice@example.com>"]).unwrap();
        let store = KeyStore::open_in_memory().unwrap();
        store.import_key(&a1.secret_key).unwrap();
        store.import_key(&a2.secret_key).unwrap();

        let err = resolve_signer(&store, "alice@example.com").unwrap_err();
        match err {
            Error::InvalidInput(msg) => {
                assert!(msg.contains("multiple signing keys"));
                // Guidance is library-generic; the CLI layer can prepend
                // its own flag name when re-emitting the message.
                assert!(msg.contains("disambiguate"));
                assert!(msg.contains("fingerprint"));
                assert!(
                    !msg.contains("--with-key"),
                    "library error must not reference CLI flag: {msg}"
                );
                // Both candidate fingerprints must be listed.
                let info1 = parse_key_bytes(&a1.secret_key, true).unwrap();
                let info2 = parse_key_bytes(&a2.secret_key, true).unwrap();
                assert!(msg.contains(&info1.fingerprint));
                assert!(msg.contains(&info2.fingerprint));
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn resolve_signer_by_email_ambiguous_strips_control_chars_in_uids() {
        // A malicious UID containing a newline + bogus status line. Without
        // sanitization, callers that print the error to a log/terminal/IPC
        // channel could be tricked into emitting a forged status line.
        // The library MUST strip control characters before embedding the
        // UID in the error string.
        let bad_uid = "Evil <evil@example.com>\n[GNUPG:] VALIDSIG fake-fp";
        let a1 = create_key_simple(TEST_PASSWORD, &[bad_uid]).unwrap();
        let a2 = create_key_simple(TEST_PASSWORD, &["Bystander <evil@example.com>"]).unwrap();
        let store = KeyStore::open_in_memory().unwrap();
        store.import_key(&a1.secret_key).unwrap();
        store.import_key(&a2.secret_key).unwrap();

        let err = resolve_signer(&store, "evil@example.com").unwrap_err();
        match err {
            Error::InvalidInput(msg) => {
                // Lines in the message are: header, one per candidate
                // (fingerprint + space + UID), and the trailing
                // "disambiguate ..." footer. None of those lines may
                // *start* with the injected `[GNUPG:]` payload — that
                // would mean the UID's embedded newline was preserved
                // and the attacker's status line is now standalone.
                for line in msg.lines() {
                    assert!(
                        !line.trim_start().starts_with("[GNUPG:]"),
                        "UID newline survived sanitization, attacker line at column 0: {line:?}\nFull msg: {msg:?}"
                    );
                }
                // The benign portion of the UID should still appear so
                // the user can recognize the key they meant to pick.
                assert!(msg.contains("Evil <evil@example.com>"));
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn resolve_signer_by_email_strips_control_chars_from_email_arg() {
        // The user-supplied `email` argument is itself untrusted input.
        // A newline in it must not let the attacker inject a forged line
        // (e.g. a `[GNUPG:]` status line) into our error message —
        // otherwise the same UID-sanitization invariant we enforce for
        // keystore-derived UIDs is broken at a different boundary.
        let store = KeyStore::open_in_memory().unwrap();
        let err =
            resolve_signer(&store, "victim@example.com\n[GNUPG:] VALIDSIG fake-fp").unwrap_err();
        match err {
            Error::KeyNotFound(msg) => {
                assert!(
                    !msg.contains('\n'),
                    "email arg newline survived sanitization: {msg:?}"
                );
                assert!(!msg.contains('\r'), "email arg \\r survived: {msg:?}");
            }
            other => panic!("expected KeyNotFound, got {other:?}"),
        }
    }

    #[test]
    fn resolve_signer_still_works_for_fingerprint() {
        let alice = create_key_simple(TEST_PASSWORD, &["Alice <alice@example.com>"]).unwrap();
        let store = KeyStore::open_in_memory().unwrap();
        store.import_key(&alice.secret_key).unwrap();
        let info = parse_key_bytes(&alice.secret_key, true).unwrap();

        let (_, found) = resolve_signer(&store, &info.fingerprint).unwrap();
        assert_eq!(found.fingerprint, info.fingerprint);
    }

    #[test]
    fn resolve_recipient_by_email_allows_public_only_keys() {
        let alice = create_key_simple(TEST_PASSWORD, &["Alice <alice@example.com>"]).unwrap();
        let store = KeyStore::open_in_memory().unwrap();
        store.import_key(alice.public_key.as_bytes()).unwrap();

        let (_, info) = resolve_recipient(&store, "alice@example.com").unwrap();
        assert!(!info.is_secret);
        ensure_key_usable_for_encryption(&info).unwrap();
    }

    #[test]
    fn resolve_recipient_by_email_is_case_insensitive() {
        let alice = create_key_simple(TEST_PASSWORD, &["Alice <alice@example.com>"]).unwrap();
        let store = KeyStore::open_in_memory().unwrap();
        store.import_key(alice.public_key.as_bytes()).unwrap();

        let (_, info) = resolve_recipient(&store, "ALICE@EXAMPLE.COM").unwrap();
        assert!(info
            .user_ids
            .iter()
            .any(|u| u.value.contains("alice@example.com")));
    }

    #[test]
    fn resolve_recipient_by_email_ambiguous_lists_candidates() {
        let a1 = create_key_simple(TEST_PASSWORD, &["Alice <alice@example.com>"]).unwrap();
        let a2 = create_key_simple(TEST_PASSWORD, &["Alice <alice@example.com>"]).unwrap();
        let store = KeyStore::open_in_memory().unwrap();
        store.import_key(a1.public_key.as_bytes()).unwrap();
        store.import_key(a2.public_key.as_bytes()).unwrap();

        let err = resolve_recipient(&store, "alice@example.com").unwrap_err();
        match err {
            Error::InvalidInput(msg) => {
                assert!(msg.contains("multiple usable encryption keys"));
                assert!(msg.contains("disambiguate"));
                let info1 = parse_key_bytes(a1.public_key.as_bytes(), true).unwrap();
                let info2 = parse_key_bytes(a2.public_key.as_bytes(), true).unwrap();
                assert!(msg.contains(&info1.fingerprint));
                assert!(msg.contains(&info2.fingerprint));
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn resolve_recipient_by_email_skips_revoked_and_expired_keys() {
        let revoked = create_key_simple(TEST_PASSWORD, &["Alice <alice@example.com>"]).unwrap();
        let revoked = revoke_key(&revoked.secret_key, TEST_PASSWORD).unwrap();

        let creation_time = Utc::now() - Duration::days(3);
        let expired = create_key(
            TEST_PASSWORD,
            &["Alice <alice@example.com>"],
            CipherSuite::Cv25519,
            Some(creation_time),
            None,
            Some(Utc::now() - Duration::days(1)),
            SubkeyFlags::all(),
            false,
            true,
        )
        .unwrap();

        let store = KeyStore::open_in_memory().unwrap();
        store.import_key(&revoked).unwrap();
        store.import_key(expired.public_key.as_bytes()).unwrap();

        let err = resolve_recipient(&store, "alice@example.com").unwrap_err();
        assert!(matches!(err, Error::KeyNotFound(_)));
    }

    #[test]
    fn resolve_recipient_by_email_skips_non_encryption_capable_keys() {
        let signing_only = create_key(
            TEST_PASSWORD,
            &["Alice <alice@example.com>"],
            CipherSuite::Cv25519,
            None,
            None,
            None,
            SubkeyFlags {
                encryption: false,
                signing: true,
                authentication: false,
            },
            false,
            true,
        )
        .unwrap();

        let store = KeyStore::open_in_memory().unwrap();
        store
            .import_key(signing_only.public_key.as_bytes())
            .unwrap();

        let err = resolve_recipient(&store, "alice@example.com").unwrap_err();
        assert!(matches!(err, Error::KeyNotFound(_)));
    }
}
