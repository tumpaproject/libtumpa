//! Network operations: WKD fetch and keys.openpgp.org (VKS) upload/verify.
//!
//! Ported from `tumpa/src-tauri/src/commands/keyserver.rs` and
//! `tumpa-cli/src/keystore.rs::cmd_fetch`.
//!
//! Enable with the `network` Cargo feature.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use wecanencrypt::KeyStore;

use crate::error::{Error, Result};

const VKS_UPLOAD_URL: &str = "https://keys.openpgp.org/vks/v1/upload";
const VKS_REQUEST_VERIFY_URL: &str = "https://keys.openpgp.org/vks/v1/request-verify";
const DEFAULT_TIMEOUT_SECS: u64 = 30;

fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(DEFAULT_TIMEOUT_SECS))
        .build()
        .map_err(|e| Error::Network(format!("http client: {e}")))
}

/// Result of uploading a key to keys.openpgp.org.
#[derive(Debug, Clone, Serialize)]
pub struct VksUploadResult {
    pub fingerprint: String,
    /// Per-email verification status returned by the VKS API
    /// (`unpublished`, `published`, `revoked`, `pending`).
    pub email_status: Vec<EmailStatus>,
    pub token: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EmailStatus {
    pub email: String,
    pub status: String,
}

#[derive(Deserialize)]
struct VksUploadResponse {
    key_fpr: String,
    status: HashMap<String, String>,
    token: String,
}

/// Upload the ASCII-armored public key for `fingerprint` to keys.openpgp.org.
///
/// After the upload, each email address needs to be verified via the token
/// returned by this call — see [`request_verification`].
pub async fn vks_upload(store: &KeyStore, fingerprint: &str) -> Result<VksUploadResult> {
    let armored = store
        .export_key_armored(fingerprint)
        .map_err(|e| Error::KeyStore(format!("export_key_armored: {e}")))?;

    let client = http_client()?;
    let body = serde_json::json!({ "keytext": armored });

    let resp = client
        .post(VKS_UPLOAD_URL)
        .json(&body)
        .send()
        .await
        .map_err(|e| Error::Network(format!("upload: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(Error::Network(format!("{status}: {text}")));
    }

    let vks: VksUploadResponse = resp
        .json()
        .await
        .map_err(|e| Error::Network(format!("parse response: {e}")))?;

    Ok(VksUploadResult {
        fingerprint: vks.key_fpr,
        email_status: vks
            .status
            .into_iter()
            .map(|(email, status)| EmailStatus { email, status })
            .collect(),
        token: vks.token,
    })
}

/// Request that keys.openpgp.org send a verification email for `email`,
/// authorized by the `token` returned from [`vks_upload`].
pub async fn request_verification(token: &str, email: &str) -> Result<()> {
    let client = http_client()?;
    let body = serde_json::json!({
        "token": token,
        "addresses": [email],
    });

    let resp = client
        .post(VKS_REQUEST_VERIFY_URL)
        .json(&body)
        .send()
        .await
        .map_err(|e| Error::Network(format!("request-verify: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(Error::Network(format!("{status}: {text}")));
    }

    Ok(())
}

/// Fetch a key by email via WKD / keyserver and import it into `store`.
///
/// Thin wrapper around [`wecanencrypt::fetch_key_by_email`].
pub fn wkd_fetch_and_import(store: &KeyStore, email: &str) -> Result<String> {
    let data = wecanencrypt::fetch_key_by_email(email)
        .map_err(|e| Error::Network(format!("fetch_key_by_email: {e}")))?;
    let fp = store
        .import_key(&data)
        .map_err(|e| Error::KeyStore(format!("import_key: {e}")))?;
    Ok(fp)
}
