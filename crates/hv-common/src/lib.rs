//! Shared types used by both the agent and the server: signed bundles,
//! severity model, canonical JSON hashing, and the `.hvb` feed format.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod signing {
    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

    /// Sign `payload` with an Ed25519 key. Used for commands, remediation
    /// scripts, agent updates and feed bundles. The agent refuses anything
    /// whose signature does not verify against the pinned server key.
    pub fn sign(key: &SigningKey, payload: &[u8]) -> [u8; 64] {
        key.sign(payload).to_bytes()
    }

    pub fn verify(key: &VerifyingKey, payload: &[u8], sig: &[u8]) -> bool {
        let Ok(sig) = Signature::from_slice(sig) else {
            return false;
        };
        key.verify(payload, &sig).is_ok()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Manifest inside every offline feed bundle (`*.hvb` = zstd tar + manifest + sig).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleManifest {
    pub kind: BundleKind,
    pub version: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub files: Vec<BundleFile>,
    /// hex SHA-256 of the concatenated file hashes, which is what gets signed
    pub digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BundleKind {
    NvdCve,
    MsrcCvrf,
    CisaKev,
    SigmaRules,
    YaraRules,
    CisBaseline,
    AgentUpdate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleFile {
    pub path: String,
    pub sha256: String,
    pub size: u64,
}

impl BundleManifest {
    pub fn compute_digest(files: &[BundleFile]) -> String {
        let mut h = Sha256::new();
        for f in files {
            h.update(f.sha256.as_bytes());
        }
        hex(&h.finalize())
    }
}

/// Canonical JSON: sorted keys, no whitespace. Baseline snapshots are hashed
/// this way so two hosts with identical configuration produce identical hashes.
pub fn canonical_json<T: Serialize>(v: &T) -> Result<Vec<u8>, serde_json::Error> {
    let value = serde_json::to_value(v)?;
    let mut out = Vec::new();
    write_canonical(&value, &mut out);
    Ok(out)
}

fn write_canonical(v: &serde_json::Value, out: &mut Vec<u8>) {
    use serde_json::Value::*;
    match v {
        Object(m) => {
            out.push(b'{');
            let mut keys: Vec<_> = m.keys().collect();
            keys.sort();
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                out.extend(serde_json::to_vec(k).unwrap());
                out.push(b':');
                write_canonical(&m[*k], out);
            }
            out.push(b'}');
        }
        Array(a) => {
            out.push(b'[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(x, out);
            }
            out.push(b']');
        }
        other => out.extend(serde_json::to_vec(other).unwrap()),
    }
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, thiserror::Error)]
pub enum VcError {
    #[error("signature verification failed")]
    BadSignature,
    #[error("bundle digest mismatch: expected {expected}, got {actual}")]
    DigestMismatch { expected: String, actual: String },
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_json_sorts_keys() {
        let v = serde_json::json!({"b":1,"a":{"d":2,"c":[3,4]}});
        let s = String::from_utf8(canonical_json(&v).unwrap()).unwrap();
        assert_eq!(s, r#"{"a":{"c":[3,4],"d":2},"b":1}"#);
    }

    #[test]
    fn sign_verify_roundtrip() {
        use ed25519_dalek::SigningKey;
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let sig = signing::sign(&key, b"hello");
        assert!(signing::verify(&key.verifying_key(), b"hello", &sig));
        assert!(!signing::verify(&key.verifying_key(), b"hellp", &sig));
    }
}
