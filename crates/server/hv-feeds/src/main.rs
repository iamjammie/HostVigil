//! hv-feeds: watches `feed_bundles` for pending `.hvb` files, verifies the
//! Ed25519 signature against the publisher key, unpacks, and loads NVD/MSRC/KEV
//! JSON into `vulnerabilities`, Sigma/YARA into the rules directory, and agent
//! updates into the blob store.

use anyhow::{Context, Result};
use ed25519_dalek::VerifyingKey;
use hv_common::{BundleKind, BundleManifest};
use sqlx::PgPool;
use std::{io::Read, path::Path};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();
    let pg = PgPool::connect(
        &std::env::var("HV_POSTGRES_URL")
            .unwrap_or_else(|_| "postgres://hostvigil:hostvigil@postgres/hostvigil".into()),
    )
    .await?;
    let pubkey = parse_key(
        &std::env::var("HV_FEED_PUBKEY").context("HV_FEED_PUBKEY (hex Ed25519) is required")?,
    )?;
    let rules_dir = std::path::PathBuf::from(
        std::env::var("HV_RULES_DIR").unwrap_or_else(|_| "/etc/hostvigil/rules".into()),
    );
    loop {
        let pending: Vec<(String, String)> = sqlx::query_as(
            "SELECT id, path FROM feed_bundles WHERE status='pending' ORDER BY ts LIMIT 5",
        )
        .fetch_all(&pg)
        .await?;
        for (id, path) in pending {
            let res = import(&pg, &pubkey, Path::new(&path), &rules_dir).await;
            let (status, msg) = match &res {
                Ok(m) => ("imported", m.clone()),
                Err(e) => ("rejected", e.to_string()),
            };
            sqlx::query(
                "UPDATE feed_bundles SET status=$2, message=$3, processed_at=now() WHERE id=$1",
            )
            .bind(&id)
            .bind(status)
            .bind(&msg)
            .execute(&pg)
            .await?;
            tracing::info!(%id, status, %msg, "bundle processed");
        }
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    }
}

pub async fn import(
    pg: &PgPool,
    key: &VerifyingKey,
    path: &Path,
    rules_dir: &Path,
) -> Result<String> {
    let bytes = std::fs::read(path)?;
    // layout: [8-byte LE manifest_len][manifest json][64-byte sig over manifest][zstd tar]
    anyhow::ensure!(bytes.len() > 72, "bundle too small");
    let mlen = u64::from_le_bytes(bytes[..8].try_into()?) as usize;
    let manifest_bytes = &bytes[8..8 + mlen];
    let sig = &bytes[8 + mlen..8 + mlen + 64];
    let payload = &bytes[8 + mlen + 64..];
    anyhow::ensure!(
        hv_common::signing::verify(key, manifest_bytes, sig),
        "signature verification failed"
    );
    let manifest: BundleManifest = serde_json::from_slice(manifest_bytes)?;
    validate_manifest(&manifest)?;
    let tar_bytes = zstd::decode_all(payload)?;
    let mut ar = tar::Archive::new(std::io::Cursor::new(tar_bytes));
    let mut n = 0usize;
    for entry in ar.entries()? {
        let mut e = entry?;
        let p = e.path()?.to_string_lossy().to_string();
        let mut data = Vec::new();
        e.read_to_end(&mut data)?;
        let want = manifest
            .files
            .iter()
            .find(|f| f.path == p)
            .with_context(|| format!("{p} not in manifest"))?;
        let got = hv_common::sha256_hex(&data);
        anyhow::ensure!(got == want.sha256, "hash mismatch for {p}");
        match manifest.kind {
            BundleKind::NvdCve | BundleKind::MsrcCvrf | BundleKind::CisaKev => {
                n += load_vulns(pg, &manifest.kind, &data).await?
            }
            BundleKind::SigmaRules | BundleKind::YaraRules | BundleKind::CisBaseline => {
                let sub = match manifest.kind {
                    BundleKind::SigmaRules => "sigma",
                    BundleKind::YaraRules => "yara",
                    _ => "cis",
                };
                let dest = rules_dir.join(sub).join(Path::new(&p).file_name().unwrap());
                std::fs::create_dir_all(dest.parent().unwrap())?;
                std::fs::write(dest, &data)?;
                n += 1;
            }
            BundleKind::AgentUpdate => {
                let dest = Path::new("/var/lib/hostvigil/blobs/agent").join(&manifest.version);
                std::fs::create_dir_all(&dest)?;
                std::fs::write(dest.join(Path::new(&p).file_name().unwrap()), &data)?;
                sqlx::query("INSERT INTO agent_releases(version, sha256, path, imported_at) VALUES($1,$2,$3,now()) ON CONFLICT DO NOTHING").bind(&manifest.version).bind(&got).bind(dest.to_string_lossy()).execute(pg).await?;
                n += 1;
            }
        }
    }
    Ok(format!(
        "{:?} {}: {} items",
        manifest.kind, manifest.version, n
    ))
}

/// Accepts NVD 2.0 `vulnerabilities[].cve`, KEV `vulnerabilities[]`, and a flattened MSRC export.
async fn load_vulns(pg: &PgPool, kind: &BundleKind, data: &[u8]) -> Result<usize> {
    let v: serde_json::Value = serde_json::from_slice(data)?;
    let items = v["vulnerabilities"].as_array().cloned().unwrap_or_default();
    let mut n = 0;
    for it in items {
        match kind {
            BundleKind::NvdCve => {
                let c = &it["cve"];
                let id = c["id"].as_str().unwrap_or("");
                if id.is_empty() {
                    continue;
                }
                let cvss = c["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
                    .as_f64()
                    .or_else(|| c["metrics"]["cvssMetricV30"][0]["cvssData"]["baseScore"].as_f64())
                    .unwrap_or(0.0);
                let title = c["descriptions"]
                    .as_array()
                    .and_then(|d| d.iter().find(|x| x["lang"] == "en"))
                    .and_then(|x| x["value"].as_str())
                    .unwrap_or("")
                    .chars()
                    .take(300)
                    .collect::<String>();
                let affects: Vec<serde_json::Value> = c["configurations"].as_array().into_iter().flatten().flat_map(|cfg| cfg["nodes"].as_array().into_iter().flatten()).flat_map(|n| n["cpeMatch"].as_array().into_iter().flatten()).filter(|m| m["vulnerable"] == true).filter_map(|m| { let cpe = m["criteria"].as_str()?; let parts: Vec<&str> = cpe.split(':').collect(); Some(serde_json::json!({"vendor": parts.get(3), "product": parts.get(4).map(|p| p.replace('_', " ")), "version_end": m["versionEndExcluding"].as_str()})) }).collect();
                sqlx::query("INSERT INTO vulnerabilities(cve, title, cvss, kev, affects, published) VALUES($1,$2,$3,false,$4,$5) ON CONFLICT(cve) DO UPDATE SET title=$2, cvss=$3, affects=$4").bind(id).bind(title).bind(cvss).bind(serde_json::Value::Array(affects)).bind(c["published"].as_str()).execute(pg).await?;
                n += 1;
            }
            BundleKind::CisaKev => {
                if let Some(id) = it["cveID"].as_str() {
                    sqlx::query("UPDATE vulnerabilities SET kev=true, kev_added=$2 WHERE cve=$1")
                        .bind(id)
                        .bind(it["dateAdded"].as_str())
                        .execute(pg)
                        .await?;
                    n += 1;
                }
            }
            BundleKind::MsrcCvrf => {
                if let Some(id) = it["cve"].as_str() {
                    let kbs: Vec<String> = it["kbs"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|k| k.as_str().map(String::from))
                        .collect();
                    sqlx::query("INSERT INTO vulnerabilities(cve, title, cvss, kev, affects, os_build_prefix, fixed_by_kb) VALUES($1,$2,$3,false,'[]',$4,$5) ON CONFLICT(cve) DO UPDATE SET os_build_prefix=$4, fixed_by_kb=$5").bind(id).bind(it["title"].as_str().unwrap_or("")).bind(it["cvss"].as_f64().unwrap_or(0.0)).bind(it["product"].as_str()).bind(&kbs).execute(pg).await?;
                    n += 1;
                }
            }
            _ => {}
        }
    }
    Ok(n)
}

pub const MAX_MEMBER_BYTES: u64 = 512 << 20;
pub const MAX_MANIFEST_FILES: usize = 10_000;

/// Manifest sanity: version is a simple token, file list is bounded and each
/// entry carries a 64-hex sha256, and the recorded digest matches the list.
pub fn validate_manifest(m: &BundleManifest) -> Result<()> {
    anyhow::ensure!(
        !m.version.is_empty()
            && m.version.len() <= 64
            && m.version
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_'),
        "bad bundle version"
    );
    anyhow::ensure!(
        !m.files.is_empty() && m.files.len() <= MAX_MANIFEST_FILES,
        "manifest file count out of range"
    );
    for f in &m.files {
        safe_member_path(&f.path)?;
        anyhow::ensure!(
            f.sha256.len() == 64
                && f.sha256
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "bad sha256 for {}",
            f.path
        );
        anyhow::ensure!(f.size <= MAX_MEMBER_BYTES, "{} too large", f.path);
    }
    let digest = BundleManifest::compute_digest(&m.files);
    anyhow::ensure!(digest == m.digest, "manifest digest mismatch");
    let age = chrono::Utc::now() - m.created_at;
    anyhow::ensure!(age.num_days() > -2, "bundle created in the future");
    Ok(())
}

/// Tar members must be plain relative file names: no absolute paths, no `..`,
/// no drive letters, no NUL. This is the check that stops a crafted bundle
/// from writing outside the rules or blob directory.
pub fn safe_member_path(p: &str) -> Result<()> {
    anyhow::ensure!(!p.is_empty() && p.len() <= 255, "bad member path length");
    anyhow::ensure!(!p.contains('\0'), "NUL in path");
    anyhow::ensure!(
        !p.starts_with('/') && !p.starts_with('\\') && !p.contains(':'),
        "absolute path not allowed: {p}"
    );
    anyhow::ensure!(
        !p.split(['/', '\\'])
            .any(|seg| seg == ".." || seg.is_empty()),
        "path traversal not allowed: {p}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hv_common::{BundleFile, BundleKind};
    #[test]
    fn member_paths() {
        assert!(safe_member_path("rules/x.yml").is_ok());
        assert!(safe_member_path("../etc/passwd").is_err());
        assert!(safe_member_path("/etc/passwd").is_err());
        assert!(safe_member_path("C:\\Windows\\x").is_err());
        assert!(safe_member_path("a//b").is_err());
    }
    #[test]
    fn manifest_digest_must_match() {
        let files = vec![BundleFile {
            path: "nvd.json".into(),
            sha256: "0".repeat(64),
            size: 10,
        }];
        let digest = BundleManifest::compute_digest(&files);
        let mut m = BundleManifest {
            kind: BundleKind::NvdCve,
            version: "20261111".into(),
            created_at: chrono::Utc::now(),
            files,
            digest,
        };
        assert!(validate_manifest(&m).is_ok());
        m.digest = "deadbeef".into();
        assert!(validate_manifest(&m).is_err());
    }
}

fn parse_key(hex: &str) -> Result<VerifyingKey> {
    anyhow::ensure!(hex.len() == 64, "key must be 64 hex chars");
    let mut b = [0u8; 32];
    for i in 0..32 {
        b[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)?;
    }
    Ok(VerifyingKey::from_bytes(&b)?)
}
