//! hostvigil-bundler: the only HostVigil component that touches the internet.
//! Produces `*.hvb` = [u64 LE manifest_len][manifest JSON][Ed25519 sig over manifest][zstd(tar)].
use anyhow::Result;
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use hv_common::{BundleFile, BundleKind, BundleManifest};

#[derive(Parser)]
#[command(name = "hostvigil-bundler")]
struct Cli {
    #[arg(long, env = "HV_SIGNING_KEY")]
    key: String,
    #[arg(long, default_value = "./out")]
    out: String,
    #[command(subcommand)]
    cmd: Cmd,
}
#[derive(Subcommand)]
enum Cmd {
    /// Pull the last N days of NVD 2.0 CVEs (api.nvd.nist.gov) and bundle them.
    Nvd {
        #[arg(long, default_value_t = 14)]
        days: i64,
    },
    /// Pull CISA KEV catalog.
    Kev,
    /// Bundle a directory of Sigma or YARA rules, or CIS TOML.
    Rules {
        dir: String,
        #[arg(long, value_parser = ["sigma", "yara", "cis"])]
        kind: String,
    },
    /// Bundle an agent MSI release.
    Agent {
        msi: String,
        #[arg(long)]
        version: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let key = load_key(&cli.key)?;
    std::fs::create_dir_all(&cli.out)?;
    let (kind, version, files): (BundleKind, String, Vec<(String, Vec<u8>)>) = match cli.cmd {
        Cmd::Nvd { days } => {
            let since = (chrono::Utc::now() - chrono::Duration::days(days))
                .format("%Y-%m-%dT%H:%M:%S.000")
                .to_string();
            let until = chrono::Utc::now()
                .format("%Y-%m-%dT%H:%M:%S.000")
                .to_string();
            let mut all = vec![];
            let mut start = 0;
            loop {
                let url = format!("https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate={since}&lastModEndDate={until}&startIndex={start}&resultsPerPage=2000");
                let v: serde_json::Value = ureq::get(&url).call()?.into_json()?;
                let items = v["vulnerabilities"].as_array().cloned().unwrap_or_default();
                let n = items.len();
                all.extend(items);
                start += n;
                if n < 2000 || start >= v["totalResults"].as_u64().unwrap_or(0) as usize {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_secs(6)); // NVD rate limit without API key
            }
            (
                BundleKind::NvdCve,
                chrono::Utc::now().format("%Y%m%d").to_string(),
                vec![(
                    "nvd.json".into(),
                    serde_json::to_vec(&serde_json::json!({"vulnerabilities": all}))?,
                )],
            )
        }
        Cmd::Kev => {
            let body = ureq::get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json").call()?.into_string()?;
            (
                BundleKind::CisaKev,
                chrono::Utc::now().format("%Y%m%d").to_string(),
                vec![("kev.json".into(), body.into_bytes())],
            )
        }
        Cmd::Rules { dir, kind } => {
            let k = match kind.as_str() {
                "sigma" => BundleKind::SigmaRules,
                "yara" => BundleKind::YaraRules,
                _ => BundleKind::CisBaseline,
            };
            let files = std::fs::read_dir(&dir)?
                .flatten()
                .filter(|e| e.path().is_file())
                .map(|e| {
                    Ok((
                        e.file_name().to_string_lossy().to_string(),
                        std::fs::read(e.path())?,
                    ))
                })
                .collect::<Result<Vec<_>>>()?;
            (
                k,
                chrono::Utc::now().format("%Y%m%d%H%M").to_string(),
                files,
            )
        }
        Cmd::Agent { msi, version } => (
            BundleKind::AgentUpdate,
            version,
            vec![("hostvigil-agent.msi".into(), std::fs::read(&msi)?)],
        ),
    };
    let path = write_bundle(&key, kind, &version, files, &cli.out)?;
    println!("{}", path.display());
    Ok(())
}

pub fn write_bundle(
    key: &SigningKey,
    kind: BundleKind,
    version: &str,
    files: Vec<(String, Vec<u8>)>,
    out: &str,
) -> Result<std::path::PathBuf> {
    let mut tarb = tar::Builder::new(Vec::new());
    let mut manifest_files = vec![];
    for (name, data) in &files {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        tarb.append_data(&mut h, name, data.as_slice())?;
        manifest_files.push(BundleFile {
            path: name.clone(),
            sha256: hv_common::sha256_hex(data),
            size: data.len() as u64,
        });
    }
    let tar = tarb.into_inner()?;
    let digest = BundleManifest::compute_digest(&manifest_files);
    let manifest = BundleManifest {
        kind: kind.clone(),
        version: version.to_string(),
        created_at: chrono::Utc::now(),
        files: manifest_files,
        digest,
    };
    let mbytes = serde_json::to_vec(&manifest)?;
    let sig = hv_common::signing::sign(key, &mbytes);
    let mut out_bytes = Vec::new();
    out_bytes.extend((mbytes.len() as u64).to_le_bytes());
    out_bytes.extend(&mbytes);
    out_bytes.extend(sig);
    out_bytes.extend(zstd::encode_all(tar.as_slice(), 9)?);
    let kind_s = serde_json::to_string(&kind)?.trim_matches('"').to_string();
    let path = std::path::Path::new(out).join(format!("{kind_s}-{version}.hvb"));
    std::fs::write(&path, out_bytes)?;
    Ok(path)
}

fn load_key(hex_or_path: &str) -> Result<SigningKey> {
    let hex = if std::path::Path::new(hex_or_path).exists() {
        std::fs::read_to_string(hex_or_path)?.trim().to_string()
    } else {
        hex_or_path.to_string()
    };
    anyhow::ensure!(hex.len() == 64, "signing key must be 32 bytes hex");
    let mut b = [0u8; 32];
    for i in 0..32 {
        b[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)?;
    }
    Ok(SigningKey::from_bytes(&b))
}
