use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// gRPC endpoint, e.g. https://hostvigil.corp.local:8443
    pub server: String,
    /// SHA-256 fingerprint of the server CA certificate (pinned at enrolment).
    pub ca_fingerprint: String,
    /// Ed25519 public key (hex) used to verify commands, scripts and updates.
    pub command_pubkey: String,
    pub data_dir: PathBuf,
    #[serde(default = "d_ring")]
    pub ring_buffer_bytes: u64,
    #[serde(default = "d_hb")]
    pub heartbeat_s: u64,
    #[serde(default = "d_inv")]
    pub inventory_interval_s: u64,
    #[serde(default)]
    pub modules: Modules,
    #[serde(default)]
    pub fim: Vec<FimWatch>,
    #[serde(default = "d_budget")]
    pub cpu_budget_pct: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Modules {
    pub etw: bool,
    pub wfp: bool,
    pub fim: bool,
    pub inventory: bool,
    pub allowlist: bool,
    pub baseline: bool,
    pub remediate: bool,
}
impl Default for Modules {
    fn default() -> Self {
        Self {
            etw: true,
            wfp: true,
            fim: true,
            inventory: true,
            allowlist: true,
            baseline: true,
            remediate: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FimWatch {
    pub path: String,
    #[serde(default = "d_true")]
    pub recursive: bool,
    #[serde(default = "d_true")]
    pub hash: bool,
    #[serde(default)]
    pub exclude_globs: Vec<String>,
}

fn d_ring() -> u64 {
    2 * 1024 * 1024 * 1024
}
fn d_hb() -> u64 {
    30
}
fn d_inv() -> u64 {
    6 * 3600
}
fn d_budget() -> f32 {
    2.0
}
fn d_true() -> bool {
    true
}

impl AgentConfig {
    pub fn load(path: &str) -> Result<Self> {
        let cfg = config::Config::builder()
            .add_source(config::File::with_name(path).required(true))
            .add_source(config::Environment::with_prefix("HOSTVIGIL").separator("__"))
            .build()
            .with_context(|| format!("loading config {path}"))?;
        Ok(cfg.try_deserialize()?)
    }

    pub fn default_fim_watches() -> Vec<FimWatch> {
        [
            r"C:\Windows\System32\drivers\etc",
            r"C:\Windows\System32\config",
            r"C:\Windows\System32\Tasks",
            r"C:\Windows\Tasks",
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
            r"C:\inetpub\wwwroot",
            r"C:\Program Files",
            r"C:\Program Files (x86)",
        ]
        .iter()
        .map(|p| FimWatch {
            path: p.to_string(),
            recursive: true,
            hash: true,
            exclude_globs: vec!["*.log".into(), "*.tmp".into()],
        })
        .collect()
    }
}
