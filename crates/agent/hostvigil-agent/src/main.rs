//! HostVigil agent entry point.
//!
//! Runs as a Windows service (`hostvigil-agent run`) or in the foreground for
//! development (`hostvigil-agent run --foreground`). All telemetry modules
//! publish `Event`s onto a bounded channel; the transport task drains it,
//! persists to the SQLite ring buffer, and streams to the server over mTLS.

#![cfg_attr(not(windows), allow(dead_code))]

mod config;
mod modules;
mod ring;
mod supervisor;
mod transport;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::info;

#[derive(Parser)]
#[command(name = "hostvigil-agent", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the agent (as a service unless --foreground).
    Run {
        #[arg(long)]
        foreground: bool,
        #[arg(long, default_value = r"C:\ProgramData\HostVigil\agent.toml")]
        config: String,
    },
    /// Enrol with the server using a one-time token and write the host certificate.
    Enrol {
        #[arg(long)]
        server: String,
        #[arg(long)]
        token: String,
        #[arg(long)]
        ca_fingerprint: String,
    },
    /// Register / unregister the Windows service.
    Install,
    Uninstall,
    /// Print collected inventory as JSON and exit (no server needed).
    Inventory,
    /// Compute and print the baseline snapshot hash.
    Baseline,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Run { foreground, config } => {
            let cfg = config::AgentConfig::load(&config)?;
            if foreground {
                init_tracing(true);
                let rt = tokio::runtime::Runtime::new()?;
                rt.block_on(supervisor::run(cfg))
            } else {
                #[cfg(windows)]
                {
                    supervisor::service::run_as_service(cfg)
                }
                #[cfg(not(windows))]
                {
                    anyhow::bail!("service mode is only available on Windows; use --foreground")
                }
            }
        }
        Cmd::Enrol {
            server,
            token,
            ca_fingerprint,
        } => {
            init_tracing(true);
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(transport::enrol::enrol(&server, &token, &ca_fingerprint))
        }
        Cmd::Install => supervisor::service::install(),
        Cmd::Uninstall => supervisor::service::uninstall(),
        Cmd::Inventory => {
            init_tracing(true);
            let snap = modules::inventory::collect_now()?;
            println!("{}", serde_json::to_string_pretty(&snap)?);
            Ok(())
        }
        Cmd::Baseline => {
            init_tracing(true);
            let b = modules::baseline::snapshot()?;
            info!(hash = %b.sha256, "baseline computed");
            println!("{}", b.sha256);
            Ok(())
        }
    }
}

fn init_tracing(stdout: bool) {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    if stdout {
        fmt().with_env_filter(filter).init();
    } else {
        fmt().with_env_filter(filter).json().init();
    }
}
