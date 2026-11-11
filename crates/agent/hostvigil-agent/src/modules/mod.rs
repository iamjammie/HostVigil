//! Telemetry and enforcement modules. Each exposes
//! `pub async fn run(cfg: Arc<AgentConfig>, tx: EventTx) -> anyhow::Result<()>`
//! and emits `hv_proto::event::Body` values. Windows-specific code is gated
//! with `#[cfg(windows)]`; other platforms get a no-op so the crate still
//! builds in CI on Linux runners.

pub mod allowlist;
pub mod baseline;
pub mod commands;
pub mod etw;
pub mod fim;
pub mod health;
pub mod inventory;
pub mod wfp;
