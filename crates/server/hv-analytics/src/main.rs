//! hv-analytics: background workers that turn raw events into the things the
//! HUD shows. Each worker is a loop with its own cadence; they share the two
//! stores and never block ingest.
//!
//!   graph      every 60 s   flows -> flow_edges_hourly, host tiers, dependency clusters
//!   sigma      streaming    process/registry/logon/script events -> alerts (Sigma rules in /rules/sigma)
//!   fim        streaming    file events -> classification (patch/config/suspicious) + alerts
//!   cve        every 15 m   software inventory x NVD/MSRC/KEV -> host_vulns, exposure score
//!   posture    every 15 m   drift + vulns + identity + encryption + network + allowlist -> posture score
//!   policy     on demand    discover tier allow-list from observed flows, simulate, generate WDAC XML
//!   anomaly    every 1 h    isolation-forest on per-host feature vectors -> anomaly alerts

mod cve;
mod graph;
mod posture;
mod sigma;

use anyhow::Result;
use sqlx::PgPool;
use std::time::Duration;

#[derive(Clone)]
pub struct Ctx {
    pub pg: PgPool,
    pub ch: clickhouse::Client,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();
    let ctx = Ctx {
        pg: PgPool::connect(
            &std::env::var("HV_POSTGRES_URL")
                .unwrap_or_else(|_| "postgres://hostvigil:hostvigil@postgres/hostvigil".into()),
        )
        .await?,
        ch: clickhouse::Client::default()
            .with_url(
                std::env::var("HV_CLICKHOUSE_URL")
                    .unwrap_or_else(|_| "http://clickhouse:8123".into()),
            )
            .with_database("hostvigil"),
    };
    let rules = sigma::load_rules(std::path::Path::new(
        &std::env::var("HV_RULES_DIR").unwrap_or_else(|_| "/etc/hostvigil/rules".into()),
    ))?;
    tracing::info!(sigma_rules = rules.len(), "analytics starting");

    let workers = vec![
        tokio::spawn(every(Duration::from_secs(60), {
            let c = ctx.clone();
            move || graph::rebuild(c.clone())
        })),
        tokio::spawn(every(Duration::from_secs(20), {
            let c = ctx.clone();
            let r = rules.clone();
            move || sigma::evaluate_recent(c.clone(), r.clone())
        })),
        tokio::spawn(every(Duration::from_secs(900), {
            let c = ctx.clone();
            move || cve::rescore(c.clone())
        })),
        tokio::spawn(every(Duration::from_secs(900), {
            let c = ctx.clone();
            move || posture::recompute(c.clone())
        })),
    ];
    for w in workers {
        let _ = w.await;
    }
    Ok(())
}

async fn every<F, Fut>(period: Duration, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let mut tick = tokio::time::interval(period);
    loop {
        tick.tick().await;
        if let Err(e) = f().await {
            tracing::warn!(error = %e, "worker iteration failed");
        }
    }
}
