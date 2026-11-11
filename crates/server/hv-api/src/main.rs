//! hv-api: REST + WebSocket for the HUD, local auth (Argon2id + JWT), RBAC,
//! audit log. Serves the built HUD from embedded assets so one binary is the
//! whole web tier. Routes mirror the HUD's data needs one-to-one.

mod auth;
mod routes;

use anyhow::Result;
use axum::{
    routing::{get, post},
    Router,
};
use clickhouse::Client as Ch;
use rust_embed::RustEmbed;
use sqlx::PgPool;
use std::sync::Arc;
use tower_http::{compression::CompressionLayer, cors::CorsLayer, trace::TraceLayer};

#[derive(RustEmbed)]
#[folder = "../../../hud/dist/"]
pub struct HudAssets;

#[derive(Clone)]
pub struct App {
    pub pg: PgPool,
    pub ch: Ch,
    pub jwt_secret: Arc<String>,
    pub bus: tokio::sync::broadcast::Sender<String>,
}

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
    let ch = Ch::default()
        .with_url(
            std::env::var("HV_CLICKHOUSE_URL").unwrap_or_else(|_| "http://clickhouse:8123".into()),
        )
        .with_database("hostvigil");
    let (bus, _) = tokio::sync::broadcast::channel(1024);
    let app = App {
        pg,
        ch,
        jwt_secret: Arc::new(
            std::env::var("HV_JWT_SECRET").unwrap_or_else(|_| uuid::Uuid::new_v4().to_string()),
        ),
        bus,
    };
    auth::ensure_bootstrap_admin(&app).await?;

    let api = Router::new()
        .route("/auth/login", post(auth::login))
        .route("/me", get(auth::me))
        .route("/overview", get(routes::overview))
        .route("/hosts", get(routes::hosts))
        .route("/hosts/:id", get(routes::host))
        .route("/hosts/:id/flows", get(routes::host_flows))
        .route("/hosts/:id/files", get(routes::host_files))
        .route("/hosts/:id/alerts", get(routes::host_alerts))
        .route("/hosts/:id/process-tree", get(routes::host_process_tree))
        .route(
            "/hosts/:id/isolate",
            post(routes::isolate).layer(auth::require("enforcer")),
        )
        .route(
            "/hosts/:id/remediate",
            post(routes::remediate).layer(auth::require("enforcer")),
        )
        .route("/flows/graph", get(routes::flow_graph))
        .route("/flows", get(routes::flows))
        .route("/alerts", get(routes::alerts))
        .route(
            "/alerts/:id/ack",
            post(routes::ack_alert).layer(auth::require("analyst")),
        )
        .route("/vulns", get(routes::vulns))
        .route("/vulns/matrix", get(routes::vuln_matrix))
        .route("/fim/changes", get(routes::fim_changes))
        .route("/allowlist/queue", get(routes::allow_queue))
        .route(
            "/allowlist/decide",
            post(routes::allow_decide).layer(auth::require("policy_author")),
        )
        .route("/policy", get(routes::policy_get))
        .route(
            "/policy/simulate",
            post(routes::policy_simulate).layer(auth::require("policy_author")),
        )
        .route(
            "/policy/stage",
            post(routes::policy_stage).layer(auth::require("policy_author")),
        )
        .route(
            "/policy/enforce",
            post(routes::policy_enforce).layer(auth::require("enforcer")),
        )
        .route("/fleet", get(routes::fleet))
        .route(
            "/fleet/update",
            post(routes::fleet_update).layer(auth::require("admin")),
        )
        .route(
            "/feeds/import",
            post(routes::feeds_import).layer(auth::require("admin")),
        )
        .route("/audit", get(routes::audit).layer(auth::require("admin")))
        .route("/ws", get(routes::ws))
        .layer(axum::middleware::from_fn_with_state(
            app.clone(),
            auth::jwt_middleware,
        ));

    let router = Router::new()
        .nest("/api/v1", api)
        .fallback(routes::hud_static)
        .layer(CompressionLayer::new())
        .layer(CorsLayer::very_permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(app);

    let addr = std::env::var("HV_API_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".into());
    tracing::info!(%addr, "hv-api listening");
    axum::serve(tokio::net::TcpListener::bind(&addr).await?, router).await?;
    Ok(())
}
