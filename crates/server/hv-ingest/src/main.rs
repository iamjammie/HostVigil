//! hv-ingest: terminates agent mTLS gRPC streams, validates sequence numbers,
//! batches events into ClickHouse, stores inventory/baseline documents in
//! PostgreSQL, and relays signed commands from hv-policy to connected agents.

mod store;
mod validate;

use anyhow::Result;
use hv_proto::{
    agent_message, server_message,
    telemetry_server::{Telemetry, TelemetryServer},
    Ack, AgentMessage, ServerMessage,
};
use std::{collections::HashMap, pin::Pin, sync::Arc};
use tokio::sync::{mpsc, RwLock};
use tokio_stream::{wrappers::ReceiverStream, Stream, StreamExt};
use tonic::{
    transport::{Certificate, Identity, Server, ServerTlsConfig},
    Request, Response, Status, Streaming,
};
use tracing::{info, warn};

/// Connected agents, keyed by host_id, so hv-policy can push commands.
pub type Fleet = Arc<RwLock<HashMap<String, mpsc::Sender<ServerMessage>>>>;

pub struct Ingest {
    store: Arc<store::Store>,
    fleet: Fleet,
}

#[tonic::async_trait]
impl Telemetry for Ingest {
    type StreamStream = Pin<Box<dyn Stream<Item = Result<ServerMessage, Status>> + Send>>;

    async fn stream(
        &self,
        req: Request<Streaming<AgentMessage>>,
    ) -> Result<Response<Self::StreamStream>, Status> {
        // mTLS: the peer certificate CN must equal the host_id announced in Hello.
        let peer_cn = req
            .peer_certs()
            .and_then(|c| c.first().map(|cert| store::cn_from_der(cert.as_ref())))
            .flatten();
        let mut inbound = req.into_inner();
        let (tx, rx) = mpsc::channel::<ServerMessage>(64);
        let store = self.store.clone();
        let fleet = self.fleet.clone();
        tokio::spawn(async move {
            let mut host_id = String::new();
            let mut expected_seq: Option<u64> = None;
            let mut acked = 0u64;
            while let Some(msg) = inbound.next().await {
                let Ok(AgentMessage { body: Some(body) }) = msg else {
                    break;
                };
                match body {
                    agent_message::Body::Hello(h) => {
                        if let Some(cn) = &peer_cn {
                            if cn != &h.host_id {
                                warn!(cn, host = %h.host_id, "certificate / host_id mismatch; closing");
                                break;
                            }
                        }
                        host_id = h.host_id.clone();
                        store.upsert_host(&h).await.ok();
                        fleet.write().await.insert(host_id.clone(), tx.clone());
                        info!(host = %host_id, version = %h.agent_version, "agent connected");
                    }
                    agent_message::Body::Events(b) => {
                        let now = chrono::Utc::now().timestamp_millis() as u64;
                        let (good, bad) =
                            validate::validate_batch(&b, expected_seq.map(|s| s - 1), now);
                        if !bad.is_empty() {
                            warn!(host = %host_id, rejected = bad.len(), first = %bad[0].1, "events failed validation");
                            store.record_violations(&host_id, &bad).await.ok();
                        }
                        for e in &good {
                            if let Some(exp) = expected_seq {
                                if e.seq > exp {
                                    store.record_gap(&host_id, exp, e.seq).await.ok();
                                }
                            }
                            expected_seq = Some(e.seq + 1);
                            acked = e.seq;
                        }
                        // ack everything the agent sent (good or rejected) so it does not replay bad events forever
                        if let Some(last) = b.events.iter().map(|e| e.seq).max() {
                            acked = acked.max(last);
                        }
                        if good.is_empty() || store.write_events(&good).await.is_ok() {
                            let _ = tx
                                .send(ServerMessage {
                                    body: Some(server_message::Body::Ack(Ack { up_to_seq: acked })),
                                })
                                .await;
                        } else {
                            warn!("clickhouse write failed; not acking so the agent replays");
                        }
                    }
                    agent_message::Body::Heartbeat(hb) => {
                        store.heartbeat(&host_id, &hb).await.ok();
                    }
                    agent_message::Body::Inventory(inv) => {
                        store.write_inventory(&host_id, &inv).await.ok();
                    }
                    agent_message::Body::Baseline(b) => {
                        store.write_baseline(&host_id, &b).await.ok();
                    }
                    agent_message::Body::Result(r) => {
                        store.command_result(&host_id, &r).await.ok();
                    }
                }
            }
            if !host_id.is_empty() {
                fleet.write().await.remove(&host_id);
                info!(host = %host_id, "agent disconnected");
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(rx).map(Ok))))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();
    let cfg = store::Config::from_env()?;
    let store = Arc::new(store::Store::connect(&cfg).await?);
    let fleet: Fleet = Default::default();
    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(
            std::fs::read(&cfg.tls_cert)?,
            std::fs::read(&cfg.tls_key)?,
        ))
        .client_ca_root(Certificate::from_pem(std::fs::read(&cfg.ca_cert)?)); // require client certs
    let addr = cfg.listen.parse()?;
    info!(%addr, "hv-ingest listening (mTLS)");
    // hv-ca's Enrolment service is mounted on the same port by hv-ca binary in the compose bundle;
    // in single-binary mode it is added here via add_service.
    Server::builder()
        .tls_config(tls)?
        .add_service(
            TelemetryServer::new(Ingest { store, fleet }).max_decoding_message_size(16 << 20),
        )
        .serve(addr)
        .await?;
    Ok(())
}
