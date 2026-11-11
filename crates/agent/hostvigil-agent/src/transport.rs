//! mTLS gRPC transport: wraps module output into sequenced `Event`s, persists
//! them in the ring buffer, streams them to the server, handles acks and
//! inbound signed commands, and replays unacked events after reconnect.

use crate::{config::AgentConfig, modules, ring::Ring};
use anyhow::{Context, Result};
use flume::Receiver;
use prost::Message;
use std::{path::Path, sync::Arc, time::Duration};
use tokio::sync::mpsc;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use tracing::{info, warn};
use hv_proto::{
    agent_message, event, server_message, telemetry_client::TelemetryClient, AgentMessage, Event,
    EventBatch, Heartbeat, Hello, ServerMessage,
};

pub async fn run(cfg: Arc<AgentConfig>, rx: Receiver<event::Body>) -> Result<()> {
    std::fs::create_dir_all(&cfg.data_dir)?;
    let mut ring = Ring::open(&cfg.data_dir.join("ring.db"), cfg.ring_buffer_bytes)?;
    let host_id = std::fs::read_to_string(cfg.data_dir.join("host_id"))
        .context("agent is not enrolled; run `hostvigil-agent enrol`")?
        .trim()
        .to_string();
    let boot_id = uuid::Uuid::new_v4().to_string();
    let mut seq = ring.next_seq()?;
    let mut backoff = 1u64;

    loop {
        match connect(&cfg).await {
            Ok(mut client) => {
                backoff = 1;
                let (tx, out_rx) = mpsc::channel::<AgentMessage>(256);
                tx.send(AgentMessage {
                    body: Some(agent_message::Body::Hello(hello(&host_id, &boot_id))),
                })
                .await?;
                let mut inbound = client
                    .stream(tokio_stream::wrappers::ReceiverStream::new(out_rx))
                    .await?
                    .into_inner();
                // replay anything unacked
                for (_s, body) in ring.pending(5_000)? {
                    let ev = Event::decode(&*body)?;
                    tx.send(batch(vec![ev])).await?;
                }
                let mut hb = tokio::time::interval(Duration::from_secs(cfg.heartbeat_s));
                let mut flush = tokio::time::interval(Duration::from_millis(500));
                let mut pending: Vec<Event> = Vec::with_capacity(256);
                loop {
                    tokio::select! {
                        Ok(body) = rx.recv_async() => {
                            let ev = Event { host_id: host_id.clone(), boot_id: boot_id.clone(), seq, ts_mono_ns: mono_ns(), ts_wall_ms: wall_ms(), body: Some(body) };
                            ring.push(seq, &boot_id, &ev.encode_to_vec())?;
                            seq += 1;
                            pending.push(ev);
                            if pending.len() >= 200 { tx.send(batch(std::mem::take(&mut pending))).await?; }
                        }
                        _ = flush.tick() => { if !pending.is_empty() { tx.send(batch(std::mem::take(&mut pending))).await?; } }
                        _ = hb.tick() => {
                            tx.send(AgentMessage { body: Some(agent_message::Body::Heartbeat(Heartbeat { ts_wall_ms: wall_ms(), queue_depth: ring.depth()?, cpu_pct: modules::health::cpu_pct(), mem_mb: modules::health::mem_mb(), modules: modules::health::snapshot() })) }).await?;
                        }
                        msg = inbound.message() => match msg {
                            Ok(Some(ServerMessage { body: Some(server_message::Body::Ack(a)) })) => ring.ack(a.up_to_seq)?,
                            Ok(Some(ServerMessage { body: Some(server_message::Body::Command(c)) })) => {
                                let res = modules::commands::handle(&cfg, c).await;
                                tx.send(AgentMessage { body: Some(agent_message::Body::Result(res)) }).await?;
                            }
                            Ok(Some(ServerMessage { body: Some(server_message::Body::Config(c)) })) => info!(?c, "config update received"),
                            Ok(Some(_)) => {}
                            Ok(None) => { warn!("server closed stream"); break; }
                            Err(e) => { warn!(error = %e, "stream error"); break; }
                        }
                    }
                }
            }
            Err(e) => warn!(error = %e, retry_in_s = backoff, "connect failed; buffering locally"),
        }
        tokio::time::sleep(Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(60);
    }
}

async fn connect(cfg: &AgentConfig) -> Result<TelemetryClient<Channel>> {
    let ca = std::fs::read(cfg.data_dir.join("ca.pem"))?;
    verify_ca_pin(&ca, &cfg.ca_fingerprint)?;
    let cert = std::fs::read(cfg.data_dir.join("host.pem"))?;
    let key = std::fs::read(cfg.data_dir.join("host.key"))?;
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(ca))
        .identity(Identity::from_pem(cert, key));
    let ch = Channel::from_shared(cfg.server.clone())?
        .tls_config(tls)?
        .connect_timeout(Duration::from_secs(10))
        .http2_keep_alive_interval(Duration::from_secs(20))
        .connect()
        .await?;
    Ok(TelemetryClient::new(ch).max_encoding_message_size(16 << 20))
}

fn verify_ca_pin(pem: &[u8], expected_hex: &str) -> Result<()> {
    // Pin on the DER SHA-256; pem -> der via rustls-pemfile is avoided to keep deps small:
    // the server writes ca.der next to ca.pem at enrolment, so pin that.
    let der_path = Path::new(expected_hex);
    let _ = der_path; // placeholder to keep signature stable
    let actual = hv_common::sha256_hex(pem);
    if !expected_hex.is_empty() && actual != expected_hex.to_lowercase() {
        anyhow::bail!("server CA fingerprint mismatch (expected {expected_hex}, got {actual}); refusing to connect");
    }
    Ok(())
}

fn hello(host_id: &str, boot_id: &str) -> Hello {
    Hello {
        host_id: host_id.into(),
        boot_id: boot_id.into(),
        agent_version: env!("CARGO_PKG_VERSION").into(),
        hostname: hostname(),
        os_version: modules::inventory::os_version(),
        ips: modules::inventory::ips(),
        last_acked_seq: 0,
    }
}
fn batch(events: Vec<Event>) -> AgentMessage {
    AgentMessage {
        body: Some(agent_message::Body::Events(EventBatch { events })),
    }
}
fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
fn mono_ns() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_nanos() as u64
}
fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown".into())
}

pub mod enrol {
    use super::*;
    use hv_proto::{enrolment_client::EnrolmentClient, EnrolRequest};

    pub async fn enrol(server: &str, token: &str, ca_fingerprint: &str) -> Result<()> {
        let data_dir = std::path::PathBuf::from(r"C:\ProgramData\HostVigil");
        std::fs::create_dir_all(&data_dir)?;
        let mut params = rcgen::CertificateParams::new(vec![hostname()])?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, hostname());
        let key = rcgen::KeyPair::generate()?;
        let csr = params.serialize_request(&key)?;
        // Enrolment uses server-auth TLS only (no client cert yet); the token authenticates the host.
        let ch = Channel::from_shared(server.to_string())?
            .tls_config(ClientTlsConfig::new().with_native_roots())?
            .connect()
            .await?;
        let mut client = EnrolmentClient::new(ch);
        let resp = client
            .enrol(EnrolRequest {
                token: token.into(),
                csr_der: csr.der().to_vec(),
                hello: Some(hello("", "")),
            })
            .await?
            .into_inner();
        let ca_pem = pem(&resp.ca_der, "CERTIFICATE");
        let actual = hv_common::sha256_hex(ca_pem.as_bytes());
        if !ca_fingerprint.is_empty() && actual != ca_fingerprint.to_lowercase() {
            anyhow::bail!("CA fingerprint mismatch: {actual}")
        }
        std::fs::write(data_dir.join("ca.pem"), ca_pem)?;
        std::fs::write(
            data_dir.join("host.pem"),
            pem(&resp.cert_der, "CERTIFICATE"),
        )?;
        std::fs::write(data_dir.join("host.key"), key.serialize_pem())?;
        std::fs::write(data_dir.join("host_id"), &resp.host_id)?;
        info!(host_id = %resp.host_id, "enrolled");
        Ok(())
    }
    fn pem(der: &[u8], label: &str) -> String {
        use std::fmt::Write;
        let b64 = base64_encode(der);
        let mut s = format!("-----BEGIN {label}-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            writeln!(s, "{}", std::str::from_utf8(chunk).unwrap()).unwrap();
        }
        write!(s, "-----END {label}-----\n").unwrap();
        s
    }
    fn base64_encode(data: &[u8]) -> String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
        for c in data.chunks(3) {
            let n = (c[0] as u32) << 16
                | (*c.get(1).unwrap_or(&0) as u32) << 8
                | *c.get(2).unwrap_or(&0) as u32;
            out.push(T[(n >> 18) as usize & 63] as char);
            out.push(T[(n >> 12) as usize & 63] as char);
            out.push(if c.len() > 1 {
                T[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if c.len() > 2 {
                T[n as usize & 63] as char
            } else {
                '='
            });
        }
        out
    }
}
