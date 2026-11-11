//! Storage adapters: ClickHouse for high-volume events, PostgreSQL for state.

use anyhow::Result;
use clickhouse::{Client, Row};
use hv_proto::{
    event::Body, BaselineSnapshot, CommandResult, Event, Heartbeat, Hello, InventorySnapshot,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub listen: String,
    pub clickhouse_url: String,
    pub postgres_url: String,
    pub tls_cert: String,
    pub tls_key: String,
    pub ca_cert: String,
}
impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(config::Config::builder()
            .set_default("listen", "0.0.0.0:8443")?
            .set_default("clickhouse_url", "http://clickhouse:8123")?
            .set_default(
                "postgres_url",
                "postgres://hostvigil:hostvigil@postgres/hostvigil",
            )?
            .set_default("tls_cert", "/etc/hostvigil/tls/server.pem")?
            .set_default("tls_key", "/etc/hostvigil/tls/server.key")?
            .set_default("ca_cert", "/etc/hostvigil/tls/ca.pem")?
            .add_source(config::Environment::with_prefix("VC"))
            .build()?
            .try_deserialize()?)
    }
}

pub struct Store {
    ch: Client,
    pg: PgPool,
}

/// Flattened ClickHouse row. One wide table keeps queries simple; the HUD's
/// per-kind views are materialised views over it (see deploy/compose/clickhouse/init.sql).
#[derive(Row, Serialize, Deserialize, Debug, Default)]
pub struct EventRow {
    pub host_id: String,
    pub boot_id: String,
    pub seq: u64,
    pub ts_wall_ms: u64,
    pub ts_recv_ms: u64,
    pub kind: String, // process | flow | file | registry | logon | script | image | allowlist | policy_hit | drift
    pub pid: u32,
    pub ppid: u32,
    pub image: String,
    pub user: String,
    pub sha256: String,
    pub signer: String,
    pub path: String,
    pub detail: String, // command line / registry value / rule text
    pub src_ip: String,
    pub src_port: u32,
    pub dst_ip: String,
    pub dst_port: u32,
    pub protocol: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub direction: u8,
    pub blocked: u8,
    pub severity: String,
    pub rule_id: String,
    pub extra: String, // JSON for anything kind-specific
}

impl Store {
    pub async fn connect(cfg: &Config) -> Result<Self> {
        let ch = Client::default()
            .with_url(&cfg.clickhouse_url)
            .with_database("hostvigil");
        let pg = PgPool::connect(&cfg.postgres_url).await?;
        sqlx::migrate!("../../../deploy/compose/postgres/migrations")
            .run(&pg)
            .await?;
        Ok(Self { ch, pg })
    }

    pub async fn write_events(&self, events: &[Event]) -> Result<()> {
        let now = chrono::Utc::now().timestamp_millis() as u64;
        let mut ins = self.ch.insert("events")?;
        for e in events {
            ins.write(&flatten(e, now)).await?;
        }
        ins.end().await?;
        Ok(())
    }

    pub async fn upsert_host(&self, h: &Hello) -> Result<()> {
        sqlx::query("INSERT INTO hosts(host_id, hostname, os_version, agent_version, ips, last_seen) VALUES($1,$2,$3,$4,$5,now())
                     ON CONFLICT(host_id) DO UPDATE SET hostname=$2, os_version=$3, agent_version=$4, ips=$5, last_seen=now(), online=true")
            .bind(&h.host_id).bind(&h.hostname).bind(&h.os_version).bind(&h.agent_version).bind(&h.ips).execute(&self.pg).await?;
        Ok(())
    }
    pub async fn heartbeat(&self, host_id: &str, hb: &Heartbeat) -> Result<()> {
        sqlx::query("UPDATE hosts SET last_seen=now(), online=true, queue_depth=$2, cpu_pct=$3, mem_mb=$4, modules=$5 WHERE host_id=$1")
            .bind(host_id).bind(hb.queue_depth as i32).bind(hb.cpu_pct).bind(hb.mem_mb as i32).bind(serde_json::to_value(hb.modules.iter().map(|(k, v)| (k, (v.running, v.events_emitted, v.events_dropped))).collect::<std::collections::HashMap<_, _>>())?).execute(&self.pg).await?;
        Ok(())
    }
    pub async fn write_inventory(&self, host_id: &str, inv: &InventorySnapshot) -> Result<()> {
        let doc = serde_json::to_value(ProtoJson(inv))?;
        sqlx::query("INSERT INTO host_inventory(host_id, ts, doc) VALUES($1, now(), $2)")
            .bind(host_id)
            .bind(doc)
            .execute(&self.pg)
            .await?;
        sqlx::query("UPDATE hosts SET inventory_at=now() WHERE host_id=$1")
            .bind(host_id)
            .execute(&self.pg)
            .await?;
        Ok(())
    }
    pub async fn write_baseline(&self, host_id: &str, b: &BaselineSnapshot) -> Result<()> {
        sqlx::query(
            "INSERT INTO baselines(host_id, ts, sha256, doc_zstd) VALUES($1, now(), $2, $3)",
        )
        .bind(host_id)
        .bind(&b.sha256)
        .bind(&b.canonical_json_zstd)
        .execute(&self.pg)
        .await?;
        Ok(())
    }
    pub async fn record_violations(
        &self,
        host_id: &str,
        bad: &[(u64, crate::validate::Violation)],
    ) -> Result<()> {
        for (seq, v) in bad.iter().take(50) {
            sqlx::query(
                "INSERT INTO ingest_violations(host_id, seq, violation, ts) VALUES($1,$2,$3,now())",
            )
            .bind(host_id)
            .bind(*seq as i64)
            .bind(v.to_string())
            .execute(&self.pg)
            .await?;
        }
        sqlx::query("UPDATE hosts SET violations = COALESCE(violations,0) + $2 WHERE host_id=$1")
            .bind(host_id)
            .bind(bad.len() as i64)
            .execute(&self.pg)
            .await?;
        Ok(())
    }
    pub async fn record_gap(&self, host_id: &str, expected: u64, got: u64) -> Result<()> {
        tracing::warn!(host = host_id, expected, got, "sequence gap");
        sqlx::query(
            "INSERT INTO ingest_gaps(host_id, expected_seq, got_seq, ts) VALUES($1,$2,$3,now())",
        )
        .bind(host_id)
        .bind(expected as i64)
        .bind(got as i64)
        .execute(&self.pg)
        .await?;
        Ok(())
    }
    pub async fn command_result(&self, host_id: &str, r: &CommandResult) -> Result<()> {
        sqlx::query("UPDATE commands SET status=$3, message=$4, completed_at=now() WHERE command_id=$1 AND host_id=$2").bind(&r.command_id).bind(host_id).bind(if r.ok { "ok" } else { "failed" }).bind(&r.message).execute(&self.pg).await?;
        Ok(())
    }
}

/// Minimal serde bridge for prost messages (prost-serde is avoided to keep the build offline-friendly).
struct ProtoJson<'a, T: prost::Message>(&'a T);
impl<T: prost::Message> Serialize for ProtoJson<'_, T> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hv_common::hex(&self.0.encode_to_vec()))
    }
}

pub fn flatten(e: &Event, now: u64) -> EventRow {
    let mut r = EventRow {
        host_id: e.host_id.clone(),
        boot_id: e.boot_id.clone(),
        seq: e.seq,
        ts_wall_ms: e.ts_wall_ms,
        ts_recv_ms: now,
        ..Default::default()
    };
    match &e.body {
        Some(Body::Process(p)) => {
            r.kind = "process".into();
            r.pid = p.pid;
            r.ppid = p.ppid;
            r.image = p.image.clone();
            r.user = p.user.clone();
            r.sha256 = p.sha256.clone();
            r.signer = p.signer.clone();
            r.detail = p.command_line.clone();
            r.extra = format!(
                r#"{{"kind":{},"parent":"{}","sigvalid":{}}}"#,
                p.kind,
                p.parent_image.replace('"', "'"),
                p.signature_valid
            );
        }
        Some(Body::Flow(f)) => {
            r.kind = "flow".into();
            r.pid = f.pid;
            r.image = f.image.clone();
            r.user = f.user.clone();
            r.src_ip = f.local_ip.clone();
            r.src_port = f.local_port;
            r.dst_ip = f.remote_ip.clone();
            r.dst_port = f.remote_port;
            r.protocol = f.protocol.clone();
            r.bytes_in = f.bytes_in;
            r.bytes_out = f.bytes_out;
            r.direction = f.direction as u8;
            r.blocked = f.blocked_by_policy as u8;
            r.rule_id = f.policy_id.clone();
        }
        Some(Body::File(f)) => {
            r.kind = "file".into();
            r.pid = f.pid;
            r.image = f.image.clone();
            r.user = f.user.clone();
            r.path = f.path.clone();
            r.sha256 = f.sha256_after.clone();
            r.signer = f.signer.clone();
            r.extra = format!(
                r#"{{"kind":{},"old_path":"{}","sha_before":"{}","usn":{}}}"#,
                f.kind,
                f.old_path.replace('"', "'"),
                f.sha256_before,
                f.usn
            );
        }
        Some(Body::Registry(x)) => {
            r.kind = "registry".into();
            r.pid = x.pid;
            r.image = x.image.clone();
            r.user = x.user.clone();
            r.path = format!("{}\\{}", x.key, x.value_name);
            r.detail = x.value_data.clone();
        }
        Some(Body::Logon(l)) => {
            r.kind = "logon".into();
            r.user = format!("{}\\{}", l.domain, l.user);
            r.src_ip = l.source_ip.clone();
            r.detail = format!(
                "type={} pkg={} id={} ok={}",
                l.logon_type, l.auth_package, l.event_id, l.success
            );
        }
        Some(Body::Script(s)) => {
            r.kind = "script".into();
            r.pid = s.pid;
            r.user = s.user.clone();
            r.sha256 = s.sha256.clone();
            r.detail = s.text.chars().take(8000).collect();
        }
        Some(Body::Image(i)) => {
            r.kind = "image".into();
            r.pid = i.pid;
            r.image = i.image.clone();
            r.path = i.loaded.clone();
            r.sha256 = i.sha256.clone();
            r.signer = i.signer.clone();
        }
        Some(Body::Allowlist(a)) => {
            r.kind = "allowlist".into();
            r.pid = a.pid;
            r.user = a.user.clone();
            r.path = a.path.clone();
            r.sha256 = a.sha256.clone();
            r.signer = a.publisher.clone();
            r.rule_id = a.policy_id.clone();
            r.blocked = (a.verdict == 1) as u8;
        }
        Some(Body::PolicyHit(h)) => {
            r.kind = "policy_hit".into();
            r.rule_id = h.rule_id.clone();
            r.blocked = h.dropped as u8;
            if let Some(f) = &h.flow {
                r.dst_ip = f.remote_ip.clone();
                r.dst_port = f.remote_port;
                r.image = f.image.clone();
            }
        }
        Some(Body::Drift(d)) => {
            r.kind = "drift".into();
            r.rule_id = d.check_id.clone();
            r.severity = d.severity.clone();
            r.detail = format!("{}: expected {} got {}", d.title, d.expected, d.actual);
            r.blocked = d.resolved as u8;
        }
        None => {
            r.kind = "unknown".into();
        }
    }
    r
}

pub fn cn_from_der(der: &[u8]) -> Option<String> {
    // x509-parser lives in hv-ca; a tiny scan for the CN OID (2.5.4.3) keeps hv-ingest light.
    let oid = [0x06, 0x03, 0x55, 0x04, 0x03];
    let i = der.windows(5).position(|w| w == oid)? + 5;
    let len = *der.get(i + 1)? as usize;
    std::str::from_utf8(der.get(i + 2..i + 2 + len)?)
        .ok()
        .map(|s| s.to_string())
}
