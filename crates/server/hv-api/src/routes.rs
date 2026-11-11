//! HTTP handlers. Every list endpoint accepts the same global filter set the
//! HUD exposes: `range` (hours), `ou`, `tier`, `os`, `crit`, `sev`, `q`.

use crate::{
    auth::{audit, Claims},
    App, HudAssets,
};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, Query, State,
    },
    http::{header, StatusCode, Uri},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Deserialize, Default)]
pub struct Filters {
    pub range: Option<u32>,
    pub ou: Option<String>,
    pub tier: Option<String>,
    pub os: Option<String>,
    pub crit: Option<String>,
    pub sev: Option<String>,
    pub q: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

pub const TIERS: &[&str] = &["Web", "App", "DB", "DC", "Workstation", "Infra", "Unknown"];
pub const SEVERITIES: &[&str] = &["info", "low", "medium", "high", "critical"];
pub const CRITICALITY: &[&str] = &["Critical", "High", "Medium", "Low"];
pub const MAX_RANGE_HOURS: u32 = 24 * 90;
pub const MAX_LIMIT: u32 = 5_000;

/// Reject anything outside the closed vocabularies or bounds before it reaches SQL.
/// Free text (`q`, `ou`, `os`) is always bound as a parameter, never interpolated,
/// so it only gets a length cap here.
pub fn validate_filters(f: &Filters) -> Result<(), String> {
    if let Some(r) = f.range {
        if r == 0 || r > MAX_RANGE_HOURS {
            return Err(format!("range must be 1..={MAX_RANGE_HOURS} hours"));
        }
    }
    if let Some(l) = f.limit {
        if l == 0 || l > MAX_LIMIT {
            return Err(format!("limit must be 1..={MAX_LIMIT}"));
        }
    }
    let in_set = |v: &Option<String>, set: &[&str], name: &str| -> Result<(), String> {
        if let Some(v) = v {
            for part in v.split(',') {
                if !set.contains(&part) {
                    return Err(format!("unknown {name} '{part}'"));
                }
            }
        }
        Ok(())
    };
    in_set(&f.tier, TIERS, "tier")?;
    in_set(&f.sev, SEVERITIES, "severity")?;
    in_set(&f.crit, CRITICALITY, "criticality")?;
    for (v, name) in [(&f.q, "q"), (&f.ou, "ou"), (&f.os, "os")] {
        if let Some(v) = v {
            if v.len() > 256 {
                return Err(format!("{name} too long"));
            }
        }
    }
    Ok(())
}

pub fn is_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}
pub fn is_host_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}
pub fn is_tier_pair(s: &str) -> bool {
    s.split_once('>')
        .map(|(a, b)| TIERS.contains(&a) && TIERS.contains(&b))
        .unwrap_or(false)
}

impl Filters {
    /// Host scope as a SQL fragment with positional binds collected in `binds`.
    pub fn host_where(&self, binds: &mut Vec<String>) -> String {
        let mut w = vec!["true".to_string()];
        let mut add = |col: &str, v: &Option<String>| {
            if let Some(v) = v {
                for part in v.split(',') {
                    binds.push(part.to_string());
                }
                let n = binds.len();
                let start = n - v.split(',').count() + 1;
                w.push(format!(
                    "{col} = ANY(ARRAY[{}])",
                    (start..=n)
                        .map(|i| format!("${i}"))
                        .collect::<Vec<_>>()
                        .join(",")
                ));
            }
        };
        add("h.ou", &self.ou);
        add("h.tier", &self.tier);
        add("h.os_version", &self.os);
        add("h.criticality", &self.crit);
        if let Some(q) = &self.q {
            binds.push(format!("%{q}%"));
            let i = binds.len();
            w.push(format!("(h.host_id ILIKE ${i} OR h.hostname ILIKE ${i} OR h.os_version ILIKE ${i} OR h.ou ILIKE ${i})"));
        }
        w.join(" AND ")
    }
    pub fn since_ms(&self) -> i64 {
        (chrono::Utc::now() - chrono::Duration::hours(self.range.unwrap_or(168) as i64))
            .timestamp_millis()
    }
}

type R = Result<Json<Value>, StatusCode>;
fn bad(msg: String) -> StatusCode {
    tracing::debug!(%msg, "request rejected");
    StatusCode::BAD_REQUEST
}
pub fn validate_policy(p: &PolicyDoc) -> Result<(), String> {
    if p.allowed.len() > 64 {
        return Err("too many rules".into());
    }
    for r in &p.allowed {
        if !is_tier_pair(r) {
            return Err(format!("bad tier pair '{r}'"));
        }
    }
    if p.note.as_ref().map(|n| n.len() > 1024).unwrap_or(false) {
        return Err("note too long".into());
    }
    Ok(())
}
fn ise<E: std::fmt::Display>(e: E) -> StatusCode {
    tracing::error!(error = %e, "handler error");
    StatusCode::INTERNAL_SERVER_ERROR
}

#[derive(Serialize, sqlx::FromRow)]
pub struct HostRow {
    host_id: String,
    hostname: String,
    ip: Option<String>,
    tier: Option<String>,
    ou: Option<String>,
    os_version: String,
    criticality: Option<String>,
    posture: Option<i32>,
    vuln_count: Option<i64>,
    drift: Option<i64>,
    allow_mode: Option<String>,
    online: bool,
    last_seen: chrono::DateTime<chrono::Utc>,
    agent_version: String,
}

pub async fn hosts(State(app): State<App>, Query(f): Query<Filters>) -> R {
    validate_filters(&f).map_err(bad)?;
    let mut binds = vec![];
    let w = f.host_where(&mut binds);
    let sql = format!("SELECT h.host_id, h.hostname, h.ips[1] AS ip, h.tier, h.ou, h.os_version, h.criticality, h.posture, (SELECT COUNT(*) FROM host_vulns v WHERE v.host_id=h.host_id) AS vuln_count, (SELECT COUNT(*) FROM drift_findings d WHERE d.host_id=h.host_id AND NOT d.resolved) AS drift, h.allow_mode, h.online, h.last_seen, h.agent_version FROM hosts h WHERE {w} ORDER BY h.posture NULLS LAST LIMIT {} OFFSET {}", f.limit.unwrap_or(500), f.offset.unwrap_or(0));
    let mut q = sqlx::query_as::<_, HostRow>(&sql);
    for b in &binds {
        q = q.bind(b);
    }
    let rows = q.fetch_all(&app.pg).await.map_err(ise)?;
    Ok(Json(json!({ "hosts": rows, "total": rows.len() })))
}

pub async fn host(State(app): State<App>, Path(id): Path<String>) -> R {
    if !is_host_id(&id) {
        return Err(StatusCode::BAD_REQUEST);
    }
    if !is_host_id(&id) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let h: Option<Value> = sqlx::query_scalar("SELECT to_jsonb(h) - 'modules' || jsonb_build_object('inventory', (SELECT doc FROM host_inventory i WHERE i.host_id=h.host_id ORDER BY ts DESC LIMIT 1), 'vulns', (SELECT COALESCE(jsonb_agg(to_jsonb(v)),'[]') FROM host_vulns v JOIN vulnerabilities c USING(cve) WHERE v.host_id=h.host_id), 'drift', (SELECT COALESCE(jsonb_agg(to_jsonb(d)),'[]') FROM drift_findings d WHERE d.host_id=h.host_id AND NOT d.resolved)) FROM hosts h WHERE h.host_id=$1").bind(&id).fetch_optional(&app.pg).await.map_err(ise)?;
    h.map(Json).ok_or(StatusCode::NOT_FOUND)
}

async fn ch_json(app: &App, sql: &str) -> Result<Value, StatusCode> {
    let body = app
        .ch
        .query(&format!("{sql} FORMAT JSONEachRow"))
        .fetch_all::<String>()
        .await
        .map_err(ise)?;
    Ok(Value::Array(
        body.iter()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect(),
    ))
}

pub async fn host_flows(
    State(app): State<App>,
    Path(id): Path<String>,
    Query(f): Query<Filters>,
) -> R {
    validate_filters(&f).map_err(bad)?;
    if !is_host_id(&id) {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(Json(ch_json(&app, &format!("SELECT host_id, image, src_ip, src_port, dst_ip, dst_port, protocol, direction, sum(bytes_in) bytes_in, sum(bytes_out) bytes_out, count() c, max(ts_wall_ms) last FROM events WHERE kind='flow' AND host_id='{}' AND ts_wall_ms >= {} GROUP BY ALL ORDER BY last DESC LIMIT 500", esc(&id), f.since_ms())).await?))
}
pub async fn host_files(
    State(app): State<App>,
    Path(id): Path<String>,
    Query(f): Query<Filters>,
) -> R {
    validate_filters(&f).map_err(bad)?;
    if !is_host_id(&id) {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(Json(ch_json(&app, &format!("SELECT ts_wall_ms, path, image, user, sha256, extra FROM events WHERE kind='file' AND host_id='{}' AND ts_wall_ms >= {} ORDER BY ts_wall_ms DESC LIMIT 500", esc(&id), f.since_ms())).await?))
}
pub async fn host_alerts(
    State(app): State<App>,
    Path(id): Path<String>,
    Query(f): Query<Filters>,
) -> R {
    validate_filters(&f).map_err(bad)?;
    if !is_host_id(&id) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let rows: Vec<Value> = sqlx::query_scalar("SELECT to_jsonb(a) FROM alerts a WHERE host_id=$1 AND ts >= to_timestamp($2/1000.0) ORDER BY ts DESC LIMIT 500").bind(&id).bind(f.since_ms()).fetch_all(&app.pg).await.map_err(ise)?;
    Ok(Json(Value::Array(rows)))
}
pub async fn host_process_tree(State(app): State<App>, Path(id): Path<String>) -> R {
    if !is_host_id(&id) {
        return Err(StatusCode::BAD_REQUEST);
    }
    if !is_host_id(&id) {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(Json(ch_json(&app, &format!("SELECT pid, ppid, image, user, sha256, signer, detail cmd, ts_wall_ms FROM events WHERE kind='process' AND host_id='{}' AND JSONExtractInt(extra,'kind')=0 AND ts_wall_ms >= now64()*1000 - 86400000 ORDER BY ts_wall_ms DESC LIMIT 2000", esc(&id))).await?))
}

pub async fn flow_graph(State(app): State<App>, Query(f): Query<Filters>) -> R {
    validate_filters(&f).map_err(bad)?;
    // edges between known hosts, aggregated hourly by the materialised view
    let edges = ch_json(&app, &format!("SELECT src_host, dst_host, image, dst_port, sum(bytes) bytes, sum(c) c FROM flow_edges_hourly WHERE hour >= toDateTime({}/1000) GROUP BY ALL", f.since_ms())).await?;
    let mut binds = vec![];
    let w = f.host_where(&mut binds);
    let mut q = sqlx::query_scalar::<_, Value>(&format!("SELECT jsonb_agg(jsonb_build_object('id',h.host_id,'tier',h.tier,'ou',h.ou,'posture',h.posture,'online',h.online)) FROM hosts h WHERE {w}"));
    for b in &binds {
        q = q.bind(b);
    }
    let nodes = q.fetch_one(&app.pg).await.map_err(ise)?;
    Ok(Json(json!({ "nodes": nodes, "edges": edges })))
}
pub async fn flows(State(app): State<App>, Query(f): Query<Filters>) -> R {
    validate_filters(&f).map_err(bad)?;
    Ok(Json(ch_json(&app, &format!("SELECT host_id, image, src_ip, dst_ip, dst_port, protocol, sum(bytes_in+bytes_out) bytes, count() c FROM events WHERE kind='flow' AND ts_wall_ms >= {} GROUP BY ALL ORDER BY bytes DESC LIMIT {}", f.since_ms(), f.limit.unwrap_or(500))).await?))
}

pub async fn alerts(State(app): State<App>, Query(f): Query<Filters>) -> R {
    validate_filters(&f).map_err(bad)?;
    let mut binds = vec![];
    let w = f.host_where(&mut binds);
    let sev = f
        .sev
        .as_ref()
        .map(|s| {
            binds.push(s.clone());
            format!(
                "AND a.severity = ANY(string_to_array(${}, ','))",
                binds.len()
            )
        })
        .unwrap_or_default();
    binds.push(f.since_ms().to_string());
    let sql = format!("SELECT to_jsonb(a) || jsonb_build_object('tier',h.tier,'ou',h.ou) FROM alerts a JOIN hosts h USING(host_id) WHERE {w} {sev} AND a.ts >= to_timestamp(${}::bigint/1000.0) ORDER BY a.ts DESC LIMIT {}", binds.len(), f.limit.unwrap_or(500));
    let mut q = sqlx::query_scalar::<_, Value>(&sql);
    for b in &binds {
        q = q.bind(b);
    }
    Ok(Json(Value::Array(q.fetch_all(&app.pg).await.map_err(ise)?)))
}
pub async fn ack_alert(
    State(app): State<App>,
    Extension(c): Extension<Claims>,
    Path(id): Path<String>,
) -> R {
    sqlx::query("UPDATE alerts SET status='ack', acked_by=$2, acked_at=now() WHERE alert_id=$1")
        .bind(&id)
        .bind(&c.sub)
        .execute(&app.pg)
        .await
        .map_err(ise)?;
    audit(&app, &c.sub, "alert.ack", &id).await;
    let _ = app
        .bus
        .send(json!({"type":"alert.ack","id":id}).to_string());
    Ok(Json(json!({"ok":true})))
}

pub async fn overview(State(app): State<App>, Query(f): Query<Filters>) -> R {
    validate_filters(&f).map_err(bad)?;
    let mut binds = vec![];
    let w = f.host_where(&mut binds);
    let mut q = sqlx::query_scalar::<_, Value>(&format!("SELECT jsonb_build_object(
        'hosts', COUNT(*), 'avg_posture', ROUND(AVG(h.posture)), 'offline', COUNT(*) FILTER (WHERE NOT h.online), 'audit_mode', COUNT(*) FILTER (WHERE h.allow_mode='Audit'),
        'drift', (SELECT COUNT(*) FROM drift_findings d JOIN hosts hh USING(host_id) WHERE NOT d.resolved),
        'open_alerts', (SELECT COUNT(*) FROM alerts a WHERE a.status='open'), 'critical_alerts', (SELECT COUNT(*) FROM alerts a WHERE a.status='open' AND a.severity='critical'),
        'critical_cves', (SELECT COUNT(DISTINCT v.cve) FROM host_vulns v JOIN vulnerabilities c USING(cve) WHERE c.cvss >= 9), 'kev', (SELECT COUNT(*) FROM host_vulns v JOIN vulnerabilities c USING(cve) WHERE c.kev),
        'by_ou', (SELECT jsonb_object_agg(ou, p) FROM (SELECT ou, ROUND(AVG(posture)) p FROM hosts GROUP BY ou) x),
        'by_tier', (SELECT jsonb_object_agg(tier, n) FROM (SELECT tier, COUNT(*) n FROM hosts GROUP BY tier) x),
        'posture_hist', (SELECT jsonb_agg(posture ORDER BY posture) FROM hosts)) FROM hosts h WHERE {w}"));
    for b in &binds {
        q = q.bind(b);
    }
    let mut v = q.fetch_one(&app.pg).await.map_err(ise)?;
    let series = ch_json(&app, &format!("SELECT toStartOfHour(fromUnixTimestamp64Milli(ts_wall_ms)) t, severity, count() n FROM events WHERE kind='drift' AND ts_wall_ms >= {} GROUP BY t, severity ORDER BY t", f.since_ms())).await?;
    v["alert_series"] = series;
    Ok(Json(v))
}

pub async fn vulns(State(app): State<App>, Query(_f): Query<Filters>) -> R {
    let rows: Vec<Value> = sqlx::query_scalar("SELECT to_jsonb(c) || jsonb_build_object('hosts', (SELECT COUNT(*) FROM host_vulns v WHERE v.cve=c.cve), 'reachable', (SELECT COUNT(*) FROM host_vulns v JOIN hosts h USING(host_id) WHERE v.cve=c.cve AND h.exposed)) FROM vulnerabilities c WHERE EXISTS (SELECT 1 FROM host_vulns v WHERE v.cve=c.cve) ORDER BY c.cvss DESC").fetch_all(&app.pg).await.map_err(ise)?;
    Ok(Json(Value::Array(rows)))
}
pub async fn vuln_matrix(State(app): State<App>) -> R {
    let rows: Vec<Value> = sqlx::query_scalar("SELECT jsonb_build_object('cve', v.cve, 'tier', h.tier, 'n', COUNT(*)) FROM host_vulns v JOIN hosts h USING(host_id) GROUP BY v.cve, h.tier").fetch_all(&app.pg).await.map_err(ise)?;
    Ok(Json(Value::Array(rows)))
}
pub async fn fim_changes(State(app): State<App>, Query(f): Query<Filters>) -> R {
    validate_filters(&f).map_err(bad)?;
    Ok(Json(ch_json(&app, &format!("SELECT host_id, ts_wall_ms, path, image, user, sha256, signer, extra, multiIf(path ILIKE '%\\\\drivers\\\\etc\\\\%' OR path ILIKE '%\\\\Startup\\\\%' OR path ILIKE '%\\\\Tasks\\\\%','suspicious', signer='Microsoft Windows' OR user='TrustedInstaller','patch','config') cls FROM events WHERE kind='file' AND ts_wall_ms >= {} ORDER BY ts_wall_ms DESC LIMIT {}", f.since_ms(), f.limit.unwrap_or(500))).await?))
}
pub async fn allow_queue(State(app): State<App>) -> R {
    Ok(Json(ch_json(&app, "SELECT host_id, path, sha256, signer publisher, count() seen, min(ts_wall_ms) first, max(ts_wall_ms) last FROM events WHERE kind='allowlist' AND ts_wall_ms >= now64()*1000 - 7*86400000 AND sha256 NOT IN (SELECT sha256 FROM allow_decisions) GROUP BY ALL ORDER BY seen DESC LIMIT 200").await?))
}
#[derive(Deserialize)]
pub struct Decide {
    pub sha256: String,
    pub publisher: Option<String>,
    pub decision: String,
}
pub async fn allow_decide(
    State(app): State<App>,
    Extension(c): Extension<Claims>,
    Json(d): Json<Decide>,
) -> R {
    if !is_sha256(&d.sha256) || !matches!(d.decision.as_str(), "allow" | "deny") {
        return Err(StatusCode::BAD_REQUEST);
    }
    sqlx::query("INSERT INTO allow_decisions(sha256, publisher, decision, decided_by, ts) VALUES($1,$2,$3,$4,now()) ON CONFLICT(sha256) DO UPDATE SET decision=$3, decided_by=$4, ts=now()").bind(&d.sha256).bind(&d.publisher).bind(&d.decision).bind(&c.sub).execute(&app.pg).await.map_err(ise)?;
    audit(
        &app,
        &c.sub,
        "allowlist.decide",
        &format!("{} {}", d.decision, d.sha256),
    )
    .await;
    Ok(Json(json!({"ok":true})))
}
pub async fn policy_get(State(app): State<App>) -> R {
    let v: Option<Value> = sqlx::query_scalar(
        "SELECT to_jsonb(p) FROM policy_versions p ORDER BY version DESC LIMIT 1",
    )
    .fetch_optional(&app.pg)
    .await
    .map_err(ise)?;
    Ok(Json(v.unwrap_or(json!({"version":0,"rules":[]}))))
}
#[derive(Deserialize)]
pub struct PolicyDoc {
    pub allowed: Vec<String>,
    pub note: Option<String>,
}
pub async fn policy_simulate(
    State(app): State<App>,
    Query(f): Query<Filters>,
    Json(p): Json<PolicyDoc>,
) -> R {
    validate_filters(&f).map_err(bad)?;
    validate_policy(&p).map_err(bad)?;
    // Which historical tier->tier flows fall outside the allow list?
    let edges = ch_json(&app, &format!("SELECT src_tier, dst_tier, sum(c) c FROM flow_edges_hourly WHERE hour >= toDateTime({}/1000) GROUP BY ALL", f.since_ms())).await?;
    let allowed: std::collections::HashSet<_> = p.allowed.iter().cloned().collect();
    let (mut total, mut dropped) = (0u64, 0u64);
    let mut would_drop = vec![];
    for e in edges.as_array().into_iter().flatten() {
        let k = format!(
            "{}>{}",
            e["src_tier"].as_str().unwrap_or(""),
            e["dst_tier"].as_str().unwrap_or("")
        );
        let c = e["c"].as_u64().unwrap_or(0);
        total += c;
        if !allowed.contains(&k) {
            dropped += c;
            would_drop.push(e.clone());
        }
    }
    Ok(Json(
        json!({ "total": total, "dropped": dropped, "keep_pct": if total > 0 { 100.0 * (total - dropped) as f64 / total as f64 } else { 100.0 }, "would_drop": would_drop }),
    ))
}
pub async fn policy_stage(
    State(app): State<App>,
    Extension(c): Extension<Claims>,
    Json(p): Json<PolicyDoc>,
) -> R {
    validate_policy(&p).map_err(bad)?;
    let v: i32 = sqlx::query_scalar("INSERT INTO policy_versions(version, rules, note, author, status) VALUES((SELECT COALESCE(MAX(version),0)+1 FROM policy_versions), $1, $2, $3, 'staged') RETURNING version").bind(serde_json::to_value(&p.allowed).unwrap()).bind(&p.note).bind(&c.sub).fetch_one(&app.pg).await.map_err(ise)?;
    audit(&app, &c.sub, "policy.stage", &format!("v{v}")).await;
    Ok(Json(json!({"version": v, "status": "staged"})))
}
pub async fn policy_enforce(
    State(app): State<App>,
    Extension(c): Extension<Claims>,
    Json(body): Json<Value>,
) -> R {
    let v = body["version"].as_i64().ok_or(StatusCode::BAD_REQUEST)?;
    let ring = body["ring"].as_i64().unwrap_or(1);
    sqlx::query("UPDATE policy_versions SET status='enforcing', ring=$2 WHERE version=$1")
        .bind(v as i32)
        .bind(ring as i32)
        .execute(&app.pg)
        .await
        .map_err(ise)?;
    sqlx::query("INSERT INTO commands(command_id, host_id, kind, payload, status, issued_by, issued_at) SELECT gen_random_uuid()::text, host_id, 'firewall', jsonb_build_object('version',$1), 'queued', $3, now() FROM hosts WHERE update_ring <= $2").bind(v as i32).bind(ring as i32).bind(&c.sub).execute(&app.pg).await.map_err(ise)?;
    audit(&app, &c.sub, "policy.enforce", &format!("v{v} ring {ring}")).await;
    Ok(Json(json!({"ok":true,"version":v,"ring":ring})))
}
pub async fn isolate(
    State(app): State<App>,
    Extension(c): Extension<Claims>,
    Path(id): Path<String>,
) -> R {
    if !is_host_id(&id) {
        return Err(StatusCode::BAD_REQUEST);
    }
    queue_cmd(&app, &c, &id, "isolate", json!({"enable":true})).await
}
pub async fn remediate(
    State(app): State<App>,
    Extension(c): Extension<Claims>,
    Path(id): Path<String>,
    Json(b): Json<Value>,
) -> R {
    if !is_host_id(&id) || b.to_string().len() > 64 * 1024 {
        return Err(StatusCode::BAD_REQUEST);
    }
    queue_cmd(&app, &c, &id, "remediation", b).await
}
async fn queue_cmd(app: &App, c: &Claims, host: &str, kind: &str, payload: Value) -> R {
    let cid = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO commands(command_id, host_id, kind, payload, status, issued_by, issued_at) VALUES($1,$2,$3,$4,'queued',$5,now())").bind(&cid).bind(host).bind(kind).bind(&payload).bind(&c.sub).execute(&app.pg).await.map_err(ise)?;
    audit(app, &c.sub, &format!("command.{kind}"), host).await;
    Ok(Json(json!({"command_id": cid, "status": "queued"})))
}
pub async fn fleet(State(app): State<App>) -> R {
    let rows: Vec<Value> = sqlx::query_scalar(
        "SELECT to_jsonb(h) - 'modules' FROM hosts h ORDER BY online, last_seen",
    )
    .fetch_all(&app.pg)
    .await
    .map_err(ise)?;
    Ok(Json(Value::Array(rows)))
}
pub async fn fleet_update(
    State(app): State<App>,
    Extension(c): Extension<Claims>,
    Json(b): Json<Value>,
) -> R {
    audit(&app, &c.sub, "fleet.update", &b.to_string()).await;
    Ok(Json(json!({"ok":true})))
}
pub async fn feeds_import(
    State(app): State<App>,
    Extension(c): Extension<Claims>,
    body: axum::body::Bytes,
) -> R {
    if body.len() < 80 || body.len() > 512 << 20 {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    // The bundle is verified and unpacked by hv-feeds; here we only persist it and hand off.
    let id = uuid::Uuid::new_v4().to_string();
    let path = format!("/var/lib/hostvigil/blobs/{id}.hvb");
    tokio::fs::write(&path, &body).await.map_err(ise)?;
    sqlx::query("INSERT INTO feed_bundles(id, path, status, uploaded_by, ts) VALUES($1,$2,'pending',$3,now())").bind(&id).bind(&path).bind(&c.sub).execute(&app.pg).await.map_err(ise)?;
    audit(&app, &c.sub, "feeds.import", &id).await;
    Ok(Json(json!({"id": id, "status": "pending verification"})))
}
pub async fn audit(State(app): State<App>) -> R {
    let rows: Vec<Value> =
        sqlx::query_scalar("SELECT to_jsonb(a) FROM audit_log a ORDER BY ts DESC LIMIT 1000")
            .fetch_all(&app.pg)
            .await
            .map_err(ise)?;
    Ok(Json(Value::Array(rows)))
}

pub async fn ws(ws: WebSocketUpgrade, State(app): State<App>) -> Response {
    ws.on_upgrade(move |s| ws_loop(s, app))
}
async fn ws_loop(mut sock: WebSocket, app: App) {
    let mut rx = app.bus.subscribe();
    loop {
        tokio::select! { Ok(msg) = rx.recv() => { if sock.send(Message::Text(msg)).await.is_err() { break } } m = sock.recv() => { if m.is_none() { break } } }
    }
}

pub async fn hud_static(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };
    match HudAssets::get(path).or_else(|| HudAssets::get("index.html")) {
        Some(f) => {
            let mime = mime_guess(path);
            ([(header::CONTENT_TYPE, mime)], f.data.into_owned()).into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
fn mime_guess(p: &str) -> &'static str {
    match p.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "application/javascript",
        Some("css") => "text/css",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("json") => "application/json",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}
fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn filters_vocabulary_and_bounds() {
        let ok = Filters {
            range: Some(168),
            tier: Some("Web,DB".into()),
            sev: Some("critical".into()),
            ..Default::default()
        };
        assert!(validate_filters(&ok).is_ok());
        assert!(validate_filters(&Filters {
            range: Some(0),
            ..Default::default()
        })
        .is_err());
        assert!(validate_filters(&Filters {
            range: Some(MAX_RANGE_HOURS + 1),
            ..Default::default()
        })
        .is_err());
        assert!(validate_filters(&Filters {
            tier: Some("Mainframe".into()),
            ..Default::default()
        })
        .is_err());
        assert!(validate_filters(&Filters {
            limit: Some(MAX_LIMIT + 1),
            ..Default::default()
        })
        .is_err());
        assert!(validate_filters(&Filters {
            q: Some("x".repeat(257)),
            ..Default::default()
        })
        .is_err());
    }
    #[test]
    fn identifiers_and_hashes() {
        assert!(is_host_id("web-001"));
        assert!(!is_host_id("web 001"));
        assert!(!is_host_id("a/../b"));
        assert!(is_sha256(&"a".repeat(64)));
        assert!(!is_sha256(&"A".repeat(64)));
        assert!(!is_sha256("abc"));
        assert!(is_tier_pair("Web>App"));
        assert!(!is_tier_pair("Web>Mainframe"));
        assert!(!is_tier_pair("Web"));
    }
    #[test]
    fn policy_doc_bounds() {
        assert!(validate_policy(&PolicyDoc {
            allowed: vec!["Web>App".into()],
            note: None
        })
        .is_ok());
        assert!(validate_policy(&PolicyDoc {
            allowed: vec!["Web>App;DROP".into()],
            note: None
        })
        .is_err());
        assert!(validate_policy(&PolicyDoc {
            allowed: vec![],
            note: Some("n".repeat(1025))
        })
        .is_err());
    }
}
