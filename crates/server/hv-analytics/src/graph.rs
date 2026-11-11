//! Dependency graph: aggregate flows into host->host edges, resolve IPs to
//! hosts, cluster into application tiers and write back the tier of each host.
use crate::Ctx;
use anyhow::Result;
use petgraph::{graph::DiGraph, visit::EdgeRef};
use std::collections::HashMap;

pub async fn rebuild(ctx: Ctx) -> Result<()> {
    // IP -> host_id map from the latest inventory
    let hosts: Vec<(String, Vec<String>, Option<String>)> =
        sqlx::query_as("SELECT host_id, ips, tier FROM hosts")
            .fetch_all(&ctx.pg)
            .await?;
    let ip_to_host: HashMap<String, String> = hosts
        .iter()
        .flat_map(|(h, ips, _)| ips.iter().map(move |ip| (ip.clone(), h.clone())))
        .collect();

    // Flow edges from the last hour of raw events -> flow_edges_hourly
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct Fl {
        host_id: String,
        image: String,
        dst_ip: String,
        dst_port: u32,
        b: u64,
        c: u64,
    }
    let rows = ctx.ch.query("SELECT host_id, image, dst_ip, dst_port, sum(bytes_in+bytes_out) b, count() c FROM events WHERE kind='flow' AND direction=0 AND ts_wall_ms >= toUnixTimestamp64Milli(now64()) - 3600000 GROUP BY ALL").fetch_all::<Fl>().await?;
    let tier_of: HashMap<&str, &str> = hosts
        .iter()
        .map(|(h, _, t)| (h.as_str(), t.as_deref().unwrap_or("Unknown")))
        .collect();
    let mut ins = ctx.ch.insert("flow_edges_hourly")?;
    let hour = chrono::Utc::now().timestamp() as u32 / 3600 * 3600;
    let mut g = DiGraph::<String, u64>::new();
    let mut idx = HashMap::new();
    for Fl {
        host_id: src,
        image,
        dst_ip,
        dst_port: port,
        b: bytes,
        c,
    } in rows
    {
        let Some(dst) = ip_to_host.get(&dst_ip) else {
            continue;
        };
        ins.write(&Edge {
            hour,
            src_host: src.clone(),
            dst_host: dst.clone(),
            src_tier: tier_of.get(src.as_str()).unwrap_or(&"Unknown").to_string(),
            dst_tier: tier_of.get(dst.as_str()).unwrap_or(&"Unknown").to_string(),
            image,
            dst_port: port,
            bytes,
            c,
        })
        .await?;
        let a = *idx
            .entry(src.clone())
            .or_insert_with(|| g.add_node(src.clone()));
        let b = *idx
            .entry(dst.clone())
            .or_insert_with(|| g.add_node(dst.clone()));
        g.add_edge(a, b, bytes);
    }
    ins.end().await?;

    // Heuristic tiering for hosts without an operator-assigned tier:
    // listens on 1433/5432 -> DB; 88/389 -> DC; 80/443 with many inbound -> Web; else App/Workstation by OS.
    let untiered: Vec<(String, String, Vec<i32>)> = sqlx::query_as("SELECT host_id, os_version, COALESCE((SELECT array_agg((p->>'port')::int) FROM host_inventory i, jsonb_array_elements(i.doc->'listening') p WHERE i.host_id=h.host_id ORDER BY 1 LIMIT 1), '{}') FROM hosts h WHERE tier IS NULL OR tier_source='auto'").fetch_all(&ctx.pg).await?;
    for (h, os, ports) in untiered {
        let tier = if ports.iter().any(|p| [1433, 5432, 3306, 1521].contains(p)) {
            "DB"
        } else if ports.iter().any(|p| [88, 389, 636].contains(p)) {
            "DC"
        } else if ports.iter().any(|p| [80, 443, 8080, 8443].contains(p)) {
            "Web"
        } else if os.contains("Server") {
            "App"
        } else {
            "Workstation"
        };
        sqlx::query("UPDATE hosts SET tier=$2, tier_source='auto' WHERE host_id=$1")
            .bind(&h)
            .bind(tier)
            .execute(&ctx.pg)
            .await?;
    }
    tracing::info!(nodes = g.node_count(), edges = g.edge_count(), heaviest = ?g.edge_references().max_by_key(|e| *e.weight()).map(|e| (g[e.source()].clone(), g[e.target()].clone(), *e.weight())), "graph rebuilt");
    Ok(())
}

#[derive(clickhouse::Row, serde::Serialize)]
struct Edge {
    hour: u32,
    src_host: String,
    dst_host: String,
    src_tier: String,
    dst_tier: String,
    image: String,
    dst_port: u32,
    bytes: u64,
    c: u64,
}
