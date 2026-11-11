//! Posture score 0-100 per host, weighted across six dimensions. Weights are
//! operator-tunable in `posture_weights`; defaults below.
use crate::Ctx;
use anyhow::Result;

pub async fn recompute(ctx: Ctx) -> Result<()> {
    sqlx::query(r#"
        WITH d AS (
          SELECT h.host_id,
            GREATEST(0, 100 - 6 * (SELECT COUNT(*) FROM host_vulns v JOIN vulnerabilities c USING(cve) WHERE v.host_id=h.host_id AND c.cvss >= 7)) AS patching,
            GREATEST(0, 100 - 9 * (SELECT COUNT(*) FROM drift_findings f WHERE f.host_id=h.host_id AND NOT f.resolved)) AS config,
            CASE WHEN COALESCE((SELECT jsonb_array_length(doc->'accounts') FROM host_inventory i WHERE i.host_id=h.host_id ORDER BY ts DESC LIMIT 1),0) > 3 THEN 50 ELSE 90 END AS identity,
            CASE WHEN COALESCE(jsonb_array_length((SELECT doc->'facts'->'unencrypted_volumes' FROM host_inventory i WHERE i.host_id=h.host_id ORDER BY ts DESC LIMIT 1)),1) = 0 THEN 95 ELSE 30 END AS encryption,
            GREATEST(20, 100 - 8 * COALESCE((SELECT jsonb_array_length(doc->'listening') FROM host_inventory i WHERE i.host_id=h.host_id ORDER BY ts DESC LIMIT 1),0)) AS network,
            CASE WHEN h.allow_mode = 'Enforce' THEN 92 ELSE 55 END AS allowlist
          FROM hosts h
        )
        UPDATE hosts h SET posture = round(0.30*d.patching + 0.20*d.config + 0.15*d.identity + 0.10*d.encryption + 0.15*d.network + 0.10*d.allowlist),
                           posture_dims = jsonb_build_object('patching',d.patching,'config',d.config,'identity',d.identity,'encryption',d.encryption,'network',d.network,'allowlist',d.allowlist),
                           posture_at = now()
        FROM d WHERE d.host_id = h.host_id
    "#).execute(&ctx.pg).await?;
    tracing::info!("posture recomputed");
    Ok(())
}
