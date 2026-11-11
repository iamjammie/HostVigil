//! Vulnerability matching against the imported offline feeds.
//! exposure = CVSS x (1.5 if KEV) x (1 + reachable_share) where reachable means
//! the host exposes an internet/lateral-facing service seen in the flow graph.
use crate::Ctx;
use anyhow::Result;

pub async fn rescore(ctx: Ctx) -> Result<()> {
    // Normalise "Name Version" from inventory into (vendor, product, version) CPE-ish triples and
    // match against the CPE ranges in `vulnerabilities.affects` (JSONB, loaded by hv-feeds).
    sqlx::query(r#"
        WITH sw AS (
          SELECT i.host_id, lower(s->>'name') AS name, s->>'version' AS version
          FROM host_inventory i, jsonb_array_elements(i.doc->'software') s
          WHERE i.ts = (SELECT max(ts) FROM host_inventory j WHERE j.host_id = i.host_id)
        ), kb AS (
          SELECT i.host_id, k->>'kb' AS kb FROM host_inventory i, jsonb_array_elements(i.doc->'hotfixes') k
          WHERE i.ts = (SELECT max(ts) FROM host_inventory j WHERE j.host_id = i.host_id)
        ), matched AS (
          SELECT sw.host_id, v.cve
          FROM sw JOIN vulnerabilities v ON EXISTS (
            SELECT 1 FROM jsonb_array_elements(v.affects) a
            WHERE sw.name LIKE lower(a->>'product') || '%'
              AND (a->>'version_end' IS NULL OR string_to_array(sw.version,'.')::int[] < string_to_array(a->>'version_end','.')::int[])
          )
          UNION
          -- OS CVEs fixed by a KB the host does NOT have
          SELECT h.host_id, v.cve FROM hosts h JOIN vulnerabilities v ON v.os_build_prefix IS NOT NULL AND h.os_version LIKE v.os_build_prefix || '%'
          WHERE NOT EXISTS (SELECT 1 FROM kb WHERE kb.host_id = h.host_id AND kb.kb = ANY(v.fixed_by_kb))
        )
        INSERT INTO host_vulns(host_id, cve, first_seen, last_seen)
        SELECT host_id, cve, now(), now() FROM matched
        ON CONFLICT (host_id, cve) DO UPDATE SET last_seen = now();
    "#).execute(&ctx.pg).await?;
    // remove vulns no longer matched
    sqlx::query("DELETE FROM host_vulns WHERE last_seen < now() - interval '2 hours'")
        .execute(&ctx.pg)
        .await?;
    // exposure scores
    sqlx::query(r#"
        UPDATE vulnerabilities v SET exposure = sub.score FROM (
          SELECT c.cve, round(c.cvss * 10 * CASE WHEN c.kev THEN 1.5 ELSE 1 END * (1 + COALESCE(AVG(CASE WHEN h.exposed THEN 1 ELSE 0 END),0))) AS score
          FROM vulnerabilities c LEFT JOIN host_vulns hv USING(cve) LEFT JOIN hosts h USING(host_id) GROUP BY c.cve, c.cvss, c.kev
        ) sub WHERE sub.cve = v.cve
    "#).execute(&ctx.pg).await?;
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM host_vulns")
        .fetch_one(&ctx.pg)
        .await?;
    tracing::info!(host_vulns = n, "cve rescore complete");
    Ok(())
}
