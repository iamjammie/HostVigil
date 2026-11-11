-- HostVigil relational schema (PostgreSQL 16)
CREATE TABLE IF NOT EXISTS hosts (
  host_id TEXT PRIMARY KEY, hostname TEXT NOT NULL, os_version TEXT NOT NULL DEFAULT '', agent_version TEXT NOT NULL DEFAULT '',
  ips TEXT[] NOT NULL DEFAULT '{}', ou TEXT, tier TEXT, tier_source TEXT DEFAULT 'auto', criticality TEXT DEFAULT 'Medium', group_name TEXT, owner TEXT,
  posture INT, posture_dims JSONB, posture_at TIMESTAMPTZ, allow_mode TEXT DEFAULT 'Audit', exposed BOOLEAN DEFAULT false, update_ring INT DEFAULT 3,
  online BOOLEAN DEFAULT false, last_seen TIMESTAMPTZ, inventory_at TIMESTAMPTZ, queue_depth INT DEFAULT 0, cpu_pct REAL, mem_mb INT, modules JSONB, decommissioned BOOLEAN DEFAULT false
);
CREATE TABLE IF NOT EXISTS host_inventory (id BIGSERIAL PRIMARY KEY, host_id TEXT REFERENCES hosts(host_id), ts TIMESTAMPTZ NOT NULL, doc JSONB NOT NULL);
CREATE INDEX IF NOT EXISTS host_inventory_host_ts ON host_inventory(host_id, ts DESC);
CREATE TABLE IF NOT EXISTS baselines (id BIGSERIAL PRIMARY KEY, host_id TEXT REFERENCES hosts(host_id), ts TIMESTAMPTZ NOT NULL, sha256 TEXT NOT NULL, doc_zstd BYTEA NOT NULL);
CREATE TABLE IF NOT EXISTS drift_findings (id BIGSERIAL PRIMARY KEY, host_id TEXT REFERENCES hosts(host_id), check_id TEXT NOT NULL, title TEXT, expected TEXT, actual TEXT, severity TEXT, resolved BOOLEAN DEFAULT false, first_seen TIMESTAMPTZ DEFAULT now(), resolved_at TIMESTAMPTZ, UNIQUE(host_id, check_id));
CREATE TABLE IF NOT EXISTS vulnerabilities (cve TEXT PRIMARY KEY, title TEXT, cvss REAL, kev BOOLEAN DEFAULT false, kev_added TEXT, affects JSONB NOT NULL DEFAULT '[]', os_build_prefix TEXT, fixed_by_kb TEXT[], published TEXT, exposure INT DEFAULT 0);
CREATE TABLE IF NOT EXISTS host_vulns (host_id TEXT REFERENCES hosts(host_id), cve TEXT REFERENCES vulnerabilities(cve), first_seen TIMESTAMPTZ, last_seen TIMESTAMPTZ, accepted_risk BOOLEAN DEFAULT false, PRIMARY KEY(host_id, cve));
CREATE TABLE IF NOT EXISTS alerts (alert_id TEXT PRIMARY KEY, host_id TEXT REFERENCES hosts(host_id), rule_id TEXT, rule TEXT, severity TEXT, tactic TEXT, process TEXT, username TEXT, ts TIMESTAMPTZ NOT NULL, status TEXT DEFAULT 'open', acked_by TEXT, acked_at TIMESTAMPTZ);
CREATE INDEX IF NOT EXISTS alerts_ts ON alerts(ts DESC); CREATE INDEX IF NOT EXISTS alerts_host ON alerts(host_id);
CREATE TABLE IF NOT EXISTS allow_decisions (sha256 TEXT PRIMARY KEY, publisher TEXT, decision TEXT NOT NULL, decided_by TEXT, ts TIMESTAMPTZ);
CREATE TABLE IF NOT EXISTS policy_versions (version INT PRIMARY KEY, rules JSONB NOT NULL, note TEXT, author TEXT, status TEXT NOT NULL, ring INT, created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS commands (command_id TEXT PRIMARY KEY, host_id TEXT REFERENCES hosts(host_id), kind TEXT NOT NULL, payload JSONB, status TEXT NOT NULL, message TEXT, issued_by TEXT, issued_at TIMESTAMPTZ, completed_at TIMESTAMPTZ);
CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL, enabled BOOLEAN DEFAULT true, created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS audit_log (id BIGSERIAL PRIMARY KEY, actor TEXT, action TEXT, detail TEXT, ts TIMESTAMPTZ NOT NULL);
CREATE TABLE IF NOT EXISTS enrol_tokens (token TEXT PRIMARY KEY, group_name TEXT, expires_at TIMESTAMPTZ NOT NULL, used_at TIMESTAMPTZ, used_by TEXT);
CREATE TABLE IF NOT EXISTS host_certs (id BIGSERIAL PRIMARY KEY, host_id TEXT, serial TEXT, not_after TEXT, issued_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ);
CREATE TABLE IF NOT EXISTS ingest_gaps (id BIGSERIAL PRIMARY KEY, host_id TEXT, expected_seq BIGINT, got_seq BIGINT, ts TIMESTAMPTZ);
CREATE TABLE IF NOT EXISTS feed_bundles (id TEXT PRIMARY KEY, path TEXT, status TEXT, message TEXT, uploaded_by TEXT, ts TIMESTAMPTZ, processed_at TIMESTAMPTZ);
CREATE TABLE IF NOT EXISTS agent_releases (version TEXT PRIMARY KEY, sha256 TEXT, path TEXT, imported_at TIMESTAMPTZ);
CREATE TABLE IF NOT EXISTS ingest_violations (id BIGSERIAL PRIMARY KEY, host_id TEXT, seq BIGINT, violation TEXT, ts TIMESTAMPTZ);
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS violations BIGINT DEFAULT 0;
