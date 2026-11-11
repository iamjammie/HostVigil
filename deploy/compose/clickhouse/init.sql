CREATE DATABASE IF NOT EXISTS hostvigil;
CREATE TABLE IF NOT EXISTS hostvigil.events (
  host_id String, boot_id String, seq UInt64, ts_wall_ms UInt64, ts_recv_ms UInt64,
  kind LowCardinality(String), pid UInt32, ppid UInt32, image String, user String, sha256 String, signer String,
  path String, detail String, src_ip String, src_port UInt32, dst_ip String, dst_port UInt32, protocol LowCardinality(String),
  bytes_in UInt64, bytes_out UInt64, direction UInt8, blocked UInt8, severity LowCardinality(String), rule_id String, extra String,
  INDEX idx_image image TYPE bloom_filter GRANULARITY 4,
  INDEX idx_sha sha256 TYPE bloom_filter GRANULARITY 4,
  INDEX idx_path path TYPE tokenbf_v1(10240, 3, 0) GRANULARITY 4
) ENGINE = MergeTree
PARTITION BY toDate(fromUnixTimestamp64Milli(ts_wall_ms))
ORDER BY (kind, host_id, ts_wall_ms)
TTL toDateTime(fromUnixTimestamp64Milli(ts_wall_ms)) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS hostvigil.flow_edges_hourly (
  hour DateTime, src_host String, dst_host String, src_tier LowCardinality(String), dst_tier LowCardinality(String),
  image String, dst_port UInt32, bytes UInt64, c UInt64
) ENGINE = SummingMergeTree((bytes, c)) ORDER BY (hour, src_host, dst_host, image, dst_port) TTL hour + INTERVAL 180 DAY;
