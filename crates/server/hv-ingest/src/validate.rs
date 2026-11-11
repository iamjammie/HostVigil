//! Ingest-side data validation. Every event from an agent is checked before
//! it touches storage, the same way PhotonWire's receiver bounds Content-Length
//! and verifies SHA-256 before writing a file. Failures are counted per host and
//! surfaced in the HUD (Fleet → agent health) rather than silently dropped.
//!
//! Rules
//! - identifiers: host_id / boot_id non-empty, ≤ 128 chars, [A-Za-z0-9._-]
//! - sequence: strictly increasing within a stream; seq 0 is invalid
//! - timestamps: wall clock within ±48 h of server time (agents with broken
//!   clocks are flagged, events still stored with `ts_recv_ms` as the truth)
//! - hashes: sha256 fields are empty or exactly 64 lowercase hex
//! - IPs: parse as IPv4/IPv6; ports 0..=65535 (0 allowed for ICMP-like flows)
//! - strings: paths ≤ 4096, command lines / script blocks ≤ 64 KiB, others ≤ 1024
//! - batches: ≤ 5 000 events and ≤ 16 MiB decoded per message

use std::net::IpAddr;
use hv_proto::{event::Body, Event, EventBatch};

pub const MAX_BATCH_EVENTS: usize = 5_000;
pub const MAX_BATCH_BYTES: usize = 16 << 20;
pub const MAX_PATH: usize = 4096;
pub const MAX_TEXT: usize = 64 * 1024;
pub const MAX_SHORT: usize = 1024;
pub const MAX_CLOCK_SKEW_MS: i64 = 48 * 3600 * 1000;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Violation {
    BatchTooLarge { events: usize },
    BadIdentifier(&'static str),
    SeqNotIncreasing { expected_gt: u64, got: u64 },
    ClockSkew { skew_ms: i64 },
    BadHash(&'static str),
    BadIp(&'static str),
    BadPort(&'static str),
    TooLong(&'static str, usize),
    EmptyBody,
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Violation::BatchTooLarge { events } => {
                write!(f, "batch has {events} events (max {MAX_BATCH_EVENTS})")
            }
            Violation::BadIdentifier(w) => write!(f, "bad identifier: {w}"),
            Violation::SeqNotIncreasing { expected_gt, got } => {
                write!(f, "seq {got} not > {expected_gt}")
            }
            Violation::ClockSkew { skew_ms } => write!(f, "clock skew {skew_ms} ms"),
            Violation::BadHash(w) => write!(f, "bad sha256 in {w}"),
            Violation::BadIp(w) => write!(f, "bad ip in {w}"),
            Violation::BadPort(w) => write!(f, "bad port in {w}"),
            Violation::TooLong(w, n) => write!(f, "{w} too long ({n})"),
            Violation::EmptyBody => write!(f, "event has no body"),
        }
    }
}

/// Validate a whole batch. Returns the events that passed plus the violations
/// found, so one bad event never discards its neighbours.
pub fn validate_batch(
    b: &EventBatch,
    last_seq: Option<u64>,
    now_ms: u64,
) -> (Vec<Event>, Vec<(u64, Violation)>) {
    let mut ok = Vec::with_capacity(b.events.len());
    let mut bad = Vec::new();
    if b.events.len() > MAX_BATCH_EVENTS {
        bad.push((
            0,
            Violation::BatchTooLarge {
                events: b.events.len(),
            },
        ));
        return (ok, bad);
    }
    let mut prev = last_seq;
    for e in &b.events {
        match validate_event(e, prev, now_ms) {
            Ok(()) => {
                prev = Some(e.seq);
                ok.push(e.clone());
            }
            Err(v) => bad.push((e.seq, v)),
        }
    }
    (ok, bad)
}

pub fn validate_event(e: &Event, last_seq: Option<u64>, now_ms: u64) -> Result<(), Violation> {
    ident(&e.host_id, "host_id")?;
    ident(&e.boot_id, "boot_id")?;
    if e.seq == 0 {
        return Err(Violation::SeqNotIncreasing {
            expected_gt: 0,
            got: 0,
        });
    }
    if let Some(l) = last_seq {
        if e.seq <= l {
            return Err(Violation::SeqNotIncreasing {
                expected_gt: l,
                got: e.seq,
            });
        }
    }
    let skew = e.ts_wall_ms as i64 - now_ms as i64;
    if skew.abs() > MAX_CLOCK_SKEW_MS {
        return Err(Violation::ClockSkew { skew_ms: skew });
    }
    match &e.body {
        None => Err(Violation::EmptyBody),
        Some(Body::Process(p)) => {
            len(&p.image, MAX_PATH, "image")?;
            len(&p.command_line, MAX_TEXT, "command_line")?;
            len(&p.user, MAX_SHORT, "user")?;
            len(&p.parent_image, MAX_PATH, "parent_image")?;
            hash(&p.sha256, "process.sha256")
        }
        Some(Body::Flow(f)) => {
            ip(&f.local_ip, "local_ip")?;
            ip(&f.remote_ip, "remote_ip")?;
            port(f.local_port, "local_port")?;
            port(f.remote_port, "remote_port")?;
            len(&f.image, MAX_PATH, "image")?;
            if !matches!(f.protocol.as_str(), "tcp" | "udp" | "icmp" | "") {
                return Err(Violation::BadIdentifier("protocol"));
            }
            Ok(())
        }
        Some(Body::File(f)) => {
            len(&f.path, MAX_PATH, "path")?;
            len(&f.old_path, MAX_PATH, "old_path")?;
            len(&f.acl_sddl, MAX_TEXT, "acl_sddl")?;
            hash(&f.sha256_before, "file.sha256_before")?;
            hash(&f.sha256_after, "file.sha256_after")
        }
        Some(Body::Registry(r)) => {
            len(&r.key, MAX_PATH, "key")?;
            len(&r.value_name, MAX_SHORT, "value_name")?;
            len(&r.value_data, MAX_TEXT, "value_data")
        }
        Some(Body::Logon(l)) => {
            len(&l.user, MAX_SHORT, "user")?;
            len(&l.domain, MAX_SHORT, "domain")?;
            if !l.source_ip.is_empty() && l.source_ip != "-" {
                ip(&l.source_ip, "source_ip")?;
            }
            Ok(())
        }
        Some(Body::Script(s)) => {
            len(&s.text, MAX_TEXT, "script.text")?;
            hash(&s.sha256, "script.sha256")
        }
        Some(Body::Image(i)) => {
            len(&i.image, MAX_PATH, "image")?;
            len(&i.loaded, MAX_PATH, "loaded")?;
            hash(&i.sha256, "image.sha256")
        }
        Some(Body::Allowlist(a)) => {
            len(&a.path, MAX_PATH, "path")?;
            len(&a.publisher, MAX_SHORT, "publisher")?;
            hash(&a.sha256, "allowlist.sha256")
        }
        Some(Body::PolicyHit(h)) => {
            len(&h.policy_id, MAX_SHORT, "policy_id")?;
            len(&h.rule_id, MAX_SHORT, "rule_id")
        }
        Some(Body::Drift(d)) => {
            ident(&d.check_id, "check_id")?;
            len(&d.title, MAX_SHORT, "title")?;
            len(&d.expected, MAX_SHORT, "expected")?;
            len(&d.actual, MAX_SHORT, "actual")?;
            if !matches!(
                d.severity.as_str(),
                "info" | "low" | "medium" | "high" | "critical"
            ) {
                return Err(Violation::BadIdentifier("severity"));
            }
            Ok(())
        }
    }
}

fn ident(s: &str, what: &'static str) -> Result<(), Violation> {
    if s.is_empty()
        || s.len() > 128
        || !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
    {
        return Err(Violation::BadIdentifier(what));
    }
    Ok(())
}
fn len(s: &str, max: usize, what: &'static str) -> Result<(), Violation> {
    if s.len() > max {
        Err(Violation::TooLong(what, s.len()))
    } else {
        Ok(())
    }
}
pub fn hash(s: &str, what: &'static str) -> Result<(), Violation> {
    if s.is_empty() {
        return Ok(());
    }
    if s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        Ok(())
    } else {
        Err(Violation::BadHash(what))
    }
}
fn ip(s: &str, what: &'static str) -> Result<(), Violation> {
    if s.is_empty() || s.parse::<IpAddr>().is_ok() {
        Ok(())
    } else {
        Err(Violation::BadIp(what))
    }
}
fn port(p: u32, what: &'static str) -> Result<(), Violation> {
    if p <= 65535 {
        Ok(())
    } else {
        Err(Violation::BadPort(what))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hv_proto::{NetworkFlow, ProcessEvent};

    fn ev(seq: u64, body: Body) -> Event {
        Event {
            host_id: "web-001".into(),
            boot_id: "b1".into(),
            seq,
            ts_mono_ns: 0,
            ts_wall_ms: 1_700_000_000_000,
            body: Some(body),
        }
    }
    const NOW: u64 = 1_700_000_000_000;

    #[test]
    fn accepts_well_formed_flow() {
        let e = ev(
            1,
            Body::Flow(NetworkFlow {
                local_ip: "10.1.2.3".into(),
                remote_ip: "fe80::1".into(),
                local_port: 51000,
                remote_port: 443,
                protocol: "tcp".into(),
                ..Default::default()
            }),
        );
        assert_eq!(validate_event(&e, None, NOW), Ok(()));
    }
    #[test]
    fn rejects_bad_ip_port_and_hash() {
        let e = ev(
            1,
            Body::Flow(NetworkFlow {
                remote_ip: "999.1.1.1".into(),
                protocol: "tcp".into(),
                ..Default::default()
            }),
        );
        assert_eq!(
            validate_event(&e, None, NOW),
            Err(Violation::BadIp("remote_ip"))
        );
        let e = ev(
            1,
            Body::Flow(NetworkFlow {
                remote_port: 70000,
                protocol: "tcp".into(),
                ..Default::default()
            }),
        );
        assert_eq!(
            validate_event(&e, None, NOW),
            Err(Violation::BadPort("remote_port"))
        );
        let e = ev(
            1,
            Body::Process(ProcessEvent {
                sha256: "ZZ".into(),
                ..Default::default()
            }),
        );
        assert_eq!(
            validate_event(&e, None, NOW),
            Err(Violation::BadHash("process.sha256"))
        );
    }
    #[test]
    fn enforces_sequence_and_clock() {
        let e = ev(5, Body::Process(ProcessEvent::default()));
        assert_eq!(
            validate_event(&e, Some(5), NOW),
            Err(Violation::SeqNotIncreasing {
                expected_gt: 5,
                got: 5
            })
        );
        assert_eq!(validate_event(&e, Some(4), NOW), Ok(()));
        let mut late = e.clone();
        late.ts_wall_ms = NOW - 3 * 24 * 3600 * 1000;
        assert!(matches!(
            validate_event(&late, None, NOW),
            Err(Violation::ClockSkew { .. })
        ));
    }
    #[test]
    fn batch_keeps_good_drops_bad() {
        let b = EventBatch {
            events: vec![
                ev(1, Body::Process(ProcessEvent::default())),
                ev(1, Body::Process(ProcessEvent::default())),
                ev(
                    2,
                    Body::Process(ProcessEvent {
                        command_line: "x".repeat(MAX_TEXT + 1),
                        ..Default::default()
                    }),
                ),
                ev(3, Body::Process(ProcessEvent::default())),
            ],
        };
        let (ok, bad) = validate_batch(&b, None, NOW);
        assert_eq!(ok.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![1, 3]);
        assert_eq!(bad.len(), 2);
    }
    #[test]
    fn rejects_hostile_identifiers() {
        let mut e = ev(1, Body::Process(ProcessEvent::default()));
        e.host_id = "web-001'; DROP TABLE hosts;--".into();
        assert_eq!(
            validate_event(&e, None, NOW),
            Err(Violation::BadIdentifier("host_id"))
        );
    }
}
