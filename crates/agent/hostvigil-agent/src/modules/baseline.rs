//! Baseline and drift. The agent produces a canonical JSON snapshot of
//! security-relevant configuration and evaluates a bundled set of CIS-style
//! checks locally (so findings arrive even when the server is down). The
//! server diffs consecutive snapshots to produce drift timelines.

use crate::{config::AgentConfig, modules::health::BASELINE, supervisor::EventTx};
use anyhow::Result;
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use hv_proto::{event::Body, DriftFinding};

#[derive(Debug, Serialize)]
pub struct Baseline {
    pub sha256: String,
    pub items: BTreeMap<String, String>,
}

pub async fn run(cfg: Arc<AgentConfig>, tx: EventTx) -> Result<()> {
    let mut tick = tokio::time::interval(Duration::from_secs(
        cfg.inventory_interval_s.clamp(300, 86_400),
    ));
    let mut last_hash = String::new();
    loop {
        tick.tick().await;
        let b = match tokio::task::spawn_blocking(snapshot).await? {
            Ok(b) => b,
            Err(e) => {
                BASELINE.error(&e);
                continue;
            }
        };
        if b.sha256 != last_hash {
            tracing::info!(hash = %b.sha256, "baseline changed");
            for f in evaluate(&b) {
                BASELINE.emitted();
                let _ = tx.send_async(Body::Drift(f)).await;
            }
            last_hash = b.sha256;
        }
    }
}

pub fn snapshot() -> Result<Baseline> {
    let items = collect_items();
    let sha256 = hv_common::sha256_hex(&hv_common::canonical_json(&items)?);
    Ok(Baseline { sha256, items })
}

/// Each check: (id, title, key in snapshot, expected value, severity).
pub const CHECKS: &[(&str, &str, &str, &str, &str)] = &[
    ("hv-smb1", "SMBv1 server disabled", "smb1", "0", "high"),
    (
        "hv-rdp-nla",
        "RDP requires Network Level Authentication",
        "rdp_nla",
        "1",
        "medium",
    ),
    (
        "hv-lsa-ppl",
        "LSA runs as Protected Process Light",
        "lsa_ppl",
        "1",
        "high",
    ),
    (
        "hv-wdigest",
        "WDigest credential caching disabled",
        "wdigest",
        "0",
        "high",
    ),
    (
        "hv-defender",
        "Defender real-time protection enabled",
        "defender_disabled",
        "0",
        "critical",
    ),
    (
        "hv-fw-domain",
        "Firewall domain profile on",
        "fw_domain",
        "1",
        "high",
    ),
    (
        "hv-ps-sbl",
        "PowerShell script block logging on",
        "ps_scriptblock",
        "1",
        "medium",
    ),
    ("hv-uac", "UAC enabled", "uac", "1", "medium"),
    (
        "hv-guest",
        "Guest account disabled",
        "guest_enabled",
        "0",
        "medium",
    ),
    (
        "hv-autorun",
        "Autorun disabled for all drives",
        "autorun",
        "255",
        "low",
    ),
    ("hv-llmnr", "LLMNR disabled", "llmnr", "0", "medium"),
    (
        "hv-netbios",
        "NetBIOS over TCP/IP disabled",
        "netbios",
        "2",
        "low",
    ),
    (
        "hv-anon-share",
        "Anonymous share enumeration restricted",
        "restrict_anon",
        "1",
        "medium",
    ),
    (
        "hv-audit-logon",
        "Logon success/failure auditing enabled",
        "audit_logon",
        "3",
        "high",
    ),
];

pub fn evaluate(b: &Baseline) -> Vec<DriftFinding> {
    CHECKS
        .iter()
        .filter_map(|(id, title, key, expected, sev)| {
            let actual = b
                .items
                .get(*key)
                .cloned()
                .unwrap_or_else(|| "missing".into());
            if actual == *expected {
                None
            } else {
                Some(DriftFinding {
                    check_id: id.to_string(),
                    title: title.to_string(),
                    expected: expected.to_string(),
                    actual,
                    severity: sev.to_string(),
                    resolved: false,
                })
            }
        })
        .collect()
}

fn collect_items() -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    #[cfg(windows)]
    {
        use winreg::{enums::*, RegKey};
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let dw = |path: &str, name: &str, default: u32| -> String {
            hklm.open_subkey(path)
                .ok()
                .and_then(|k| k.get_value::<u32, _>(name).ok())
                .unwrap_or(default)
                .to_string()
        };
        m.insert(
            "smb1".into(),
            dw(
                r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                "SMB1",
                1,
            ),
        );
        m.insert(
            "rdp_nla".into(),
            dw(
                r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                "UserAuthentication",
                0,
            ),
        );
        m.insert(
            "lsa_ppl".into(),
            dw(r"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL", 0),
        );
        m.insert(
            "wdigest".into(),
            dw(
                r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
                "UseLogonCredential",
                0,
            ),
        );
        m.insert(
            "defender_disabled".into(),
            dw(
                r"SOFTWARE\Policies\Microsoft\Windows Defender",
                "DisableAntiSpyware",
                0,
            ),
        );
        m.insert("fw_domain".into(), dw(r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile", "EnableFirewall", 0));
        m.insert(
            "ps_scriptblock".into(),
            dw(
                r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
                "EnableScriptBlockLogging",
                0,
            ),
        );
        m.insert(
            "uac".into(),
            dw(
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                "EnableLUA",
                0,
            ),
        );
        m.insert(
            "autorun".into(),
            dw(
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                "NoDriveTypeAutoRun",
                0,
            ),
        );
        m.insert(
            "llmnr".into(),
            dw(
                r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
                "EnableMulticast",
                1,
            ),
        );
        m.insert(
            "restrict_anon".into(),
            dw(
                r"SYSTEM\CurrentControlSet\Control\Lsa",
                "RestrictAnonymous",
                0,
            ),
        );
        m.insert("guest_enabled".into(), guest_enabled());
        m.insert("netbios".into(), "0".into()); // per-adapter; v0.2
        m.insert("audit_logon".into(), auditpol("Logon"));
    }
    #[cfg(not(windows))]
    {
        m.insert("platform".into(), "non-windows".into());
    }
    m
}

#[cfg(windows)]
fn guest_enabled() -> String {
    let out = std::process::Command::new("net")
        .args(["user", "Guest"])
        .output();
    out.map(|o| {
        if String::from_utf8_lossy(&o.stdout).contains("Account active               Yes") {
            "1".into()
        } else {
            "0".into()
        }
    })
    .unwrap_or_else(|_| "missing".into())
}
#[cfg(windows)]
fn auditpol(sub: &str) -> String {
    let out = std::process::Command::new("auditpol")
        .args(["/get", &format!("/subcategory:{sub}"), "/r"])
        .output();
    out.map(|o| {
        let s = String::from_utf8_lossy(&o.stdout);
        if s.contains("Success and Failure") {
            "3".into()
        } else if s.contains("Success") {
            "1".into()
        } else if s.contains("Failure") {
            "2".into()
        } else {
            "0".into()
        }
    })
    .unwrap_or_else(|_| "missing".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn evaluate_flags_every_missing_item() {
        let b = Baseline {
            sha256: String::new(),
            items: BTreeMap::new(),
        };
        assert_eq!(evaluate(&b).len(), CHECKS.len());
    }
    #[test]
    fn evaluate_passes_when_compliant() {
        let items: BTreeMap<String, String> = CHECKS
            .iter()
            .map(|c| (c.2.to_string(), c.3.to_string()))
            .collect();
        assert!(evaluate(&Baseline {
            sha256: String::new(),
            items
        })
        .is_empty());
    }
}
