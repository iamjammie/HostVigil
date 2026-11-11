//! Application allowlisting via WDAC (Code Integrity) with AppLocker as a
//! fallback on editions without WDAC. Audit-mode events (3076/3077 in
//! Microsoft-Windows-CodeIntegrity/Operational, 8003/8004 for AppLocker) are
//! forwarded so the server can learn the golden image and propose a policy.
//! Enforcement applies a server-signed policy XML through CiTool.

#[cfg(windows)]
use crate::modules::health::ALLOWLIST;
use crate::{config::AgentConfig, supervisor::EventTx};
use anyhow::Result;
use hv_proto::AllowlistPolicy;
#[cfg(windows)]
use hv_proto::{allowlist_event::Verdict, event::Body, AllowlistEvent};
use std::sync::Arc;

pub async fn run(_cfg: Arc<AgentConfig>, tx: EventTx) -> Result<()> {
    #[cfg(windows)]
    {
        windows_impl::subscribe(tx).await
    }
    #[cfg(not(windows))]
    {
        let _ = tx;
        tracing::warn!("allowlist module is Windows-only; idling");
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await
        }
    }
}

pub fn apply_policy(p: &AllowlistPolicy) -> Result<()> {
    let dir = std::path::Path::new(r"C:\ProgramData\HostVigil\policy");
    std::fs::create_dir_all(dir)?;
    let xml = dir.join(format!("{}-v{}.xml", p.policy_id, p.version));
    std::fs::write(&xml, &p.policy_xml)?;
    match p.engine {
        e if e == hv_proto::allowlist_policy::Engine::Wdac as i32 => {
            // ConvertFrom-CIPolicy -> .cip, then CiTool --update-policy (Win11 22H2+/Server 2022+); legacy path copies to
            // C:\Windows\System32\CodeIntegrity\CiPolicies\Active\{guid}.cip and triggers RefreshPolicy.
            let cip = xml.with_extension("cip");
            run_ps(&format!(
                "ConvertFrom-CIPolicy -XmlFilePath '{}' -BinaryFilePath '{}'",
                xml.display(),
                cip.display()
            ))?;
            if std::path::Path::new(r"C:\Windows\System32\CiTool.exe").exists() {
                let st = std::process::Command::new(r"C:\Windows\System32\CiTool.exe")
                    .args(["--update-policy", &cip.to_string_lossy(), "--json"])
                    .status()?;
                anyhow::ensure!(st.success(), "CiTool failed");
            } else {
                run_ps(&format!("Copy-Item '{}' 'C:\\Windows\\System32\\CodeIntegrity\\CiPolicies\\Active\\'; Invoke-CimMethod -Namespace root/Microsoft/Windows/CI -ClassName PS_UpdateAndCompareCIPolicy -MethodName Update -Arguments @{{FilePath='{}'}}", cip.display(), cip.display()))?;
            }
        }
        _ => {
            run_ps(&format!(
                "Set-AppLockerPolicy -XmlPolicy '{}' ",
                xml.display()
            ))?;
        }
    }
    tracing::info!(policy = %p.policy_id, version = p.version, mode = p.mode, "allowlist policy applied");
    Ok(())
}

fn run_ps(script: &str) -> Result<()> {
    let st = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .status()?;
    anyhow::ensure!(st.success(), "powershell exited with {st}");
    Ok(())
}

/// Build a WDAC policy XML from a learned set of publishers and hashes.
/// Publisher rules are preferred; hashes cover unsigned binaries the team approved.
pub fn render_wdac_xml(
    policy_id: &str,
    audit: bool,
    publishers: &[&str],
    hashes: &[&str],
) -> String {
    let mut rules = String::new();
    for (i, p) in publishers.iter().enumerate() {
        rules.push_str(&format!(r#"<Signer ID="ID_SIGNER_{i}" Name="{p}"><CertRoot Type="TBS" Value=""/><CertPublisher Value="{p}"/></Signer>"#));
    }
    for (i, h) in hashes.iter().enumerate() {
        rules.push_str(&format!(
            r#"<Allow ID="ID_ALLOW_{i}" FriendlyName="approved hash" Hash="{h}"/>"#
        ));
    }
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Base Policy">
  <VersionEx>1.0.0.0</VersionEx><PolicyID>{{{policy_id}}}</PolicyID><BasePolicyID>{{{policy_id}}}</BasePolicyID>
  <Rules>
    {audit_rule}
    <Rule><Option>Enabled:UMCI</Option></Rule>
    <Rule><Option>Enabled:Unsigned System Integrity Policy</Option></Rule>
    <Rule><Option>Enabled:Advanced Boot Options Menu</Option></Rule>
    <Rule><Option>Enabled:Update Policy No Reboot</Option></Rule>
  </Rules>
  <FileRules>{rules}</FileRules>
  <Signers/>
  <SigningScenarios><SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_WINDOWS" FriendlyName="User mode"><ProductSigners/></SigningScenario></SigningScenarios>
</SiPolicy>"#,
        audit_rule = if audit {
            "<Rule><Option>Enabled:Audit Mode</Option></Rule>"
        } else {
            ""
        }
    )
}

#[cfg(windows)]
mod windows_impl {
    use super::*;
    pub async fn subscribe(tx: EventTx) -> Result<()> {
        // EvtSubscribe on Microsoft-Windows-CodeIntegrity/Operational (3076 audit, 3077 block) and
        // Microsoft-Windows-AppLocker/EXE and DLL (8003 audit, 8004 block). v0.1 polls with wevtutil
        // every 15 s; v0.2 switches to EvtSubscribe push.
        let mut last = String::new();
        loop {
            let out = std::process::Command::new("wevtutil")
                .args([
                    "qe",
                    "Microsoft-Windows-CodeIntegrity/Operational",
                    "/q:*[System[(EventID=3076 or EventID=3077)]]",
                    "/c:200",
                    "/rd:true",
                    "/f:xml",
                ])
                .output();
            if let Ok(o) = out {
                let xml = String::from_utf8_lossy(&o.stdout);
                for ev in xml.split("</Event>") {
                    if ev.trim().is_empty() || last.contains(ev) {
                        continue;
                    }
                    let id = extract(ev, "EventID").parse::<u32>().unwrap_or(0);
                    let path = extract(ev, "FileNameBuffer");
                    if path.is_empty() {
                        continue;
                    }
                    ALLOWLIST.emitted();
                    let _ = tx
                        .send_async(Body::Allowlist(AllowlistEvent {
                            verdict: if id == 3077 {
                                Verdict::Blocked
                            } else {
                                Verdict::AuditWouldBlock
                            } as i32,
                            path,
                            sha256: extract(ev, "SHA256FlatHash"),
                            publisher: String::new(),
                            policy_id: extract(ev, "PolicyName"),
                            pid: extract(ev, "ProcessID").parse().unwrap_or(0),
                            user: String::new(),
                        }))
                        .await;
                }
                last = xml.chars().take(200_000).collect();
            }
            tokio::time::sleep(std::time::Duration::from_secs(15)).await;
        }
    }
    fn extract(xml: &str, name: &str) -> String {
        let a = format!("Name='{name}'>");
        let b = format!("<{name}>");
        let start = xml
            .find(&a)
            .map(|i| i + a.len())
            .or_else(|| xml.find(&b).map(|i| i + b.len()));
        start
            .and_then(|s| xml[s..].find('<').map(|e| xml[s..s + e].to_string()))
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn wdac_xml_has_audit_flag_only_in_audit_mode() {
        let a = super::render_wdac_xml("ABC", true, &["Microsoft Corporation"], &[]);
        let e = super::render_wdac_xml("ABC", false, &["Microsoft Corporation"], &["AA"]);
        assert!(a.contains("Audit Mode"));
        assert!(!e.contains("Audit Mode"));
        assert!(e.contains("ID_ALLOW_0"));
    }
}
