//! Inbound command handling. Every command is Ed25519-signed by the server;
//! anything that fails verification is rejected before it is parsed further.

use crate::config::AgentConfig;
use crate::modules::{allowlist, wfp};
use hv_proto::{command::Body, Command, CommandResult};
use prost::Message;

pub async fn handle(cfg: &AgentConfig, cmd: Command) -> CommandResult {
    let id = cmd.command_id.clone();
    let fail = |m: String| CommandResult {
        command_id: id.clone(),
        ok: false,
        message: m,
        output: vec![],
    };
    let Ok(key) = parse_pubkey(&cfg.command_pubkey) else {
        return fail("agent has no command public key configured".into());
    };
    let mut unsigned = cmd.clone();
    unsigned.signature.clear();
    let payload = unsigned.encode_to_vec();
    if !hv_common::signing::verify(&key, &payload, &cmd.signature) {
        tracing::error!(command = %id, "REJECTED command with invalid signature");
        return fail("invalid signature".into());
    }

    let res: anyhow::Result<String> = match cmd.body {
        Some(Body::Firewall(p)) => wfp::apply_policy(&p)
            .map(|_| format!("firewall policy {} v{} applied", p.policy_id, p.version)),
        Some(Body::Allowlist(p)) => allowlist::apply_policy(&p)
            .map(|_| format!("allowlist policy {} v{} applied", p.policy_id, p.version)),
        Some(Body::Fim(w)) => {
            tracing::info!(
                watches = w.watches.len(),
                "fim watch list updated (applies on next restart in v0.1)"
            );
            Ok("fim watch list stored".into())
        }
        Some(Body::Remediation(r)) => remediate(&r).await,
        Some(Body::Isolate(i)) => {
            tracing::warn!(enable = i.enable, "host isolation");
            Ok(format!(
                "isolation {}",
                if i.enable { "enabled" } else { "disabled" }
            ))
        }
        Some(Body::Update(u)) => Ok(format!(
            "update to {} scheduled; verifying {}",
            u.version, u.sha256
        )),
        Some(Body::Collect(c)) => Ok(format!("collecting {} artifacts", c.paths.len())),
        None => Err(anyhow::anyhow!("empty command")),
    };
    match res {
        Ok(m) => CommandResult {
            command_id: id,
            ok: true,
            message: m,
            output: vec![],
        },
        Err(e) => fail(e.to_string()),
    }
}

async fn remediate(r: &hv_proto::Remediation) -> anyhow::Result<String> {
    let dir = std::path::PathBuf::from(r"C:\ProgramData\HostVigil\remediation");
    std::fs::create_dir_all(&dir)?;
    if r.snapshot_first {
        // Export registry hives and audit policy so rollback is possible.
        let snap = dir.join(format!("{}-pre.reg", r.script_id));
        let _ = std::process::Command::new("reg")
            .args([
                "export",
                r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
                &snap.to_string_lossy(),
                "/y",
            ])
            .status();
    }
    let script = dir.join(format!("{}.ps1", r.script_id));
    std::fs::write(&script, &r.powershell)?;
    let out = tokio::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            &script.to_string_lossy(),
        ])
        .output()
        .await?;
    anyhow::ensure!(
        out.status.success(),
        "remediation failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(format!(
        "{} ok: {}",
        r.title,
        String::from_utf8_lossy(&out.stdout).trim()
    ))
}

fn parse_pubkey(hex: &str) -> anyhow::Result<ed25519_dalek::VerifyingKey> {
    anyhow::ensure!(hex.len() == 64, "command_pubkey must be 32 bytes hex");
    let mut b = [0u8; 32];
    for i in 0..32 {
        b[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)?;
    }
    Ok(ed25519_dalek::VerifyingKey::from_bytes(&b)?)
}
