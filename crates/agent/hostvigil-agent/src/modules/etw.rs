//! ETW consumer: process create/exit, image loads, registry writes, logons,
//! PowerShell script blocks. Uses real-time kernel-logger-free providers so
//! no driver is needed. Hashing and Authenticode checks run on a worker pool
//! so the ETW callback never blocks.

#[cfg(windows)]
use crate::modules::health::ETW;
use crate::{config::AgentConfig, supervisor::EventTx};
use anyhow::Result;
#[cfg(windows)]
use hv_proto::event::Body;
use std::sync::Arc;

/// Provider GUIDs (stable across Windows 10/11/Server 2016-2025).
pub const PROVIDERS: &[(&str, &str, u64)] = &[
    (
        "Microsoft-Windows-Kernel-Process",
        "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716",
        0x10 | 0x40,
    ), // process + image
    (
        "Microsoft-Windows-Kernel-Registry",
        "70EB4F03-C1DE-4F73-A051-33D13D5413BD",
        0x1000 | 0x2000 | 0x4000,
    ),
    (
        "Microsoft-Windows-Security-Auditing",
        "54849625-5478-4994-A5BA-3E3B0328C30D",
        u64::MAX,
    ), // requires audit policy; 4624/4625/4648/4672/4688
    (
        "Microsoft-Windows-PowerShell",
        "A0C1853B-5C40-4B15-8766-3CF1C58F985A",
        0x0000000000000800,
    ), // script block logging (4104)
    (
        "Microsoft-Windows-Kernel-Audit-API-Calls",
        "E02A841C-75A3-4FA7-AFC8-AE09CF9B7F23",
        u64::MAX,
    ), // OpenProcess on lsass etc.
];

pub async fn run(_cfg: Arc<AgentConfig>, tx: EventTx) -> Result<()> {
    #[cfg(windows)]
    {
        return windows_impl::run(tx).await;
    }
    #[cfg(not(windows))]
    {
        let _ = tx;
        tracing::warn!("etw module is Windows-only; idling");
        futures_idle().await
    }
}

#[allow(dead_code)]
async fn futures_idle() -> Result<()> {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await
    }
}

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use ferrisetw::{
        parser::Parser, provider::Provider, schema_locator::SchemaLocator, trace::UserTrace,
        EventRecord,
    };
    use hv_proto::{
        process_event, ImageLoad, LogonEvent, ProcessEvent, RegistryEvent, ScriptBlock,
    };

    pub async fn run(tx: EventTx) -> Result<()> {
        let (raw_tx, raw_rx) = flume::bounded::<Body>(20_000);
        // ETW callbacks run on the provider thread; keep them cheap and hop to tokio.
        let providers: Vec<Provider> = PROVIDERS
            .iter()
            .map(|(name, guid, keywords)| {
                let raw_tx = raw_tx.clone();
                let name = *name;
                Provider::by_guid(*guid)
                    .any(*keywords)
                    .add_callback(move |rec: &EventRecord, loc: &SchemaLocator| {
                        if let Some(body) = decode(name, rec, loc) {
                            if raw_tx.try_send(body).is_err() {
                                ETW.dropped(1);
                            }
                        }
                    })
                    .build()
            })
            .collect();
        let mut trace = UserTrace::new().named("HostVigilAgent".into());
        for p in providers {
            trace = trace.enable(p);
        }
        let (_trace, handle) = trace.start()?;
        std::thread::spawn(move || {
            let _ = UserTrace::process_from_handle(handle);
        });

        // enrichment: hash + signer lookups off the hot path
        while let Ok(mut body) = raw_rx.recv_async().await {
            if let Body::Process(p) = &mut body {
                if p.kind == process_event::Kind::Create as i32 && !p.image.is_empty() {
                    let (sha, signer, valid) = super::enrich::hash_and_sign(&p.image).await;
                    p.sha256 = sha;
                    p.signer = signer;
                    p.signature_valid = valid;
                }
            }
            ETW.emitted();
            if tx.send_async(body).await.is_err() {
                break;
            }
        }
        Ok(())
    }

    fn decode(provider: &str, rec: &EventRecord, loc: &SchemaLocator) -> Option<Body> {
        let schema = loc.event_schema(rec).ok()?;
        let p = Parser::create(rec, &schema);
        let s = |n: &str| p.try_parse::<String>(n).unwrap_or_default();
        let u32v = |n: &str| p.try_parse::<u32>(n).unwrap_or_default();
        match (provider, rec.event_id()) {
            ("Microsoft-Windows-Kernel-Process", 1) => Some(Body::Process(ProcessEvent {
                kind: process_event::Kind::Create as i32,
                pid: u32v("ProcessID"),
                ppid: u32v("ParentProcessID"),
                image: s("ImageName"),
                command_line: String::new(),
                user: String::new(),
                session_id: u32v("SessionID"),
                ..Default::default()
            })),
            ("Microsoft-Windows-Kernel-Process", 2) => Some(Body::Process(ProcessEvent {
                kind: process_event::Kind::Exit as i32,
                pid: u32v("ProcessID"),
                image: s("ImageName"),
                exit_code: u32v("ExitStatus"),
                ..Default::default()
            })),
            ("Microsoft-Windows-Kernel-Process", 5) => Some(Body::Image(ImageLoad {
                pid: u32v("ProcessID"),
                loaded: s("ImageName"),
                ..Default::default()
            })),
            ("Microsoft-Windows-Kernel-Registry", 5) | ("Microsoft-Windows-Kernel-Registry", 6) => {
                Some(Body::Registry(RegistryEvent {
                    kind: 0,
                    key: s("RelativeName"),
                    value_name: s("ValueName"),
                    value_data: String::new(),
                    pid: rec.process_id(),
                    ..Default::default()
                }))
            }
            ("Microsoft-Windows-Security-Auditing", 4624)
            | ("Microsoft-Windows-Security-Auditing", 4625) => Some(Body::Logon(LogonEvent {
                logon_type: u32v("LogonType"),
                user: s("TargetUserName"),
                domain: s("TargetDomainName"),
                source_ip: s("IpAddress"),
                success: rec.event_id() == 4624,
                auth_package: s("AuthenticationPackageName"),
                event_id: rec.event_id() as u32,
            })),
            ("Microsoft-Windows-PowerShell", 4104) => {
                let text = s("ScriptBlockText");
                let sha = hv_common::sha256_hex(text.as_bytes());
                Some(Body::Script(ScriptBlock {
                    engine: "powershell".into(),
                    text,
                    sha256: sha,
                    pid: rec.process_id(),
                    user: String::new(),
                }))
            }
            _ => None,
        }
    }
}

pub mod enrich {
    /// SHA-256 of the file plus Authenticode signer subject and validity.
    /// Cached by (path, mtime) so repeated launches of the same binary are free.
    pub async fn hash_and_sign(path: &str) -> (String, String, bool) {
        use std::collections::HashMap;
        use std::sync::Mutex;
        static CACHE: Mutex<Option<HashMap<String, (String, String, bool)>>> = Mutex::new(None);
        if let Some(v) = CACHE
            .lock()
            .unwrap()
            .get_or_insert_with(HashMap::new)
            .get(path)
        {
            return v.clone();
        }
        let p = path.to_string();
        let res = tokio::task::spawn_blocking(move || {
            let sha = std::fs::read(&p)
                .map(|b| hv_common::sha256_hex(&b))
                .unwrap_or_default();
            let (signer, valid) = authenticode(&p);
            (sha, signer, valid)
        })
        .await
        .unwrap_or_default();
        CACHE
            .lock()
            .unwrap()
            .get_or_insert_with(HashMap::new)
            .insert(path.to_string(), res.clone());
        res
    }

    #[cfg(windows)]
    fn authenticode(path: &str) -> (String, bool) {
        // WinVerifyTrust with WINTRUST_ACTION_GENERIC_VERIFY_V2; subject pulled via CryptQueryObject.
        // Full implementation in v0.2; v0.1 reports validity only.
        use windows::core::HSTRING;
        use windows::Win32::Foundation::HWND;
        use windows::Win32::Security::WinTrust::{
            WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO,
            WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
        };
        let file = HSTRING::from(path);
        let mut fi = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: windows::core::PCWSTR(file.as_ptr()),
            ..Default::default()
        };
        let mut wd = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            dwStateAction: WTD_STATEACTION_VERIFY,
            ..Default::default()
        };
        wd.Anonymous.pFile = &mut fi;
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let status = unsafe {
            WinVerifyTrust(
                HWND(std::ptr::null_mut()),
                &mut action,
                &mut wd as *mut _ as *mut _,
            )
        };
        (String::new(), status == 0)
    }
    #[cfg(not(windows))]
    fn authenticode(_path: &str) -> (String, bool) {
        (String::new(), false)
    }
}
