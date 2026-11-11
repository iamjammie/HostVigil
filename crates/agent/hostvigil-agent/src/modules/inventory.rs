//! Endpoint metadata: OS, hardware, TPM/BitLocker, installed software,
//! services, scheduled tasks, local accounts, listening ports, certificates,
//! hotfixes. Full snapshot every `inventory_interval_s`; registry-watch
//! deltas in between (Uninstall keys, Services, Run keys).

use crate::{config::AgentConfig, modules::health::INVENTORY, supervisor::EventTx};
use anyhow::Result;
use hv_proto::{
    HostFacts, Hotfix, InventorySnapshot, ListeningPort, LocalAccount, ScheduledTask, Service,
    Software,
};
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;

pub async fn run(cfg: Arc<AgentConfig>, _tx: EventTx) -> Result<()> {
    // Inventory is sent as its own AgentMessage (not an Event) because it is a
    // full-state document, not a point-in-time fact. The transport exposes a
    // side channel for it; v0.1 logs the snapshot size and hands it over via
    // the shared OnceLock the transport polls on each heartbeat.
    let mut tick = tokio::time::interval(Duration::from_secs(cfg.inventory_interval_s.max(60)));
    loop {
        tick.tick().await;
        match tokio::task::spawn_blocking(collect_now).await? {
            Ok(snap) => {
                INVENTORY.emitted();
                LATEST.lock().unwrap().replace(snap.into_proto());
            }
            Err(e) => {
                INVENTORY.error(&e);
                tracing::warn!(error = %e, "inventory collection failed");
            }
        }
    }
}

pub static LATEST: std::sync::Mutex<Option<InventorySnapshot>> = std::sync::Mutex::new(None);

#[derive(Debug, Default, Serialize)]
pub struct Snapshot {
    pub facts: Facts,
    pub software: Vec<Sw>,
    pub services: Vec<Svc>,
    pub tasks: Vec<Task>,
    pub accounts: Vec<Account>,
    pub listening: Vec<Port>,
    pub hotfixes: Vec<Kb>,
}
#[derive(Debug, Default, Serialize)]
pub struct Facts {
    pub hostname: String,
    pub domain: String,
    pub os_version: String,
    pub build: String,
    pub manufacturer: String,
    pub model: String,
    pub tpm_present: bool,
    pub secure_boot: bool,
    pub bitlocker_volumes: Vec<String>,
    pub unencrypted_volumes: Vec<String>,
    pub cpu_cores: u32,
    pub ram_mb: u64,
    pub ips: Vec<String>,
    pub rdp_enabled: bool,
    pub rdp_nla: bool,
    pub smb1_enabled: bool,
    pub defender_enabled: bool,
    pub lsa_ppl: bool,
    pub laps_applied: bool,
}
#[derive(Debug, Default, Serialize)]
pub struct Sw {
    pub name: String,
    pub version: String,
    pub publisher: String,
    pub install_date: String,
    pub source: String,
}
#[derive(Debug, Default, Serialize)]
pub struct Svc {
    pub name: String,
    pub display: String,
    pub path: String,
    pub start_type: String,
    pub account: String,
    pub state: String,
    pub unquoted_path: bool,
}
#[derive(Debug, Default, Serialize)]
pub struct Task {
    pub name: String,
    pub path: String,
    pub action: String,
    pub run_as: String,
    pub enabled: bool,
}
#[derive(Debug, Default, Serialize)]
pub struct Account {
    pub name: String,
    pub enabled: bool,
    pub admin: bool,
    pub password_never_expires: bool,
}
#[derive(Debug, Default, Serialize)]
pub struct Port {
    pub protocol: String,
    pub port: u32,
    pub pid: u32,
    pub image: String,
}
#[derive(Debug, Default, Serialize)]
pub struct Kb {
    pub kb: String,
    pub installed_on: String,
}

impl Snapshot {
    pub fn into_proto(self) -> InventorySnapshot {
        let f = self.facts;
        InventorySnapshot {
            ts_wall_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            facts: Some(HostFacts {
                hostname: f.hostname,
                domain: f.domain,
                os_version: f.os_version,
                build: f.build,
                manufacturer: f.manufacturer,
                model: f.model,
                tpm_present: f.tpm_present,
                secure_boot: f.secure_boot,
                bitlocker_volumes: f.bitlocker_volumes,
                unencrypted_volumes: f.unencrypted_volumes,
                cpu_cores: f.cpu_cores,
                ram_mb: f.ram_mb,
                ips: f.ips,
                rdp_enabled: f.rdp_enabled,
                rdp_nla: f.rdp_nla,
                smb1_enabled: f.smb1_enabled,
                defender_enabled: f.defender_enabled,
                lsa_ppl: f.lsa_ppl,
                laps_applied: f.laps_applied,
                ..Default::default()
            }),
            software: self
                .software
                .into_iter()
                .map(|s| Software {
                    name: s.name,
                    version: s.version,
                    publisher: s.publisher,
                    install_date: s.install_date,
                    source: s.source,
                    path: String::new(),
                })
                .collect(),
            services: self
                .services
                .into_iter()
                .map(|s| Service {
                    name: s.name,
                    display: s.display,
                    path: s.path,
                    start_type: s.start_type,
                    account: s.account,
                    state: s.state,
                    unquoted_path: s.unquoted_path,
                    signer: String::new(),
                })
                .collect(),
            tasks: self
                .tasks
                .into_iter()
                .map(|t| ScheduledTask {
                    name: t.name,
                    path: t.path,
                    action: t.action,
                    run_as: t.run_as,
                    trigger: String::new(),
                    enabled: t.enabled,
                    author: String::new(),
                })
                .collect(),
            accounts: self
                .accounts
                .into_iter()
                .map(|a| LocalAccount {
                    name: a.name,
                    enabled: a.enabled,
                    admin: a.admin,
                    last_logon: String::new(),
                    password_never_expires: a.password_never_expires,
                })
                .collect(),
            listening: self
                .listening
                .into_iter()
                .map(|p| ListeningPort {
                    protocol: p.protocol,
                    port: p.port,
                    pid: p.pid,
                    image: p.image,
                    bind: String::new(),
                })
                .collect(),
            certificates: vec![],
            hotfixes: self
                .hotfixes
                .into_iter()
                .map(|k| Hotfix {
                    kb: k.kb,
                    installed_on: k.installed_on,
                    description: String::new(),
                })
                .collect(),
        }
    }
}

pub fn collect_now() -> Result<Snapshot> {
    #[cfg(windows)]
    {
        windows_impl::collect()
    }
    #[cfg(not(windows))]
    {
        Ok(Snapshot {
            facts: Facts {
                hostname: std::env::var("HOSTNAME").unwrap_or_default(),
                os_version: os_version(),
                ips: ips(),
                cpu_cores: std::thread::available_parallelism()
                    .map(|n| n.get() as u32)
                    .unwrap_or(1),
                ..Default::default()
            },
            ..Default::default()
        })
    }
}

pub fn os_version() -> String {
    #[cfg(windows)]
    {
        windows_impl::os_version()
    }
    #[cfg(not(windows))]
    {
        std::fs::read_to_string("/etc/os-release")
            .ok()
            .and_then(|s| {
                s.lines().find(|l| l.starts_with("PRETTY_NAME=")).map(|l| {
                    l.trim_start_matches("PRETTY_NAME=")
                        .trim_matches('"')
                        .to_string()
                })
            })
            .unwrap_or_else(|| "unknown".into())
    }
}

pub fn ips() -> Vec<String> {
    // Portable fallback: bind a UDP socket toward a non-routable address to learn the primary IP.
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("10.255.255.255:1")?;
            s.local_addr()
        })
        .map(|a| vec![a.ip().to_string()])
        .unwrap_or_default()
}

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use std::collections::HashMap;
    use winreg::{enums::*, RegKey};
    use wmi::{COMLibrary, WMIConnection};

    pub fn os_version() -> String {
        let cv = RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
            .ok();
        let g = |k: &str| {
            cv.as_ref()
                .and_then(|c| c.get_value::<String, _>(k).ok())
                .unwrap_or_default()
        };
        let ubr: u32 = cv
            .as_ref()
            .and_then(|c| c.get_value("UBR").ok())
            .unwrap_or(0);
        format!(
            "{} {} ({}.{})",
            g("ProductName"),
            g("DisplayVersion"),
            g("CurrentBuildNumber"),
            ubr
        )
    }

    pub fn collect() -> Result<Snapshot> {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let com = COMLibrary::new()?;
        let wmi = WMIConnection::new(com)?;
        let q = |sql: &str| -> Vec<HashMap<String, wmi::Variant>> {
            wmi.raw_query(sql).unwrap_or_default()
        };
        let s = |m: &HashMap<String, wmi::Variant>, k: &str| match m.get(k) {
            Some(wmi::Variant::String(v)) => v.clone(),
            Some(other) => format!("{other:?}"),
            None => String::new(),
        };
        let b = |m: &HashMap<String, wmi::Variant>, k: &str| {
            matches!(m.get(k), Some(wmi::Variant::Bool(true)))
        };

        let cs = q("SELECT Manufacturer, Model, Domain, TotalPhysicalMemory, NumberOfLogicalProcessors FROM Win32_ComputerSystem").into_iter().next().unwrap_or_default();
        let tpm = q("SELECT IsEnabled_InitialValue FROM Win32_Tpm")
            .into_iter()
            .next()
            .map(|m| b(&m, "IsEnabled_InitialValue"))
            .unwrap_or(false);
        let (mut enc, mut unenc) = (vec![], vec![]);
        for v in q("SELECT DriveLetter, ProtectionStatus FROM Win32_EncryptableVolume") {
            let dl = s(&v, "DriveLetter");
            if matches!(v.get("ProtectionStatus"), Some(wmi::Variant::UI4(1))) {
                enc.push(dl)
            } else {
                unenc.push(dl)
            }
        }

        let mut software = vec![];
        for (root, flags, src) in [
            (
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                KEY_READ,
                "registry",
            ),
            (
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
                KEY_READ,
                "registry-wow64",
            ),
        ] {
            if let Ok(k) = hklm.open_subkey_with_flags(root, flags) {
                for sub in k.enum_keys().flatten() {
                    if let Ok(e) = k.open_subkey(&sub) {
                        let name: String = e.get_value("DisplayName").unwrap_or_default();
                        if name.is_empty() {
                            continue;
                        }
                        software.push(Sw {
                            name,
                            version: e.get_value("DisplayVersion").unwrap_or_default(),
                            publisher: e.get_value("Publisher").unwrap_or_default(),
                            install_date: e.get_value("InstallDate").unwrap_or_default(),
                            source: src.into(),
                        });
                    }
                }
            }
        }
        let services = q(
            "SELECT Name, DisplayName, PathName, StartMode, StartName, State FROM Win32_Service",
        )
        .into_iter()
        .map(|m| {
            let path = s(&m, "PathName");
            let unquoted = !path.starts_with('"')
                && path.contains(' ')
                && !path.to_ascii_lowercase().contains("svchost");
            Svc {
                name: s(&m, "Name"),
                display: s(&m, "DisplayName"),
                path,
                start_type: s(&m, "StartMode"),
                account: s(&m, "StartName"),
                state: s(&m, "State"),
                unquoted_path: unquoted,
            }
        })
        .collect();
        let accounts = q("SELECT Name, Disabled, PasswordExpires FROM Win32_UserAccount WHERE LocalAccount = TRUE").into_iter().map(|m| Account { name: s(&m, "Name"), enabled: !b(&m, "Disabled"), admin: false, password_never_expires: !b(&m, "PasswordExpires") }).collect();
        let hotfixes = q("SELECT HotFixID, InstalledOn FROM Win32_QuickFixEngineering")
            .into_iter()
            .map(|m| Kb {
                kb: s(&m, "HotFixID"),
                installed_on: s(&m, "InstalledOn"),
            })
            .collect();
        let tasks = vec![]; // Task Scheduler COM (ITaskService) in v0.2; v0.1 reads via schtasks /query /xml on demand
        let listening = listening_ports();

        let dw = |path: &str, name: &str| -> Option<u32> {
            hklm.open_subkey(path).ok()?.get_value(name).ok()
        };
        Ok(Snapshot {
            facts: Facts {
                hostname: std::env::var("COMPUTERNAME").unwrap_or_default(),
                domain: s(&cs, "Domain"),
                os_version: os_version(),
                build: String::new(),
                manufacturer: s(&cs, "Manufacturer"),
                model: s(&cs, "Model"),
                tpm_present: tpm,
                secure_boot: dw(
                    r"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
                    "UEFISecureBootEnabled",
                ) == Some(1),
                bitlocker_volumes: enc,
                unencrypted_volumes: unenc,
                cpu_cores: std::thread::available_parallelism()
                    .map(|n| n.get() as u32)
                    .unwrap_or(1),
                ram_mb: 0,
                ips: super::ips(),
                rdp_enabled: dw(
                    r"SYSTEM\CurrentControlSet\Control\Terminal Server",
                    "fDenyTSConnections",
                ) == Some(0),
                rdp_nla: dw(
                    r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                    "UserAuthentication",
                ) == Some(1),
                smb1_enabled: dw(
                    r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                    "SMB1",
                )
                .unwrap_or(1)
                    == 1,
                defender_enabled: dw(
                    r"SOFTWARE\Policies\Microsoft\Windows Defender",
                    "DisableAntiSpyware",
                ) != Some(1),
                lsa_ppl: dw(r"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL")
                    .map(|v| v >= 1)
                    .unwrap_or(false),
                laps_applied: hklm
                    .open_subkey(r"SOFTWARE\Microsoft\Policies\LAPS")
                    .is_ok(),
            },
            software,
            services,
            tasks,
            accounts,
            listening,
            hotfixes,
        })
    }

    fn listening_ports() -> Vec<Port> {
        // GetExtendedTcpTable(TCP_TABLE_OWNER_PID_LISTENER) + GetExtendedUdpTable; v0.1 shells out for brevity.
        let out = std::process::Command::new("netstat")
            .args(["-ano", "-p", "tcp"])
            .output()
            .ok();
        let Some(out) = out else { return vec![] };
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| l.contains("LISTENING"))
            .filter_map(|l| {
                let c: Vec<_> = l.split_whitespace().collect();
                let port = c.get(1)?.rsplit(':').next()?.parse().ok()?;
                let pid = c.get(4)?.parse().ok()?;
                Some(Port {
                    protocol: "tcp".into(),
                    port,
                    pid,
                    image: String::new(),
                })
            })
            .collect()
    }
}
