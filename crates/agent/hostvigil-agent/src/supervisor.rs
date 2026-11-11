//! Starts every enabled module, restarts any that panic or exit, and owns the
//! Windows service lifecycle.

use crate::{config::AgentConfig, modules, transport};
use anyhow::Result;
use flume::{bounded, Sender};
use hv_proto::event::Body;
use std::sync::Arc;
use tokio::task::JoinSet;
use tracing::{error, info, warn};

/// Any module emits bodies; the transport wraps them into `Event`s with
/// host/boot/seq/timestamps so modules never need to know about sequencing.
pub type EventTx = Sender<Body>;

pub async fn run(cfg: AgentConfig) -> Result<()> {
    let cfg = Arc::new(cfg);
    let (tx, rx) = bounded::<Body>(50_000);
    let mut set = JoinSet::new();

    // transport first so early events are buffered, not lost
    {
        let cfg = cfg.clone();
        set.spawn(async move { transport::run(cfg, rx).await.map_err(|e| ("transport", e)) });
    }
    macro_rules! spawn_module {
        ($flag:expr, $name:literal, $fut:expr) => {
            if $flag {
                let cfg = cfg.clone();
                let tx = tx.clone();
                set.spawn(async move { $fut(cfg, tx).await.map_err(|e| ($name, e)) });
                info!(module = $name, "started");
            }
        };
    }
    spawn_module!(cfg.modules.etw, "etw", modules::etw::run);
    spawn_module!(cfg.modules.wfp, "wfp", modules::wfp::run);
    spawn_module!(cfg.modules.fim, "fim", modules::fim::run);
    spawn_module!(cfg.modules.inventory, "inventory", modules::inventory::run);
    spawn_module!(cfg.modules.allowlist, "allowlist", modules::allowlist::run);
    spawn_module!(cfg.modules.baseline, "baseline", modules::baseline::run);

    while let Some(res) = set.join_next().await {
        match res {
            Ok(Ok(())) => warn!("a module exited cleanly; this is unexpected while running"),
            Ok(Err((name, e))) => {
                error!(module = name, error = %e, "module failed; supervisor will restart it")
            }
            Err(e) => error!(error = %e, "module task panicked"),
        }
        // Restart policy is deliberately simple for v0.1: the service manager
        // restarts the whole process on exit (see installer/service recovery).
        break;
    }
    anyhow::bail!("supervisor exiting so SCM recovery can restart the service")
}

#[cfg(windows)]
pub mod service {
    use super::*;
    use std::ffi::OsString;
    use std::time::Duration;
    use windows_service::{
        define_windows_service,
        service::{
            ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl,
            ServiceExitCode, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    const NAME: &str = "HostVigilAgent";
    static mut CFG: Option<AgentConfig> = None;

    define_windows_service!(ffi_main, service_main);

    pub fn run_as_service(cfg: AgentConfig) -> Result<()> {
        // SAFETY: set once before the dispatcher starts the service thread.
        unsafe { CFG = Some(cfg) };
        service_dispatcher::start(NAME, ffi_main)?;
        Ok(())
    }

    fn service_main(_args: Vec<OsString>) {
        let cfg = unsafe { CFG.take() }.expect("config");
        let (stop_tx, stop_rx) = std::sync::mpsc::channel();
        let handler = move |c: ServiceControl| match c {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = stop_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let status = service_control_handler::register(NAME, handler).expect("register");
        let set = |state| {
            status.set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: state,
                controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 0,
                wait_hint: Duration::from_secs(10),
                process_id: None,
            })
        };
        let _ = set(ServiceState::Running);
        let rt = tokio::runtime::Runtime::new().expect("runtime");
        rt.spawn(async move {
            if let Err(e) = run(cfg).await {
                tracing::error!(error = %e, "agent stopped")
            }
        });
        let _ = stop_rx.recv();
        rt.shutdown_timeout(Duration::from_secs(5));
        let _ = set(ServiceState::Stopped);
    }

    pub fn install() -> Result<()> {
        let mgr =
            ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)?;
        let exe = std::env::current_exe()?;
        let info = ServiceInfo {
            name: NAME.into(),
            display_name: "HostVigil Agent".into(),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: exe,
            launch_arguments: vec!["run".into()],
            dependencies: vec![],
            account_name: None, // LocalSystem
            account_password: None,
        };
        let svc = mgr.create_service(&info, ServiceAccess::CHANGE_CONFIG)?;
        svc.set_description(
            "HostVigil endpoint telemetry, FIM, allowlisting and microsegmentation agent",
        )?;
        println!("installed {NAME}");
        Ok(())
    }

    pub fn uninstall() -> Result<()> {
        let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let svc = mgr.open_service(NAME, ServiceAccess::DELETE | ServiceAccess::STOP)?;
        let _ = svc.stop();
        svc.delete()?;
        println!("removed {NAME}");
        Ok(())
    }
}

#[cfg(not(windows))]
pub mod service {
    use anyhow::Result;
    pub fn install() -> Result<()> {
        anyhow::bail!("service install is Windows-only")
    }
    pub fn uninstall() -> Result<()> {
        anyhow::bail!("service uninstall is Windows-only")
    }
}
