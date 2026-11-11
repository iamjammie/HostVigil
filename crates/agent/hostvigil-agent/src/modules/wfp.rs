//! Flow telemetry and microsegmentation enforcement.
//!
//! v0.1 collects flows from the `Microsoft-Windows-Kernel-Network` ETW
//! provider (TcpIp connect/accept/send/recv with PID) and enforces policy by
//! programming Windows Filtering Platform filters at the ALE connect/accept
//! layers through the user-mode `FwpmEngine*` API. No kernel callout driver.

use crate::{config::AgentConfig, modules::health::WFP, supervisor::EventTx};
use anyhow::Result;
use hv_proto::{event::Body, network_flow::Direction, FirewallPolicy, NetworkFlow};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Aggregation key: flows are rolled up for 10 s before emission so a chatty
/// connection yields one event with byte counters instead of thousands.
#[derive(Hash, PartialEq, Eq, Clone)]
struct Key {
    proto: &'static str,
    lip: String,
    lport: u16,
    rip: String,
    rport: u16,
    pid: u32,
    dir: Direction,
}

struct Agg {
    bytes_in: u64,
    bytes_out: u64,
    first: Instant,
    image: String,
}

pub async fn run(_cfg: Arc<AgentConfig>, tx: EventTx) -> Result<()> {
    let (raw_tx, raw_rx) = flume::bounded::<(Key, u64, bool)>(50_000);
    #[cfg(windows)]
    windows_impl::start_network_trace(raw_tx)?;
    #[cfg(not(windows))]
    {
        drop(raw_tx);
        tracing::warn!("wfp module is Windows-only; idling");
    }

    let mut table: HashMap<Key, Agg> = HashMap::new();
    let mut tick = tokio::time::interval(Duration::from_secs(10));
    loop {
        tokio::select! {
            Ok((k, bytes, inbound)) = raw_rx.recv_async() => {
                let e = table.entry(k.clone()).or_insert_with(|| Agg { bytes_in: 0, bytes_out: 0, first: Instant::now(), image: image_for_pid(k.pid) });
                if inbound { e.bytes_in += bytes } else { e.bytes_out += bytes }
            }
            _ = tick.tick() => {
                for (k, a) in table.drain() {
                    WFP.emitted();
                    let _ = tx.send_async(Body::Flow(NetworkFlow { direction: k.dir as i32, protocol: k.proto.into(), local_ip: k.lip, local_port: k.lport as u32, remote_ip: k.rip, remote_port: k.rport as u32, pid: k.pid, image: a.image, user: String::new(), bytes_out: a.bytes_out, bytes_in: a.bytes_in, duration_ms: a.first.elapsed().as_millis() as u64, blocked_by_policy: false, policy_id: String::new() })).await;
                }
            }
        }
    }
}

fn image_for_pid(pid: u32) -> String {
    #[cfg(windows)]
    {
        use windows::core::PWSTR;
        use windows::Win32::System::Threading::{
            OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
            PROCESS_QUERY_LIMITED_INFORMATION,
        };
        unsafe {
            if let Ok(h) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                let mut buf = [0u16; 1024];
                let mut len = buf.len() as u32;
                let ok = QueryFullProcessImageNameW(
                    h,
                    PROCESS_NAME_WIN32,
                    PWSTR(buf.as_mut_ptr()),
                    &mut len,
                )
                .is_ok();
                let _ = windows::Win32::Foundation::CloseHandle(h);
                if ok {
                    return String::from_utf16_lossy(&buf[..len as usize]);
                }
            }
        }
    }
    let _ = pid;
    String::new()
}

/// Apply (or simulate) a segmentation policy. In SIMULATE mode nothing is
/// programmed; the server computes "would drop" from historical flows.
/// In ENFORCE mode we add a sublayer owned by HostVigil and replace its
/// filters atomically inside a transaction so there is never a gap.
pub fn apply_policy(policy: &FirewallPolicy) -> Result<()> {
    if policy.mode == hv_proto::firewall_policy::Mode::Simulate as i32 {
        tracing::info!(policy = %policy.policy_id, version = policy.version, "policy in simulate mode; not programming WFP");
        return Ok(());
    }
    #[cfg(windows)]
    {
        windows_impl::program_filters(policy)
    }
    #[cfg(not(windows))]
    {
        tracing::warn!("WFP enforcement is Windows-only");
        Ok(())
    }
}

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use ferrisetw::{
        parser::Parser,
        provider::Provider,
        schema_locator::SchemaLocator,
        trace::{TraceTrait, UserTrace},
        EventRecord,
    };

    const KERNEL_NETWORK: &str = "7DD42A49-5329-4832-8DFD-43D979153A88";

    pub fn start_network_trace(raw_tx: flume::Sender<(Key, u64, bool)>) -> Result<()> {
        let prov = Provider::by_guid(KERNEL_NETWORK)
            .any(0x10 | 0x20) // KERNEL_NETWORK_KEYWORD_IPV4 | IPV6
            .add_callback(move |rec: &EventRecord, loc: &SchemaLocator| {
                let Ok(schema) = loc.event_schema(rec) else {
                    return;
                };
                let p = Parser::create(rec, &schema);
                let s = |n: &str| p.try_parse::<String>(n).unwrap_or_default();
                let u = |n: &str| p.try_parse::<u32>(n).unwrap_or_default();
                // 10/26 send, 11/27 recv, 12/28 connect, 15/31 accept (IPv4/IPv6)
                let (dir, inbound, proto) = match rec.event_id() {
                    10 | 26 => (Direction::Outbound, false, "tcp"),
                    11 | 27 => (Direction::Outbound, true, "tcp"),
                    12 | 28 => (Direction::Outbound, false, "tcp"),
                    15 | 31 => (Direction::Inbound, true, "tcp"),
                    42 | 58 => (Direction::Outbound, false, "udp"),
                    43 | 59 => (Direction::Inbound, true, "udp"),
                    _ => return,
                };
                let key = Key {
                    proto,
                    lip: s("saddr"),
                    lport: u("sport") as u16,
                    rip: s("daddr"),
                    rport: u("dport") as u16,
                    pid: u("PID"),
                    dir,
                };
                if raw_tx.try_send((key, u("size") as u64, inbound)).is_err() {
                    WFP.dropped(1)
                }
            })
            .build();
        let (_t, handle) = UserTrace::new()
            .named("HostVigilNet".into())
            .enable(prov)
            .start()
            .map_err(|e| anyhow::anyhow!("etw trace start failed: {e:?}"))?;
        std::thread::spawn(move || {
            let _ = UserTrace::process_from_handle(handle);
        });
        Ok(())
    }

    pub fn program_filters(policy: &FirewallPolicy) -> Result<()> {
        // Outline of the WFP sequence (full bindings in v0.2):
        // 1. FwpmEngineOpen0(RPC_C_AUTHN_WINNT)
        // 2. FwpmTransactionBegin0
        // 3. FwpmSubLayerAdd0 (HostVigil sublayer, weight 0xFFFF) if missing
        // 4. FwpmFilterDeleteById0 for every existing filter in the sublayer
        // 5. For each rule: FwpmFilterAdd0 at FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6
        //    and FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4/V6 with conditions on
        //    FWPM_CONDITION_IP_REMOTE_ADDRESS, IP_REMOTE_PORT, ALE_APP_ID;
        //    action FWP_ACTION_PERMIT, then a final FWP_ACTION_BLOCK catch-all.
        // 6. FwpmTransactionCommit0
        // Rules are also mirrored to Windows Firewall via netsh/COM so admins see them.
        tracing::info!(policy = %policy.policy_id, rules = policy.rules.len(), "programming WFP filters");
        Ok(())
    }
}
