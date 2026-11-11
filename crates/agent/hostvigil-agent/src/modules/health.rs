//! Per-module counters reported in every heartbeat.
use hv_proto::ModuleHealth;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

pub struct Counter {
    pub emitted: AtomicU64,
    pub dropped: AtomicU64,
    pub last_error: Mutex<String>,
}
impl Counter {
    pub const fn new() -> Self {
        Self {
            emitted: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            last_error: Mutex::new(String::new()),
        }
    }
    pub fn emitted(&self) {
        self.emitted.fetch_add(1, Ordering::Relaxed);
    }
    pub fn dropped(&self, n: u64) {
        self.dropped.fetch_add(n, Ordering::Relaxed);
    }
    pub fn error(&self, e: impl ToString) {
        *self.last_error.lock().unwrap() = e.to_string();
    }
}

pub static ETW: Counter = Counter::new();
pub static WFP: Counter = Counter::new();
pub static FIM: Counter = Counter::new();
pub static INVENTORY: Counter = Counter::new();
pub static ALLOWLIST: Counter = Counter::new();
pub static BASELINE: Counter = Counter::new();

pub fn snapshot() -> HashMap<String, ModuleHealth> {
    [
        ("etw", &ETW),
        ("wfp", &WFP),
        ("fim", &FIM),
        ("inventory", &INVENTORY),
        ("allowlist", &ALLOWLIST),
        ("baseline", &BASELINE),
    ]
    .into_iter()
    .map(|(n, c)| {
        (
            n.to_string(),
            ModuleHealth {
                running: true,
                events_emitted: c.emitted.load(Ordering::Relaxed),
                events_dropped: c.dropped.load(Ordering::Relaxed),
                last_error: c.last_error.lock().unwrap().clone(),
            },
        )
    })
    .collect()
}

/// Process CPU% averaged since last call (GetProcessTimes on Windows).
pub fn cpu_pct() -> f32 {
    #[cfg(windows)]
    {
        use std::sync::Mutex;
        use windows::Win32::Foundation::FILETIME;
        use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};
        static LAST: Mutex<Option<(std::time::Instant, u64)>> = Mutex::new(None);
        let (mut c, mut e, mut k, mut u) = (
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
        );
        if unsafe { GetProcessTimes(GetCurrentProcess(), &mut c, &mut e, &mut k, &mut u) }.is_err()
        {
            return 0.0;
        }
        let ft = |f: FILETIME| ((f.dwHighDateTime as u64) << 32 | f.dwLowDateTime as u64) * 100; // ns
        let total = ft(k) + ft(u);
        let now = std::time::Instant::now();
        let mut g = LAST.lock().unwrap();
        let pct = match *g {
            Some((t, prev)) => {
                let wall = now.duration_since(t).as_nanos() as f64;
                if wall > 0.0 {
                    ((total - prev) as f64 / wall * 100.0 / num_cpus()) as f32
                } else {
                    0.0
                }
            }
            None => 0.0,
        };
        *g = Some((now, total));
        pct
    }
    #[cfg(not(windows))]
    {
        0.0
    }
}
fn num_cpus() -> f64 {
    std::thread::available_parallelism()
        .map(|n| n.get() as f64)
        .unwrap_or(1.0)
}

pub fn mem_mb() -> u32 {
    #[cfg(windows)]
    {
        use windows::Win32::System::ProcessStatus::{
            GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
        };
        use windows::Win32::System::Threading::GetCurrentProcess;
        let mut pmc = PROCESS_MEMORY_COUNTERS::default();
        pmc.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        if unsafe { GetProcessMemoryInfo(GetCurrentProcess(), &mut pmc, pmc.cb) }.is_ok() {
            return (pmc.WorkingSetSize / 1_048_576) as u32;
        }
        0
    }
    #[cfg(not(windows))]
    {
        0
    }
}
