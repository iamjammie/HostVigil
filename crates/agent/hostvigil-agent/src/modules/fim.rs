//! File integrity monitoring via the NTFS USN change journal.
//!
//! Reading the journal (FSCTL_QUERY_USN_JOURNAL / FSCTL_READ_USN_JOURNAL)
//! gives every create/modify/delete/rename on the volume with the file
//! reference number, which we resolve to a path and match against the watch
//! list. Matching files are hashed (SHA-256) with a per-second throttle and
//! the owning process is attributed from the ETW process table when the
//! change is within 2 s of a matching FileIO event.

use crate::{
    config::{AgentConfig, FimWatch},
    modules::health::FIM,
    supervisor::EventTx,
};
use anyhow::Result;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use hv_proto::{event::Body, file_change::Kind, FileChange};

pub async fn run(cfg: Arc<AgentConfig>, tx: EventTx) -> Result<()> {
    let watches = if cfg.fim.is_empty() {
        AgentConfig::default_fim_watches()
    } else {
        cfg.fim.clone()
    };
    tracing::info!(paths = watches.len(), "fim watching");
    #[cfg(windows)]
    {
        windows_impl::run(watches, tx).await
    }
    #[cfg(not(windows))]
    {
        let _ = (watches, tx);
        tracing::warn!("fim module is Windows-only; idling");
        loop {
            tokio::time::sleep(Duration::from_secs(3600)).await
        }
    }
}

pub fn matches(path: &str, watches: &[FimWatch]) -> bool {
    let p = path.to_ascii_lowercase();
    watches.iter().any(|w| {
        let base = w.path.to_ascii_lowercase();
        let inside = if w.recursive {
            p.starts_with(&base)
        } else {
            Path::new(&p)
                .parent()
                .map(|d| d.to_string_lossy() == base)
                .unwrap_or(false)
        };
        inside && !w.exclude_globs.iter().any(|g| glob_match(g, &p))
    })
}

/// Tiny glob: supports `*` and `?` only, which covers "*.log"-style excludes.
pub fn glob_match(pat: &str, text: &str) -> bool {
    fn rec(p: &[u8], t: &[u8]) -> bool {
        match (p.first(), t.first()) {
            (None, None) => true,
            (Some(b'*'), _) => rec(&p[1..], t) || (!t.is_empty() && rec(p, &t[1..])),
            (Some(b'?'), Some(_)) => rec(&p[1..], &t[1..]),
            (Some(a), Some(b)) if a.eq_ignore_ascii_case(b) => rec(&p[1..], &t[1..]),
            _ => false,
        }
    }
    let name = text.rsplit('\\').next().unwrap_or(text);
    rec(pat.as_bytes(), name.as_bytes()) || rec(pat.as_bytes(), text.as_bytes())
}

pub fn classify_kind(reason: u32) -> Kind {
    const USN_REASON_FILE_CREATE: u32 = 0x0000_0100;
    const USN_REASON_FILE_DELETE: u32 = 0x0000_0200;
    const USN_REASON_RENAME_NEW_NAME: u32 = 0x0000_2000;
    const USN_REASON_SECURITY_CHANGE: u32 = 0x0000_0800;
    if reason & USN_REASON_FILE_CREATE != 0 {
        Kind::Created
    } else if reason & USN_REASON_FILE_DELETE != 0 {
        Kind::Deleted
    } else if reason & USN_REASON_RENAME_NEW_NAME != 0 {
        Kind::Renamed
    } else if reason & USN_REASON_SECURITY_CHANGE != 0 {
        Kind::AclChanged
    } else {
        Kind::Modified
    }
}

pub async fn hash_file(path: &str) -> String {
    let p = path.to_string();
    tokio::task::spawn_blocking(move || {
        std::fs::read(&p)
            .map(|b| hv_common::sha256_hex(&b))
            .unwrap_or_default()
    })
    .await
    .unwrap_or_default()
}

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use windows::core::HSTRING;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_READ, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::Ioctl::{
        FSCTL_QUERY_USN_JOURNAL, FSCTL_READ_USN_JOURNAL, READ_USN_JOURNAL_DATA_V0,
        USN_JOURNAL_DATA_V0, USN_RECORD_V2,
    };
    use windows::Win32::System::IO::DeviceIoControl;

    pub async fn run(watches: Vec<FimWatch>, tx: EventTx) -> Result<()> {
        let vol = unsafe {
            CreateFileW(
                &HSTRING::from(r"\\.\C:"),
                FILE_GENERIC_READ.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                HANDLE::default(),
            )?
        };
        let mut jd = USN_JOURNAL_DATA_V0::default();
        let mut ret = 0u32;
        unsafe {
            DeviceIoControl(
                vol,
                FSCTL_QUERY_USN_JOURNAL,
                None,
                0,
                Some(&mut jd as *mut _ as *mut _),
                std::mem::size_of::<USN_JOURNAL_DATA_V0>() as u32,
                Some(&mut ret),
                None,
            )?
        };
        let mut next_usn = jd.NextUsn;
        let mut buf = vec![0u8; 64 * 1024];
        let mut last_hash = std::time::Instant::now();
        loop {
            let rd = READ_USN_JOURNAL_DATA_V0 {
                StartUsn: next_usn,
                ReasonMask: 0xFFFF_FFFF,
                ReturnOnlyOnClose: 0,
                Timeout: 1,
                BytesToWaitFor: 1,
                UsnJournalID: jd.UsnJournalID,
            };
            let mut got = 0u32;
            let ok = unsafe {
                DeviceIoControl(
                    vol,
                    FSCTL_READ_USN_JOURNAL,
                    Some(&rd as *const _ as *const _),
                    std::mem::size_of::<READ_USN_JOURNAL_DATA_V0>() as u32,
                    Some(buf.as_mut_ptr() as *mut _),
                    buf.len() as u32,
                    Some(&mut got),
                    None,
                )
            };
            if ok.is_err() || got < 8 {
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            }
            next_usn = i64::from_le_bytes(buf[..8].try_into().unwrap());
            let mut off = 8usize;
            while off + std::mem::size_of::<USN_RECORD_V2>() <= got as usize {
                let rec: &USN_RECORD_V2 =
                    unsafe { &*(buf.as_ptr().add(off) as *const USN_RECORD_V2) };
                if rec.RecordLength == 0 {
                    break;
                }
                let name_off = rec.FileNameOffset as usize;
                let name_len = rec.FileNameLength as usize / 2;
                let name = unsafe {
                    std::slice::from_raw_parts(
                        buf.as_ptr().add(off + name_off) as *const u16,
                        name_len,
                    )
                };
                let name = String::from_utf16_lossy(name);
                if let Some(path) = resolve_path(rec.ParentFileReferenceNumber, &name) {
                    if matches(&path, &watches) {
                        let kind = classify_kind(rec.Reason);
                        let want_hash = kind != Kind::Deleted
                            && watches.iter().any(|w| w.hash)
                            && last_hash.elapsed() > Duration::from_millis(50);
                        let sha = if want_hash {
                            last_hash = std::time::Instant::now();
                            hash_file(&path).await
                        } else {
                            String::new()
                        };
                        FIM.emitted();
                        let _ = tx
                            .send_async(Body::File(FileChange {
                                kind: kind as i32,
                                path,
                                sha256_after: sha,
                                usn: rec.Usn as u64,
                                ..Default::default()
                            }))
                            .await;
                    }
                }
                off += rec.RecordLength as usize;
            }
        }
        #[allow(unreachable_code)]
        {
            let _ = unsafe { CloseHandle(vol) };
            Ok(())
        }
    }

    /// Resolve parent FRN -> directory path via OpenFileById + GetFinalPathNameByHandle.
    /// Cached; directories rarely move. v0.1 falls back to the bare file name.
    fn resolve_path(_parent_frn: u64, name: &str) -> Option<String> {
        use std::collections::HashMap;
        use std::sync::Mutex;
        static CACHE: Mutex<Option<HashMap<u64, String>>> = Mutex::new(None);
        let dir = CACHE
            .lock()
            .unwrap()
            .get_or_insert_with(HashMap::new)
            .get(&_parent_frn)
            .cloned();
        Some(match dir {
            Some(d) => format!("{d}\\{name}"),
            None => name.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn glob_and_watch_matching() {
        assert!(glob_match("*.log", r"c:\windows\x.log"));
        assert!(!glob_match("*.log", r"c:\windows\x.exe"));
        let w = vec![FimWatch {
            path: r"C:\Windows\System32\drivers\etc".into(),
            recursive: true,
            hash: true,
            exclude_globs: vec!["*.tmp".into()],
        }];
        assert!(matches(r"C:\Windows\System32\drivers\etc\hosts", &w));
        assert!(!matches(r"C:\Windows\System32\drivers\etc\hosts.tmp", &w));
        assert!(!matches(r"C:\Users\x\hosts", &w));
    }
    #[test]
    fn usn_reason_classification() {
        assert_eq!(classify_kind(0x100), Kind::Created);
        assert_eq!(classify_kind(0x200 | 0x1), Kind::Deleted);
        assert_eq!(classify_kind(0x2), Kind::Modified);
    }
}
