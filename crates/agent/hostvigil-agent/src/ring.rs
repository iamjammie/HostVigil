//! Durable ring buffer backed by SQLite. Events are appended with their
//! sequence number and deleted once the server acks `up_to_seq`. When the
//! byte quota is exceeded the oldest events are dropped and a counter is
//! incremented so the server can report the gap.

use anyhow::Result;
use rusqlite::{params, Connection};
use std::path::Path;

pub struct Ring {
    conn: Connection,
    quota: u64,
    pub dropped: u64,
}

impl Ring {
    pub fn open(path: &Path, quota: u64) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY, boot_id TEXT NOT NULL, body BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);",
        )?;
        Ok(Self {
            conn,
            quota,
            dropped: 0,
        })
    }

    pub fn next_seq(&self) -> Result<u64> {
        let v: Option<i64> = self
            .conn
            .query_row("SELECT MAX(seq) FROM events", [], |r| r.get(0))?;
        Ok(v.map(|x| x as u64 + 1).unwrap_or(1))
    }

    pub fn push(&mut self, seq: u64, boot_id: &str, body: &[u8]) -> Result<()> {
        self.conn.execute(
            "INSERT INTO events(seq, boot_id, body) VALUES(?1, ?2, ?3)",
            params![seq as i64, boot_id, body],
        )?;
        self.enforce_quota()?;
        Ok(())
    }

    /// Oldest unacked events, up to `limit`.
    pub fn pending(&self, limit: usize) -> Result<Vec<(u64, Vec<u8>)>> {
        let mut st = self
            .conn
            .prepare("SELECT seq, body FROM events ORDER BY seq LIMIT ?1")?;
        let rows = st.query_map([limit as i64], |r| {
            Ok((r.get::<_, i64>(0)? as u64, r.get(1)?))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn ack(&self, up_to_seq: u64) -> Result<()> {
        self.conn
            .execute("DELETE FROM events WHERE seq <= ?1", [up_to_seq as i64])?;
        Ok(())
    }

    pub fn depth(&self) -> Result<u32> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get::<_, i64>(0))?
            as u32)
    }

    fn enforce_quota(&mut self) -> Result<()> {
        let bytes: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(LENGTH(body)),0) FROM events",
            [],
            |r| r.get(0),
        )?;
        if bytes as u64 > self.quota {
            // drop oldest 5%
            let n: i64 = self
                .conn
                .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
            let drop = (n / 20).max(1);
            self.conn.execute(
                "DELETE FROM events WHERE seq IN (SELECT seq FROM events ORDER BY seq LIMIT ?1)",
                [drop],
            )?;
            self.dropped += drop as u64;
            tracing::warn!(
                dropped = drop,
                "ring buffer quota exceeded, oldest events dropped"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn push_pending_ack() {
        let dir = std::env::temp_dir().join(format!("hv-ring-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut r = Ring::open(&dir.join("ring.db"), 1 << 20).unwrap();
        assert_eq!(r.next_seq().unwrap(), 1);
        r.push(1, "b", b"one").unwrap();
        r.push(2, "b", b"two").unwrap();
        assert_eq!(r.pending(10).unwrap().len(), 2);
        r.ack(1).unwrap();
        assert_eq!(r.pending(10).unwrap()[0].0, 2);
        assert_eq!(r.depth().unwrap(), 1);
    }
}
