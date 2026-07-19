use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use hickory_proto::rr::RecordType;
use serde::Serialize;
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, warn};

use crate::db::DbPool;

/// The action taken for a DNS query.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum QueryAction {
    Allowed,
    Blocked,
    Rewritten,
    Forwarded,
}

impl std::fmt::Display for QueryAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QueryAction::Allowed => write!(f, "allowed"),
            QueryAction::Blocked => write!(f, "blocked"),
            QueryAction::Rewritten => write!(f, "rewritten"),
            QueryAction::Forwarded => write!(f, "forwarded"),
        }
    }
}

/// A single DNS query log entry sent from the handler to the background writer.
#[derive(Debug, Clone)]
pub struct QueryEntry {
    pub client_ip: IpAddr,
    pub domain: String,
    pub query_type: RecordType,
    pub action: QueryAction,
    pub resolver: Option<String>,
    pub latency_us: Option<u64>,
}

/// Aggregate stats returned by the API.
#[derive(Debug, Serialize)]
pub struct StatsSummary {
    pub total_queries: u64,
    pub blocked: u64,
    pub allowed: u64,
    pub rewritten: u64,
    pub forwarded: u64,
    pub top_clients: Vec<ClientCount>,
    pub top_domains: Vec<DomainCount>,
    pub top_blocked_domains: Vec<DomainCount>,
    pub upstream_stats: Vec<UpstreamStats>,
}

#[derive(Debug, Serialize)]
pub struct ClientCount {
    pub ip: String,
    pub count: u64,
}

#[derive(Debug, Serialize)]
pub struct DomainCount {
    pub domain: String,
    pub count: u64,
}

#[derive(Debug, Serialize)]
pub struct UpstreamStats {
    pub resolver: String,
    pub count: u64,
    pub avg_latency_us: u64,
    pub min_latency_us: u64,
    pub max_latency_us: u64,
}

/// Lightweight query log entry for the API.
#[derive(Debug, Serialize)]
pub struct QueryLogEntry {
    pub id: i64,
    pub timestamp: String,
    pub client_ip: String,
    pub domain: String,
    pub query_type: String,
    pub action: String,
    pub resolver: Option<String>,
    pub latency_us: Option<u64>,
}

/// Serializable entry for SSE live streaming.
#[derive(Debug, Clone, Serialize)]
pub struct LiveQuery {
    pub client_ip: String,
    pub domain: String,
    pub query_type: String,
    pub action: String,
    pub resolver: Option<String>,
    pub latency_us: Option<u64>,
}

/// Thread-safe query log with atomic counters and a background batch writer.
pub struct QueryLog {
    total: AtomicU64,
    blocked: AtomicU64,
    allowed: AtomicU64,
    rewritten: AtomicU64,
    forwarded: AtomicU64,
    tx: mpsc::Sender<QueryEntry>,
    live_tx: broadcast::Sender<LiveQuery>,
    retention_days: Arc<AtomicU64>,
}

const BATCH_SIZE: usize = 100;
const FLUSH_INTERVAL_MS: u64 = 1000;
const VACUUM_AFTER_DELETED_ROWS: usize = 1_000;

impl QueryLog {
    /// Create a new QueryLog and spawn the background writer task.
    pub fn new(
        pool: DbPool,
        retention: Arc<AtomicU64>,
    ) -> (Arc<Self>, tokio::task::JoinHandle<()>) {
        let (tx, rx) = mpsc::channel::<QueryEntry>(4096);
        let (live_tx, _) = broadcast::channel::<LiveQuery>(256);

        let log = Arc::new(Self {
            total: AtomicU64::new(0),
            blocked: AtomicU64::new(0),
            allowed: AtomicU64::new(0),
            rewritten: AtomicU64::new(0),
            forwarded: AtomicU64::new(0),
            tx,
            live_tx,
            retention_days: retention.clone(),
        });

        let handle = tokio::spawn(Self::writer_task(pool, rx, retention));

        (log, handle)
    }

    /// Subscribe to the live query stream for SSE.
    pub fn subscribe(&self) -> broadcast::Receiver<LiveQuery> {
        self.live_tx.subscribe()
    }

    /// Record a single query. Non-blocking on the hot-path.
    pub fn record(&self, entry: QueryEntry) {
        self.total.fetch_add(1, Ordering::Relaxed);
        match entry.action {
            QueryAction::Blocked => self.blocked.fetch_add(1, Ordering::Relaxed),
            QueryAction::Allowed => self.allowed.fetch_add(1, Ordering::Relaxed),
            QueryAction::Rewritten => self.rewritten.fetch_add(1, Ordering::Relaxed),
            QueryAction::Forwarded => self.forwarded.fetch_add(1, Ordering::Relaxed),
        };

        // Avoid per-query string allocation when nobody is watching the live SSE feed.
        if self.live_tx.receiver_count() > 0 {
            let live = LiveQuery {
                client_ip: entry.client_ip.to_string(),
                domain: entry.domain.clone(),
                query_type: entry.query_type.to_string(),
                action: entry.action.to_string(),
                resolver: entry.resolver.clone(),
                latency_us: entry.latency_us,
            };
            let _ = self.live_tx.send(live);
        }

        if self.tx.try_send(entry).is_err() {
            debug!("QueryLog channel full, dropping entry");
        }
    }

    /// Real-time aggregate counters from atomics.
    pub fn counters(&self) -> (u64, u64, u64, u64, u64) {
        (
            self.total.load(Ordering::Relaxed),
            self.blocked.load(Ordering::Relaxed),
            self.allowed.load(Ordering::Relaxed),
            self.rewritten.load(Ordering::Relaxed),
            self.forwarded.load(Ordering::Relaxed),
        )
    }

    /// Update retention days (hot-reloaded from the web API).
    pub fn set_retention(&self, days: u64) {
        self.retention_days.store(days, Ordering::Relaxed);
    }

    /// Background task: batch entries and flush to SQLite periodically.
    async fn writer_task(
        pool: DbPool,
        mut rx: mpsc::Receiver<QueryEntry>,
        retention: Arc<AtomicU64>,
    ) {
        let mut batch: Vec<QueryEntry> = Vec::with_capacity(BATCH_SIZE * 2);
        let mut interval =
            tokio::time::interval(tokio::time::Duration::from_millis(FLUSH_INTERVAL_MS));

        loop {
            tokio::select! {
                msg = rx.recv() => {
                    match msg {
                        Some(entry) => {
                            batch.push(entry);
                            if batch.len() >= BATCH_SIZE {
                                Self::flush(&pool, &mut batch, retention.load(Ordering::Relaxed)).await;
                            }
                        }
                        None => {
                            if !batch.is_empty() {
                                Self::flush(&pool, &mut batch, retention.load(Ordering::Relaxed)).await;
                            }
                            debug!("QueryLog writer shutting down");
                            return;
                        }
                    }
                }
                _ = interval.tick() => {
                    if !batch.is_empty() {
                        Self::flush(&pool, &mut batch, retention.load(Ordering::Relaxed)).await;
                    }
                }
            }
        }
    }

    /// Insert a batch into SQLite and prune old records.
    async fn flush(pool: &DbPool, batch: &mut Vec<QueryEntry>, retention_days: u64) {
        if batch.is_empty() {
            return;
        }

        let pool = pool.clone();
        let entries = std::mem::take(batch);
        if let Err(e) = tokio::task::spawn_blocking(move || {
            Self::flush_entries(&pool, entries, retention_days);
        })
        .await
        {
            warn!("QueryLog flush task failed: {}", e);
        }
    }

    fn flush_entries(pool: &DbPool, entries: Vec<QueryEntry>, retention_days: u64) {
        let conn = match pool.get() {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to get DB connection for query log: {}", e);
                return;
            }
        };

        let tx = match conn.unchecked_transaction() {
            Ok(t) => t,
            Err(e) => {
                warn!("Failed to start transaction for query log: {}", e);
                return;
            }
        };

        for entry in entries {
            let action_str = entry.action.to_string();
            let query_type_str = entry.query_type.to_string();
            let ip_str = entry.client_ip.to_string();
            if let Err(e) = tx.execute(
                "INSERT INTO query_log (timestamp, client_ip, domain, query_type, action, resolver, latency_us) VALUES (datetime('now'), ?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![ip_str, entry.domain, query_type_str, action_str, entry.resolver, entry.latency_us],
            ) {
                warn!("Failed to insert query log entry: {}", e);
            }
        }

        if let Err(e) = tx.commit() {
            warn!("Failed to commit query log batch: {}", e);
        }

        if retention_days > 0 {
            match conn.execute(
                "DELETE FROM query_log WHERE timestamp < datetime('now', ?1)",
                rusqlite::params![format!("-{} days", retention_days)],
            ) {
                Ok(deleted) => Self::compact_after_delete(&conn, deleted),
                Err(e) => warn!("Failed to prune query log: {}", e),
            }
        }
    }

    fn compact_after_delete(conn: &rusqlite::Connection, deleted: usize) {
        if deleted == 0 {
            return;
        }

        if deleted >= VACUUM_AFTER_DELETED_ROWS
            && let Err(e) = conn.execute_batch("VACUUM")
        {
            warn!("Failed to vacuum query log storage after pruning: {}", e);
        }

        if let Err(e) = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)") {
            warn!("Failed to checkpoint query log WAL after pruning: {}", e);
        }
    }

    /// Get aggregate stats from the database.
    pub fn get_stats(pool: &DbPool, limit: i64) -> StatsSummary {
        let conn = match pool.get() {
            Ok(c) => c,
            Err(_) => {
                return StatsSummary {
                    total_queries: 0,
                    blocked: 0,
                    allowed: 0,
                    rewritten: 0,
                    forwarded: 0,
                    top_clients: vec![],
                    top_domains: vec![],
                    top_blocked_domains: vec![],
                    upstream_stats: vec![],
                };
            }
        };

        let (total, blocked, allowed, rewritten, forwarded): (u64, u64, u64, u64, u64) = conn
            .query_row(
                "SELECT
                    COUNT(*),
                    COALESCE(SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN action = 'allowed' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN action = 'rewritten' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN action = 'forwarded' THEN 1 ELSE 0 END), 0)
                 FROM query_log",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap_or((0, 0, 0, 0, 0));

        let top_clients: Vec<ClientCount> = match conn.prepare(
            "SELECT client_ip, COUNT(*) as cnt FROM query_log GROUP BY client_ip ORDER BY cnt DESC LIMIT ?1",
        ) {
            Ok(mut stmt) => stmt
                .query_map(rusqlite::params![limit], |row| {
                    Ok(ClientCount {
                        ip: row.get(0)?,
                        count: row.get(1)?,
                    })
                })
                .map(|rows| rows.filter_map(|r| r.ok()).collect())
                .unwrap_or_default(),
            Err(_) => vec![],
        };

        let top_domains: Vec<DomainCount> = match conn.prepare(
            "SELECT domain, COUNT(*) as cnt FROM query_log GROUP BY domain ORDER BY cnt DESC LIMIT ?1",
        ) {
            Ok(mut stmt) => stmt
                .query_map(rusqlite::params![limit], |row| {
                    Ok(DomainCount {
                        domain: row.get(0)?,
                        count: row.get(1)?,
                    })
                })
                .map(|rows| rows.filter_map(|r| r.ok()).collect())
                .unwrap_or_default(),
            Err(_) => vec![],
        };

        // Top blocked domains
        let top_blocked_domains: Vec<DomainCount> = match conn.prepare(
            "SELECT domain, COUNT(*) as cnt FROM query_log WHERE action = 'blocked' GROUP BY domain ORDER BY cnt DESC LIMIT ?1",
        ) {
            Ok(mut stmt) => stmt
                .query_map(rusqlite::params![limit], |row| {
                    Ok(DomainCount {
                        domain: row.get(0)?,
                        count: row.get(1)?,
                    })
                })
                .map(|rows| rows.filter_map(|r| r.ok()).collect())
                .unwrap_or_default(),
            Err(_) => vec![],
        };

        // Upstream stats
        let upstream_stats: Vec<UpstreamStats> = match conn.prepare(
            "SELECT resolver, COUNT(*), CAST(AVG(latency_us) AS INTEGER), MIN(latency_us), MAX(latency_us) FROM query_log WHERE resolver IS NOT NULL AND resolver != '' GROUP BY resolver ORDER BY COUNT(*) DESC",
        ) {
            Ok(mut stmt) => stmt
                .query_map([], |row| {
                    Ok(UpstreamStats {
                        resolver: row.get(0)?,
                        count: row.get(1)?,
                        avg_latency_us: row.get(2)?,
                        min_latency_us: row.get(3)?,
                        max_latency_us: row.get(4)?,
                    })
                })
                .map(|rows| rows.filter_map(|r| r.ok()).collect())
                .unwrap_or_default(),
            Err(_) => vec![],
        };

        StatsSummary {
            total_queries: total,
            blocked,
            allowed,
            rewritten,
            forwarded,
            top_clients,
            top_domains,
            top_blocked_domains,
            upstream_stats,
        }
    }

    /// Get recent query log entries (paginated).
    pub fn get_queries(pool: &DbPool, limit: i64, offset: i64) -> Vec<QueryLogEntry> {
        let conn = match pool.get() {
            Ok(c) => c,
            Err(_) => return vec![],
        };

        match conn.prepare(
            "SELECT id, timestamp, client_ip, domain, query_type, action, resolver, latency_us FROM query_log ORDER BY id DESC LIMIT ?1 OFFSET ?2",
        ) {
            Ok(mut stmt) => stmt
                .query_map(rusqlite::params![limit, offset], |row| {
                    Ok(QueryLogEntry {
                        id: row.get(0)?,
                        timestamp: row.get(1)?,
                        client_ip: row.get(2)?,
                        domain: row.get(3)?,
                        query_type: row.get(4)?,
                        action: row.get(5)?,
                        resolver: row.get(6)?,
                        latency_us: row.get(7)?,
                    })
                })
                .map(|rows| rows.filter_map(|r| r.ok()).collect())
                .unwrap_or_default(),
            Err(_) => vec![],
        }
    }

    /// Clear all query logs.
    pub fn clear(pool: &DbPool) {
        let conn = match pool.get() {
            Ok(c) => c,
            Err(_) => return,
        };
        match conn.execute("DELETE FROM query_log", []) {
            Ok(deleted) => Self::compact_after_delete(&conn, deleted),
            Err(e) => warn!("Failed to clear query log: {}", e),
        }
        let _ = conn.execute("DELETE FROM sqlite_sequence WHERE name='query_log'", []);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_DB: AtomicU64 = AtomicU64::new(0);

    fn test_db_path() -> std::path::PathBuf {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_millis();
        let id = NEXT_DB.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("rustblocker-stats-test-{millis}-{id}.db"))
    }

    fn test_pool() -> DbPool {
        crate::db::create_pool(test_db_path()).expect("failed to create test database pool")
    }

    fn query_entry(domain: &str) -> QueryEntry {
        QueryEntry {
            client_ip: "127.0.0.1".parse().expect("valid test IP"),
            domain: domain.to_string(),
            query_type: RecordType::A,
            action: QueryAction::Blocked,
            resolver: None,
            latency_us: Some(10),
        }
    }

    #[tokio::test]
    async fn record_only_builds_live_events_when_subscribed() {
        let (log, writer) = QueryLog::new(test_pool(), Arc::new(AtomicU64::new(30)));

        assert_eq!(log.live_tx.receiver_count(), 0);
        log.record(query_entry("no-subscriber.example"));

        let mut rx = log.subscribe();
        assert_eq!(log.live_tx.receiver_count(), 1);
        log.record(query_entry("subscriber.example"));

        let live = rx.recv().await.expect("live query event");
        assert_eq!(live.domain, "subscriber.example");
        assert_eq!(live.action, "blocked");

        writer.abort();
    }

    #[test]
    fn stats_summary_counts_actions_in_one_pass() {
        let pool = test_pool();
        let conn = pool.get().expect("test db connection");
        let rows = [
            ("10.0.0.1", "blocked.example", "blocked", None, None),
            ("10.0.0.1", "blocked.example", "blocked", None, None),
            (
                "10.0.0.2",
                "forwarded.example",
                "forwarded",
                Some("1.1.1.1"),
                Some(20_u64),
            ),
            (
                "10.0.0.3",
                "forwarded.example",
                "forwarded",
                Some("1.1.1.1"),
                Some(40_u64),
            ),
            ("10.0.0.4", "rewritten.example", "rewritten", None, None),
        ];

        for (client_ip, domain, action, resolver, latency_us) in rows {
            conn.execute(
                "INSERT INTO query_log (timestamp, client_ip, domain, query_type, action, resolver, latency_us)
                 VALUES (datetime('now'), ?1, ?2, 'A', ?3, ?4, ?5)",
                rusqlite::params![client_ip, domain, action, resolver, latency_us],
            )
            .expect("insert query log row");
        }

        let stats = QueryLog::get_stats(&pool, 10);

        assert_eq!(stats.total_queries, 5);
        assert_eq!(stats.blocked, 2);
        assert_eq!(stats.allowed, 0);
        assert_eq!(stats.rewritten, 1);
        assert_eq!(stats.forwarded, 2);
        assert_eq!(stats.top_blocked_domains[0].domain, "blocked.example");
        assert_eq!(stats.top_blocked_domains[0].count, 2);
        assert_eq!(stats.upstream_stats[0].resolver, "1.1.1.1");
        assert_eq!(stats.upstream_stats[0].avg_latency_us, 30);
    }

    #[test]
    fn pruning_query_log_compacts_wal() {
        let path = test_db_path();
        let pool = crate::db::create_pool(&path).expect("failed to create test database pool");
        let conn = pool.get().expect("test db connection");
        for i in 0..1_200 {
            conn.execute(
                "INSERT INTO query_log (timestamp, client_ip, domain, query_type, action) VALUES (datetime('now', '-2 days'), '127.0.0.1', ?1, 'A', 'blocked')",
                rusqlite::params![format!("old-{i}.example")],
            )
            .expect("insert old query log row");
        }
        drop(conn);

        QueryLog::flush_entries(&pool, vec![query_entry("fresh.example")], 1);

        let conn = pool.get().expect("test db connection after prune");
        let old_rows: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM query_log WHERE domain LIKE 'old-%'",
                [],
                |row| row.get(0),
            )
            .expect("count old rows");
        let fresh_rows: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM query_log WHERE domain = 'fresh.example'",
                [],
                |row| row.get(0),
            )
            .expect("count fresh rows");
        let wal_frames: u64 = conn
            .query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |row| row.get(1))
            .expect("read WAL frame count");

        assert_eq!(old_rows, 0);
        assert_eq!(fresh_rows, 1);
        assert_eq!(wal_frames, 0, "prune should checkpoint and truncate WAL");

        drop(conn);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    #[test]
    fn query_log_stats_indexes_are_created() {
        let pool = test_pool();
        let conn = pool.get().expect("test db connection");
        let mut stmt = conn
            .prepare("PRAGMA index_list('query_log')")
            .expect("prepare index list");
        let indexes: HashSet<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .expect("read index list")
            .filter_map(|row| row.ok())
            .collect();

        assert!(indexes.contains("idx_query_log_domain"));
        assert!(indexes.contains("idx_query_log_action_domain"));
        assert!(indexes.contains("idx_query_log_resolver"));
    }
}
