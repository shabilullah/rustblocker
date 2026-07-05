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

/// Lightweight query log entry for the API.
#[derive(Debug, Serialize)]
pub struct QueryLogEntry {
    pub id: i64,
    pub timestamp: String,
    pub client_ip: String,
    pub domain: String,
    pub query_type: String,
    pub action: String,
}

/// Serializable entry for SSE live streaming.
#[derive(Debug, Clone, Serialize)]
pub struct LiveQuery {
    pub client_ip: String,
    pub domain: String,
    pub query_type: String,
    pub action: String,
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
}

const BATCH_SIZE: usize = 100;
const FLUSH_INTERVAL_MS: u64 = 1000;

impl QueryLog {
    /// Create a new QueryLog and spawn the background writer task.
    pub fn new(pool: DbPool, retention_days: u64) -> (Arc<Self>, tokio::task::JoinHandle<()>) {
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
        });

        let handle = tokio::spawn(Self::writer_task(pool, rx, retention_days));

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

        // Broadcast to live SSE subscribers before consuming entry.
        let live = LiveQuery {
            client_ip: entry.client_ip.to_string(),
            domain: entry.domain.clone(),
            query_type: entry.query_type.to_string(),
            action: entry.action.to_string(),
        };
        let _ = self.live_tx.send(live);

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

    /// Background task: batch entries and flush to SQLite periodically.
    async fn writer_task(pool: DbPool, mut rx: mpsc::Receiver<QueryEntry>, retention_days: u64) {
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
                                Self::flush(&pool, &mut batch, retention_days);
                            }
                        }
                        None => {
                            if !batch.is_empty() {
                                Self::flush(&pool, &mut batch, retention_days);
                            }
                            debug!("QueryLog writer shutting down");
                            return;
                        }
                    }
                }
                _ = interval.tick() => {
                    if !batch.is_empty() {
                        Self::flush(&pool, &mut batch, retention_days);
                    }
                }
            }
        }
    }

    /// Insert a batch into SQLite and prune old records.
    fn flush(pool: &DbPool, batch: &mut Vec<QueryEntry>, retention_days: u64) {
        if batch.is_empty() {
            return;
        }

        let conn = match pool.get() {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to get DB connection for query log: {}", e);
                batch.clear();
                return;
            }
        };

        let tx = match conn.unchecked_transaction() {
            Ok(t) => t,
            Err(e) => {
                warn!("Failed to start transaction for query log: {}", e);
                batch.clear();
                return;
            }
        };

        for entry in batch.drain(..) {
            let action_str = entry.action.to_string();
            let query_type_str = entry.query_type.to_string();
            let ip_str = entry.client_ip.to_string();
            let _ = tx.execute(
                "INSERT INTO query_log (timestamp, client_ip, domain, query_type, action) VALUES (datetime('now'), ?1, ?2, ?3, ?4)",
                rusqlite::params![ip_str, entry.domain, query_type_str, action_str],
            );
        }

        if let Err(e) = tx.commit() {
            warn!("Failed to commit query log batch: {}", e);
        }

        // Prune old entries.
        if retention_days > 0 {
            let _ = conn.execute(
                "DELETE FROM query_log WHERE timestamp < datetime('now', ?1)",
                rusqlite::params![format!("-{} days", retention_days)],
            );
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
                };
            }
        };

        let total: u64 = conn
            .query_row("SELECT COUNT(*) FROM query_log", [], |r| r.get(0))
            .unwrap_or(0);

        let blocked: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM query_log WHERE action = 'blocked'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);

        let allowed: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM query_log WHERE action = 'allowed'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);

        let rewritten: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM query_log WHERE action = 'rewritten'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);

        let forwarded: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM query_log WHERE action = 'forwarded'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);

        let mut stmt = conn
            .prepare(
                "SELECT client_ip, COUNT(*) as cnt FROM query_log GROUP BY client_ip ORDER BY cnt DESC LIMIT ?1",
            )
            .unwrap();
        let top_clients: Vec<ClientCount> = stmt
            .query_map(rusqlite::params![limit], |row| {
                Ok(ClientCount {
                    ip: row.get(0)?,
                    count: row.get(1)?,
                })
            })
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        let mut stmt = conn
            .prepare(
                "SELECT domain, COUNT(*) as cnt FROM query_log GROUP BY domain ORDER BY cnt DESC LIMIT ?1",
            )
            .unwrap();
        let top_domains: Vec<DomainCount> = stmt
            .query_map(rusqlite::params![limit], |row| {
                Ok(DomainCount {
                    domain: row.get(0)?,
                    count: row.get(1)?,
                })
            })
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        StatsSummary {
            total_queries: total,
            blocked,
            allowed,
            rewritten,
            forwarded,
            top_clients,
            top_domains,
        }
    }

    /// Get recent query log entries (paginated).
    pub fn get_queries(pool: &DbPool, limit: i64, offset: i64) -> Vec<QueryLogEntry> {
        let conn = match pool.get() {
            Ok(c) => c,
            Err(_) => return vec![],
        };

        let mut stmt = conn
            .prepare(
                "SELECT id, timestamp, client_ip, domain, query_type, action FROM query_log ORDER BY id DESC LIMIT ?1 OFFSET ?2",
            )
            .unwrap();

        stmt.query_map(rusqlite::params![limit, offset], |row| {
            Ok(QueryLogEntry {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                client_ip: row.get(2)?,
                domain: row.get(3)?,
                query_type: row.get(4)?,
                action: row.get(5)?,
            })
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    /// Clear all query logs.
    pub fn clear(pool: &DbPool) {
        let conn = match pool.get() {
            Ok(c) => c,
            Err(_) => return,
        };
        let _ = conn.execute("DELETE FROM query_log", []);
        let _ = conn.execute("DELETE FROM sqlite_sequence WHERE name='query_log'", []);
    }
}
