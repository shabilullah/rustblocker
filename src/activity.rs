use serde::Serialize;
use tokio::sync::broadcast;

/// Severity level for activity log entries.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Success,
    Warning,
    Error,
}

/// A single activity log entry, streamed via SSE.
#[derive(Debug, Clone, Serialize)]
pub struct ActivityEntry {
    /// Correlation ID grouping entries for one operation (e.g. "acme-1720742400").
    pub op_id: String,
    /// Human-readable operation label (e.g. "Request Certificate").
    pub op: String,
    /// One-line progress message.
    pub message: String,
    /// Severity level.
    pub level: Severity,
    /// Unix timestamp (seconds).
    pub ts: i64,
}

/// Thread-safe activity log backed by a broadcast channel.
/// Mirrors the `QueryLog` / `LiveQuery` SSE pattern.
pub struct ActivityLog {
    tx: broadcast::Sender<ActivityEntry>,
}

impl ActivityLog {
    /// Create with capacity for 1024 entries before lagging.
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(1024);
        Self { tx }
    }

    /// Subscribe for SSE streaming.
    pub fn subscribe(&self) -> broadcast::Receiver<ActivityEntry> {
        self.tx.subscribe()
    }

    /// Emit a log entry. Silently drops if no subscribers.
    pub fn emit(&self, entry: ActivityEntry) {
        let _ = self.tx.send(entry);
    }

    /// Convenience: emit an info entry.
    pub fn info(&self, op_id: &str, op: &str, message: &str) {
        self.emit(ActivityEntry {
            op_id: op_id.to_string(),
            op: op.to_string(),
            message: message.to_string(),
            level: Severity::Info,
            ts: now(),
        });
    }

    /// Convenience: emit a success entry.
    pub fn success(&self, op_id: &str, op: &str, message: &str) {
        self.emit(ActivityEntry {
            op_id: op_id.to_string(),
            op: op.to_string(),
            message: message.to_string(),
            level: Severity::Success,
            ts: now(),
        });
    }

    /// Convenience: emit a warning entry.
    pub fn warning(&self, op_id: &str, op: &str, message: &str) {
        self.emit(ActivityEntry {
            op_id: op_id.to_string(),
            op: op.to_string(),
            message: message.to_string(),
            level: Severity::Warning,
            ts: now(),
        });
    }

    /// Convenience: emit an error entry.
    pub fn error(&self, op_id: &str, op: &str, message: &str) {
        self.emit(ActivityEntry {
            op_id: op_id.to_string(),
            op: op.to_string(),
            message: message.to_string(),
            level: Severity::Error,
            ts: now(),
        });
    }

    /// Run a future while emitting periodic "still working..." heartbeat messages.
    /// Spawns a background task that emits every `interval_secs` seconds.
    pub async fn with_progress<F, T>(
        &self,
        op_id: &str,
        op: &str,
        message: &str,
        interval_secs: u64,
        fut: F,
    ) -> T
    where
        F: Future<Output = T>,
    {
        let op_id = op_id.to_string();
        let op = op.to_string();
        let message = message.to_string();

        // Clone the sender for the heartbeat task
        let tx = self.tx.clone();

        let heartbeat = tokio::spawn(async move {
            let mut elapsed = 0u64;
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;
                elapsed += interval_secs;
                let _ = tx.send(ActivityEntry {
                    op_id: op_id.clone(),
                    op: op.clone(),
                    message: format!("{} ({}s)...", message, elapsed),
                    level: Severity::Info,
                    ts: now(),
                });
            }
        });

        let result = fut.await;
        heartbeat.abort();
        result
    }
}

impl Default for ActivityLog {
    fn default() -> Self {
        Self::new()
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
