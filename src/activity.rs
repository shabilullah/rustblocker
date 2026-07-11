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
