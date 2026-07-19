/// Error type for database operations — covers both pool exhaustion and SQL failures.
/// Used by all `pub fn` in this module so callers can map to HTTP 500 instead of panicking.
#[derive(Debug)]
pub enum DbError {
    Pool(r2d2::Error),
    Sql(rusqlite::Error),
}
impl From<r2d2::Error> for DbError {
    fn from(e: r2d2::Error) -> Self {
        DbError::Pool(e)
    }
}
impl From<rusqlite::Error> for DbError {
    fn from(e: rusqlite::Error) -> Self {
        DbError::Sql(e)
    }
}
impl std::fmt::Display for DbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DbError::Pool(e) => write!(f, "database pool error: {e}"),
            DbError::Sql(e) => write!(f, "database error: {e}"),
        }
    }
}
impl std::error::Error for DbError {}

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::info;

use crate::lists::DomainStore;

pub type DbPool = Pool<SqliteConnectionManager>;

pub struct DomainImportResult {
    pub inserted: usize,
    pub store: DomainStore,
}

/// Result of refreshing a source: status text plus a full rebuilt runtime store
/// for the affected list table (so removed source domains leave RAM).
pub struct SourceRefreshResult {
    pub status: String,
    pub store: DomainStore,
}

pub fn create_pool<P: AsRef<Path>>(db_path: P) -> Result<DbPool, DbError> {
    let path = db_path.as_ref();
    let manager = SqliteConnectionManager::file(path);
    let pool = Pool::new(manager)?;
    {
        let conn = pool.get()?;
        init_schema(&conn)?;
    }
    info!("SQLite database ready: {}", path.display());
    Ok(pool)
}

fn init_schema(conn: &rusqlite::Connection) -> Result<(), DbError> {
    // Use WAL mode so writes never block reads (critical for live stats during imports).
    conn.execute_batch("PRAGMA journal_mode = WAL;")?;
    // Let SQLite retry for up to 5s instead of immediately returning SQLITE_BUSY.
    conn.execute_batch("PRAGMA busy_timeout = 5000;")?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL UNIQUE,
            private_key BLOB NOT NULL,
            certificate BLOB NOT NULL,
            issued_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            last_renewed INTEGER
        );
        CREATE TABLE IF NOT EXISTS upstreams (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            address TEXT NOT NULL,
            port INTEGER NOT NULL DEFAULT 53
        );
        CREATE TABLE IF NOT EXISTS blocklist_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL UNIQUE
        );
        CREATE TABLE IF NOT EXISTS allowlist_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL UNIQUE
        );
        CREATE TABLE IF NOT EXISTS rewrites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL UNIQUE,
            ipv4 TEXT,
            ipv6 TEXT
        );
        CREATE TABLE IF NOT EXISTS sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL UNIQUE,
            list_type TEXT NOT NULL DEFAULT 'blocklist',
            enabled INTEGER NOT NULL DEFAULT 1,
            update_interval_hours INTEGER NOT NULL DEFAULT 24,
            last_updated TEXT,
            last_status TEXT
        );
        CREATE TABLE IF NOT EXISTS query_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            client_ip TEXT NOT NULL,
            domain TEXT NOT NULL,
            query_type TEXT NOT NULL,
            action TEXT NOT NULL,
            resolver TEXT,
            latency_us INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_query_log_timestamp ON query_log(timestamp);
        CREATE INDEX IF NOT EXISTS idx_query_log_client_ip ON query_log(client_ip);
        CREATE INDEX IF NOT EXISTS idx_query_log_action ON query_log(action);
        CREATE INDEX IF NOT EXISTS idx_query_log_domain ON query_log(domain);
        CREATE INDEX IF NOT EXISTS idx_query_log_action_domain ON query_log(action, domain);
        CREATE INDEX IF NOT EXISTS idx_query_log_resolver ON query_log(resolver);",
    )?;
    // Migration: add columns that may be missing in databases created by older versions.
    // CREATE TABLE IF NOT EXISTS won't alter existing tables, so we do it explicitly.
    let _ = conn.execute("ALTER TABLE query_log ADD COLUMN resolver TEXT", []);
    let _ = conn.execute("ALTER TABLE query_log ADD COLUMN latency_us INTEGER", []);
    let _ = conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS source_domains (
            source_id INTEGER NOT NULL,
            domain TEXT NOT NULL,
            PRIMARY KEY (source_id, domain)
        );
        CREATE INDEX IF NOT EXISTS idx_source_domains_domain ON source_domains(domain);
        CREATE INDEX IF NOT EXISTS idx_source_domains_source ON source_domains(source_id);
        CREATE TABLE IF NOT EXISTS manual_domains (
            list_type TEXT NOT NULL,
            domain TEXT NOT NULL,
            PRIMARY KEY (list_type, domain)
        );",
    );
    Ok(())
}

/// Seed the database with sensible defaults (only if tables are empty).
pub fn seed_defaults(pool: &DbPool) -> Result<(), DbError> {
    let conn = pool.get()?;

    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM settings", [], |row| row.get(0))
        .unwrap_or(0);
    if count > 0 {
        info!("Database already seeded");
        return Ok(());
    }

    info!("Seeding database with default settings...");

    let settings = [
        ("listen_address", "0.0.0.0"),
        ("listen_port", "53"),
        ("sinkhole_ipv4", "0.0.0.0"),
        ("sinkhole_ipv6", "::"),
        ("log_level", "info"),
        ("upstream_timeout_secs", "5"),
        ("forward_strategy", "adaptive"),
        ("adaptive_hedge_delay_ms", "75"),
        ("allowed_networks", ""),
        ("stats_retention_days", "30"),
    ];
    for (key, value) in &settings {
        conn.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES (?1, ?2)",
            params![key, value],
        )
        .ok();
    }

    conn.execute(
        "INSERT OR IGNORE INTO upstreams (address, port) VALUES (?1, ?2)",
        params!["8.8.8.8", 53],
    )
    .ok();

    info!("Database seeded with defaults (1 upstream: 8.8.8.8:53)");
    Ok(())
}

/// Fetch content from a URL or read from a local file path.
pub async fn fetch_source(path: &str) -> String {
    if path.starts_with("http://") || path.starts_with("https://") {
        info!("Fetching from {}...", path);
        match reqwest::get(path).await {
            Ok(resp) => resp.text().await.unwrap_or_default(),
            Err(e) => {
                tracing::warn!("Failed to fetch {}: {}", path, e);
                String::new()
            }
        }
    } else {
        std::fs::read_to_string(path).unwrap_or_default()
    }
}

/// Import domains from a URL or file into the database.
pub async fn import_from_source(pool: &DbPool, table: &str, path: &str) -> usize {
    let content = fetch_source(path).await;
    if content.is_empty() {
        return 0;
    }
    let pool = pool.clone();
    let table = table.to_string();
    tokio::task::spawn_blocking(move || {
        bulk_import_domains_with_entries(&pool, &table, &content)
            .map(|r| r.inserted)
            .unwrap_or(0)
    })
    .await
    .unwrap_or(0)
}

fn parse_domain_line(line: &str) -> Option<String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let domain_part = if line.starts_with("0.0.0.0") || line.starts_with("127.0.0.1") {
        line.split_whitespace().nth(1).unwrap_or("")
    } else {
        line
    };

    let domain_part = domain_part.trim();
    if domain_part.is_empty() {
        return None;
    }

    let normalized = domain_part.to_lowercase();
    let normalized = normalized.strip_suffix('.').unwrap_or(&normalized);
    if normalized.is_empty() {
        None
    } else {
        Some(normalized.to_string())
    }
}

/// Insert parsed domains, preserving `*.` prefix for wildcards.
fn insert_domains_from_content(
    conn: &rusqlite::Connection,
    table: &str,
    content: &str,
) -> DomainStore {
    let sql = format!("INSERT OR IGNORE INTO {} (domain) VALUES (?1)", table);
    let list_type = match table {
        "allowlist_domains" => "allowlist",
        _ => "blocklist",
    };
    let mut store = DomainStore::default();
    // Wrap all inserts in a single transaction so a 100k-line source
    // doesn't create 100k individual write transactions.
    let _ = conn.execute("BEGIN", []);
    for line in content.lines() {
        if let Some(domain) = parse_domain_line(line) {
            conn.execute(&sql, params![domain]).ok();
            // API bulk import is treated as manual so source refresh won't prune it.
            let _ = conn.execute(
                "INSERT OR IGNORE INTO manual_domains (list_type, domain) VALUES (?1, ?2)",
                params![list_type, domain],
            );
            store.insert(&domain);
        }
    }
    let _ = conn.execute("COMMIT", []);
    store
}

// --- Settings ---

pub fn get_settings(pool: &DbPool) -> Result<serde_json::Value, DbError> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare("SELECT key, value FROM settings")?;
    let rows: Vec<(String, String)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .filter_map(|r| r.ok())
        .collect();

    let mut map = serde_json::Map::new();
    for (key, value) in rows {
        if key == "admin_password_hash" || key == "session_secret" || key == "sync_password" {
            continue; // never expose sensitive auth state through the settings API
        }
        // Mask Cloudflare API token in responses
        let value = if key == "cloudflare_api_token" {
            "***masked***".to_string()
        } else {
            value
        };
        map.insert(key, serde_json::Value::String(value));
    }
    Ok(serde_json::Value::Object(map))
}

pub fn set_setting(pool: &DbPool, key: &str, value: &str) -> Result<(), DbError> {
    let conn = pool.get()?;
    conn.execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES (?1, ?2)",
        params![key, value],
    )?;
    Ok(())
}

pub fn get_password_hash(pool: &DbPool) -> Option<String> {
    get_setting(pool, "admin_password_hash")
}

pub fn set_password_hash(pool: &DbPool, hash: &str) -> Result<(), DbError> {
    set_setting(pool, "admin_password_hash", hash)
}
pub fn get_setting(pool: &DbPool, key: &str) -> Option<String> {
    let conn = pool.get().ok()?;
    conn.query_row(
        "SELECT value FROM settings WHERE key = ?1",
        params![key],
        |row| row.get(0),
    )
    .ok()
}

pub type CertificateData = (Vec<u8>, Vec<u8>, i64);

// --- Certificates ---

pub fn store_certificate(
    pool: &DbPool,
    domain: &str,
    private_key: &[u8],
    certificate: &[u8],
    expires_at: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let conn = pool.get()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;

    conn.execute(
        "INSERT OR REPLACE INTO certificates (domain, private_key, certificate, issued_at, expires_at, last_renewed) 
         VALUES (?1, ?2, ?3, ?4, ?5, ?4)",
        params![domain, private_key, certificate, now, expires_at],
    )?;
    Ok(())
}

pub fn get_certificate(pool: &DbPool, domain: &str) -> anyhow::Result<Option<CertificateData>> {
    let conn = pool.get()?;
    let result = conn.query_row(
        "SELECT private_key, certificate, expires_at FROM certificates WHERE domain = ?1",
        params![domain],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    );

    match result {
        Ok(data) => Ok(Some(data)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(anyhow::anyhow!(e)),
    }
}

pub fn list_expiring_certificates(
    pool: &DbPool,
    days_threshold: i64,
) -> anyhow::Result<Vec<String>> {
    let conn = pool.get()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    let threshold = now + (days_threshold * 86400);

    let mut stmt = conn.prepare("SELECT domain FROM certificates WHERE expires_at < ?1")?;
    let domains: Vec<String> = stmt
        .query_map(params![threshold], |row| row.get(0))?
        .filter_map(|r| r.ok())
        .collect();

    Ok(domains)
}

pub fn get_certificate_status(pool: &DbPool, domain: &str) -> Option<serde_json::Value> {
    let conn = pool.get().ok()?;
    let result: Result<(i64, i64, Option<i64>), _> = conn.query_row(
        "SELECT issued_at, expires_at, last_renewed FROM certificates WHERE domain = ?1",
        params![domain],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    );

    match result {
        Ok((issued_at, expires_at, last_renewed)) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let days_remaining = (expires_at - now) / 86400;

            Some(serde_json::json!({
                "has_certificate": true,
                "domain": domain,
                "issued_at": issued_at,
                "expires_at": expires_at,
                "days_remaining": days_remaining,
                "last_renewed": last_renewed
            }))
        }
        Err(_) => Some(serde_json::json!({
            "has_certificate": false
        })),
    }
}

// --- Upstreams ---

#[derive(Debug, Serialize, Deserialize)]
pub struct DbUpstream {
    pub id: i64,
    pub address: String,
    pub port: i64,
}

pub fn get_upstreams(pool: &DbPool) -> Result<Vec<DbUpstream>, DbError> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare("SELECT id, address, port FROM upstreams ORDER BY id")?;
    let rows = stmt
        .query_map([], |row| {
            Ok(DbUpstream {
                id: row.get(0)?,
                address: row.get(1)?,
                port: row.get(2)?,
            })
        })?
        .filter_map(|r| r.ok())
        .collect();
    Ok(rows)
}
pub fn add_upstream(pool: &DbPool, address: &str, port: i64) -> Result<i64, DbError> {
    let conn = pool.get()?;
    conn.execute(
        "INSERT INTO upstreams (address, port) VALUES (?1, ?2)",
        params![address, port],
    )?;
    Ok(conn.last_insert_rowid())
}
pub fn delete_upstream(pool: &DbPool, id: i64) -> Result<bool, DbError> {
    let conn = pool.get()?;
    let rows = conn.execute("DELETE FROM upstreams WHERE id = ?1", params![id])?;
    Ok(rows > 0)
}
// --- Domains (blocklist / allowlist) ---

#[derive(Debug, Serialize, Deserialize)]
pub struct DbDomain {
    pub id: i64,
    pub domain: String,
}

pub fn get_domains(pool: &DbPool, table: &str) -> Result<Vec<DbDomain>, DbError> {
    let conn = pool.get()?;
    let sql = format!("SELECT id, domain FROM {} ORDER BY domain", table);
    let mut stmt = conn.prepare(&sql)?;
    let v = stmt
        .query_map([], |row| {
            Ok(DbDomain {
                id: row.get(0)?,
                domain: row.get(1)?,
            })
        })?
        .filter_map(|r| r.ok())
        .collect();
    Ok(v)
}

pub fn count_domains(pool: &DbPool, table: &str) -> Result<i64, DbError> {
    let conn = pool.get()?;
    let sql = format!("SELECT COUNT(*) FROM {}", table);
    Ok(conn.query_row(&sql, [], |row| row.get(0))?)
}

pub fn search_domains(
    pool: &DbPool,
    table: &str,
    search: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<DbDomain>, DbError> {
    let conn = pool.get()?;
    if search.is_empty() {
        let sql = format!(
            "SELECT id, domain FROM {} ORDER BY domain LIMIT ?1 OFFSET ?2",
            table
        );
        let mut stmt = conn.prepare(&sql)?;
        let v = stmt
            .query_map(rusqlite::params![limit, offset], |row| {
                Ok(DbDomain {
                    id: row.get(0)?,
                    domain: row.get(1)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();
        return Ok(v);
    }
    let sql = format!(
        "SELECT id, domain FROM {} WHERE domain LIKE ?1 ORDER BY domain LIMIT ?2 OFFSET ?3",
        table
    );
    let pattern = format!("%{}%", search);
    let mut stmt = conn.prepare(&sql)?;
    let v = stmt
        .query_map(rusqlite::params![pattern, limit, offset], |row| {
            Ok(DbDomain {
                id: row.get(0)?,
                domain: row.get(1)?,
            })
        })?
        .filter_map(|r| r.ok())
        .collect();
    Ok(v)
}

pub fn add_domain(pool: &DbPool, table: &str, domain: &str) -> Result<i64, DbError> {
    let conn = pool.get()?;
    let normalized = domain.to_lowercase();
    let normalized = normalized.strip_suffix('.').unwrap_or(&normalized);
    let sql = format!("INSERT OR IGNORE INTO {} (domain) VALUES (?1)", table);
    conn.execute(&sql, params![normalized])?;
    let id: i64 = conn
        .query_row(
            &format!("SELECT id FROM {} WHERE domain = ?1", table),
            params![normalized],
            |row| row.get(0),
        )
        .unwrap_or(0);
    // do NOT bump last_insert_rowid via a manual_domains insert; resolve via SELECT only.
    let list_type = match table {
        "allowlist_domains" => "allowlist",
        _ => "blocklist",
    };
    let _ = conn.execute(
        "INSERT OR IGNORE INTO manual_domains (list_type, domain) VALUES (?1, ?2)",
        params![list_type, normalized],
    );
    Ok(id)
}

pub fn get_domain_by_id(pool: &DbPool, table: &str, id: i64) -> Option<DbDomain> {
    let conn = pool.get().ok()?;
    let sql = format!("SELECT id, domain FROM {} WHERE id = ?1", table);
    conn.query_row(&sql, params![id], |row| {
        Ok(DbDomain {
            id: row.get(0)?,
            domain: row.get(1)?,
        })
    })
    .ok()
}

pub fn delete_domain(pool: &DbPool, table: &str, id: i64) -> Result<bool, DbError> {
    let conn = pool.get()?;
    let sql = format!("DELETE FROM {} WHERE id = ?1", table);
    let rows = conn.execute(&sql, params![id])?;
    Ok(rows > 0)
}

pub fn delete_domain_by_id(pool: &DbPool, table: &str, id: i64) -> Option<String> {
    let conn = pool.get().ok()?;
    let select_sql = format!("SELECT domain FROM {} WHERE id = ?1", table);
    let domain: String = conn
        .query_row(&select_sql, params![id], |row| row.get(0))
        .ok()?;
    let delete_sql = format!("DELETE FROM {} WHERE id = ?1", table);
    let rows = conn.execute(&delete_sql, params![id]).ok()?;
    if rows > 0 {
        let list_type = match table {
            "allowlist_domains" => "allowlist",
            _ => "blocklist",
        };
        let _ = conn.execute(
            "DELETE FROM manual_domains WHERE list_type = ?1 AND domain = ?2",
            params![list_type, domain],
        );
        Some(domain)
    } else {
        None
    }
}

pub fn bulk_import_domains(pool: &DbPool, table: &str, content: &str) -> usize {
    bulk_import_domains_with_entries(pool, table, content)
        .map(|r| r.inserted)
        .unwrap_or(0)
}

pub fn bulk_import_domains_with_entries(
    pool: &DbPool,
    table: &str,
    content: &str,
) -> Result<DomainImportResult, DbError> {
    let conn = pool.get()?;
    let before: i64 = conn
        .query_row(&format!("SELECT COUNT(*) FROM {}", table), [], |row| {
            row.get(0)
        })
        .unwrap_or(0);
    let store = insert_domains_from_content(&conn, table, content);
    let after: i64 = conn
        .query_row(&format!("SELECT COUNT(*) FROM {}", table), [], |row| {
            row.get(0)
        })
        .unwrap_or(0);
    Ok(DomainImportResult {
        inserted: (after - before) as usize,
        store,
    })
}

// --- Rewrites ---

#[derive(Debug, Serialize, Deserialize)]
pub struct DbRewrite {
    pub id: i64,
    pub domain: String,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
}

pub fn get_rewrites(pool: &DbPool) -> Result<Vec<DbRewrite>, DbError> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare("SELECT id, domain, ipv4, ipv6 FROM rewrites ORDER BY domain")?;
    let v = stmt
        .query_map([], |row| {
            Ok(DbRewrite {
                id: row.get(0)?,
                domain: row.get(1)?,
                ipv4: row.get(2)?,
                ipv6: row.get(3)?,
            })
        })?
        .filter_map(|r| r.ok())
        .collect();
    Ok(v)
}

pub fn get_rewrite_by_id(pool: &DbPool, id: i64) -> Option<DbRewrite> {
    let conn = pool.get().ok()?;
    conn.query_row(
        "SELECT id, domain, ipv4, ipv6 FROM rewrites WHERE id = ?1",
        params![id],
        |row| {
            Ok(DbRewrite {
                id: row.get(0)?,
                domain: row.get(1)?,
                ipv4: row.get(2)?,
                ipv6: row.get(3)?,
            })
        },
    )
    .ok()
}

pub fn add_rewrite(
    pool: &DbPool,
    domain: &str,
    ipv4: Option<&str>,
    ipv6: Option<&str>,
) -> Result<i64, DbError> {
    let conn = pool.get()?;
    let normalized = domain.to_lowercase();
    let normalized = normalized.strip_suffix('.').unwrap_or(&normalized);
    conn.execute(
        "INSERT OR IGNORE INTO rewrites (domain, ipv4, ipv6) VALUES (?1, ?2, ?3)",
        params![normalized, ipv4, ipv6],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn delete_rewrite(pool: &DbPool, id: i64) -> Result<bool, DbError> {
    let conn = pool.get()?;
    let rows = conn.execute("DELETE FROM rewrites WHERE id = ?1", params![id])?;
    Ok(rows > 0)
}

pub fn delete_rewrite_by_id(pool: &DbPool, id: i64) -> Option<DbRewrite> {
    let conn = pool.get().ok()?;
    let rewrite = conn
        .query_row(
            "SELECT id, domain, ipv4, ipv6 FROM rewrites WHERE id = ?1",
            params![id],
            |row| {
                Ok(DbRewrite {
                    id: row.get(0)?,
                    domain: row.get(1)?,
                    ipv4: row.get(2)?,
                    ipv6: row.get(3)?,
                })
            },
        )
        .ok()?;
    let rows = conn
        .execute("DELETE FROM rewrites WHERE id = ?1", params![id])
        .ok()?;
    if rows > 0 { Some(rewrite) } else { None }
}

// --- Sources (blocklist/allowlist URLs with auto-update) ---

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DbSource {
    pub id: i64,
    pub url: String,
    pub list_type: String,
    pub enabled: bool,
    pub update_interval_hours: i64,
    pub last_updated: Option<String>,
    pub last_status: Option<String>,
}

pub fn get_source_by_id(pool: &DbPool, id: i64) -> Option<DbSource> {
    let conn = pool.get().ok()?;
    conn.query_row(
        "SELECT id, url, list_type, enabled, update_interval_hours, last_updated, last_status FROM sources WHERE id = ?1",
        params![id],
        |row| {
            Ok(DbSource {
                id: row.get(0)?,
                url: row.get(1)?,
                list_type: row.get(2)?,
                enabled: row.get::<_, i64>(3)? != 0,
                update_interval_hours: row.get(4)?,
                last_updated: row.get(5)?,
                last_status: row.get(6)?,
            })
        },
    )
    .ok()
}

pub fn get_sources(pool: &DbPool) -> Result<Vec<DbSource>, DbError> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare("SELECT id, url, list_type, enabled, update_interval_hours, last_updated, last_status FROM sources ORDER BY id")?;
    let v = stmt
        .query_map([], |row| {
            Ok(DbSource {
                id: row.get(0)?,
                url: row.get(1)?,
                list_type: row.get(2)?,
                enabled: row.get::<_, i64>(3)? != 0,
                update_interval_hours: row.get(4)?,
                last_updated: row.get(5)?,
                last_status: row.get(6)?,
            })
        })?
        .filter_map(|r| r.ok())
        .collect();
    Ok(v)
}

pub fn add_source(
    pool: &DbPool,
    url: &str,
    list_type: &str,
    interval_hours: i64,
) -> Result<i64, DbError> {
    let conn = pool.get()?;
    conn.execute(
        "INSERT OR IGNORE INTO sources (url, list_type, enabled, update_interval_hours) VALUES (?1, ?2, 1, ?3)",
        params![url, list_type, interval_hours],
    )?;
    let id = conn
        .query_row(
            "SELECT id FROM sources WHERE url = ?1",
            params![url],
            |row| row.get(0),
        )
        .unwrap_or(0);
    Ok(id)
}

pub fn delete_source(pool: &DbPool, id: i64) -> bool {
    delete_source_with_cleanup(pool, id).is_some()
}

/// Delete a source and drop domains that are no longer referenced by any source.
/// Returns `(list_type, rebuilt DomainStore)` when the source existed.
pub fn delete_source_with_cleanup(pool: &DbPool, id: i64) -> Option<(String, DomainStore)> {
    let mut conn = pool.get().ok()?;
    let list_type: String = conn
        .query_row(
            "SELECT list_type FROM sources WHERE id = ?1",
            params![id],
            |row| row.get(0),
        )
        .ok()?;
    let table = match list_type.as_str() {
        "allowlist" => "allowlist_domains",
        _ => "blocklist_domains",
    };

    let tx = conn.transaction().ok()?;
    let owned: Vec<String> = {
        let mut stmt = tx
            .prepare("SELECT domain FROM source_domains WHERE source_id = ?1")
            .ok()?;
        stmt.query_map(params![id], |row| row.get(0))
            .ok()?
            .filter_map(|r| r.ok())
            .collect()
    };
    tx.execute(
        "DELETE FROM source_domains WHERE source_id = ?1",
        params![id],
    )
    .ok()?;
    let rows = tx
        .execute("DELETE FROM sources WHERE id = ?1", params![id])
        .ok()?;
    if rows == 0 {
        return None;
    }

    {
        let _ = tx.execute_batch(
            "CREATE TEMP TABLE IF NOT EXISTS tmp_source_old_domains (
                domain TEXT PRIMARY KEY
            );
            DELETE FROM tmp_source_old_domains;",
        );
        {
            let mut stmt = tx
                .prepare("INSERT OR IGNORE INTO tmp_source_old_domains (domain) VALUES (?1)")
                .ok()?;
            for domain in &owned {
                let _ = stmt.execute(params![domain]);
            }
        }
        let prune_sql = match table {
            "allowlist_domains" => {
                "DELETE FROM allowlist_domains
                 WHERE domain IN (
                     SELECT o.domain FROM tmp_source_old_domains o
                     WHERE NOT EXISTS (
                         SELECT 1 FROM source_domains sd WHERE sd.domain = o.domain
                     )
                     AND NOT EXISTS (
                         SELECT 1 FROM manual_domains m
                         WHERE m.list_type = 'allowlist' AND m.domain = o.domain
                     )
                 )"
            }
            _ => {
                "DELETE FROM blocklist_domains
                 WHERE domain IN (
                     SELECT o.domain FROM tmp_source_old_domains o
                     WHERE NOT EXISTS (
                         SELECT 1 FROM source_domains sd WHERE sd.domain = o.domain
                     )
                     AND NOT EXISTS (
                         SELECT 1 FROM manual_domains m
                         WHERE m.list_type = 'blocklist' AND m.domain = o.domain
                     )
                 )"
            }
        };
        let _ = tx.execute(prune_sql, []);
    }
    tx.commit().ok()?;

    Some((list_type, load_domain_store_from_conn(&conn, table)))
}

pub fn update_source_status(pool: &DbPool, id: i64, status: &str) -> Result<(), DbError> {
    let conn = pool.get()?;
    conn.execute(
        "UPDATE sources SET last_updated = datetime('now'), last_status = ?1 WHERE id = ?2",
        params![status, id],
    )?;
    Ok(())
}

pub fn get_stale_sources(pool: &DbPool) -> Result<Vec<DbSource>, DbError> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        "SELECT id, url, list_type, enabled, update_interval_hours, last_updated, last_status
         FROM sources
         WHERE enabled = 1 AND (
             last_updated IS NULL
             OR datetime(last_updated, '+' || update_interval_hours || ' hours') <= datetime('now')
         )
         ORDER BY id",
    )?;
    let v = stmt
        .query_map([], |row| {
            Ok(DbSource {
                id: row.get(0)?,
                url: row.get(1)?,
                list_type: row.get(2)?,
                enabled: row.get::<_, i64>(3)? != 0,
                update_interval_hours: row.get(4)?,
                last_updated: row.get(5)?,
                last_status: row.get(6)?,
            })
        })?
        .filter_map(|r| r.ok())
        .collect();
    Ok(v)
}

/// Replace one source's domain set, prune unreferenced domains, and rebuild the
/// runtime store for the affected list table.
fn replace_source_domains(
    pool: &DbPool,
    source_id: i64,
    table: &str,
    content: &str,
) -> Result<(usize, DomainStore), String> {
    let mut conn = pool
        .get()
        .map_err(|e| format!("failed to get DB connection: {e}"))?;

    let mut new_list: Vec<String> = content.lines().filter_map(parse_domain_line).collect();
    new_list.sort();
    new_list.dedup();

    let tx = conn
        .transaction()
        .map_err(|e| format!("failed to begin transaction: {e}"))?;

    // Snapshot old ownership for this source into a temp table for set-based prune.
    tx.execute_batch(
        "CREATE TEMP TABLE IF NOT EXISTS tmp_source_old_domains (
            domain TEXT PRIMARY KEY
        );
        DELETE FROM tmp_source_old_domains;",
    )
    .map_err(|e| format!("prepare temp old domains: {e}"))?;

    tx.execute(
        "INSERT OR IGNORE INTO tmp_source_old_domains (domain)
         SELECT domain FROM source_domains WHERE source_id = ?1",
        params![source_id],
    )
    .map_err(|e| format!("snapshot old domains: {e}"))?;

    tx.execute(
        "DELETE FROM source_domains WHERE source_id = ?1",
        params![source_id],
    )
    .map_err(|e| format!("clear source_domains: {e}"))?;

    {
        let mut insert_src = tx
            .prepare("INSERT OR IGNORE INTO source_domains (source_id, domain) VALUES (?1, ?2)")
            .map_err(|e| format!("prepare source_domains insert: {e}"))?;
        let mut insert_domain = match table {
            "allowlist_domains" => tx
                .prepare("INSERT OR IGNORE INTO allowlist_domains (domain) VALUES (?1)")
                .map_err(|e| format!("prepare allowlist insert: {e}"))?,
            _ => tx
                .prepare("INSERT OR IGNORE INTO blocklist_domains (domain) VALUES (?1)")
                .map_err(|e| format!("prepare blocklist insert: {e}"))?,
        };
        for domain in &new_list {
            insert_src
                .execute(params![source_id, domain])
                .map_err(|e| format!("insert source_domains: {e}"))?;
            insert_domain
                .execute(params![domain])
                .map_err(|e| format!("insert domain: {e}"))?;
        }
    }

    // Set-based prune: domains this source used to own, no longer owned by any source,
    // and not marked manual. Avoids per-domain COUNT/DELETE loops on large lists.
    let prune_sql = match table {
        "allowlist_domains" => {
            "DELETE FROM allowlist_domains
             WHERE domain IN (
                 SELECT o.domain FROM tmp_source_old_domains o
                 WHERE NOT EXISTS (
                     SELECT 1 FROM source_domains sd WHERE sd.domain = o.domain
                 )
                 AND NOT EXISTS (
                     SELECT 1 FROM manual_domains m
                     WHERE m.list_type = 'allowlist' AND m.domain = o.domain
                 )
             )"
        }
        _ => {
            "DELETE FROM blocklist_domains
             WHERE domain IN (
                 SELECT o.domain FROM tmp_source_old_domains o
                 WHERE NOT EXISTS (
                     SELECT 1 FROM source_domains sd WHERE sd.domain = o.domain
                 )
                 AND NOT EXISTS (
                     SELECT 1 FROM manual_domains m
                     WHERE m.list_type = 'blocklist' AND m.domain = o.domain
                 )
             )"
        }
    };
    tx.execute(prune_sql, [])
        .map_err(|e| format!("prune unreferenced domains: {e}"))?;

    tx.execute(
        "UPDATE sources SET last_updated = datetime('now'), last_status = ?1 WHERE id = ?2",
        params![format!("ok: {} domains", new_list.len()), source_id],
    )
    .map_err(|e| format!("update source status: {e}"))?;

    tx.commit()
        .map_err(|e| format!("commit source refresh: {e}"))?;

    let rebuilt = load_domain_store_from_conn(&conn, table);
    Ok((new_list.len(), rebuilt))
}
fn load_domain_store_from_conn(conn: &rusqlite::Connection, table: &str) -> DomainStore {
    let mut store = DomainStore::default();
    let sql = match table {
        "allowlist_domains" => "SELECT domain FROM allowlist_domains",
        _ => "SELECT domain FROM blocklist_domains",
    };
    if let Ok(mut stmt) = conn.prepare(sql)
        && let Ok(rows) = stmt.query_map([], |row| row.get::<_, String>(0))
    {
        for domain in rows.flatten() {
            store.insert(&domain);
        }
    }
    store
}

/// Refresh a single source: fetch URL, replace that source's domain set, prune
/// domains no longer owned by any source, and rebuild the in-memory store.
/// Returns a status string like "ok: 12345 domains" or "failed: ...".
pub async fn refresh_source(
    pool: &DbPool,
    source: &DbSource,
    blocklist_store: Option<&std::sync::Arc<parking_lot::RwLock<crate::lists::DomainStore>>>,
    allowlist_store: Option<&std::sync::Arc<parking_lot::RwLock<crate::lists::DomainStore>>>,
) -> String {
    let table = match source.list_type.as_str() {
        "allowlist" => "allowlist_domains",
        _ => "blocklist_domains",
    };

    info!("Refreshing source: {} ({})", source.url, source.list_type);
    let content = fetch_source(&source.url).await;
    if content.is_empty() {
        let status = "failed: empty response".to_string();
        let pool = pool.clone();
        let status_for_db = status.clone();
        let source_id = source.id;
        let _ = tokio::task::spawn_blocking(move || {
            let _ = update_source_status(&pool, source_id, &status_for_db);
        })
        .await;
        return status;
    }

    let pool_for_db = pool.clone();
    let table_for_db = table.to_string();
    let source_id = source.id;
    let db_result = tokio::task::spawn_blocking(move || {
        replace_source_domains(&pool_for_db, source_id, &table_for_db, &content)
    })
    .await;

    let (status, rebuilt_store) = match db_result {
        Ok(Ok((count, store))) => (format!("ok: {count} domains"), store),
        Ok(Err(e)) => {
            let status = format!("failed: {e}");
            let pool = pool.clone();
            let status_for_db = status.clone();
            let source_id = source.id;
            let _ = tokio::task::spawn_blocking(move || {
                let _ = update_source_status(&pool, source_id, &status_for_db);
            })
            .await;
            return status;
        }
        Err(e) => {
            let status = format!("failed: database task failed: {e}");
            let pool = pool.clone();
            let status_for_db = status.clone();
            let source_id = source.id;
            let _ = tokio::task::spawn_blocking(move || {
                let _ = update_source_status(&pool, source_id, &status_for_db);
            })
            .await;
            return status;
        }
    };

    // Full replace — removed source domains leave RAM.
    let store = match source.list_type.as_str() {
        "allowlist" => allowlist_store,
        _ => blocklist_store,
    };
    if let Some(store) = store {
        let mut s = store.write();
        s.replace_with(rebuilt_store);
    }

    info!("Source refreshed: {} -> {}", source.url, status);
    status
}
// --- Sync manifest ---

/// Compute a deterministic SHA-256 hash for each sync category so slaves can
/// detect what changed without fetching full payloads every poll cycle.
///
/// Returns a map of category name → hex-encoded SHA-256 digest.
pub fn sync_manifest(pool: &DbPool) -> Result<std::collections::HashMap<String, String>, DbError> {
    use sha2::{Digest, Sha256};

    let conn = pool.get()?;
    let mut map = std::collections::HashMap::new();

    // settings — sorted key=value pairs, excluding auth secrets
    {
        let mut stmt = conn
            .prepare("SELECT key, value FROM settings WHERE key != 'admin_password_hash' AND key != 'session_secret' ORDER BY key")?;
        let pairs: Vec<String> = stmt
            .query_map([], |row| {
                let k: String = row.get(0)?;
                let v: String = row.get(1)?;
                Ok(format!("{}={}", k, v))
            })?
            .filter_map(|r| r.ok())
            .collect();
        let mut h = Sha256::new();
        for p in &pairs {
            h.update(p.as_bytes());
            h.update(b"\n");
        }
        map.insert("settings".to_string(), format!("{:x}", h.finalize()));
    }

    // upstreams — sorted address:port
    {
        let mut stmt =
            conn.prepare("SELECT address, port FROM upstreams ORDER BY address, port")?;
        let rows: Vec<String> = stmt
            .query_map([], |row| {
                let a: String = row.get(0)?;
                let p: i64 = row.get(1)?;
                Ok(format!("{}:{}", a, p))
            })?
            .filter_map(|r| r.ok())
            .collect();
        let mut h = Sha256::new();
        for r in &rows {
            h.update(r.as_bytes());
            h.update(b"\n");
        }
        map.insert("upstreams".to_string(), format!("{:x}", h.finalize()));
    }

    // rewrites — sorted domain
    {
        let mut stmt = conn.prepare("SELECT domain, ipv4, ipv6 FROM rewrites ORDER BY domain")?;
        let rows: Vec<String> = stmt
            .query_map([], |row| {
                let d: String = row.get(0)?;
                let v4: Option<String> = row.get(1)?;
                let v6: Option<String> = row.get(2)?;
                Ok(format!(
                    "{}|{}|{}",
                    d,
                    v4.as_deref().unwrap_or(""),
                    v6.as_deref().unwrap_or("")
                ))
            })?
            .filter_map(|r| r.ok())
            .collect();
        let mut h = Sha256::new();
        for r in &rows {
            h.update(r.as_bytes());
            h.update(b"\n");
        }
        map.insert("rewrites".to_string(), format!("{:x}", h.finalize()));
    }

    // sources — sorted url
    {
        let mut stmt = conn.prepare(
            "SELECT url, list_type, enabled, update_interval_hours FROM sources ORDER BY url",
        )?;
        let rows: Vec<String> = stmt
            .query_map([], |row| {
                let url: String = row.get(0)?;
                let lt: String = row.get(1)?;
                let en: i64 = row.get(2)?;
                let ih: i64 = row.get(3)?;
                Ok(format!("{}|{}|{}|{}", url, lt, en, ih))
            })?
            .filter_map(|r| r.ok())
            .collect();
        let mut h = Sha256::new();
        for r in &rows {
            h.update(r.as_bytes());
            h.update(b"\n");
        }
        map.insert("sources".to_string(), format!("{:x}", h.finalize()));
    }

    // blocklist — sorted domain
    {
        let mut h = Sha256::new();
        let mut stmt = conn.prepare("SELECT domain FROM blocklist_domains ORDER BY domain")?;
        let v: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .filter_map(|r| r.ok())
            .collect();
        for d in &v {
            h.update(d.as_bytes());
            h.update(b"\n");
        }
        map.insert("blocklist".to_string(), format!("{:x}", h.finalize()));
    }

    // allowlist — sorted domain
    {
        let mut h = Sha256::new();
        let mut stmt = conn.prepare("SELECT domain FROM allowlist_domains ORDER BY domain")?;
        let v: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .filter_map(|r| r.ok())
            .collect();
        for d in &v {
            h.update(d.as_bytes());
            h.update(b"\n");
        }
        map.insert("allowlist".to_string(), format!("{:x}", h.finalize()));
    }

    Ok(map)
}

/// Return a full snapshot of a single sync category as JSON.
/// Used by the slave to fetch only categories whose hash changed.
pub fn sync_snapshot(pool: &DbPool, category: &str) -> Result<Option<serde_json::Value>, DbError> {
    match category {
        "settings" => Ok(Some(get_settings(pool)?)),
        "upstreams" => Ok(Some(
            serde_json::to_value(get_upstreams(pool)?).unwrap_or_default(),
        )),
        "rewrites" => Ok(Some(
            serde_json::to_value(get_rewrites(pool)?).unwrap_or_default(),
        )),
        "sources" => Ok(Some(
            serde_json::to_value(get_sources(pool)?).unwrap_or_default(),
        )),
        "blocklist" => {
            let domains: Vec<String> = get_domains(pool, "blocklist_domains")?
                .into_iter()
                .map(|d| d.domain)
                .collect();
            Ok(Some(serde_json::to_value(domains).unwrap_or_default()))
        }
        "allowlist" => {
            let domains: Vec<String> = get_domains(pool, "allowlist_domains")?
                .into_iter()
                .map(|d| d.domain)
                .collect();
            Ok(Some(serde_json::to_value(domains).unwrap_or_default()))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_DB: AtomicU64 = AtomicU64::new(0);

    fn test_pool() -> DbPool {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_millis();
        let id = NEXT_DB.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("rustblocker-db-test-{millis}-{id}.db"));
        create_pool(path).expect("failed to create test database pool")
    }

    #[test]
    fn delete_domain_by_id_returns_deleted_domain() {
        let pool = test_pool();
        let id = add_domain(&pool, "blocklist_domains", "Delete-Me.Example.").unwrap();

        let deleted = delete_domain_by_id(&pool, "blocklist_domains", id);

        assert_eq!(deleted.as_deref(), Some("delete-me.example"));
        assert!(get_domain_by_id(&pool, "blocklist_domains", id).is_none());
        assert!(delete_domain_by_id(&pool, "blocklist_domains", id).is_none());
    }

    #[test]
    fn source_refresh_removes_domains_no_longer_in_source() {
        let pool = test_pool();
        let id = add_source(&pool, "memory://sticky-source", "blocklist", 24).unwrap();

        let full = "0.0.0.0 keep.example.com\n0.0.0.0 drop.example.com\n";
        let (full_count, full_store) =
            replace_source_domains(&pool, id, "blocklist_domains", full).expect("full replace");
        assert_eq!(full_count, 2);
        assert!(full_store.matches("keep.example.com"));
        assert!(full_store.matches("drop.example.com"));

        let shrink = "0.0.0.0 keep.example.com\n";
        let (shrink_count, shrink_store) =
            replace_source_domains(&pool, id, "blocklist_domains", shrink).expect("shrink replace");
        assert_eq!(shrink_count, 1);
        assert!(shrink_store.matches("keep.example.com"));
        assert!(
            !shrink_store.matches("drop.example.com"),
            "removed source domain must leave the rebuilt store"
        );

        // DB must also drop the unreferenced domain.
        let domains = get_domains(&pool, "blocklist_domains").unwrap_or_default();
        let names: Vec<_> = domains.into_iter().map(|d| d.domain).collect();
        assert!(names.iter().any(|d| d == "keep.example.com"));
        assert!(!names.iter().any(|d| d == "drop.example.com"));
    }

    #[test]
    fn source_refresh_preserves_manual_domains() {
        let pool = test_pool();
        let _manual_id = add_domain(&pool, "blocklist_domains", "manual.example.com");
        let id = add_source(&pool, "memory://manual-overlap", "blocklist", 24).unwrap();
        replace_source_domains(
            &pool,
            id,
            "blocklist_domains",
            "0.0.0.0 manual.example.com\n0.0.0.0 source-only.example.com\n",
        )
        .expect("seed overlapping source");

        let (_count, store) = replace_source_domains(
            &pool,
            id,
            "blocklist_domains",
            "0.0.0.0 source-only.example.com\n",
        )
        .expect("shrink source without manual domain");

        // Source-only domain remains; manual domain must remain even though source dropped it.
        assert!(store.matches("source-only.example.com"));
        assert!(store.matches("manual.example.com"));
        let domains = get_domains(&pool, "blocklist_domains").unwrap_or_default();
        let names: Vec<_> = domains.into_iter().map(|d| d.domain).collect();
        assert!(names.iter().any(|d| d == "manual.example.com"));
    }

    #[test]
    fn source_delete_prunes_owned_domains() {
        let pool = test_pool();
        let id = add_source(&pool, "memory://delete-source", "blocklist", 24).unwrap();
        replace_source_domains(
            &pool,
            id,
            "blocklist_domains",
            "0.0.0.0 only-from-source.example.com\n",
        )
        .expect("seed source domains");

        let (list_type, rebuilt) = delete_source_with_cleanup(&pool, id).expect("source deleted");
        assert_eq!(list_type, "blocklist");
        assert!(!rebuilt.matches("only-from-source.example.com"));
        assert_eq!(
            count_domains(&pool, "blocklist_domains").unwrap_or_default(),
            0
        );
    }

    #[test]
    fn delete_rewrite_by_id_returns_deleted_rewrite() {
        let pool = test_pool();
        let id = add_rewrite(&pool, "Rewrite-Me.Example.", Some("192.0.2.77"), None).unwrap();

        let deleted = delete_rewrite_by_id(&pool, id).expect("deleted rewrite");

        assert_eq!(deleted.domain, "rewrite-me.example");
        assert_eq!(deleted.ipv4.as_deref(), Some("192.0.2.77"));
        assert!(get_rewrite_by_id(&pool, id).is_none());
        assert!(delete_rewrite_by_id(&pool, id).is_none());
    }
}
