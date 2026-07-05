use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use tracing::info;

pub type DbPool = Pool<SqliteConnectionManager>;

pub fn create_pool(db_path: &str) -> Result<DbPool, r2d2::Error> {
    let manager = SqliteConnectionManager::file(db_path);
    let pool = Pool::new(manager)?;
    {
        let conn = pool.get().expect("failed to get DB connection");
        init_schema(&conn);
    }
    info!("SQLite database ready: {}", db_path);
    Ok(pool)
}

fn init_schema(conn: &rusqlite::Connection) {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
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
        );",
    )
    .expect("failed to init schema");
}

/// Seed the database with sensible defaults (only if tables are empty).
pub fn seed_defaults(pool: &DbPool) {
    let conn = pool.get().expect("failed to get DB connection");

    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM settings", [], |row| row.get(0))
        .unwrap_or(0);
    if count > 0 {
        info!("Database already seeded");
        return;
    }

    info!("Seeding database with default settings...");

    let settings = [
        ("listen_address", "0.0.0.0"),
        ("listen_port", "53"),
        ("sinkhole_ipv4", "0.0.0.0"),
        ("sinkhole_ipv6", "::"),
        ("log_level", "info"),
        ("upstream_timeout_secs", "5"),
        ("allowed_networks", ""),
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
    bulk_import_domains(pool, table, &content)
}

/// Insert domains from content, preserving `*.` prefix for wildcards.
fn insert_domains_from_content(conn: &rusqlite::Connection, table: &str, content: &str) {
    let sql = format!("INSERT OR IGNORE INTO {} (domain) VALUES (?1)", table);
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let domain_part = if line.starts_with("0.0.0.0") || line.starts_with("127.0.0.1") {
            line.split_whitespace().nth(1).unwrap_or("")
        } else {
            line
        };

        let domain_part = domain_part.trim();
        if domain_part.is_empty() {
            continue;
        }

        let normalized = domain_part.to_lowercase();
        let normalized = normalized.strip_suffix('.').unwrap_or(&normalized);
        if !normalized.is_empty() {
            conn.execute(&sql, params![normalized]).ok();
        }
    }
}

// --- Settings ---

pub fn get_settings(pool: &DbPool) -> serde_json::Value {
    let conn = pool.get().expect("failed to get DB connection");
    let mut stmt = conn.prepare("SELECT key, value FROM settings").unwrap();
    let rows: Vec<(String, String)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();

    let mut map = serde_json::Map::new();
    for (key, value) in rows {
        map.insert(key, serde_json::Value::String(value));
    }
    serde_json::Value::Object(map)
}

pub fn set_setting(pool: &DbPool, key: &str, value: &str) {
    let conn = pool.get().expect("failed to get DB connection");
    conn.execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES (?1, ?2)",
        params![key, value],
    )
    .ok();
}

// --- Upstreams ---

#[derive(Debug, Serialize, Deserialize)]
pub struct DbUpstream {
    pub id: i64,
    pub address: String,
    pub port: i64,
}

pub fn get_upstreams(pool: &DbPool) -> Vec<DbUpstream> {
    let conn = pool.get().expect("failed to get DB connection");
    let mut stmt = conn
        .prepare("SELECT id, address, port FROM upstreams ORDER BY id")
        .unwrap();
    stmt.query_map([], |row| {
        Ok(DbUpstream {
            id: row.get(0)?,
            address: row.get(1)?,
            port: row.get(2)?,
        })
    })
    .unwrap()
    .filter_map(|r| r.ok())
    .collect()
}

pub fn add_upstream(pool: &DbPool, address: &str, port: i64) -> i64 {
    let conn = pool.get().expect("failed to get DB connection");
    conn.execute(
        "INSERT INTO upstreams (address, port) VALUES (?1, ?2)",
        params![address, port],
    )
    .ok();
    conn.last_insert_rowid()
}

pub fn delete_upstream(pool: &DbPool, id: i64) -> bool {
    let conn = pool.get().expect("failed to get DB connection");
    let rows = conn
        .execute("DELETE FROM upstreams WHERE id = ?1", params![id])
        .unwrap();
    rows > 0
}

// --- Domains (blocklist / allowlist) ---

#[derive(Debug, Serialize, Deserialize)]
pub struct DbDomain {
    pub id: i64,
    pub domain: String,
}

pub fn get_domains(pool: &DbPool, table: &str) -> Vec<DbDomain> {
    let conn = pool.get().expect("failed to get DB connection");
    let sql = format!("SELECT id, domain FROM {} ORDER BY domain", table);
    let mut stmt = conn.prepare(&sql).unwrap();
    stmt.query_map([], |row| {
        Ok(DbDomain {
            id: row.get(0)?,
            domain: row.get(1)?,
        })
    })
    .unwrap()
    .filter_map(|r| r.ok())
    .collect()
}

pub fn count_domains(pool: &DbPool, table: &str) -> i64 {
    let conn = pool.get().expect("failed to get DB connection");
    let sql = format!("SELECT COUNT(*) FROM {}", table);
    conn.query_row(&sql, [], |row| row.get(0)).unwrap_or(0)
}

pub fn search_domains(
    pool: &DbPool,
    table: &str,
    search: &str,
    limit: i64,
    offset: i64,
) -> Vec<DbDomain> {
    let conn = pool.get().expect("failed to get DB connection");
    if search.is_empty() {
        let sql = format!(
            "SELECT id, domain FROM {} ORDER BY domain LIMIT ?1 OFFSET ?2",
            table
        );
        let mut stmt = conn.prepare(&sql).unwrap();
        stmt.query_map(rusqlite::params![limit, offset], |row| {
            Ok(DbDomain {
                id: row.get(0)?,
                domain: row.get(1)?,
            })
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    } else {
        let sql = format!(
            "SELECT id, domain FROM {} WHERE domain LIKE ?1 ORDER BY domain LIMIT ?2 OFFSET ?3",
            table
        );
        let pattern = format!("%{}%", search);
        let mut stmt = conn.prepare(&sql).unwrap();
        stmt.query_map(rusqlite::params![pattern, limit, offset], |row| {
            Ok(DbDomain {
                id: row.get(0)?,
                domain: row.get(1)?,
            })
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }
}

pub fn add_domain(pool: &DbPool, table: &str, domain: &str) -> i64 {
    let conn = pool.get().expect("failed to get DB connection");
    let normalized = domain.to_lowercase();
    let normalized = normalized.strip_suffix('.').unwrap_or(&normalized);
    let sql = format!("INSERT OR IGNORE INTO {} (domain) VALUES (?1)", table);
    conn.execute(&sql, params![normalized]).ok();
    conn.last_insert_rowid()
}

pub fn delete_domain(pool: &DbPool, table: &str, id: i64) -> bool {
    let conn = pool.get().expect("failed to get DB connection");
    let sql = format!("DELETE FROM {} WHERE id = ?1", table);
    let rows = conn.execute(&sql, params![id]).unwrap();
    rows > 0
}

pub fn bulk_import_domains(pool: &DbPool, table: &str, content: &str) -> usize {
    let conn = pool.get().expect("failed to get DB connection");
    let before: i64 = conn
        .query_row(&format!("SELECT COUNT(*) FROM {}", table), [], |row| {
            row.get(0)
        })
        .unwrap_or(0);
    insert_domains_from_content(&conn, table, content);
    let after: i64 = conn
        .query_row(&format!("SELECT COUNT(*) FROM {}", table), [], |row| {
            row.get(0)
        })
        .unwrap_or(0);
    (after - before) as usize
}

// --- Rewrites ---

#[derive(Debug, Serialize, Deserialize)]
pub struct DbRewrite {
    pub id: i64,
    pub domain: String,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
}

pub fn get_rewrites(pool: &DbPool) -> Vec<DbRewrite> {
    let conn = pool.get().expect("failed to get DB connection");
    let mut stmt = conn
        .prepare("SELECT id, domain, ipv4, ipv6 FROM rewrites ORDER BY domain")
        .unwrap();
    stmt.query_map([], |row| {
        Ok(DbRewrite {
            id: row.get(0)?,
            domain: row.get(1)?,
            ipv4: row.get(2)?,
            ipv6: row.get(3)?,
        })
    })
    .unwrap()
    .filter_map(|r| r.ok())
    .collect()
}

pub fn add_rewrite(pool: &DbPool, domain: &str, ipv4: Option<&str>, ipv6: Option<&str>) -> i64 {
    let conn = pool.get().expect("failed to get DB connection");
    let normalized = domain.to_lowercase();
    let normalized = normalized.strip_suffix('.').unwrap_or(&normalized);
    conn.execute(
        "INSERT OR IGNORE INTO rewrites (domain, ipv4, ipv6) VALUES (?1, ?2, ?3)",
        params![normalized, ipv4, ipv6],
    )
    .ok();
    conn.last_insert_rowid()
}

pub fn delete_rewrite(pool: &DbPool, id: i64) -> bool {
    let conn = pool.get().expect("failed to get DB connection");
    let rows = conn
        .execute("DELETE FROM rewrites WHERE id = ?1", params![id])
        .unwrap();
    rows > 0
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

pub fn get_sources(pool: &DbPool) -> Vec<DbSource> {
    let conn = pool.get().expect("failed to get DB connection");
    let mut stmt = conn
        .prepare("SELECT id, url, list_type, enabled, update_interval_hours, last_updated, last_status FROM sources ORDER BY id")
        .unwrap();
    stmt.query_map([], |row| {
        Ok(DbSource {
            id: row.get(0)?,
            url: row.get(1)?,
            list_type: row.get(2)?,
            enabled: row.get::<_, i64>(3)? != 0,
            update_interval_hours: row.get(4)?,
            last_updated: row.get(5)?,
            last_status: row.get(6)?,
        })
    })
    .unwrap()
    .filter_map(|r| r.ok())
    .collect()
}

pub fn add_source(pool: &DbPool, url: &str, list_type: &str, interval_hours: i64) -> i64 {
    let conn = pool.get().expect("failed to get DB connection");
    conn.execute(
        "INSERT OR IGNORE INTO sources (url, list_type, enabled, update_interval_hours) VALUES (?1, ?2, 1, ?3)",
        params![url, list_type, interval_hours],
    ).ok();
    conn.last_insert_rowid()
}

pub fn delete_source(pool: &DbPool, id: i64) -> bool {
    let conn = pool.get().expect("failed to get DB connection");
    let rows = conn
        .execute("DELETE FROM sources WHERE id = ?1", params![id])
        .unwrap();
    rows > 0
}

pub fn update_source_status(pool: &DbPool, id: i64, status: &str) {
    let conn = pool.get().expect("failed to get DB connection");
    conn.execute(
        "UPDATE sources SET last_updated = datetime('now'), last_status = ?1 WHERE id = ?2",
        params![status, id],
    )
    .ok();
}

pub fn get_stale_sources(pool: &DbPool) -> Vec<DbSource> {
    let conn = pool.get().expect("failed to get DB connection");
    let mut stmt = conn
        .prepare(
            "SELECT id, url, list_type, enabled, update_interval_hours, last_updated, last_status
             FROM sources
             WHERE enabled = 1 AND (
                 last_updated IS NULL
                 OR datetime(last_updated, '+' || update_interval_hours || ' hours') <= datetime('now')
             )
             ORDER BY id",
        )
        .unwrap();
    stmt.query_map([], |row| {
        Ok(DbSource {
            id: row.get(0)?,
            url: row.get(1)?,
            list_type: row.get(2)?,
            enabled: row.get::<_, i64>(3)? != 0,
            update_interval_hours: row.get(4)?,
            last_updated: row.get(5)?,
            last_status: row.get(6)?,
        })
    })
    .unwrap()
    .filter_map(|r| r.ok())
    .collect()
}

/// Refresh a single source: fetch URL, import domains, update status.
/// Returns a status string like "ok: 12345 domains" or "failed: ...".
pub async fn refresh_source(
    pool: &DbPool,
    source: &DbSource,
    blocklist_store: Option<&parking_lot::RwLock<crate::lists::DomainStore>>,
    allowlist_store: Option<&parking_lot::RwLock<crate::lists::DomainStore>>,
) -> String {
    let table = match source.list_type.as_str() {
        "allowlist" => "allowlist_domains",
        _ => "blocklist_domains",
    };

    info!("Refreshing source: {} ({})", source.url, source.list_type);
    let content = fetch_source(&source.url).await;
    if content.is_empty() {
        let status = "failed: empty response".to_string();
        update_source_status(pool, source.id, &status);
        return status;
    }

    let count = bulk_import_domains(pool, table, &content);
    let status = format!("ok: {} domains", count);
    update_source_status(pool, source.id, &status);

    // Reload in-memory store
    let store = match source.list_type.as_str() {
        "allowlist" => allowlist_store,
        _ => blocklist_store,
    };
    if let Some(store) = store {
        let domains = get_domains(pool, table);
        let mut s = store.write();
        s.exact.clear();
        s.wildcards.clear();
        for d in &domains {
            if let Some(stripped) = d.domain.strip_prefix("*.") {
                s.wildcards.insert(stripped.to_lowercase());
            } else {
                s.exact.insert(d.domain.to_lowercase());
            }
        }
    }

    info!("Source refreshed: {} -> {}", source.url, status);
    status
}
