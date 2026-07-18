//! Slave-side sync: polls a master RustBlocker instance, detects changes via
//! a manifest of per-category SHA-256 hashes, and applies only what changed.
//!
//! Activated by passing `--sync-master <url>` (and `--sync-password <pass>`).
//! The slave authenticates with the master's admin password, then polls
//! `GET /api/sync/manifest` every `--sync-interval` seconds (default 30).
//! When a category hash differs from the last-seen value the slave fetches
//! `GET /api/sync/snapshot/<category>` and applies it locally.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::config::{RewriteRule, UpstreamConfig};
use crate::db::{self, DbPool};
use crate::forwarder::{ForwardStrategy, ParallelForwarder};
use crate::lists::{AllowlistStore, BlocklistStore, DomainStore, RewriteMap};
use parking_lot::RwLock;
use serde::Deserialize;
use std::result::Result;
use tracing::{error, info, warn};

#[derive(Debug, Deserialize)]
struct ManifestResponse {
    hashes: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct LoginResponse {
    authenticated: bool,
}

pub struct SyncConfig {
    pub master_url: String,
    pub password: String,
    pub interval: Duration,
}

/// Runtime sync status — written by the polling loop, read by /api/sync/status.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SyncState {
    pub status: String,         // "connecting" | "ok" | "error" | "disabled"
    pub last_sync: Option<u64>, // unix timestamp of last successful manifest poll
    pub error: Option<String>,
    pub master_url: String,
}

impl Default for SyncState {
    fn default() -> Self {
        Self {
            status: "disabled".into(),
            last_sync: None,
            error: None,
            master_url: String::new(),
        }
    }
}

pub type SharedSyncState = Arc<parking_lot::Mutex<SyncState>>;

/// Spawn the slave polling loop.  Runs forever; cancel by aborting the task.
pub fn spawn(
    config: SyncConfig,
    pool: DbPool,
    blocklist: BlocklistStore,
    allowlist: AllowlistStore,
    rewrites: Arc<RwLock<RewriteMap>>,
    forwarder: Arc<RwLock<ParallelForwarder>>,
    state: SharedSyncState,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = run(
            config, pool, blocklist, allowlist, rewrites, forwarder, state,
        )
        .await
        {
            error!("Sync: failed to start: {e}");
        }
    })
}

async fn run(
    config: SyncConfig,
    pool: DbPool,
    blocklist: BlocklistStore,
    allowlist: AllowlistStore,
    rewrites: Arc<RwLock<RewriteMap>>,
    forwarder: Arc<RwLock<ParallelForwarder>>,
    state: SharedSyncState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build sync HTTP client: {e}"))?;
    let base = config.master_url.trim_end_matches('/');
    let mut known_hashes: HashMap<String, String> = HashMap::new();

    info!("Sync slave started, master: {}", base);

    loop {
        // --- Authenticate (or re-authenticate after session expiry) ---
        // Clear known hashes on every (re-)auth so any changes that occurred
        // while the master was unreachable are guaranteed to be re-fetched.
        known_hashes.clear();
        {
            let mut s = state.lock();
            s.status = "connecting".into();
            s.master_url = base.to_string();
            s.error = None;
        }
        if !login(&client, base, &config.password).await {
            warn!(
                "Sync: login to master failed, retrying in {:?}",
                config.interval
            );
            {
                let mut s = state.lock();
                s.status = "error".into();
                s.error = Some("Login to master failed".into());
            }
            tokio::time::sleep(config.interval).await;
            continue;
        }

        // --- Poll loop: manifest → diff → fetch changed categories ---
        let mut interval = tokio::time::interval(config.interval);
        interval.tick().await; // discard immediate first tick

        loop {
            interval.tick().await;

            let manifest = match fetch_manifest(&client, base).await {
                Some(m) => m,
                None => {
                    warn!("Sync: failed to fetch manifest, will re-authenticate");
                    {
                        let mut s = state.lock();
                        s.status = "error".into();
                        s.error = Some("Failed to fetch manifest".into());
                    }
                    break; // outer loop re-authenticates
                }
            };

            for (category, hash) in &manifest.hashes {
                if known_hashes
                    .get(category.as_str())
                    .map(|h| h == hash)
                    .unwrap_or(false)
                {
                    continue; // unchanged
                }

                info!("Sync: category '{}' changed, fetching snapshot", category);
                match fetch_snapshot(&client, base, category).await {
                    Some(data) => {
                        apply_snapshot(
                            category, &data, &pool, &blocklist, &allowlist, &rewrites, &forwarder,
                        )
                        .await;
                        known_hashes.insert(category.clone(), hash.clone());
                        info!("Sync: applied '{}'", category);
                    }
                    None => {
                        warn!("Sync: failed to fetch snapshot for '{}'", category);
                    }
                }
            }
            {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let mut s = state.lock();
                s.status = "ok".into();
                s.last_sync = Some(now);
                s.error = None;
            }
        }
    }
}

async fn login(client: &reqwest::Client, base: &str, password: &str) -> bool {
    let url = format!("{}/api/auth/login", base);
    match client
        .post(&url)
        .json(&serde_json::json!({ "password": password }))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => match resp.json::<LoginResponse>().await {
            Ok(body) => body.authenticated,
            Err(e) => {
                warn!("Sync: login response parse error: {}", e);
                false
            }
        },
        Ok(resp) => {
            warn!("Sync: login returned HTTP {}", resp.status());
            false
        }
        Err(e) => {
            warn!("Sync: login request error: {}", e);
            false
        }
    }
}

async fn fetch_manifest(client: &reqwest::Client, base: &str) -> Option<ManifestResponse> {
    let url = format!("{}/api/sync/manifest", base);
    let resp = client.get(&url).send().await.ok()?;
    if !resp.status().is_success() {
        warn!("Sync: manifest returned HTTP {}", resp.status());
        return None;
    }
    resp.json::<ManifestResponse>()
        .await
        .map_err(|e| warn!("Sync: manifest parse error: {}", e))
        .ok()
}

async fn fetch_snapshot(
    client: &reqwest::Client,
    base: &str,
    category: &str,
) -> Option<serde_json::Value> {
    let url = format!("{}/api/sync/snapshot/{}", base, category);
    let resp = client.get(&url).send().await.ok()?;
    if !resp.status().is_success() {
        warn!(
            "Sync: snapshot '{}' returned HTTP {}",
            category,
            resp.status()
        );
        return None;
    }
    resp.json::<serde_json::Value>()
        .await
        .map_err(|e| warn!("Sync: snapshot '{}' parse error: {}", category, e))
        .ok()
}

async fn apply_snapshot(
    category: &str,
    data: &serde_json::Value,
    pool: &DbPool,
    blocklist: &BlocklistStore,
    allowlist: &AllowlistStore,
    rewrites: &Arc<RwLock<RewriteMap>>,
    forwarder: &Arc<RwLock<ParallelForwarder>>,
) {
    let category = category.to_string();
    let data = data.clone();
    let pool = pool.clone();
    let blocklist = blocklist.clone();
    let allowlist = allowlist.clone();
    let rewrites = rewrites.clone();
    let forwarder = forwarder.clone();

    let category_for_log = category.clone();
    if let Err(e) = tokio::task::spawn_blocking(move || {
        apply_snapshot_blocking(
            &category, &data, &pool, &blocklist, &allowlist, &rewrites, &forwarder,
        );
    })
    .await
    {
        warn!(
            "Sync: apply snapshot task failed for '{}': {}",
            category_for_log, e
        );
    }
}

fn apply_snapshot_blocking(
    category: &str,
    data: &serde_json::Value,
    pool: &DbPool,
    blocklist: &BlocklistStore,
    allowlist: &AllowlistStore,
    rewrites: &Arc<RwLock<RewriteMap>>,
    forwarder: &Arc<RwLock<ParallelForwarder>>,
) {
    match category {
        "settings" => apply_settings(data, pool, forwarder),
        "upstreams" => apply_upstreams(data, pool, forwarder),
        "rewrites" => apply_rewrites(data, pool, rewrites),
        "sources" => apply_sources(data, pool),
        "blocklist" => apply_blocklist(data, pool, &blocklist.0),
        "allowlist" => apply_allowlist(data, pool, &allowlist.0),
        other => warn!("Sync: unknown category '{}'", other),
    }
}

fn apply_settings(
    data: &serde_json::Value,
    pool: &DbPool,
    forwarder: &Arc<RwLock<ParallelForwarder>>,
) {
    let obj = match data.as_object() {
        Some(o) => o,
        None => {
            warn!("Sync: settings payload is not an object");
            return;
        }
    };
    // Never overwrite keys that are slave-local: network binding, ACL (could
    // lock admin out if master's ACL differs), auth secrets, sync config, and
    // certificate settings for this node's own HTTPS endpoint.
    const SKIP: &[&str] = &[
        "listen_address",
        "listen_port",
        "allowed_networks",
        "admin_password_hash",
        "session_secret",
        "domain",
        "acme_email",
        "acme_error",
        "acme_directory_url",
        "cloudflare_api_token",
        "wildcard_cert",
        "sync_password",
        "sync_master",
        "sync_enabled",
        "sync_interval_secs",
    ];
    for (key, val) in obj {
        if SKIP.contains(&key.as_str()) {
            continue;
        }
        if let Some(v) = val.as_str()
            && let Err(e) = db::set_setting(pool, key, v)
        {
            tracing::warn!("db set_setting failed: {e}");
        }
    }

    reload_forwarder_from_db(pool, forwarder, "settings apply");
}

fn forward_strategy_from_db(pool: &DbPool) -> ForwardStrategy {
    db::get_setting(pool, "forward_strategy")
        .and_then(|s| s.parse().ok())
        .unwrap_or_default()
}

fn reload_forwarder_from_db(
    pool: &DbPool,
    forwarder: &Arc<RwLock<ParallelForwarder>>,
    reason: &str,
) {
    let timeout_secs: u64 = db::get_setting(pool, "upstream_timeout_secs")
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);
    let strategy = forward_strategy_from_db(pool);
    let configs: Vec<UpstreamConfig> = db::get_upstreams(pool)
        .unwrap_or_default()
        .iter()
        .map(|u| UpstreamConfig {
            address: u.address.clone(),
            port: Some(u.port as u16),
        })
        .collect();

    if let Err(e) = forwarder.write().reload(&configs, timeout_secs, strategy) {
        warn!("Sync: forwarder reload failed after {}: {}", reason, e);
    }
}

fn apply_upstreams(
    data: &serde_json::Value,
    pool: &DbPool,
    forwarder: &Arc<RwLock<ParallelForwarder>>,
) {
    #[derive(Deserialize)]
    struct UpstreamItem {
        address: String,
        port: i64,
    }

    let items: Vec<UpstreamItem> = match serde_json::from_value(data.clone()) {
        Ok(v) => v,
        Err(e) => {
            warn!("Sync: upstreams parse error: {}", e);
            return;
        }
    };

    // Replace all upstreams atomically.
    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            warn!("Sync: failed to get DB connection for upstreams: {e}");
            return;
        }
    };
    let result: rusqlite::Result<()> = (|| {
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM upstreams", [])?;
        {
            let mut stmt = tx.prepare("INSERT INTO upstreams (address, port) VALUES (?1, ?2)")?;
            for item in &items {
                stmt.execute(rusqlite::params![item.address, item.port])?;
            }
        }
        tx.commit()
    })();

    if let Err(e) = result {
        warn!("Sync: DB error applying upstreams: {}", e);
        return;
    }
    drop(conn);

    // Hot-reload forwarder only after the transaction committed.
    let timeout_secs: u64 = db::get_setting(pool, "upstream_timeout_secs")
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);
    let configs: Vec<UpstreamConfig> = items
        .iter()
        .map(|u| UpstreamConfig {
            address: u.address.clone(),
            port: Some(u.port as u16),
        })
        .collect();
    let strategy = forward_strategy_from_db(pool);
    if let Err(e) = forwarder.write().reload(&configs, timeout_secs, strategy) {
        warn!("Sync: forwarder reload failed: {}", e);
    }
}

fn apply_rewrites(data: &serde_json::Value, pool: &DbPool, rewrites: &Arc<RwLock<RewriteMap>>) {
    #[derive(Deserialize)]
    struct RewriteItem {
        domain: String,
        ipv4: Option<String>,
        ipv6: Option<String>,
    }

    let items: Vec<RewriteItem> = match serde_json::from_value(data.clone()) {
        Ok(v) => v,
        Err(e) => {
            warn!("Sync: rewrites parse error: {}", e);
            return;
        }
    };

    // Replace rewrites atomically in DB first, then update in-memory map.
    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            warn!("Sync: failed to get DB connection for rewrites: {e}");
            return;
        }
    };
    let result: rusqlite::Result<()> = (|| {
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM rewrites", [])?;
        {
            let mut stmt =
                tx.prepare("INSERT INTO rewrites (domain, ipv4, ipv6) VALUES (?1, ?2, ?3)")?;
            for item in &items {
                stmt.execute(rusqlite::params![item.domain, item.ipv4, item.ipv6])?;
            }
        }
        tx.commit()
    })();

    if let Err(e) = result {
        warn!("Sync: DB error applying rewrites: {}", e);
        return;
    }
    drop(conn);

    // Update in-memory map only after the DB transaction committed.
    let mut map = rewrites.write();
    map.rules.clear();
    for item in &items {
        map.insert(RewriteRule {
            domain: item.domain.clone(),
            ipv4: item.ipv4.clone(),
            ipv6: item.ipv6.clone(),
        });
    }
}

fn apply_sources(data: &serde_json::Value, pool: &DbPool) {
    #[derive(Deserialize)]
    struct SourceItem {
        url: String,
        list_type: String,
        update_interval_hours: i64,
    }

    let items: Vec<SourceItem> = match serde_json::from_value(data.clone()) {
        Ok(v) => v,
        Err(e) => {
            warn!("Sync: sources parse error: {}", e);
            return;
        }
    };

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            warn!("Sync: failed to get DB connection for sources: {e}");
            return;
        }
    };
    let result: rusqlite::Result<()> = (|| {
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM sources", [])?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO sources (url, list_type, update_interval_hours) VALUES (?1, ?2, ?3)",
            )?;
            for item in &items {
                stmt.execute(rusqlite::params![
                    item.url,
                    item.list_type,
                    item.update_interval_hours
                ])?;
            }
        }
        tx.commit()
    })();
    drop(conn);

    if let Err(e) = result {
        warn!("Sync: DB error applying sources: {}", e);
    }
}

fn apply_blocklist(data: &serde_json::Value, pool: &DbPool, store: &Arc<RwLock<DomainStore>>) {
    apply_domains_inner(data, pool, "blocklist_domains", store);
}

fn apply_allowlist(data: &serde_json::Value, pool: &DbPool, store: &Arc<RwLock<DomainStore>>) {
    apply_domains_inner(data, pool, "allowlist_domains", store);
}

fn apply_domains_inner(
    data: &serde_json::Value,
    pool: &DbPool,
    table: &'static str,
    store: &Arc<RwLock<DomainStore>>,
) {
    let domains: Vec<String> = match serde_json::from_value(data.clone()) {
        Ok(v) => v,
        Err(e) => {
            warn!("Sync: domains parse error for {}: {}", table, e);
            return;
        }
    };

    // Replace entire table atomically inside a real transaction so a failure
    // between DELETE and INSERT doesn't leave the table empty.
    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            warn!("Sync: failed to get DB connection for domains: {e}");
            return;
        }
    };
    let result: rusqlite::Result<()> = (|| {
        let tx = conn.transaction()?;
        // Table name is a &'static str from a closed match in apply_snapshot — not user input.
        match table {
            "blocklist_domains" => {
                tx.execute("DELETE FROM blocklist_domains", [])?;
                let mut stmt =
                    tx.prepare("INSERT OR IGNORE INTO blocklist_domains (domain) VALUES (?1)")?;
                for domain in &domains {
                    stmt.execute(rusqlite::params![domain])?;
                }
            }
            "allowlist_domains" => {
                tx.execute("DELETE FROM allowlist_domains", [])?;
                let mut stmt =
                    tx.prepare("INSERT OR IGNORE INTO allowlist_domains (domain) VALUES (?1)")?;
                for domain in &domains {
                    stmt.execute(rusqlite::params![domain])?;
                }
            }
            other => {
                warn!(
                    "Sync: apply_domains_inner called with unexpected table '{}'",
                    other
                );
                return Ok(());
            }
        }
        tx.commit()
    })();

    if let Err(e) = result {
        warn!("Sync: DB error applying {}: {}", table, e);
        return;
    }
    drop(conn);

    // Reload in-memory store only after the transaction committed.
    // Build fresh + replace_with so arena/HashMap capacity from a larger prior
    // snapshot is dropped (clear()+insert retains old capacity).
    let mut fresh = DomainStore::default();
    for domain in &domains {
        fresh.insert(domain);
    }
    store.write().replace_with(fresh);
}
