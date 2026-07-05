use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use parking_lot::RwLock;
use tokio::net::{TcpListener, UdpSocket};
use tracing::{info, warn};

use rustblocker::api;
use rustblocker::config::UpstreamConfig;
use rustblocker::db;
use rustblocker::forwarder::ParallelForwarder;
use rustblocker::handler::DnsBlockerHandler;
use rustblocker::lists::{normalize_domain, DomainStore, RewriteMap};

fn main() -> Result<()> {
    // Initialize tracing with default level — overridable via RUST_LOG env var
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .init();

    info!("Starting RustBlocker");

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(run_server())
}

/// Load a DomainStore from the database.
fn load_store_from_db(pool: &db::DbPool, table: &str) -> DomainStore {
    let domains = db::get_domains(pool, table);
    let mut store = DomainStore::default();
    for d in &domains {
        if let Some(stripped) = d.domain.strip_prefix("*.") {
            store.wildcards.insert(stripped.to_lowercase());
        } else {
            store.exact.insert(d.domain.to_lowercase());
        }
    }
    store
}

/// Load a RewriteMap from the database.
fn load_rewrites_from_db(pool: &db::DbPool) -> RewriteMap {
    let rewrites = db::get_rewrites(pool);
    let mut map = RewriteMap::default();
    for r in &rewrites {
        let rule = rustblocker::config::RewriteRule {
            domain: r.domain.clone(),
            ipv4: r.ipv4.clone(),
            ipv6: r.ipv6.clone(),
        };
        map.rules.insert(normalize_domain(&r.domain), rule);
    }
    map
}

/// Load settings from DB as key-value pairs.
fn get_setting_string(pool: &db::DbPool, key: &str) -> String {
    let settings = db::get_settings(pool);
    settings
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

async fn run_server() -> Result<()> {
    // Initialize SQLite
    let pool = db::create_pool("rustblocker.db")
        .context("Failed to create SQLite database")?;

    // Seed with defaults if DB is empty
    db::seed_defaults(&pool);

    // Read settings from DB
    let listen_address = get_setting_string(&pool, "listen_address");
    let listen_port: u16 = get_setting_string(&pool, "listen_port")
        .parse()
        .unwrap_or(5353);
    let sinkhole_ipv4_str = get_setting_string(&pool, "sinkhole_ipv4");
    let sinkhole_ipv6_str = get_setting_string(&pool, "sinkhole_ipv6");
    let _log_level = get_setting_string(&pool, "log_level");
    let upstream_timeout: u64 = get_setting_string(&pool, "upstream_timeout_secs")
        .parse()
        .unwrap_or(5);

    let listen_addr: SocketAddr = format!("{}:{}", listen_address, listen_port)
        .parse()
        .context("Invalid listen address from DB")?;

    // Load domain stores from DB into Arc<RwLock<>>
    let blocklist = Arc::new(RwLock::new(load_store_from_db(&pool, "blocklist_domains")));
    let allowlist = Arc::new(RwLock::new(load_store_from_db(&pool, "allowlist_domains")));
    let rewrites = Arc::new(RwLock::new(load_rewrites_from_db(&pool)));

    info!(
        "Loaded from DB: {} blocked, {} allowed, {} rewrites",
        blocklist.read().exact.len() + blocklist.read().wildcards.len(),
        allowlist.read().exact.len() + allowlist.read().wildcards.len(),
        rewrites.read().rules.len(),
    );

    // Build upstreams from DB
    let db_upstreams = db::get_upstreams(&pool);
    let upstreams: Vec<UpstreamConfig> = db_upstreams
        .iter()
        .map(|u| UpstreamConfig {
            address: u.address.clone(),
            port: Some(u.port as u16),
        })
        .collect();

    let forwarder = Arc::new(
        ParallelForwarder::new(&upstreams, upstream_timeout)
            .context("Failed to create upstream forwarder")?,
    );

    let sinkhole_ipv4: std::net::Ipv4Addr = sinkhole_ipv4_str.parse()
        .context("Invalid sinkhole_ipv4 from DB")?;
    let sinkhole_ipv6: std::net::Ipv6Addr = sinkhole_ipv6_str.parse()
        .context("Invalid sinkhole_ipv6 from DB")?;

    // Create DNS handler with shared stores
    let handler = DnsBlockerHandler::new(
        blocklist.clone(),
        allowlist.clone(),
        rewrites.clone(),
        forwarder.clone(),
        sinkhole_ipv4,
        sinkhole_ipv6,
    );

    let mut server = hickory_server::server::Server::new(handler);

    // Bind DNS sockets
    let udp_socket = UdpSocket::bind(listen_addr)
        .await
        .with_context(|| format!("Failed to bind UDP socket on {}", listen_addr))?;
    info!("DNS listening on UDP {}", listen_addr);
    server.register_socket(udp_socket);

    let tcp_listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("Failed to bind TCP listener on {}", listen_addr))?;
    info!("DNS listening on TCP {}", listen_addr);
    server.register_listener(tcp_listener, Duration::from_secs(5), 1024);

    // Configure web server on listen_port + 1
    let web_port = listen_port + 1;
    let web_addr = format!("{}:{}", listen_address, web_port);

    let pool_data = actix_web::web::Data::new(pool.clone());
    let blocklist_data = actix_web::web::Data::new(blocklist.clone());
    let allowlist_data = actix_web::web::Data::new(allowlist.clone());
    let rewrites_data = actix_web::web::Data::new(rewrites.clone());

    let web_server = actix_web::HttpServer::new(move || {
        actix_web::App::new()
            .app_data(pool_data.clone())
            .app_data(blocklist_data.clone())
            .app_data(allowlist_data.clone())
            .app_data(rewrites_data.clone())
            .configure(api::configure)
            .service(actix_files::Files::new("/", "static").index_file("index.html"))
    })
    .bind(&web_addr)
    .with_context(|| format!("Failed to bind web server on {}", web_addr))?;

    let web_handle = web_server.run();
    info!("Web UI listening on http://{}", web_addr);

    info!(
        "RustBlocker ready — {} upstream(s), DNS port {}, web port {}",
        upstreams.len(),
        listen_port,
        web_port,
    );

    // Run both servers concurrently, shutdown on Ctrl+C
    tokio::select! {
        result = web_handle => {
            if let Err(e) = result {
                warn!("Web server error: {}", e);
            }
        }
        result = server.block_until_done() => {
            if let Err(e) = result {
                warn!("DNS server error: {}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Shutting down...");
        }
    }

    Ok(())
}
