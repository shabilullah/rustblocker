use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use parking_lot::RwLock;
use tokio::net::{TcpListener, UdpSocket};
use tracing::{info, warn};

use rustblocker::acl;
use rustblocker::api;
use rustblocker::config::UpstreamConfig;
use rustblocker::db;
use rustblocker::forwarder::ParallelForwarder;
use rustblocker::handler::DnsBlockerHandler;
use rustblocker::lists::{DomainStore, RewriteMap, normalize_domain};
use rustblocker::stats::QueryLog;

#[derive(Parser)]
#[command(name = "rustblocker", about = "A DNS blocker written in Rust")]
struct Cli {
    /// DNS listen port (overrides database setting)
    #[arg(long)]
    dns_port: Option<u16>,

    /// Web UI listen port (overrides database setting, defaults to dns_port + 1)
    #[arg(long)]
    web_port: Option<u16>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .init();

    info!("Starting RustBlocker");

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(run_server(cli))
}

fn load_store_from_db(pool: &db::DbPool, table: &str) -> DomainStore {
    let domains = db::get_domains(pool, table);
    let mut store = DomainStore::default();
    for d in &domains {
        store.insert(&d.domain);
    }
    store
}

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

fn get_setting_string(pool: &db::DbPool, key: &str) -> String {
    let settings = db::get_settings(pool);
    settings
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

const CSP_POLICY: &str = "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'";

async fn run_server(cli: Cli) -> Result<()> {
    let pool = db::create_pool("rustblocker.db").context("Failed to create SQLite database")?;

    db::seed_defaults(&pool);

    let listen_address = get_setting_string(&pool, "listen_address");
    let db_dns_port: u16 = get_setting_string(&pool, "listen_port")
        .parse()
        .unwrap_or(53);
    let upstream_timeout: u64 = get_setting_string(&pool, "upstream_timeout_secs")
        .parse()
        .unwrap_or(5);

    let dns_port = cli.dns_port.unwrap_or(db_dns_port);
    let web_port = cli.web_port.unwrap_or(dns_port + 1);

    let listen_addr: SocketAddr = format!("{}:{}", listen_address, dns_port)
        .parse()
        .context("Invalid listen address")?;

    // Load ACL from database
    let allowed_networks = get_setting_string(&pool, "allowed_networks");
    let shared_acl = acl::load_acl_from_db(&pool);
    if !allowed_networks.is_empty() {
        info!("ACL enabled: {}", allowed_networks);
    }

    let blocklist = Arc::new(RwLock::new(load_store_from_db(&pool, "blocklist_domains")));
    let allowlist = Arc::new(RwLock::new(load_store_from_db(&pool, "allowlist_domains")));
    let rewrites = Arc::new(RwLock::new(load_rewrites_from_db(&pool)));

    info!(
        "Loaded from DB: {} blocked, {} allowed, {} rewrites",
        blocklist.read().exact.len() + blocklist.read().wildcards.len(),
        allowlist.read().exact.len() + allowlist.read().wildcards.len(),
        rewrites.read().rules.len(),
    );

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

    let retention_days: u64 = get_setting_string(&pool, "stats_retention_days")
        .parse()
        .unwrap_or(30);
    let (query_log, _log_handle) = QueryLog::new(pool.clone(), retention_days);

    let sinkhole_ipv4_str = get_setting_string(&pool, "sinkhole_ipv4");
    let sinkhole_ipv6_str = get_setting_string(&pool, "sinkhole_ipv6");
    let sinkhole_ipv4: std::net::Ipv4Addr = sinkhole_ipv4_str
        .parse()
        .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);
    let sinkhole_ipv6: std::net::Ipv6Addr = sinkhole_ipv6_str
        .parse()
        .unwrap_or(std::net::Ipv6Addr::UNSPECIFIED);

    let handler = DnsBlockerHandler::new(
        blocklist.clone(),
        allowlist.clone(),
        rewrites.clone(),
        forwarder.clone(),
        sinkhole_ipv4,
        sinkhole_ipv6,
        shared_acl.clone(),
        query_log.clone(),
    );

    let mut server = hickory_server::server::Server::new(handler);

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

    let web_addr = format!("{}:{}", listen_address, web_port);

    let pool_data = actix_web::web::Data::new(pool.clone());
    let blocklist_data = actix_web::web::Data::new(blocklist.clone());
    let allowlist_data = actix_web::web::Data::new(allowlist.clone());
    let rewrites_data = actix_web::web::Data::new(rewrites.clone());
    let acl_data = actix_web::web::Data::new(shared_acl.clone());
    let query_log_data = actix_web::web::Data::from(query_log.clone());

    let web_server = actix_web::HttpServer::new(move || {
        actix_web::App::new()
            .wrap(
                actix_web::middleware::DefaultHeaders::new()
                    .add(("Content-Security-Policy", CSP_POLICY))
                    .add(("X-Content-Type-Options", "nosniff"))
                    .add(("X-Frame-Options", "DENY"))
                    .add(("Referrer-Policy", "no-referrer")),
            )
            .app_data(pool_data.clone())
            .app_data(blocklist_data.clone())
            .app_data(allowlist_data.clone())
            .app_data(rewrites_data.clone())
            .app_data(acl_data.clone())
            .app_data(query_log_data.clone())
            .configure(api::configure)
            .route(
                "/",
                actix_web::web::get().to(|| async {
                    actix_web::HttpResponse::Ok()
                        .content_type("text/html; charset=utf-8")
                        .body(include_str!("../static/index.html"))
                }),
            )
            .route(
                "/tailwind.min.css",
                actix_web::web::get().to(|| async {
                    actix_web::HttpResponse::Ok()
                        .content_type("text/css; charset=utf-8")
                        .insert_header(("Cache-Control", "public, max-age=86400"))
                        .body(include_str!("../static/tailwind.min.css"))
                }),
            )
    })
    .bind(&web_addr)
    .with_context(|| format!("Failed to bind web server on {}", web_addr))?;

    let web_handle = web_server.run();
    info!("Web UI listening on http://{}", web_addr);

    info!(
        "RustBlocker ready — {} upstream(s), DNS port {}, web port {}",
        upstreams.len(),
        dns_port,
        web_port,
    );

    // Auto-refresh stale sources every 10 minutes
    let refresh_pool = pool.clone();
    let refresh_bl = blocklist.clone();
    let refresh_al = allowlist.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(600));
        interval.tick().await;
        loop {
            interval.tick().await;
            let stale = db::get_stale_sources(&refresh_pool);
            if stale.is_empty() {
                continue;
            }
            info!("Auto-refreshing {} stale source(s)...", stale.len());
            for source in &stale {
                let status =
                    db::refresh_source(&refresh_pool, source, Some(&refresh_bl), Some(&refresh_al))
                        .await;
                info!("Auto-refreshed {}: {}", source.url, status);
            }
        }
    });

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
