use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
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
use rustblocker::forwarder::{ForwardStrategy, ParallelForwarder};
use rustblocker::handler::DnsBlockerHandler;
use rustblocker::lists::{AllowlistStore, BlocklistStore, DomainStore, RewriteMap};
use rustblocker::stats::QueryLog;
use rustblocker::sync;

#[derive(Parser)]
#[command(name = "rustblocker", about = "A DNS blocker written in Rust", version)]
struct Cli {
    /// DNS listen port (overrides database setting)
    #[arg(long)]
    dns_port: Option<u16>,

    /// Web UI listen port (overrides database setting, defaults to dns_port + 1)
    #[arg(long)]
    web_port: Option<u16>,

    /// Enable HTTPS (kept for compatibility; HTTPS is attempted by default when a valid certificate exists)
    #[arg(long)]
    https: bool,

    /// HTTPS listen port (default: 443)
    #[arg(long, default_value = "443")]
    https_port: u16,

    /// Force HTTP-only mode (disable HTTPS even if configured)
    #[arg(long)]
    force_http: bool,

    /// Generate/reset the admin password, save its hash, and print the password
    #[arg(long)]
    genpass: bool,

    /// Path to the SQLite database (default: rustblocker.db in current directory)
    #[arg(long, value_name = "PATH")]
    db_path: Option<PathBuf>,

    /// Sync slave mode: URL of the master RustBlocker (overrides DB setting)
    #[arg(long, value_name = "URL")]
    sync_master: Option<String>,

    /// Password to authenticate with the master (overrides DB setting)
    #[arg(long, value_name = "PASSWORD")]
    sync_password: Option<String>,

    /// Poll interval seconds (overrides DB setting, default: 30)
    #[arg(long, value_name = "SECS")]
    sync_interval: Option<u64>,
}

impl Cli {
    fn db_path(&self) -> std::path::PathBuf {
        self.db_path.clone().unwrap_or_else(|| {
            // If the service database already exists, default to it so that
            // `rustblocker --genpass` works without extra flags on a deployed box.
            let service_db = std::path::PathBuf::from("/var/lib/rustblocker/rustblocker.db");
            if service_db.exists() {
                service_db
            } else {
                std::path::PathBuf::from("rustblocker.db")
            }
        })
    }
}

fn main() -> Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let cli = Cli::parse();

    if cli.genpass {
        let db_path = cli.db_path();
        let pool = db::create_pool(&db_path).context("Failed to create SQLite database")?;
        db::seed_defaults(&pool);
        let password = rustblocker::auth::AuthState::generate_password();
        let hash = rustblocker::auth::AuthState::hash_password(&password);
        db::set_password_hash(&pool, &hash);

        // Verify the write actually landed. Silent failures (e.g. permission
        // denied on a root-owned DB) produce the same "invalid password"
        // symptom that started this investigation.
        let stored_hash = db::get_password_hash(&pool);
        if stored_hash.as_deref() != Some(hash.as_str()) {
            return Err(anyhow::anyhow!(
                "Password hash was not persisted to {}. \
                 Check file permissions or run as the service user.",
                db_path.display()
            ));
        }

        // Rotate session secret so old sessions are invalidated on the next server start.
        let session_secret = rustblocker::auth::AuthState::generate_secret();
        let encoded_secret = rustblocker::auth::encode_secret(&session_secret);
        db::set_setting(&pool, "session_secret", &encoded_secret);
        let stored_secret = db::get_setting(&pool, "session_secret");
        if stored_secret.as_deref() != Some(encoded_secret.as_str()) {
            return Err(anyhow::anyhow!(
                "Session secret was not persisted to {}. \
                 Check file permissions or run as the service user.",
                db_path.display()
            ));
        }

        println!("Generated admin password:");
        println!("{}", password);
        let abs_path = std::fs::canonicalize(&db_path)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| db_path.display().to_string());
        eprintln!("Updated database: {}", abs_path);
        if restart_service_if_running() {
            eprintln!("RustBlocker service restarted; existing web sessions are now invalidated.");
        } else {
            eprintln!(
                "Note: existing web sessions will be invalidated when the server is restarted."
            );
        }
        return Ok(());
    }

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .init();

    info!("Starting RustBlocker");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run_server(cli))
}

/// Restart the rustblocker service if it is currently managed by OpenRC or systemd.
/// Returns true if a restart command was issued and succeeded.
fn restart_service_if_running() -> bool {
    let service_active = |cmd: &str, args: &[&str]| -> bool {
        std::process::Command::new(cmd)
            .args(args)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };

    if service_active("rc-service", &["rustblocker", "status"]) {
        return std::process::Command::new("rc-service")
            .args(["rustblocker", "restart"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
    }

    if service_active("systemctl", &["is-active", "--quiet", "rustblocker"]) {
        return std::process::Command::new("systemctl")
            .args(["restart", "rustblocker"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
    }

    false
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
    let rules = rewrites
        .iter()
        .map(|r| rustblocker::config::RewriteRule {
            domain: r.domain.clone(),
            ipv4: r.ipv4.clone(),
            ipv6: r.ipv6.clone(),
        })
        .collect();
    RewriteMap::load(rules)
}

fn get_setting_string(pool: &db::DbPool, key: &str) -> String {
    let settings = db::get_settings(pool);
    settings
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

const CSP_POLICY: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'";

async fn run_server(cli: Cli) -> Result<()> {
    let pool = db::create_pool(cli.db_path()).context("Failed to create SQLite database")?;

    db::seed_defaults(&pool);

    if db::get_password_hash(&pool).is_none() {
        warn!("No admin password set. Use `rustblocker --genpass` before accessing the web UI.");
    }

    let listen_address = get_setting_string(&pool, "listen_address");
    let db_dns_port: u16 = get_setting_string(&pool, "listen_port")
        .parse()
        .unwrap_or(53);
    let upstream_timeout: u64 = get_setting_string(&pool, "upstream_timeout_secs")
        .parse()
        .unwrap_or(5);
    let forward_strategy: ForwardStrategy = get_setting_string(&pool, "forward_strategy")
        .parse()
        .unwrap_or_default();

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

    let blocklist = BlocklistStore(Arc::new(RwLock::new(load_store_from_db(
        &pool,
        "blocklist_domains",
    ))));
    let allowlist = AllowlistStore(Arc::new(RwLock::new(load_store_from_db(
        &pool,
        "allowlist_domains",
    ))));
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

    let forwarder = Arc::new(RwLock::new(
        ParallelForwarder::new_with_strategy(&upstreams, upstream_timeout, forward_strategy)
            .context("Failed to create upstream forwarder")?,
    ));

    let retention_days: u64 = get_setting_string(&pool, "stats_retention_days")
        .parse()
        .unwrap_or(30);
    let retention = Arc::new(AtomicU64::new(retention_days));
    let (query_log, _log_handle) = QueryLog::new(pool.clone(), retention);

    let sinkhole_ipv4_str = get_setting_string(&pool, "sinkhole_ipv4");
    let sinkhole_ipv6_str = get_setting_string(&pool, "sinkhole_ipv6");
    let sinkhole_ipv4_raw: std::net::Ipv4Addr = sinkhole_ipv4_str
        .parse()
        .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);
    let sinkhole_ipv6_raw: std::net::Ipv6Addr = sinkhole_ipv6_str
        .parse()
        .unwrap_or(std::net::Ipv6Addr::UNSPECIFIED);
    let sinkhole_ipv4 = Arc::new(RwLock::new(sinkhole_ipv4_raw));
    let sinkhole_ipv6 = Arc::new(RwLock::new(sinkhole_ipv6_raw));

    let handler = DnsBlockerHandler::new(
        blocklist.clone(),
        allowlist.clone(),
        rewrites.clone(),
        forwarder.clone(),
        sinkhole_ipv4.clone(),
        sinkhole_ipv6.clone(),
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

    let web_addr: SocketAddr = format!("{}:{}", listen_address, web_port).parse()?;

    let pool_data = actix_web::web::Data::new(pool.clone());
    let blocklist_data = actix_web::web::Data::new(blocklist.clone());
    let allowlist_data = actix_web::web::Data::new(allowlist.clone());
    let rewrites_data = actix_web::web::Data::new(rewrites.clone());
    let acl_data = actix_web::web::Data::new(shared_acl.clone());
    let query_log_data = actix_web::web::Data::from(query_log.clone());
    let forwarder_data = actix_web::web::Data::new(forwarder.clone());
    let sinkhole_v4_data = actix_web::web::Data::new(sinkhole_ipv4.clone());
    let sinkhole_v6_data = actix_web::web::Data::new(sinkhole_ipv6.clone());
    let sync_state: rustblocker::sync::SharedSyncState = Arc::new(parking_lot::Mutex::new(
        rustblocker::sync::SyncState::default(),
    ));
    let sync_state_data = actix_web::web::Data::new(sync_state.clone());
    let activity_log = actix_web::web::Data::new(rustblocker::activity::ActivityLog::new());
    let session_secret = db::get_setting(&pool, "session_secret")
        .and_then(|s| rustblocker::auth::decode_secret(&s).ok())
        .unwrap_or_else(|| {
            let secret = rustblocker::auth::AuthState::generate_secret();
            db::set_setting(
                &pool,
                "session_secret",
                &rustblocker::auth::encode_secret(&secret),
            );
            secret
        });
    let auth_data = Arc::new(rustblocker::auth::AuthState::from_secret(session_secret));

    // HTTPS is attempted by default. If a valid certificate is stored for the
    // configured domain, bind HTTPS on `https_port`; otherwise continue HTTP-only.
    let https_config = if !cli.force_http {
        // Get domain from settings
        let domain = db::get_setting(&pool, "domain");
        match domain {
            Some(domain) => {
                info!("Loading TLS certificate for domain: {}", domain);
                match rustblocker::tls::get_tls_config_from_db(&pool, &domain).await {
                    Ok(Some(config)) => {
                        info!("TLS certificate loaded successfully");
                        Some(config)
                    }
                    Ok(None) => {
                        warn!("No valid certificate found in database, running HTTP-only");
                        None
                    }
                    Err(e) => {
                        warn!("Failed to load TLS certificate: {}, running HTTP-only", e);
                        None
                    }
                }
            }
            None => {
                warn!("No domain configured for HTTPS, running HTTP-only");
                None
            }
        }
    } else {
        None
    };

    let web_server = actix_web::HttpServer::new({
        let auth_data = auth_data.clone();
        move || {
            actix_web::App::new()
                .wrap(
                    actix_web::middleware::DefaultHeaders::new()
                        .add(("Content-Security-Policy", CSP_POLICY))
                        .add(("X-Content-Type-Options", "nosniff"))
                        .add(("X-Frame-Options", "DENY"))
                        .add(("Referrer-Policy", "no-referrer")),
                )
                .wrap(rustblocker::auth::AuthMiddleware::new(auth_data.clone()))
                .app_data(pool_data.clone())
                .app_data(blocklist_data.clone())
                .app_data(allowlist_data.clone())
                .app_data(rewrites_data.clone())
                .app_data(acl_data.clone())
                .app_data(query_log_data.clone())
                .app_data(forwarder_data.clone())
                .app_data(sinkhole_v4_data.clone())
                .app_data(sinkhole_v6_data.clone())
                .app_data(actix_web::web::Data::new(auth_data.clone()))
                .app_data(activity_log.clone())
                .app_data(sync_state_data.clone())
                .configure(api::configure)
                .route(
                    "/",
                    actix_web::web::get().to(|| async {
                        actix_web::HttpResponse::Ok()
                            .content_type("text/html; charset=utf-8")
                            .insert_header(("Cache-Control", "no-cache"))
                            .body(
                                include_str!("../static/index.html")
                                    .replace("{VERSION}", env!("CARGO_PKG_VERSION")),
                            )
                    }),
                )
                .route(
                    "/tailwind.min.css",
                    actix_web::web::get().to(|| async {
                        actix_web::HttpResponse::Ok()
                            .content_type("text/css; charset=utf-8")
                            .insert_header(("Cache-Control", "no-cache"))
                            .body(include_str!("../static/tailwind.min.css"))
                    }),
                )
                .route(
                    "/app.js",
                    actix_web::web::get().to(|| async {
                        actix_web::HttpResponse::Ok()
                            .content_type("application/javascript; charset=utf-8")
                            .insert_header(("Cache-Control", "no-cache"))
                            .body(include_str!("../static/app.js"))
                    }),
                )
                .route(
                    "/icon.png",
                    actix_web::web::get().to(|| async {
                        actix_web::HttpResponse::Ok()
                            .content_type("image/png")
                            .insert_header(("Cache-Control", "public, max-age=86400"))
                            .body(&include_bytes!("../static/icon.png")[..])
                    }),
                )
                .route(
                    "/favicon.png",
                    actix_web::web::get().to(|| async {
                        actix_web::HttpResponse::Ok()
                            .content_type("image/png")
                            .insert_header(("Cache-Control", "public, max-age=86400"))
                            .body(&include_bytes!("../static/favicon.png")[..])
                    }),
                )
                .route(
                    "/favicon.ico",
                    actix_web::web::get().to(|| async {
                        actix_web::HttpResponse::Ok()
                            .content_type("image/x-icon")
                            .insert_header(("Cache-Control", "public, max-age=86400"))
                            .body(&include_bytes!("../static/favicon.ico")[..])
                    }),
                )
        }
    });

    // Bind HTTP
    let web_server = web_server
        .bind(&web_addr)
        .with_context(|| format!("Failed to bind web server on {}", web_addr))?;

    // Bind HTTPS if config is available
    let has_https_config = https_config.is_some();
    let web_server = if let Some(tls_config) = https_config {
        let https_addr = SocketAddr::new(web_addr.ip(), cli.https_port);
        info!("Binding HTTPS on {}", https_addr);
        web_server
            .bind_rustls_0_23(&https_addr, tls_config)
            .with_context(|| format!("Failed to bind HTTPS server on {}", https_addr))?
    } else {
        web_server
    };

    let web_handle = web_server.run();
    if !cli.force_http && has_https_config {
        info!(
            "Web UI listening on http://{} and https://{}:{}",
            web_addr,
            web_addr.ip(),
            cli.https_port
        );
    } else {
        info!("Web UI listening on http://{}", web_addr);
    }

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
            let stale = match tokio::task::spawn_blocking({
                let refresh_pool = refresh_pool.clone();
                move || db::get_stale_sources(&refresh_pool)
            })
            .await
            {
                Ok(stale) => stale,
                Err(e) => {
                    warn!("Failed to load stale sources: {}", e);
                    continue;
                }
            };
            if stale.is_empty() {
                continue;
            }
            info!("Auto-refreshing {} stale source(s)...", stale.len());
            for source in &stale {
                let status = db::refresh_source(
                    &refresh_pool,
                    source,
                    Some(&*refresh_bl),
                    Some(&*refresh_al),
                )
                .await;
                info!("Auto-refreshed {}: {}", source.url, status);
            }
        }
    });

    // Check for expiring certificates on startup
    if !cli.force_http && db::get_setting(&pool, "domain").is_some() {
        if let Err(e) = rustblocker::renewal::check_expiring_on_startup(
            &pool,
            rustblocker::renewal::AUTO_RENEWAL_THRESHOLD_DAYS,
        )
        .await
        {
            warn!("Failed to check expiring certificates: {}", e);
        }

        let renewal_pool = pool.clone();
        let _renewal_handle = rustblocker::renewal::spawn_renewal_task(
            renewal_pool,
            rustblocker::renewal::AUTO_RENEWAL_INTERVAL_HOURS,
            rustblocker::renewal::AUTO_RENEWAL_THRESHOLD_DAYS,
        );
        info!(
            "Certificate auto-renewal enabled (checks every {} hours, renews within {} days)",
            rustblocker::renewal::AUTO_RENEWAL_INTERVAL_HOURS,
            rustblocker::renewal::AUTO_RENEWAL_THRESHOLD_DAYS
        );
    }
    // Sync slave: read config from DB (CLI args override DB values).
    {
        let cli_had_sync_master = cli.sync_master.is_some();
        let master_url = cli
            .sync_master
            .or_else(|| db::get_setting(&pool, "sync_master"))
            .unwrap_or_default();
        let enabled: bool = db::get_setting(&pool, "sync_enabled")
            .map(|v| v == "true")
            .unwrap_or(false);
        let password = cli
            .sync_password
            .or_else(|| db::get_setting(&pool, "sync_password"))
            .unwrap_or_default();
        let interval_secs = cli
            .sync_interval
            .or_else(|| db::get_setting(&pool, "sync_interval_secs").and_then(|v| v.parse().ok()))
            .unwrap_or(30);

        if !master_url.is_empty() && (enabled || cli_had_sync_master) {
            if password.is_empty() {
                warn!(
                    "Sync master configured but sync_password is empty; sync will fail authentication"
                );
            }
            let sync_cfg = sync::SyncConfig {
                master_url: master_url.clone(),
                password,
                interval: Duration::from_secs(interval_secs),
            };
            sync::spawn(
                sync_cfg,
                pool.clone(),
                blocklist.clone(),
                allowlist.clone(),
                rewrites.clone(),
                forwarder.clone(),
                sync_state.clone(),
            );
            info!(
                "Sync slave started, polling master {} every {}s",
                master_url, interval_secs
            );
        }
    }

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
