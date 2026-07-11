use actix_web::{HttpRequest, HttpResponse, Responder, web};
use std::sync::Arc;

use parking_lot::RwLock;
use serde::Deserialize;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use tracing::warn;

use crate::acl::SharedAcl;
use crate::activity::ActivityLog;
use crate::auth::{AuthState, SESSION_COOKIE_NAME, SESSION_MAX_AGE_SECS, encode_secret};
use crate::config::UpstreamConfig;
use crate::db::{self, DbPool};
use crate::forwarder::ParallelForwarder;
use crate::lists::{AllowlistStore, BlocklistStore, DomainStore};
use crate::stats::QueryLog;
use crate::sync::SharedSyncState;
use crate::update;

#[derive(Debug, Deserialize)]
struct SettingUpdate {
    key: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct DomainAdd {
    domain: String,
}

#[derive(Debug, Deserialize)]
struct BulkImport {
    content: Option<String>,
    url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpstreamAdd {
    address: String,
    port: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct RewriteAdd {
    domain: String,
    ipv4: Option<String>,
    ipv6: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DomainQuery {
    search: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct StatsQuery {
    limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct QueryLogQuery {
    limit: Option<i64>,
    offset: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct LoginPayload {
    password: String,
}

#[derive(Debug, Deserialize)]
struct ChangePasswordPayload {
    current_password: String,
    new_password: String,
}

/// ACL check helper — logs rejection and returns false if not allowed.
fn check_acl(req: &HttpRequest, acl: &SharedAcl) -> bool {
    if let Some(addr) = req.peer_addr() {
        let acl_guard = acl.read();
        if !acl_guard.is_allowed(addr.ip()) {
            warn!("Web ACL rejected: {}", addr.ip());
            return false;
        }
    }
    true
}

/// Schedule a process restart after a short delay.
/// Used by settings changes and in-place updates; relies on the service
/// supervisor (OpenRC/systemd) to respawn the binary.
fn schedule_restart(reason: &str, delay: Duration) {
    let reason = reason.to_string();
    tokio::spawn(async move {
        tokio::time::sleep(delay).await;
        tracing::info!("Restarting RustBlocker: {}", reason);
        std::process::exit(0);
    });
}

/// Resolve import content from either inline content or a URL.
async fn resolve_import_content(body: &BulkImport) -> String {
    if let Some(url) = &body.url {
        db::fetch_source(url).await
    } else if let Some(content) = &body.content {
        content.clone()
    } else {
        String::new()
    }
}

/// Insert a domain into the correct set (exact or wildcard) of a DomainStore.
fn insert_domain(store: &mut DomainStore, domain: &str) {
    store.insert(domain);
}

/// Remove a domain from both sets of a DomainStore.
fn remove_domain(store: &mut DomainStore, domain: &str) {
    store.remove(domain);
}

// --- Settings ---

async fn get_settings(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    acl: web::Data<SharedAcl>,
) -> impl Responder {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }
    let settings = db::get_settings(&pool);
    HttpResponse::Ok().json(settings)
}

// --- ACME endpoints ---

#[derive(Debug, Deserialize)]
struct CertificateRequest {
    domain: String,
    wildcard: Option<bool>,
}

async fn request_certificate(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    acl: web::Data<SharedAcl>,
    activity_log: web::Data<ActivityLog>,
    body: web::Json<CertificateRequest>,
) -> HttpResponse {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }
    // Get Cloudflare API token from settings
    let api_token = match db::get_setting(&pool, "cloudflare_api_token") {
        Some(token) if !token.is_empty() => token,
        _ => {
            activity_log.error(
                "cert",
                "Request Certificate",
                "Cloudflare API token not configured",
            );
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Cloudflare API token not configured"
            }));
        }
    };

    // Get ACME email from settings
    let acme_email = match db::get_setting(&pool, "acme_email") {
        Some(email) if !email.is_empty() => email,
        _ => {
            activity_log.error("cert", "Request Certificate", "ACME email not configured");
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "ACME email not configured"
            }));
        }
    };

    // Get directory URL (default to production)
    let directory_url = db::get_setting(&pool, "acme_directory_url")
        .unwrap_or_else(|| "https://acme-v02.api.letsencrypt.org/directory".to_string());

    let domain = body.domain.clone();
    let domain_for_response = domain.clone();
    let wildcard = body.wildcard.unwrap_or(false);
    let op_id = format!(
        "cert-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    );

    activity_log.info(
        &op_id,
        "Request Certificate",
        &format!("Request started for: {}", domain),
    );

    let log_clone = activity_log.into_inner();
    let op_id_for_spawn = op_id.clone();
    let pool_clone = pool.clone();

    tokio::spawn(async move {
        let log_ref: &ActivityLog = &log_clone;
        match request_certificate_impl(
            &pool_clone,
            &domain,
            wildcard,
            &api_token,
            &acme_email,
            &directory_url,
            Some(log_ref),
            &op_id_for_spawn,
        )
        .await
        {
            Ok(_) => {
                log_clone.success(
                    &op_id_for_spawn,
                    "Request Certificate",
                    "Certificate stored successfully!",
                );
            }
            Err(e) => {
                log_clone.error(
                    &op_id_for_spawn,
                    "Request Certificate",
                    &format!("Failed: {}", e),
                );
            }
        }
    });

    HttpResponse::Accepted().json(serde_json::json!({
        "message": "Certificate request started",
        "domain": domain_for_response,
        "op_id": op_id
    }))
}

async fn renew_certificate(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    acl: web::Data<SharedAcl>,
    activity_log: web::Data<ActivityLog>,
    body: web::Json<CertificateRequest>,
) -> HttpResponse {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }

    let api_token = match db::get_setting(&pool, "cloudflare_api_token") {
        Some(token) if !token.is_empty() => token,
        _ => {
            activity_log.error(
                "renew",
                "Force Renewal",
                "Cloudflare API token not configured",
            );
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Cloudflare API token not configured"
            }));
        }
    };

    let acme_email = match db::get_setting(&pool, "acme_email") {
        Some(email) if !email.is_empty() => email,
        _ => {
            activity_log.error("renew", "Force Renewal", "ACME email not configured");
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "ACME email not configured"
            }));
        }
    };

    let directory_url = db::get_setting(&pool, "acme_directory_url")
        .unwrap_or_else(|| "https://acme-v02.api.letsencrypt.org/directory".to_string());

    let domain = body.domain.clone();
    let domain_for_response = domain.clone();
    let wildcard = body.wildcard.unwrap_or(false);
    let op_id = format!(
        "renew-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    );

    activity_log.info(
        &op_id,
        "Force Renewal",
        &format!("Renewal started for: {}", domain),
    );

    let log_clone = activity_log.into_inner();
    let op_id_for_spawn = op_id.clone();
    let pool_clone = pool.clone();

    tokio::spawn(async move {
        let log_ref: &ActivityLog = &log_clone;
        match request_certificate_impl(
            &pool_clone,
            &domain,
            wildcard,
            &api_token,
            &acme_email,
            &directory_url,
            Some(log_ref),
            &op_id_for_spawn,
        )
        .await
        {
            Ok(_) => {
                log_clone.success(
                    &op_id_for_spawn,
                    "Force Renewal",
                    "Certificate renewed successfully!",
                );
            }
            Err(e) => {
                log_clone.error(&op_id_for_spawn, "Force Renewal", &format!("Failed: {}", e));
            }
        }
    });

    HttpResponse::Accepted().json(serde_json::json!({
        "message": "Certificate renewal started",
        "domain": domain_for_response,
        "op_id": op_id
    }))
}

/// Background task to request certificate via ACME.
#[allow(clippy::too_many_arguments)]
async fn request_certificate_impl(
    pool: &DbPool,
    domain: &str,
    wildcard: bool,
    api_token: &str,
    acme_email: &str,
    directory_url: &str,
    log: Option<&ActivityLog>,
    op_id: &str,
) -> anyhow::Result<()> {
    use crate::acme::AcmeManager;
    use crate::cloudflare::CloudflareClient;
    use std::sync::Arc;

    let cloudflare = Arc::new(CloudflareClient::new(api_token.to_string())?);

    let acme = AcmeManager::new(
        directory_url.to_string(),
        acme_email.to_string(),
        cloudflare,
    );

    let (private_key, certificate) = acme.order_certificate(domain, wildcard, log, op_id).await?;

    let expires_at = parse_certificate_expiry(&certificate)?;

    db::store_certificate(pool, domain, &private_key, &certificate, expires_at)
        .map_err(|e| anyhow::anyhow!("Database error: {}", e))?;

    Ok(())
}

/// Parse certificate expiry from PEM.
fn parse_certificate_expiry(cert_pem: &[u8]) -> anyhow::Result<i64> {
    use x509_parser::prelude::*;

    let pem_parsed =
        ::pem::parse(cert_pem).map_err(|e| anyhow::anyhow!("Failed to parse PEM: {}", e))?;
    let cert = X509Certificate::from_der(pem_parsed.contents())?.1;

    // Convert ASN1Time to Unix timestamp
    let not_after = cert.validity().not_after.timestamp();

    Ok(not_after)
}

async fn certificate_status(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    acl: web::Data<SharedAcl>,
) -> impl Responder {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }

    // Get domain from settings
    let domain = db::get_setting(&pool, "domain");

    match domain {
        Some(domain) => match db::get_certificate_status(&pool, &domain) {
            Some(status) => HttpResponse::Ok().json(status),
            None => HttpResponse::Ok().json(serde_json::json!({"has_certificate": false})),
        },
        None => HttpResponse::Ok().json(serde_json::json!({
            "has_certificate": false,
            "error": "No domain configured"
        })),
    }
}

// --- Activity Stream ---

async fn activity_stream(
    req: HttpRequest,
    acl: web::Data<SharedAcl>,
    activity_log: web::Data<ActivityLog>,
) -> HttpResponse {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }

    let rx = activity_log.subscribe();

    let stream = futures::stream::unfold(rx, |mut rx| async {
        match rx.recv().await {
            Ok(entry) => {
                let json = serde_json::to_string(&entry).unwrap_or_default();
                Some((
                    Ok::<_, actix_web::Error>(actix_web::web::Bytes::from(format!(
                        "data: {json}\n\n"
                    ))),
                    rx,
                ))
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                Some((Ok(actix_web::web::Bytes::from(": lagged\n\n")), rx))
            }
            Err(_) => None,
        }
    });

    HttpResponse::Ok()
        .insert_header(("Content-Type", "text/event-stream"))
        .insert_header(("Cache-Control", "no-cache"))
        .insert_header(("X-Accel-Buffering", "no"))
        .streaming(stream)
}

// --- Cloudflare Test Connection ---

#[derive(Debug, Deserialize)]
struct CloudflareTestRequest {
    api_token: String,
}

async fn test_cloudflare_connection(
    req: HttpRequest,
    acl: web::Data<SharedAcl>,
    activity_log: web::Data<ActivityLog>,
    body: web::Json<CloudflareTestRequest>,
) -> impl Responder {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }

    activity_log.info(
        "cf-test",
        "Test Connection",
        "Testing Cloudflare API token...",
    );

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            activity_log.error("cf-test", "Test Connection", &e.to_string());
            return HttpResponse::Ok()
                .json(serde_json::json!({"ok": false, "error": e.to_string()}));
        }
    };

    let result = client
        .get("https://api.cloudflare.com/client/v4/zones?per_page=1")
        .header("Authorization", format!("Bearer {}", body.api_token))
        .send()
        .await;

    match result {
        Ok(resp) if resp.status().is_success() => {
            activity_log.success(
                "cf-test",
                "Test Connection",
                "Cloudflare API token is valid!",
            );
            HttpResponse::Ok().json(serde_json::json!({"ok": true}))
        }
        Ok(resp) => {
            let status = resp.status().as_u16();
            let msg = if status == 401 || status == 403 {
                format!(
                    "Authentication failed (HTTP {}) — check token permissions",
                    status
                )
            } else {
                format!("Cloudflare API returned HTTP {}", status)
            };
            activity_log.error("cf-test", "Test Connection", &msg);
            HttpResponse::Ok().json(serde_json::json!({"ok": false, "error": msg}))
        }
        Err(e) => {
            let msg = format!("Connection failed: {}", e);
            activity_log.error("cf-test", "Test Connection", &msg);
            HttpResponse::Ok().json(serde_json::json!({"ok": false, "error": msg}))
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn update_setting(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    acl: web::Data<SharedAcl>,
    activity_log: web::Data<ActivityLog>,
    sinkhole_ipv4: web::Data<Arc<RwLock<Ipv4Addr>>>,
    sinkhole_ipv6: web::Data<Arc<RwLock<Ipv6Addr>>>,
    forwarder: web::Data<Arc<RwLock<ParallelForwarder>>>,
    query_log: web::Data<QueryLog>,
    body: web::Json<SettingUpdate>,
) -> impl Responder {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }
    // Listening socket settings can only take effect after a restart.
    if body.key == "listen_address" || body.key == "listen_port" {
        let valid = match body.key.as_str() {
            "listen_address" => body.value.parse::<std::net::IpAddr>().is_ok(),
            "listen_port" => body.value.parse::<u16>().is_ok(),
            _ => false,
        };
        if !valid {
            activity_log.warning(
                "settings",
                "Save Settings",
                &format!("Invalid {}: {}", body.key, body.value),
            );
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("invalid {}: {}", body.key, body.value)
            }));
        }
        db::set_setting(&pool, &body.key, &body.value);
        let reason = format!("{} changed to {}", body.key, body.value);
        activity_log.info(
            "settings",
            "Save Settings",
            &format!("Setting saved: {} = {}", body.key, body.value),
        );
        schedule_restart(&reason, Duration::from_secs(1));
        return HttpResponse::Ok().json(serde_json::json!({
            "ok": true,
            "restart_pending": true,
        }));
    }

    db::set_setting(&pool, &body.key, &body.value);
    activity_log.info(
        "settings",
        "Save Settings",
        &format!("Setting saved: {} = {}", body.key, body.value),
    );
    // Hot-reload the setting in memory
    match body.key.as_str() {
        "sinkhole_ipv4" => {
            if let Ok(ip) = body.value.parse::<Ipv4Addr>() {
                *sinkhole_ipv4.write() = ip;
                tracing::info!("Sinkhole IPv4 reloaded: {}", ip);
            } else {
                tracing::warn!("Invalid sinkhole IPv4: {}", body.value);
            }
        }
        "sinkhole_ipv6" => {
            if let Ok(ip) = body.value.parse::<Ipv6Addr>() {
                *sinkhole_ipv6.write() = ip;
                tracing::info!("Sinkhole IPv6 reloaded: {}", ip);
            } else {
                tracing::warn!("Invalid sinkhole IPv6: {}", body.value);
            }
        }
        "upstream_timeout_secs" => {
            if let Ok(secs) = body.value.parse::<u64>() {
                forwarder.write().set_timeout(secs);
                tracing::info!("Upstream timeout reloaded: {}s", secs);
            } else {
                tracing::warn!("Invalid upstream timeout: {}", body.value);
            }
        }
        "stats_retention_days" => {
            if let Ok(days) = body.value.parse::<u64>() {
                query_log.set_retention(days);
                tracing::info!("Stats retention reloaded: {} days", days);
            } else {
                tracing::warn!("Invalid retention days: {}", body.value);
            }
        }
        "allowed_networks" => {
            let mut acl_guard = acl.write();
            *acl_guard = crate::acl::Acl::parse(&body.value);
            tracing::info!("ACL reloaded: {}", body.value);
        }
        _ => {}
    }
    HttpResponse::Ok().json(serde_json::json!({"ok": true}))
}

// --- Upstreams ---

async fn get_upstreams(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    acl: web::Data<SharedAcl>,
) -> impl Responder {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }
    let upstreams = db::get_upstreams(&pool);
    HttpResponse::Ok().json(upstreams)
}
async fn add_upstream(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    acl: web::Data<SharedAcl>,
    forwarder: web::Data<Arc<RwLock<ParallelForwarder>>>,
    body: web::Json<UpstreamAdd>,
) -> impl Responder {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }
    let id = db::add_upstream(&pool, &body.address, body.port.unwrap_or(53));
    reload_forwarder(&pool, &forwarder);
    HttpResponse::Created().json(serde_json::json!({"id": id}))
}

async fn delete_upstream(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    acl: web::Data<SharedAcl>,
    forwarder: web::Data<Arc<RwLock<ParallelForwarder>>>,
    path: web::Path<i64>,
) -> impl Responder {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }
    let id = path.into_inner();
    let ok = db::delete_upstream(&pool, id);
    if ok {
        reload_forwarder(&pool, &forwarder);
        HttpResponse::Ok().json(serde_json::json!({"ok": true}))
    } else {
        HttpResponse::NotFound().json(serde_json::json!({"error": "not found"}))
    }
}

fn reload_forwarder(pool: &DbPool, forwarder: &Arc<RwLock<ParallelForwarder>>) {
    let db_upstreams = db::get_upstreams(pool);
    let upstreams: Vec<UpstreamConfig> = db_upstreams
        .iter()
        .map(|u| UpstreamConfig {
            address: u.address.clone(),
            port: Some(u.port as u16),
        })
        .collect();
    let timeout_secs: u64 = db::get_setting(pool, "upstream_timeout_secs")
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);
    if let Err(e) = forwarder.write().reload(&upstreams, timeout_secs) {
        warn!("Failed to reload forwarder: {}", e);
    }
}

// --- Blocklist domains ---

async fn get_blocklist(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    acl: web::Data<SharedAcl>,
    query: web::Query<DomainQuery>,
) -> impl Responder {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }
    let search = query.search.as_deref().unwrap_or("");
    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);
    let total = db::count_domains(&pool, "blocklist_domains");
    let domains = db::search_domains(&pool, "blocklist_domains", search, limit, offset);
    HttpResponse::Ok().json(serde_json::json!({
        "domains": domains,
        "total": total,
    }))
}

async fn add_blocklist_domain(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    acl: web::Data<SharedAcl>,
    blocklist: web::Data<BlocklistStore>,
    body: web::Json<DomainAdd>,
) -> impl Responder {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }
    let id = db::add_domain(&pool, "blocklist_domains", &body.domain);
    insert_domain(&mut blocklist.write(), &body.domain);
    HttpResponse::Created().json(serde_json::json!({"id": id}))
}

async fn delete_blocklist_domain(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    acl: web::Data<SharedAcl>,
    blocklist: web::Data<BlocklistStore>,
    path: web::Path<i64>,
) -> impl Responder {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }
    let id = path.into_inner();
    let domains = db::get_domains(&pool, "blocklist_domains");
    let domain = domains
        .iter()
        .find(|d| d.id == id)
        .map(|d| d.domain.clone());
    if db::delete_domain(&pool, "blocklist_domains", id) {
        if let Some(ref d) = domain {
            remove_domain(&mut blocklist.write(), d);
        }
        HttpResponse::Ok().json(serde_json::json!({"ok": true}))
    } else {
        HttpResponse::NotFound().json(serde_json::json!({"error": "not found"}))
    }
}

async fn bulk_import_blocklist(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    acl: web::Data<SharedAcl>,
    blocklist: web::Data<BlocklistStore>,
    body: web::Json<BulkImport>,
) -> impl Responder {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }
    let content = resolve_import_content(&body).await;
    if content.is_empty() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "no content or url provided"}));
    }
    let count = db::bulk_import_domains(&pool, "blocklist_domains", &content);
    reload_domain_store(&pool, "blocklist_domains", &blocklist);
    HttpResponse::Ok().json(serde_json::json!({"imported": count}))
}

// --- Allowlist domains ---

async fn get_allowlist(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    acl: web::Data<SharedAcl>,
    query: web::Query<DomainQuery>,
) -> impl Responder {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }
    let search = query.search.as_deref().unwrap_or("");
    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);
    let total = db::count_domains(&pool, "allowlist_domains");
    let domains = db::search_domains(&pool, "allowlist_domains", search, limit, offset);
    HttpResponse::Ok().json(serde_json::json!({
        "domains": domains,
        "total": total,
    }))
}

async fn add_allowlist_domain(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    acl: web::Data<SharedAcl>,
    allowlist: web::Data<AllowlistStore>,
    body: web::Json<DomainAdd>,
) -> impl Responder {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }
    let id = db::add_domain(&pool, "allowlist_domains", &body.domain);
    insert_domain(&mut allowlist.write(), &body.domain);
    HttpResponse::Created().json(serde_json::json!({"id": id}))
}

async fn delete_allowlist_domain(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    acl: web::Data<SharedAcl>,
    allowlist: web::Data<AllowlistStore>,
    path: web::Path<i64>,
) -> impl Responder {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }
    let id = path.into_inner();
    let domains = db::get_domains(&pool, "allowlist_domains");
    let domain = domains
        .iter()
        .find(|d| d.id == id)
        .map(|d| d.domain.clone());
    if db::delete_domain(&pool, "allowlist_domains", id) {
        if let Some(ref d) = domain {
            remove_domain(&mut allowlist.write(), d);
        }
        HttpResponse::Ok().json(serde_json::json!({"ok": true}))
    } else {
        HttpResponse::NotFound().json(serde_json::json!({"error": "not found"}))
    }
}

async fn bulk_import_allowlist(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    acl: web::Data<SharedAcl>,
    allowlist: web::Data<AllowlistStore>,
    body: web::Json<BulkImport>,
) -> impl Responder {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }
    let content = resolve_import_content(&body).await;
    if content.is_empty() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "no content or url provided"}));
    }
    let count = db::bulk_import_domains(&pool, "allowlist_domains", &content);
    reload_domain_store(&pool, "allowlist_domains", &allowlist);
    HttpResponse::Ok().json(serde_json::json!({"imported": count}))
}

// --- Rewrites ---

async fn get_rewrites(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    acl: web::Data<SharedAcl>,
) -> impl Responder {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }
    let rewrites = db::get_rewrites(&pool);
    HttpResponse::Ok().json(rewrites)
}

async fn add_rewrite(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    acl: web::Data<SharedAcl>,
    rewrites: web::Data<Arc<RwLock<crate::lists::RewriteMap>>>,
    body: web::Json<RewriteAdd>,
) -> impl Responder {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }
    let id = db::add_rewrite(
        &pool,
        &body.domain,
        body.ipv4.as_deref(),
        body.ipv6.as_deref(),
    );
    let domain = body.domain.to_lowercase();
    let rule = crate::config::RewriteRule {
        domain: domain.clone(),
        ipv4: body.ipv4.clone(),
        ipv6: body.ipv6.clone(),
    };
    rewrites.write().rules.insert(domain, rule);
    HttpResponse::Created().json(serde_json::json!({"id": id}))
}

async fn delete_rewrite(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    acl: web::Data<SharedAcl>,
    rewrites: web::Data<Arc<RwLock<crate::lists::RewriteMap>>>,
    path: web::Path<i64>,
) -> impl Responder {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }
    let id = path.into_inner();
    let all = db::get_rewrites(&pool);
    let domain = all.iter().find(|r| r.id == id).map(|r| r.domain.clone());
    if db::delete_rewrite(&pool, id) {
        if let Some(ref d) = domain {
            rewrites.write().rules.remove(&d.to_lowercase());
        }
        HttpResponse::Ok().json(serde_json::json!({"ok": true}))
    } else {
        HttpResponse::NotFound().json(serde_json::json!({"error": "not found"}))
    }
}

// --- Sources ---

#[derive(Debug, Deserialize)]
struct SourceAdd {
    url: String,
    list_type: Option<String>,
    update_interval_hours: Option<i64>,
}

async fn get_sources(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    acl: web::Data<SharedAcl>,
) -> impl Responder {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }
    let sources = db::get_sources(&pool);
    HttpResponse::Ok().json(sources)
}

async fn add_source(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    acl: web::Data<SharedAcl>,
    blocklist: web::Data<BlocklistStore>,
    allowlist: web::Data<AllowlistStore>,
    body: web::Json<SourceAdd>,
) -> impl Responder {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }
    let list_type = body.list_type.as_deref().unwrap_or("blocklist");
    let interval = body.update_interval_hours.unwrap_or(24);
    let id = db::add_source(&pool, &body.url, list_type, interval);

    let source = db::DbSource {
        id,
        url: body.url.clone(),
        list_type: list_type.to_string(),
        enabled: true,
        update_interval_hours: interval,
        last_updated: None,
        last_status: None,
    };
    let status = db::refresh_source(&pool, &source, Some(&blocklist), Some(&allowlist)).await;

    HttpResponse::Created().json(serde_json::json!({"id": id, "status": status}))
}

async fn delete_source(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    acl: web::Data<SharedAcl>,
    path: web::Path<i64>,
) -> impl Responder {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }
    let id = path.into_inner();
    if db::delete_source(&pool, id) {
        HttpResponse::Ok().json(serde_json::json!({"ok": true}))
    } else {
        HttpResponse::NotFound().json(serde_json::json!({"error": "not found"}))
    }
}

async fn refresh_all_sources(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    acl: web::Data<SharedAcl>,
    blocklist: web::Data<BlocklistStore>,
    allowlist: web::Data<AllowlistStore>,
) -> impl Responder {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }
    let sources = db::get_sources(&pool);
    let mut results = Vec::new();
    for source in &sources {
        if !source.enabled {
            continue;
        }
        let status = db::refresh_source(&pool, source, Some(&blocklist), Some(&allowlist)).await;
        results.push(serde_json::json!({"id": source.id, "url": source.url, "status": status}));
    }
    HttpResponse::Ok().json(serde_json::json!({"refreshed": results.len(), "results": results}))
}

// --- Stats ---

async fn get_stats(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    acl: web::Data<SharedAcl>,
    query: web::Query<StatsQuery>,
) -> impl Responder {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }
    let limit = query.limit.unwrap_or(10);
    let stats = QueryLog::get_stats(&pool, limit);
    HttpResponse::Ok().json(stats)
}

async fn get_queries(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    acl: web::Data<SharedAcl>,
    query: web::Query<QueryLogQuery>,
) -> impl Responder {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }
    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);
    let queries = QueryLog::get_queries(&pool, limit, offset);
    HttpResponse::Ok().json(queries)
}

async fn clear_stats(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    acl: web::Data<SharedAcl>,
) -> impl Responder {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }
    QueryLog::clear(&pool);
    HttpResponse::Ok().json(serde_json::json!({"status": "cleared"}))
}

async fn live_queries(
    req: HttpRequest,
    acl: web::Data<SharedAcl>,
    query_log: web::Data<QueryLog>,
) -> HttpResponse {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }

    let rx = query_log.subscribe();

    let stream = futures::stream::unfold(rx, |mut rx| async {
        match rx.recv().await {
            Ok(entry) => {
                let json = serde_json::to_string(&entry).unwrap_or_default();
                Some((
                    Ok::<_, actix_web::Error>(actix_web::web::Bytes::from(format!(
                        "data: {json}\n\n"
                    ))),
                    rx,
                ))
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                Some((Ok(actix_web::web::Bytes::from(": lagged\n\n")), rx))
            }
            Err(_) => None,
        }
    });

    HttpResponse::Ok()
        .insert_header(("Content-Type", "text/event-stream"))
        .insert_header(("Cache-Control", "no-cache"))
        .insert_header(("X-Accel-Buffering", "no"))
        .streaming(stream)
}

// --- Restart ---

async fn restart_server(
    req: HttpRequest,
    acl: web::Data<SharedAcl>,
    activity_log: web::Data<ActivityLog>,
) -> impl Responder {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }
    activity_log.info("restart", "Restart Server", "Server restart requested");
    tracing::info!("Restart requested via API, exiting in 1s...");
    schedule_restart("restart requested via API", Duration::from_secs(1));
    activity_log.warning(
        "restart",
        "Restart Server",
        "Server restarting in 1 second...",
    );
    HttpResponse::Ok().json(serde_json::json!({"status": "restarting"}))
}

// --- Auth ---

fn auth_cookie(session_value: String, max_age: i64) -> actix_web::cookie::Cookie<'static> {
    actix_web::cookie::Cookie::build(SESSION_COOKIE_NAME, session_value)
        .http_only(true)
        .same_site(actix_web::cookie::SameSite::Strict)
        .path("/")
        .max_age(actix_web::cookie::time::Duration::seconds(max_age))
        .finish()
}

async fn login(
    pool: web::Data<DbPool>,
    auth: web::Data<Arc<AuthState>>,
    body: web::Json<LoginPayload>,
) -> impl Responder {
    let hash = match db::get_password_hash(&pool) {
        Some(h) => h,
        None => {
            return HttpResponse::Unauthorized()
                .json(serde_json::json!({"error": "no admin password configured"}));
        }
    };
    if !AuthState::verify_password(&body.password, &hash) {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "invalid password"}));
    }
    let session = auth.create_session(SESSION_MAX_AGE_SECS);
    HttpResponse::Ok()
        .cookie(auth_cookie(session, SESSION_MAX_AGE_SECS as i64))
        .json(serde_json::json!({"authenticated": true}))
}

async fn logout() -> impl Responder {
    HttpResponse::Ok()
        .cookie(auth_cookie(String::new(), 0))
        .json(serde_json::json!({"authenticated": false}))
}

async fn auth_check(auth: web::Data<Arc<AuthState>>, req: HttpRequest) -> impl Responder {
    let authed = req
        .cookie(SESSION_COOKIE_NAME)
        .map(|c| auth.validate_session(c.value()))
        .unwrap_or(false);
    HttpResponse::Ok().json(serde_json::json!({"authenticated": authed}))
}

async fn change_password(
    pool: web::Data<DbPool>,
    auth: web::Data<Arc<AuthState>>,
    body: web::Json<ChangePasswordPayload>,
) -> impl Responder {
    let hash = match db::get_password_hash(&pool) {
        Some(h) => h,
        None => {
            return HttpResponse::Unauthorized()
                .json(serde_json::json!({"error": "no admin password configured"}));
        }
    };
    if !AuthState::verify_password(&body.current_password, &hash) {
        return HttpResponse::Unauthorized()
            .json(serde_json::json!({"error": "current password is incorrect"}));
    }
    if body.new_password.len() < 6 {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "new password must be at least 6 characters"}));
    }
    let new_hash = AuthState::hash_password(&body.new_password);
    db::set_password_hash(&pool, &new_hash);

    // Rotate the session signing secret so existing sessions are invalidated.
    // Issue a new session cookie for the current user so they stay logged in.
    let new_secret = auth.rotate_secret();
    db::set_setting(&pool, "session_secret", &encode_secret(&new_secret));
    let session = auth.create_session(SESSION_MAX_AGE_SECS);
    HttpResponse::Ok()
        .cookie(auth_cookie(session, SESSION_MAX_AGE_SECS as i64))
        .json(serde_json::json!({"status": "ok"}))
}

// --- Health ---

async fn health() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({"status": "ok"}))
}

// --- Update ---

/// GET /api/version — public, no ACL check.
async fn get_version() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "version": update::current_version(),
        "target": env!("TARGET_TRIPLE"),
    }))
}

/// GET /api/update/check — ACL-protected.
async fn check_update(req: HttpRequest, acl: web::Data<SharedAcl>) -> impl Responder {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }
    match update::check_for_update() {
        Ok(Some(info)) => HttpResponse::Ok().json(serde_json::json!({
            "update_available": true,
            "version": info.version,
            "notes": info.notes,
            "download_url": info.download_url,
            "current_version": info.current_version,
        })),
        Ok(None) => HttpResponse::Ok().json(serde_json::json!({
            "update_available": false,
            "current_version": update::current_version(),
        })),
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({
            "error": format!("{:#}", e),
        })),
    }
}

/// POST /api/update/apply — ACL-protected. Self-replaces binary, then exits.
async fn apply_update(req: HttpRequest, acl: web::Data<SharedAcl>) -> impl Responder {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }
    match tokio::task::spawn_blocking(update::apply_update).await {
        Ok(Ok(version)) => {
            let reason = format!("updated to {}", version);
            tracing::info!("Updated to {}, restarting in 1s...", version);
            schedule_restart(&reason, Duration::from_secs(1));
            HttpResponse::Ok().json(serde_json::json!({
                "status": "updated",
                "version": version,
                "restart_pending": true,
            }))
        }
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("{:#}", e),
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("join error: {:#}", e),
        })),
    }
}

// --- Helper: reload DomainStore from DB, routing wildcards correctly ---

fn reload_domain_store(pool: &DbPool, table: &str, store: &Arc<RwLock<DomainStore>>) {
    let domains = db::get_domains(pool, table);
    let mut s = store.write();
    s.exact.clear();
    s.wildcards.clear();
    for d in &domains {
        insert_domain(&mut s, &d.domain);
    }
}

// --- Sync config (slave-side settings stored in DB) ---

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SyncConfig {
    enabled: bool,
    master_url: String,
    password: String,
    interval_secs: u64,
}

async fn get_sync_config(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    acl: web::Data<SharedAcl>,
) -> impl Responder {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }
    // Return config but never expose the stored password — just whether it is set.
    let master_url = db::get_setting(&pool, "sync_master").unwrap_or_default();
    let enabled: bool = db::get_setting(&pool, "sync_enabled")
        .map(|v| v == "true")
        .unwrap_or(false);
    let interval_secs: u64 = db::get_setting(&pool, "sync_interval_secs")
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);
    let password_set = db::get_setting(&pool, "sync_password")
        .map(|v| !v.is_empty())
        .unwrap_or(false);
    HttpResponse::Ok().json(serde_json::json!({
        "enabled": enabled,
        "master_url": master_url,
        "password_set": password_set,
        "interval_secs": interval_secs,
    }))
}

async fn put_sync_config(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    acl: web::Data<SharedAcl>,
    body: web::Json<SyncConfig>,
) -> impl Responder {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }
    db::set_setting(
        &pool,
        "sync_enabled",
        if body.enabled { "true" } else { "false" },
    );
    db::set_setting(&pool, "sync_master", &body.master_url);
    db::set_setting(&pool, "sync_interval_secs", &body.interval_secs.to_string());
    // Only update password if a non-empty value was sent (empty = keep existing).
    if !body.password.is_empty() {
        db::set_setting(&pool, "sync_password", &body.password);
    }
    HttpResponse::Ok().json(serde_json::json!({"ok": true, "restart_required": true}))
}

// --- Sync (master-side endpoints) ---

async fn sync_manifest(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    acl: web::Data<SharedAcl>,
) -> impl Responder {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }
    let hashes = db::sync_manifest(&pool);
    HttpResponse::Ok().json(serde_json::json!({"hashes": hashes}))
}

async fn sync_snapshot(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    acl: web::Data<SharedAcl>,
    path: web::Path<String>,
) -> impl Responder {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }
    let category = path.into_inner();
    match db::sync_snapshot(&pool, &category) {
        Some(data) => HttpResponse::Ok().json(data),
        None => HttpResponse::NotFound()
            .json(serde_json::json!({"error": format!("unknown category: {}", category)})),
    }
}

async fn get_sync_status(
    req: HttpRequest,
    acl: web::Data<SharedAcl>,
    state: web::Data<SharedSyncState>,
) -> impl Responder {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }
    let s = state.lock().clone();
    HttpResponse::Ok().json(s)
}

#[derive(Debug, Deserialize)]
struct SyncVerifyPayload {
    master_url: String,
    password: Option<String>,
}

async fn verify_sync_connection(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    acl: web::Data<SharedAcl>,
    body: web::Json<SyncVerifyPayload>,
) -> impl Responder {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }

    let master_url = body.master_url.trim_end_matches('/').to_string();

    // Resolve password: use provided value or fall back to saved sync_password.
    let pw = match &body.password {
        Some(p) if !p.is_empty() => p.clone(),
        _ => match db::get_setting(&pool, "sync_password") {
            Some(saved) if !saved.is_empty() => saved,
            _ => {
                return HttpResponse::Ok()
                    .json(serde_json::json!({"ok": false, "error": "No password provided"}));
            }
        },
    };

    let client = match reqwest::Client::builder()
        .cookie_store(true)
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return HttpResponse::Ok()
                .json(serde_json::json!({"ok": false, "error": e.to_string()}));
        }
    };

    let login_url = format!("{}/api/auth/login", master_url);
    let result = client
        .post(&login_url)
        .json(&serde_json::json!({"password": pw}))
        .send()
        .await;

    match result {
        Ok(resp) if resp.status().is_success() => match resp.json::<serde_json::Value>().await {
            Ok(json) if json.get("authenticated") == Some(&serde_json::Value::Bool(true)) => {
                HttpResponse::Ok().json(serde_json::json!({"ok": true}))
            }
            Ok(_) => HttpResponse::Ok()
                .json(serde_json::json!({"ok": false, "error": "Authentication failed"})),
            Err(e) => {
                HttpResponse::Ok().json(serde_json::json!({"ok": false, "error": e.to_string()}))
            }
        },
        Ok(resp) => {
            let status = resp.status().as_u16();
            HttpResponse::Ok().json(
                serde_json::json!({"ok": false, "error": format!("HTTP {status}")}
                ),
            )
        }
        Err(e) => HttpResponse::Ok().json(serde_json::json!({"ok": false, "error": e.to_string()})),
    }
}

/// Configure all API routes.
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .route("/health", web::get().to(health))
            .route("/version", web::get().to(get_version))
            .route("/auth/check", web::get().to(auth_check))
            .route("/auth/login", web::post().to(login))
            .route("/auth/logout", web::post().to(logout))
            .route("/auth/password", web::put().to(change_password))
            .route("/update/check", web::get().to(check_update))
            .route("/update/apply", web::post().to(apply_update))
            .route("/settings", web::get().to(get_settings))
            .route("/settings", web::put().to(update_setting))
            .route("/upstreams", web::get().to(get_upstreams))
            .route("/upstreams", web::post().to(add_upstream))
            .route("/upstreams/{id}", web::delete().to(delete_upstream))
            .route("/blocklist", web::get().to(get_blocklist))
            .route("/blocklist", web::post().to(add_blocklist_domain))
            .route("/blocklist/{id}", web::delete().to(delete_blocklist_domain))
            .route("/blocklist/import", web::post().to(bulk_import_blocklist))
            .route("/allowlist", web::get().to(get_allowlist))
            .route("/allowlist", web::post().to(add_allowlist_domain))
            .route("/allowlist/{id}", web::delete().to(delete_allowlist_domain))
            .route("/allowlist/import", web::post().to(bulk_import_allowlist))
            .route("/rewrites", web::get().to(get_rewrites))
            .route("/rewrites", web::post().to(add_rewrite))
            .route("/rewrites/{id}", web::delete().to(delete_rewrite))
            .route("/sources", web::get().to(get_sources))
            .route("/sources", web::post().to(add_source))
            .route("/sources/{id}", web::delete().to(delete_source))
            .route("/sources/refresh", web::post().to(refresh_all_sources))
            .route("/stats", web::get().to(get_stats))
            .route("/stats/queries", web::get().to(get_queries))
            .route("/stats", web::delete().to(clear_stats))
            .route("/stats/live", web::get().to(live_queries))
            .route("/restart", web::post().to(restart_server))
            .route("/sync/manifest", web::get().to(sync_manifest))
            .route("/sync/snapshot/{category}", web::get().to(sync_snapshot))
            .route("/sync/config", web::get().to(get_sync_config))
            .route("/sync/config", web::put().to(put_sync_config))
            .route("/sync/status", web::get().to(get_sync_status))
            .route("/sync/verify", web::post().to(verify_sync_connection))
            .route("/acme/request", web::post().to(request_certificate))
            .route("/acme/renew", web::post().to(renew_certificate))
            .route("/acme/status", web::get().to(certificate_status))
            .route("/activity/stream", web::get().to(activity_stream))
            .route(
                "/cloudflare/test",
                web::post().to(test_cloudflare_connection),
            ),
    );
}
