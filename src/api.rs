use actix_web::{HttpRequest, HttpResponse, Responder, web};
use std::sync::Arc;

use parking_lot::RwLock;
use serde::Deserialize;
use tracing::warn;

use crate::acl::SharedAcl;
use crate::config::UpstreamConfig;
use crate::db::{self, DbPool};
use crate::forwarder::ParallelForwarder;
use crate::lists::DomainStore;
use crate::stats::QueryLog;

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

async fn update_setting(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    acl: web::Data<SharedAcl>,
    body: web::Json<SettingUpdate>,
) -> impl Responder {
    if !check_acl(&req, &acl) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
    }
    db::set_setting(&pool, &body.key, &body.value);
    // Hot-reload ACL when allowed_networks is changed
    if body.key == "allowed_networks" {
        let mut acl_guard = acl.write();
        *acl_guard = crate::acl::Acl::parse(&body.value);
        tracing::info!("ACL reloaded: {}", body.value);
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
    if let Err(e) = forwarder.write().reload(&upstreams) {
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
    blocklist: web::Data<Arc<RwLock<DomainStore>>>,
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
    blocklist: web::Data<Arc<RwLock<DomainStore>>>,
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
    blocklist: web::Data<Arc<RwLock<DomainStore>>>,
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
    allowlist: web::Data<Arc<RwLock<DomainStore>>>,
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
    allowlist: web::Data<Arc<RwLock<DomainStore>>>,
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
    allowlist: web::Data<Arc<RwLock<DomainStore>>>,
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
    blocklist: web::Data<Arc<RwLock<DomainStore>>>,
    allowlist: web::Data<Arc<RwLock<DomainStore>>>,
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
    blocklist: web::Data<Arc<RwLock<DomainStore>>>,
    allowlist: web::Data<Arc<RwLock<DomainStore>>>,
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

// --- Health ---

async fn health() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({"status": "ok"}))
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

/// Configure all API routes.
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .route("/health", web::get().to(health))
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
            .route("/stats/live", web::get().to(live_queries)),
    );
}
