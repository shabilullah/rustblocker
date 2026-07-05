use actix_web::{web, HttpResponse, Responder};
use serde::Deserialize;
use std::sync::Arc;
use parking_lot::RwLock;

use crate::db::{self, DbPool};
use crate::lists::DomainStore;

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
    content: String,
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

/// Insert a domain into the correct set (exact or wildcard) of a DomainStore.
fn insert_domain(store: &mut DomainStore, domain: &str) {
    let lower = domain.to_lowercase();
    if let Some(stripped) = lower.strip_prefix("*.") {
        store.wildcards.insert(stripped.to_string());
    } else {
        store.exact.insert(lower);
    }
}

/// Remove a domain from both sets of a DomainStore.
fn remove_domain(store: &mut DomainStore, domain: &str) {
    let lower = domain.to_lowercase();
    if let Some(stripped) = lower.strip_prefix("*.") {
        store.wildcards.remove(stripped);
    }
    store.exact.remove(&lower);
}

// --- Settings ---

async fn get_settings(pool: web::Data<DbPool>) -> impl Responder {
    let settings = db::get_settings(&pool);
    HttpResponse::Ok().json(settings)
}

async fn update_setting(
    pool: web::Data<DbPool>,
    body: web::Json<SettingUpdate>,
) -> impl Responder {
    db::set_setting(&pool, &body.key, &body.value);
    HttpResponse::Ok().json(serde_json::json!({"ok": true}))
}

// --- Upstreams ---

async fn get_upstreams(pool: web::Data<DbPool>) -> impl Responder {
    let upstreams = db::get_upstreams(&pool);
    HttpResponse::Ok().json(upstreams)
}

async fn add_upstream(
    pool: web::Data<DbPool>,
    body: web::Json<UpstreamAdd>,
) -> impl Responder {
    let id = db::add_upstream(&pool, &body.address, body.port.unwrap_or(53));
    HttpResponse::Created().json(serde_json::json!({"id": id}))
}

async fn delete_upstream(
    pool: web::Data<DbPool>,
    path: web::Path<i64>,
) -> impl Responder {
    let id = path.into_inner();
    if db::delete_upstream(&pool, id) {
        HttpResponse::Ok().json(serde_json::json!({"ok": true}))
    } else {
        HttpResponse::NotFound().json(serde_json::json!({"error": "not found"}))
    }
}

// --- Blocklist domains ---

async fn get_blocklist(pool: web::Data<DbPool>) -> impl Responder {
    let domains = db::get_domains(&pool, "blocklist_domains");
    HttpResponse::Ok().json(domains)
}

async fn add_blocklist_domain(
    pool: web::Data<DbPool>,
    blocklist: web::Data<Arc<RwLock<DomainStore>>>,
    body: web::Json<DomainAdd>,
) -> impl Responder {
    let id = db::add_domain(&pool, "blocklist_domains", &body.domain);
    insert_domain(&mut blocklist.write(), &body.domain);
    HttpResponse::Created().json(serde_json::json!({"id": id}))
}

async fn delete_blocklist_domain(
    pool: web::Data<DbPool>,
    blocklist: web::Data<Arc<RwLock<DomainStore>>>,
    path: web::Path<i64>,
) -> impl Responder {
    let id = path.into_inner();
    let domains = db::get_domains(&pool, "blocklist_domains");
    let domain = domains.iter().find(|d| d.id == id).map(|d| d.domain.clone());
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
    blocklist: web::Data<Arc<RwLock<DomainStore>>>,
    body: web::Json<BulkImport>,
) -> impl Responder {
    let count = db::bulk_import_domains(&pool, "blocklist_domains", &body.content);
    reload_domain_store(&pool, "blocklist_domains", &blocklist);
    HttpResponse::Ok().json(serde_json::json!({"imported": count}))
}

// --- Allowlist domains ---

async fn get_allowlist(pool: web::Data<DbPool>) -> impl Responder {
    let domains = db::get_domains(&pool, "allowlist_domains");
    HttpResponse::Ok().json(domains)
}

async fn add_allowlist_domain(
    pool: web::Data<DbPool>,
    allowlist: web::Data<Arc<RwLock<DomainStore>>>,
    body: web::Json<DomainAdd>,
) -> impl Responder {
    let id = db::add_domain(&pool, "allowlist_domains", &body.domain);
    insert_domain(&mut allowlist.write(), &body.domain);
    HttpResponse::Created().json(serde_json::json!({"id": id}))
}

async fn delete_allowlist_domain(
    pool: web::Data<DbPool>,
    allowlist: web::Data<Arc<RwLock<DomainStore>>>,
    path: web::Path<i64>,
) -> impl Responder {
    let id = path.into_inner();
    let domains = db::get_domains(&pool, "allowlist_domains");
    let domain = domains.iter().find(|d| d.id == id).map(|d| d.domain.clone());
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
    allowlist: web::Data<Arc<RwLock<DomainStore>>>,
    body: web::Json<BulkImport>,
) -> impl Responder {
    let count = db::bulk_import_domains(&pool, "allowlist_domains", &body.content);
    reload_domain_store(&pool, "allowlist_domains", &allowlist);
    HttpResponse::Ok().json(serde_json::json!({"imported": count}))
}

// --- Rewrites ---

async fn get_rewrites(pool: web::Data<DbPool>) -> impl Responder {
    let rewrites = db::get_rewrites(&pool);
    HttpResponse::Ok().json(rewrites)
}

async fn add_rewrite(
    pool: web::Data<DbPool>,
    rewrites: web::Data<Arc<RwLock<crate::lists::RewriteMap>>>,
    body: web::Json<RewriteAdd>,
) -> impl Responder {
    let id = db::add_rewrite(&pool, &body.domain, body.ipv4.as_deref(), body.ipv6.as_deref());
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
    rewrites: web::Data<Arc<RwLock<crate::lists::RewriteMap>>>,
    path: web::Path<i64>,
) -> impl Responder {
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
            .route("/rewrites/{id}", web::delete().to(delete_rewrite)),
    );
}
