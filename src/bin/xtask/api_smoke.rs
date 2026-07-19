use crate::core::{ResourceSnapshot, Runner};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub fn run(r: &mut Runner) -> Result<(), String> {
    let cfg = SmokeConfig::from_runner(r);
    let resource_base = r.resource_snapshot().ok().map(|snapshot| snapshot.rss_kb);

    query_log_prune(r, &cfg);
    allowlist_delete(r);
    allowlist_stats(r, &cfg);
    db_concurrency(r, &cfg);
    import_hot_reload(r, &cfg);
    dns_rewrite(r, &cfg);
    dns_wildcard(r, &cfg);

    check_resource_snapshot(r, "resource-after-functional", resource_base);

    dns_burst(r, &cfg);
    hot_reload_under_load(r, &cfg);
    import_memory_loop(r, &cfg, resource_base);
    cleanup_audit(r, &cfg);

    check_resource_snapshot(r, "resource-final", resource_base);

    Ok(())
}

#[derive(Clone, Debug)]
struct SmokeConfig {
    ssh_host: String,
    webui_password: String,
    timeout_secs: u64,
    run_tag: String,
    forward_probe_domain: String,
    db_concurrency_requests: u64,
    dns_burst_requests: u64,
    dns_burst_max_ms: u64,
    dns_burst_max_failures: u64,
    dns_burst_split_samples: u64,
    dns_burst_split_max_ms: u64,
    hot_reload_dns_requests: u64,
    memory_import_loops: u64,
    memory_import_domains: u64,
    memory_rss_max_kb: u64,
    memory_rss_growth_max_kb: u64,
    process_fd_max: u64,
    process_threads_max: u64,
    remote_db_path: String,
    query_log_prune_rows: u64,
    query_log_prune_wal_max_bytes: u64,
    query_log_prune_baseline_file: String,
    mock_query_log_prune_baseline: bool,
    stress_install_sqlite3: bool,
    sinkhole_ipv4: String,
    mock_build_id: String,
    git_rev: String,
}

impl SmokeConfig {
    fn from_runner(r: &mut Runner) -> Self {
        let run_tag = format!("mock-{}-{}", unix_secs(), std::process::id());
        let settings = r
            .curl_json("GET", "/api/settings", None)
            .unwrap_or(Value::Null);
        let sinkhole_ipv4 = settings
            .get("sinkhole_ipv4")
            .and_then(Value::as_str)
            .unwrap_or("0.0.0.0")
            .to_string();

        Self {
            ssh_host: r.env("SSH_HOST").unwrap_or_default(),
            webui_password: r.env("WEBUI_PASSWORD").unwrap_or_default(),
            timeout_secs: r.env_u64("TIMEOUT").unwrap_or(30),
            run_tag,
            forward_probe_domain: r
                .env("FORWARD_PROBE_DOMAIN")
                .unwrap_or_else(|| "example.com".to_string()),
            db_concurrency_requests: r.env_u64("DB_CONCURRENCY_REQUESTS").unwrap_or(16),
            dns_burst_requests: r.env_u64("DNS_BURST_REQUESTS").unwrap_or(96),
            dns_burst_max_ms: r.env_u64("DNS_BURST_MAX_MS").unwrap_or(8000),
            dns_burst_max_failures: r.env_u64("DNS_BURST_MAX_FAILURES").unwrap_or(0),
            dns_burst_split_samples: r.env_u64("DNS_BURST_SPLIT_SAMPLES").unwrap_or(24),
            dns_burst_split_max_ms: r.env_u64("DNS_BURST_SPLIT_MAX_MS").unwrap_or(2000),
            hot_reload_dns_requests: r.env_u64("HOT_RELOAD_DNS_REQUESTS").unwrap_or(60),
            memory_import_loops: r.env_u64("MEMORY_IMPORT_LOOPS").unwrap_or(3),
            memory_import_domains: r.env_u64("MEMORY_IMPORT_DOMAINS").unwrap_or(100),
            memory_rss_max_kb: r.env_u64("MEMORY_RSS_MAX_KB").unwrap_or(262_144),
            memory_rss_growth_max_kb: r.env_u64("MEMORY_RSS_GROWTH_MAX_KB").unwrap_or(131_072),
            process_fd_max: r.env_u64("PROCESS_FD_MAX").unwrap_or(1024),
            process_threads_max: r.env_u64("PROCESS_THREADS_MAX").unwrap_or(128),
            remote_db_path: r
                .env("REMOTE_DB_PATH")
                .unwrap_or_else(|| "/var/lib/rustblocker/rustblocker.db".to_string()),
            query_log_prune_rows: r.env_u64("QUERY_LOG_PRUNE_ROWS").unwrap_or(1500),
            query_log_prune_wal_max_bytes: r
                .env_u64("QUERY_LOG_PRUNE_WAL_MAX_BYTES")
                .unwrap_or(262_144),
            query_log_prune_baseline_file: r
                .env("QUERY_LOG_PRUNE_BASELINE_FILE")
                .unwrap_or_else(|| "target/mock-query-log-prune-baseline.json".to_string()),
            mock_query_log_prune_baseline: env_bool_or(r, "MOCK_QUERY_LOG_PRUNE_BASELINE", true),
            stress_install_sqlite3: env_bool_or(r, "STRESS_INSTALL_SQLITE3", true),
            sinkhole_ipv4,
            mock_build_id: r
                .env("MOCK_BUILD_ID")
                .unwrap_or_else(|| "xtask-native".to_string()),
            git_rev: git_rev().unwrap_or_else(|| "nogit".to_string()),
        }
    }
}

fn query_log_prune(r: &mut Runner, cfg: &SmokeConfig) {
    if !cfg.mock_query_log_prune_baseline {
        r.skip("query-log-prune", "disabled");
        return;
    }

    let mut status = "running".to_string();
    let mut old_rows_before = 0;

    if r.ssh_status("command -v sqlite3 >/dev/null 2>&1")
        || (cfg.stress_install_sqlite3 && stress_install_sqlite3(r))
    {
        r.ok(
            "query-log-prune",
            "sqlite3 available for retention storage probe",
        );
    } else {
        status = "failed".to_string();
        r.fail(
            "query-log-prune",
            "sqlite3 unavailable; cannot measure DB/WAL storage",
        );
    }

    let prune_prefix = format!("{}-prune", cfg.run_tag);
    let db_bytes_before = remote_file_size(r, &cfg.remote_db_path);
    let wal_bytes_before = remote_file_size(r, &format!("{}-wal", cfg.remote_db_path));
    let freelist_before = remote_sqlite_u64(r, cfg, "PRAGMA freelist_count;");

    if status == "running" {
        let sql = format!(
            "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < {}) INSERT INTO query_log (timestamp, client_ip, domain, query_type, action) SELECT datetime('now', '-60 days'), '127.0.0.1', '{}-' || i || '.example', 'A', 'blocked' FROM n;",
            cfg.query_log_prune_rows, prune_prefix
        );
        let cmd = format!(
            "sqlite3 {} {}",
            shell_quote(&cfg.remote_db_path),
            shell_quote(&sql)
        );
        if r.remote_root(&cmd).is_ok() {
            old_rows_before = remote_sqlite_u64(
                r,
                cfg,
                &format!(
                    "SELECT COUNT(*) FROM query_log WHERE domain LIKE '{}-%';",
                    prune_prefix
                ),
            );
            r.ok(
                "query-log-prune",
                format!(
                    "inserted expired rows={} db_before={}B wal_before={}B freelist_before={}",
                    old_rows_before, db_bytes_before, wal_bytes_before, freelist_before
                ),
            );
        } else {
            status = "failed".to_string();
            r.fail("query-log-prune", "failed to insert expired query_log rows");
        }
    }

    if status == "running" {
        let _ = r.dns_query(&cfg.forward_probe_domain);
        let mut old_rows_after = old_rows_before;
        for _ in 0..10 {
            thread::sleep(Duration::from_secs(1));
            old_rows_after = remote_sqlite_u64(
                r,
                cfg,
                &format!(
                    "SELECT COUNT(*) FROM query_log WHERE domain LIKE '{}-%';",
                    prune_prefix
                ),
            );
            if old_rows_after == 0 {
                break;
            }
            let _ = r.dns_query(&cfg.forward_probe_domain);
        }
        let total_rows_after = remote_sqlite_u64(r, cfg, "SELECT COUNT(*) FROM query_log;");
        let (mut db_bytes_after, mut wal_bytes_after, mut freelist_after) =
            query_log_prune_storage(r, cfg);
        if wal_bytes_after > cfg.query_log_prune_wal_max_bytes {
            for _ in 0..5 {
                thread::sleep(Duration::from_secs(1));
                (db_bytes_after, wal_bytes_after, freelist_after) = query_log_prune_storage(r, cfg);
                if wal_bytes_after <= cfg.query_log_prune_wal_max_bytes {
                    break;
                }
            }
        }
        let prune_health = r.curl_code("GET", "/api/health", None).unwrap_or(0);
        let passed = old_rows_before >= cfg.query_log_prune_rows
            && old_rows_after == 0
            && wal_bytes_after <= cfg.query_log_prune_wal_max_bytes
            && prune_health == 200;
        status = if passed { "passed" } else { "failed" }.to_string();
        write_query_log_prune_baseline(
            r,
            cfg,
            &status,
            old_rows_before,
            old_rows_after,
            total_rows_after,
            db_bytes_before,
            db_bytes_after,
            wal_bytes_before,
            wal_bytes_after,
            freelist_before,
            freelist_after,
        );
        if passed {
            r.ok(
                "query-log-prune",
                format!(
                    "pruned {} expired rows; old_after={} total_after={} db={}->{}B wal={}->{}B freelist={}->{}; wrote {}",
                    old_rows_before,
                    old_rows_after,
                    total_rows_after,
                    db_bytes_before,
                    db_bytes_after,
                    wal_bytes_before,
                    wal_bytes_after,
                    freelist_before,
                    freelist_after,
                    cfg.query_log_prune_baseline_file
                ),
            );
        } else {
            r.fail(
                "query-log-prune",
                format!(
                    "retention prune/storage gate failed old_before={} old_after={} wal_after={} max_wal={} health={}; wrote {}",
                    old_rows_before,
                    old_rows_after,
                    wal_bytes_after,
                    cfg.query_log_prune_wal_max_bytes,
                    prune_health,
                    cfg.query_log_prune_baseline_file
                ),
            );
        }
    }
}

fn allowlist_delete(r: &mut Runner) {
    let domain = format!(
        "mock-allow-delete-{}-{}.rustblocker.test",
        unix_secs(),
        std::process::id()
    );

    let added = r.curl_json("POST", "/api/allowlist", Some(json!({ "domain": domain })));
    let allowlist_id = added.as_ref().ok().and_then(json_id);
    if let Some(id) = allowlist_id {
        r.ok(
            "allowlist-delete",
            format!("added temporary allowlist entry {domain} (id={id})"),
        );
    } else {
        r.fail(
            "allowlist-delete",
            format!(
                "failed to add {} (response: {})",
                domain,
                format_result_json(&added)
            ),
        );
    }

    if let Some(id) = allowlist_id {
        let code = r
            .curl_code("DELETE", &format!("/api/allowlist/{id}"), None)
            .unwrap_or(0);
        let search = r
            .curl_json(
                "GET",
                &format!("/api/allowlist?search={}&limit=5", url_encode(&domain)),
                None,
            )
            .unwrap_or(Value::Null);
        if code == 200 && domains_empty(&search) {
            r.ok(
                "allowlist-delete",
                format!("removed temporary allowlist entry id={id}"),
            );
        } else {
            r.fail(
                "allowlist-delete",
                format!(
                    "failed to remove temporary allowlist entry id={} (HTTP {}, search: {})",
                    id, code, search
                ),
            );
        }
    } else {
        r.skip(
            "allowlist-delete",
            "delete skipped because temporary entry was not created",
        );
    }
}

fn allowlist_stats(r: &mut Runner, cfg: &SmokeConfig) {
    let domain = format!(
        "mock-allow-stats-{}-{}.example.com",
        unix_secs(),
        std::process::id()
    );

    let stats_before = r
        .curl_json("GET", "/api/stats", None)
        .unwrap_or(Value::Null);
    let allowed_before = json_u64_key(&stats_before, "allowed");
    let added = r.curl_json("POST", "/api/allowlist", Some(json!({ "domain": domain })));
    let allowlist_id = added.as_ref().ok().and_then(json_id);
    if let (Some(id), Some(before)) = (allowlist_id, allowed_before) {
        r.ok(
            "allowlist-stats",
            format!(
                "added temporary allowlist entry {} (id={}, allowed before={})",
                domain, id, before
            ),
        );
    } else {
        r.fail(
            "allowlist-stats",
            format!(
                "failed to prepare allowlist stats check (allowed before={}, response: {})",
                allowed_before
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "missing".to_string()),
                format_result_json(&added)
            ),
        );
    }

    if let (Some(id), Some(before)) = (allowlist_id, allowed_before) {
        let _ = r.dns_query(&domain);
        let mut allowed_after = None;
        let mut query_log_after = String::new();
        let mut ok = false;
        for _ in 0..8 {
            thread::sleep(Duration::from_secs(1));
            let stats_after = r
                .curl_json("GET", "/api/stats", None)
                .unwrap_or(Value::Null);
            allowed_after = json_u64_key(&stats_after, "allowed");
            query_log_after = r
                .curl_body("GET", "/api/stats/queries?limit=20", None)
                .map(|response| response.body)
                .unwrap_or_default();
            if allowed_after.is_some_and(|after| after > before)
                && query_log_after.contains(&format!("\"domain\":\"{}\"", domain))
                && query_log_after.contains("\"action\":\"allowed\"")
            {
                ok = true;
                break;
            }
        }
        if ok {
            r.ok(
                "allowlist-stats",
                format!(
                    "DNS allowlist hit persisted as allowed (allowed {}->{})",
                    before,
                    allowed_after.unwrap_or(before)
                ),
            );
        } else {
            r.fail(
                "allowlist-stats",
                format!(
                    "allowlist DNS hit was not persisted as allowed (allowed before={}, after={}, queries: {})",
                    before,
                    allowed_after
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "missing".to_string()),
                    if query_log_after.is_empty() {
                        "empty".to_string()
                    } else {
                        query_log_after
                    }
                ),
            );
        }
        let _ = r.curl_code("DELETE", &format!("/api/allowlist/{id}"), None);
    } else {
        r.skip(
            "allowlist-stats",
            "stats check skipped because temporary entry was not created",
        );
    }
    let _ = cfg;
}

fn db_concurrency(r: &mut Runner, cfg: &SmokeConfig) {
    let Ok(http) = LocalHttp::login(r, cfg) else {
        r.fail(
            "db-concurrency",
            "local curl login failed for concurrent probes",
        );
        return;
    };

    let started = Instant::now();
    let stop = Arc::new(AtomicBool::new(false));
    let health_stop = Arc::clone(&stop);
    let base_url = http.base_url.clone();
    let health_thread = thread::spawn(move || health_probe_loop(&base_url, health_stop));

    let mut children = Vec::new();
    for idx in 0..cfg.db_concurrency_requests {
        match http.spawn_snapshot(idx) {
            Ok(child) => children.push(child),
            Err(err) => {
                stop.store(true, Ordering::SeqCst);
                let _ = health_thread.join();
                r.fail(
                    "db-concurrency",
                    format!("failed to start blocklist snapshot probe: {err}"),
                );
                return;
            }
        }
    }

    let dns_host = cfg.ssh_host.clone();
    let dns_thread = thread::spawn(move || target_dns_a(&dns_host, "example.com"));
    let mut probe_overlapped = false;
    for _ in 0..20 {
        if !any_running(&mut children) {
            break;
        }
        probe_overlapped = true;
        thread::sleep(Duration::from_millis(50));
    }

    let mut snapshot_http_ok = true;
    let mut snapshot_bytes = 0_u64;
    for child in children {
        match child.wait() {
            Ok((200, bytes)) => snapshot_bytes += bytes,
            Ok((_, _)) | Err(_) => snapshot_http_ok = false,
        }
    }
    stop.store(true, Ordering::SeqCst);
    let health = health_thread.join().unwrap_or_default();
    let dns_probes = usize::from(dns_thread.join().is_ok());
    let concurrency_ok = health.failures == 0 && dns_probes == 1;

    if !snapshot_http_ok {
        r.fail(
            "db-concurrency",
            "one or more blocklist snapshots returned non-200",
        );
    } else if !probe_overlapped {
        r.skip(
            "db-concurrency",
            "blocklist snapshot completed too quickly to prove concurrent responsiveness",
        );
    } else if concurrency_ok {
        r.ok(
            "db-concurrency",
            format!(
                "health/DNS responsive during {} blocklist snapshots ({} bytes, {} health probes, {} DNS probes, max health {}ms, elapsed {}ms)",
                cfg.db_concurrency_requests,
                snapshot_bytes,
                health.probes,
                dns_probes,
                health.max_ms,
                started.elapsed().as_millis()
            ),
        );
    } else {
        r.fail(
            "db-concurrency",
            format!(
                "health/DNS degraded during {} blocklist snapshots ({} health probes, {} DNS probes, max health {}ms)",
                cfg.db_concurrency_requests, health.probes, dns_probes, health.max_ms
            ),
        );
    }
}

fn import_hot_reload(r: &mut Runner, cfg: &SmokeConfig) {
    let import_base = format!(
        "mock-import-{}-{}.rustblocker.test",
        unix_secs(),
        std::process::id()
    );
    let import_exact = format!("exact.{import_base}");
    let import_wildcard_base = format!("wild.{import_base}");
    let import_wildcard_subdomain = format!("sub.{import_wildcard_base}");

    let imported = r.curl_json(
        "POST",
        "/api/blocklist/import",
        Some(json!({
            "content": format!("0.0.0.0 {}\n*.{}\n", import_exact, import_wildcard_base),
        })),
    );
    let imported_count = imported
        .as_ref()
        .ok()
        .and_then(|value| json_u64_key(value, "imported"))
        .unwrap_or(0);
    if imported_count >= 2 {
        r.ok(
            "import-hot-reload",
            format!("imported temporary blocklist entries for {import_base}"),
        );
    } else {
        r.fail(
            "import-hot-reload",
            format!(
                "bulk import failed for {} (response: {})",
                import_base,
                format_result_json(&imported)
            ),
        );
    }

    let exact_dns = r.dns_query(&import_exact).unwrap_or_default();
    let wildcard_dns = r.dns_query(&import_wildcard_subdomain).unwrap_or_default();
    if has_line(&exact_dns, &cfg.sinkhole_ipv4) && has_line(&wildcard_dns, &cfg.sinkhole_ipv4) {
        r.ok(
            "import-hot-reload",
            format!(
                "bulk imported exact and wildcard domains resolved to sinkhole {}",
                cfg.sinkhole_ipv4
            ),
        );
    } else {
        r.fail(
            "import-hot-reload",
            format!(
                "bulk imported domains were not sinkholed (exact: {}; wildcard: {})",
                empty(&exact_dns),
                empty(&wildcard_dns)
            ),
        );
    }

    match live_query_sse_smoke(r, cfg, &import_exact) {
        Ok(sample) if sample.contains(&format!("\"domain\":\"{}\"", import_exact)) => r.ok(
            "query-log-live",
            format!("live SSE emitted query event for {import_exact}"),
        ),
        Ok(sample) => r.fail(
            "query-log-live",
            format!(
                "live SSE did not emit query event for {}; output: {}",
                import_exact,
                sample.chars().take(200).collect::<String>()
            ),
        ),
        Err(err) => r.fail(
            "query-log-live",
            format!("live SSE did not emit query event for {import_exact}; output: {err}"),
        ),
    }

    match r.cleanup_blocklist_api(&import_base, 250, 20) {
        Ok(deleted) => r.ok(
            "import-hot-reload",
            format!("removed temporary imported entries for {import_base} ({deleted} delete confirmations)"),
        ),
        Err(_) => r.fail(
            "import-hot-reload",
            format!("failed to remove temporary imported entries for {import_base}"),
        ),
    }
}

fn dns_rewrite(r: &mut Runner, cfg: &SmokeConfig) {
    let domain = format!(
        "mock-rewrite-{}-{}.rustblocker.test",
        unix_secs(),
        std::process::id()
    );
    let rewrite_ipv4 = "192.0.2.123";

    let added = r.curl_json(
        "POST",
        "/api/rewrites",
        Some(json!({ "domain": domain, "ipv4": rewrite_ipv4, "ipv6": null })),
    );
    let rewrite_id = added.as_ref().ok().and_then(json_id);
    if let Some(id) = rewrite_id {
        r.ok(
            "dns-rewrite",
            format!("added temporary rewrite {domain} -> {rewrite_ipv4} (id={id})"),
        );
    } else {
        r.fail(
            "dns-rewrite",
            format!(
                "failed to add {} (response: {})",
                domain,
                format_result_json(&added)
            ),
        );
    }

    let dns = r.dns_query(&domain).unwrap_or_default();
    if has_line(&dns, rewrite_ipv4) {
        r.ok(
            "dns-rewrite",
            format!("{domain} resolved to rewrite IP {rewrite_ipv4}"),
        );
    } else {
        r.fail(
            "dns-rewrite",
            format!(
                "{} did not resolve to {}; output: {}",
                domain,
                rewrite_ipv4,
                empty(&dns)
            ),
        );
    }

    if let Some(id) = rewrite_id {
        let code = r
            .curl_code("DELETE", &format!("/api/rewrites/{id}"), None)
            .unwrap_or(0);
        if code == 200 {
            r.ok("dns-rewrite", format!("removed temporary rewrite id={id}"));
        } else {
            r.fail(
                "dns-rewrite",
                format!("failed to remove temporary rewrite id={id} (HTTP {code})"),
            );
        }
    } else {
        r.skip(
            "dns-rewrite",
            "cleanup skipped because temporary rewrite was not created",
        );
    }
    let _ = cfg;
}

fn dns_wildcard(r: &mut Runner, cfg: &SmokeConfig) {
    let wildcard_base = format!(
        "mock-wildcard-{}-{}.rustblocker.test",
        unix_secs(),
        std::process::id()
    );
    let wildcard_entry = format!("*.{wildcard_base}");
    let wildcard_subdomain = format!("sub.{wildcard_base}");

    let added = r.curl_json(
        "POST",
        "/api/blocklist",
        Some(json!({ "domain": wildcard_entry })),
    );
    let wildcard_id = added.as_ref().ok().and_then(json_id);
    if let Some(id) = wildcard_id {
        r.ok(
            "dns-wildcard",
            format!("added temporary blocklist entry {wildcard_entry} (id={id})"),
        );
    } else {
        r.fail(
            "dns-wildcard",
            format!(
                "failed to add {wildcard_entry} (response: {})",
                format_result_json(&added)
            ),
        );
    }

    match remote_dns_a(r, &wildcard_subdomain) {
        Ok(answer) if has_line(&answer, "__NO_DNS_TOOL__") => r.fail(
            "dns-wildcard",
            "remote host has no dig/drill/nslookup for DNS smoke test",
        ),
        Ok(answer) if has_line(&answer, &cfg.sinkhole_ipv4) => r.ok(
            "dns-wildcard",
            format!(
                "{} resolved to sinkhole {}",
                wildcard_subdomain, cfg.sinkhole_ipv4
            ),
        ),
        Ok(answer) => r.fail(
            "dns-wildcard",
            format!(
                "{} did not resolve to {}; output: {}",
                wildcard_subdomain,
                cfg.sinkhole_ipv4,
                empty(&answer)
            ),
        ),
        Err(_) => r.fail(
            "dns-wildcard",
            format!("DNS query failed for {wildcard_subdomain}"),
        ),
    }

    match remote_dns_a(r, &wildcard_base) {
        Ok(answer) if has_line(&answer, &cfg.sinkhole_ipv4) => r.fail(
            "dns-wildcard",
            format!(
                "bare wildcard base {} incorrectly resolved to sinkhole {}",
                wildcard_base, cfg.sinkhole_ipv4
            ),
        ),
        Ok(_) => r.ok(
            "dns-wildcard",
            format!("bare wildcard base {wildcard_base} was not sinkholed"),
        ),
        Err(_) => r.ok(
            "dns-wildcard",
            format!(
                "bare wildcard base {wildcard_base} was not sinkholed (query returned no A answer)"
            ),
        ),
    }

    if let Some(id) = wildcard_id {
        let code = r
            .curl_code("DELETE", &format!("/api/blocklist/{id}"), None)
            .unwrap_or(0);
        if code == 200 {
            r.ok(
                "dns-wildcard",
                format!("removed temporary blocklist entry id={id}"),
            );
        } else {
            r.fail(
                "dns-wildcard",
                format!("failed to remove temporary blocklist entry id={id} (HTTP {code})"),
            );
        }
    } else {
        r.skip(
            "dns-wildcard",
            "cleanup skipped because temporary entry was not created",
        );
    }
}

fn dns_burst(r: &mut Runner, cfg: &SmokeConfig) {
    let base = format!("{}-burst.rustblocker.test", cfg.run_tag);
    let exact = format!("exact.{base}");
    let wildcard_base = format!("wild.{base}");
    let wildcard_entry = format!("*.{wildcard_base}");
    let wildcard_subdomain = format!("sub.{wildcard_base}");
    let rewrite = format!("rewrite.{base}");
    let rewrite_ipv4 = "192.0.2.124";

    let exact_id = r
        .curl_json("POST", "/api/blocklist", Some(json!({ "domain": exact })))
        .ok()
        .and_then(|v| json_id(&v));
    let wildcard_id = r
        .curl_json(
            "POST",
            "/api/blocklist",
            Some(json!({ "domain": wildcard_entry })),
        )
        .ok()
        .and_then(|v| json_id(&v));
    let rewrite_id = r
        .curl_json(
            "POST",
            "/api/rewrites",
            Some(json!({ "domain": rewrite, "ipv4": rewrite_ipv4, "ipv6": null })),
        )
        .ok()
        .and_then(|v| json_id(&v));

    if exact_id.is_some() && wildcard_id.is_some() && rewrite_id.is_some() {
        r.ok(
            "dns-burst-setup",
            format!("created exact, wildcard, and rewrite entries for {base}"),
        );
    } else {
        r.fail(
            "dns-burst-setup",
            format!(
                "failed to prepare DNS burst entries (exact id={}; wildcard id={}; rewrite id={})",
                opt_id(exact_id),
                opt_id(wildcard_id),
                opt_id(rewrite_id)
            ),
        );
    }

    if exact_id.is_some() && wildcard_id.is_some() && rewrite_id.is_some() {
        let mut exact_ready = String::new();
        let mut wildcard_ready = String::new();
        let mut rewrite_ready = String::new();
        let mut ready = false;
        for _ in 0..10 {
            exact_ready = r.dns_query(&exact).unwrap_or_default();
            wildcard_ready = r.dns_query(&wildcard_subdomain).unwrap_or_default();
            rewrite_ready = r.dns_query(&rewrite).unwrap_or_default();
            if has_line(&exact_ready, &cfg.sinkhole_ipv4)
                && has_line(&wildcard_ready, &cfg.sinkhole_ipv4)
                && has_line(&rewrite_ready, rewrite_ipv4)
            {
                ready = true;
                break;
            }
            thread::sleep(Duration::from_millis(200));
        }

        if !ready {
            r.fail(
                "dns-burst",
                format!(
                    "burst entries were not visible before concurrent test (exact={}, wildcard={}, rewrite={})",
                    empty(&exact_ready),
                    empty(&wildcard_ready),
                    empty(&rewrite_ready)
                ),
            );
        } else {
            measure_dns_path_latency(r, cfg, "exact", &exact, &cfg.sinkhole_ipv4);

            measure_dns_path_latency(r, cfg, "wildcard", &wildcard_subdomain, &cfg.sinkhole_ipv4);

            measure_dns_path_latency(r, cfg, "rewrite", &rewrite, rewrite_ipv4);

            let started = Instant::now();
            let failures = Arc::new(std::sync::Mutex::new(Vec::new()));
            thread::scope(|scope| {
                for i in 1..=cfg.dns_burst_requests {
                    let (domain, expect) = match i % 3 {
                        0 => (exact.clone(), cfg.sinkhole_ipv4.clone()),
                        1 => (wildcard_subdomain.clone(), cfg.sinkhole_ipv4.clone()),
                        _ => (rewrite.clone(), rewrite_ipv4.to_string()),
                    };
                    let host = cfg.ssh_host.clone();
                    let failures = Arc::clone(&failures);
                    scope.spawn(move || {
                        let answer = target_dns_a_retry(&host, &domain, &expect);
                        if !has_line(&answer, &expect) {
                            let mut guard = failures.lock().expect("dns burst failures lock");
                            guard.push(format!(
                                "{} expected={} got={}",
                                domain,
                                expect,
                                empty(&answer)
                            ));
                        }
                    });
                }
            });
            let elapsed_ms = started.elapsed().as_millis() as u64;
            let failures = failures.lock().expect("dns burst failures lock");
            if failures.len() as u64 <= cfg.dns_burst_max_failures
                && elapsed_ms <= cfg.dns_burst_max_ms
            {
                r.ok(
                    "dns-burst",
                    format!(
                        "{} hot-path queries completed in {}ms with {} failures",
                        cfg.dns_burst_requests,
                        elapsed_ms,
                        failures.len()
                    ),
                );
            } else {
                r.fail(
                    "dns-burst",
                    format!(
                        "{} hot-path queries had {} failures in {}ms (max failures {}, max {}ms, sample: {})",
                        cfg.dns_burst_requests,
                        failures.len(),
                        elapsed_ms,
                        cfg.dns_burst_max_failures,
                        cfg.dns_burst_max_ms,
                        failures.first().map(String::as_str).unwrap_or("none")
                    ),
                );
            }
        }
    } else {
        r.skip("dns-burst", "burst skipped because setup failed");
    }

    let mut cleanup_ok = r.cleanup_blocklist_api(&base, 250, 10).is_ok();
    if let Some(id) = rewrite_id {
        let _ = r.curl_code("DELETE", &format!("/api/rewrites/{id}"), None);
    }
    let blocklist_left = r
        .curl_json(
            "GET",
            &format!("/api/blocklist?search={}&limit=1", url_encode(&base)),
            None,
        )
        .unwrap_or(Value::Null);
    let rewrites_left = r
        .curl_body("GET", "/api/rewrites", None)
        .map(|response| response.body)
        .unwrap_or_default();
    if !domains_empty(&blocklist_left) || rewrites_left.contains(&base) {
        cleanup_ok = false;
    }
    if cleanup_ok {
        r.ok("dns-burst-cleanup", "removed DNS burst entries");
    } else {
        r.fail(
            "dns-burst-cleanup",
            "failed to remove one or more DNS burst entries",
        );
    }
}

fn hot_reload_under_load(r: &mut Runner, cfg: &SmokeConfig) {
    let domain = format!("{}-hot-reload.rustblocker.test", cfg.run_tag);
    let host = cfg.ssh_host.clone();
    let background_domain = domain.clone();
    let hot_reload_dns_requests = cfg.hot_reload_dns_requests;

    let background = thread::spawn(move || {
        let mut count = 0_u64;
        for _ in 0..hot_reload_dns_requests {
            let _ = target_dns_a(&host, &background_domain);
            count += 1;
            thread::sleep(Duration::from_millis(20));
        }
        count
    });
    thread::sleep(Duration::from_millis(200));
    let added = r.curl_json("POST", "/api/blocklist", Some(json!({ "domain": domain })));
    let id = added.as_ref().ok().and_then(json_id);
    let blocked_dns = r.dns_query(&domain).unwrap_or_default();
    if id.is_some() && has_line(&blocked_dns, &cfg.sinkhole_ipv4) {
        r.ok(
            "hot-reload-under-load",
            format!(
                "blocklist add hot-reloaded while {} DNS probes were active",
                cfg.hot_reload_dns_requests
            ),
        );
    } else {
        r.fail(
            "hot-reload-under-load",
            format!(
                "blocklist add did not hot-reload under DNS load (id={}, dns={})",
                opt_id(id),
                empty(&blocked_dns)
            ),
        );
    }

    if let Some(id) = id {
        let code = r
            .curl_code("DELETE", &format!("/api/blocklist/{id}"), None)
            .unwrap_or(0);
        let after_delete = r.dns_query(&domain).unwrap_or_default();
        let count = background.join().unwrap_or(0);
        if code == 200 && !has_line(&after_delete, &cfg.sinkhole_ipv4) {
            r.ok(
                "hot-reload-under-load",
                format!("blocklist delete hot-reloaded after {count} background DNS probes"),
            );
        } else {
            r.fail(
                "hot-reload-under-load",
                format!(
                    "blocklist delete did not hot-reload (HTTP {}, dns={})",
                    code,
                    empty(&after_delete)
                ),
            );
        }
    } else {
        let _ = background.join();
        r.skip(
            "hot-reload-under-load",
            "delete skipped because temporary entry was not created",
        );
    }
}

fn import_memory_loop(r: &mut Runner, cfg: &SmokeConfig, default_base_rss: Option<u64>) {
    let memory_base_rss = r
        .resource_snapshot()
        .ok()
        .map(|snapshot| snapshot.rss_kb)
        .or(default_base_rss);
    let mut ok = true;
    let mut imported_total = 0_u64;
    let mut cleaned_total = 0_u64;

    for loop_idx in 1..=cfg.memory_import_loops {
        let base = format!("{}-mem-{}.rustblocker.test", cfg.run_tag, loop_idx);
        let mut content = String::new();
        for i in 1..=cfg.memory_import_domains {
            content.push_str(&format!("0.0.0.0 mem-{i}.{base}\n"));
        }
        let response = r.curl_json(
            "POST",
            "/api/blocklist/import",
            Some(json!({ "content": content })),
        );
        let imported = response
            .as_ref()
            .ok()
            .and_then(|value| json_u64_key(value, "imported"))
            .unwrap_or(0);
        if imported < cfg.memory_import_domains {
            ok = false;
        }
        imported_total += imported;
        match r.cleanup_blocklist_api(&base, cfg.memory_import_domains + 25, 20) {
            Ok(deleted) => cleaned_total += deleted,
            Err(_) => {
                let left = r
                    .curl_json(
                        "GET",
                        &format!("/api/blocklist?search={base}&limit=1"),
                        None,
                    )
                    .unwrap_or(Value::Null);
                if !domains_empty(&left) {
                    ok = false;
                }
            }
        }
        thread::sleep(Duration::from_millis(100));
    }

    thread::sleep(Duration::from_secs(2));
    if ok {
        r.ok(
            "import-memory-loop",
            format!(
                "{} imports inserted {} entries; prefix cleanup verified ({} delete confirmations)",
                cfg.memory_import_loops, imported_total, cleaned_total
            ),
        );
    } else {
        r.fail(
            "import-memory-loop",
            format!(
                "repeated import cleanup incomplete (inserted {}, {} delete confirmations)",
                imported_total, cleaned_total
            ),
        );
    }

    check_resource_snapshot(r, "resource-after-import-loop", memory_base_rss);
}

fn cleanup_audit(r: &mut Runner, cfg: &SmokeConfig) {
    let mut leaks = 0;
    for endpoint in ["blocklist", "allowlist"] {
        let value = r
            .curl_json(
                "GET",
                &format!(
                    "/api/{endpoint}?search={}&limit=5",
                    url_encode(&cfg.run_tag)
                ),
                None,
            )
            .unwrap_or(Value::Null);
        if !domains_empty(&value) {
            leaks += 1;
        }
    }
    let rewrites = r
        .curl_body("GET", "/api/rewrites", None)
        .map(|response| response.body)
        .unwrap_or_default();
    if rewrites.contains(&cfg.run_tag) {
        leaks += 1;
    }
    if leaks == 0 {
        r.ok(
            "cleanup-audit",
            format!("no temporary entries remain for {}", cfg.run_tag),
        );
    } else {
        r.fail(
            "cleanup-audit",
            format!("found temporary entries remaining for {}", cfg.run_tag),
        );
    }
}

fn check_resource_snapshot(r: &mut Runner, label: &str, base_rss: Option<u64>) {
    let cfg = SmokeConfig::from_runner(r);
    match r.resource_snapshot() {
        Ok(snapshot) => emit_resource_snapshot(r, label, base_rss, &cfg, snapshot),
        Err(_) => r.fail(label, "could not read rustblocker process resources"),
    }
}

fn emit_resource_snapshot(
    r: &mut Runner,
    label: &str,
    base_rss: Option<u64>,
    cfg: &SmokeConfig,
    snapshot: ResourceSnapshot,
) {
    let growth = base_rss
        .map(|base| snapshot.rss_kb.saturating_sub(base))
        .unwrap_or(0);
    if snapshot.rss_kb > cfg.memory_rss_max_kb {
        r.fail(
            label,
            format!(
                "RSS {}KB exceeded max {}KB (pid={}, threads={}, fds={})",
                snapshot.rss_kb,
                cfg.memory_rss_max_kb,
                snapshot.pid,
                snapshot.threads,
                snapshot.fds
            ),
        );
    } else if base_rss.is_some() && growth > cfg.memory_rss_growth_max_kb {
        r.fail(
            label,
            format!(
                "RSS grew {}KB from baseline {}KB, max growth {}KB (rss={}KB)",
                growth,
                base_rss.unwrap_or(0),
                cfg.memory_rss_growth_max_kb,
                snapshot.rss_kb
            ),
        );
    } else if snapshot.fds > cfg.process_fd_max {
        r.fail(
            label,
            format!(
                "open FDs {} exceeded max {} (pid={}, rss={}KB)",
                snapshot.fds, cfg.process_fd_max, snapshot.pid, snapshot.rss_kb
            ),
        );
    } else if snapshot.threads > cfg.process_threads_max {
        r.fail(
            label,
            format!(
                "threads {} exceeded max {} (pid={}, rss={}KB)",
                snapshot.threads, cfg.process_threads_max, snapshot.pid, snapshot.rss_kb
            ),
        );
    } else {
        r.ok(
            label,
            format!(
                "pid={} rss={}KB growth={}KB threads={} fds={}",
                snapshot.pid, snapshot.rss_kb, growth, snapshot.threads, snapshot.fds
            ),
        );
    }
}

fn measure_dns_path_latency(
    r: &mut Runner,
    cfg: &SmokeConfig,
    label: &str,
    domain: &str,
    expected: &str,
) {
    let mut latencies = Vec::new();
    let mut failures = Vec::new();
    for _ in 0..cfg.dns_burst_split_samples {
        let started = Instant::now();
        let answer = target_dns_a_retry(&cfg.ssh_host, domain, expected);
        latencies.push(started.elapsed().as_millis() as u64);
        if !has_line(&answer, expected) {
            failures.push(format!(
                "{} expected={} got={}",
                domain,
                expected,
                empty(&answer)
            ));
        }
    }
    latencies.sort_unstable();
    let count = latencies.len();
    let min = latencies.first().copied().unwrap_or(0);
    let max = latencies.last().copied().unwrap_or(0);
    let avg = if count > 0 {
        latencies.iter().sum::<u64>() / count as u64
    } else {
        0
    };
    let p95 = percentile95(&latencies);
    if failures.is_empty() && p95 <= cfg.dns_burst_split_max_ms {
        r.ok(
            &format!("dns-latency-{label}"),
            format!(
                "samples={} min={}ms p95={}ms max={}ms avg={}ms failures=0",
                count, min, p95, max, avg
            ),
        );
    } else {
        r.fail(
            &format!("dns-latency-{label}"),
            format!(
                "samples={} min={}ms p95={}ms max={}ms avg={}ms failures={} sample={}",
                count,
                min,
                p95,
                max,
                avg,
                failures.len(),
                failures.first().map(String::as_str).unwrap_or("none")
            ),
        );
    }
}

fn live_query_sse_smoke(
    r: &mut Runner,
    cfg: &SmokeConfig,
    query_domain: &str,
) -> Result<String, String> {
    let http = LocalHttp::login(r, cfg)?;
    let base_url = http.base_url.clone();
    let cookie = http.cookie_path.clone();
    let domain = query_domain.to_string();
    let host = cfg.ssh_host.clone();
    let handle = thread::spawn(move || curl_live_stats(&base_url, &cookie));
    thread::sleep(Duration::from_millis(500));
    let _ = target_dns_a(&host, &domain);
    handle
        .join()
        .map_err(|_| "live SSE thread panicked".to_string())?
}

#[derive(Clone)]
struct LocalHttp {
    base_url: String,
    cookie_path: PathBuf,
    timeout_secs: u64,
}

impl LocalHttp {
    fn login(r: &Runner, cfg: &SmokeConfig) -> Result<Self, String> {
        let cookie_path = std::env::temp_dir().join(format!(
            "rb-xtask-cookie-{}-{}.txt",
            unix_millis(),
            std::process::id()
        ));
        let base_url = r.base_url().to_string();
        let body = json!({ "password": cfg.webui_password }).to_string();
        let status = Command::new("curl")
            .args([
                "-s",
                "--connect-timeout",
                "5",
                "--max-time",
                &cfg.timeout_secs.to_string(),
                "-o",
                if cfg!(windows) { "NUL" } else { "/dev/null" },
                "-w",
                "%{http_code}",
                "-c",
            ])
            .arg(&cookie_path)
            .args([
                "-X",
                "POST",
                &format!("{base_url}/api/auth/login"),
                "-H",
                "Content-Type: application/json",
                "-d",
                &body,
            ])
            .output()
            .map_err(|err| format!("start curl login: {err}"))?;
        let code = String::from_utf8_lossy(&status.stdout).trim().to_string();
        if code == "200" {
            Ok(Self {
                base_url,
                cookie_path,
                timeout_secs: cfg.timeout_secs,
            })
        } else {
            Err(format!("login HTTP {code}"))
        }
    }

    fn spawn_snapshot(&self, idx: u64) -> Result<SnapshotChild, String> {
        let out_path = std::env::temp_dir().join(format!(
            "rb-xtask-snapshot-{}-{}-{idx}.json",
            unix_millis(),
            std::process::id()
        ));
        let child = Command::new("curl")
            .args([
                "-s",
                "--connect-timeout",
                "5",
                "--max-time",
                &self.timeout_secs.to_string(),
                "-b",
            ])
            .arg(&self.cookie_path)
            .args([
                "-o",
                out_path.to_string_lossy().as_ref(),
                "-w",
                "%{http_code}",
                &format!("{}/api/sync/snapshot/blocklist", self.base_url),
            ])
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|err| format!("start snapshot curl: {err}"))?;
        Ok(SnapshotChild { child, out_path })
    }
}

impl Drop for LocalHttp {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.cookie_path);
    }
}

struct SnapshotChild {
    child: Child,
    out_path: PathBuf,
}

impl SnapshotChild {
    fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        self.child.try_wait()
    }

    fn wait(self) -> Result<(u16, u64), String> {
        let output = self
            .child
            .wait_with_output()
            .map_err(|err| format!("wait snapshot curl: {err}"))?;
        let code = String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse::<u16>()
            .unwrap_or(0);
        let bytes = fs::metadata(&self.out_path).map(|m| m.len()).unwrap_or(0);
        let _ = fs::remove_file(&self.out_path);
        Ok((code, bytes))
    }
}

#[derive(Default)]
struct HealthProbeStats {
    probes: u64,
    max_ms: u64,
    failures: u64,
}

fn health_probe_loop(base_url: &str, stop: Arc<AtomicBool>) -> HealthProbeStats {
    let mut stats = HealthProbeStats::default();
    while !stop.load(Ordering::SeqCst) {
        let started = Instant::now();
        let code = Command::new("curl")
            .args([
                "-s",
                "--connect-timeout",
                "1",
                "--max-time",
                "2",
                "-o",
                if cfg!(windows) { "NUL" } else { "/dev/null" },
                "-w",
                "%{http_code}",
                &format!("{base_url}/api/health"),
            ])
            .output()
            .ok()
            .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
            .unwrap_or_default();
        let elapsed = started.elapsed().as_millis() as u64;
        stats.probes += 1;
        stats.max_ms = stats.max_ms.max(elapsed);
        if code != "200" || elapsed > 2000 {
            stats.failures += 1;
        }
        thread::sleep(Duration::from_millis(50));
    }
    stats
}

fn any_running(children: &mut [SnapshotChild]) -> bool {
    children
        .iter_mut()
        .any(|child| child.try_wait().ok().flatten().is_none())
}

fn curl_live_stats(base_url: &str, cookie_path: &Path) -> Result<String, String> {
    Command::new("curl")
        .args(["-s", "--no-buffer", "--max-time", "6", "-b"])
        .arg(cookie_path)
        .arg(format!("{base_url}/api/stats/live"))
        .output()
        .map_err(|err| format!("start curl live SSE: {err}"))
        .map(|out| String::from_utf8_lossy(&out.stdout).to_string())
}

fn target_dns_a_retry(host: &str, domain: &str, expected: &str) -> String {
    let mut answer = String::new();
    for _ in 0..5 {
        answer = target_dns_a(host, domain);
        if has_line(&answer, expected) {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    answer
}

fn target_dns_a(host: &str, domain: &str) -> String {
    if host.is_empty() {
        return String::new();
    }
    if let Ok(out) = Command::new("dig")
        .args([
            format!("@{host}"),
            "+time=2".to_string(),
            "+tries=1".to_string(),
            "+short".to_string(),
            "A".to_string(),
            domain.to_string(),
        ])
        .output()
        && out.status.success()
    {
        return String::from_utf8_lossy(&out.stdout).to_string();
    }
    if let Ok(out) = Command::new("drill")
        .args([format!("@{host}"), domain.to_string(), "A".to_string()])
        .output()
        && out.status.success()
    {
        return parse_drill(&String::from_utf8_lossy(&out.stdout));
    }
    if let Ok(out) = Command::new("nslookup")
        .args(["-type=A", domain, host])
        .output()
        && out.status.success()
    {
        return parse_nslookup(&String::from_utf8_lossy(&out.stdout));
    }
    String::new()
}

fn remote_dns_a(r: &Runner, domain: &str) -> Result<String, String> {
    let command = format!(
        "domain={}; if command -v dig >/dev/null 2>&1; then dig @127.0.0.1 +time=2 +tries=1 +short A \"$domain\"; elif command -v drill >/dev/null 2>&1; then drill @127.0.0.1 \"$domain\" A | awk '/^[^;].*[[:space:]]A[[:space:]]/ {{ print $NF }}'; elif command -v nslookup >/dev/null 2>&1; then nslookup -type=A \"$domain\" 127.0.0.1 | awk '/^Name:/ {{ answer=1 }} answer && /^Address(es)?:/ {{ for (i=2; i<=NF; i++) if ($i ~ /^[0-9.]+$/) print $i }} answer && /^[[:space:]]+[0-9]+\\./ {{ print $1 }}'; else echo '__NO_DNS_TOOL__'; exit 3; fi",
        shell_quote(domain)
    );
    r.ssh_output(&command)
}

fn remote_file_size(r: &Runner, path: &str) -> u64 {
    let command = format!(
        "if [ -f {} ]; then wc -c < {} | tr -d '[:space:]'; else printf '0'; fi",
        shell_quote(path),
        shell_quote(path)
    );
    r.remote_root(&command)
        .ok()
        .and_then(|out| out.trim().parse().ok())
        .unwrap_or(0)
}

fn remote_sqlite_u64(r: &Runner, cfg: &SmokeConfig, sql: &str) -> u64 {
    let command = format!(
        "sqlite3 {} {}",
        shell_quote(&cfg.remote_db_path),
        shell_quote(sql)
    );
    r.remote_root(&command)
        .ok()
        .and_then(|out| out.lines().last().unwrap_or("0").trim().parse().ok())
        .unwrap_or(0)
}

fn query_log_prune_storage(r: &Runner, cfg: &SmokeConfig) -> (u64, u64, u64) {
    (
        remote_file_size(r, &cfg.remote_db_path),
        remote_file_size(r, &format!("{}-wal", cfg.remote_db_path)),
        remote_sqlite_u64(r, cfg, "PRAGMA freelist_count;"),
    )
}

#[allow(clippy::too_many_arguments)]
fn write_query_log_prune_baseline(
    r: &Runner,
    cfg: &SmokeConfig,
    status: &str,
    old_rows_before: u64,
    old_rows_after: u64,
    total_rows_after: u64,
    db_bytes_before: u64,
    db_bytes_after: u64,
    wal_bytes_before: u64,
    wal_bytes_after: u64,
    freelist_before: u64,
    freelist_after: u64,
) {
    let value = json!({
        "status": status,
        "build_id": cfg.mock_build_id,
        "git_rev": cfg.git_rev,
        "rows_inserted": cfg.query_log_prune_rows,
        "old_rows_before": old_rows_before,
        "old_rows_after": old_rows_after,
        "total_rows_after": total_rows_after,
        "db_bytes_before": db_bytes_before,
        "db_bytes_after": db_bytes_after,
        "wal_bytes_before": wal_bytes_before,
        "wal_bytes_after": wal_bytes_after,
        "freelist_before": freelist_before,
        "freelist_after": freelist_after,
        "created_at": iso_now(),
    });
    let _ = r.write_baseline_json(&cfg.query_log_prune_baseline_file, value);
}

fn stress_install_sqlite3(r: &Runner) -> bool {
    r.remote_root("if command -v sqlite3 >/dev/null 2>&1; then exit 0; elif command -v apk >/dev/null 2>&1; then apk add --no-cache sqlite; elif command -v apt-get >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y sqlite3; elif command -v dnf >/dev/null 2>&1; then dnf install -y sqlite; elif command -v yum >/dev/null 2>&1; then yum install -y sqlite; else exit 2; fi; command -v sqlite3 >/dev/null 2>&1").is_ok()
}

fn parse_drill(output: &str) -> String {
    output
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let _name = parts.next()?;
            let _ttl = parts.next()?;
            let _class = parts.next()?;
            let record_type = parts.next()?;
            let value = parts.next()?;
            (record_type == "A" && is_ipv4(value)).then(|| value.to_string())
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn parse_nslookup(output: &str) -> String {
    let mut answers = Vec::new();
    let mut seen_name = false;
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Name:") {
            seen_name = true;
        }
        if seen_name {
            if let Some(rest) = trimmed.strip_prefix("Address:") {
                for token in rest.split_whitespace() {
                    if is_ipv4(token) {
                        answers.push(token.to_string());
                    }
                }
            } else if let Some(rest) = trimmed.strip_prefix("Addresses:") {
                for token in rest.split_whitespace() {
                    if is_ipv4(token) {
                        answers.push(token.to_string());
                    }
                }
            } else if is_ipv4(trimmed) {
                answers.push(trimmed.to_string());
            }
        }
    }
    answers.join("\n")
}

fn is_ipv4(s: &str) -> bool {
    let mut count = 0;
    for part in s.split('.') {
        count += 1;
        if part.is_empty() || part.parse::<u8>().is_err() {
            return false;
        }
    }
    count == 4
}

fn domains_empty(value: &Value) -> bool {
    value
        .get("domains")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
}

fn json_id(value: &Value) -> Option<u64> {
    value.get("id").and_then(Value::as_u64).or_else(|| {
        value
            .get("domains")
            .and_then(Value::as_array)
            .and_then(|domains| domains.first())
            .and_then(|entry| entry.get("id"))
            .and_then(Value::as_u64)
    })
}
fn env_bool_or(r: &Runner, key: &str, default: bool) -> bool {
    r.env(key).map_or(default, |value| {
        matches!(
            value.as_str(),
            "true" | "TRUE" | "1" | "yes" | "YES" | "on" | "ON"
        )
    })
}

fn json_u64_key(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(|v| {
        v.as_u64()
            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
    })
}

fn format_result_json(result: &Result<Value, String>) -> String {
    match result {
        Ok(value) => value.to_string(),
        Err(err) => err.clone(),
    }
}

fn opt_id(id: Option<u64>) -> String {
    id.map(|id| id.to_string())
        .unwrap_or_else(|| "missing".to_string())
}

fn has_line(haystack: &str, needle: &str) -> bool {
    haystack.lines().any(|line| line.trim() == needle)
}

fn empty(value: &str) -> String {
    if value.trim().is_empty() {
        "empty".to_string()
    } else {
        value.trim().to_string()
    }
}

fn percentile95(sorted: &[u64]) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let mut idx = (sorted.len() * 95).div_ceil(100);
    if idx == 0 {
        idx = 1;
    }
    sorted[idx - 1]
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn url_encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn git_rev() -> Option<String> {
    Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

fn iso_now() -> String {
    let secs = unix_secs();
    format!("{}", secs)
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}
