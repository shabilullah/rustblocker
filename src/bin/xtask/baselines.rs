use crate::core::{CurlResponse, Runner};
use serde_json::{Value, json};
use std::fs;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const REAL_DOMAINS: &[&str] = &[
    "example.com",
    "cloudflare.com",
    "google.com",
    "github.com",
    "mozilla.org",
    "rust-lang.org",
    "wikipedia.org",
    "amazon.com",
    "microsoft.com",
    "apple.com",
];

pub fn run(r: &mut Runner) -> Result<(), String> {
    let ctx = BaselineRun::new(r)?;
    run_domainstore(r, &ctx)?;
    run_resolver_cache(r, &ctx)?;
    run_sticky(r, &ctx)?;
    run_remove_compact(r, &ctx)?;
    run_sync_apply(r, &ctx)
}

struct BaselineRun {
    git_rev: String,
    build_id: String,
    run_tag: String,
    ssh_host: String,
    web_port: u64,
    sinkhole_ipv4: String,
    binary_name: String,
    remote_install_dir: String,
    webui_password: String,
}

impl BaselineRun {
    fn new(r: &mut Runner) -> Result<Self, String> {
        Ok(Self {
            git_rev: r.env_or("GIT_REV", "nogit"),
            build_id: r.env_or("MOCK_BUILD_ID", "mock-native"),
            run_tag: r.env_or("RUN_TAG", &format!("mock-{}", unix_secs())),
            ssh_host: r.env_or("SSH_HOST", "127.0.0.1"),
            web_port: r.env_u64_or("WEB_PORT", 54),
            sinkhole_ipv4: sinkhole_ipv4(r)?,
            binary_name: r.env_or("BINARY_NAME", "rustblocker"),
            remote_install_dir: r.env_or("REMOTE_INSTALL_DIR", "/usr/local/lib/rustblocker"),
            webui_password: r.env_or("WEBUI_PASSWORD", ""),
        })
    }
}

fn run_domainstore(r: &mut Runner, ctx: &BaselineRun) -> Result<(), String> {
    if !env_bool_or(r, "MOCK_DOMAINSTORE_BASELINE", true) {
        r.skip(
            "domainstore-baseline",
            "disabled; set MOCK_DOMAINSTORE_BASELINE=true to measure DomainStore RSS",
        );
        return Ok(());
    }

    let base = format!("{}-domainstore-baseline.rustblocker.test", ctx.run_tag);
    let domains = r.env_u64_or("DOMAINSTORE_BASELINE_DOMAINS", 10_000);
    let batch = r.env_u64_or("DOMAINSTORE_BASELINE_BATCH", 1_000).max(1);
    let file = r.env_or(
        "DOMAINSTORE_BASELINE_FILE",
        "target/mock-domainstore-memory-baseline.json",
    );
    let bytes_per_domain_max = r.env_u64_or("DOMAINSTORE_BASELINE_BYTES_PER_DOMAIN_MAX", 0);
    let rss_growth_max_kb = r.env_u64_or("DOMAINSTORE_BASELINE_RSS_GROWTH_MAX_KB", 0);
    let dns_samples = r.env_u64_or("DOMAINSTORE_BASELINE_DNS_SAMPLES", 24);
    let dns_max_failures = r.env_u64_or("DOMAINSTORE_BASELINE_DNS_MAX_FAILURES", 0);
    let settle_secs = r.env_u64_or("DOMAINSTORE_BASELINE_SETTLE_SECS", 2);
    let api_cleanup_max = r.env_u64_or("STRESS_API_CLEANUP_MAX_DOMAINS", 10_000);

    let mut status = "running".to_string();
    let note = "post-fix packed-arena DomainStore";
    let mut cleanup_method = "unknown".to_string();
    let mut imported = 0_u64;
    let mut rss_before = 0_u64;
    let mut rss_after = 0_u64;
    let mut rss_growth = 0_u64;
    let mut bytes_per_domain = 0_u64;
    let mut dns_stats = DnsStats::default();

    if has_sqlite(r) {
        cleanup_method = "sqlite".to_string();
        r.ok(
            "domainstore-baseline-prereq",
            format!("cleanup method={cleanup_method} domains={domains}"),
        );
    } else if domains <= api_cleanup_max {
        cleanup_method = "api".to_string();
        r.ok(
            "domainstore-baseline-prereq",
            format!("cleanup method={cleanup_method} domains={domains}"),
        );
    } else {
        status = "cleanup_unavailable".to_string();
        r.fail(
            "domainstore-baseline-prereq",
            format!(
                "no safe cleanup method: install sqlite3 on target or keep DOMAINSTORE_BASELINE_DOMAINS <= STRESS_API_CLEANUP_MAX_DOMAINS ({api_cleanup_max})"
            ),
        );
    }

    if status == "running" {
        match r.resource_snapshot() {
            Ok(snapshot) => {
                rss_before = snapshot.rss_kb;
                r.ok(
                    "domainstore-baseline-before",
                    format!("rss={rss_before}KB base={base}"),
                );
            }
            Err(_) => {
                status = "resource_failed".to_string();
                r.fail(
                    "domainstore-baseline-before",
                    "could not read process resources before import",
                );
            }
        }
    } else {
        r.skip(
            "domainstore-baseline-before",
            "skipped because prerequisite failed",
        );
    }

    if status == "running" {
        let started = Instant::now();
        let mut ok = true;
        let mut error = "none".to_string();
        while imported < domains {
            let count = batch.min(domains - imported);
            match import_blocklist_batch(r, &base, imported + 1, count, "stress") {
                Ok(n) if n >= count => imported += n,
                Ok(n) => {
                    imported += n;
                    ok = false;
                    error = format!("short import {n}/{count}");
                    break;
                }
                Err(err) => {
                    ok = false;
                    error = err;
                    break;
                }
            }
        }
        let elapsed_ms = started.elapsed().as_millis();
        if ok && blocklist_total(r, &base)? >= domains {
            r.ok(
                "domainstore-baseline-import",
                format!("imported {imported} domains in {elapsed_ms}ms"),
            );
        } else {
            status = "import_failed".to_string();
            r.fail(
                "domainstore-baseline-import",
                format!(
                    "import incomplete after {elapsed_ms}ms (imported={imported}/{domains}, error={error})"
                ),
            );
        }
    } else {
        r.skip(
            "domainstore-baseline-import",
            "skipped because prerequisite failed",
        );
    }

    if status == "running" {
        sleep_secs(settle_secs);
        dns_stats = measure_stress_dns_latency(r, &base, domains, dns_samples, &ctx.sinkhole_ipv4);
        match r.resource_snapshot() {
            Ok(snapshot) => {
                rss_after = snapshot.rss_kb;
                rss_growth = rss_after.saturating_sub(rss_before);
                bytes_per_domain = rss_growth
                    .saturating_mul(1024)
                    .checked_div(imported)
                    .unwrap_or(0);
                if dns_stats.failures > dns_max_failures {
                    status = "dns_failed".to_string();
                    r.fail(
                        "domainstore-baseline-after",
                        format!(
                            "dns failures={} p95={}ms (sample={})",
                            dns_stats.failures,
                            dns_stats.p95_ms,
                            dns_stats.failure_sample.as_deref().unwrap_or("none")
                        ),
                    );
                } else if rss_growth_max_kb > 0 && rss_growth > rss_growth_max_kb {
                    status = "rss_exceeded".to_string();
                    r.fail(
                        "domainstore-baseline-after",
                        format!(
                            "rss growth {rss_growth}KB exceeded max {rss_growth_max_kb}KB (before={rss_before}KB after={rss_after}KB)"
                        ),
                    );
                } else if bytes_per_domain_max > 0 && bytes_per_domain > bytes_per_domain_max {
                    status = "bytes_per_domain_exceeded".to_string();
                    r.fail(
                        "domainstore-baseline-after",
                        format!(
                            "bytes/domain {bytes_per_domain} exceeded max {bytes_per_domain_max} (growth={rss_growth}KB)"
                        ),
                    );
                } else {
                    status = "passed".to_string();
                    r.ok(
                        "domainstore-baseline-after",
                        format!(
                            "rss_before={rss_before}KB rss_after={rss_after}KB growth={rss_growth}KB bytes/domain={bytes_per_domain} dns_p95={}ms failures={}",
                            dns_stats.p95_ms, dns_stats.failures
                        ),
                    );
                }
            }
            Err(_) => {
                status = "resource_failed".to_string();
                r.fail(
                    "domainstore-baseline-after",
                    "could not read process resources after import",
                );
            }
        }
    } else {
        r.skip(
            "domainstore-baseline-after",
            "skipped because import did not complete",
        );
    }

    if imported > 0 {
        if cleanup_blocklist(r, &base, &cleanup_method) {
            let leftover = r.curl_json(
                "GET",
                &format!("/api/blocklist?search={base}&limit=1"),
                None,
            )?;
            if array_empty(&leftover, "domains") {
                r.ok(
                    "domainstore-baseline-cleanup",
                    "removed baseline prefix and restarted service",
                );
            } else {
                r.fail(
                    "domainstore-baseline-cleanup",
                    format!("cleanup left residual entries (search={leftover})"),
                );
            }
        } else {
            r.fail(
                "domainstore-baseline-cleanup",
                format!("failed to clean baseline prefix {base}"),
            );
        }
    } else {
        r.skip(
            "domainstore-baseline-cleanup",
            "no baseline entries were imported",
        );
    }

    let value = json!({
        "status": status,
        "build_id": ctx.build_id,
        "git_rev": ctx.git_rev,
        "domains": domains,
        "imported": imported,
        "rss_before_kb": rss_before,
        "rss_after_kb": rss_after,
        "rss_growth_kb": rss_growth,
        "bytes_per_domain": bytes_per_domain,
        "dns_samples": dns_stats.samples,
        "dns_failures": dns_stats.failures,
        "dns_p95_ms": dns_stats.p95_ms,
        "dns_max_ms": dns_stats.max_ms,
        "dns_avg_ms": dns_stats.avg_ms,
        "cleanup_method": cleanup_method,
        "note": note,
        "created_at": created_at(),
    });

    r.write_baseline_json(&file, value)?;
    if status == "passed" {
        r.ok(
            "domainstore-baseline-report",
            format!("wrote {file} (domains={imported} growth={rss_growth}KB bytes/domain={bytes_per_domain})"),
        );
    } else {
        r.ok(
            "domainstore-baseline-report",
            format!("wrote {file} with status={status}"),
        );
    }
    Ok(())
}

fn run_resolver_cache(r: &mut Runner, ctx: &BaselineRun) -> Result<(), String> {
    if !env_bool_or(r, "MOCK_RESOLVER_CACHE_BASELINE", true) {
        r.skip(
            "resolver-cache-baseline",
            "hardcoded off (MOCK_RESOLVER_CACHE_BASELINE=false)",
        );
        return Ok(());
    }

    let file = r.env_or(
        "RESOLVER_CACHE_BASELINE_FILE",
        "target/mock-resolver-cache-baseline.json",
    );
    let unique_samples = r.env_u64_or("RESOLVER_CACHE_BASELINE_UNIQUE_SAMPLES", 200);
    let warm_samples = r.env_u64_or("RESOLVER_CACHE_BASELINE_WARM_SAMPLES", 48);
    let hit_rounds = r.env_u64_or("RESOLVER_CACHE_BASELINE_HIT_ROUNDS", 3);
    let heavy_p95_max = r.env_u64_or("RESOLVER_CACHE_HEAVY_P95_MAX_MS", 350);
    let warm_p95_max = r.env_u64_or("RESOLVER_CACHE_WARM_P95_MAX_MS", 150);
    let climb_max = r.env_u64_or("RESOLVER_CACHE_P95_CLIMB_MAX_MS", 50);
    let hit_ratio_max = r.env_u64_or("RESOLVER_CACHE_HIT_RATIO_MAX_PCT", 110);
    let prev_p95 = read_prev_resolver_p95(&file);

    let rss_before = r.resource_snapshot().map(|s| s.rss_kb).unwrap_or(0);
    let mut heavy_lat = Vec::new();
    let mut first_lat = Vec::new();
    let mut warm_lat = Vec::new();
    let mut all_lat = Vec::new();
    let mut servfail = 0_u64;
    let mut empty = 0_u64;
    let mut upstream = 0_u64;

    for i in 1..=unique_samples {
        let domain = format!("rb-cache-heavy-{}-{i}.example.com", ctx.run_tag);
        let (answer, latency) = timed_dns(r, &domain);
        heavy_lat.push(latency);
        all_lat.push(latency);
        if dns_error(&answer) {
            servfail += 1;
        } else {
            upstream += 1;
        }
    }

    let rss_after_heavy = r.resource_snapshot().map(|s| s.rss_kb).unwrap_or(0);
    let rss_delta = rss_after_heavy.saturating_sub(rss_before);

    for domain in REAL_DOMAINS {
        let (answer, latency) = timed_dns(r, domain);
        first_lat.push(latency);
        all_lat.push(latency);
        classify_dns_result(&answer, &mut upstream, &mut servfail, &mut empty);
    }

    for _ in 0..hit_rounds {
        for i in 0..warm_samples {
            let domain = REAL_DOMAINS[i as usize % REAL_DOMAINS.len()];
            let (answer, latency) = timed_dns(r, domain);
            warm_lat.push(latency);
            all_lat.push(latency);
            classify_dns_result(&answer, &mut upstream, &mut servfail, &mut empty);
        }
    }

    let heavy_p95 = percentile95(&heavy_lat);
    let first_p95 = percentile95(&first_lat);
    let warm_p95 = percentile95(&warm_lat);
    let all_p95 = percentile95(&all_lat);
    let all_max = all_lat.iter().copied().max().unwrap_or(0);
    let hit_ratio = warm_p95
        .saturating_mul(100)
        .checked_div(first_p95)
        .unwrap_or(0);
    let query_count = upstream + servfail + empty;
    let total_fail = servfail + empty;
    let note = format!(
        "cache_size=32768 heavy_unique={unique_samples} warm_rounds={hit_rounds}x{warm_samples}"
    );

    let fail_detail = if total_fail != 0 {
        Some(format!("failures empty={empty} servfail={servfail}"))
    } else if heavy_p95 > heavy_p95_max {
        Some(format!(
            "heavy_unique_p95={heavy_p95}ms exceeded max {heavy_p95_max}ms"
        ))
    } else if warm_p95 > warm_p95_max {
        Some(format!(
            "warm_p95={warm_p95}ms exceeded max {warm_p95_max}ms"
        ))
    } else if warm_p95 > first_p95 + climb_max {
        Some(format!(
            "warm_p95={warm_p95}ms climbed above first_p95={first_p95}ms + {climb_max}ms (hit proxy collapsed)"
        ))
    } else if hit_ratio > hit_ratio_max {
        Some(format!(
            "hit_ratio_pct={hit_ratio} (warm/first) exceeded max {hit_ratio_max}"
        ))
    } else if prev_p95.is_some_and(|prev| warm_p95 > prev + climb_max) {
        Some(format!(
            "warm_p95={warm_p95}ms climbed from prior {}ms by more than {climb_max}ms",
            prev_p95.unwrap()
        ))
    } else {
        None
    };

    let status = if let Some(detail) = &fail_detail {
        r.fail(
            "resolver-cache-baseline",
            format!(
                "{detail} (heavy={heavy_p95} first={first_p95} warm={warm_p95} hit_ratio={hit_ratio}% rss_delta={rss_delta}KB)"
            ),
        );
        "failed"
    } else {
        r.ok(
            "resolver-cache-baseline",
            format!(
                "ok q={query_count} heavy_p95={heavy_p95}ms first_p95={first_p95}ms warm_p95={warm_p95}ms hit_ratio={hit_ratio}% rss_delta={rss_delta}KB prev_warm={}",
                prev_p95.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string())
            ),
        );
        "passed"
    };

    r.write_baseline_json(
        &file,
        json!({
            "status": status,
            "build_id": ctx.build_id,
            "git_rev": ctx.git_rev,
            "cache_size_per_resolver": 32768,
            "query_count": query_count,
            "upstream_success": upstream,
            "servfail": servfail,
            "empty": empty,
            "heavy_unique_samples": unique_samples,
            "warm_repeat_samples": warm_samples * hit_rounds,
            "first_pass_samples": REAL_DOMAINS.len(),
            "dns_heavy_unique_p95_ms": heavy_p95,
            "dns_first_p95_ms": first_p95,
            "dns_warm_p95_ms": warm_p95,
            "dns_cold_p95_ms": heavy_p95,
            "dns_p95_ms": all_p95,
            "dns_max_ms": all_max,
            "hit_ratio_pct": hit_ratio,
            "rss_before_kb": rss_before,
            "rss_after_heavy_kb": rss_after_heavy,
            "rss_delta_kb": rss_delta,
            "prev_dns_p95_ms": prev_p95,
            "heavy_p95_max_ms": heavy_p95_max,
            "warm_p95_max_ms": warm_p95_max,
            "p95_climb_max_ms": climb_max,
            "hit_ratio_max_pct": hit_ratio_max,
            "note": note,
            "created_at": created_at(),
        }),
    )?;
    println!(
        "wrote {file} status={status} heavy_p95={heavy_p95} first_p95={first_p95} warm_p95={warm_p95} hit_ratio={hit_ratio}% rss_delta={rss_delta}KB"
    );
    Ok(())
}

fn run_sticky(r: &mut Runner, ctx: &BaselineRun) -> Result<(), String> {
    if !env_bool_or(r, "MOCK_STICKY_BASELINE", true) {
        r.skip(
            "sticky-baseline",
            "disabled; set MOCK_STICKY_BASELINE=true to measure sticky source refresh",
        );
        return Ok(());
    }

    let prefix = format!("{}-sticky.rustblocker.test", ctx.run_tag);
    let full_path = format!("/tmp/{prefix}-full.list");
    let shrink_path = format!("/tmp/{prefix}-shrink.list");
    let domains = r.env_u64_or("STICKY_BASELINE_DOMAINS", 5_000);
    let keep = r.env_u64_or("STICKY_BASELINE_KEEP", 2_500);
    let file = r.env_or(
        "STICKY_BASELINE_FILE",
        "target/mock-sticky-domain-baseline.json",
    );
    let settle_secs = r.env_u64_or("STICKY_BASELINE_SETTLE_SECS", 2);
    let mut status = "running".to_string();
    let note = "post-fix sticky source refresh (provenance rebuild)";
    let removed_domain = format!("sticky-{domains}.{prefix}");
    let keep_domain = format!("sticky-1.{prefix}");
    let mut source_id = 0_u64;
    let mut rss_before = 0;
    let mut rss_full = 0;
    let mut rss_shrink = 0;
    let mut rss_reclaim = 0;
    let mut sticky_dns = 0;
    let mut keep_dns_ok = 0;
    let mut full_dns_ok = 0;
    let mut full_count = 0;

    if keep >= domains {
        r.fail(
            "sticky-baseline-prereq",
            format!("STICKY_BASELINE_KEEP ({keep}) must be < STICKY_BASELINE_DOMAINS ({domains})"),
        );
        status = "invalid_config".to_string();
    }

    if status == "running" && write_remote_sticky_list(r, &full_path, 1, domains, &prefix) {
        let _ = write_remote_sticky_list(r, &shrink_path, 1, keep, &prefix);
        r.ok(
            "sticky-baseline-files",
            format!("wrote remote lists full={domains} keep={keep}"),
        );
    } else if status == "running" {
        status = "file_failed".to_string();
        r.fail(
            "sticky-baseline-files",
            "failed to write remote source list files",
        );
    } else {
        r.skip(
            "sticky-baseline-files",
            "skipped because prerequisite failed",
        );
    }

    if status == "running" {
        match r.resource_snapshot() {
            Ok(snapshot) => {
                rss_before = snapshot.rss_kb;
                r.ok("sticky-baseline-before", format!("rss={rss_before}KB"));
            }
            Err(_) => {
                status = "resource_failed".to_string();
                r.fail(
                    "sticky-baseline-before",
                    "could not read process resources before source import",
                );
            }
        }
    } else {
        r.skip(
            "sticky-baseline-before",
            "skipped because prerequisite failed",
        );
    }

    if status == "running" {
        let resp = r.curl_body(
            "POST",
            "/api/sources",
            Some(json!({"url": full_path, "list_type": "blocklist", "update_interval_hours": 24})),
        )?;
        let body = parse_body_json(&resp);
        source_id = body.get("id").and_then(Value::as_u64).unwrap_or(0);
        let source_status = body
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        if resp.code == 201 && source_id > 0 {
            r.ok(
                "sticky-baseline-import",
                format!("source id={source_id} status={source_status}"),
            );
        } else {
            status = "import_failed".to_string();
            r.fail(
                "sticky-baseline-import",
                format!("add source failed HTTP={} body={}", resp.code, resp.body),
            );
        }
    } else {
        r.skip(
            "sticky-baseline-import",
            "skipped because prerequisite failed",
        );
    }

    if status == "running" {
        sleep_secs(settle_secs);
        let full_dns = r.dns_query(&removed_domain).unwrap_or_default();
        let keep_dns = r.dns_query(&keep_domain).unwrap_or_default();
        if has_exact_line(&full_dns, &ctx.sinkhole_ipv4)
            && has_exact_line(&keep_dns, &ctx.sinkhole_ipv4)
        {
            full_dns_ok = 1;
            if let Ok(snapshot) = r.resource_snapshot() {
                rss_full = snapshot.rss_kb;
            }
            full_count = blocklist_total(r, &prefix).unwrap_or(0);
            r.ok(
                "sticky-baseline-full-dns",
                format!("full list sinkholed count={full_count} keep={keep_domain} removed={removed_domain}"),
            );
        } else {
            status = "dns_failed".to_string();
            r.fail(
                "sticky-baseline-full-dns",
                format!(
                    "expected sinkhole {}; keep={} removed={}",
                    ctx.sinkhole_ipv4,
                    empty_if_blank(&keep_dns),
                    empty_if_blank(&full_dns)
                ),
            );
        }
    } else {
        r.skip(
            "sticky-baseline-full-dns",
            "skipped because import did not complete",
        );
    }

    if status == "running" {
        let _ = r.remote_root(&format!(
            "cp -f {} {}",
            shell_quote(&shrink_path),
            shell_quote(&full_path)
        ));
        let shrink_lines = r
            .remote_root(&format!("wc -l < {}", shell_quote(&full_path)))
            .unwrap_or_default()
            .trim()
            .to_string();
        let resp = r.curl_body("POST", &format!("/api/sources/{source_id}/refresh"), None)?;
        let refresh_status = parse_body_json(&resp)
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        if resp.code == 200 && resp.body.contains(&format!("ok: {keep} domains")) {
            r.ok(
                "sticky-baseline-shrink-refresh",
                format!(
                    "refreshed sources after shrink (lines={shrink_lines}, status={refresh_status})"
                ),
            );
        } else {
            status = "refresh_failed".to_string();
            r.fail(
                "sticky-baseline-shrink-refresh",
                format!(
                    "refresh failed HTTP={} lines={} body={}",
                    resp.code,
                    empty_if_blank(&shrink_lines),
                    empty_if_blank(&resp.body)
                ),
            );
        }
    } else {
        r.skip(
            "sticky-baseline-shrink-refresh",
            "skipped because full import did not complete",
        );
    }

    if status == "running" {
        let mut removed_dns = String::new();
        let mut keep_dns2 = String::new();
        for _ in 0..5 {
            sleep_secs(settle_secs);
            removed_dns = r.dns_query(&removed_domain).unwrap_or_default();
            keep_dns2 = r.dns_query(&keep_domain).unwrap_or_default();
            keep_dns_ok = u64::from(has_exact_line(&keep_dns2, &ctx.sinkhole_ipv4));
            sticky_dns = u64::from(has_exact_line(&removed_dns, &ctx.sinkhole_ipv4));
            if keep_dns_ok == 1 {
                break;
            }
        }
        let search = r.curl_json(
            "GET",
            &format!("/api/blocklist?search={keep_domain}&limit=5"),
            None,
        )?;
        let search_total = json_u64(&search, "total").unwrap_or(0);
        if let Ok(snapshot) = r.resource_snapshot() {
            rss_shrink = snapshot.rss_kb;
            rss_reclaim = rss_full.saturating_sub(rss_shrink);
        }
        if keep_dns_ok != 1 {
            status = "dns_failed".to_string();
            r.fail(
                "sticky-baseline-after-shrink",
                format!(
                    "kept domain no longer sinkholed (got={}, search_total={search_total}, refresh=unknown)",
                    empty_if_blank(&keep_dns2)
                ),
            );
        } else if sticky_dns != 0 {
            status = "sticky_dns".to_string();
            r.fail(
                "sticky-baseline-after-shrink",
                format!(
                    "removed domain still sinkholed (sticky_dns=1, removed_dns={})",
                    empty_if_blank(&removed_dns)
                ),
            );
        } else if restart_remote_service(r)
            && wait_for_health(r, ctx.web_port, 15, 2)
            && relogin(r, &ctx.webui_password)?
        {
            let removed_cold = r.dns_query(&removed_domain).unwrap_or_default();
            let keep_cold = r.dns_query(&keep_domain).unwrap_or_default();
            if !has_exact_line(&keep_cold, &ctx.sinkhole_ipv4) {
                status = "dns_failed".to_string();
                r.fail(
                    "sticky-baseline-after-shrink",
                    format!(
                        "cold restart lost keep domain (got={})",
                        empty_if_blank(&keep_cold)
                    ),
                );
            } else if has_exact_line(&removed_cold, &ctx.sinkhole_ipv4) {
                status = "sticky_dns".to_string();
                r.fail(
                    "sticky-baseline-after-shrink",
                    "cold restart still sinkholes removed domain",
                );
            } else {
                status = "passed".to_string();
                let shrink_count = blocklist_total(r, &prefix).unwrap_or(0);
                r.ok(
                    "sticky-baseline-after-shrink",
                    format!("sticky_dns=0 keep_ok=1 cold_ok=1 count_full={full_count} count_shrink={shrink_count} rss_full={rss_full}KB rss_shrink={rss_shrink}KB reclaim={rss_reclaim}KB removed_dns={}", empty_if_blank(&removed_dns)),
                );
            }
        } else {
            status = "passed".to_string();
            let shrink_count = blocklist_total(r, &prefix).unwrap_or(0);
            r.ok(
                "sticky-baseline-after-shrink",
                format!("sticky_dns=0 keep_ok=1 count_full={full_count} count_shrink={shrink_count} rss_full={rss_full}KB rss_shrink={rss_shrink}KB reclaim={rss_reclaim}KB removed_dns={} (cold check skipped)", empty_if_blank(&removed_dns)),
            );
        }
    } else {
        r.skip(
            "sticky-baseline-after-shrink",
            "skipped because shrink refresh did not complete",
        );
    }

    sticky_cleanup(r, &prefix, source_id, &full_path, &shrink_path);
    r.ok(
        "sticky-baseline-cleanup",
        format!("removed sticky source/domains for {prefix}"),
    );

    r.write_baseline_json(
        &file,
        json!({
            "status": status,
            "build_id": ctx.build_id,
            "git_rev": ctx.git_rev,
            "domains_full": domains,
            "domains_keep": keep,
            "rss_before_kb": rss_before,
            "rss_full_kb": rss_full,
            "rss_shrink_kb": rss_shrink,
            "rss_reclaim_kb": rss_reclaim,
            "sticky_dns": sticky_dns,
            "full_dns_ok": full_dns_ok,
            "keep_dns_ok": keep_dns_ok,
            "removed_domain": removed_domain,
            "keep_domain": keep_domain,
            "note": note,
            "created_at": created_at(),
        }),
    )?;
    r.ok(
        "sticky-baseline-report",
        format!("wrote {file} status={status} sticky_dns={sticky_dns} reclaim={rss_reclaim}KB"),
    );
    Ok(())
}

fn run_remove_compact(r: &mut Runner, ctx: &BaselineRun) -> Result<(), String> {
    if !env_bool_or(r, "MOCK_REMOVE_COMPACT_BASELINE", true) {
        r.skip(
            "remove-compact",
            "hardcoded off (MOCK_REMOVE_COMPACT_BASELINE=false)",
        );
        return Ok(());
    }

    let prefix = format!("{}-rmcompact.rustblocker.test", ctx.run_tag);
    let domains = r.env_u64_or("REMOVE_COMPACT_DOMAINS", 100);
    let keep = r.env_u64_or("REMOVE_COMPACT_KEEP", 10);
    let churn = r.env_u64_or("REMOVE_COMPACT_CHURN", 40);
    let settle_secs = r.env_u64_or("REMOVE_COMPACT_SETTLE_SECS", 1);
    let file = r.env_or(
        "REMOVE_COMPACT_BASELINE_FILE",
        "target/mock-remove-compact-baseline.json",
    );
    let note = "post-fix DomainStore::remove compact via API DELETE";
    let keep_domain = format!("rmc-1.{prefix}");
    let removed_domain = format!("rmc-{domains}.{prefix}");
    let wildcard_probe = format!("sub.wild.{prefix}");
    let mut status = "running".to_string();
    let mut rss_before = 0;
    let mut rss_full = 0;
    let mut rss_after_delete = 0;
    let mut rss_after_churn = 0;
    let mut rss_churn_growth = 0;
    let mut imported = 0;
    let mut deleted = 0;
    let mut churn_ok = 0;
    let mut sticky_dns = 0;
    let mut keep_dns_ok = 0;

    if keep >= domains {
        r.fail(
            "remove-compact-prereq",
            format!("REMOVE_COMPACT_KEEP ({keep}) must be < REMOVE_COMPACT_DOMAINS ({domains})"),
        );
        status = "invalid_config".to_string();
    }

    if status == "running" {
        match r.resource_snapshot() {
            Ok(snapshot) => {
                rss_before = snapshot.rss_kb;
                r.ok(
                    "remove-compact-before",
                    format!("rss={rss_before}KB domains={domains} keep={keep} churn={churn}"),
                );
            }
            Err(_) => {
                status = "resource_failed".to_string();
                r.fail(
                    "remove-compact-before",
                    "could not read process resources before import",
                );
            }
        }
    } else {
        r.skip(
            "remove-compact-before",
            "skipped because prerequisite failed",
        );
    }

    if status == "running" {
        let mut content = String::new();
        for i in 1..=domains {
            content.push_str(&format!("0.0.0.0 rmc-{i}.{prefix}\n"));
        }
        content.push_str(&format!("*.wild.{prefix}\n"));
        let resp = r.curl_body(
            "POST",
            "/api/blocklist/import",
            Some(json!({"content": content})),
        )?;
        imported = json_u64(&parse_body_json(&resp), "imported").unwrap_or(0);
        if resp.code == 200 && imported >= domains {
            sleep_secs(settle_secs);
            if let Ok(snapshot) = r.resource_snapshot() {
                rss_full = snapshot.rss_kb;
            }
            r.ok(
                "remove-compact-import",
                format!("imported {imported} entries rss_full={rss_full}KB"),
            );
        } else {
            status = "import_failed".to_string();
            r.fail(
                "remove-compact-import",
                format!(
                    "import failed HTTP={} body={}",
                    resp.code,
                    empty_if_blank(&resp.body)
                ),
            );
        }
    } else {
        r.skip(
            "remove-compact-import",
            "skipped because prerequisite failed",
        );
    }

    if status == "running" {
        let full_dns = r.dns_query(&removed_domain).unwrap_or_default();
        let keep_dns = r.dns_query(&keep_domain).unwrap_or_default();
        let wild_dns = r.dns_query(&wildcard_probe).unwrap_or_default();
        if has_exact_line(&full_dns, &ctx.sinkhole_ipv4)
            && has_exact_line(&keep_dns, &ctx.sinkhole_ipv4)
            && has_exact_line(&wild_dns, &ctx.sinkhole_ipv4)
        {
            r.ok(
                "remove-compact-full-dns",
                "keep/removed/wildcard all sinkholed before delete",
            );
        } else {
            status = "dns_failed".to_string();
            r.fail(
                "remove-compact-full-dns",
                format!(
                    "expected sinkhole {}; keep={} removed={} wild={}",
                    ctx.sinkhole_ipv4,
                    empty_if_blank(&keep_dns),
                    empty_if_blank(&full_dns),
                    empty_if_blank(&wild_dns)
                ),
            );
        }
    } else {
        r.skip(
            "remove-compact-full-dns",
            "skipped because import did not complete",
        );
    }

    if status == "running" {
        let delete_ok = delete_non_keep(r, &prefix, "rmc-", keep, &mut deleted)?;
        sleep_secs(settle_secs);
        if let Ok(snapshot) = r.resource_snapshot() {
            rss_after_delete = snapshot.rss_kb;
        }
        let expected_deleted = domains - keep + 1;
        if delete_ok && deleted >= expected_deleted {
            r.ok(
                "remove-compact-delete",
                format!("deleted {deleted} entries via API (expected>={expected_deleted}) rss_after={rss_after_delete}KB"),
            );
        } else {
            status = "delete_failed".to_string();
            r.fail(
                "remove-compact-delete",
                format!("delete incomplete deleted={deleted} expected>={expected_deleted} ok={delete_ok}"),
            );
        }
    } else {
        r.skip(
            "remove-compact-delete",
            "skipped because full DNS check failed",
        );
    }

    if status == "running" {
        let mut removed_dns = String::new();
        let mut keep_dns2 = String::new();
        let mut wild_dns2 = String::new();
        let mut wild_sticky = 0;
        for _ in 0..5 {
            sleep_secs(settle_secs);
            removed_dns = r.dns_query(&removed_domain).unwrap_or_default();
            keep_dns2 = r.dns_query(&keep_domain).unwrap_or_default();
            wild_dns2 = r.dns_query(&wildcard_probe).unwrap_or_default();
            keep_dns_ok = u64::from(has_exact_line(&keep_dns2, &ctx.sinkhole_ipv4));
            sticky_dns = u64::from(has_exact_line(&removed_dns, &ctx.sinkhole_ipv4));
            wild_sticky = u64::from(has_exact_line(&wild_dns2, &ctx.sinkhole_ipv4));
            if keep_dns_ok == 1 && sticky_dns == 0 && wild_sticky == 0 {
                break;
            }
        }
        if keep_dns_ok != 1 {
            status = "dns_failed".to_string();
            r.fail(
                "remove-compact-after-delete",
                format!(
                    "keep domain no longer sinkholed (got={})",
                    empty_if_blank(&keep_dns2)
                ),
            );
        } else if sticky_dns != 0 || wild_sticky != 0 {
            status = "sticky_dns".to_string();
            r.fail(
                "remove-compact-after-delete",
                format!(
                    "removed still sinkholed sticky_dns={sticky_dns} wild_sticky={wild_sticky} removed={} wild={}",
                    empty_if_blank(&removed_dns),
                    empty_if_blank(&wild_dns2)
                ),
            );
        } else {
            r.ok(
                "remove-compact-after-delete",
                format!(
                    "sticky_dns=0 keep_ok=1 wild_sticky=0 removed_dns={}",
                    empty_if_blank(&removed_dns)
                ),
            );
        }
    } else {
        r.skip(
            "remove-compact-after-delete",
            "skipped because delete did not complete",
        );
    }

    if status == "running" {
        let churn_base = format!("{prefix}.churn");
        let mut churn_problem = String::new();
        churn_ok = 1;
        for i in 1..=churn {
            let domain = format!("churn-{i}.{churn_base}");
            let resp = r.curl_body("POST", "/api/blocklist", Some(json!({"domain": domain})))?;
            let id = json_u64(&parse_body_json(&resp), "id").unwrap_or(0);
            if resp.code != 201 || id == 0 {
                churn_ok = 0;
                churn_problem = format!(
                    "add failed at {i}: http={} id={id} body={}",
                    resp.code, resp.body
                );
                break;
            }
            let code = r.curl_code("DELETE", &format!("/api/blocklist/{id}"), None)?;
            if code != 200 {
                churn_ok = 0;
                churn_problem = format!("delete failed at {i}: http={code} id={id}");
                break;
            }
        }
        sleep_secs(settle_secs);
        let churn_keep_dns = r.dns_query(&keep_domain).unwrap_or_default();
        if !has_exact_line(&churn_keep_dns, &ctx.sinkhole_ipv4) {
            churn_ok = 0;
            if churn_problem.is_empty() {
                churn_problem = format!("keep dns lost: {}", empty_if_blank(&churn_keep_dns));
            }
        }
        if let Ok(snapshot) = r.resource_snapshot() {
            rss_after_churn = snapshot.rss_kb;
            if rss_after_delete > 0 {
                rss_churn_growth = rss_after_churn.saturating_sub(rss_after_delete);
            }
        }
        let leftover = blocklist_search_empty(r, &churn_base)
            .map(|empty| u64::from(!empty))
            .unwrap_or(1);
        if leftover != 0 {
            churn_ok = 0;
            if churn_problem.is_empty() {
                churn_problem = format!("leftover={leftover}");
            }
        }
        if churn_ok != 1 {
            status = "churn_failed".to_string();
            r.fail(
                "remove-compact-churn",
                format!("insert/delete churn failed or left residue: {churn_problem} (rss_note_growth={rss_churn_growth}KB)"),
            );
        } else {
            status = "passed".to_string();
            r.ok(
                "remove-compact-churn",
                format!("{churn} insert/delete cycles ok keep_sinkholed residue=0 rss_note_growth={rss_churn_growth}KB rss_after={rss_after_churn}KB"),
            );
        }
    } else {
        r.skip(
            "remove-compact-churn",
            "skipped because after-delete DNS check failed",
        );
    }

    cleanup_blocklist_best_effort(r, &prefix);
    cleanup_blocklist_best_effort(r, &format!("{prefix}.churn"));
    r.ok(
        "remove-compact-cleanup",
        format!("removed temporary domains for {prefix}"),
    );

    r.write_baseline_json(
        &file,
        json!({
            "status": status,
            "build_id": ctx.build_id,
            "git_rev": ctx.git_rev,
            "domains": domains,
            "keep": keep,
            "churn": churn,
            "imported": imported,
            "deleted": deleted,
            "churn_ok": churn_ok,
            "sticky_dns": sticky_dns,
            "keep_dns_ok": keep_dns_ok,
            "removed_domain": removed_domain,
            "keep_domain": keep_domain,
            "rss_before_kb": rss_before,
            "rss_full_kb": rss_full,
            "rss_after_delete_kb": rss_after_delete,
            "rss_after_churn_kb": rss_after_churn,
            "rss_churn_growth_kb": rss_churn_growth,
            "note": note,
            "created_at": created_at(),
        }),
    )?;
    if status == "passed" {
        r.ok(
            "remove-compact-report",
            format!("wrote {file} status=passed deleted={deleted} churn={churn} growth={rss_churn_growth}KB"),
        );
    } else {
        r.fail(
            "remove-compact-report",
            format!(
                "wrote {file} status={status} sticky_dns={sticky_dns} growth={rss_churn_growth}KB"
            ),
        );
    }
    Ok(())
}

fn run_sync_apply(r: &mut Runner, ctx: &BaselineRun) -> Result<(), String> {
    if !env_bool_or(r, "MOCK_SYNC_APPLY_BASELINE", true) {
        r.skip(
            "sync-apply",
            "hardcoded off (MOCK_SYNC_APPLY_BASELINE=false)",
        );
        return Ok(());
    }

    let prefix = format!("{}-syncapply.rustblocker.test", ctx.run_tag);
    let domains = r.env_u64_or("SYNC_APPLY_DOMAINS", 80);
    let keep = r.env_u64_or("SYNC_APPLY_KEEP", 15);
    let interval_secs = r.env_u64_or("SYNC_APPLY_INTERVAL_SECS", 2);
    let settle_secs = r.env_u64_or("SYNC_APPLY_SETTLE_SECS", 3);
    let wait_attempts = r.env_u64_or("SYNC_APPLY_WAIT_ATTEMPTS", 20);
    let slave_dns_port = r.env_u64_or("SYNC_APPLY_SLAVE_DNS_PORT", 1853);
    let slave_web_port = r.env_u64_or("SYNC_APPLY_SLAVE_WEB_PORT", 1854);
    let file = r.env_or(
        "SYNC_APPLY_BASELINE_FILE",
        "target/mock-sync-apply-domains-baseline.json",
    );
    let note = "post-fix sync apply_domains replace_with via temp slave";
    let keep_domain = format!("sap-1.{prefix}");
    let removed_domain = format!("sap-{domains}.{prefix}");
    let slave_db = format!("/tmp/rb-sync-apply-{}.db", unix_secs());
    let slave_log = "/tmp/rb-sync-apply-slave.log".to_string();
    let slave = SlavePaths {
        dns_port: slave_dns_port,
        web_port: slave_web_port,
        db: slave_db,
        log: slave_log,
        pid: 0,
    };
    let mut status = "running".to_string();
    let mut imported = 0;
    let mut deleted = 0;
    let mut sticky_dns = 0;
    let mut keep_dns_ok = 0;
    let mut full_dns_ok = 0;
    let mut slave = slave;

    if keep >= domains {
        r.fail(
            "sync-apply-prereq",
            format!("SYNC_APPLY_KEEP ({keep}) must be < SYNC_APPLY_DOMAINS ({domains})"),
        );
        status = "invalid_config".to_string();
    }

    if status == "running" {
        cleanup_slave(r, &slave);
        r.ok(
            "sync-apply-prep",
            format!("cleared prior slave state ports={slave_dns_port}/{slave_web_port}"),
        );
    } else {
        r.skip("sync-apply-prep", "skipped because prerequisite failed");
    }

    if status == "running" {
        let mut content = String::new();
        for i in 1..=domains {
            content.push_str(&format!("0.0.0.0 sap-{i}.{prefix}\n"));
        }
        let resp = r.curl_body(
            "POST",
            "/api/blocklist/import",
            Some(json!({"content": content})),
        )?;
        imported = json_u64(&parse_body_json(&resp), "imported").unwrap_or(0);
        if resp.code == 200 && imported >= domains {
            r.ok(
                "sync-apply-master-import",
                format!("master imported {imported} domains"),
            );
        } else {
            status = "import_failed".to_string();
            r.fail(
                "sync-apply-master-import",
                format!(
                    "import failed HTTP={} body={}",
                    resp.code,
                    empty_if_blank(&resp.body)
                ),
            );
        }
    } else {
        r.skip(
            "sync-apply-master-import",
            "skipped because prerequisite failed",
        );
    }

    if status == "running" {
        match start_slave(r, ctx, &slave, interval_secs) {
            Ok(pid) => {
                slave.pid = pid;
                if wait_for_slave_health(r, ctx, slave_web_port) {
                    r.ok(
                        "sync-apply-slave-start",
                        format!("slave pid={pid} dns={slave_dns_port} web={slave_web_port}"),
                    );
                } else {
                    status = "slave_start_failed".to_string();
                    let log = remote_tail(r, &slave.log, 40);
                    r.fail(
                        "sync-apply-slave-start",
                        format!("slave health failed pid={pid} log={}", empty_if_blank(&log)),
                    );
                    cleanup_slave(r, &slave);
                }
            }
            Err(out) => {
                status = "slave_start_failed".to_string();
                r.fail(
                    "sync-apply-slave-start",
                    format!("failed to launch slave (out={})", empty_if_blank(&out)),
                );
            }
        }
    } else {
        r.skip(
            "sync-apply-slave-start",
            "skipped because master import failed",
        );
    }

    if status == "running" {
        let mut sync_ok = false;
        let mut full_dns = String::new();
        let mut keep_dns = String::new();
        for _ in 0..wait_attempts {
            sleep_secs(settle_secs);
            full_dns = remote_dns_a_port(r, &removed_domain, slave_dns_port);
            keep_dns = remote_dns_a_port(r, &keep_domain, slave_dns_port);
            if has_exact_line(&full_dns, &ctx.sinkhole_ipv4)
                && has_exact_line(&keep_dns, &ctx.sinkhole_ipv4)
            {
                full_dns_ok = 1;
                sync_ok = true;
                break;
            }
        }
        if sync_ok {
            r.ok(
                "sync-apply-full-sync",
                format!("slave DNS full+keep sinkholed on port {slave_dns_port}"),
            );
        } else {
            status = "sync_failed".to_string();
            let log = remote_tail(r, &slave.log, 60);
            r.fail(
                "sync-apply-full-sync",
                format!(
                    "slave DNS did not sinkhole full list keep={} removed={} log={}",
                    empty_if_blank(&keep_dns),
                    empty_if_blank(&full_dns),
                    empty_if_blank(&log)
                ),
            );
        }
    } else {
        r.skip(
            "sync-apply-full-sync",
            "skipped because slave did not start",
        );
    }

    if status == "running" {
        let delete_ok = delete_non_keep(r, &prefix, "sap-", keep, &mut deleted)?;
        let expected_deleted = domains - keep;
        if delete_ok && deleted >= expected_deleted {
            r.ok(
                "sync-apply-master-shrink",
                format!("master deleted {deleted} (expected>={expected_deleted})"),
            );
        } else {
            status = "shrink_failed".to_string();
            r.fail(
                "sync-apply-master-shrink",
                format!("delete incomplete deleted={deleted} expected>={expected_deleted} ok={delete_ok}"),
            );
        }
    } else {
        r.skip(
            "sync-apply-master-shrink",
            "skipped because full sync failed",
        );
    }

    if status == "running" {
        let mut removed_dns = String::new();
        let mut keep_dns2 = String::new();
        sticky_dns = 1;
        for _ in 0..wait_attempts {
            sleep_secs(settle_secs);
            removed_dns = remote_dns_a_port(r, &removed_domain, slave_dns_port);
            keep_dns2 = remote_dns_a_port(r, &keep_domain, slave_dns_port);
            keep_dns_ok = u64::from(has_exact_line(&keep_dns2, &ctx.sinkhole_ipv4));
            sticky_dns = u64::from(has_exact_line(&removed_dns, &ctx.sinkhole_ipv4));
            if keep_dns_ok == 1 && sticky_dns == 0 {
                break;
            }
        }
        if keep_dns_ok != 1 {
            status = "dns_failed".to_string();
            r.fail(
                "sync-apply-after-shrink",
                format!(
                    "slave keep no longer sinkholed (got={})",
                    empty_if_blank(&keep_dns2)
                ),
            );
        } else if sticky_dns != 0 {
            status = "sticky_dns".to_string();
            r.fail(
                "sync-apply-after-shrink",
                format!("slave still sinkholes removed domain (apply_domains did not replace) removed_dns={}", empty_if_blank(&removed_dns)),
            );
        } else {
            status = "passed".to_string();
            r.ok(
                "sync-apply-after-shrink",
                "sticky_dns=0 keep_ok=1 slave applied shrink via replace_with path",
            );
        }
    } else {
        r.skip(
            "sync-apply-after-shrink",
            "skipped because master shrink failed",
        );
    }

    cleanup_blocklist_best_effort(r, &prefix);
    cleanup_slave(r, &slave);
    r.ok(
        "sync-apply-cleanup",
        "removed master prefix + stopped slave",
    );

    r.write_baseline_json(
        &file,
        json!({
            "status": status,
            "build_id": ctx.build_id,
            "git_rev": ctx.git_rev,
            "domains": domains,
            "keep": keep,
            "imported": imported,
            "deleted": deleted,
            "sticky_dns": sticky_dns,
            "keep_dns_ok": keep_dns_ok,
            "full_dns_ok": full_dns_ok,
            "removed_domain": removed_domain,
            "keep_domain": keep_domain,
            "slave_dns_port": slave_dns_port,
            "note": note,
            "created_at": created_at(),
        }),
    )?;
    if status == "passed" {
        r.ok(
            "sync-apply-report",
            format!("wrote {file} status=passed deleted={deleted} sticky_dns={sticky_dns}"),
        );
    } else {
        r.fail(
            "sync-apply-report",
            format!("wrote {file} status={status} sticky_dns={sticky_dns}"),
        );
    }
    Ok(())
}

#[derive(Default)]
struct DnsStats {
    samples: u64,
    failures: u64,
    p95_ms: u64,
    max_ms: u64,
    avg_ms: u64,
    failure_sample: Option<String>,
}

struct SlavePaths {
    dns_port: u64,
    web_port: u64,
    db: String,
    log: String,
    pid: u64,
}

fn import_blocklist_batch(
    r: &mut Runner,
    base: &str,
    start: u64,
    count: u64,
    prefix: &str,
) -> Result<u64, String> {
    let mut content = String::new();
    for i in start..start + count {
        content.push_str(&format!("0.0.0.0 {prefix}-{i}.{base}\n"));
    }
    let response = r.curl_body(
        "POST",
        "/api/blocklist/import",
        Some(json!({"content": content})),
    )?;
    let imported = json_u64(&parse_body_json(&response), "imported").unwrap_or(0);
    if response.code == 200 && imported >= count {
        Ok(imported)
    } else {
        Err(format!(
            "HTTP {} response: {}",
            response.code,
            empty_if_blank(&response.body)
        ))
    }
}

fn measure_stress_dns_latency(
    r: &mut Runner,
    base: &str,
    domain_count: u64,
    samples: u64,
    expected: &str,
) -> DnsStats {
    let sample_count = samples.min(domain_count).max(1);
    let mut latencies = Vec::new();
    let mut failures = 0;
    let mut failure_sample = None;
    for i in 1..=sample_count {
        let index = ((i - 1) * domain_count / sample_count) + 1;
        let domain = format!("stress-{index}.{base}");
        let started = Instant::now();
        let answer = r.dns_query(&domain).unwrap_or_default();
        let elapsed = started.elapsed().as_millis() as u64;
        latencies.push(elapsed);
        if !has_exact_line(&answer, expected) {
            failures += 1;
            if failure_sample.is_none() {
                failure_sample = Some(format!(
                    "{domain} expected={expected} got={}",
                    empty_if_blank(&answer)
                ));
            }
        }
    }
    DnsStats {
        samples: sample_count,
        failures,
        p95_ms: percentile95(&latencies),
        max_ms: latencies.iter().copied().max().unwrap_or(0),
        avg_ms: avg(&latencies),
        failure_sample,
    }
}

fn delete_non_keep(
    r: &mut Runner,
    prefix: &str,
    item_prefix: &str,
    keep: u64,
    deleted: &mut u64,
) -> Result<bool, String> {
    let mut ok = true;
    for _ in 0..40 {
        let page = r.curl_json(
            "GET",
            &format!("/api/blocklist?search={prefix}&limit=250"),
            None,
        )?;
        if array_empty(&page, "domains") {
            break;
        }
        let mut deleted_this_pass = 0;
        for entry in page_domains(&page) {
            let Some(domain) = entry.get("domain").and_then(Value::as_str) else {
                continue;
            };
            let Some(id) = entry.get("id").and_then(Value::as_u64) else {
                continue;
            };
            if keep_domain_number(domain, item_prefix, prefix).is_some_and(|n| n <= keep) {
                continue;
            }
            if r.curl_code("DELETE", &format!("/api/blocklist/{id}"), None)? == 200 {
                *deleted += 1;
                deleted_this_pass += 1;
            } else {
                ok = false;
            }
        }
        let check_page = r.curl_json(
            "GET",
            &format!("/api/blocklist?search={prefix}&limit=250"),
            None,
        )?;
        let leftover_non_keep = page_domains(&check_page).iter().any(|entry| {
            entry
                .get("domain")
                .and_then(Value::as_str)
                .is_some_and(|domain| {
                    keep_domain_number(domain, item_prefix, prefix).is_none_or(|n| n > keep)
                })
        });
        if !leftover_non_keep {
            break;
        }
        if deleted_this_pass == 0 {
            ok = false;
            break;
        }
    }
    Ok(ok)
}

fn keep_domain_number(domain: &str, item_prefix: &str, suffix: &str) -> Option<u64> {
    let rest = domain.strip_prefix(item_prefix)?;
    let number = rest.strip_suffix(&format!(".{suffix}"))?;
    number.parse().ok()
}

fn blocklist_search_empty(r: &mut Runner, search: &str) -> Result<bool, String> {
    let value = r.curl_json(
        "GET",
        &format!("/api/blocklist?search={search}&limit=1"),
        None,
    )?;
    Ok(array_empty(&value, "domains"))
}

fn blocklist_total(r: &mut Runner, search: &str) -> Result<u64, String> {
    let value = r.curl_json(
        "GET",
        &format!("/api/blocklist?search={search}&limit=1"),
        None,
    )?;
    Ok(json_u64(&value, "total").unwrap_or(0))
}

fn page_domains(value: &Value) -> Vec<Value> {
    value
        .get("domains")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn array_empty(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
}

fn parse_body_json(response: &CurlResponse) -> Value {
    serde_json::from_str(&response.body).unwrap_or(Value::Null)
}

fn json_u64(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}

fn timed_dns(r: &mut Runner, domain: &str) -> (String, u64) {
    let started = Instant::now();
    let answer = r.dns_query(domain).unwrap_or_default();
    (answer, started.elapsed().as_millis() as u64)
}

fn classify_dns_result(answer: &str, upstream: &mut u64, servfail: &mut u64, empty: &mut u64) {
    if answer.trim().is_empty() {
        *empty += 1;
    } else if dns_error(answer) {
        *servfail += 1;
    } else {
        *upstream += 1;
    }
}

fn dns_error(answer: &str) -> bool {
    let lower = answer.to_ascii_lowercase();
    ["servfail", "error", "connection refused", "timed out"]
        .iter()
        .any(|needle| lower.contains(needle))
}

fn percentile95(values: &[u64]) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let idx = (sorted.len() as u64 * 95).div_ceil(100).max(1) as usize;
    sorted[idx - 1]
}

fn avg(values: &[u64]) -> u64 {
    if values.is_empty() {
        0
    } else {
        values.iter().sum::<u64>() / values.len() as u64
    }
}

fn has_exact_line(output: &str, expected: &str) -> bool {
    output.lines().any(|line| line.trim() == expected)
}

fn empty_if_blank(value: &str) -> &str {
    if value.trim().is_empty() {
        "empty"
    } else {
        value.trim()
    }
}

fn sleep_secs(seconds: u64) {
    thread::sleep(Duration::from_secs(seconds));
}

fn sinkhole_ipv4(r: &mut Runner) -> Result<String, String> {
    let settings = r.curl_json("GET", "/api/settings", None)?;
    Ok(settings
        .get("sinkhole_ipv4")
        .and_then(Value::as_str)
        .unwrap_or("0.0.0.0")
        .to_string())
}

fn has_sqlite(r: &mut Runner) -> bool {
    r.remote_root("command -v sqlite3 >/dev/null 2>&1").is_ok()
        || (env_bool_or(r, "STRESS_INSTALL_SQLITE3", true) && install_sqlite3(r))
}

fn install_sqlite3(r: &mut Runner) -> bool {
    r.remote_root("if command -v sqlite3 >/dev/null 2>&1; then exit 0; elif command -v apk >/dev/null 2>&1; then apk add --no-cache sqlite; elif command -v apt-get >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y sqlite3; elif command -v dnf >/dev/null 2>&1; then dnf install -y sqlite; elif command -v yum >/dev/null 2>&1; then yum install -y sqlite; else exit 2; fi; command -v sqlite3 >/dev/null 2>&1").is_ok()
}

fn env_bool_or(r: &Runner, key: &str, default: bool) -> bool {
    r.env(key).map_or(default, |value| {
        matches!(
            value.as_str(),
            "true" | "TRUE" | "1" | "yes" | "YES" | "on" | "ON"
        )
    })
}

fn cleanup_blocklist(r: &mut Runner, prefix: &str, method: &str) -> bool {
    match method {
        "sqlite" => r.cleanup_blocklist_sqlite(prefix).is_ok(),
        "api" => r.cleanup_blocklist_api(prefix, 250, 200).is_ok(),
        _ => false,
    }
}

fn cleanup_blocklist_best_effort(r: &mut Runner, prefix: &str) {
    if has_sqlite(r) {
        let _ = r.cleanup_blocklist_sqlite(prefix);
    } else {
        let _ = r.cleanup_blocklist_api(prefix, 250, 40);
    }
}

fn write_remote_sticky_list(
    r: &mut Runner,
    remote_path: &str,
    start: u64,
    end: u64,
    prefix: &str,
) -> bool {
    let command = format!(
        "i={start}; end={end}; path={}; prefix={}; : > \"$path\"; while [ \"$i\" -le \"$end\" ]; do printf '0.0.0.0 sticky-%s.%s\\n' \"$i\" \"$prefix\" >> \"$path\"; i=$((i + 1)); done; wc -l < \"$path\"",
        shell_quote(remote_path),
        shell_quote(prefix)
    );
    r.remote_root(&command).is_ok()
}

fn sticky_cleanup(
    r: &mut Runner,
    prefix: &str,
    source_id: u64,
    full_path: &str,
    shrink_path: &str,
) {
    if source_id > 0 {
        let _ = r.curl_code("DELETE", &format!("/api/sources/{source_id}"), None);
    }
    cleanup_blocklist_best_effort(r, prefix);
    let _ = restart_remote_service(r);
    let _ = r.remote_root(&format!(
        "rm -f {} {}",
        shell_quote(full_path),
        shell_quote(shrink_path)
    ));
}

fn restart_remote_service(r: &mut Runner) -> bool {
    r.remote_root(
        "systemctl restart rustblocker 2>/dev/null || rc-service rustblocker restart 2>/dev/null",
    )
    .is_ok()
}

fn wait_for_health(r: &mut Runner, web_port: u64, attempts: u64, sleep: u64) -> bool {
    for _ in 0..attempts {
        sleep_secs(sleep);
        if r.curl_code("GET", "/api/health", None).unwrap_or(0) == 200 {
            return true;
        }
        let _ = web_port;
    }
    false
}

fn relogin(r: &mut Runner, password: &str) -> Result<bool, String> {
    Ok(r.curl_code(
        "POST",
        "/api/auth/login",
        Some(json!({"password": password})),
    )? == 200)
}

fn start_slave(
    r: &mut Runner,
    ctx: &BaselineRun,
    slave: &SlavePaths,
    interval_secs: u64,
) -> Result<u64, String> {
    let bin = format!("{}/{}", ctx.remote_install_dir, ctx.binary_name);
    let master_url = format!("http://127.0.0.1:{}", ctx.web_port);
    let _ = r.remote_root(&format!(
        "rm -f {} {} {} {}",
        shell_quote(&slave.db),
        shell_quote(&format!("{}-wal", slave.db)),
        shell_quote(&format!("{}-shm", slave.db)),
        shell_quote(&slave.log)
    ));
    let out = r
        .remote_root(&format!(
            "nohup {} --db-path {} --dns-port {} --web-port {} --force-http --sync-master {} --sync-password {} --sync-interval {} >{} 2>&1 & echo $!",
            shell_quote(&bin),
            shell_quote(&slave.db),
            slave.dns_port,
            slave.web_port,
            shell_quote(&master_url),
            shell_quote(&ctx.webui_password),
            interval_secs,
            shell_quote(&slave.log),
        ))
        .unwrap_or_default();
    let pid = out.trim().parse::<u64>().map_err(|_| out.clone())?;
    if pid > 0 { Ok(pid) } else { Err(out) }
}

fn wait_for_slave_health(r: &mut Runner, ctx: &BaselineRun, web_port: u64) -> bool {
    for _ in 0..15 {
        if r.curl_code(
            "GET",
            &format!("http://{}:{web_port}/api/health", ctx.ssh_host),
            None,
        )
        .unwrap_or(0)
            == 200
        {
            return true;
        }
        sleep_secs(1);
    }
    false
}

fn cleanup_slave(r: &mut Runner, slave: &SlavePaths) {
    if slave.pid > 0 {
        let _ = r.remote_root(&format!(
            "kill {} 2>/dev/null || true; sleep 1; kill -9 {} 2>/dev/null || true",
            slave.pid, slave.pid
        ));
    }
    let _ = r.remote_root(&format!(
        "pkill -f 'rustblocker.*--dns-port {}' 2>/dev/null || true; fuser -k {}/udp {}/tcp {}/tcp 2>/dev/null || true",
        slave.dns_port, slave.dns_port, slave.dns_port, slave.web_port
    ));
    let _ = r.remote_root(&format!(
        "rm -f {} {} {} {}",
        shell_quote(&slave.db),
        shell_quote(&format!("{}-wal", slave.db)),
        shell_quote(&format!("{}-shm", slave.db)),
        shell_quote(&slave.log)
    ));
}

fn remote_dns_a_port(r: &mut Runner, domain: &str, port: u64) -> String {
    let command = format!(
        "domain={}; port={port}; if command -v dig >/dev/null 2>&1; then dig @127.0.0.1 -p \"$port\" +time=2 +tries=1 +short A \"$domain\"; elif command -v drill >/dev/null 2>&1; then drill -p \"$port\" @127.0.0.1 \"$domain\" A | awk '/^[^;].*[[:space:]]A[[:space:]]/ {{ print $NF }}'; elif command -v nslookup >/dev/null 2>&1; then nslookup -type=A -port=$port \"$domain\" 127.0.0.1 | awk '/^Name:/ {{ answer=1 }} answer && /^Address(es)?:/ {{ for (i=2; i<=NF; i++) if ($i ~ /^[0-9.]+$/) print $i }} answer && /^[[:space:]]+[0-9]+\\./ {{ print $1 }}'; else echo '__NO_DNS_TOOL__'; exit 3; fi",
        shell_quote(domain)
    );
    r.ssh_output(&command).unwrap_or_default()
}

fn remote_tail(r: &mut Runner, path: &str, lines: u64) -> String {
    r.remote_root(&format!(
        "tail -n {lines} {} 2>/dev/null",
        shell_quote(path)
    ))
    .unwrap_or_default()
}

fn read_prev_resolver_p95(path: &str) -> Option<u64> {
    let text = fs::read_to_string(Path::new(path)).ok()?;
    let value = serde_json::from_str::<Value>(&text).ok()?;
    value
        .get("dns_warm_p95_ms")
        .or_else(|| value.get("dns_p95_ms"))
        .and_then(Value::as_u64)
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn created_at() -> String {
    let secs = unix_secs() as i64;
    let days = secs.div_euclid(86_400);
    let seconds = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds / 3_600;
    let minute = (seconds % 3_600) / 60;
    let second = seconds % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
