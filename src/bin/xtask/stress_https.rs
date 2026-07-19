use crate::core::{ResourceSnapshot, Runner};
use serde_json::{Value, json};
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn run(r: &mut Runner) -> Result<(), String> {
    dns_concurrency_stress(r)?;
    blocklist_stress(r)?;
    cloudflare_https(r)?;
    auth_password_roundtrip(r)?;
    dns_flood_capacity(r)?;
    Ok(())
}

fn dns_concurrency_stress(r: &mut Runner) -> Result<(), String> {
    let enabled = env_bool_default(r, "MOCK_DNS_CONCURRENCY_STRESS", true);
    let mut status: String;

    let mut elapsed_ms = 0_u64;
    let mut ok_count = 0_u64;
    let mut failures = 0_u64;
    let mut rejected_before = 0_u64;
    let mut rejected_after = 0_u64;

    if !enabled {
        r.skip(
            "dns-concurrency-stress",
            "hardcoded off (MOCK_DNS_CONCURRENCY_STRESS=false)",
        );
        return Ok(());
    }

    status = "running".to_string();
    let note: String = "side process --dns-max-in-flight=1 + blackhole upstream; one-SSH flood proves rejected rises".to_string();
    let requests = env_u64_default(r, "DNS_CONCURRENCY_STRESS_REQUESTS", 256);
    let max_ms = env_u64_default(r, "DNS_CONCURRENCY_STRESS_MAX_MS", 15_000);
    let baseline_file = env_default(
        r,
        "DNS_CONCURRENCY_STRESS_BASELINE_FILE",
        "target/mock-dns-concurrency-stress-baseline.json",
    );
    let dns_port = 1953_u64;
    let web_port = 1954_u64;
    let db = format!("/tmp/rb-dns-conc-{}.db", std::process::id());
    let log = "/tmp/rb-dns-conc-slave.log".to_string();
    let base = format!("http://{}:{web_port}", env_required(r, "SSH_HOST")?);
    let suffix = format!("{}-dns-conc.example.com", run_tag());
    let slave_bin = format!(
        "{}/{}",
        env_default(r, "REMOTE_INSTALL_DIR", "/usr/local/lib/rustblocker"),
        env_default(r, "BINARY_NAME", "rustblocker")
    );
    let mut pid: String;

    let cleanup = |r: &mut Runner, pid: &str| -> Result<(), String> {
        if !pid.is_empty() {
            let _ = r.remote_root(&format!(
                "kill {pid} 2>/dev/null || true; sleep 1; kill -9 {pid} 2>/dev/null || true"
            ));
        }
        let _ = r.remote_root(&format!(
            "pkill -f 'rustblocker.*--dns-port {dns_port}' 2>/dev/null || true; fuser -k {dns_port}/udp {dns_port}/tcp {web_port}/tcp 2>/dev/null || true; rm -f {} {} {} {}",
            sh_quote(&db),
            sh_quote(&format!("{db}-wal")),
            sh_quote(&format!("{db}-shm")),
            sh_quote(&log),
        ));
        Ok(())
    };

    cleanup(r, "")?;
    let start = || {
        format!(
            "nohup {} --db-path {} --dns-port {dns_port} --web-port {web_port} --force-http --dns-max-in-flight 1 >{} 2>&1 & echo $!",
            sh_quote(&slave_bin),
            sh_quote(&db),
            sh_quote(&log),
        )
    };
    let start_out = r.remote_root(&start()).unwrap_or_default();
    pid = start_out.trim().to_string();
    if parse_u64(&pid).unwrap_or(0) == 0 {
        status = "start_failed".to_string();
        r.fail(
            "dns-concurrency-start",
            format!("failed to launch side process out={}", empty(&start_out)),
        );
    } else if wait_url_code(
        &format!("{base}/api/health"),
        200,
        20,
        Duration::from_millis(500),
    ) {
        let _ = r.remote_root(&format!(
            "kill {pid} 2>/dev/null || true; sleep 1; kill -9 {pid} 2>/dev/null || true"
        ));
        if !(r.ssh_status("command -v sqlite3 >/dev/null 2>&1")
            || (env_bool_default(r, "STRESS_INSTALL_SQLITE3", true) && install_sqlite3(r)))
        {
            status = "start_failed".to_string();
            r.fail(
                "dns-concurrency-start",
                "sqlite3 unavailable; cannot seed blackhole upstream",
            );
            cleanup(r, &pid)?;
        } else {
            let seed = format!(
                "sqlite3 {} \"DELETE FROM upstreams; INSERT INTO upstreams(address, port) VALUES('192.0.2.1', 53); UPDATE settings SET value='5' WHERE key='upstream_timeout_secs';\"",
                sh_quote(&db)
            );
            let _ = r.remote_root(&seed);
            let start_out = r.remote_root(&start()).unwrap_or_default();
            pid = start_out.trim().to_string();
            if !wait_url_code(
                &format!("{base}/api/health"),
                200,
                20,
                Duration::from_millis(500),
            ) {
                status = "start_failed".to_string();
                let tail = r
                    .remote_root(&format!("tail -n 40 {} 2>/dev/null", sh_quote(&log)))
                    .unwrap_or_default();
                r.fail(
                    "dns-concurrency-start",
                    format!("health failed pid={} log={}", empty(&pid), empty(&tail)),
                );
                cleanup(r, &pid)?;
            } else {
                let metrics =
                    curl_external_json(&format!("{base}/api/dns/concurrency")).unwrap_or_default();
                if json_u64(&metrics, "max_in_flight") == 1 {
                    r.ok(
                        "dns-concurrency-start",
                        format!(
                            "side pid={pid} max_in_flight=1 blackhole_upstream=192.0.2.1 metrics={metrics}"
                        ),
                    );
                } else {
                    status = "start_failed".to_string();
                    r.fail(
                        "dns-concurrency-start",
                        format!(
                            "expected max_in_flight=1 got metrics={}",
                            empty(&metrics.to_string())
                        ),
                    );
                    cleanup(r, &pid)?;
                }
            }
        }
    } else {
        status = "start_failed".to_string();
        let tail = r
            .remote_root(&format!("tail -n 40 {} 2>/dev/null", sh_quote(&log)))
            .unwrap_or_default();
        r.fail(
            "dns-concurrency-start",
            format!("health failed pid={} log={}", empty(&pid), empty(&tail)),
        );
        cleanup(r, &pid)?;
    }

    if status == "running" {
        let before_json =
            curl_external_json(&format!("{base}/api/dns/concurrency")).unwrap_or_default();
        rejected_before = json_u64(&before_json, "rejected");
        let _ = r.resource_snapshot();
        let started = now_ms();
        let out = r.remote_root(&format!(
            "ok=/tmp/rb-dns-conc-ok-$$; fail=/tmp/rb-dns-conc-fail-$$; : > $ok; : > $fail; i=1; while [ $i -le {requests} ]; do (d=\"q${{i}}.{suffix}\"; if command -v dig >/dev/null 2>&1; then ans=$(dig @127.0.0.1 -p {dns_port} +time=2 +tries=1 +short A \"$d\" 2>/dev/null || true); else ans=; fi; if printf '%s\\n' \"$ans\" | grep -Eq '^[0-9]{{1,3}}(\\.[0-9]{{1,3}}){{3}}$'; then echo 1 >> $ok; else echo 1 >> $fail; fi) & i=$((i + 1)); done; wait; printf '%s %s\\n' \"$(wc -l < $ok | tr -d '[:space:]')\" \"$(wc -l < $fail | tr -d '[:space:]')\"; rm -f $ok $fail"
        )).unwrap_or_default();
        elapsed_ms = now_ms().saturating_sub(started);
        let counts = parse_two_u64s(&out);
        ok_count = counts.0;
        failures = counts.1;
        let after_json =
            curl_external_json(&format!("{base}/api/dns/concurrency")).unwrap_or_default();
        rejected_after = json_u64(&after_json, "rejected");
        let in_flight_after = json_u64(&after_json, "in_flight");
        let health_code = curl_external_code(&format!("{base}/api/health")).unwrap_or(0);

        let fail_detail = if health_code != 200 {
            Some(format!("side health HTTP {health_code}"))
        } else if rejected_after <= rejected_before {
            Some(format!(
                "rejected did not rise (before={rejected_before} after={rejected_after} metrics={after_json})"
            ))
        } else if elapsed_ms > max_ms {
            Some(format!("elapsed={elapsed_ms}ms > max {max_ms}ms"))
        } else {
            None
        };

        if let Some(detail) = fail_detail {
            status = "failed".to_string();
            let tail = r
                .remote_root(&format!("tail -n 30 {} 2>/dev/null", sh_quote(&log)))
                .unwrap_or_default();
            r.fail(
                "dns-concurrency-stress",
                format!(
                    "{detail} (ok={ok_count} failish={failures} log={})",
                    empty(&tail)
                ),
            );
        } else {
            status = "passed".to_string();
            r.ok(
                "dns-concurrency-stress",
                format!(
                    "rejected {rejected_before}->{rejected_after} ok={ok_count} overload_or_fail={failures} elapsed={elapsed_ms}ms in_flight={in_flight_after} health=200"
                ),
            );
        }
    } else {
        r.skip(
            "dns-concurrency-stress",
            "skipped because side process failed to start",
        );
    }

    cleanup(r, &pid)?;
    write_dns_concurrency_stress_baseline(
        r,
        &baseline_file,
        &status,
        requests,
        ok_count,
        failures,
        rejected_before,
        rejected_after,
        elapsed_ms,
        &note,
    )?;
    if status == "passed" {
        r.ok(
            "dns-concurrency-report",
            format!("wrote {baseline_file} status=passed"),
        );
    } else {
        r.fail(
            "dns-concurrency-report",
            format!("wrote {baseline_file} status={status}"),
        );
    }
    Ok(())
}

fn blocklist_stress(r: &mut Runner) -> Result<(), String> {
    if !env_bool_default(r, "MOCK_STRESS_BLOCKLIST", false) {
        r.skip(
            "blocklist-stress",
            "disabled; set MOCK_STRESS_BLOCKLIST=true to discover blocklist capacity baseline",
        );
        return Ok(());
    }

    let tiers = resolve_stress_tiers(r);
    let base = format!("{}-blocklist-stress.rustblocker.test", run_tag());
    let mut total = 0_u64;
    let mut last_ok = 0_u64;
    let mut first_bad = 0_u64;
    let mut status = "not_started".to_string();
    let mut last = StressTierResult::default();
    let mut cleanup_method = "none".to_string();
    let api_cleanup_max = env_u64_default(r, "STRESS_API_CLEANUP_MAX_DOMAINS", 10_000);
    let remote_db = env_default(r, "REMOTE_DB_PATH", "/var/lib/rustblocker/rustblocker.db");

    if r.ssh_status("command -v sqlite3 >/dev/null 2>&1")
        || (env_bool_default(r, "STRESS_INSTALL_SQLITE3", true) && install_sqlite3(r))
    {
        cleanup_method = "sqlite".to_string();
        r.ok(
            "blocklist-stress-prereq",
            format!("cleanup method=sqlite (api cap={api_cleanup_max}, db={remote_db})"),
        );
    } else if tiers.iter().copied().max().unwrap_or(0) <= api_cleanup_max {
        cleanup_method = "api".to_string();
        r.ok(
            "blocklist-stress-prereq",
            format!("cleanup method=api (api cap={api_cleanup_max}, db={remote_db})"),
        );
    } else {
        status = "cleanup_unavailable".to_string();
        r.fail(
            "blocklist-stress-prereq",
            format!("no safe cleanup method: install sqlite3 on target or keep max tier <= STRESS_API_CLEANUP_MAX_DOMAINS ({api_cleanup_max})"),
        );
    }

    let base_rss = if status != "cleanup_unavailable" {
        match r.resource_snapshot() {
            Ok(snap) => {
                status = "running".to_string();
                r.ok(
                    "blocklist-stress-baseline",
                    format!(
                        "base={base} rss={}KB tiers={}",
                        snap.rss_kb,
                        join_u64s(&tiers)
                    ),
                );
                snap.rss_kb
            }
            Err(_) => {
                status = "resource_failed".to_string();
                r.fail(
                    "blocklist-stress-baseline",
                    "could not read process resources before stress",
                );
                0
            }
        }
    } else {
        r.skip(
            "blocklist-stress-baseline",
            "skipped because stress prerequisite failed",
        );
        0
    };

    if status == "running" {
        for tier in &tiers {
            if *tier <= total {
                r.skip(
                    "blocklist-stress-tier",
                    format!("tier {tier} already covered by prior imports"),
                );
                continue;
            }
            let started = now_ms();
            let mut tier_import_ok = true;
            while total < *tier {
                let remaining = tier - total;
                let batch = env_u64_default(r, "STRESS_BLOCKLIST_BATCH", 1_000).min(remaining);
                match stress_import_blocklist_batch(r, &base, total + 1, batch) {
                    Ok(imported) => total += imported,
                    Err(err) => {
                        tier_import_ok = false;
                        last.import_error = err;
                        break;
                    }
                }
            }
            let import_ms = now_ms().saturating_sub(started);
            if !tier_import_ok {
                first_bad = *tier;
                status = "import_failed".to_string();
                r.fail(
                    "blocklist-stress-tier",
                    format!(
                        "tier {tier} import failed after {import_ms}ms ({})",
                        last.import_error
                    ),
                );
                break;
            }
            if !stress_ensure_blocklist_size(r, &base, *tier)? {
                first_bad = *tier;
                status = "api_size_failed".to_string();
                r.fail(
                    "blocklist-stress-tier",
                    format!("tier {tier} imported but API search did not report expected size"),
                );
                break;
            }

            let dns = stress_measure_dns_latency(
                r,
                &base,
                *tier,
                env_u64_default(r, "STRESS_DNS_SAMPLES", 120),
            )?;
            let snap = match r.resource_snapshot() {
                Ok(snap) => snap,
                Err(_) => {
                    first_bad = *tier;
                    status = "resource_failed".to_string();
                    r.fail(
                        "blocklist-stress-tier",
                        format!("tier {tier} could not read process resources"),
                    );
                    break;
                }
            };
            let rss_growth = snap.rss_kb.saturating_sub(base_rss);
            if dns.failures > env_u64_default(r, "STRESS_DNS_MAX_FAILURES", 0)
                || dns.p95_ms > env_u64_default(r, "STRESS_DNS_P95_MAX_MS", 250)
                || dns.max_ms > env_u64_default(r, "STRESS_DNS_MAX_MS", 1_000)
                || rss_growth > env_u64_default(r, "STRESS_RSS_GROWTH_MAX_KB", 131_072)
            {
                first_bad = *tier;
                status = "limit_reached".to_string();
                r.ok(
                    "blocklist-stress-limit",
                    format!(
                        "tier {tier} rejected (p95={}ms max={}ms failures={} rss_growth={}KB sample={})",
                        dns.p95_ms,
                        dns.max_ms,
                        dns.failures,
                        rss_growth,
                        empty(&dns.failure_sample)
                    ),
                );
                break;
            }

            last_ok = *tier;
            last = StressTierResult {
                dns,
                rss_growth,
                rss_kb: snap.rss_kb,
                threads: snap.threads,
                fds: snap.fds,
                import_error: String::new(),
            };
            status = "passed".to_string();
            r.ok(
                "blocklist-stress-tier",
                format!(
                    "tier {tier} accepted: import={import_ms}ms dns_samples={} p95={}ms max={}ms avg={}ms rss={}KB growth={}KB",
                    last.dns.samples,
                    last.dns.p95_ms,
                    last.dns.max_ms,
                    last.dns.avg_ms,
                    last.rss_kb,
                    last.rss_growth,
                ),
            );
        }
    }

    if total > 0 {
        if stress_cleanup_blocklist(r, &cleanup_method, &base)? {
            let left = r.curl_json(
                "GET",
                &format!("/api/blocklist?search={base}&limit=1"),
                None,
            )?;
            let recovery_dns = r.dns_query(&format!("stress-1.{base}")).unwrap_or_default();
            if json_array_empty(&left, "domains") && !has_line(&recovery_dns, &sinkhole_ipv4(r)?) {
                r.ok(
                    "blocklist-stress-recovery",
                    "removed stress prefix and restarted service",
                );
            } else {
                r.fail(
                    "blocklist-stress-recovery",
                    format!(
                        "stress prefix cleanup did not fully recover runtime state (search={left}, dns={})",
                        empty(&recovery_dns)
                    ),
                );
            }
        } else {
            r.fail(
                "blocklist-stress-recovery",
                format!("failed to force-clean stress prefix {base}"),
            );
        }
    } else {
        r.skip(
            "blocklist-stress-recovery",
            "no stress entries were imported",
        );
    }

    let baseline_file = env_default(
        r,
        "STRESS_BASELINE_FILE",
        "target/mock-blocklist-stress-baseline.json",
    );
    if last_ok > 0 {
        write_stress_baseline(
            r,
            &baseline_file,
            &status,
            &tiers,
            last_ok,
            first_bad,
            &last,
        )?;
        let min_domains = env_u64_default(r, "STRESS_BASELINE_MIN_DOMAINS", 0);
        if last_ok < min_domains {
            r.fail(
                "blocklist-stress-baseline",
                format!(
                    "last accepted tier {last_ok} below required baseline {min_domains}; wrote {baseline_file}"
                ),
            );
        } else {
            r.ok(
                "blocklist-stress-baseline",
                format!(
                    "baseline recorded at {last_ok} domains (first rejected={first_bad}, file={baseline_file})"
                ),
            );
        }
    } else if status == "cleanup_unavailable" {
        r.skip(
            "blocklist-stress-baseline",
            "baseline not written because stress prerequisite failed",
        );
    } else {
        write_stress_baseline(
            r,
            &baseline_file,
            &status,
            &tiers,
            0,
            first_bad,
            &StressTierResult::default(),
        )?;
        r.fail(
            "blocklist-stress-baseline",
            format!("no acceptable stress tier found; wrote {baseline_file}"),
        );
    }
    Ok(())
}

fn cloudflare_https(r: &mut Runner) -> Result<(), String> {
    if !env_bool_default(r, "ENABLE_CLOUDFLARE_HTTPS", false) {
        r.skip(
            "cloudflare-https",
            "disabled; set ENABLE_CLOUDFLARE_HTTPS=true in .deployenv to run Cloudflare, ACME, and HTTPS checks",
        );
        return Ok(());
    }

    for (key, env_key, default) in [
        ("domain", "DOMAIN", ""),
        ("acme_email", "ACME_EMAIL", ""),
        ("cloudflare_api_token", "CF_TOKEN", ""),
        ("wildcard_cert", "WILDCARD", "false"),
    ] {
        let value = env_default(r, env_key, default);
        if value.is_empty() {
            r.skip("configure", format!("{key} not set"));
            continue;
        }
        let code = r.curl_code(
            "PUT",
            "/api/settings",
            Some(json!({ "key": key, "value": value })),
        )?;
        if code == 200 {
            r.ok("configure", format!("{key} = {}", mask_value(&value)));
        } else {
            r.fail("configure", format!("{key} -> HTTP {code}"));
        }
    }

    let cf_token = env_default(r, "CF_TOKEN", "");
    if cf_token.is_empty() {
        r.skip("cf-test", "CF_TOKEN not set");
    } else {
        let resp = r.curl_json(
            "POST",
            "/api/cloudflare/test",
            Some(json!({ "api_token": cf_token })),
        )?;
        if resp.get("ok").and_then(Value::as_bool) == Some(true) {
            r.ok("cf-test", "token valid");
        } else {
            r.fail(
                "cf-test",
                resp.get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("invalid token"),
            );
        }
    }

    let domain = env_default(r, "DOMAIN", "");
    if domain.is_empty() {
        r.skip("acme", "DOMAIN not set");
        return Ok(());
    }

    let before_pid = r
        .ssh_output("pgrep -f '/usr/local/lib/rustblocker/rustblocker' | head -1")
        .unwrap_or_default()
        .trim()
        .to_string();
    let before = r
        .curl_json("GET", "/api/acme/status", None)
        .unwrap_or_else(|_| json!({}));
    let before_renewed = json_u64(&before, "last_renewed");
    let before_days = json_u64(&before, "days_remaining");
    let threshold = json_u64(&before, "auto_renewal_threshold_days").max(7);
    let mut got_cert = false;
    let mut poll_failed = false;
    let mut expect_restart = true;

    if before.get("has_certificate").and_then(Value::as_bool) == Some(true)
        && before_days > threshold
        && !env_bool_default(r, "FORCE_ACME", false)
    {
        r.skip(
            "acme-request",
            format!(
                "valid certificate already present ({before_days}d remaining); set FORCE_ACME=true to request a fresh cert"
            ),
        );
        got_cert = true;
        expect_restart = false;
    } else {
        let wildcard = env_bool_default(r, "WILDCARD", false);
        let resp = r.curl_json(
            "POST",
            "/api/acme/request",
            Some(json!({ "domain": domain, "wildcard": wildcard })),
        )?;
        let op_id = resp.get("op_id").and_then(Value::as_str).unwrap_or("");
        if op_id.is_empty() {
            r.fail("acme-request", "request rejected");
        } else {
            r.ok("acme-request", format!("accepted op_id={op_id}"));
            r.ok(
                "acme-poll",
                format!("polling for certificate (op_id={op_id})..."),
            );
            let attempts = env_u64_default(r, "ACME_POLL_ATTEMPTS", 30);
            for i in 1..=attempts {
                thread::sleep(Duration::from_secs(10));
                let status = r
                    .curl_json("GET", "/api/acme/status", None)
                    .unwrap_or_default();
                if status.get("has_certificate").and_then(Value::as_bool) == Some(true) {
                    let current = json_u64(&status, "last_renewed");
                    if before_renewed == 0 || (current != 0 && current != before_renewed) {
                        let days = json_u64(&status, "days_remaining");
                        r.ok(
                            "acme-poll",
                            format!(
                                "certificate obtained ({}d remaining) after {}s",
                                display_u64(days),
                                i * 10
                            ),
                        );
                        got_cert = true;
                        break;
                    }
                }
                if let Some(err) = status.get("acme_error").and_then(Value::as_str) {
                    r.fail(
                        "acme-poll",
                        if err.is_empty() {
                            "ACME request failed"
                        } else {
                            err
                        },
                    );
                    poll_failed = true;
                    break;
                }
                eprintln!(
                    "{}",
                    json!({"name":"acme-poll","status":"ok","detail":format!("still waiting ({}s)...", i * 10)})
                );
            }
            if !got_cert && !poll_failed {
                r.fail(
                    "acme-poll",
                    format!(
                        "timeout after {}s — check Activity Log in web UI",
                        attempts * 10
                    ),
                );
                let _ = r.ssh_output("tail -n 120 /var/log/rustblocker.log 2>/dev/null || true");
            }
        }
    }

    if got_cert {
        if expect_restart {
            let mut after_pid = String::new();
            let mut restarted = false;
            for _ in 0..20 {
                thread::sleep(Duration::from_secs(1));
                after_pid = r
                    .ssh_output("pgrep -f '/usr/local/lib/rustblocker/rustblocker' | head -1")
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                if !before_pid.is_empty() && !after_pid.is_empty() && before_pid != after_pid {
                    restarted = true;
                    break;
                }
            }
            if restarted {
                r.ok(
                    "https",
                    format!("automatic restart observed ({before_pid} -> {after_pid})"),
                );
            } else {
                r.fail("https", "automatic restart was not observed");
            }
        } else {
            r.skip(
                "https",
                "automatic restart not required for existing valid certificate",
            );
        }

        let url = format!("https://{domain}/api/health");
        let mut https_ok = false;
        let mut waited = 0;
        for i in 1..=20 {
            thread::sleep(Duration::from_secs(2));
            waited = i * 2;
            if curl_external_code_insecure(&url).unwrap_or(0) == 200 {
                https_ok = true;
                break;
            }
        }
        if https_ok {
            if expect_restart {
                r.ok(
                    "https",
                    format!("HTTPS health check passed after automatic restart (after {waited}s)"),
                );
            } else {
                r.ok(
                    "https",
                    format!("HTTPS health check passed (after {waited}s)"),
                );
            }
        } else {
            r.fail("https", "HTTPS health check failed");
            let _ = r.ssh_output("rc-service rustblocker status 2>/dev/null || systemctl status rustblocker --no-pager 2>/dev/null || true; tail -n 80 /var/log/rustblocker.log 2>/dev/null || true");
        }
    }
    Ok(())
}

fn auth_password_roundtrip(r: &mut Runner) -> Result<(), String> {
    let webui_password = env_required(r, "WEBUI_PASSWORD")?;
    let new_password = format!("MockedNewPass-{}{}", unix_secs(), std::process::id());

    let wrong = r.curl_code(
        "PUT",
        "/api/auth/password",
        Some(json!({
            "current_password": format!("wrong-password-{}", unix_secs()),
            "new_password": "ValidNewP1",
        })),
    )?;
    if wrong == 401 {
        r.ok(
            "auth-change-wrong-current",
            "wrong current password rejected (HTTP 401)",
        );
    } else {
        r.fail(
            "auth-change-wrong-current",
            format!("expected 401 for wrong current password, got HTTP {wrong}"),
        );
    }

    let short = r.curl_code(
        "PUT",
        "/api/auth/password",
        Some(json!({ "current_password": webui_password, "new_password": "ab" })),
    )?;
    if short == 400 {
        r.ok(
            "auth-change-short",
            "short new password rejected (HTTP 400)",
        );
    } else {
        r.fail(
            "auth-change-short",
            format!("expected 400 for short password, got HTTP {short}"),
        );
    }

    let change = r.curl_code(
        "PUT",
        "/api/auth/password",
        Some(json!({ "current_password": webui_password, "new_password": new_password })),
    )?;
    if change == 200 {
        r.ok(
            "auth-change-valid",
            "password changed via hash_password Result path (HTTP 200)",
        );
    } else {
        let body = r
            .curl_body("PUT", "/api/auth/password", None)
            .map(|response| response.body)
            .unwrap_or_default();
        r.fail(
            "auth-change-valid",
            format!(
                "expected 200 for valid password change, got HTTP {change} (body: {})",
                empty(&body)
            ),
        );
    }

    let relogin = r.curl_code(
        "POST",
        "/api/auth/login",
        Some(json!({ "password": new_password })),
    )?;
    if relogin == 200 {
        r.ok(
            "auth-change-relogin",
            "re-login with new password succeeded (HTTP 200)",
        );
    } else {
        r.fail(
            "auth-change-relogin",
            format!("expected 200 re-login with new password, got HTTP {relogin}"),
        );
    }

    let revert = r.curl_code(
        "PUT",
        "/api/auth/password",
        Some(json!({ "current_password": new_password, "new_password": webui_password })),
    )?;
    if revert == 200 {
        r.ok(
            "auth-change-revert",
            "password reverted to original (HTTP 200)",
        );
    } else {
        r.fail(
            "auth-change-revert",
            format!("expected 200 revert, got HTTP {revert}"),
        );
    }

    let restore = r.curl_code(
        "POST",
        "/api/auth/login",
        Some(json!({ "password": webui_password })),
    )?;
    if restore == 200 {
        r.ok(
            "auth-change-restore",
            "session restored with original password (HTTP 200)",
        );
    } else {
        r.fail(
            "auth-change-restore",
            format!("expected 200 restore login, got HTTP {restore}"),
        );
    }

    let health = r.curl_code("GET", "/api/health", None)?;
    if health == 200 {
        r.ok(
            "panic-free-health",
            "health ok after password round-trip, worker survived bcrypt + session rotation",
        );
    } else {
        r.fail(
            "panic-free-health",
            "health check failed after password round-trip, worker may have panicked",
        );
    }
    Ok(())
}

fn dns_flood_capacity(r: &mut Runner) -> Result<(), String> {
    if !env_bool_default(r, "MOCK_DNS_FLOOD_CAPACITY", true) {
        r.skip("dns-flood-capacity", "disabled");
        return Ok(());
    }

    let tiers = env_u64_list(r, "DNS_FLOOD_CAPACITY_TIERS", &[256, 512, 1024, 2048, 4096]);
    let baseline_file = env_default(
        r,
        "DNS_FLOOD_CAPACITY_BASELINE_FILE",
        "target/mock-dns-flood-capacity-baseline.json",
    );
    let max_ms = env_u64_default(r, "DNS_FLOOD_CAPACITY_MAX_MS", 30_000);
    let min_ok = env_u64_default(r, "DNS_FLOOD_CAPACITY_MIN_OK", 256);
    let max_fail_pct = env_u64_default(r, "DNS_FLOOD_CAPACITY_MAX_FAILURE_PCT", 5);
    let mut status = "running".to_string();
    let mut last_ok = 0_u64;
    let mut first_bad = 0_u64;
    let mut last_qps = 0_u64;
    let mut last_rejected_delta = 0_u64;
    let mut last_snapshot = ResourceLite::default();

    let metrics_before = r
        .curl_json("GET", "/api/dns/concurrency", None)
        .unwrap_or_else(|_| json!({}));
    let rejected_before = json_u64(&metrics_before, "rejected");
    if r.ssh_status("command -v dig >/dev/null 2>&1") {
        r.ok(
            "dns-flood-capacity",
            format!(
                "starting tiers={} rejected_before={rejected_before}",
                join_u64s(&tiers)
            ),
        );
    } else {
        status = "failed".to_string();
        r.fail(
            "dns-flood-capacity",
            "dig missing on target; cannot run box-local flood",
        );
    }

    for tier in &tiers {
        if status != "running" {
            break;
        }
        let prefix = format!("{}-cap-{tier}.example.com", run_tag());
        let started = now_ms();
        let out = r.remote_root(&format!(
            "ok=/tmp/rb-dns-cap-ok-$$; fail=/tmp/rb-dns-cap-fail-$$; : > $ok; : > $fail; i=1; while [ $i -le {tier} ]; do (d=\"q${{i}}.{prefix}\"; dig @127.0.0.1 +time=2 +tries=1 +short A \"$d\" >/tmp/rb-dns-cap-one-$$-$i 2>/dev/null && echo 1 >> $ok || echo 1 >> $fail; rm -f /tmp/rb-dns-cap-one-$$-$i) & i=$((i + 1)); done; wait; printf '%s %s\\n' \"$(wc -l < $ok | tr -d '[:space:]')\" \"$(wc -l < $fail | tr -d '[:space:]')\"; rm -f $ok $fail"
        )).unwrap_or_default();
        let elapsed_ms = now_ms().saturating_sub(started).max(1);
        let (cap_ok, cap_fail) = parse_two_u64s(&out);
        let qps = cap_ok * 1_000 / elapsed_ms;
        let health = r.curl_code("GET", "/api/health", None).unwrap_or(0);
        let metrics_after = r
            .curl_json("GET", "/api/dns/concurrency", None)
            .unwrap_or_else(|_| json!({}));
        let rejected_after = json_u64(&metrics_after, "rejected");
        let rejected_delta = rejected_after.saturating_sub(rejected_before);
        let in_flight = json_u64(&metrics_after, "in_flight");
        if let Ok(snap) = r.resource_snapshot() {
            last_snapshot = ResourceLite::from(snap);
        }
        let fail_pct = cap_fail * 100 / tier;
        let detail = format!(
            "tier={tier} ok={cap_ok} fail={cap_fail} fail_pct={fail_pct}% elapsed={elapsed_ms}ms qps={qps} rejected_delta={rejected_delta} in_flight={in_flight} rss={}KB threads={} fds={} health={health}",
            last_snapshot.rss_kb, last_snapshot.threads, last_snapshot.fds
        );
        if health == 200
            && cap_ok >= min_ok
            && fail_pct <= max_fail_pct
            && elapsed_ms <= max_ms
            && last_snapshot.rss_kb <= env_u64_default(r, "MEMORY_RSS_MAX_KB", 262_144)
            && last_snapshot.threads <= env_u64_default(r, "PROCESS_THREADS_MAX", 128)
            && last_snapshot.fds <= env_u64_default(r, "PROCESS_FD_MAX", 1_024)
        {
            last_ok = *tier;
            last_qps = qps;
            last_rejected_delta = rejected_delta;
            r.ok("dns-flood-capacity", &detail);
        } else {
            first_bad = *tier;
            status = "passed".to_string();
            r.ok(
                "dns-flood-capacity",
                format!("capacity ceiling reached: {detail}"),
            );
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }

    if status == "running" {
        status = "passed".to_string();
    }
    write_dns_flood_capacity_baseline(
        r,
        &baseline_file,
        &status,
        &tiers,
        last_ok,
        first_bad,
        last_qps,
        last_rejected_delta,
        &last_snapshot,
    )?;
    if last_ok > 0 {
        r.ok(
            "dns-flood-capacity-report",
            format!("last_ok={last_ok} qps={last_qps} first_bad={first_bad} wrote {baseline_file}"),
        );
    } else {
        r.fail(
            "dns-flood-capacity-report",
            format!("no passing tier; wrote {baseline_file}"),
        );
    }
    Ok(())
}

#[derive(Default)]
struct DnsLatencyStats {
    samples: u64,
    p95_ms: u64,
    max_ms: u64,
    avg_ms: u64,
    failures: u64,
    failure_sample: String,
}

#[derive(Default)]
struct StressTierResult {
    dns: DnsLatencyStats,
    rss_growth: u64,
    rss_kb: u64,
    threads: u64,
    fds: u64,
    import_error: String,
}

#[derive(Default)]
struct ResourceLite {
    rss_kb: u64,
    threads: u64,
    fds: u64,
}

impl From<ResourceSnapshot> for ResourceLite {
    fn from(value: ResourceSnapshot) -> Self {
        Self {
            rss_kb: value.rss_kb,
            threads: value.threads,
            fds: value.fds,
        }
    }
}

fn stress_import_blocklist_batch(
    r: &mut Runner,
    base: &str,
    start: u64,
    count: u64,
) -> Result<u64, String> {
    let mut content = String::new();
    for i in start..start + count {
        content.push_str("0.0.0.0 stress-");
        content.push_str(&i.to_string());
        content.push('.');
        content.push_str(base);
        content.push('\n');
    }
    let body = r.curl_json(
        "POST",
        "/api/blocklist/import",
        Some(json!({ "content": content })),
    )?;
    let imported = json_u64(&body, "imported");
    if imported >= count {
        Ok(imported)
    } else {
        Err(format!("HTTP 200 response: {body}"))
    }
}

fn stress_ensure_blocklist_size(r: &mut Runner, base: &str, expected: u64) -> Result<bool, String> {
    let search = r.curl_json(
        "GET",
        &format!("/api/blocklist?search={base}&limit=1"),
        None,
    )?;
    Ok(json_u64(&search, "total") >= expected)
}

fn stress_measure_dns_latency(
    r: &mut Runner,
    base: &str,
    domain_count: u64,
    samples: u64,
) -> Result<DnsLatencyStats, String> {
    let sinkhole = sinkhole_ipv4(r)?;
    let sample_count = samples.min(domain_count).max(1);
    let mut latencies = Vec::with_capacity(sample_count as usize);
    let mut failures = Vec::new();
    for i in 1..=sample_count {
        let index = ((i - 1) * domain_count / sample_count) + 1;
        let domain = format!("stress-{index}.{base}");
        let started = now_ms();
        let answer = r.dns_query(&domain).unwrap_or_default();
        latencies.push(now_ms().saturating_sub(started));
        if !has_line(&answer, &sinkhole) {
            failures.push(format!(
                "{domain} expected={sinkhole} got={}",
                empty(&answer)
            ));
        }
    }
    latencies.sort_unstable();
    let samples = latencies.len() as u64;
    let avg_ms = latencies
        .iter()
        .sum::<u64>()
        .checked_div(samples)
        .unwrap_or(0);
    let idx95 = (samples * 95).div_ceil(100).saturating_sub(1) as usize;
    Ok(DnsLatencyStats {
        samples,
        p95_ms: *latencies.get(idx95).unwrap_or(&0),
        max_ms: *latencies.last().unwrap_or(&0),
        avg_ms,
        failures: failures.len() as u64,
        failure_sample: failures.first().cloned().unwrap_or_default(),
    })
}

fn stress_cleanup_blocklist(r: &mut Runner, method: &str, prefix: &str) -> Result<bool, String> {
    let ok = if method == "sqlite" {
        r.cleanup_blocklist_sqlite(prefix).is_ok()
    } else {
        r.cleanup_blocklist_api(
            prefix,
            env_u64_default(r, "STRESS_API_CLEANUP_PAGE_SIZE", 250),
            200,
        )
        .is_ok()
    };
    if ok {
        let _ = r.remote_root("systemctl restart rustblocker 2>/dev/null || rc-service rustblocker restart 2>/dev/null");
        Ok(wait_health(r, 15, Duration::from_secs(2)))
    } else {
        Ok(false)
    }
}

fn install_sqlite3(r: &mut Runner) -> bool {
    r.remote_root("if command -v sqlite3 >/dev/null 2>&1; then exit 0; elif command -v apk >/dev/null 2>&1; then apk add --no-cache sqlite; elif command -v apt-get >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y sqlite3; elif command -v dnf >/dev/null 2>&1; then dnf install -y sqlite; elif command -v yum >/dev/null 2>&1; then yum install -y sqlite; else exit 2; fi; command -v sqlite3 >/dev/null 2>&1").is_ok()
}

fn wait_health(r: &mut Runner, attempts: usize, delay: Duration) -> bool {
    for _ in 0..attempts {
        if r.curl_code("GET", "/api/health", None).unwrap_or(0) == 200 {
            return true;
        }
        thread::sleep(delay);
    }
    false
}

#[allow(clippy::too_many_arguments)]
fn write_dns_concurrency_stress_baseline(
    r: &mut Runner,
    path: &str,
    status: &str,
    requests: u64,
    ok_count: u64,
    failures: u64,
    rejected_before: u64,
    rejected_after: u64,
    elapsed_ms: u64,
    note: &str,
) -> Result<(), String> {
    r.write_baseline_json(
        Path::new(path),
        json!({
            "status": status,
            "build_id": env_default(r, "MOCK_BUILD_ID", &format!("mock-{}-{}", unix_secs(), git_rev())),
            "git_rev": git_rev(),
            "dns_max_in_flight": 1,
            "requests": requests,
            "ok": ok_count,
            "overload_or_fail": failures,
            "rejected_before": rejected_before,
            "rejected_after": rejected_after,
            "elapsed_ms": elapsed_ms,
            "note": note,
            "created_at": created_at(),
        }),
    )
}

fn write_stress_baseline(
    r: &mut Runner,
    path: &str,
    status: &str,
    tiers: &[u64],
    last_ok: u64,
    first_bad: u64,
    last: &StressTierResult,
) -> Result<(), String> {
    r.write_baseline_json(
        Path::new(path),
        json!({
            "status": status,
            "git_rev": git_rev(),
            "target": env_default(r, "SSH_HOST", ""),
            "tier_mode": env_default(r, "STRESS_BLOCKLIST_TIERS", "auto"),
            "tiers": join_u64s(tiers),
            "last_accepted_domains": last_ok,
            "first_rejected_domains": first_bad,
            "dns_samples": last.dns.samples,
            "dns_p95_ms": last.dns.p95_ms,
            "dns_max_ms": last.dns.max_ms,
            "dns_failures": last.dns.failures,
            "rss_growth_kb": last.rss_growth,
            "rss_kb": last.rss_kb,
            "threads": last.threads,
            "fds": last.fds,
            "created_at": created_at(),
        }),
    )
}

#[allow(clippy::too_many_arguments)]
fn write_dns_flood_capacity_baseline(
    r: &mut Runner,
    path: &str,
    status: &str,
    tiers: &[u64],
    last_ok: u64,
    first_bad: u64,
    last_qps: u64,
    last_rejected_delta: u64,
    last_snapshot: &ResourceLite,
) -> Result<(), String> {
    r.write_baseline_json(
        Path::new(path),
        json!({
            "status": status,
            "build_id": env_default(r, "MOCK_BUILD_ID", &format!("mock-{}-{}", unix_secs(), git_rev())),
            "git_rev": git_rev(),
            "tiers": join_u64s(tiers),
            "last_ok_queries": last_ok,
            "first_bad_queries": first_bad,
            "last_qps": last_qps,
            "last_rejected_delta": last_rejected_delta,
            "rss_kb": last_snapshot.rss_kb,
            "threads": last_snapshot.threads,
            "fds": last_snapshot.fds,
            "created_at": created_at(),
        }),
    )
}

fn resolve_stress_tiers(r: &mut Runner) -> Vec<u64> {
    let configured = env_default(r, "STRESS_BLOCKLIST_TIERS", "auto");
    if configured != "auto" {
        return parse_u64_list(&configured);
    }
    let baseline_file = env_default(
        r,
        "STRESS_BASELINE_FILE",
        "target/mock-blocklist-stress-baseline.json",
    );
    let current = std::fs::read_to_string(&baseline_file)
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .map(|value| json_u64(&value, "last_accepted_domains"))
        .unwrap_or(0);
    let mut current = current;
    let max = env_u64_default(r, "STRESS_AUTO_MAX_DOMAINS", 0);
    let multiplier = env_u64_default(r, "STRESS_AUTO_MULTIPLIER", 2);
    let passes = env_u64_default(r, "STRESS_AUTO_PASSES", 1);
    let mut tiers = Vec::new();
    for _ in 0..passes {
        let mut next = if current > 0 {
            current.saturating_mul(multiplier)
        } else {
            env_u64_default(r, "STRESS_AUTO_START_DOMAINS", 10_000)
        };
        if max > 0 && next > max {
            next = max;
        }
        if next <= current {
            break;
        }
        tiers.push(next);
        current = next;
    }
    if tiers.is_empty() {
        tiers.push(env_u64_default(r, "STRESS_AUTO_START_DOMAINS", 10_000));
    }
    tiers
}

fn sinkhole_ipv4(r: &mut Runner) -> Result<String, String> {
    let settings = r.curl_json("GET", "/api/settings", None)?;
    Ok(settings
        .get("sinkhole_ipv4")
        .and_then(Value::as_str)
        .unwrap_or("0.0.0.0")
        .to_string())
}

fn curl_external_json(url: &str) -> Result<Value, String> {
    let output = Command::new("curl")
        .args(["-sS", "--connect-timeout", "2", "--max-time", "5", url])
        .output()
        .map_err(|err| format!("start curl: {err}"))?;
    if !output.status.success() {
        return Err(format!("curl exited {:?}", output.status.code()));
    }
    serde_json::from_slice(&output.stdout).map_err(|err| format!("parse curl json: {err}"))
}

fn curl_external_code(url: &str) -> Result<u16, String> {
    curl_code_args([
        "-s",
        "--connect-timeout",
        "2",
        "--max-time",
        "3",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        url,
    ])
}

fn curl_external_code_insecure(url: &str) -> Result<u16, String> {
    curl_code_args([
        "-s",
        "-k",
        "--connect-timeout",
        "2",
        "--max-time",
        "5",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        url,
    ])
}

fn curl_code_args<const N: usize>(args: [&str; N]) -> Result<u16, String> {
    let output = Command::new("curl")
        .args(args)
        .output()
        .map_err(|err| format!("start curl: {err}"))?;
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u16>()
        .map_err(|err| format!("parse curl code: {err}"))
}

fn wait_url_code(url: &str, expected: u16, attempts: usize, delay: Duration) -> bool {
    for _ in 0..attempts {
        if curl_external_code(url).unwrap_or(0) == expected {
            return true;
        }
        thread::sleep(delay);
    }
    false
}

fn env_required(r: &Runner, key: &str) -> Result<String, String> {
    r.env(key).ok_or_else(|| format!("{key} required"))
}

fn env_default(r: &Runner, key: &str, default: &str) -> String {
    r.env(key).unwrap_or_else(|| default.to_string())
}

fn env_bool_default(r: &Runner, key: &str, default: bool) -> bool {
    match r.env(key) {
        Some(value) => matches!(
            value.as_str(),
            "true" | "TRUE" | "1" | "yes" | "YES" | "on" | "ON"
        ),
        None => default,
    }
}

fn env_u64_default(r: &Runner, key: &str, default: u64) -> u64 {
    r.env_u64(key).unwrap_or(default)
}

fn env_u64_list(r: &Runner, key: &str, default: &[u64]) -> Vec<u64> {
    let text = env_default(r, key, &join_u64s(default));
    let parsed = parse_u64_list(&text);
    if parsed.is_empty() {
        default.to_vec()
    } else {
        parsed
    }
}

fn parse_u64_list(text: &str) -> Vec<u64> {
    text.split_whitespace().filter_map(parse_u64).collect()
}

fn parse_u64(text: &str) -> Option<u64> {
    text.trim().parse::<u64>().ok()
}

fn parse_two_u64s(text: &str) -> (u64, u64) {
    let mut values = text.split_whitespace().filter_map(parse_u64);
    (values.next().unwrap_or(0), values.next().unwrap_or(0))
}

fn json_u64(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or(0)
}

fn json_array_empty(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::is_empty)
        .unwrap_or(false)
}

fn has_line(text: &str, expected: &str) -> bool {
    text.lines().any(|line| line.trim() == expected)
}

fn join_u64s(values: &[u64]) -> String {
    values
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(" ")
}

fn empty(value: &str) -> &str {
    if value.trim().is_empty() {
        "empty"
    } else {
        value.trim()
    }
}

fn display_u64(value: u64) -> String {
    if value == 0 {
        "?".to_string()
    } else {
        value.to_string()
    }
}

fn mask_value(value: &str) -> String {
    if value.len() > 20 {
        let head = &value[..4];
        let tail = &value[value.len() - 4..];
        format!("{head}...{tail}")
    } else {
        value.to_string()
    }
}

fn sh_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn run_tag() -> String {
    format!("mock-{}-{}", unix_secs(), std::process::id())
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn created_at() -> String {
    let output = Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    output.unwrap_or_else(|| unix_secs().to_string())
}

fn git_rev() -> String {
    Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "nogit".to_string())
}
