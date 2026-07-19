use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const BINARY_NAME: &str = "rustblocker";
const REMOTE_INSTALL_DIR: &str = "/usr/local/lib/rustblocker";

#[derive(Debug, Clone)]
pub struct Config {
    pub deployenv: PathBuf,
    pub report_dir: PathBuf,
    pub compare: Option<PathBuf>,
    pub skip_build: bool,
    pub skip_deploy: bool,
    pub timeout_secs: u64,
    values: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct CurlResponse {
    pub code: u16,
    pub body: String,
}

#[derive(Debug, Clone, Copy)]
pub struct ResourceSnapshot {
    pub pid: u64,
    pub rss_kb: u64,
    pub threads: u64,
    pub fds: u64,
}

pub struct Runner {
    pub config: Config,
    step: u64,
    failed: bool,
    run_jsonl: PathBuf,
    cookie_jar: PathBuf,
    summary_json: PathBuf,
    compare_json: PathBuf,
    remote: String,
}

pub fn mock_deploy(raw_args: Vec<String>) -> Result<(), String> {
    let config = Config::load(raw_args)?;
    fs::create_dir_all(&config.report_dir)
        .map_err(|err| format!("create {}: {err}", config.report_dir.display()))?;

    let mut runner = Runner::new(config)?;
    let result = runner.run();
    let summary = runner.write_summary(if result.is_ok() { 0 } else { 1 })?;
    println!("xtask: summary={}", runner.summary_json.display());

    if let Some(previous) = runner.config.compare.as_ref() {
        let comparison = compare_summaries(previous, &runner.summary_json)?;
        write_json(&runner.compare_json, &comparison)?;
        println!("xtask: compare={}", runner.compare_json.display());
    }

    result.and_then(|_| {
        if summary.get("status").and_then(Value::as_str) == Some("ok") {
            Ok(())
        } else {
            Err("mock deploy failed".to_string())
        }
    })
}

impl Config {
    fn load(raw_args: Vec<String>) -> Result<Self, String> {
        let mut deployenv = PathBuf::from("scripts/.deployenv");
        let mut report_dir = PathBuf::from("target")
            .join("xtask-mock-deploy")
            .join(default_run_id());
        let mut compare = None;
        let mut skip_build = false;
        let mut skip_deploy = false;
        let mut timeout_secs = 30;

        for arg in raw_args {
            if let Some(value) = arg.strip_prefix("--report-dir=") {
                report_dir = PathBuf::from(value);
            } else if let Some(value) = arg.strip_prefix("--compare=") {
                compare = Some(PathBuf::from(value));
            } else if let Some(value) = arg.strip_prefix("--deployenv=") {
                deployenv = PathBuf::from(value);
            } else if let Some(value) = arg.strip_prefix("--timeout=") {
                timeout_secs = value
                    .parse::<u64>()
                    .map_err(|err| format!("invalid --timeout={value}: {err}"))?;
            } else if arg == "--skip-build" {
                skip_build = true;
            } else if arg == "--skip-deploy" {
                skip_deploy = true;
            } else if arg == "--help" || arg == "-h" {
                usage_mock_deploy();
                std::process::exit(0);
            } else {
                return Err(format!("unknown mock-deploy arg: {arg}"));
            }
        }

        let mut values = parse_deployenv(&deployenv)?;
        apply_defaults(&mut values);
        for key in ["SSH_HOST", "SSH_USER", "SSH_PASSWORD", "WEBUI_PASSWORD"] {
            let present = env::var(key).ok().or_else(|| values.get(key).cloned());
            if present.is_none_or(|value| value.is_empty()) {
                return Err(format!("{key} missing in {}", deployenv.display()));
            }
        }

        Ok(Self {
            deployenv,
            report_dir,
            compare,
            skip_build,
            skip_deploy,
            timeout_secs,
            values,
        })
    }

    pub fn env(&self, key: &str) -> Option<String> {
        env::var(key).ok().or_else(|| self.values.get(key).cloned())
    }

    pub fn env_or(&self, key: &str, default: &str) -> String {
        self.env(key).unwrap_or_else(|| default.to_string())
    }

    pub fn env_bool(&self, key: &str) -> bool {
        self.env(key).is_some_and(|value| {
            matches!(
                value.as_str(),
                "true" | "TRUE" | "1" | "yes" | "YES" | "on" | "ON"
            )
        })
    }

    pub fn env_u64(&self, key: &str) -> Option<u64> {
        self.env(key).and_then(|value| value.parse::<u64>().ok())
    }

    pub fn env_u64_or(&self, key: &str, default: u64) -> u64 {
        self.env_u64(key).unwrap_or(default)
    }

    pub fn base_url(&self) -> String {
        format!(
            "http://{}:{}",
            self.env_or("SSH_HOST", ""),
            self.env_or("WEB_PORT", "54")
        )
    }
}

#[allow(dead_code)]
impl Runner {
    fn new(config: Config) -> Result<Self, String> {
        let run_jsonl = config.report_dir.join("run.jsonl");
        let summary_json = config.report_dir.join("summary.json");
        let compare_json = config.report_dir.join("compare.json");
        let cookie_jar = config.report_dir.join("cookie.jar");
        File::create(&run_jsonl).map_err(|err| format!("create {}: {err}", run_jsonl.display()))?;
        File::create(&cookie_jar)
            .map_err(|err| format!("create {}: {err}", cookie_jar.display()))?;
        let remote = format!(
            "{}@{}",
            config.env_or("SSH_USER", ""),
            config.env_or("SSH_HOST", "")
        );
        Ok(Self {
            config,
            step: 0,
            failed: false,
            run_jsonl,
            cookie_jar,
            summary_json,
            compare_json,
            remote,
        })
    }

    fn run(&mut self) -> Result<(), String> {
        self.ok_at(
            0,
            "env",
            format!("loaded {}", self.config.deployenv.display()),
        );
        let target = self.detect_target()?;
        self.build(&target)?;
        self.deploy(&target)?;
        self.login()?;
        let settings = self.settings()?;
        self.resource_baseline();
        self.forward_strategy(&settings)?;
        self.adaptive_hedge_delay(&settings)?;
        self.forward_strategy_dns(&settings)?;
        self.version()?;
        self.db_api()?;
        self.stats_concurrency()?;
        self.run_group_hooks()?;
        if self.failed {
            Err("one or more mock deploy steps failed".to_string())
        } else {
            Ok(())
        }
    }

    pub fn env(&self, key: &str) -> Option<String> {
        self.config.env(key)
    }

    pub fn env_or(&self, key: &str, default: &str) -> String {
        self.config.env_or(key, default)
    }

    pub fn env_bool(&self, key: &str) -> bool {
        self.config.env_bool(key)
    }

    pub fn env_u64(&self, key: &str) -> Option<u64> {
        self.config.env_u64(key)
    }

    pub fn env_u64_or(&self, key: &str, default: u64) -> u64 {
        self.config.env_u64_or(key, default)
    }

    pub fn base_url(&self) -> String {
        self.config.base_url()
    }

    pub fn step(&mut self) -> u64 {
        self.step += 1;
        self.step
    }

    pub fn ok(&mut self, name: &str, detail: impl AsRef<str>) {
        let step = self.step();
        self.ok_at(step, name, detail);
    }

    pub fn fail(&mut self, name: &str, detail: impl AsRef<str>) {
        let step = self.step();
        self.fail_at(step, name, detail);
    }

    pub fn skip(&mut self, name: &str, detail: impl AsRef<str>) {
        let step = self.step();
        self.skip_at(step, name, detail);
    }

    pub fn ok_at(&mut self, step: u64, name: &str, detail: impl AsRef<str>) {
        self.event(step, name, "ok", detail.as_ref());
    }

    pub fn fail_at(&mut self, step: u64, name: &str, detail: impl AsRef<str>) {
        self.failed = true;
        self.event(step, name, "fail", detail.as_ref());
    }

    pub fn skip_at(&mut self, step: u64, name: &str, detail: impl AsRef<str>) {
        self.event(step, name, "skip", detail.as_ref());
    }

    pub fn curl_code(
        &mut self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> Result<u16, String> {
        self.curl_body(method, path, body)
            .map(|response| response.code)
    }

    pub fn curl_json(
        &mut self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, String> {
        let response = self.curl_body(method, path, body)?;
        if !(200..300).contains(&response.code) {
            return Err(format!(
                "HTTP {} for {method} {path}: {}",
                response.code, response.body
            ));
        }
        serde_json::from_str(&response.body).map_err(|err| {
            format!(
                "parse JSON from {method} {path}: {err}; body: {}",
                response.body
            )
        })
    }

    pub fn curl_body(
        &mut self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> Result<CurlResponse, String> {
        let url = self.url(path);
        let mut command = Command::new("curl");
        command
            .args(["-s", "--connect-timeout", "5", "--max-time"])
            .arg(self.config.timeout_secs.to_string())
            .args(["-w", "\n%{http_code}", "-b"])
            .arg(&self.cookie_jar)
            .args(["-c"])
            .arg(&self.cookie_jar)
            .args(["-X", method]);
        let mut body_file = None;
        if let Some(body) = body {
            let path = self.config.report_dir.join(format!(
                "curl-body-{}-{}.json",
                unix_millis(),
                std::process::id()
            ));
            fs::write(&path, body.to_string())
                .map_err(|err| format!("write {}: {err}", path.display()))?;
            command.args(["-H", "Content-Type: application/json", "--data-binary"]);
            command.arg(format!("@{}", path.display()));
            body_file = Some(path);
        }
        let output = command
            .arg(url)
            .output()
            .map_err(|err| format!("start curl: {err}"))?;
        if let Some(path) = body_file {
            let _ = fs::remove_file(path);
        }
        let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
        if !output.status.success() && text.trim().is_empty() {
            return Err(format!("curl exited {}", output.status));
        }
        trim_trailing_newlines(&mut text);
        let split = text
            .rfind('\n')
            .ok_or_else(|| format!("curl missing http code: {text}"))?;
        let code = text[split + 1..]
            .trim()
            .parse::<u16>()
            .map_err(|err| format!("parse curl http code: {err}"))?;
        let body = text[..split].to_string();
        Ok(CurlResponse { code, body })
    }

    pub fn ssh_output(&self, command: &str) -> Result<String, String> {
        let output = self
            .ssh_command(command)
            .output()
            .map_err(|err| format!("start ssh: {err}"))?;
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if output.status.success() {
            Ok(stdout)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            Err(format!("ssh exited {}: {stderr}", output.status))
        }
    }

    pub fn ssh_status(&self, command: &str) -> bool {
        self.ssh_command(command)
            .status()
            .is_ok_and(|status| status.success())
    }

    pub fn scp_to_remote(&self, local: &Path, remote_path: &str) -> Result<(), String> {
        let output = self
            .scp_command()
            .arg(local)
            .arg(format!("{}:{remote_path}", self.remote))
            .output()
            .map_err(|err| format!("start scp: {err}"))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "scp exited {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            ))
        }
    }

    pub fn remote_root(&self, command: &str) -> Result<String, String> {
        let quoted_command = shell_quote(command);
        let quoted_password = shell_quote(&self.env_or("SSH_PASSWORD", ""));
        self.ssh_output(&format!(
            "if [ \"$(id -u)\" -eq 0 ]; then sh -c {quoted_command}; elif command -v sudo >/dev/null 2>&1; then printf '%s\\n' {quoted_password} | sudo -S sh -c {quoted_command}; elif command -v doas >/dev/null 2>&1; then printf '%s\\n' {quoted_password} | doas sh -c {quoted_command}; else echo 'root privileges required: install sudo/doas or deploy as root' >&2; exit 1; fi"
        ))
    }

    pub fn dns_query(&self, domain: &str) -> Result<String, String> {
        match udp_dns_a(
            &self.env_or("SSH_HOST", ""),
            53,
            domain,
            Duration::from_secs(2),
        ) {
            Ok(answer) if !answer.is_empty() => Ok(answer),
            _ => self.dns_query_remote(domain),
        }
    }

    pub fn dns_query_remote(&self, domain: &str) -> Result<String, String> {
        let quoted = shell_quote(domain);
        self.ssh_output(&format!(
            "domain={quoted}; if command -v dig >/dev/null 2>&1; then dig @127.0.0.1 +time=2 +tries=1 +short A \"$domain\"; elif command -v drill >/dev/null 2>&1; then drill @127.0.0.1 \"$domain\" A | awk '/^[^;].*[[:space:]]A[[:space:]]/ {{ print $NF }}'; elif command -v nslookup >/dev/null 2>&1; then nslookup -type=A \"$domain\" 127.0.0.1; else exit 127; fi"
        ))
    }

    pub fn resource_snapshot(&self) -> Result<ResourceSnapshot, String> {
        let output = self.remote_root("pid=$(pidof rustblocker 2>/dev/null | awk '{print $1}'); [ -n \"$pid\" ] || pid=$(pgrep -x rustblocker 2>/dev/null | head -1); [ -n \"$pid\" ] || exit 1; rss=$(awk '/^VmRSS:/ {print $2}' /proc/$pid/status 2>/dev/null); threads=$(awk '/^Threads:/ {print $2}' /proc/$pid/status 2>/dev/null); fds=$(find /proc/$pid/fd -maxdepth 1 2>/dev/null | wc -l); printf '%s %s %s %s\n' \"$pid\" \"${rss:-0}\" \"${threads:-0}\" \"${fds:-0}\"")?;
        let mut parts = output.split_whitespace();
        Ok(ResourceSnapshot {
            pid: parse_u64(parts.next(), "pid")?,
            rss_kb: parse_u64(parts.next(), "rss")?,
            threads: parse_u64(parts.next(), "threads")?,
            fds: parse_u64(parts.next(), "fds")?,
        })
    }

    pub fn cleanup_blocklist_api(
        &mut self,
        prefix: &str,
        page_size: u64,
        max_passes: u64,
    ) -> Result<u64, String> {
        let mut deleted = 0;
        for _ in 0..max_passes {
            let page = self.curl_json(
                "GET",
                &format!("/api/blocklist?search={prefix}&limit={page_size}"),
                None,
            )?;
            let ids = page
                .get("domains")
                .and_then(Value::as_array)
                .map(|domains| {
                    domains
                        .iter()
                        .filter_map(|domain| domain.get("id").and_then(Value::as_u64))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if ids.is_empty() {
                return Ok(deleted);
            }
            for id in ids {
                let code = self.curl_code("DELETE", &format!("/api/blocklist/{id}"), None)?;
                if code != 200 {
                    return Err(format!("delete blocklist id {id} HTTP {code}"));
                }
                deleted += 1;
            }
        }
        Err(format!("cleanup did not finish after {max_passes} passes"))
    }

    pub fn cleanup_blocklist_sqlite(&self, prefix: &str) -> Result<(), String> {
        let db = shell_quote(&self.env_or("REMOTE_DB_PATH", "/var/lib/rustblocker/rustblocker.db"));
        let like = shell_quote(&format!("%{prefix}%"));
        self.remote_root(&format!(
            "sqlite3 {db} \"DELETE FROM blocklist_domains WHERE domain LIKE {like};\""
        ))?;
        self.restart_remote_service()?;
        Ok(())
    }

    pub fn write_baseline_json<P, V>(&self, path: P, value: V) -> Result<(), String>
    where
        P: AsRef<Path>,
        V: std::borrow::Borrow<Value>,
    {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("create {}: {err}", parent.display()))?;
        }
        write_json(path, value.borrow())
    }

    fn detect_target(&mut self) -> Result<String, String> {
        let arch = self.ssh_output("uname -m").unwrap_or_default();
        let target = match arch.trim() {
            "x86_64" | "amd64" => self.env_or("DEPLOY_TARGET", "x86_64-unknown-linux-musl"),
            "aarch64" | "arm64" => self.env_or("DEPLOY_TARGET", "aarch64-unknown-linux-musl"),
            other => {
                self.fail_at(
                    0,
                    "target",
                    format!(
                        "unsupported or unknown remote architecture: {}",
                        if other.is_empty() { "unknown" } else { other }
                    ),
                );
                return Err("unsupported remote target".to_string());
            }
        };
        Ok(target)
    }

    fn build(&mut self, target: &str) -> Result<(), String> {
        let binary_path = binary_path(target);
        if self.config.skip_build {
            self.skip("build", "skipped");
        } else {
            let build_id = default_run_id();
            self.ok(
                "build",
                format!("building release binary with build id {build_id}..."),
            );
            let mut command = if command_exists("cargo-zigbuild") {
                let mut command = Command::new("cargo");
                command.args(["zigbuild", "--release", "--target", target]);
                command
            } else {
                let mut command = Command::new("cargo");
                command.args(["build", "--release", "--target", target]);
                command
            };
            command.env("RUSTBLOCKER_BUILD_ID", &build_id);
            let status = command
                .status()
                .map_err(|err| format!("start cargo build: {err}"))?;
            if status.success() {
                self.ok(
                    "build",
                    format!("release binary built for {target} with build id {build_id}"),
                );
            } else {
                self.fail_at(self.step, "build", "cargo build failed");
                return Err("build failed".to_string());
            }
        }
        if !binary_path.exists() {
            self.fail_at(
                0,
                "build",
                format!("missing binary: {}", binary_path.display()),
            );
            return Err("missing build output".to_string());
        }
        Ok(())
    }

    fn deploy(&mut self, target: &str) -> Result<(), String> {
        if self.config.skip_deploy {
            self.skip("deploy", "skipped");
            return Ok(());
        }
        let binary_path = binary_path(target);
        let stop_step = self.step();
        if self.remote_root("systemctl stop rustblocker 2>/dev/null || rc-service rustblocker stop 2>/dev/null || true").is_ok() {
            self.ok_at(stop_step, "deploy", "service stopped");
        } else {
            self.fail_at(stop_step, "deploy", "stop failed (non-fatal)");
        }

        let remote_tmp = format!("/tmp/{BINARY_NAME}-{}", std::process::id());
        let upload_step = self.step();
        self.scp_to_remote(&binary_path, &remote_tmp)
            .map(|_| self.ok_at(upload_step, "deploy", "binary uploaded"))
            .inspect_err(|_| {
                self.fail_at(upload_step, "deploy", "scp failed");
            })?;

        let install_step = self.step();
        let install_cmd = format!(
            "mkdir -p {REMOTE_INSTALL_DIR} && cp {remote_tmp} {REMOTE_INSTALL_DIR}/{BINARY_NAME} && chmod +x {REMOTE_INSTALL_DIR}/{BINARY_NAME} && rm -f {remote_tmp}"
        );
        self.remote_root(&install_cmd)
            .map(|_| self.ok_at(install_step, "deploy", "binary installed"))
            .inspect_err(|_| {
                self.fail_at(install_step, "deploy", "install failed");
            })?;

        let config_step = self.step();
        self.ensure_remote_service_defaults()
            .map(|_| {
                self.ok_at(
                    config_step,
                    "deploy",
                    "service configured for default HTTPS behavior",
                )
            })
            .inspect_err(|_| {
                self.fail_at(
                    config_step,
                    "deploy",
                    "failed to configure service defaults",
                );
            })?;

        let start_step = self.step();
        self.remote_root("systemctl start rustblocker 2>/dev/null || rc-service rustblocker start 2>/dev/null || true")
            .map(|_| self.ok_at(start_step, "deploy", "service started"))
            .inspect_err(|_| {
                self.fail_at(start_step, "deploy", "start failed");
            })?;

        let health_step = self.step();
        for attempt in 1..=10 {
            std::thread::sleep(Duration::from_secs(2));
            if self
                .curl_code("GET", "/api/health", None)
                .is_ok_and(|code| code == 200)
            {
                self.ok_at(
                    health_step,
                    "deploy",
                    format!("health check passed (after {}s)", attempt * 2),
                );
                return Ok(());
            }
        }
        self.fail_at(
            health_step,
            "deploy",
            "health check failed — service did not start",
        );
        let _ = self.ssh_output("rc-service rustblocker status 2>/dev/null || systemctl status rustblocker --no-pager 2>/dev/null || true; tail -n 80 /var/log/rustblocker.log 2>/dev/null || true");
        Ok(())
    }

    fn login(&mut self) -> Result<(), String> {
        let code = self.curl_code(
            "POST",
            "/api/auth/login",
            Some(json!({ "password": self.env_or("WEBUI_PASSWORD", "") })),
        )?;
        if code == 200 {
            self.ok("login", "authenticated");
        } else {
            self.fail("login", format!("HTTP {code}"));
        }
        Ok(())
    }

    fn settings(&mut self) -> Result<Value, String> {
        let response = self.curl_body("GET", "/api/settings", None)?;
        if response.body.contains('"') {
            self.ok("settings", "settings endpoint reachable");
        } else {
            self.fail("settings", "could not read settings");
        }
        serde_json::from_str(&response.body).map_err(|err| format!("parse settings JSON: {err}"))
    }

    fn resource_baseline(&mut self) {
        let step = self.step();
        match self.resource_snapshot() {
            Ok(snapshot) => {
                self.check_resource_snapshot_at(step, "resource-baseline", snapshot, None)
            }
            Err(_) => self.fail_at(
                step,
                "resource-baseline",
                "could not read rustblocker process resources",
            ),
        }
    }

    fn forward_strategy(&mut self, settings: &Value) -> Result<(), String> {
        let original =
            json_string(settings, "forward_strategy").unwrap_or_else(|| "adaptive".to_string());
        let code_parallel = self.put_setting("forward_strategy", "parallel")?;
        let settings_parallel = self.curl_body("GET", "/api/settings", None)?.body;
        let code_adaptive = self.put_setting("forward_strategy", "adaptive")?;
        let settings_adaptive = self.curl_body("GET", "/api/settings", None)?.body;
        if original != "adaptive" {
            let _ = self.put_setting("forward_strategy", &original);
        }
        if code_parallel == 200
            && code_adaptive == 200
            && settings_parallel.contains("\"forward_strategy\":\"parallel\"")
            && settings_adaptive.contains("\"forward_strategy\":\"adaptive\"")
        {
            self.ok(
                "forward-strategy",
                format!("settings API switched parallel/adaptive and restored {original}"),
            );
        } else {
            self.fail("forward-strategy", format!("forward strategy setting did not round-trip (parallel HTTP {code_parallel}, adaptive HTTP {code_adaptive})"));
        }
        Ok(())
    }

    fn adaptive_hedge_delay(&mut self, settings: &Value) -> Result<(), String> {
        let original =
            json_string(settings, "adaptive_hedge_delay_ms").unwrap_or_else(|| "75".to_string());
        let code_25 = self.put_setting("adaptive_hedge_delay_ms", "25")?;
        let settings_25 = self.curl_body("GET", "/api/settings", None)?.body;
        let code_restore = self.put_setting("adaptive_hedge_delay_ms", &original)?;
        let settings_restore = self.curl_body("GET", "/api/settings", None)?.body;
        if code_25 == 200
            && code_restore == 200
            && settings_25.contains("\"adaptive_hedge_delay_ms\":\"25\"")
            && settings_restore.contains(&format!("\"adaptive_hedge_delay_ms\":\"{original}\""))
        {
            self.ok(
                "adaptive-hedge-delay",
                format!("setting switched 25ms and restored {original}ms"),
            );
        } else {
            self.fail("adaptive-hedge-delay", format!("hedge delay setting did not round-trip (25 HTTP {code_25} restore HTTP {code_restore})"));
        }
        Ok(())
    }

    fn forward_strategy_dns(&mut self, settings: &Value) -> Result<(), String> {
        let original =
            json_string(settings, "forward_strategy").unwrap_or_else(|| "adaptive".to_string());
        let domain = self.env_or("FORWARD_PROBE_DOMAIN", "example.com");
        let code_parallel = self.put_setting("forward_strategy", "parallel")?;
        let parallel_dns = self.dns_query(&domain).unwrap_or_default();
        let code_adaptive = self.put_setting("forward_strategy", "adaptive")?;
        let adaptive_dns = self.dns_query(&domain).unwrap_or_default();
        if original != "adaptive" {
            let _ = self.put_setting("forward_strategy", &original);
        }
        if code_parallel == 200
            && code_adaptive == 200
            && has_ipv4_answer(&parallel_dns)
            && has_ipv4_answer(&adaptive_dns)
        {
            self.ok(
                "forward-strategy-dns",
                format!("parallel/adaptive both resolved {domain}"),
            );
        } else {
            self.fail("forward-strategy-dns", format!("parallel/adaptive DNS probe failed for {domain} (parallel HTTP {code_parallel}: {}; adaptive HTTP {code_adaptive}: {})", empty(&parallel_dns), empty(&adaptive_dns)));
        }
        Ok(())
    }

    fn version(&mut self) -> Result<(), String> {
        let version = self.curl_json("GET", "/api/version", None)?;
        let build = json_string(&version, "build").unwrap_or_default();
        let cache_size = json_u64(&version, "resolver_cache_size").unwrap_or(0);
        let dns_max = json_u64(&version, "dns_max_in_flight").unwrap_or(0);
        let hedge = json_u64(&version, "adaptive_hedge_delay_ms").unwrap_or(0);
        let version_ok = if self.config.skip_build || self.config.skip_deploy {
            !build.is_empty() && cache_size > 0 && dns_max > 0 && hedge > 0
        } else {
            cache_size == 32768 && dns_max == 512 && hedge == 75
        };
        if version_ok {
            self.ok("version", format!("deployed build id is {build} resolver_cache_size={cache_size} dns_max_in_flight={dns_max} adaptive_hedge_delay_ms={hedge}"));
        } else {
            self.fail("version", format!("unexpected version payload build='{}' cache='{cache_size}' dns_max='{dns_max}' hedge='{hedge}' (expected cache=32768 dns_max=512 hedge=75; response: {version})", empty(&build)));
        }
        Ok(())
    }

    fn db_api(&mut self) -> Result<(), String> {
        let stats = self.curl_body("GET", "/api/stats", None)?.body;
        if stats.contains("\"total_queries\"") {
            self.ok("db-api", "stats endpoint reachable");
        } else {
            self.fail("db-api", "could not read stats");
        }
        let sources = self.curl_body("GET", "/api/sources", None)?.body;
        if sources.trim_start().starts_with('[') {
            self.ok("db-api", "sources endpoint reachable");
        } else {
            self.fail("db-api", "could not read sources");
        }
        Ok(())
    }

    fn stats_concurrency(&mut self) -> Result<(), String> {
        let requests = self.env_u64_or("STATS_CONCURRENCY_REQUESTS", 8);
        let started = Instant::now();
        let mut children = Vec::new();
        for _ in 0..requests {
            let mut command = Command::new("curl");
            command
                .args(["-s", "--connect-timeout", "5", "--max-time"])
                .arg(self.config.timeout_secs.to_string())
                .arg("-b")
                .arg(&self.cookie_jar)
                .arg(format!("{}/api/stats?limit=10", self.base_url()))
                .stdout(Stdio::piped());
            children.push(
                command
                    .spawn()
                    .map_err(|err| format!("start curl stats: {err}"))?,
            );
        }
        let mut ok = true;
        let mut bytes = 0;
        for child in children {
            let output = child
                .wait_with_output()
                .map_err(|err| format!("wait curl stats: {err}"))?;
            bytes += output.stdout.len();
            if !output.status.success()
                || !String::from_utf8_lossy(&output.stdout).contains("\"total_queries\"")
            {
                ok = false;
            }
        }
        if ok {
            self.ok(
                "stats-concurrency",
                format!(
                    "{requests} stats summaries completed ({bytes} bytes, elapsed {}ms)",
                    started.elapsed().as_millis()
                ),
            );
        } else {
            self.fail(
                "stats-concurrency",
                "one or more concurrent stats summaries failed",
            );
        }
        Ok(())
    }

    fn run_group_hooks(&mut self) -> Result<(), String> {
        crate::api_smoke::run(self)?;
        crate::baselines::run(self)?;
        crate::stress_https::run(self)?;
        Ok(())
    }

    fn put_setting(&mut self, key: &str, value: &str) -> Result<u16, String> {
        self.curl_code(
            "PUT",
            "/api/settings",
            Some(json!({ "key": key, "value": value })),
        )
    }

    fn check_resource_snapshot_at(
        &mut self,
        step: u64,
        label: &str,
        snapshot: ResourceSnapshot,
        base_rss: Option<u64>,
    ) {
        let growth = base_rss
            .map(|base| snapshot.rss_kb.saturating_sub(base))
            .unwrap_or(0);
        let max_rss = self.env_u64_or("MEMORY_RSS_MAX_KB", 262144);
        let max_growth = self.env_u64_or("MEMORY_RSS_GROWTH_MAX_KB", 131072);
        let max_fds = self.env_u64_or("PROCESS_FD_MAX", 1024);
        let max_threads = self.env_u64_or("PROCESS_THREADS_MAX", 128);
        if snapshot.rss_kb > max_rss {
            self.fail_at(
                step,
                label,
                format!(
                    "RSS {}KB exceeded max {}KB (pid={}, threads={}, fds={})",
                    snapshot.rss_kb, max_rss, snapshot.pid, snapshot.threads, snapshot.fds
                ),
            );
        } else if base_rss.is_some() && growth > max_growth {
            self.fail_at(
                step,
                label,
                format!(
                    "RSS grew {growth}KB from baseline {}KB, max growth {max_growth}KB (rss={}KB)",
                    base_rss.unwrap_or(0),
                    snapshot.rss_kb
                ),
            );
        } else if snapshot.fds > max_fds {
            self.fail_at(
                step,
                label,
                format!(
                    "open FDs {} exceeded max {} (pid={}, rss={}KB)",
                    snapshot.fds, max_fds, snapshot.pid, snapshot.rss_kb
                ),
            );
        } else if snapshot.threads > max_threads {
            self.fail_at(
                step,
                label,
                format!(
                    "threads {} exceeded max {} (pid={}, rss={}KB)",
                    snapshot.threads, max_threads, snapshot.pid, snapshot.rss_kb
                ),
            );
        } else {
            self.ok_at(
                step,
                label,
                format!(
                    "pid={} rss={}KB growth={}KB threads={} fds={}",
                    snapshot.pid, snapshot.rss_kb, growth, snapshot.threads, snapshot.fds
                ),
            );
        }
    }

    fn restart_remote_service(&self) -> Result<(), String> {
        self.remote_root("systemctl restart rustblocker 2>/dev/null || rc-service rustblocker restart 2>/dev/null")?;
        Ok(())
    }

    fn ensure_remote_service_defaults(&self) -> Result<(), String> {
        self.remote_root("if [ -f /etc/init.d/rustblocker ]; then sed -i 's#command_args=\"--dns-port 53 --db-path /var/lib/rustblocker/rustblocker.db --https --https-port 443\"#command_args=\"--dns-port 53 --db-path /var/lib/rustblocker/rustblocker.db\"#' /etc/init.d/rustblocker; elif [ -f /etc/systemd/system/rustblocker.service ]; then sed -i 's#ExecStart=/usr/local/bin/rustblocker --dns-port 53 --db-path /var/lib/rustblocker/rustblocker.db --https --https-port 443#ExecStart=/usr/local/bin/rustblocker --dns-port 53 --db-path /var/lib/rustblocker/rustblocker.db#' /etc/systemd/system/rustblocker.service; systemctl daemon-reload 2>/dev/null || true; fi")?;
        Ok(())
    }

    fn write_summary(&self, exit_code: i32) -> Result<Value, String> {
        let summary = summarize_run(&self.run_jsonl, exit_code);
        write_json(&self.summary_json, &summary)?;
        Ok(summary)
    }

    fn event(&mut self, step: u64, name: &str, status: &str, detail: &str) {
        let value = json!({
            "step": step,
            "name": name,
            "status": status,
            "detail": detail,
        });
        println!("{value}");
        if let Ok(mut file) = OpenOptions::new().append(true).open(&self.run_jsonl) {
            let _ = writeln!(file, "{value}");
        }
    }

    fn url(&self, path: &str) -> String {
        if path.starts_with("http://") || path.starts_with("https://") {
            path.to_string()
        } else {
            format!("{}{}", self.base_url(), path)
        }
    }

    fn ssh_command(&self, command: &str) -> Command {
        let mut ssh = if command_exists("sshpass") {
            let mut command = Command::new("sshpass");
            command.args(["-e", "ssh"]);
            command.env("SSHPASS", self.env_or("SSH_PASSWORD", ""));
            command
        } else {
            let mut command = Command::new("ssh");
            apply_askpass_env(&mut command);
            command
        };
        ssh.args(["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"])
            .arg(&self.remote)
            .arg(command);
        ssh
    }

    fn scp_command(&self) -> Command {
        let mut scp = if command_exists("sshpass") {
            let mut command = Command::new("sshpass");
            command.args(["-e", "scp"]);
            command.env("SSHPASS", self.env_or("SSH_PASSWORD", ""));
            command
        } else {
            let mut command = Command::new("scp");
            apply_askpass_env(&mut command);
            command
        };
        scp.args(["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"]);
        scp
    }
}

fn parse_deployenv(path: &Path) -> Result<BTreeMap<String, String>, String> {
    let file = File::open(path).map_err(|err| format!("read {}: {err}", path.display()))?;
    let mut values = BTreeMap::new();
    for line in BufReader::new(file).lines() {
        let line = line.map_err(|err| format!("read {}: {err}", path.display()))?;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || !line.contains('=') {
            continue;
        }
        let (key, value) = line.split_once('=').unwrap_or((line, ""));
        let key = key.trim();
        if key.is_empty() || key.starts_with("export ") {
            continue;
        }
        values.insert(key.to_string(), unquote_env_value(value.trim()));
    }
    Ok(values)
}

fn apply_defaults(values: &mut BTreeMap<String, String>) {
    for (key, value) in [
        ("WEB_PORT", "54"),
        ("ENABLE_CLOUDFLARE_HTTPS", "false"),
        ("DB_CONCURRENCY_REQUESTS", "16"),
        ("STATS_CONCURRENCY_REQUESTS", "8"),
        ("DNS_BURST_REQUESTS", "96"),
        ("DNS_BURST_MAX_MS", "8000"),
        ("DNS_BURST_MAX_FAILURES", "0"),
        ("FORWARD_PROBE_DOMAIN", "example.com"),
        ("MEMORY_RSS_MAX_KB", "262144"),
        ("MEMORY_RSS_GROWTH_MAX_KB", "131072"),
        ("PROCESS_FD_MAX", "1024"),
        ("PROCESS_THREADS_MAX", "128"),
        ("REMOTE_DB_PATH", "/var/lib/rustblocker/rustblocker.db"),
        ("MOCK_STRESS_BLOCKLIST", "false"),
        ("STRESS_INSTALL_SQLITE3", "true"),
        ("STRESS_API_CLEANUP_MAX_DOMAINS", "10000"),
        ("STRESS_API_CLEANUP_PAGE_SIZE", "250"),
    ] {
        values
            .entry(key.to_string())
            .or_insert_with(|| value.to_string());
    }
}

fn unquote_env_value(value: &str) -> String {
    let mut value = value.trim().to_string();
    if let Some(comment) = value.find(" #") {
        value.truncate(comment);
        value = value.trim_end().to_string();
    }
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if (bytes[0] == b'\'' && bytes[value.len() - 1] == b'\'')
            || (bytes[0] == b'\"' && bytes[value.len() - 1] == b'\"')
        {
            return value[1..value.len() - 1].to_string();
        }
    }
    value
}

fn summarize_run(run_jsonl: &Path, exit_code: i32) -> Value {
    let mut ok = 0_u64;
    let mut fail = 0_u64;
    let mut skip = 0_u64;
    let mut events = 0_u64;
    let mut failures = Vec::new();
    let mut last_by_name: Map<String, Value> = Map::new();

    if let Ok(file) = File::open(run_jsonl) {
        for line in BufReader::new(file).lines().map_while(Result::ok) {
            let trimmed = line.trim();
            if !(trimmed.starts_with('{') && trimmed.ends_with('}')) {
                continue;
            }
            let Ok(value) = serde_json::from_str::<Value>(trimmed) else {
                continue;
            };
            let Some(status) = value.get("status").and_then(Value::as_str) else {
                continue;
            };
            events += 1;
            match status {
                "ok" => ok += 1,
                "fail" => {
                    fail += 1;
                    failures.push(value.clone());
                }
                "skip" => skip += 1,
                _ => {}
            }
            if let Some(name) = value.get("name").and_then(Value::as_str) {
                last_by_name.insert(name.to_string(), value);
            }
        }
    }

    json!({
        "status": if fail == 0 && exit_code == 0 { "ok" } else { "fail" },
        "exit_code": exit_code,
        "events": events,
        "ok": ok,
        "fail": fail,
        "skip": skip,
        "failures": failures,
        "last_by_name": last_by_name,
        "run_jsonl": run_jsonl,
        "created_at_unix": unix_secs(),
    })
}

fn compare_summaries(previous: &Path, current: &Path) -> Result<Value, String> {
    let previous_summary = read_json(previous)?;
    let current_summary = read_json(current)?;
    let previous_names = previous_summary
        .get("last_by_name")
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{} missing last_by_name", previous.display()))?;
    let current_names = current_summary
        .get("last_by_name")
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{} missing last_by_name", current.display()))?;

    let mut changed = Vec::new();
    for (name, current_event) in current_names {
        let current_status = current_event.get("status").and_then(Value::as_str);
        let previous_status = previous_names
            .get(name)
            .and_then(|event| event.get("status"))
            .and_then(Value::as_str);
        if previous_status != current_status {
            changed.push(json!({
                "name": name,
                "previous": previous_status,
                "current": current_status,
            }));
        }
    }

    let missing = previous_names
        .keys()
        .filter(|name| !current_names.contains_key(*name))
        .cloned()
        .collect::<Vec<_>>();

    Ok(json!({
        "status": if changed.is_empty() && missing.is_empty() { "ok" } else { "changed" },
        "previous": previous,
        "current": current,
        "changed_statuses": changed,
        "missing_current_steps": missing,
        "created_at_unix": unix_secs(),
    }))
}

fn read_json(path: &Path) -> Result<Value, String> {
    let bytes = fs::read(path).map_err(|err| format!("read {}: {err}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|err| format!("parse {}: {err}", path.display()))
}

fn write_json(path: &Path, value: &Value) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|err| format!("serialize json: {err}"))?;
    fs::write(path, bytes).map_err(|err| format!("write {}: {err}", path.display()))
}

fn binary_path(target: &str) -> PathBuf {
    PathBuf::from("target")
        .join(target)
        .join("release")
        .join(BINARY_NAME)
}

fn command_exists(name: &str) -> bool {
    let mut command = if cfg!(windows) {
        let mut command = Command::new("where");
        command.arg(name);
        command
    } else {
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg(format!("command -v {} >/dev/null 2>&1", shell_quote(name)));
        command
    };
    command
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn apply_askpass_env(command: &mut Command) {
    let bat = Path::new("askpass.bat");
    let sh = Path::new("askpass.sh");
    if bat.exists() {
        command.env("SSH_ASKPASS", bat);
    } else if sh.exists() {
        command.env("SSH_ASKPASS", sh);
    }
    command.env("DISPLAY", "dummy");
    command.env("SSH_ASKPASS_REQUIRE", "force");
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn trim_trailing_newlines(value: &mut String) {
    while value.ends_with('\n') || value.ends_with('\r') {
        value.pop();
    }
}

fn parse_u64(value: Option<&str>, name: &str) -> Result<u64, String> {
    value
        .ok_or_else(|| format!("missing {name}"))?
        .parse::<u64>()
        .map_err(|err| format!("parse {name}: {err}"))
}

fn json_string(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(|item| {
        item.as_str()
            .map(ToString::to_string)
            .or_else(|| item.as_u64().map(|number| number.to_string()))
    })
}

fn json_u64(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(|item| {
        item.as_u64()
            .or_else(|| item.as_str().and_then(|text| text.parse::<u64>().ok()))
    })
}

fn has_ipv4_answer(value: &str) -> bool {
    value.lines().any(|line| {
        let parts = line.trim().split('.').collect::<Vec<_>>();
        parts.len() == 4 && parts.iter().all(|part| part.parse::<u8>().is_ok())
    })
}

fn udp_dns_a(host: &str, port: u16, domain: &str, timeout: Duration) -> Result<String, String> {
    if host.is_empty() || domain.is_empty() {
        return Err("missing dns host or domain".to_string());
    }
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|err| format!("bind udp dns: {err}"))?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|err| format!("set dns timeout: {err}"))?;
    socket
        .set_write_timeout(Some(timeout))
        .map_err(|err| format!("set dns timeout: {err}"))?;

    let mut packet = Vec::with_capacity(512);
    packet.extend_from_slice(&0x5242_u16.to_be_bytes());
    packet.extend_from_slice(&0x0100_u16.to_be_bytes());
    packet.extend_from_slice(&1_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    for label in domain.trim_end_matches('.').split('.') {
        let len = label.len();
        if len == 0 || len > 63 {
            return Err(format!("invalid dns label: {domain}"));
        }
        packet.push(len as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&1_u16.to_be_bytes());
    packet.extend_from_slice(&1_u16.to_be_bytes());

    socket
        .send_to(&packet, (host, port))
        .map_err(|err| format!("send dns query: {err}"))?;
    let mut buf = [0_u8; 512];
    let (len, _) = socket
        .recv_from(&mut buf)
        .map_err(|err| format!("receive dns response: {err}"))?;
    parse_dns_a_response(&buf[..len])
}

fn parse_dns_a_response(buf: &[u8]) -> Result<String, String> {
    if buf.len() < 12 {
        return Err("short dns response".to_string());
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let rcode = buf[3] & 0x0f;
    if rcode != 0 && rcode != 3 {
        return Err(format!("dns rcode {rcode}"));
    }
    let mut offset = 12;
    for _ in 0..qdcount {
        skip_dns_name(buf, &mut offset)?;
        offset = offset
            .checked_add(4)
            .filter(|value| *value <= buf.len())
            .ok_or_else(|| "truncated dns question".to_string())?;
    }
    let mut ips = Vec::new();
    for _ in 0..ancount {
        skip_dns_name(buf, &mut offset)?;
        if offset + 10 > buf.len() {
            return Err("truncated dns answer".to_string());
        }
        let rr_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let rr_class = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
        let rdlen = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]) as usize;
        offset += 10;
        if offset + rdlen > buf.len() {
            return Err("truncated dns rdata".to_string());
        }
        if rr_type == 1 && rr_class == 1 && rdlen == 4 {
            ips.push(format!(
                "{}.{}.{}.{}",
                buf[offset],
                buf[offset + 1],
                buf[offset + 2],
                buf[offset + 3]
            ));
        }
        offset += rdlen;
    }
    Ok(ips.join("\n"))
}

fn skip_dns_name(buf: &[u8], offset: &mut usize) -> Result<(), String> {
    loop {
        if *offset >= buf.len() {
            return Err("truncated dns name".to_string());
        }
        let len = buf[*offset];
        *offset += 1;
        if len & 0xc0 == 0xc0 {
            if *offset >= buf.len() {
                return Err("truncated dns pointer".to_string());
            }
            *offset += 1;
            return Ok(());
        }
        if len == 0 {
            return Ok(());
        }
        if len & 0xc0 != 0 {
            return Err("unsupported dns label".to_string());
        }
        *offset = offset
            .checked_add(len as usize)
            .filter(|value| *value <= buf.len())
            .ok_or_else(|| "truncated dns label".to_string())?;
    }
}

fn empty(value: &str) -> &str {
    if value.is_empty() { "empty" } else { value }
}

fn default_run_id() -> String {
    let git_rev = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "nogit".to_string());
    format!("{}-{git_rev}", unix_secs())
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

fn usage_mock_deploy() {
    eprintln!(
        "  cargo run --bin xtask -- mock-deploy [--report-dir=DIR] [--compare=SUMMARY_JSON] [--deployenv=FILE] [--skip-build] [--skip-deploy] [--timeout=SECONDS]"
    );
}
