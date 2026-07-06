//! DNS benchmark — compares query latency and throughput across servers.
//!
//! Usage:
//!   cargo run --release --example benchmark -- --servers 192.168.0.3:53,10.0.1.1:53
//!   cargo run --release --example benchmark -- --servers 192.168.0.3:53 --queries 5000 --concurrency 50
//!   cargo run --release --example benchmark -- --servers 192.168.0.3:53 --mode sinkhole --queries 10000
//!   cargo run --release --example benchmark -- --servers 192.168.0.3:53 --duration-secs 30 --target-qps 100
//!
//! Modes:
//!   mixed     — realistic mix: A, AAAA, CNAME chains, NODATA, NXDOMAIN (default)
//!   sinkhole  — blocklisted domains only (measures server-only processing, no upstream)
//!   cached    — same domain repeated (measures resolver cache performance)
//!   forwarded — real domains only (measures upstream round-trip)

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

use clap::Parser;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

/// Domains for each benchmark mode.
const MIXED_DOMAINS: &[(&str, RecordType)] = &[
    ("google.com", RecordType::A),
    ("github.com", RecordType::A),
    ("example.com", RecordType::A),
    ("stackoverflow.com", RecordType::A),
    ("cloudflare.com", RecordType::A),
    ("amazon.com", RecordType::A),
    ("microsoft.com", RecordType::A),
    ("apple.com", RecordType::A),
    ("reddit.com", RecordType::A),
    ("wikipedia.org", RecordType::A),
    ("www.github.com", RecordType::A),
    ("www.google.com", RecordType::A),
    ("google.com", RecordType::AAAA),
    ("cloudflare.com", RecordType::AAAA),
    ("github.com", RecordType::AAAA),
    ("stackoverflow.com", RecordType::AAAA),
    ("nonexistent-bench-123.com", RecordType::A),
];

/// Sinkhole test domains — must be blocklisted on the server.
/// These measure pure server processing (no upstream round-trip).
const SINKHOLE_DOMAINS: &[(&str, RecordType)] = &[
    ("ads.test", RecordType::A),
    ("tracker.test", RecordType::A),
    ("malware.test", RecordType::A),
    ("blocked1.test", RecordType::A),
    ("blocked2.test", RecordType::A),
];

/// Cached test — same domain repeated to measure cache hits.
const CACHED_DOMAINS: &[(&str, RecordType)] = &[("example.com", RecordType::A)];

/// Forwarded-only — real domains that require upstream round-trip.
const FORWARDED_DOMAINS: &[(&str, RecordType)] = &[
    ("google.com", RecordType::A),
    ("github.com", RecordType::A),
    ("example.com", RecordType::A),
    ("stackoverflow.com", RecordType::A),
    ("cloudflare.com", RecordType::A),
];

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Mixed,
    Sinkhole,
    Cached,
    Forwarded,
}

impl Mode {
    fn from_str(s: &str) -> Self {
        match s {
            "sinkhole" => Mode::Sinkhole,
            "cached" => Mode::Cached,
            "forwarded" => Mode::Forwarded,
            _ => Mode::Mixed,
        }
    }

    fn domains(self) -> &'static [(&'static str, RecordType)] {
        match self {
            Mode::Mixed => MIXED_DOMAINS,
            Mode::Sinkhole => SINKHOLE_DOMAINS,
            Mode::Cached => CACHED_DOMAINS,
            Mode::Forwarded => FORWARDED_DOMAINS,
        }
    }
}

#[derive(Parser)]
#[command(name = "benchmark", about = "DNS server benchmark tool")]
struct Cli {
    /// Comma-separated list of servers (ip:port)
    #[arg(long, default_value = "127.0.0.1:53")]
    servers: String,

    /// Number of queries to send per server
    #[arg(long, default_value_t = 1000)]
    queries: usize,

    /// Concurrent in-flight queries per server
    #[arg(long, default_value_t = 10)]
    concurrency: usize,

    /// Timeout per query in milliseconds
    #[arg(long, default_value_t = 2000)]
    timeout_ms: u64,

    /// Warmup queries before timing
    #[arg(long, default_value_t = 10)]
    warmup: usize,

    /// Skip ICMP ping (for systems without ICMP)
    #[arg(long)]
    no_ping: bool,

    /// Benchmark mode: mixed, sinkhole, cached, forwarded
    #[arg(long, default_value = "mixed")]
    mode: String,

    /// Sustained duration mode: run for N seconds at a target QPS
    /// (overrides --queries)
    #[arg(long)]
    duration_secs: Option<u64>,

    /// Target queries per second (use with --duration-secs)
    #[arg(long)]
    target_qps: Option<u64>,

    /// RustBlocker web API URL (for server-side stats capture)
    #[arg(long)]
    api_url: Option<String>,
}

#[derive(Clone, Default)]
struct ServerResult {
    latencies: Vec<Duration>,
    errors: usize,
    total: usize,
    /// Wall-clock time for the entire benchmark run.
    wall: Duration,
    /// Count of responses with unexpected response codes (correctness).
    bad_responses: usize,
}

impl ServerResult {
    fn new() -> Self {
        Self::default()
    }

    fn percentile(&self, p: f64) -> Duration {
        if self.latencies.is_empty() {
            return Duration::ZERO;
        }
        let mut sorted = self.latencies.clone();
        sorted.sort();
        let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
        sorted[idx.min(sorted.len() - 1)]
    }

    /// True throughput: total queries / wall-clock seconds.
    fn qps(&self) -> f64 {
        if self.wall.is_zero() {
            0.0
        } else {
            self.total as f64 / self.wall.as_secs_f64()
        }
    }
}

/// Global query ID counter — avoids needing rand.
static QUERY_ID: AtomicU16 = AtomicU16::new(0);

/// Build a DNS query packet using hickory_proto (not hand-rolled).
/// Returns (query_id, packet) so the caller can validate the response ID.
fn build_query(domain: &str, qtype: RecordType) -> (u16, Vec<u8>) {
    let id = QUERY_ID.fetch_add(1, Ordering::Relaxed);
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    let name = Name::from_ascii(format!("{}.", domain)).expect("invalid domain");
    msg.add_query(Query::query(name, qtype));
    let packet = msg.to_vec().expect("failed to encode DNS query");
    (id, packet)
}

/// Send a single DNS query, returning (RTT, response_code_bool).
/// Binds a fresh ephemeral socket per call so concurrent tasks never steal
/// each other's responses. Retries once on timeout (cold-start race).
///
/// Returns (latency, is_noerror) on success.
async fn query_once(
    server: SocketAddr,
    domain: &str,
    qtype: RecordType,
    timeout: Duration,
) -> Result<(Duration, bool), &'static str> {
    let (query_id, packet) = build_query(domain, qtype);
    let sock = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|_| "bind failed")?;
    let mut buf = vec![0u8; 1024];

    for attempt in 0..2 {
        let start = Instant::now();
        sock.send_to(&packet, server)
            .await
            .map_err(|_| "send failed")?;

        tokio::select! {
            result = sock.recv_from(&mut buf) => {
                let (len, _) = result.map_err(|_| "recv failed")?;
                if len >= 4 {
                    // Validate response ID against the captured query ID.
                    if buf[0] == (query_id >> 8) as u8 && buf[1] == (query_id & 0xff) as u8 {
                        // Extract response code from byte 3, lower 4 bits.
                        let rcode = buf[3] & 0x0F;
                        let is_noerror = rcode == 0;
                        return Ok((start.elapsed(), is_noerror));
                    }
                }
            }
            _ = tokio::time::sleep(timeout) => {
                if attempt == 0 {
                    continue; // retry once
                }
                return Err("timed out");
            }
        }
    }
    Err("no valid response after retries")
}

/// Warmup: send a few queries before timing to prime caches & sockets.
async fn warmup(server: SocketAddr, mode: Mode, count: usize, timeout: Duration) {
    let domains = mode.domains();
    for i in 0..count {
        let (domain, qtype) = domains[i % domains.len()];
        let _ = query_once(server, domain, qtype, timeout).await;
    }
}

/// Pick a query for the given index and mode.
fn pick_query(index: usize, mode: Mode) -> (&'static str, RecordType) {
    let domains = mode.domains();
    let (domain, qtype) = domains[index % domains.len()];
    (domain, qtype)
}

/// Benchmark a single server with concurrent queries (fixed count).
async fn benchmark_server(
    addr: SocketAddr,
    mode: Mode,
    total_queries: usize,
    concurrency: usize,
    timeout: Duration,
    warmup_count: usize,
) -> ServerResult {
    warmup(addr, mode, warmup_count, timeout).await;

    let result = Arc::new(Mutex::new(ServerResult::new()));
    let sem = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut handles = Vec::new();

    let wall_start = Instant::now();
    for i in 0..total_queries {
        let (domain, qtype) = pick_query(i, mode);
        let result = result.clone();
        let sem = sem.clone();

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.expect("semaphore closed");
            match query_once(addr, domain, qtype, timeout).await {
                Ok((lat, is_noerror)) => {
                    let mut r = result.lock().await;
                    r.latencies.push(lat);
                    if !is_noerror {
                        r.bad_responses += 1;
                    }
                }
                Err(e) => {
                    eprintln!("  error: {e}");
                    let mut r = result.lock().await;
                    r.errors += 1;
                }
            }
            result.lock().await.total += 1;
        }));
    }

    for h in handles {
        let _ = h.await;
    }
    let wall = wall_start.elapsed();

    let mut r = result.lock().await;
    r.wall = wall;
    r.clone()
}

/// Sustained-duration benchmark: fire at a target QPS for N seconds.
async fn benchmark_sustained(
    addr: SocketAddr,
    mode: Mode,
    duration: Duration,
    target_qps: u64,
    concurrency: usize,
    timeout: Duration,
    warmup_count: usize,
) -> ServerResult {
    warmup(addr, mode, warmup_count, timeout).await;

    let result = Arc::new(Mutex::new(ServerResult::new()));
    let sem = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let interval = Duration::from_secs_f64(1.0 / target_qps as f64);
    let mut handles = Vec::new();
    let mut i = 0usize;

    let wall_start = Instant::now();
    let mut tick = tokio::time::interval(interval);
    tick.tick().await; // skip first immediate tick

    while wall_start.elapsed() < duration {
        tick.tick().await;
        let (domain, qtype) = pick_query(i, mode);
        i += 1;
        let result = result.clone();
        let sem = sem.clone();

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.expect("semaphore closed");
            match query_once(addr, domain, qtype, timeout).await {
                Ok((lat, is_noerror)) => {
                    let mut r = result.lock().await;
                    r.latencies.push(lat);
                    if !is_noerror {
                        r.bad_responses += 1;
                    }
                }
                Err(e) => {
                    eprintln!("  error: {e}");
                    let mut r = result.lock().await;
                    r.errors += 1;
                }
            }
            result.lock().await.total += 1;
        }));
    }

    // Wait for all in-flight to complete.
    for h in handles {
        let _ = h.await;
    }
    let wall = wall_start.elapsed();

    let mut r = result.lock().await;
    r.wall = wall;
    r.clone()
}

/// Measure ICMP ping RTT (best of 3) using the system ping command.
fn ping_rtt(addr: &str) -> Option<Duration> {
    let ip = addr.split(':').next().unwrap_or(addr);
    let output = std::process::Command::new("ping")
        .args(["-n", "3", "-w", "500", ip])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let avg_line = stdout.lines().find(|l| l.contains("Average"))?;
    let avg_str = avg_line
        .split("Average = ")
        .nth(1)?
        .trim_end_matches("ms")
        .trim();
    let avg_ms: f64 = avg_str.parse().ok()?;
    Some(Duration::from_secs_f64(avg_ms / 1000.0))
}

/// Fetch server-side stats from the RustBlocker web API.
async fn fetch_api_stats(api_url: &str) -> Option<serde_json::Value> {
    let url = format!("{}/api/stats", api_url.trim_end_matches('/'));
    let body = reqwest::get(&url).await.ok()?.text().await.ok()?;
    serde_json::from_str(&body).ok()
}

fn format_us(d: Duration) -> String {
    format!("{:.2}ms", d.as_secs_f64() * 1000.0)
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let servers: Vec<SocketAddr> = cli
        .servers
        .split(',')
        .map(|s| s.trim().parse().expect("invalid server address"))
        .collect();
    let timeout = Duration::from_millis(cli.timeout_ms);
    let mode = Mode::from_str(&cli.mode);

    println!("DNS Benchmark");
    println!(
        "  Servers:     {}",
        servers
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("  Mode:        {}", cli.mode);
    if let Some(dur) = cli.duration_secs {
        println!("  Duration:    {}s", dur);
        println!("  Target QPS:  {}", cli.target_qps.unwrap_or(100));
    } else {
        println!("  Queries:     {} per server", cli.queries);
    }
    println!("  Concurrency: {} per server", cli.concurrency);
    println!("  Timeout:     {}ms", cli.timeout_ms);
    println!("  Warmup:      {} queries", cli.warmup);
    println!();

    // Ping RTT for each server (topology awareness)
    if !cli.no_ping {
        println!("Network topology (ICMP ping RTT):");
        for addr in &servers {
            let ip = addr.to_string();
            if let Some(rtt) = ping_rtt(&ip) {
                println!("  {:<22} ping RTT: {}", ip, format_us(rtt));
            } else {
                println!("  {:<22} ping RTT: (unavailable)", ip);
            }
        }
        println!();
        println!("  Note: DNS latency includes ping RTT. For sinkhole mode,");
        println!("  the DNS delta from ping RTT isolates server processing time.");
        println!();
    }

    // Capture server-side stats before the bench (RustBlocker only).
    let api_url = cli.api_url.as_deref();
    let stats_before = if let Some(url) = api_url {
        fetch_api_stats(url).await
    } else {
        None
    };
    if stats_before.is_some() {
        println!(
            "  Capturing server-side stats from API: {}",
            api_url.unwrap()
        );
        println!();
    }

    let mut results = Vec::new();
    for addr in &servers {
        print!("Benchmarking {} ... ", addr);
        std::io::Write::flush(&mut std::io::stdout()).ok();

        let result = if let Some(dur) = cli.duration_secs {
            benchmark_sustained(
                *addr,
                mode,
                Duration::from_secs(dur),
                cli.target_qps.unwrap_or(100),
                cli.concurrency,
                timeout,
                cli.warmup,
            )
            .await
        } else {
            benchmark_server(
                *addr,
                mode,
                cli.queries,
                cli.concurrency,
                timeout,
                cli.warmup,
            )
            .await
        };

        println!("done in {:.1}s (wall)", result.wall.as_secs_f64());
        results.push((addr.to_string(), result));
    }

    println!();
    println!(
        "{:<22} {:>8} {:>8} {:>8} {:>8} {:>8} {:>10} {:>8}",
        "Server", "Queries", "Errors", "BadResp", "Median", "P99", "QPS", "Wall"
    );
    println!("{}", "-".repeat(92));
    for (name, r) in &results {
        println!(
            "{:<22} {:>8} {:>8} {:>8} {:>8} {:>8} {:>10.0} {:>7.1}s",
            name,
            r.total,
            r.errors,
            r.bad_responses,
            format_us(r.percentile(0.5)),
            format_us(r.percentile(0.99)),
            r.qps(),
            r.wall.as_secs_f64(),
        );
    }

    // Relative comparison
    if results.len() >= 2 {
        println!();
        println!("Relative comparison (vs first server):");
        let baseline = results[0].1.percentile(0.5);
        let baseline_qps = results[0].1.qps();
        for (name, r) in &results[1..] {
            let med = r.percentile(0.5);
            if med.is_zero() || baseline.is_zero() {
                println!("  {}: cannot compare (zero latency)", name);
                continue;
            }
            let ratio = med.as_secs_f64() / baseline.as_secs_f64();
            let label = if ratio > 1.0 {
                format!("{:.2}x slower", ratio)
            } else {
                format!("{:.2}x faster", 1.0 / ratio)
            };
            let qps_ratio = r.qps() / baseline_qps;
            println!(
                "  {:<22} median {} vs {} — {} | QPS {:.0} vs {:.0} ({:.2}x)",
                name,
                format_us(med),
                format_us(baseline),
                label,
                r.qps(),
                baseline_qps,
                qps_ratio,
            );
        }
    }

    // Server-side stats after the bench.
    if let Some(url) = api_url {
        if let Some(after) = fetch_api_stats(url).await {
            println!();
            println!("Server-side stats (from API):");
            if let Some(before) = &stats_before {
                let before_q = before
                    .get("total_queries")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let after_q = after
                    .get("total_queries")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let before_blocked = before.get("blocked").and_then(|v| v.as_u64()).unwrap_or(0);
                let after_blocked = after.get("blocked").and_then(|v| v.as_u64()).unwrap_or(0);
                let before_fwd = before
                    .get("forwarded")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let after_fwd = after.get("forwarded").and_then(|v| v.as_u64()).unwrap_or(0);
                println!(
                    "  Total queries:  {} -> {} (delta: {})",
                    before_q,
                    after_q,
                    after_q.saturating_sub(before_q)
                );
                println!(
                    "  Blocked:        {} -> {} (delta: {})",
                    before_blocked,
                    after_blocked,
                    after_blocked.saturating_sub(before_blocked)
                );
                println!(
                    "  Forwarded:      {} -> {} (delta: {})",
                    before_fwd,
                    after_fwd,
                    after_fwd.saturating_sub(before_fwd)
                );
            }
        }
    }

    // Fairness notes
    if mode == Mode::Forwarded || mode == Mode::Mixed {
        println!();
        println!("Note: forwarded queries include upstream round-trip time.");
        println!("For server-only processing, use --mode sinkhole.");
    }
    if results.len() >= 2 {
        println!();
        println!("Note: if upstreams differ, latency is dominated by the upstream,");
        println!("not the local server. For a fair comparison:");
        println!("  1. Configure both servers with the same upstream (e.g. 8.8.8.8)");
        println!("  2. Use --mode sinkhole to measure server-only processing");
        println!("  3. Run the benchmark from a third machine for balanced paths");
    }
}
