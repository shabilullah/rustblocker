//! DNS benchmark — compares query latency and throughput across servers.
//!
//! Usage:
//!   cargo run --release --example benchmark -- --servers 192.168.0.3:53,10.0.1.1:53
//!   cargo run --release --example benchmark -- --servers 192.168.0.3:53,10.0.1.1:53 --queries 2000 --concurrency 20
//!
//! Sends real DNS queries (A, AAAA, CNAME chain, NODATA, NXDOMAIN) and
//! reports per-server median/p95/p99 latency, QPS, error rate, and ICMP
//! ping RTT so network-topology differences are visible. Includes a warmup
//! phase before timing.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

use clap::Parser;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

/// Query domains — realistic mix: A, AAAA, CNAME chains, NODATA, NXDOMAIN.
const BENCH_DOMAINS: &[(&str, RecordType)] = &[
    // A records
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
    // CNAME chains
    ("www.github.com", RecordType::A),
    ("www.google.com", RecordType::A),
    // AAAA (has AAAA)
    ("google.com", RecordType::AAAA),
    ("cloudflare.com", RecordType::AAAA),
    // AAAA NODATA (domain exists, no AAAA)
    ("github.com", RecordType::AAAA),
    ("stackoverflow.com", RecordType::AAAA),
    // NXDOMAIN
    ("nonexistent-bench-123.com", RecordType::A),
];

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
}

#[derive(Clone, Default)]
struct ServerResult {
    latencies: Vec<Duration>,
    errors: usize,
    total: usize,
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
}
/// Build a DNS query packet using hickory_proto (not hand-rolled).
/// Returns (query_id, packet) so the caller can validate the response ID.
/// Global query ID counter — avoids needing rand.
static QUERY_ID: AtomicU16 = AtomicU16::new(0);

fn build_query(domain: &str, qtype: RecordType) -> (u16, Vec<u8>) {
    let id = QUERY_ID.fetch_add(1, Ordering::Relaxed);
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    let name = Name::from_ascii(format!("{}.", domain)).expect("invalid domain");
    msg.add_query(Query::query(name, qtype));
    let packet = msg.to_vec().expect("failed to encode DNS query");
    (id, packet)
}

/// Send a single DNS query, returning RTT.
/// Binds a fresh ephemeral socket per call so concurrent tasks never steal
/// each other's responses. Retries once on timeout (cold-start race).
async fn query_once(
    server: SocketAddr,
    domain: &str,
    qtype: RecordType,
    timeout: Duration,
) -> Result<Duration, &'static str> {
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
                if len >= 2 {
                    // Validate response ID against the captured query ID,
                    // not a re-read of the global counter.
                    if buf[0] == (query_id >> 8) as u8 && buf[1] == (query_id & 0xff) as u8 {
                        return Ok(start.elapsed());
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
async fn warmup(server: SocketAddr, count: usize, timeout: Duration) {
    for i in 0..count {
        let (domain, qtype) = pick_query(i);
        let _ = query_once(server, domain, qtype, timeout).await;
    }
}

/// Benchmark a single server with concurrent queries.
/// Each task binds its own socket — no shared-socket demux problems.
async fn benchmark_server(
    addr: SocketAddr,
    total_queries: usize,
    concurrency: usize,
    timeout: Duration,
    warmup_count: usize,
) -> ServerResult {
    // Warmup phase
    warmup(addr, warmup_count, timeout).await;

    let result = Arc::new(Mutex::new(ServerResult::new()));
    let sem = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut handles = Vec::new();

    for i in 0..total_queries {
        let (domain, qtype) = pick_query(i);
        let result = result.clone();
        let sem = sem.clone();

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.expect("semaphore closed");
            match query_once(addr, domain, qtype, timeout).await {
                Ok(lat) => result.lock().await.latencies.push(lat),
                Err(_) => result.lock().await.errors += 1,
            }
            result.lock().await.total += 1;
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    let r = result.lock().await;
    r.clone()
}
fn pick_query(index: usize) -> (&'static str, RecordType) {
    let (domain, rtype) = BENCH_DOMAINS[index % BENCH_DOMAINS.len()];
    (domain, rtype)
}
/// Measure ICMP ping RTT (best of 3) using the system ping command.
fn ping_rtt(addr: &str) -> Option<Duration> {
    // Parse just the IP (strip port if present)
    let ip = addr.split(':').next().unwrap_or(addr);
    let output = std::process::Command::new("ping")
        .args(["-n", "3", "-w", "500", ip])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Windows ping output: "Minimum = 1ms, Maximum = 2ms, Average = 1ms"
    // Parse the "Average" value
    let avg_line = stdout.lines().find(|l| l.contains("Average"))?;
    let avg_str = avg_line
        .split("Average = ")
        .nth(1)?
        .trim_end_matches("ms")
        .trim();
    let avg_ms: f64 = avg_str.parse().ok()?;
    Some(Duration::from_secs_f64(avg_ms / 1000.0))
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

    println!("DNS Benchmark");
    println!(
        "  Servers:     {}",
        servers
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("  Queries:     {} per server", cli.queries);
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
        println!("  Note: DNS latency includes ping RTT. Compare the Delta between");
        println!("  DNS median and ping RTT to isolate DNS processing time.");
        println!();
    }

    let mut results = Vec::new();
    for addr in &servers {
        print!("Benchmarking {} ... ", addr);
        std::io::Write::flush(&mut std::io::stdout()).ok();
        let wall_start = Instant::now();
        let result =
            benchmark_server(*addr, cli.queries, cli.concurrency, timeout, cli.warmup).await;
        let wall = wall_start.elapsed();
        println!("done in {:.1}s (wall clock)", wall.as_secs_f64());
        results.push((addr.to_string(), result));
    }

    println!();
    println!(
        "{:<22} {:>8} {:>8} {:>8} {:>8} {:>8} {:>10}",
        "Server", "Queries", "Errors", "Median", "P95", "P99", "QPS"
    );
    println!("{}", "-".repeat(82));
    for (name, r) in &results {
        let qps = if r.latencies.is_empty() {
            0.0
        } else {
            r.latencies.len() as f64 / r.latencies.iter().sum::<Duration>().as_secs_f64()
        };
        println!(
            "{:<22} {:>8} {:>8} {:>8} {:>8} {:>8} {:>10.0}",
            name,
            r.total,
            r.errors,
            format_us(r.percentile(0.5)),
            format_us(r.percentile(0.95)),
            format_us(r.percentile(0.99)),
            qps,
        );
    }

    // Relative comparison
    if results.len() >= 2 {
        println!();
        println!("Relative comparison (vs first server):");
        let baseline = results[0].1.percentile(0.5);
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
            println!(
                "  {:<22} {} vs {} — {}",
                name,
                format_us(med),
                format_us(baseline),
                label
            );
        }

        println!();
        println!("Note: if upstreams differ, forwarder latency is dominated by the");
        println!("upstream DNS, not the local server. For a fair comparison:");
        println!("  1. Configure both servers with the same upstream (e.g. 8.8.8.8)");
        println!("  2. Use the same DNS port (53) for both");
        println!("  3. Run the benchmark from a third machine for balanced network paths");
    }
}
