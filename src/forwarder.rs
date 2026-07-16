use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use futures::future::{BoxFuture, FutureExt};
use futures::stream::{FuturesUnordered, StreamExt};
use hickory_net::{DnsError, NetError};
use hickory_proto::op::{Metadata, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordData, RecordType};
use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::lookup::Lookup;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::{Resolver, TokioResolver};
use hickory_server::server::{ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::config::UpstreamConfig;

const DEFAULT_HEDGE_DELAY_MS: u64 = 75;
const DEFAULT_MAX_ADAPTIVE_PARALLEL: usize = 2;
const DEFAULT_LATENCY_SCORE_US: u64 = 50_000;
const FAILURE_PENALTY_US: u64 = 500_000;

/// Result of a successful upstream resolve, including timing info.
pub struct ResolveResult {
    pub info: ResponseInfo,
    pub resolver: String,
    pub latency_us: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ForwardStrategy {
    #[default]
    Adaptive,
    Parallel,
}

impl ForwardStrategy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Adaptive => "adaptive",
            Self::Parallel => "parallel",
        }
    }
}

impl std::str::FromStr for ForwardStrategy {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "adaptive" => Ok(Self::Adaptive),
            "parallel" => Ok(Self::Parallel),
            _ => Err(format!("invalid forward strategy: {value}")),
        }
    }
}

#[derive(Debug)]
struct UpstreamHealth {
    latency_score_us: AtomicU64,
    failures: AtomicU64,
}

impl UpstreamHealth {
    fn new() -> Self {
        Self {
            latency_score_us: AtomicU64::new(DEFAULT_LATENCY_SCORE_US),
            failures: AtomicU64::new(0),
        }
    }

    fn rank_score(&self) -> u64 {
        self.latency_score_us
            .load(Ordering::Relaxed)
            .saturating_add(
                self.failures
                    .load(Ordering::Relaxed)
                    .saturating_mul(FAILURE_PENALTY_US),
            )
    }

    fn record_success(&self, latency_us: u64) {
        let previous = self.latency_score_us.load(Ordering::Relaxed);
        let updated = previous
            .saturating_mul(7)
            .saturating_add(latency_us)
            .saturating_div(8)
            .max(1);
        self.latency_score_us.store(updated, Ordering::Relaxed);

        let failures = self.failures.load(Ordering::Relaxed);
        if failures > 0 {
            self.failures.store(failures - 1, Ordering::Relaxed);
        }
    }

    fn record_hedged_miss(&self, elapsed_us: u64) {
        let previous = self.latency_score_us.load(Ordering::Relaxed);
        if elapsed_us > previous {
            self.latency_score_us.store(elapsed_us, Ordering::Relaxed);
        }
    }

    fn record_failure(&self) {
        let failures = self.failures.load(Ordering::Relaxed);
        self.failures
            .store(failures.saturating_add(1).min(16), Ordering::Relaxed);
    }
}

type LookupFuture = BoxFuture<'static, (usize, std::result::Result<Lookup, NetError>)>;

enum ForwardAttemptError {
    Upstream(Option<NetError>),
    Response(anyhow::Error),
}

fn lookup_future(
    idx: usize,
    resolver: TokioResolver,
    name: Name,
    query_type: RecordType,
) -> LookupFuture {
    async move { (idx, resolver.lookup(name, query_type).await) }.boxed()
}

/// DNS forwarder with configurable upstream selection strategy.
pub struct ParallelForwarder {
    resolvers: Arc<Vec<TokioResolver>>,
    addresses: Arc<Vec<String>>,
    health: Arc<Vec<UpstreamHealth>>,
    timeout: Duration,
    strategy: ForwardStrategy,
    hedge_delay: Duration,
    max_adaptive_parallel: usize,
}

impl Clone for ParallelForwarder {
    fn clone(&self) -> Self {
        Self {
            resolvers: self.resolvers.clone(),
            addresses: self.addresses.clone(),
            health: self.health.clone(),
            timeout: self.timeout,
            strategy: self.strategy,
            hedge_delay: self.hedge_delay,
            max_adaptive_parallel: self.max_adaptive_parallel,
        }
    }
}

impl ParallelForwarder {
    /// Default cache size per resolver: 256K responses (was 1M).
    /// All upstreams query the same domain space, so most entries overlap.
    /// Reducing per-resolver cache cuts total memory ~4× with negligible
    /// cache-miss penalty (queries still hit the fastest upstream first).
    const DEFAULT_CACHE_SIZE: u64 = 256_000;
    /// More aggressive hedging: fan out to 3 upstreams simultaneously.
    const DEFAULT_NUM_CONCURRENT_REQS: usize = 3;
    /// Shorter negative TTL to avoid caching stale NXDOMAIN/NODATA too long.
    const DEFAULT_NEGATIVE_MIN_TTL_SECS: u64 = 600; // 10 minutes

    pub fn new(upstreams: &[UpstreamConfig], timeout_secs: u64) -> Result<Self> {
        Self::new_with_strategy(upstreams, timeout_secs, ForwardStrategy::default())
    }

    pub fn new_with_strategy(
        upstreams: &[UpstreamConfig],
        timeout_secs: u64,
        strategy: ForwardStrategy,
    ) -> Result<Self> {
        let mut resolvers = Vec::with_capacity(upstreams.len());
        let mut addresses = Vec::with_capacity(upstreams.len());
        for upstream in upstreams {
            let ip: IpAddr = upstream
                .address
                .parse()
                .with_context(|| format!("Invalid upstream IP: {}", upstream.address))?;

            let ns_config = NameServerConfig::udp_and_tcp(ip);
            let config = ResolverConfig::from_parts(None, vec![], vec![ns_config]);

            // Tune resolver opts: smaller shared cache, more concurrent requests.
            let mut opts = ResolverOpts::default();
            opts.cache_size = Self::DEFAULT_CACHE_SIZE;
            opts.num_concurrent_reqs = Self::DEFAULT_NUM_CONCURRENT_REQS;
            opts.negative_min_ttl = Some(Duration::from_secs(Self::DEFAULT_NEGATIVE_MIN_TTL_SECS));

            let resolver = Resolver::builder_with_config(config, TokioRuntimeProvider::default())
                .with_options(opts)
                .build()?;
            resolvers.push(resolver);
            addresses.push(upstream.address.clone());
            debug!("Added upstream resolver: {}", upstream.address);
        }

        Ok(Self {
            health: Arc::new(
                (0..resolvers.len())
                    .map(|_| UpstreamHealth::new())
                    .collect(),
            ),
            resolvers: Arc::new(resolvers),
            addresses: Arc::new(addresses),
            timeout: Duration::from_secs(timeout_secs),
            strategy,
            hedge_delay: Duration::from_millis(DEFAULT_HEDGE_DELAY_MS),
            max_adaptive_parallel: DEFAULT_MAX_ADAPTIVE_PARALLEL,
        })
    }
    /// Reload upstream resolvers from a fresh config list.
    /// Called after adding/removing upstreams via the web API.
    pub fn reload(
        &mut self,
        upstreams: &[UpstreamConfig],
        timeout_secs: u64,
        strategy: ForwardStrategy,
    ) -> Result<()> {
        let fresh = Self::new_with_strategy(upstreams, timeout_secs, strategy)?;
        self.resolvers = fresh.resolvers;
        self.addresses = fresh.addresses;
        self.health = fresh.health;
        self.timeout = Duration::from_secs(timeout_secs);
        self.strategy = strategy;
        Ok(())
    }

    /// Update the upstream timeout without rebuilding resolvers.
    pub fn set_timeout(&mut self, timeout_secs: u64) {
        self.timeout = Duration::from_secs(timeout_secs);
    }

    pub fn set_strategy(&mut self, strategy: ForwardStrategy) {
        self.strategy = strategy;
    }

    pub fn strategy(&self) -> ForwardStrategy {
        self.strategy
    }

    fn adaptive_order(&self) -> Vec<usize> {
        let mut indexes: Vec<usize> = (0..self.resolvers.len()).collect();
        indexes.sort_by_key(|idx| {
            self.health
                .get(*idx)
                .map(UpstreamHealth::rank_score)
                .unwrap_or(u64::MAX)
        });
        indexes
    }

    fn record_success(&self, idx: usize, latency_us: u64) {
        if let Some(health) = self.health.get(idx) {
            health.record_success(latency_us);
        }
    }

    fn record_hedged_misses(&self, launched: &[usize], winner: usize, elapsed_us: u64) {
        for idx in launched {
            if *idx != winner
                && let Some(health) = self.health.get(*idx)
            {
                health.record_hedged_miss(elapsed_us);
            }
        }
    }

    fn record_failure(&self, idx: usize) {
        if let Some(health) = self.health.get(idx) {
            health.record_failure();
        }
    }

    /// Resolve a DNS lookup through the configured upstream forwarding strategy.
    pub async fn resolve(
        &self,
        request: &hickory_server::server::Request,
        mut response_handle: impl hickory_server::server::ResponseHandler,
    ) -> Result<ResolveResult> {
        let query = request
            .queries
            .queries()
            .first()
            .expect("request must have a query");
        let name = Name::from(query.name());
        let query_type = query.query_type();

        debug!(
            "Forwarding query: {} ({}) using {} strategy",
            name,
            query_type,
            self.strategy.as_str()
        );

        let start = Instant::now();
        match self.strategy {
            ForwardStrategy::Adaptive => {
                self.resolve_adaptive(request, &mut response_handle, name, query_type, start)
                    .await
            }
            ForwardStrategy::Parallel => {
                self.resolve_parallel(request, &mut response_handle, name, query_type, start)
                    .await
            }
        }
    }

    async fn resolve_parallel(
        &self,
        request: &hickory_server::server::Request,
        response_handle: &mut impl ResponseHandler,
        name: Name,
        query_type: RecordType,
        start: Instant,
    ) -> Result<ResolveResult> {
        let futures: Vec<_> = self
            .resolvers
            .iter()
            .enumerate()
            .map(|(idx, resolver)| {
                let name = name.clone();
                let rtype = query_type;
                async move { (idx, resolver.lookup(name, rtype).await) }
            })
            .collect();

        let result = timeout(self.timeout, async {
            let mut last_err: Option<NetError> = None;
            let mut futs: Vec<_> = futures.into_iter().map(Box::pin).collect();
            while !futs.is_empty() {
                let (resolved, _idx, remaining) = futures::future::select_all(futs).await;
                futs = remaining;
                match resolved {
                    (idx, Ok(lookup)) => {
                        let latency_us = start.elapsed().as_micros() as u64;
                        self.record_success(idx, latency_us);
                        return self
                            .send_lookup_response(
                                request,
                                response_handle,
                                idx,
                                query_type,
                                &lookup,
                                latency_us,
                            )
                            .await
                            .map_err(ForwardAttemptError::Response);
                    }
                    (idx, Err(e)) => {
                        debug!("Upstream resolver failed: {}", e);
                        if is_negative_response(&e) {
                            let latency_us = start.elapsed().as_micros() as u64;
                            self.record_success(idx, latency_us);
                            let (info, resolver) =
                                build_error_response(request, response_handle, &e)
                                    .await
                                    .map_err(ForwardAttemptError::Response)?;
                            return Ok(ResolveResult {
                                info,
                                resolver,
                                latency_us,
                            });
                        }
                        self.record_failure(idx);
                        last_err = Some(e);
                    }
                }
            }
            Err(ForwardAttemptError::Upstream(last_err))
        })
        .await;

        match result {
            Ok(Ok(resolve_result)) => Ok(resolve_result),
            Ok(Err(ForwardAttemptError::Upstream(Some(last_err)))) => {
                let latency_us = start.elapsed().as_micros() as u64;
                let (info, resolver) =
                    build_error_response(request, response_handle, &last_err).await?;
                Ok(ResolveResult {
                    info,
                    resolver,
                    latency_us,
                })
            }
            Ok(Err(ForwardAttemptError::Upstream(None))) => {
                warn!("All upstream resolvers failed without a captured error");
                Ok(ResolveResult {
                    info: send_servfail(request, response_handle).await?,
                    resolver: "error".to_string(),
                    latency_us: start.elapsed().as_micros() as u64,
                })
            }
            Ok(Err(ForwardAttemptError::Response(e))) => Err(e),
            Err(_) => {
                warn!("All upstream resolvers timed out, sending SERVFAIL");
                Ok(ResolveResult {
                    info: send_servfail(request, response_handle).await?,
                    resolver: "timeout".to_string(),
                    latency_us: start.elapsed().as_micros() as u64,
                })
            }
        }
    }

    async fn resolve_adaptive(
        &self,
        request: &hickory_server::server::Request,
        response_handle: &mut impl ResponseHandler,
        name: Name,
        query_type: RecordType,
        start: Instant,
    ) -> Result<ResolveResult> {
        let order = self.adaptive_order();
        if order.is_empty() {
            warn!("No upstream resolvers configured");
            return Ok(ResolveResult {
                info: send_servfail(request, response_handle).await?,
                resolver: "error".to_string(),
                latency_us: start.elapsed().as_micros() as u64,
            });
        }

        let max_parallel = self.max_adaptive_parallel.max(1).min(order.len());
        let result = timeout(self.timeout, async {
            let mut in_flight: FuturesUnordered<LookupFuture> = FuturesUnordered::new();
            let mut next = 0usize;
            let mut launched = Vec::with_capacity(max_parallel);
            let mut last_err: Option<NetError> = None;
            let mut hedge_delay = Box::pin(tokio::time::sleep(self.hedge_delay));

            let launch = |idx: usize,
                          in_flight: &mut FuturesUnordered<LookupFuture>,
                          launched: &mut Vec<usize>| {
                if let Some(resolver) = self.resolvers.get(idx).cloned() {
                    in_flight.push(lookup_future(idx, resolver, name.clone(), query_type));
                    launched.push(idx);
                }
            };

            launch(order[next], &mut in_flight, &mut launched);
            next += 1;

            loop {
                if in_flight.is_empty() {
                    if next >= order.len() {
                        return Err(ForwardAttemptError::Upstream(last_err));
                    }
                    launch(order[next], &mut in_flight, &mut launched);
                    next += 1;
                    hedge_delay = Box::pin(tokio::time::sleep(self.hedge_delay));
                }

                tokio::select! {
                    resolved = in_flight.next() => {
                        match resolved {
                            Some((idx, Ok(lookup))) => {
                                let latency_us = start.elapsed().as_micros() as u64;
                                self.record_success(idx, latency_us);
                                self.record_hedged_misses(&launched, idx, latency_us);
                                return self
                                    .send_lookup_response(
                                        request,
                                        response_handle,
                                        idx,
                                        query_type,
                                        &lookup,
                                        latency_us,
                                    )
                                    .await
                                    .map_err(ForwardAttemptError::Response);
                            }
                            Some((idx, Err(e))) => {
                                debug!("Upstream resolver failed: {}", e);
                                if is_negative_response(&e) {
                                    let latency_us = start.elapsed().as_micros() as u64;
                                    self.record_success(idx, latency_us);
                                    let (info, resolver) =
                                        build_error_response(request, response_handle, &e)
                                            .await
                                            .map_err(ForwardAttemptError::Response)?;
                                    return Ok(ResolveResult {
                                        info,
                                        resolver,
                                        latency_us,
                                    });
                                }

                                self.record_failure(idx);
                                last_err = Some(e);
                                if in_flight.len() < max_parallel && next < order.len() {
                                    launch(order[next], &mut in_flight, &mut launched);
                                    next += 1;
                                    hedge_delay = Box::pin(tokio::time::sleep(self.hedge_delay));
                                }
                            }
                            None => {}
                        }
                    }
                    _ = &mut hedge_delay, if in_flight.len() < max_parallel && next < order.len() => {
                        launch(order[next], &mut in_flight, &mut launched);
                        next += 1;
                        hedge_delay = Box::pin(tokio::time::sleep(self.hedge_delay));
                    }
                }
            }
        })
        .await;

        match result {
            Ok(Ok(resolve_result)) => Ok(resolve_result),
            Ok(Err(ForwardAttemptError::Upstream(Some(last_err)))) => {
                let latency_us = start.elapsed().as_micros() as u64;
                let (info, resolver) =
                    build_error_response(request, response_handle, &last_err).await?;
                Ok(ResolveResult {
                    info,
                    resolver,
                    latency_us,
                })
            }
            Ok(Err(ForwardAttemptError::Upstream(None))) => {
                warn!("All upstream resolvers failed without a captured error");
                Ok(ResolveResult {
                    info: send_servfail(request, response_handle).await?,
                    resolver: "error".to_string(),
                    latency_us: start.elapsed().as_micros() as u64,
                })
            }
            Ok(Err(ForwardAttemptError::Response(e))) => Err(e),
            Err(_) => {
                warn!("Adaptive upstream resolvers timed out, sending SERVFAIL");
                Ok(ResolveResult {
                    info: send_servfail(request, response_handle).await?,
                    resolver: "timeout".to_string(),
                    latency_us: start.elapsed().as_micros() as u64,
                })
            }
        }
    }

    async fn send_lookup_response(
        &self,
        request: &hickory_server::server::Request,
        response_handle: &mut impl ResponseHandler,
        idx: usize,
        query_type: RecordType,
        lookup: &Lookup,
        latency_us: u64,
    ) -> Result<ResolveResult> {
        let answers = extract_answers(query_type, lookup);
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut metadata = Metadata::response_from_request(&request.metadata);
        metadata.response_code = ResponseCode::NoError;
        let response = builder.build(metadata, answers.iter(), [].iter(), [].iter(), [].iter());
        let info = response_handle.send_response(response).await?;
        let resolver = self
            .addresses
            .get(idx)
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
        Ok(ResolveResult {
            info,
            resolver,
            latency_us,
        })
    }
}

fn extract_answers(
    query_type: RecordType,
    lookup: &hickory_resolver::lookup::Lookup,
) -> Vec<Record> {
    let mut answers = Vec::new();
    for record in lookup.answers() {
        match query_type {
            RecordType::A | RecordType::AAAA => {
                // Preserve CNAME records so clients can follow the alias
                // chain (e.g. click.redditmail.com -> CNAME thirdparty.bnc.lt
                // -> A 52.11.118.109). Dropping the CNAME leaves a bare A
                // answer whose name does not match the query name, which
                // stub resolvers reject.
                match record.data {
                    RData::A(_) | RData::AAAA(_) | RData::CNAME(_) => {
                        answers.push(Record::from_rdata(
                            record.name.clone(),
                            record.ttl,
                            record.data.clone(),
                        ));
                    }
                    _ => {}
                }
            }
            _ => {
                // Non-address query types: pass through matching records.
                if record.record_type() == query_type {
                    answers.push(Record::from_rdata(
                        record.name.clone(),
                        record.ttl,
                        record.data.clone(),
                    ));
                }
            }
        }
    }
    answers
}

/// Classify an upstream error into a response code and resolver label.
///
/// Returns `(response_code, label)`:
/// - `NoRecordsFound` (NODATA / NXDomain) → the upstream's original code,
///   `"negative"`. These are legitimate responses, not failures.
/// - Any other error → `ServFail`, `"error"`. Real transport/protocol
///   failures warrant SERVFAIL.
fn classify_upstream_error(err: &NetError) -> (ResponseCode, &'static str) {
    match err {
        NetError::Dns(DnsError::NoRecordsFound(no_records)) => {
            (no_records.response_code, "negative")
        }
        _ => (ResponseCode::ServFail, "error"),
    }
}

fn is_negative_response(err: &NetError) -> bool {
    matches!(classify_upstream_error(err), (_, "negative"))
}

/// Build a response for an upstream error, forwarding legitimate negative
/// responses (NODATA / NXDomain) verbatim and SERVFAIL for real failures.
async fn build_error_response(
    request: &hickory_server::server::Request,
    response_handle: &mut impl hickory_server::server::ResponseHandler,
    err: &NetError,
) -> Result<(ResponseInfo, String)> {
    let (rcode, label) = classify_upstream_error(err);
    if label == "negative" {
        // NoRecordsFound carries optional SOA + authority records that should
        // be preserved for downstream negative caching.
        let no_records = match err {
            NetError::Dns(DnsError::NoRecordsFound(nr)) => nr,
            _ => unreachable!(),
        };
        let ttl = no_records.negative_ttl.unwrap_or(0);
        let soa_records: Vec<Record> = no_records
            .soa
            .as_ref()
            .map(|soa| {
                Record::from_rdata(
                    soa.name.clone(),
                    ttl.max(soa.ttl),
                    soa.data.clone().into_rdata(),
                )
            })
            .into_iter()
            .collect();
        let auth_records: Vec<Record> = no_records
            .authorities
            .as_ref()
            .map(|a| a.iter().cloned().collect())
            .unwrap_or_default();

        debug!(
            "Forwarding {} response (negative) for {} (ttl={})",
            rcode, no_records.query, ttl,
        );

        let builder = MessageResponseBuilder::from_message_request(request);
        let mut metadata = Metadata::response_from_request(&request.metadata);
        metadata.response_code = rcode;
        let response = builder.build(
            metadata,
            [].iter(),
            auth_records.iter(),
            soa_records.iter(),
            [].iter(),
        );
        let info = response_handle.send_response(response).await?;
        Ok((info, label.to_string()))
    } else {
        warn!("Forwarding error: {}, sending SERVFAIL", err);
        let info = send_servfail(request, response_handle).await?;
        Ok((info, label.to_string()))
    }
}

async fn send_servfail(
    request: &hickory_server::server::Request,
    response_handle: &mut impl hickory_server::server::ResponseHandler,
) -> Result<ResponseInfo> {
    let builder = MessageResponseBuilder::from_message_request(request);
    let response = builder.error_msg(&request.metadata, ResponseCode::ServFail);
    let info = response_handle.send_response(response).await?;
    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_net::NoRecords;
    use hickory_proto::op::Query;
    use hickory_proto::rr::rdata::{A, CNAME};
    use hickory_proto::rr::{Name, RData};
    use hickory_resolver::lookup::Lookup;
    use std::net::Ipv4Addr;

    fn record(name: &str, ttl: u32, data: RData) -> Record {
        Record::from_rdata(Name::from_ascii(format!("{}.", name)).unwrap(), ttl, data)
    }

    /// Regression: an A query for a CNAME-chained domain (e.g.
    /// click.redditmail.com -> CNAME thirdparty.bnc.lt -> A 52.11.118.109)
    /// must keep the CNAME record in the answer so stub resolvers can link
    /// the A answer back to the queried name.
    #[test]
    fn extract_answers_preserves_cname_chain_for_a_query() {
        let query = Query::query(
            Name::from_ascii("click.redditmail.com.").unwrap(),
            RecordType::A,
        );
        let answers = vec![
            record(
                "click.redditmail.com",
                300,
                RData::CNAME(CNAME(Name::from_ascii("thirdparty.bnc.lt.").unwrap())),
            ),
            record(
                "thirdparty.bnc.lt",
                60,
                RData::A(A::from(Ipv4Addr::new(52, 11, 118, 109))),
            ),
        ];
        let lookup = Lookup::new_with_max_ttl(query, answers);

        let extracted = extract_answers(RecordType::A, &lookup);

        // Both the CNAME and the A record must survive.
        assert_eq!(
            extracted.len(),
            2,
            "CNAME record was dropped from answer chain"
        );
        assert!(extracted.iter().any(|r| matches!(r.data, RData::CNAME(_))));
        assert!(extracted.iter().any(|r| matches!(r.data, RData::A(_))));
    }

    /// A plain A query (no CNAME) must still return only the A record.
    #[test]
    fn extract_answers_returns_a_record_without_cname() {
        let query = Query::query(Name::from_ascii("example.com.").unwrap(), RecordType::A);
        let answers = vec![record(
            "example.com",
            60,
            RData::A(A::from(Ipv4Addr::new(93, 184, 216, 34))),
        )];
        let lookup = Lookup::new_with_max_ttl(query, answers);

        let extracted = extract_answers(RecordType::A, &lookup);
        assert_eq!(extracted.len(), 1);
        assert!(matches!(extracted[0].data, RData::A(_)));
    }

    // --- classify_upstream_error: response-code preservation for negative
    // responses (the core fix for the "AAAA forwarded error" bug) ---

    fn no_records_query(name: &str) -> Box<Query> {
        Query::query(
            Name::from_ascii(format!("{}.", name)).unwrap(),
            RecordType::AAAA,
        )
        .into()
    }

    /// NODATA: a domain exists but has no record of the queried type (e.g.
    /// github.com AAAA). Upstream returns NOERROR with 0 answers; this must
    /// be forwarded as NOERROR, not masked as SERVFAIL.
    #[test]
    fn classify_nodata_returns_noerror() {
        let nr = NoRecords::new(no_records_query("github.com"), ResponseCode::NoError);
        let err: NetError = DnsError::NoRecordsFound(nr).into();
        let (rcode, label) = classify_upstream_error(&err);
        assert_eq!(rcode, ResponseCode::NoError);
        assert_eq!(label, "negative");
    }

    /// NXDomain: the domain does not exist. Must be forwarded as NXDOMAIN,
    /// not SERVFAIL.
    #[test]
    fn classify_nxdomain_returns_nxdomain() {
        let nr = NoRecords::new(
            no_records_query("nonexistent.invalid"),
            ResponseCode::NXDomain,
        );
        let err: NetError = DnsError::NoRecordsFound(nr).into();
        let (rcode, label) = classify_upstream_error(&err);
        assert_eq!(rcode, ResponseCode::NXDomain);
        assert_eq!(label, "negative");
    }

    /// Real transport failures (timeout, IO) must still produce SERVFAIL.
    #[test]
    fn classify_transport_error_returns_servfail() {
        let err: NetError = std::io::Error::from(std::io::ErrorKind::TimedOut).into();
        let (rcode, label) = classify_upstream_error(&err);
        assert_eq!(rcode, ResponseCode::ServFail);
        assert_eq!(label, "error");
    }

    #[test]
    fn forward_strategy_parses_supported_values() {
        assert_eq!(
            "adaptive".parse::<ForwardStrategy>().unwrap(),
            ForwardStrategy::Adaptive
        );
        assert_eq!(
            "PARALLEL".parse::<ForwardStrategy>().unwrap(),
            ForwardStrategy::Parallel
        );
        assert!("sequential".parse::<ForwardStrategy>().is_err());
    }

    #[test]
    fn forwarder_defaults_to_adaptive_strategy() {
        let forwarder = ParallelForwarder::new(
            &[UpstreamConfig {
                address: "1.1.1.1".to_string(),
                port: Some(53),
            }],
            5,
        )
        .expect("forwarder construction");

        assert_eq!(forwarder.strategy(), ForwardStrategy::Adaptive);
    }

    #[test]
    fn adaptive_order_penalizes_failing_upstreams() {
        let forwarder = ParallelForwarder::new(
            &[
                UpstreamConfig {
                    address: "1.1.1.1".to_string(),
                    port: Some(53),
                },
                UpstreamConfig {
                    address: "8.8.8.8".to_string(),
                    port: Some(53),
                },
            ],
            5,
        )
        .expect("forwarder construction");

        assert_eq!(forwarder.adaptive_order()[0], 0);

        forwarder.record_failure(0);
        assert_eq!(forwarder.adaptive_order()[0], 1);

        forwarder.record_success(0, 1);
        assert_eq!(forwarder.adaptive_order()[0], 0);
    }
}
