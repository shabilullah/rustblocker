use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use futures::future::{BoxFuture, FutureExt};
use futures::stream::{FuturesUnordered, StreamExt};
use hickory_net::NetError;
use hickory_net::proto::op::{DnsRequest, DnsRequestOptions, DnsResponse, Message, ResponseCode};
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::tcp::TcpClientStream;
use hickory_net::udp::UdpClientStream;
use hickory_net::xfer::{DnsExchange, DnsHandle, FirstAnswer};
use hickory_proto::rr::Name;
use hickory_server::server::{ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::config::UpstreamConfig;

pub const DEFAULT_HEDGE_DELAY_MS: u64 = 75;
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

type RawDnsClient = DnsExchange<TokioRuntimeProvider>;
type LookupFuture = BoxFuture<'static, (usize, std::result::Result<DnsResponse, NetError>)>;

enum ForwardAttemptError {
    Upstream(Option<NetError>),
    Response(anyhow::Error),
}

#[derive(Clone)]
struct UpstreamClient {
    udp: RawDnsClient,
    address: SocketAddr,
    timeout: Duration,
}

impl UpstreamClient {
    async fn query(&self, request: DnsRequest) -> std::result::Result<DnsResponse, NetError> {
        let response = self.udp.send(request.clone()).first_answer().await?;
        if !response.truncation {
            return Ok(response);
        }

        debug!(upstream = %self.address, "UDP response truncated; retrying over TCP");
        let tcp = TcpClientStream::exchange(
            self.address,
            None,
            self.timeout,
            Some(32),
            TokioRuntimeProvider::default(),
        )
        .await?;
        tcp.send(request).first_answer().await
    }
}

fn lookup_future(idx: usize, client: UpstreamClient, request: DnsRequest) -> LookupFuture {
    async move { (idx, client.query(request).await) }.boxed()
}

/// DNS forwarder with configurable upstream selection strategy.
pub struct ParallelForwarder {
    clients: Arc<Vec<UpstreamClient>>,
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
            clients: self.clients.clone(),
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
    pub fn new(upstreams: &[UpstreamConfig], timeout_secs: u64) -> Result<Self> {
        Self::new_with_options(
            upstreams,
            timeout_secs,
            ForwardStrategy::default(),
            DEFAULT_HEDGE_DELAY_MS,
        )
    }

    pub fn new_with_strategy(
        upstreams: &[UpstreamConfig],
        timeout_secs: u64,
        strategy: ForwardStrategy,
    ) -> Result<Self> {
        Self::new_with_options(upstreams, timeout_secs, strategy, DEFAULT_HEDGE_DELAY_MS)
    }

    pub fn new_with_options(
        upstreams: &[UpstreamConfig],
        timeout_secs: u64,
        strategy: ForwardStrategy,
        hedge_delay_ms: u64,
    ) -> Result<Self> {
        let timeout = Duration::from_secs(timeout_secs);
        let mut clients = Vec::with_capacity(upstreams.len());
        let mut addresses = Vec::with_capacity(upstreams.len());
        for upstream in upstreams {
            let ip: IpAddr = upstream
                .address
                .parse()
                .with_context(|| format!("Invalid upstream IP: {}", upstream.address))?;
            let address = SocketAddr::new(ip, upstream.port.unwrap_or(53));
            let udp = UdpClientStream::builder(address, TokioRuntimeProvider::default())
                .with_timeout(Some(timeout))
                .exchange();
            clients.push(UpstreamClient {
                udp,
                address,
                timeout,
            });
            addresses.push(address.to_string());
            debug!("Added upstream resolver: {}", address);
        }

        Ok(Self {
            health: Arc::new((0..clients.len()).map(|_| UpstreamHealth::new()).collect()),
            clients: Arc::new(clients),
            addresses: Arc::new(addresses),
            timeout,
            strategy,
            hedge_delay: Duration::from_millis(hedge_delay_ms),
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
        hedge_delay_ms: u64,
    ) -> Result<()> {
        let fresh = Self::new_with_options(upstreams, timeout_secs, strategy, hedge_delay_ms)?;
        self.clients = fresh.clients;
        self.addresses = fresh.addresses;
        self.health = fresh.health;
        self.timeout = Duration::from_secs(timeout_secs);
        self.strategy = strategy;
        self.hedge_delay = fresh.hedge_delay;
        Ok(())
    }

    /// Update the upstream timeout without rebuilding resolvers.
    pub fn set_timeout(&mut self, timeout_secs: u64) {
        self.timeout = Duration::from_secs(timeout_secs);
    }

    pub fn set_strategy(&mut self, strategy: ForwardStrategy) {
        self.strategy = strategy;
    }

    pub fn set_hedge_delay_ms(&mut self, hedge_delay_ms: u64) {
        self.hedge_delay = Duration::from_millis(hedge_delay_ms);
    }

    pub fn strategy(&self) -> ForwardStrategy {
        self.strategy
    }

    pub fn hedge_delay_ms(&self) -> u64 {
        self.hedge_delay.as_millis() as u64
    }

    fn adaptive_order(&self) -> Vec<usize> {
        let mut indexes: Vec<usize> = (0..self.clients.len()).collect();
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
        let query = match request.queries.queries().first() {
            Some(q) => q,
            None => {
                warn!("DNS request has no query, sending SERVFAIL");
                let info = send_servfail(request, &mut response_handle).await?;
                return Ok(ResolveResult {
                    info,
                    resolver: "invalid_query".to_string(),
                    latency_us: 0,
                });
            }
        };
        let name = Name::from(query.name());
        let query_type = query.query_type();
        let upstream_request = upstream_request(
            request.metadata,
            query.original().clone(),
            request.edns.clone(),
        );

        debug!(
            "Forwarding query: {} ({}) using {} strategy",
            name,
            query_type,
            self.strategy.as_str()
        );

        let start = Instant::now();
        if self.clients.len() == 1 {
            return self
                .resolve_one(request, &mut response_handle, upstream_request, start)
                .await;
        }

        match self.strategy {
            ForwardStrategy::Adaptive => {
                self.resolve_adaptive(request, &mut response_handle, upstream_request, start)
                    .await
            }
            ForwardStrategy::Parallel => {
                self.resolve_parallel(request, &mut response_handle, upstream_request, start)
                    .await
            }
        }
    }

    async fn resolve_one(
        &self,
        request: &hickory_server::server::Request,
        response_handle: &mut impl ResponseHandler,
        upstream_request: DnsRequest,
        start: Instant,
    ) -> Result<ResolveResult> {
        let Some(client) = self.clients.first().cloned() else {
            warn!("No upstream resolvers configured");
            return Ok(ResolveResult {
                info: send_servfail(request, response_handle).await?,
                resolver: "no_upstream".to_string(),
                latency_us: start.elapsed().as_micros() as u64,
            });
        };

        match timeout(self.timeout, client.query(upstream_request)).await {
            Ok(Ok(response)) => {
                let latency_us = start.elapsed().as_micros() as u64;
                self.record_success(0, latency_us);
                self.send_upstream_response(request, response_handle, 0, response, latency_us)
                    .await
            }
            Ok(Err(error)) => {
                self.record_failure(0);
                self.send_upstream_failure(request, response_handle, error, start)
                    .await
            }
            Err(_) => {
                warn!("Upstream resolver timed out, sending SERVFAIL");
                Ok(ResolveResult {
                    info: send_servfail(request, response_handle).await?,
                    resolver: "timeout".to_string(),
                    latency_us: start.elapsed().as_micros() as u64,
                })
            }
        }
    }

    async fn resolve_parallel(
        &self,
        request: &hickory_server::server::Request,
        response_handle: &mut impl ResponseHandler,
        upstream_request: DnsRequest,
        start: Instant,
    ) -> Result<ResolveResult> {
        let result = timeout(self.timeout, async {
            let mut last_err: Option<NetError> = None;
            let mut futs: FuturesUnordered<LookupFuture> = self
                .clients
                .iter()
                .cloned()
                .enumerate()
                .map(|(idx, client)| lookup_future(idx, client, upstream_request.clone()))
                .collect();

            while let Some((idx, result)) = futs.next().await {
                match result {
                    Ok(response) => {
                        let latency_us = start.elapsed().as_micros() as u64;
                        self.record_success(idx, latency_us);
                        return self
                            .send_upstream_response(
                                request,
                                response_handle,
                                idx,
                                response,
                                latency_us,
                            )
                            .await
                            .map_err(ForwardAttemptError::Response);
                    }
                    Err(error) => {
                        debug!("Upstream resolver failed: {}", error);
                        self.record_failure(idx);
                        last_err = Some(error);
                    }
                }
            }
            Err(ForwardAttemptError::Upstream(last_err))
        })
        .await;

        match result {
            Ok(Ok(resolve_result)) => Ok(resolve_result),
            Ok(Err(ForwardAttemptError::Upstream(Some(last_err)))) => {
                self.send_upstream_failure(request, response_handle, last_err, start)
                    .await
            }
            Ok(Err(ForwardAttemptError::Upstream(None))) => {
                warn!("All upstream resolvers failed without a captured error");
                Ok(ResolveResult {
                    info: send_servfail(request, response_handle).await?,
                    resolver: "upstream_error".to_string(),
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
        upstream_request: DnsRequest,
        start: Instant,
    ) -> Result<ResolveResult> {
        let order = self.adaptive_order();
        if order.is_empty() {
            warn!("No upstream resolvers configured");
            return Ok(ResolveResult {
                info: send_servfail(request, response_handle).await?,
                resolver: "no_upstream".to_string(),
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
                if let Some(client) = self.clients.get(idx).cloned() {
                    in_flight.push(lookup_future(idx, client, upstream_request.clone()));
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
                            Some((idx, Ok(response))) => {
                                let latency_us = start.elapsed().as_micros() as u64;
                                self.record_success(idx, latency_us);
                                self.record_hedged_misses(&launched, idx, latency_us);
                                return self
                                    .send_upstream_response(
                                        request,
                                        response_handle,
                                        idx,
                                        response,
                                        latency_us,
                                    )
                                    .await
                                    .map_err(ForwardAttemptError::Response);
                            }
                            Some((idx, Err(error))) => {
                                debug!("Upstream resolver failed: {}", error);
                                self.record_failure(idx);
                                last_err = Some(error);
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
                self.send_upstream_failure(request, response_handle, last_err, start)
                    .await
            }
            Ok(Err(ForwardAttemptError::Upstream(None))) => {
                warn!("All upstream resolvers failed without a captured error");
                Ok(ResolveResult {
                    info: send_servfail(request, response_handle).await?,
                    resolver: "upstream_error".to_string(),
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

    async fn send_upstream_response(
        &self,
        request: &hickory_server::server::Request,
        response_handle: &mut impl ResponseHandler,
        idx: usize,
        response: DnsResponse,
        latency_us: u64,
    ) -> Result<ResolveResult> {
        let resolver = response_label(&response, self.addresses.get(idx));
        let message = downstream_message(
            response.into_message(),
            request.metadata.id,
            request.edns.as_ref(),
        );
        let mut builder = MessageResponseBuilder::from_message_request(request);
        if let Some(edns) = &message.edns {
            builder.edns(edns);
        }
        let response = builder.build(
            message.metadata,
            message.answers.iter(),
            message.authorities.iter(),
            [].iter(),
            message.additionals.iter(),
        );
        let info = response_handle.send_response(response).await?;
        Ok(ResolveResult {
            info,
            resolver,
            latency_us,
        })
    }

    async fn send_upstream_failure(
        &self,
        request: &hickory_server::server::Request,
        response_handle: &mut impl ResponseHandler,
        error: NetError,
        start: Instant,
    ) -> Result<ResolveResult> {
        let label = classify_upstream_failure(&error);
        warn!("Upstream {}: {}; returning SERVFAIL", label, error);
        Ok(ResolveResult {
            info: send_servfail(request, response_handle).await?,
            resolver: label.to_string(),
            latency_us: start.elapsed().as_micros() as u64,
        })
    }
}

fn downstream_message(
    mut message: Message,
    request_id: u16,
    client_edns: Option<&hickory_proto::op::Edns>,
) -> Message {
    message.metadata.id = request_id;
    if let (Some(client_edns), Some(upstream_edns)) = (client_edns, &mut message.edns) {
        upstream_edns.set_max_payload(upstream_edns.max_payload().min(client_edns.max_payload()));
    } else if client_edns.is_none() {
        message.edns = None;
    }
    message
}

fn upstream_request(
    metadata: hickory_proto::op::Metadata,
    query: hickory_proto::op::Query,
    edns: Option<hickory_proto::op::Edns>,
) -> DnsRequest {
    let mut message = Message::query();
    message.metadata = metadata;
    message.queries.push(query);
    message.edns = edns;

    let mut options = DnsRequestOptions::default();
    options.use_edns = message.edns.is_some();
    options.edns_payload_len = message.max_payload();
    options.edns_set_dnssec_ok = message
        .edns
        .as_ref()
        .is_some_and(|edns| edns.flags().dnssec_ok);
    options.recursion_desired = message.metadata.recursion_desired;
    DnsRequest::new(message, options)
}
fn response_label(response: &DnsResponse, address: Option<&String>) -> String {
    match response.metadata.response_code {
        ResponseCode::NoError if response.answers.is_empty() => "nodata".to_string(),
        ResponseCode::NoError => address.cloned().unwrap_or_else(|| "unknown".to_string()),
        code => response_code_label(code).to_string(),
    }
}

fn classify_upstream_failure(error: &NetError) -> &'static str {
    match error {
        NetError::Timeout => "timeout",
        NetError::Io(io)
            if matches!(
                io.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ) =>
        {
            "timeout"
        }
        NetError::Io(_) | NetError::NoConnections | NetError::Busy => "transport_error",
        NetError::Proto(_) | NetError::QueryCaseMismatch | NetError::ParseInt(_) => {
            "protocol_error"
        }
        _ => "upstream_error",
    }
}

fn response_code_label(code: ResponseCode) -> &'static str {
    match code {
        ResponseCode::NoError => "noerror",
        ResponseCode::FormErr => "formerr",
        ResponseCode::ServFail => "servfail",
        ResponseCode::NXDomain => "nxdomain",
        ResponseCode::NotImp => "notimp",
        ResponseCode::Refused => "refused",
        ResponseCode::YXDomain => "yxdomain",
        ResponseCode::YXRRSet => "yxrrset",
        ResponseCode::NXRRSet => "nxrrset",
        ResponseCode::NotAuth => "notauth",
        ResponseCode::NotZone => "notzone",
        ResponseCode::BADVERS => "badvers",
        ResponseCode::BADSIG => "badsig",
        ResponseCode::BADKEY => "badkey",
        ResponseCode::BADTIME => "badtime",
        ResponseCode::BADMODE => "badmode",
        ResponseCode::BADNAME => "badname",
        ResponseCode::BADALG => "badalg",
        ResponseCode::BADTRUNC => "badtrunc",
        ResponseCode::BADCOOKIE => "badcookie",
        ResponseCode::Unknown(_) => "unknown_response",
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
    use hickory_proto::op::{Edns, MessageType, Metadata, Query};
    use hickory_proto::rr::rdata::{A, CNAME, SOA};
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn record(name: &str, ttl: u32, data: RData) -> Record {
        Record::from_rdata(Name::from_ascii(format!("{}.", name)).unwrap(), ttl, data)
    }

    fn request_metadata(checking_disabled: bool) -> Metadata {
        let mut metadata = Metadata::new(7, MessageType::Query, hickory_proto::op::OpCode::Query);
        metadata.recursion_desired = true;
        metadata.checking_disabled = checking_disabled;
        metadata
    }

    #[test]
    fn upstream_request_preserves_query_metadata_and_edns() {
        let query = Query::query(Name::from_ascii("example.com.").unwrap(), RecordType::AAAA);
        let mut edns = Edns::new();
        edns.set_max_payload(1232).set_dnssec_ok(true);
        let metadata = request_metadata(true);

        let forwarded = upstream_request(metadata, query.clone(), Some(edns.clone()));

        assert_eq!(forwarded.queries, vec![query]);
        assert!(forwarded.metadata.recursion_desired);
        assert!(forwarded.metadata.checking_disabled);
        assert_eq!(forwarded.edns, Some(edns));
        assert!(forwarded.options().use_edns);
        assert_eq!(forwarded.options().edns_payload_len, 1232);
        assert!(forwarded.options().edns_set_dnssec_ok);
    }

    #[test]
    fn downstream_message_preserves_sections_flags_and_edns_limit() {
        let query = Query::query(Name::from_ascii("www.example.com.").unwrap(), RecordType::A);
        let mut message = Message::response(99, hickory_proto::op::OpCode::Query);
        message.metadata.authoritative = true;
        message.metadata.recursion_available = true;
        message.metadata.authentic_data = true;
        message.metadata.checking_disabled = true;
        message.queries.push(query);
        message.answers.push(record(
            "www.example.com",
            300,
            RData::CNAME(CNAME(Name::from_ascii("example.com.").unwrap())),
        ));
        message.answers.push(record(
            "example.com",
            60,
            RData::A(A::from(Ipv4Addr::new(93, 184, 216, 34))),
        ));
        message.authorities.push(record(
            "example.com",
            60,
            RData::SOA(SOA::new(
                Name::from_ascii("ns.example.com.").unwrap(),
                Name::from_ascii("hostmaster.example.com.").unwrap(),
                1,
                3600,
                600,
                86400,
                60,
            )),
        ));
        message.additionals.push(record(
            "ns.example.com",
            60,
            RData::AAAA(hickory_proto::rr::rdata::AAAA::from(Ipv6Addr::LOCALHOST)),
        ));
        let mut upstream_edns = Edns::new();
        upstream_edns.set_max_payload(4096).set_dnssec_ok(true);
        message.edns = Some(upstream_edns);
        let expected = message.clone();
        let mut client_edns = Edns::new();
        client_edns.set_max_payload(1232);

        let response = downstream_message(message, 7, Some(&client_edns));

        assert_eq!(response.metadata.id, 7);
        assert_eq!(
            response.metadata.authoritative,
            expected.metadata.authoritative
        );
        assert_eq!(
            response.metadata.recursion_available,
            expected.metadata.recursion_available
        );
        assert_eq!(
            response.metadata.authentic_data,
            expected.metadata.authentic_data
        );
        assert_eq!(
            response.metadata.checking_disabled,
            expected.metadata.checking_disabled
        );
        assert_eq!(response.answers, expected.answers);
        assert_eq!(response.authorities, expected.authorities);
        assert_eq!(response.additionals, expected.additionals);
        assert_eq!(response.edns.as_ref().map(Edns::max_payload), Some(1232));
        assert!(
            response
                .edns
                .as_ref()
                .is_some_and(|edns| edns.flags().dnssec_ok)
        );
    }

    #[test]
    fn downstream_message_omits_opt_for_non_edns_client() {
        let mut message = Message::response(99, hickory_proto::op::OpCode::Query);
        message.edns = Some(Edns::new());

        let response = downstream_message(message, 7, None);

        assert!(response.edns.is_none());
    }

    #[test]
    fn response_labels_dns_outcomes_without_hiding_upstream_address() {
        let mut positive = Message::response(1, hickory_proto::op::OpCode::Query);
        positive.answers.push(record(
            "example.com",
            60,
            RData::A(A::from(Ipv4Addr::new(93, 184, 216, 34))),
        ));
        let positive = DnsResponse::from_message(positive).unwrap();
        assert_eq!(
            response_label(&positive, Some(&"127.0.0.1:5300".to_string())),
            "127.0.0.1:5300"
        );

        let nodata =
            DnsResponse::from_message(Message::response(1, hickory_proto::op::OpCode::Query))
                .unwrap();
        assert_eq!(response_label(&nodata, None), "nodata");

        let mut nxdomain = Message::response(1, hickory_proto::op::OpCode::Query);
        nxdomain.metadata.response_code = ResponseCode::NXDomain;
        let nxdomain = DnsResponse::from_message(nxdomain).unwrap();
        assert_eq!(response_label(&nxdomain, None), "nxdomain");
    }

    #[test]
    fn classify_upstream_failures() {
        assert_eq!(classify_upstream_failure(&NetError::Timeout), "timeout");
        let io: NetError = std::io::Error::from(std::io::ErrorKind::ConnectionReset).into();
        assert_eq!(classify_upstream_failure(&io), "transport_error");
        let protocol = NetError::Proto("malformed response".into());
        assert_eq!(classify_upstream_failure(&protocol), "protocol_error");
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

    #[tokio::test]
    async fn forwarder_defaults_to_adaptive_strategy() {
        let forwarder = ParallelForwarder::new(
            &[UpstreamConfig {
                address: "1.1.1.1".to_string(),
                port: Some(53),
            }],
            5,
        )
        .expect("forwarder construction");
        assert_eq!(forwarder.strategy(), ForwardStrategy::Adaptive);
        assert_eq!(forwarder.hedge_delay_ms(), DEFAULT_HEDGE_DELAY_MS);

        let custom = ParallelForwarder::new_with_options(
            &[UpstreamConfig {
                address: "1.1.1.1".to_string(),
                port: Some(53),
            }],
            5,
            ForwardStrategy::Adaptive,
            25,
        )
        .expect("custom forwarder construction");
        assert_eq!(custom.hedge_delay_ms(), 25);
    }

    #[tokio::test]
    async fn adaptive_order_penalizes_failing_upstreams() {
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
