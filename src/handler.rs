use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use hickory_proto::op::{Header, HeaderCounts, Metadata, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;
use parking_lot::RwLock;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{debug, info, warn};

use crate::acl::SharedAcl;
use crate::forwarder::ParallelForwarder;
use crate::lists::{AllowlistStore, BlocklistStore, RewriteMap, normalize_domain};
use crate::stats::{QueryAction, QueryEntry, QueryLog};

/// Default max concurrent DNS request handlers (UDP+TCP combined).
/// Caps in-flight work under flood; excess gets immediate SERVFAIL.
pub const DEFAULT_DNS_MAX_IN_FLIGHT: usize = 512;

/// Shared DNS concurrency gate + counters (handler + HTTP metrics).
#[derive(Clone)]
pub struct DnsConcurrency {
    semaphore: Arc<Semaphore>,
    max_in_flight: usize,
    rejected: Arc<AtomicU64>,
}

impl DnsConcurrency {
    pub fn new(max_in_flight: usize) -> Self {
        let max_in_flight = max_in_flight.max(1);
        Self {
            semaphore: Arc::new(Semaphore::new(max_in_flight)),
            max_in_flight,
            rejected: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn max_in_flight(&self) -> usize {
        self.max_in_flight
    }

    pub fn rejected_count(&self) -> u64 {
        self.rejected.load(Ordering::Relaxed)
    }

    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }

    /// Approximate in-flight handlers = max - available permits.
    pub fn in_flight(&self) -> usize {
        self.max_in_flight
            .saturating_sub(self.semaphore.available_permits())
    }

    pub fn try_acquire(&self) -> Option<OwnedSemaphorePermit> {
        self.semaphore.clone().try_acquire_owned().ok()
    }

    pub fn record_reject(&self) {
        self.rejected.fetch_add(1, Ordering::Relaxed);
    }
}

pub struct DnsBlockerHandler {
    pub blocklist: BlocklistStore,
    pub allowlist: AllowlistStore,
    pub rewrites: Arc<RwLock<RewriteMap>>,
    forwarder: Arc<RwLock<ParallelForwarder>>,
    sinkhole_ipv4: Arc<RwLock<Ipv4Addr>>,
    sinkhole_ipv6: Arc<RwLock<Ipv6Addr>>,
    acl: SharedAcl,
    query_log: Arc<QueryLog>,
    concurrency: DnsConcurrency,
}

impl DnsBlockerHandler {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        blocklist: BlocklistStore,
        allowlist: AllowlistStore,
        rewrites: Arc<RwLock<RewriteMap>>,
        forwarder: Arc<RwLock<ParallelForwarder>>,
        sinkhole_ipv4: Arc<RwLock<Ipv4Addr>>,
        sinkhole_ipv6: Arc<RwLock<Ipv6Addr>>,
        acl: SharedAcl,
        query_log: Arc<QueryLog>,
    ) -> Self {
        Self::with_concurrency(
            blocklist,
            allowlist,
            rewrites,
            forwarder,
            sinkhole_ipv4,
            sinkhole_ipv6,
            acl,
            query_log,
            DnsConcurrency::new(DEFAULT_DNS_MAX_IN_FLIGHT),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_max_in_flight(
        blocklist: BlocklistStore,
        allowlist: AllowlistStore,
        rewrites: Arc<RwLock<RewriteMap>>,
        forwarder: Arc<RwLock<ParallelForwarder>>,
        sinkhole_ipv4: Arc<RwLock<Ipv4Addr>>,
        sinkhole_ipv6: Arc<RwLock<Ipv6Addr>>,
        acl: SharedAcl,
        query_log: Arc<QueryLog>,
        max_in_flight: usize,
    ) -> Self {
        Self::with_concurrency(
            blocklist,
            allowlist,
            rewrites,
            forwarder,
            sinkhole_ipv4,
            sinkhole_ipv6,
            acl,
            query_log,
            DnsConcurrency::new(max_in_flight),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_concurrency(
        blocklist: BlocklistStore,
        allowlist: AllowlistStore,
        rewrites: Arc<RwLock<RewriteMap>>,
        forwarder: Arc<RwLock<ParallelForwarder>>,
        sinkhole_ipv4: Arc<RwLock<Ipv4Addr>>,
        sinkhole_ipv6: Arc<RwLock<Ipv6Addr>>,
        acl: SharedAcl,
        query_log: Arc<QueryLog>,
        concurrency: DnsConcurrency,
    ) -> Self {
        Self {
            blocklist,
            allowlist,
            rewrites,
            forwarder,
            sinkhole_ipv4,
            sinkhole_ipv6,
            acl,
            query_log,
            concurrency,
        }
    }

    pub fn concurrency(&self) -> &DnsConcurrency {
        &self.concurrency
    }

    pub fn max_in_flight(&self) -> usize {
        self.concurrency.max_in_flight()
    }

    pub fn rejected_count(&self) -> u64 {
        self.concurrency.rejected_count()
    }

    pub fn in_flight(&self) -> usize {
        self.concurrency.in_flight()
    }
}

fn build_rdata(query_type: RecordType, ipv4: Ipv4Addr, ipv6: Ipv6Addr) -> RData {
    match query_type {
        RecordType::AAAA => RData::AAAA(AAAA::from(ipv6)),
        _ => RData::A(A::from(ipv4)),
    }
}
/// Construct a fallback `ResponseInfo` (SERVFAIL) when the response cannot be
/// sent (client disconnect, IO error). Mirrors hickory's internal
/// `ResponseInfo::serve_failed`, which is `pub(crate)`. Built via the public
/// `From<Header>` impl with the same fields hickory sets.
fn serve_failed(request: &Request) -> ResponseInfo {
    let mut metadata = Metadata::response_from_request(&request.metadata);
    metadata.response_code = ResponseCode::ServFail;
    ResponseInfo::from(Header {
        metadata,
        counts: HeaderCounts::default(),
    })
}

impl RequestHandler for DnsBlockerHandler {
    fn handle_request<'life0, 'life1, 'async_trait, R, T>(
        &'life0 self,
        request: &'life1 Request,
        response_handle: R,
    ) -> Pin<Box<dyn Future<Output = ResponseInfo> + Send + 'async_trait>>
    where
        R: 'async_trait + ResponseHandler,
        T: 'async_trait + hickory_server::net::runtime::Time,
        Self: 'async_trait,
        'life0: 'async_trait,
        'life1: 'async_trait,
    {
        Box::pin(async move {
            // Bound concurrent work before any heavy path (finding 7).
            // try_acquire: under flood, reject immediately instead of queueing
            // unbounded futures that still hold memory.
            let _permit: OwnedSemaphorePermit = match self.concurrency.try_acquire() {
                Some(p) => p,
                None => {
                    self.concurrency.record_reject();
                    warn!(
                        "DNS concurrency limit reached (max_in_flight={}); rejecting",
                        self.concurrency.max_in_flight()
                    );
                    let builder = MessageResponseBuilder::from_message_request(request);
                    let response = builder.error_msg(&request.metadata, ResponseCode::ServFail);
                    let mut rh = response_handle;
                    return match rh.send_response(response).await {
                        Ok(info) => info,
                        Err(e) => {
                            warn!("failed to send overload SERVFAIL: {}", e);
                            serve_failed(request)
                        }
                    };
                }
            };

            // ACL check — extract bool, drop guard, then async
            let src_ip = request.src().ip();
            let is_blocked = {
                let acl = self.acl.read();
                !acl.is_allowed(src_ip)
            };
            if is_blocked {
                warn!("ACL rejected: {}", src_ip);
                let builder = MessageResponseBuilder::from_message_request(request);
                let response = builder.error_msg(&request.metadata, ResponseCode::Refused);
                let mut rh = response_handle;
                return match rh.send_response(response).await {
                    Ok(info) => info,
                    Err(e) => {
                        warn!("failed to send REFUSED response: {}", e);
                        serve_failed(request)
                    }
                };
            }
            let query = match request.queries.queries().first() {
                Some(q) => q,
                None => {
                    warn!("Request with no queries");
                    let builder = MessageResponseBuilder::from_message_request(request);
                    let response = builder.error_msg(&request.metadata, ResponseCode::FormErr);
                    let mut rh = response_handle;
                    return match rh.send_response(response).await {
                        Ok(info) => info,
                        Err(e) => {
                            warn!("failed to send FormErr response: {}", e);
                            serve_failed(request)
                        }
                    };
                }
            };

            let raw_name = query.name().to_string();
            let domain = normalize_domain(&raw_name);
            let query_type = query.query_type();
            let query_name = hickory_proto::rr::Name::from(query.name());

            debug!("Query from {}: {} ({})", src_ip, domain, query_type);

            // 1. Check rewrite map
            let rewrite_rdata: Option<RData> = {
                let rewrites = self.rewrites.read();
                rewrites.lookup(&domain).and_then(|rule| match query_type {
                    RecordType::A => rule.ipv4.map(|ip| RData::A(A::from(ip))),
                    RecordType::AAAA => rule.ipv6.map(|ip| RData::AAAA(AAAA::from(ip))),
                    _ => None,
                })
            };

            if let Some(rdata) = rewrite_rdata {
                self.query_log.record(QueryEntry {
                    client_ip: src_ip,
                    domain: domain.clone(),
                    query_type,
                    action: QueryAction::Rewritten,
                    resolver: None,
                    latency_us: None,
                });
                debug!("Rewrite: {} -> {}", domain, rdata);
                let builder = MessageResponseBuilder::from_message_request(request);
                let mut metadata = Metadata::response_from_request(&request.metadata);
                metadata.response_code = ResponseCode::NoError;
                let record = Record::from_rdata(query_name, 60, rdata);
                let answers = [record];
                let response =
                    builder.build(metadata, answers.iter(), [].iter(), [].iter(), [].iter());
                let mut rh = response_handle;
                return match rh.send_response(response).await {
                    Ok(info) => info,
                    Err(e) => {
                        warn!("failed to send rewrite response: {}", e);
                        serve_failed(request)
                    }
                };
            }

            // 2. Check allowlist, then blocklist
            let (allowlisted, block_response): (bool, Option<RData>) = {
                let allowlist = self.allowlist.read();
                if allowlist.matches(&domain) {
                    debug!("Allowed: {}", domain);
                    (true, None)
                } else {
                    let blocklist = self.blocklist.read();
                    if blocklist.matches(&domain) {
                        info!("Blocked: {}", domain);
                        self.query_log.record(QueryEntry {
                            client_ip: src_ip,
                            domain: domain.clone(),
                            query_type,
                            action: QueryAction::Blocked,
                            resolver: None,
                            latency_us: None,
                        });
                        let sink_v4 = *self.sinkhole_ipv4.read();
                        let sink_v6 = *self.sinkhole_ipv6.read();
                        (false, Some(build_rdata(query_type, sink_v4, sink_v6)))
                    } else {
                        (false, None)
                    }
                }
            };

            if let Some(rdata) = block_response {
                let builder = MessageResponseBuilder::from_message_request(request);
                let mut metadata = Metadata::response_from_request(&request.metadata);
                metadata.response_code = ResponseCode::NoError;
                let record = Record::from_rdata(query_name, 60, rdata);
                let answers = [record];
                let response =
                    builder.build(metadata, answers.iter(), [].iter(), [].iter(), [].iter());
                let mut rh = response_handle;
                return match rh.send_response(response).await {
                    Ok(info) => info,
                    Err(e) => {
                        warn!("failed to send sinkhole response: {}", e);
                        serve_failed(request)
                    }
                };
            }

            // 3. Forward to upstream
            let forwarder = self.forwarder.read().clone();
            // Lock guard dropped here — safe to .await below.
            let result = match forwarder.resolve(request, response_handle).await {
                Ok(result) => result,
                Err(e) => {
                    warn!("forwarder failed to send response: {}", e);
                    self.query_log.record(QueryEntry {
                        client_ip: src_ip,
                        domain: domain.clone(),
                        query_type,
                        action: if allowlisted {
                            QueryAction::Allowed
                        } else {
                            QueryAction::Forwarded
                        },
                        resolver: None,
                        latency_us: None,
                    });
                    return serve_failed(request);
                }
            };
            self.query_log.record(QueryEntry {
                client_ip: src_ip,
                domain,
                query_type,
                action: if allowlisted {
                    QueryAction::Allowed
                } else {
                    QueryAction::Forwarded
                },
                resolver: Some(result.resolver),
                latency_us: Some(result.latency_us),
            });
            result.info
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::Acl;
    use crate::config::UpstreamConfig;
    use crate::lists::{AllowlistStore, BlocklistStore, DomainStore};
    use crate::stats::QueryLog;
    use std::sync::atomic::AtomicU64;

    fn test_handler(max_in_flight: usize) -> DnsBlockerHandler {
        let blocklist = BlocklistStore(Arc::new(RwLock::new(DomainStore::default())));
        let allowlist = AllowlistStore(Arc::new(RwLock::new(DomainStore::default())));
        let rewrites = Arc::new(RwLock::new(RewriteMap::default()));
        let forwarder = Arc::new(RwLock::new(
            ParallelForwarder::new(
                &[UpstreamConfig {
                    address: "127.0.0.1".to_string(),
                    port: Some(99),
                }],
                1,
            )
            .expect("forwarder"),
        ));
        let db_path = std::env::temp_dir().join(format!("rb-sem-test-{}.db", std::process::id()));
        let pool = crate::db::create_pool(db_path.to_str().unwrap()).expect("pool");
        crate::db::seed_defaults(&pool).expect("seed");
        let query_log = QueryLog::new(pool, Arc::new(AtomicU64::new(30))).0;
        DnsBlockerHandler::with_max_in_flight(
            blocklist,
            allowlist,
            rewrites,
            forwarder,
            Arc::new(RwLock::new(Ipv4Addr::UNSPECIFIED)),
            Arc::new(RwLock::new(Ipv6Addr::UNSPECIFIED)),
            Arc::new(RwLock::new(Acl::default())),
            query_log,
            max_in_flight,
        )
    }

    #[tokio::test]
    async fn default_max_in_flight_is_bounded() {
        assert_eq!(DEFAULT_DNS_MAX_IN_FLIGHT, 512);
        let h = test_handler(DEFAULT_DNS_MAX_IN_FLIGHT);
        assert_eq!(h.max_in_flight(), 512);
        assert_eq!(h.in_flight(), 0);
        assert_eq!(h.rejected_count(), 0);
    }

    #[tokio::test]
    async fn zero_max_clamped_to_one() {
        let h = test_handler(0);
        assert_eq!(h.max_in_flight(), 1);
    }

    #[tokio::test]
    async fn semaphore_exhaustion_tracks_capacity() {
        let h = test_handler(2);
        let p1 = h.concurrency().try_acquire().expect("first permit");
        assert_eq!(h.in_flight(), 1);
        let p2 = h.concurrency().try_acquire().expect("second permit");
        assert_eq!(h.in_flight(), 2);
        assert!(
            h.concurrency().try_acquire().is_none(),
            "third must fail at capacity"
        );
        drop(p1);
        assert_eq!(h.in_flight(), 1);
        assert!(h.concurrency().try_acquire().is_some());
        drop(p2);
    }

    #[tokio::test]
    async fn overload_increments_rejected_when_full() {
        let h = test_handler(1);
        let _hold = h.concurrency().try_acquire().expect("hold sole permit");
        assert_eq!(h.rejected_count(), 0);
        assert!(h.concurrency().try_acquire().is_none());
        // Mirror handle_request reject path.
        h.concurrency().record_reject();
        assert_eq!(h.rejected_count(), 1);
        assert_eq!(h.in_flight(), 1);
    }
}
