//! Shared test harness: a mock `ResponseHandler` and helpers for building
//! DNS requests, stores, and a fully-wired `DnsBlockerHandler` — no network.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use hickory_net::NetError;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::BinEncoder;
use hickory_server::net::xfer::Protocol;
use hickory_server::server::{Request, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponse;
use parking_lot::RwLock;

use rustblocker::acl::{Acl, SharedAcl};
use rustblocker::config::RewriteRule;
use rustblocker::forwarder::ParallelForwarder;
use rustblocker::handler::DnsBlockerHandler;
use rustblocker::lists::{AllowlistStore, BlocklistStore, DomainStore, RewriteMap};
use rustblocker::stats::QueryLog;

use std::sync::atomic::{AtomicU64, Ordering};

static ID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generate a unique id for temp DB file paths (process-wide counter).
fn unique_id() -> u64 {
    ID_COUNTER.fetch_add(1, Ordering::SeqCst)
}

/// A mock `ResponseHandler` that captures the serialized response.
///
/// Uses `MessageResponse::destructive_emit` (the only public encode path) to
/// produce the `ResponseInfo`, which derefs to `Metadata` (response_code,
/// counts, etc.). The raw bytes are also kept so answer records can be
/// inspected if needed.
#[derive(Clone)]
pub struct MockResponseHandler {
    /// Last captured response info (response_code + counts).
    /// Wrapped in `Arc<RwLock<>>` so the same handler (cloned across futures)
    /// shares state with the test thread.
    info: Arc<RwLock<Option<ResponseInfo>>>,
    bytes: Arc<RwLock<Option<Vec<u8>>>>,
}

impl MockResponseHandler {
    pub fn new() -> Self {
        Self {
            info: Arc::new(RwLock::new(None)),
            bytes: Arc::new(RwLock::new(None)),
        }
    }

    /// The response code (NoError, NXDomain, ServFail, Refused).
    pub fn response_code(&self) -> hickory_proto::op::ResponseCode {
        self.info
            .read()
            .as_ref()
            .map(|i| i.response_code)
            .unwrap_or(hickory_proto::op::ResponseCode::ServFail)
    }

    /// The answer-count from the response header.
    pub fn answer_count(&self) -> u16 {
        self.info
            .read()
            .as_ref()
            .map(|i| i.counts().answers)
            .unwrap_or(0)
    }

    /// The authority-section count (for NODATA/NXDomain negative caching).
    pub fn authority_count(&self) -> u16 {
        self.info
            .read()
            .as_ref()
            .map(|i| i.counts().authorities)
            .unwrap_or(0)
    }
}

impl std::default::Default for MockResponseHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ResponseHandler for MockResponseHandler {
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a hickory_proto::rr::Record> + Send + 'a,
            impl Iterator<Item = &'a hickory_proto::rr::Record> + Send + 'a,
            impl Iterator<Item = &'a hickory_proto::rr::Record> + Send + 'a,
            impl Iterator<Item = &'a hickory_proto::rr::Record> + Send + 'a,
        >,
    ) -> Result<ResponseInfo, NetError> {
        let mut buf = Vec::with_capacity(512);
        let mut encoder = BinEncoder::new(&mut buf);
        let info = response
            .destructive_emit(&mut encoder)
            .map_err(NetError::from)?;
        *self.info.write() = Some(info);
        *self.bytes.write() = Some(buf);
        Ok(info)
    }
}

/// Build a DNS `Request` for the given domain and record type (A by default).
pub fn make_request(name: &str, query_type: RecordType) -> Request {
    let mut msg = Message::new(0x1234, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(
        Name::from_ascii(format!("{}.", name)).unwrap(),
        query_type,
    ));
    let bytes = msg.to_vec().expect("encode failed");
    Request::from_bytes(
        bytes,
        "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
        Protocol::Udp,
    )
    .unwrap()
}

/// Build a `DomainStore` pre-loaded via `insert` (so wildcards route correctly).
pub fn make_store(domains: &[&str]) -> DomainStore {
    let mut store = DomainStore::default();
    for d in domains {
        store.insert(d);
    }
    store
}

/// Build a `RewriteMap` from (domain, ipv4, ipv6) tuples.
pub fn make_rewrites(rules: &[(&str, Option<&str>, Option<&str>)]) -> RewriteMap {
    let rules = rules
        .iter()
        .map(|(d, v4, v6)| RewriteRule {
            domain: d.to_string(),
            ipv4: v4.map(|s| s.to_string()),
            ipv6: v6.map(|s| s.to_string()),
        })
        .collect();
    RewriteMap::load(rules)
}

/// A configured `DnsBlockerHandler` with an allow-all ACL and a forwarder
/// pointing at a dead upstream (1.1.1.1:99 — tests should avoid reaching
/// the forwarder for block/allow/rewrite cases; forwarded queries will
/// simply time out and SERVFAIL, which is fine for those tests).
pub fn make_handler(
    blocklist: &[&str],
    allowlist: &[&str],
    rewrites: &[(&str, Option<&str>, Option<&str>)],
) -> (DnsBlockerHandler, Arc<QueryLog>) {
    let blocklist = BlocklistStore(Arc::new(RwLock::new(make_store(blocklist))));
    let allowlist = AllowlistStore(Arc::new(RwLock::new(make_store(allowlist))));
    let rewrites = Arc::new(RwLock::new(make_rewrites(rewrites)));

    // Forwarder pointing at a non-listening port so forwarding fails fast
    // rather than hitting real DNS. Block/allow/rewrite paths return before
    // the forwarder is reached.
    let forwarder = Arc::new(RwLock::new(
        ParallelForwarder::new(
            &[rustblocker::config::UpstreamConfig {
                address: "127.0.0.1".to_string(),
                port: Some(99),
            }],
            1,
        )
        .expect("forwarder construction"),
    ));

    let acl: SharedAcl = Arc::new(RwLock::new(Acl::default())); // allow all
    // Use a temp file, NOT :memory: — r2d2 gives each connection its own
    // private in-memory DB, so schema/seed on conn #1 wouldn't be visible
    // to conn #2 (seed_defaults, QueryLog writer, etc.).
    let db_path = std::env::temp_dir().join(format!("rb-test-{}.db", unique_id()));
    let pool = rustblocker::db::create_pool(db_path.to_str().expect("path")).expect("db pool");
    rustblocker::db::seed_defaults(&pool);
    let retention = Arc::new(AtomicU64::new(30));
    let query_log = rustblocker::stats::QueryLog::new(pool, retention).0;

    let handler = DnsBlockerHandler::new(
        blocklist,
        allowlist,
        rewrites,
        forwarder,
        Arc::new(RwLock::new(Ipv4Addr::new(0, 0, 0, 0))),
        Arc::new(RwLock::new(Ipv6Addr::UNSPECIFIED)),
        acl,
        query_log.clone(),
    );
    (handler, query_log)
}
