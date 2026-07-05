use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::Arc;

use hickory_proto::op::{Metadata, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;
use parking_lot::RwLock;
use tracing::{debug, info, warn};

use crate::forwarder::ParallelForwarder;
use crate::lists::{normalize_domain, DomainStore, RewriteMap};

pub struct DnsBlockerHandler {
    pub blocklist: Arc<RwLock<DomainStore>>,
    pub allowlist: Arc<RwLock<DomainStore>>,
    pub rewrites: Arc<RwLock<RewriteMap>>,
    forwarder: Arc<ParallelForwarder>,
    sinkhole_ipv4: Ipv4Addr,
    sinkhole_ipv6: Ipv6Addr,
}

impl DnsBlockerHandler {
    pub fn new(
        blocklist: Arc<RwLock<DomainStore>>,
        allowlist: Arc<RwLock<DomainStore>>,
        rewrites: Arc<RwLock<RewriteMap>>,
        forwarder: Arc<ParallelForwarder>,
        sinkhole_ipv4: Ipv4Addr,
        sinkhole_ipv6: Ipv6Addr,
    ) -> Self {
        Self {
            blocklist,
            allowlist,
            rewrites,
            forwarder,
            sinkhole_ipv4,
            sinkhole_ipv6,
        }
    }
}

/// Build a sinkhole or rewrite response record.
fn build_rdata(query_type: RecordType, ipv4: Ipv4Addr, ipv6: Ipv6Addr) -> RData {
    match query_type {
        RecordType::AAAA => RData::AAAA(AAAA::from(ipv6)),
        _ => RData::A(A::from(ipv4)),
    }
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
            let query = match request.queries.queries().first() {
                Some(q) => q,
                None => {
                    warn!("Request with no queries");
                    let builder = MessageResponseBuilder::from_message_request(request);
                    let response = builder.error_msg(&request.metadata, ResponseCode::FormErr);
                    let mut rh = response_handle;
                    return rh
                        .send_response(response)
                        .await
                        .expect("failed to send FormErr response");
                }
            };

            let raw_name = query.name().to_string();
            let domain = normalize_domain(&raw_name);
            let query_type = query.query_type();
            let query_name = hickory_proto::rr::Name::from(query.name());

            debug!("Query: {} ({})", domain, query_type);

            // 1. Check rewrite map — scope the read guard before any .await
            let rewrite_rdata: Option<RData> = {
                let rewrites = self.rewrites.read();
                rewrites.lookup(&domain).and_then(|rule| {
                    match query_type {
                        RecordType::A => rule.ipv4.as_ref()
                            .and_then(|s| s.parse::<Ipv4Addr>().ok())
                            .map(|ip| RData::A(A::from(ip))),
                        RecordType::AAAA => rule.ipv6.as_ref()
                            .and_then(|s| s.parse::<Ipv6Addr>().ok())
                            .map(|ip| RData::AAAA(AAAA::from(ip))),
                        _ => None,
                    }
                })
            }; // rewrites guard dropped here

            if let Some(rdata) = rewrite_rdata {
                info!("Rewrite: {} -> {}", domain, rdata);
                let builder = MessageResponseBuilder::from_message_request(request);
                let mut metadata = Metadata::response_from_request(&request.metadata);
                metadata.response_code = ResponseCode::NoError;
                let record = Record::from_rdata(query_name, 60, rdata);
                let answers = [record];
                let response = builder.build(
                    metadata,
                    answers.iter(),
                    [].iter(),
                    [].iter(),
                    [].iter(),
                );
                let mut rh = response_handle;
                return rh
                    .send_response(response)
                    .await
                    .expect("failed to send rewrite response");
            }

            // 2. Check allowlist, then blocklist — scope guards before any .await
            let action: Option<RData> = {
                let allowlist = self.allowlist.read();
                if allowlist.matches(&domain) {
                    debug!("Allowed: {}", domain);
                    None
                } else {
                    let blocklist = self.blocklist.read();
                    if blocklist.matches(&domain) {
                        info!("Blocked: {}", domain);
                        Some(build_rdata(query_type, self.sinkhole_ipv4, self.sinkhole_ipv6))
                    } else {
                        None
                    }
                }
            }; // both guards dropped here

            if let Some(rdata) = action {
                let builder = MessageResponseBuilder::from_message_request(request);
                let mut metadata = Metadata::response_from_request(&request.metadata);
                metadata.response_code = ResponseCode::NoError;
                let record = Record::from_rdata(query_name, 60, rdata);
                let answers = [record];
                let response = builder.build(
                    metadata,
                    answers.iter(),
                    [].iter(),
                    [].iter(),
                    [].iter(),
                );
                let mut rh = response_handle;
                return rh
                    .send_response(response)
                    .await
                    .expect("failed to send sinkhole response");
            }

            // 3. Forward to upstream (no locks held)
            debug!("Forwarding: {}", domain);
            let rh = response_handle;
            self.forwarder
                .resolve(request, rh)
                .await
                .expect("forwarder failed to send response")
        })
    }
}
