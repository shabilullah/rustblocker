use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use hickory_proto::op::{Metadata, ResponseCode};
use hickory_proto::rr::{RData, Record, RecordType};
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::{Resolver, TokioResolver};
use hickory_server::server::ResponseInfo;
use hickory_server::zone_handler::MessageResponseBuilder;
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::config::UpstreamConfig;

/// Parallel DNS forwarder that races queries across multiple upstream resolvers.
pub struct ParallelForwarder {
    resolvers: Vec<TokioResolver>,
    timeout: Duration,
}

impl ParallelForwarder {
    pub fn new(upstreams: &[UpstreamConfig], timeout_secs: u64) -> Result<Self> {
        let mut resolvers = Vec::with_capacity(upstreams.len());
        for upstream in upstreams {
            let ip: IpAddr = upstream
                .address
                .parse()
                .with_context(|| format!("Invalid upstream IP: {}", upstream.address))?;

            let ns_config = NameServerConfig::udp_and_tcp(ip);
            let config = ResolverConfig::from_parts(None, vec![], vec![ns_config]);

            let resolver = Resolver::builder_with_config(config, TokioRuntimeProvider::default())
                .build()?;
            resolvers.push(resolver);
            debug!("Added upstream resolver: {}", upstream.address);
        }

        Ok(Self {
            resolvers,
            timeout: Duration::from_secs(timeout_secs),
        })
    }

    /// Race a DNS lookup across all upstream resolvers, return the first successful response.
    pub async fn resolve(
        &self,
        request: &hickory_server::server::Request,
        mut response_handle: impl hickory_server::server::ResponseHandler,
    ) -> Result<ResponseInfo> {
        let query = request
            .queries
            .queries()
            .first()
            .expect("request must have a query");
        let name = query.name().clone();
        let query_type = query.query_type();

        debug!("Forwarding query: {} ({})", name, query_type);

        let futures: Vec<_> = self
            .resolvers
            .iter()
            .map(|resolver| {
                let name = name.clone();
                let rtype = query_type;
                async move { resolver.lookup(name, rtype).await }
            })
            .collect();

        let result = timeout(self.timeout, async {
            let mut last_err = None;
            let mut futs: Vec<_> = futures.into_iter().map(Box::pin).collect();
            while !futs.is_empty() {
                let (resolved, _idx, remaining) = futures::future::select_all(futs).await;
                futs = remaining;
                match resolved {
                    Ok(lookup) => {
                        // Build answer records from the lookup
                        let answers = extract_answers(query_type, &lookup);
                        // Build and send response while answers are alive
                        let builder = MessageResponseBuilder::from_message_request(request);
                        let mut metadata = Metadata::response_from_request(&request.metadata);
                        metadata.response_code = ResponseCode::NoError;
                        let response = builder.build(
                            metadata,
                            answers.iter(),
                            [].iter(),
                            [].iter(),
                            [].iter(),
                        );
                        let info = response_handle.send_response(response).await?;
                        return Ok(info);
                    }
                    Err(e) => {
                        warn!("Upstream resolver failed: {}", e);
                        last_err = Some(e);
                    }
                }
            }
            Err(anyhow::anyhow!("All upstream resolvers failed: {:?}", last_err))
        })
        .await;

        match result {
            Ok(Ok(info)) => Ok(info),
            Ok(Err(e)) => {
                warn!("Forwarding error: {}, sending SERVFAIL", e);
                send_servfail(request, &mut response_handle).await
            }
            Err(_) => {
                warn!("All upstream resolvers timed out, sending SERVFAIL");
                send_servfail(request, &mut response_handle).await
            }
        }
    }
}

fn extract_answers(query_type: RecordType, lookup: &hickory_resolver::lookup::Lookup) -> Vec<Record> {
    let mut answers = Vec::new();
    for record in lookup.answers() {
        match (query_type, &record.data) {
            (RecordType::A, RData::A(_)) | (RecordType::AAAA, RData::AAAA(_)) => {
                answers.push(Record::from_rdata(record.name.clone(), record.ttl, record.data.clone()));
            }
            _ if query_type != RecordType::A && query_type != RecordType::AAAA => {
                answers.push(Record::from_rdata(record.name.clone(), record.ttl, record.data.clone()));
            }
            _ => {}
        }
    }
    answers
}

async fn send_servfail(
    request: &hickory_server::server::Request,
    response_handle: &mut (impl hickory_server::server::ResponseHandler + Send),
) -> Result<ResponseInfo> {
    let builder = MessageResponseBuilder::from_message_request(request);
    let response = builder.error_msg(&request.metadata, ResponseCode::ServFail);
    let info = response_handle.send_response(response).await?;
    Ok(info)
}
