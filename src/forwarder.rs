use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

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

/// Result of a successful upstream resolve, including timing info.
pub struct ResolveResult {
    pub info: ResponseInfo,
    pub resolver: String,
    pub latency_us: u64,
}

/// Parallel DNS forwarder that races queries across multiple upstream resolvers.
pub struct ParallelForwarder {
    resolvers: Arc<Vec<TokioResolver>>,
    addresses: Arc<Vec<String>>,
    timeout: Duration,
}

impl Clone for ParallelForwarder {
    fn clone(&self) -> Self {
        Self {
            resolvers: self.resolvers.clone(),
            addresses: self.addresses.clone(),
            timeout: self.timeout,
        }
    }
}

impl ParallelForwarder {
    pub fn new(upstreams: &[UpstreamConfig], timeout_secs: u64) -> Result<Self> {
        let mut resolvers = Vec::with_capacity(upstreams.len());
        let mut addresses = Vec::with_capacity(upstreams.len());
        for upstream in upstreams {
            let ip: IpAddr = upstream
                .address
                .parse()
                .with_context(|| format!("Invalid upstream IP: {}", upstream.address))?;

            let ns_config = NameServerConfig::udp_and_tcp(ip);
            let config = ResolverConfig::from_parts(None, vec![], vec![ns_config]);

            let resolver =
                Resolver::builder_with_config(config, TokioRuntimeProvider::default()).build()?;
            resolvers.push(resolver);
            addresses.push(upstream.address.clone());
            debug!("Added upstream resolver: {}", upstream.address);
        }

        Ok(Self {
            resolvers: Arc::new(resolvers),
            addresses: Arc::new(addresses),
            timeout: Duration::from_secs(timeout_secs),
        })
    }

    /// Reload upstream resolvers from a fresh config list.
    /// Called after adding/removing upstreams via the web API.
    pub fn reload(&mut self, upstreams: &[UpstreamConfig]) -> Result<()> {
        let fresh = Self::new(upstreams, self.timeout.as_secs())?;
        self.resolvers = fresh.resolvers;
        self.addresses = fresh.addresses;
        Ok(())
    }

    /// Race a DNS lookup across all upstream resolvers, return the first successful response.
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
        let name = query.name().clone();
        let query_type = query.query_type();

        debug!("Forwarding query: {} ({})", name, query_type);

        let start = Instant::now();
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
            let mut last_err = None;
            let mut futs: Vec<_> = futures.into_iter().map(Box::pin).collect();
            while !futs.is_empty() {
                let (resolved, _idx, remaining) = futures::future::select_all(futs).await;
                futs = remaining;
                match resolved {
                    (idx, Ok(lookup)) => {
                        let latency_us = start.elapsed().as_micros() as u64;
                        let answers = extract_answers(query_type, &lookup);
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
                        let resolver = self
                            .addresses
                            .get(idx)
                            .cloned()
                            .unwrap_or_else(|| "unknown".to_string());
                        return Ok(ResolveResult {
                            info,
                            resolver,
                            latency_us,
                        });
                    }
                    (_, Err(e)) => {
                        warn!("Upstream resolver failed: {}", e);
                        last_err = Some(e);
                    }
                }
            }
            Err(anyhow::anyhow!(
                "All upstream resolvers failed: {:?}",
                last_err
            ))
        })
        .await;

        match result {
            Ok(Ok(resolve_result)) => Ok(resolve_result),
            Ok(Err(e)) => {
                warn!("Forwarding error: {}, sending SERVFAIL", e);
                let info = send_servfail(request, &mut response_handle).await?;
                Ok(ResolveResult {
                    info,
                    resolver: "error".to_string(),
                    latency_us: start.elapsed().as_micros() as u64,
                })
            }
            Err(_) => {
                warn!("All upstream resolvers timed out, sending SERVFAIL");
                Ok(ResolveResult {
                    info: send_servfail(request, &mut response_handle).await?,
                    resolver: "timeout".to_string(),
                    latency_us: start.elapsed().as_micros() as u64,
                })
            }
        }
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
}
