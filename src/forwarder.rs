use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use hickory_net::{DnsError, NetError};
use hickory_proto::op::{Metadata, ResponseCode};
use hickory_proto::rr::{RData, Record, RecordData, RecordType};
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
    pub fn reload(&mut self, upstreams: &[UpstreamConfig], timeout_secs: u64) -> Result<()> {
        let fresh = Self::new(upstreams, timeout_secs)?;
        self.resolvers = fresh.resolvers;
        self.addresses = fresh.addresses;
        self.timeout = Duration::from_secs(timeout_secs);
        Ok(())
    }

    /// Update the upstream timeout without rebuilding resolvers.
    pub fn set_timeout(&mut self, timeout_secs: u64) {
        self.timeout = Duration::from_secs(timeout_secs);
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
            let mut last_err: Option<NetError> = None;
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
                        debug!("Upstream resolver failed: {}", e);
                        last_err = Some(e);
                    }
                }
            }
            Err(last_err)
        })
        .await;

        match result {
            Ok(Ok(resolve_result)) => Ok(resolve_result),
            Ok(Err(Some(last_err))) => {
                let latency_us = start.elapsed().as_micros() as u64;
                // NoRecordsFound is a legitimate upstream response: it covers
                // NODATA (NOERROR with 0 answers, e.g. an AAAA query for a
                // domain with only A records) and NXDomain (nonexistent domain).
                // Forward it to the client verbatim with the original response
                // code and authority records rather than masking it as SERVFAIL.
                let (info, resolver) =
                    build_error_response(request, &mut response_handle, &last_err).await?;
                Ok(ResolveResult {
                    info,
                    resolver,
                    latency_us,
                })
            }
            Ok(Err(None)) => {
                warn!("All upstream resolvers failed without a captured error");
                Ok(ResolveResult {
                    info: send_servfail(request, &mut response_handle).await?,
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
}
