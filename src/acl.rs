use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use ipnet::IpNet;
use parking_lot::RwLock;
use tracing::info;

/// Access control list based on CIDR networks.
/// Empty list means allow all.
#[derive(Debug, Clone, Default)]
pub struct Acl {
    networks: Vec<IpNet>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclParseError {
    cidr: String,
}

impl fmt::Display for AclParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid CIDR: {}", self.cidr)
    }
}

impl std::error::Error for AclParseError {}

impl Acl {
    /// Parse a comma-separated list of CIDRs. Empty input means allow all.
    pub fn parse(cidr_list: &str) -> Result<Self, AclParseError> {
        if cidr_list.trim().is_empty() {
            info!("ACL: no networks configured, allowing all");
            return Ok(Self::default());
        }

        let mut networks = Vec::new();
        for cidr in cidr_list.split(',').map(str::trim) {
            let network = cidr.parse::<IpNet>().map_err(|_| AclParseError {
                cidr: cidr.to_string(),
            })?;
            networks.push(network);
        }

        info!(
            "ACL: restricting to {} network(s): {:?}",
            networks.len(),
            networks
        );
        Ok(Self { networks })
    }

    /// Check if an IP address is allowed.
    /// Returns true if allowed (empty list = allow all).
    pub fn is_allowed(&self, addr: IpAddr) -> bool {
        if self.networks.is_empty() {
            return true;
        }
        self.networks.iter().any(|net| net.contains(&addr))
    }
}

/// Shared ACL state for both DNS handler and web server.
pub type SharedAcl = Arc<RwLock<Acl>>;

#[cfg(test)]
mod tests {
    use super::Acl;
    use std::net::IpAddr;

    #[test]
    fn empty_input_explicitly_allows_all() {
        let acl = Acl::parse("  ").unwrap();
        assert!(acl.is_allowed("192.0.2.1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn invalid_entry_rejects_entire_acl() {
        assert!(Acl::parse("192.168.1.0/24,192.168.1.0/33").is_err());
        assert!(Acl::parse(",").is_err());
    }
}
