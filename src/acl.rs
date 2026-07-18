use std::net::IpAddr;
use std::sync::Arc;

use ipnet::IpNet;
use parking_lot::RwLock;
use tracing::{info, warn};

/// Access control list based on CIDR networks.
/// Empty list means allow all.
#[derive(Debug, Clone, Default)]
pub struct Acl {
    networks: Vec<IpNet>,
}

impl Acl {
    /// Parse a comma-separated list of CIDRs. Empty string means allow all.
    pub fn parse(cidr_list: &str) -> Self {
        let networks: Vec<IpNet> = cidr_list
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .filter_map(|s| match s.parse::<IpNet>() {
                Ok(net) => Some(net),
                Err(e) => {
                    warn!("Invalid CIDR '{}': {}", s, e);
                    None
                }
            })
            .collect();

        if networks.is_empty() {
            info!("ACL: no networks configured, allowing all");
        } else {
            info!(
                "ACL: restricting to {} network(s): {:?}",
                networks.len(),
                networks
            );
        }

        Self { networks }
    }

    /// Check if an IP address is allowed.
    /// Returns true if allowed (empty list = allow all).
    pub fn is_allowed(&self, addr: IpAddr) -> bool {
        if self.networks.is_empty() {
            return true;
        }
        self.networks.iter().any(|net| net.contains(&addr))
    }

    /// Replace the ACL with a new CIDR list (for hot-reload).
    pub fn replace(&mut self, cidr_list: &str) {
        let new_acl = Self::parse(cidr_list);
        self.networks = new_acl.networks;
    }
}

/// Shared ACL state for both DNS handler and web server.
pub type SharedAcl = Arc<RwLock<Acl>>;

/// Load ACL from the `allowed_networks` setting in the database.
pub fn load_acl_from_db(pool: &crate::db::DbPool) -> SharedAcl {
    let settings = crate::db::get_settings(pool).unwrap_or_default();
    let cidr_list = settings
        .get("allowed_networks")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    Arc::new(RwLock::new(Acl::parse(cidr_list)))
}
