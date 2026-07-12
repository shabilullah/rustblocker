use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use parking_lot::RwLock;
use tracing::info;

/// Store for domain block/allow lists with exact and wildcard matching.
#[derive(Debug, Default)]
pub struct DomainStore {
    pub exact: HashSet<String>,
    pub wildcards: HashSet<String>, // stored as "example.com" from "*.example.com"
}

/// Newtype wrapper so actix can distinguish blocklist from allowlist in app data.
#[derive(Clone)]
pub struct BlocklistStore(pub Arc<RwLock<DomainStore>>);

/// Newtype wrapper so actix can distinguish allowlist from blocklist in app data.
#[derive(Clone)]
pub struct AllowlistStore(pub Arc<RwLock<DomainStore>>);

impl std::ops::Deref for BlocklistStore {
    type Target = Arc<RwLock<DomainStore>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::Deref for AllowlistStore {
    type Target = Arc<RwLock<DomainStore>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DomainStore {
    pub async fn load_from_sources(paths: &[String]) -> Result<Self> {
        let mut store = Self::default();
        for path in paths {
            if path.starts_with("http://") || path.starts_with("https://") {
                store.load_url(path).await?;
            } else {
                store.load_file(Path::new(path))?;
            }
        }
        Ok(store)
    }

    fn load_file(&mut self, path: &Path) -> Result<()> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read list file: {}", path.display()))?;
        let count = self.parse_lines(&content, &path.display().to_string());
        info!("Loaded {} entries from {}", count, path.display());
        Ok(())
    }

    async fn load_url(&mut self, url: &str) -> Result<()> {
        info!("Fetching blocklist from {}...", url);
        let content = reqwest::get(url)
            .await
            .with_context(|| format!("Failed to fetch URL: {}", url))?
            .text()
            .await
            .with_context(|| format!("Failed to read response from: {}", url))?;
        let count = self.parse_lines(&content, url);
        info!("Loaded {} entries from {}", count, url);
        Ok(())
    }

    /// Parse lines from a blocklist/allowlist. Supports:
    /// - Plain domains: `example.com`
    /// - Wildcards: `*.example.com`
    /// - Hosts file format: `0.0.0.0 example.com` or `127.0.0.1 example.com`
    /// - Comments: lines starting with `#`
    fn parse_lines(&mut self, content: &str, source: &str) -> usize {
        let mut count = 0;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Handle hosts file format: "0.0.0.0 domain" or "127.0.0.1 domain"
            let domain_part = if line.starts_with("0.0.0.0") || line.starts_with("127.0.0.1") {
                line.split_whitespace().nth(1).unwrap_or("")
            } else {
                line
            };

            let domain_part = domain_part.trim();
            if domain_part.is_empty() {
                continue;
            }

            if let Some(domain) = domain_part.strip_prefix("*.") {
                // Wildcard: "*.example.com" -> store "example.com"
                let normalized = normalize_domain(domain);
                if !normalized.is_empty() {
                    self.wildcards.insert(normalized);
                    count += 1;
                }
            } else {
                let normalized = normalize_domain(domain_part);
                if !normalized.is_empty() {
                    self.exact.insert(normalized);
                    count += 1;
                }
            }
        }
        info!("Parsed {} entries from {}", count, source);
        count
    }

    /// Insert a domain into the store, normalizing it first
    /// (lowercase, strip trailing dot).
    pub fn insert(&mut self, domain: &str) {
        let normalized = normalize_domain(domain);
        if let Some(stripped) = normalized.strip_prefix("*.") {
            self.wildcards.insert(stripped.to_string());
        } else {
            self.exact.insert(normalized);
        }
    }

    /// Remove a domain from the store, normalizing it first.
    pub fn remove(&mut self, domain: &str) {
        let normalized = normalize_domain(domain);
        if let Some(stripped) = normalized.strip_prefix("*.") {
            self.wildcards.remove(stripped);
        }
        self.exact.remove(&normalized);
    }

    /// Check if a normalized domain matches this store.
    pub fn matches(&self, domain: &str) -> bool {
        if self.exact.contains(domain) {
            return true;
        }

        // Wildcard match: "sub.example.com" matches wildcard "example.com".
        // Walk parent suffixes from the queried domain so lookup cost scales
        // with label depth instead of the number of wildcard entries.
        for (idx, byte) in domain.bytes().enumerate() {
            if byte == b'.' && self.wildcards.contains(&domain[idx + 1..]) {
                return true;
            }
        }
        false
    }

    /// Compile all entries (exact + wildcards) into a single deduplicated file.
    /// Output format: one domain per line, wildcards prefixed with `*.`.
    pub fn compile_to_file(&self, output_path: &str) -> Result<usize> {
        let mut entries: Vec<String> = self.exact.iter().cloned().collect();
        for w in &self.wildcards {
            entries.push(format!("*.{}", w));
        }
        entries.sort();
        let count = entries.len();
        let content = entries.join("\n") + "\n";
        std::fs::write(output_path, &content)
            .with_context(|| format!("Failed to write compiled blocklist to {}", output_path))?;
        info!("Compiled {} entries to {}", count, output_path);
        Ok(count)
    }
}

/// Map of domain -> rewrite rules for custom DNS responses.
#[derive(Debug, Default)]
pub struct RewriteMap {
    pub rules: HashMap<String, RuntimeRewriteRule>,
}

/// Runtime rewrite rule with IPs parsed once at load/update time.
#[derive(Debug, Clone)]
pub struct RuntimeRewriteRule {
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
}

impl RuntimeRewriteRule {
    fn from_config(rule: &crate::config::RewriteRule) -> Self {
        Self {
            ipv4: rule.ipv4.as_deref().and_then(|ip| ip.parse().ok()),
            ipv6: rule.ipv6.as_deref().and_then(|ip| ip.parse().ok()),
        }
    }
}

impl RewriteMap {
    pub fn load(rules: Vec<crate::config::RewriteRule>) -> Self {
        let map: HashMap<String, RuntimeRewriteRule> = rules
            .iter()
            .map(|rule| {
                (
                    normalize_domain(&rule.domain),
                    RuntimeRewriteRule::from_config(rule),
                )
            })
            .collect();
        info!("Loaded {} rewrite rules", map.len());
        Self { rules: map }
    }

    pub fn insert(&mut self, rule: crate::config::RewriteRule) {
        let domain = normalize_domain(&rule.domain);
        self.rules
            .insert(domain, RuntimeRewriteRule::from_config(&rule));
    }

    pub fn remove(&mut self, domain: &str) {
        self.rules.remove(&normalize_domain(domain));
    }

    pub fn lookup(&self, domain: &str) -> Option<&RuntimeRewriteRule> {
        self.rules.get(domain)
    }
}

/// Normalize a domain: lowercase, strip trailing dot.
pub fn normalize_domain(domain: &str) -> String {
    let d = domain.to_lowercase();
    d.strip_suffix('.').unwrap_or(&d).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_domain() {
        assert_eq!(normalize_domain("Example.COM."), "example.com");
        assert_eq!(normalize_domain("example.com"), "example.com");
        assert_eq!(normalize_domain("FOO.BAR."), "foo.bar");
    }

    #[test]
    fn test_exact_match() {
        let mut store = DomainStore::default();
        store.exact.insert("example.com".to_string());
        assert!(store.matches("example.com"));
        assert!(!store.matches("sub.example.com"));
        assert!(!store.matches("other.com"));
    }

    #[test]
    fn test_wildcard_match() {
        let mut store = DomainStore::default();
        store.wildcards.insert("example.com".to_string());
        assert!(store.matches("sub.example.com"));
        assert!(store.matches("sub.sub.example.com"));
        // Wildcard does NOT match the bare domain itself
        assert!(!store.matches("example.com"));
    }

    #[test]
    fn test_wildcard_does_not_match_partial() {
        let mut store = DomainStore::default();
        store.wildcards.insert("example.com".to_string());
        // Should NOT match "notexample.com" (missing the dot separator)
        assert!(!store.matches("notexample.com"));
    }

    #[test]
    fn test_wildcard_match_uses_parent_suffixes() {
        let mut store = DomainStore::default();
        for i in 0..1000 {
            store.wildcards.insert(format!("irrelevant-{i}.test"));
        }
        store.wildcards.insert("example.com".to_string());

        assert!(store.matches("sub.sub.example.com"));
        assert!(!store.matches("example.com"));
        assert!(!store.matches("example.com.evil.test"));
    }

    #[test]
    fn test_parse_hosts_format() {
        let mut store = DomainStore::default();
        let content = "\
# Comment
0.0.0.0 ads.example.com
127.0.0.1 tracker.example.com
plain.example.com
*.wild.example.com
# Another comment

";
        let count = store.parse_lines(content, "test");
        assert_eq!(count, 4);
        assert!(store.matches("ads.example.com"));
        assert!(store.matches("tracker.example.com"));
        assert!(store.matches("plain.example.com"));
        assert!(store.matches("sub.wild.example.com"));
    }

    #[test]
    fn test_parse_ignores_comments_and_blanks() {
        let mut store = DomainStore::default();
        let content = "\
# This is a comment
   # indented comment

0.0.0.0 blocked.com
";
        let count = store.parse_lines(content, "test");
        assert_eq!(count, 1);
        assert!(store.matches("blocked.com"));
    }

    #[test]
    fn test_rewrite_map_parses_ips_once() {
        let map = RewriteMap::load(vec![
            crate::config::RewriteRule {
                domain: "Example.COM.".to_string(),
                ipv4: Some("192.0.2.10".to_string()),
                ipv6: Some("2001:db8::10".to_string()),
            },
            crate::config::RewriteRule {
                domain: "invalid.example".to_string(),
                ipv4: Some("not-an-ip".to_string()),
                ipv6: None,
            },
        ]);

        let rule = map.lookup("example.com").expect("rewrite rule");
        assert_eq!(rule.ipv4, Some("192.0.2.10".parse().unwrap()));
        assert_eq!(rule.ipv6, Some("2001:db8::10".parse().unwrap()));

        let invalid = map.lookup("invalid.example").expect("invalid rewrite rule");
        assert_eq!(invalid.ipv4, None);
        assert_eq!(invalid.ipv6, None);
    }
}
