use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use parking_lot::RwLock;
use tracing::info;

/// Compact domain store: one packed byte arena + hash indexes.
///
/// Domains are stored length-prefixed in `arena` instead of as individual
/// `String` allocations. Indexes map a stable string hash to one or more
/// arena offsets (rare collisions are disambiguated by byte equality).
#[derive(Debug, Default, Clone)]
pub struct DomainStore {
    /// Packed entries: `[u16 LE length][domain bytes]...`
    arena: Vec<u8>,
    /// hash(domain) -> arena offsets of exact-match domains
    exact: HashMap<u64, Vec<u32>>,
    /// hash(suffix) -> arena offsets of wildcard suffixes (`*.example.com` stores `example.com`)
    wildcards: HashMap<u64, Vec<u32>>,
    exact_count: usize,
    wildcard_count: usize,
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

fn domain_hash(domain: &str) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    domain.hash(&mut hasher);
    hasher.finish()
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

            if self.insert(domain_part) {
                count += 1;
            }
        }
        info!("Parsed {} entries from {}", count, source);
        count
    }

    /// Number of exact-match domains.
    pub fn exact_len(&self) -> usize {
        self.exact_count
    }

    /// Number of wildcard suffixes.
    pub fn wildcard_len(&self) -> usize {
        self.wildcard_count
    }

    /// Total exact + wildcard entries.
    pub fn len(&self) -> usize {
        self.exact_count + self.wildcard_count
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drop all entries and reclaim the arena.
    pub fn clear(&mut self) {
        self.arena.clear();
        self.exact.clear();
        self.wildcards.clear();
        self.exact_count = 0;
        self.wildcard_count = 0;
    }

    /// Merge another store into this one (used by bulk import / source refresh).
    pub fn merge(&mut self, other: DomainStore) {
        // Prefer borrowing other's arena rather than cloning domain strings.
        for offsets in other.exact.values() {
            for &offset in offsets {
                let domain = other.domain_at(offset);
                self.insert_normalized(domain, false);
            }
        }
        for offsets in other.wildcards.values() {
            for &offset in offsets {
                let domain = other.domain_at(offset);
                self.insert_normalized(domain, true);
            }
        }
    }

    /// Replace the entire store with another store's contents.
    /// Reclaims arena memory from removed domains.
    pub fn replace_with(&mut self, other: DomainStore) {
        *self = other;
    }

    /// Insert a domain into the store, normalizing it first
    /// (lowercase, strip trailing dot).
    ///
    /// Returns `true` if the domain was newly inserted.
    pub fn insert(&mut self, domain: &str) -> bool {
        let normalized = normalize_domain(domain);
        if normalized.is_empty() {
            return false;
        }
        if let Some(stripped) = normalized.strip_prefix("*.") {
            if stripped.is_empty() {
                return false;
            }
            self.insert_normalized(stripped, true)
        } else {
            self.insert_normalized(&normalized, false)
        }
    }

    /// Remove a domain from the store, normalizing it first.
    ///
    /// Arena bytes for removed domains are intentionally not reclaimed; removes
    /// are rare relative to inserts and full rebuilds clear the arena.
    pub fn remove(&mut self, domain: &str) {
        let normalized = normalize_domain(domain);
        if let Some(stripped) = normalized.strip_prefix("*.") {
            remove_from_index(
                &self.arena,
                &mut self.wildcards,
                &mut self.wildcard_count,
                stripped,
            );
        }
        remove_from_index(
            &self.arena,
            &mut self.exact,
            &mut self.exact_count,
            &normalized,
        );
    }

    /// Check if a normalized domain matches this store.
    pub fn matches(&self, domain: &str) -> bool {
        if contains_in(&self.arena, &self.exact, domain, domain_hash(domain)) {
            return true;
        }

        // Wildcard match: "sub.example.com" matches wildcard "example.com".
        // Walk parent suffixes from the queried domain so lookup cost scales
        // with label depth instead of the number of wildcard entries.
        for (idx, byte) in domain.bytes().enumerate() {
            if byte == b'.' {
                let suffix = &domain[idx + 1..];
                if contains_in(&self.arena, &self.wildcards, suffix, domain_hash(suffix)) {
                    return true;
                }
            }
        }
        false
    }

    /// Compile all entries (exact + wildcards) into a single deduplicated file.
    /// Output format: one domain per line, wildcards prefixed with `*.`.
    pub fn compile_to_file(&self, output_path: &str) -> Result<usize> {
        let mut entries: Vec<String> = Vec::with_capacity(self.len());
        for offsets in self.exact.values() {
            for &offset in offsets {
                entries.push(self.domain_at(offset).to_owned());
            }
        }
        for offsets in self.wildcards.values() {
            for &offset in offsets {
                entries.push(format!("*.{}", self.domain_at(offset)));
            }
        }
        entries.sort();
        let count = entries.len();
        let content = entries.join("\n") + "\n";
        std::fs::write(output_path, &content)
            .with_context(|| format!("Failed to write compiled blocklist to {}", output_path))?;
        info!("Compiled {} entries to {}", count, output_path);
        Ok(count)
    }

    fn insert_normalized(&mut self, domain: &str, wildcard: bool) -> bool {
        if domain.is_empty() {
            return false;
        }
        if domain.len() > u16::MAX as usize {
            // Domains this long are not valid DNS labels in practice; skip to
            // keep the arena length prefix compact.
            return false;
        }

        let hash = domain_hash(domain);
        let exists = if wildcard {
            contains_in(&self.arena, &self.wildcards, domain, hash)
        } else {
            contains_in(&self.arena, &self.exact, domain, hash)
        };
        if exists {
            return false;
        }

        let offset = self.push_domain(domain);
        if wildcard {
            self.wildcards.entry(hash).or_default().push(offset);
            self.wildcard_count += 1;
        } else {
            self.exact.entry(hash).or_default().push(offset);
            self.exact_count += 1;
        }
        true
    }

    fn push_domain(&mut self, domain: &str) -> u32 {
        let offset = self.arena.len() as u32;
        let len = domain.len() as u16;
        self.arena.extend_from_slice(&len.to_le_bytes());
        self.arena.extend_from_slice(domain.as_bytes());
        offset
    }

    fn domain_at(&self, offset: u32) -> &str {
        domain_at(&self.arena, offset)
    }
}

fn contains_in(arena: &[u8], index: &HashMap<u64, Vec<u32>>, domain: &str, hash: u64) -> bool {
    let Some(offsets) = index.get(&hash) else {
        return false;
    };
    offsets
        .iter()
        .any(|&offset| domain_eq(arena, offset, domain))
}

fn remove_from_index(
    arena: &[u8],
    index: &mut HashMap<u64, Vec<u32>>,
    count: &mut usize,
    domain: &str,
) {
    let hash = domain_hash(domain);
    let Some(offsets) = index.get_mut(&hash) else {
        return;
    };
    let before = offsets.len();
    offsets.retain(|&offset| !domain_eq(arena, offset, domain));
    let removed = before - offsets.len();
    if removed > 0 {
        *count = count.saturating_sub(removed);
    }
    if offsets.is_empty() {
        index.remove(&hash);
    }
}

fn domain_at(arena: &[u8], offset: u32) -> &str {
    let i = offset as usize;
    debug_assert!(i + 2 <= arena.len());
    let len = u16::from_le_bytes([arena[i], arena[i + 1]]) as usize;
    debug_assert!(i + 2 + len <= arena.len());
    // Domains are inserted from &str / normalize_domain, so bytes are valid UTF-8.
    unsafe { std::str::from_utf8_unchecked(&arena[i + 2..i + 2 + len]) }
}

fn domain_eq(arena: &[u8], offset: u32, domain: &str) -> bool {
    domain_at(arena, offset) == domain
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
    if d.ends_with('.') {
        d[..d.len() - 1].to_owned()
    } else {
        d
    }
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
        assert!(store.insert("example.com"));
        assert!(store.matches("example.com"));
        assert!(!store.matches("sub.example.com"));
        assert!(!store.matches("other.com"));
        assert_eq!(store.exact_len(), 1);
        assert_eq!(store.wildcard_len(), 0);
    }

    #[test]
    fn test_wildcard_match() {
        let mut store = DomainStore::default();
        assert!(store.insert("*.example.com"));
        assert!(store.matches("sub.example.com"));
        assert!(store.matches("sub.sub.example.com"));
        // Wildcard does NOT match the bare domain itself
        assert!(!store.matches("example.com"));
        assert_eq!(store.exact_len(), 0);
        assert_eq!(store.wildcard_len(), 1);
    }

    #[test]
    fn test_wildcard_does_not_match_partial() {
        let mut store = DomainStore::default();
        assert!(store.insert("*.example.com"));
        // Should NOT match "notexample.com" (missing the dot separator)
        assert!(!store.matches("notexample.com"));
    }

    #[test]
    fn test_wildcard_match_uses_parent_suffixes() {
        let mut store = DomainStore::default();
        for i in 0..1000 {
            store.insert(&format!("*.irrelevant-{i}.test"));
        }
        store.insert("*.example.com");

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
    fn test_insert_is_idempotent() {
        let mut store = DomainStore::default();
        assert!(store.insert("Example.COM."));
        assert!(!store.insert("example.com"));
        assert_eq!(store.exact_len(), 1);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_remove_exact_and_wildcard() {
        let mut store = DomainStore::default();
        store.insert("ads.example.com");
        store.insert("*.tracker.example.com");
        assert!(store.matches("ads.example.com"));
        assert!(store.matches("x.tracker.example.com"));

        store.remove("ads.example.com");
        store.remove("*.tracker.example.com");
        assert!(!store.matches("ads.example.com"));
        assert!(!store.matches("x.tracker.example.com"));
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_merge_combines_exact_and_wildcard() {
        let mut a = DomainStore::default();
        a.insert("a.example.com");
        a.insert("*.wild-a.example.com");

        let mut b = DomainStore::default();
        b.insert("b.example.com");
        b.insert("*.wild-b.example.com");
        // Duplicate should not inflate counts.
        b.insert("a.example.com");

        a.merge(b);
        assert!(a.matches("a.example.com"));
        assert!(a.matches("b.example.com"));
        assert!(a.matches("x.wild-a.example.com"));
        assert!(a.matches("x.wild-b.example.com"));
        assert_eq!(a.exact_len(), 2);
        assert_eq!(a.wildcard_len(), 2);
    }

    #[test]
    fn test_clear_resets_store() {
        let mut store = DomainStore::default();
        store.insert("example.com");
        store.insert("*.ads.example.com");
        store.clear();
        assert!(store.is_empty());
        assert!(!store.matches("example.com"));
        assert!(!store.matches("x.ads.example.com"));
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
