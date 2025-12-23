//! Trap detection for identifying and blocking honeypot/catch-all responses
//!
//! Tracks response fingerprints during scanning and detects when:
//! - Multiple responses share identical body hashes (SPA shells, catch-alls)
//! - Entire URL prefixes consistently return the same response
//!
//! Once detected, trap prefixes can be blocked to prevent wasted requests.

use super::similarity::SIM_HASHER;
use crate::nlp::preprocess;
use crate::response::FeroxResponse;
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

/// Default threshold for detecting trap responses
/// If more than this many responses share the same hash, it's likely a trap
pub const DEFAULT_TRAP_THRESHOLD: usize = 10;

/// Tracks response fingerprints to detect traps and catch-all responses
#[derive(Debug)]
pub struct TrapDetector {
    /// Hash -> count of responses with this hash
    hash_counts: RwLock<HashMap<u64, usize>>,
    /// Hash -> first URL seen (for logging/debugging)
    hash_first_url: RwLock<HashMap<u64, String>>,
    /// Detected trap hashes (responses that exceeded threshold)
    trap_hashes: RwLock<HashSet<u64>>,
    /// URL prefixes that are known traps (e.g., "/admin/")
    trap_prefixes: RwLock<HashSet<String>>,
    /// Prefix -> hash mapping for prefix-based trap detection
    prefix_hash_counts: RwLock<HashMap<String, HashMap<u64, usize>>>,
    /// Threshold for considering a response a trap
    threshold: usize,
    /// Whether trap detection is enabled
    enabled: bool,
    /// Count of responses filtered as traps
    filtered_count: RwLock<usize>,
}

impl Default for TrapDetector {
    fn default() -> Self {
        Self::new(DEFAULT_TRAP_THRESHOLD, true)
    }
}

impl TrapDetector {
    /// Create a new TrapDetector with the given threshold
    pub fn new(threshold: usize, enabled: bool) -> Self {
        Self {
            hash_counts: RwLock::new(HashMap::new()),
            hash_first_url: RwLock::new(HashMap::new()),
            trap_hashes: RwLock::new(HashSet::new()),
            trap_prefixes: RwLock::new(HashSet::new()),
            prefix_hash_counts: RwLock::new(HashMap::new()),
            threshold,
            enabled,
            filtered_count: RwLock::new(0),
        }
    }

    /// Check if trap detection is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get the current threshold
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Get the count of filtered responses
    pub fn filtered_count(&self) -> usize {
        *self
            .filtered_count
            .read()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Record a response and check if it should be filtered as a trap
    ///
    /// Returns true if the response should be filtered (is a trap)
    pub fn record_and_check(&self, response: &FeroxResponse) -> bool {
        if !self.enabled {
            return false;
        }

        let hash = self.hash_response(response);
        let url = response.url().to_string();
        let prefix = self.extract_prefix(&url);

        // Check if this hash is already known as a trap
        if self.is_trap_hash(hash) {
            self.increment_filtered();
            return true;
        }

        // Check if the prefix is already known as a trap
        if let Some(ref prefix) = prefix {
            if self.is_trap_prefix_internal(prefix) {
                self.increment_filtered();
                return true;
            }
        }

        // Record the hash and check if it now exceeds threshold
        let count = self.record_hash(hash, &url);

        if count > self.threshold {
            // Mark this hash as a trap
            if let Ok(mut traps) = self.trap_hashes.write() {
                traps.insert(hash);
            }
            log::info!(
                "Trap detected: {} responses with identical fingerprint (first seen: {})",
                count,
                self.get_first_url(hash).unwrap_or_default()
            );
            self.increment_filtered();
            return true;
        }

        // Record prefix-specific hash counts
        if let Some(ref prefix) = prefix {
            self.record_prefix_hash(prefix, hash);
            self.check_and_mark_prefix_trap(prefix);
        }

        false
    }

    /// Check if a URL's prefix is a known trap (for early termination)
    ///
    /// Call this BEFORE making a request to skip known trap prefixes
    pub fn is_trap_prefix(&self, url: &str) -> bool {
        if !self.enabled {
            return false;
        }

        if let Some(prefix) = self.extract_prefix(url) {
            return self.is_trap_prefix_internal(&prefix);
        }
        false
    }

    /// Mark a response as a trap (e.g., from JSON soft-404 or redirect detection)
    pub fn mark_as_trap(&self, response: &FeroxResponse) {
        if !self.enabled {
            return;
        }

        let hash = self.hash_response(response);
        if let Ok(mut traps) = self.trap_hashes.write() {
            traps.insert(hash);
        }

        // Also consider marking the prefix as a trap
        let url = response.url().to_string();
        if let Some(prefix) = self.extract_prefix(&url) {
            self.record_prefix_hash(&prefix, hash);
            self.check_and_mark_prefix_trap(&prefix);
        }
    }

    /// Hash a response body using SimHash
    fn hash_response(&self, response: &FeroxResponse) -> u64 {
        SIM_HASHER.create_signature(preprocess(response.text()).iter())
    }

    /// Record a hash occurrence and return the new count
    fn record_hash(&self, hash: u64, url: &str) -> usize {
        let count = {
            let mut counts = self.hash_counts.write().unwrap_or_else(|e| e.into_inner());
            let count = counts.entry(hash).or_insert(0);
            *count += 1;
            *count
        };

        // Store first URL for this hash
        if count == 1 {
            if let Ok(mut first_urls) = self.hash_first_url.write() {
                first_urls.insert(hash, url.to_string());
            }
        }

        count
    }

    /// Get the first URL that had a particular hash
    fn get_first_url(&self, hash: u64) -> Option<String> {
        self.hash_first_url
            .read()
            .ok()
            .and_then(|urls| urls.get(&hash).cloned())
    }

    /// Check if a hash is known as a trap
    fn is_trap_hash(&self, hash: u64) -> bool {
        self.trap_hashes
            .read()
            .ok()
            .is_some_and(|traps| traps.contains(&hash))
    }

    /// Internal check for trap prefix
    fn is_trap_prefix_internal(&self, prefix: &str) -> bool {
        self.trap_prefixes
            .read()
            .ok()
            .is_some_and(|prefixes| prefixes.contains(prefix))
    }

    /// Record a hash for a specific prefix
    fn record_prefix_hash(&self, prefix: &str, hash: u64) {
        if let Ok(mut prefix_hashes) = self.prefix_hash_counts.write() {
            let hash_counts = prefix_hashes.entry(prefix.to_string()).or_default();
            *hash_counts.entry(hash).or_insert(0) += 1;
        }
    }

    /// Check if a prefix should be marked as a trap
    ///
    /// A prefix is a trap if:
    /// - All responses under it share the same hash, AND
    /// - There are at least `threshold` responses
    fn check_and_mark_prefix_trap(&self, prefix: &str) {
        let should_mark = {
            if let Ok(prefix_hashes) = self.prefix_hash_counts.read() {
                if let Some(hash_counts) = prefix_hashes.get(prefix) {
                    // Check if there's a single dominant hash
                    let total: usize = hash_counts.values().sum();
                    if total >= self.threshold {
                        // Check if 90% or more of responses share the same hash
                        if let Some(&max_count) = hash_counts.values().max() {
                            let ratio = max_count as f64 / total as f64;
                            ratio >= 0.9
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            }
        };

        if should_mark {
            self.mark_prefix_as_trap(prefix);
        }
    }

    /// Mark a prefix as a trap
    fn mark_prefix_as_trap(&self, prefix: &str) -> bool {
        if let Ok(mut prefixes) = self.trap_prefixes.write() {
            if prefixes.insert(prefix.to_string()) {
                log::info!(
                    "Trap prefix detected: {} - blocking further requests",
                    prefix
                );
                return true;
            }
        }
        false
    }

    /// Extract the prefix from a URL path
    ///
    /// Takes the first 2 segments: /api/products/123 -> /api/products
    pub fn extract_prefix(&self, url: &str) -> Option<String> {
        let parsed = url::Url::parse(url).ok()?;
        let path = parsed.path();

        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

        if parts.len() >= 2 {
            Some(format!("/{}/{}", parts[0], parts[1]))
        } else if parts.len() == 1 {
            Some(format!("/{}", parts[0]))
        } else {
            None // Root path, no prefix
        }
    }

    /// Increment the filtered response counter
    fn increment_filtered(&self) {
        if let Ok(mut count) = self.filtered_count.write() {
            *count += 1;
        }
    }

    /// Get statistics about trap detection
    pub fn stats(&self) -> TrapStats {
        let trap_hashes = self.trap_hashes.read().map(|h| h.len()).unwrap_or(0);
        let trap_prefixes = self.trap_prefixes.read().map(|p| p.len()).unwrap_or(0);
        let unique_hashes = self.hash_counts.read().map(|h| h.len()).unwrap_or(0);
        let filtered = self.filtered_count();

        TrapStats {
            trap_hashes,
            trap_prefixes,
            unique_hashes,
            filtered,
            threshold: self.threshold,
        }
    }

    /// Get the list of detected trap prefixes
    pub fn get_trap_prefixes(&self) -> Vec<String> {
        self.trap_prefixes
            .read()
            .map(|p| p.iter().cloned().collect())
            .unwrap_or_default()
    }
}

/// Statistics about trap detection
#[derive(Debug, Clone)]
pub struct TrapStats {
    /// Number of unique hashes marked as traps
    pub trap_hashes: usize,
    /// Number of prefixes marked as traps
    pub trap_prefixes: usize,
    /// Total unique response hashes seen
    pub unique_hashes: usize,
    /// Number of responses filtered as traps
    pub filtered: usize,
    /// Current threshold
    pub threshold: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_prefix() {
        let detector = TrapDetector::default();

        assert_eq!(
            detector.extract_prefix("https://example.com/api/products/123"),
            Some("/api/products".to_string())
        );
        assert_eq!(
            detector.extract_prefix("https://example.com/admin"),
            Some("/admin".to_string())
        );
        assert_eq!(detector.extract_prefix("https://example.com/"), None);
    }

    #[test]
    fn test_disabled_detector() {
        let detector = TrapDetector::new(10, false);
        assert!(!detector.is_enabled());
        assert!(!detector.is_trap_prefix("https://example.com/admin/test"));
    }

    #[test]
    fn test_threshold() {
        let detector = TrapDetector::new(5, true);
        assert_eq!(detector.threshold(), 5);
    }
}
