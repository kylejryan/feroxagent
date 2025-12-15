//! Comprehensive pentest report generation
//!
//! Combines recon input, attack surface analysis, and scan results
//! into an actionable pentesting report.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Discovered endpoint from the scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredEndpoint {
    pub url: String,
    pub status_code: u16,
    pub content_length: u64,
    pub content_type: Option<String>,
    pub interesting: bool,
    pub notes: Vec<String>,
}

/// Comprehensive pentest report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PentestReport {
    /// Target URL
    pub target: String,

    /// Original recon URLs (from katana/gospider/etc)
    pub recon_urls: Vec<String>,

    /// Detected technologies
    pub technologies: Vec<String>,

    /// Attack surface analysis from LLM
    pub attack_surface_report: String,

    /// Discovered endpoints from the scan
    pub discovered_endpoints: Vec<DiscoveredEndpoint>,

    /// High-value findings (interesting status codes, sensitive paths)
    pub high_value_findings: Vec<DiscoveredEndpoint>,

    /// Summary statistics
    pub stats: ReportStats,
}

/// Statistics for the report
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReportStats {
    pub total_recon_urls: usize,
    pub total_paths_tested: usize,
    pub total_discovered: usize,
    pub status_code_breakdown: HashMap<u16, usize>,
}

impl PentestReport {
    /// Create a new report
    pub fn new(target: String) -> Self {
        Self {
            target,
            recon_urls: Vec::new(),
            technologies: Vec::new(),
            attack_surface_report: String::new(),
            discovered_endpoints: Vec::new(),
            high_value_findings: Vec::new(),
            stats: ReportStats::default(),
        }
    }

    /// Add recon URLs
    pub fn set_recon_urls(&mut self, urls: Vec<String>) {
        self.stats.total_recon_urls = urls.len();
        self.recon_urls = urls;
    }

    /// Set attack surface report
    pub fn set_attack_surface(&mut self, report: String) {
        self.attack_surface_report = report;
    }

    /// Set detected technologies
    pub fn set_technologies(&mut self, techs: Vec<String>) {
        self.technologies = techs;
    }

    /// Add a discovered endpoint
    pub fn add_endpoint(&mut self, endpoint: DiscoveredEndpoint) {
        // Track status code breakdown
        *self
            .stats
            .status_code_breakdown
            .entry(endpoint.status_code)
            .or_insert(0) += 1;

        // Check if high-value
        if endpoint.interesting {
            self.high_value_findings.push(endpoint.clone());
        }

        self.discovered_endpoints.push(endpoint);
        self.stats.total_discovered = self.discovered_endpoints.len();
    }

    /// Check if an endpoint is interesting/high-value
    pub fn is_interesting(
        url: &str,
        status_code: u16,
        content_type: Option<&str>,
    ) -> (bool, Vec<String>) {
        let mut notes = Vec::new();
        let mut interesting = false;

        // Interesting status codes
        match status_code {
            200 => {
                // Check for sensitive paths
                if is_sensitive_path(url) {
                    interesting = true;
                    notes.push(format!(
                        "Sensitive path accessible: {}",
                        get_sensitivity_reason(url)
                    ));
                }
            }
            201 | 202 | 204 => {
                interesting = true;
                notes.push("Writable endpoint - test for unauthorized modifications".to_string());
            }
            301 | 302 | 307 | 308 => {
                if url.contains("admin") || url.contains("login") || url.contains("auth") {
                    interesting = true;
                    notes.push("Auth-related redirect - check destination".to_string());
                }
            }
            400 => {
                interesting = true;
                notes.push("Bad request - may indicate parameter requirements".to_string());
            }
            401 => {
                interesting = true;
                notes.push("Authentication required - test for bypass".to_string());
            }
            403 => {
                interesting = true;
                notes.push(
                    "Forbidden - test for bypass (path traversal, header manipulation)".to_string(),
                );
            }
            405 => {
                interesting = true;
                notes.push("Method not allowed - try other HTTP methods".to_string());
            }
            500 | 502 | 503 => {
                interesting = true;
                notes.push("Server error - potential for information disclosure".to_string());
            }
            _ => {}
        }

        // Check content type
        if let Some(ct) = content_type {
            if ct.contains("json") && (url.contains("/api") || url.contains("/graphql")) {
                interesting = true;
                notes.push("JSON API endpoint".to_string());
            }
            if ct.contains("xml") {
                interesting = true;
                notes.push("XML endpoint - test for XXE".to_string());
            }
        }

        // Sensitive paths always interesting
        if is_sensitive_path(url) && !interesting {
            interesting = true;
            notes.push(format!("Sensitive path: {}", get_sensitivity_reason(url)));
        }

        (interesting, notes)
    }

    /// Generate the final report output
    pub fn generate_output(&self) -> String {
        let mut output = String::new();

        // Header
        output.push_str(&format!("\n{}\n", "═".repeat(80)));
        output.push_str(&format!(
            "  FEROXAGENT PENTEST REPORT\n  Target: {}\n",
            self.target
        ));
        output.push_str(&format!("{}\n\n", "═".repeat(80)));

        // Statistics
        output.push_str("## Summary\n\n");
        output.push_str(&format!(
            "- Recon URLs analyzed: {}\n",
            self.stats.total_recon_urls
        ));
        output.push_str(&format!(
            "- Paths tested: {}\n",
            self.stats.total_paths_tested
        ));
        output.push_str(&format!(
            "- Endpoints discovered: {}\n",
            self.stats.total_discovered
        ));
        output.push_str(&format!(
            "- High-value findings: {}\n\n",
            self.high_value_findings.len()
        ));

        // Status code breakdown
        if !self.stats.status_code_breakdown.is_empty() {
            output.push_str("### Status Code Breakdown\n");
            let mut codes: Vec<_> = self.stats.status_code_breakdown.iter().collect();
            codes.sort_by_key(|(code, _)| *code);
            for (code, count) in codes {
                output.push_str(&format!("  {} - {} responses\n", code, count));
            }
            output.push('\n');
        }

        // Detected technologies
        if !self.technologies.is_empty() {
            output.push_str("## Detected Technologies\n\n");
            for tech in &self.technologies {
                output.push_str(&format!("- {}\n", tech));
            }
            output.push('\n');
        }

        // Attack surface analysis
        if !self.attack_surface_report.is_empty()
            && self.attack_surface_report != "No notable findings."
        {
            output.push_str("## Attack Surface Analysis\n\n");
            output.push_str(&self.attack_surface_report);
            output.push_str("\n\n");
        }

        // High-value findings
        if !self.high_value_findings.is_empty() {
            output.push_str("## High-Value Findings\n\n");
            output.push_str("These endpoints warrant immediate investigation:\n\n");

            for endpoint in &self.high_value_findings {
                output.push_str(&format!(
                    "### {} [{}]\n",
                    endpoint.url, endpoint.status_code
                ));
                if let Some(ref ct) = endpoint.content_type {
                    output.push_str(&format!("Content-Type: {}\n", ct));
                }
                output.push_str(&format!("Size: {} bytes\n", endpoint.content_length));
                if !endpoint.notes.is_empty() {
                    output.push_str("Notes:\n");
                    for note in &endpoint.notes {
                        output.push_str(&format!("  - {}\n", note));
                    }
                }
                output.push('\n');
            }
        }

        // All discovered endpoints (condensed)
        if !self.discovered_endpoints.is_empty() {
            output.push_str("## All Discovered Endpoints\n\n");
            output.push_str("```\n");
            for endpoint in &self.discovered_endpoints {
                output.push_str(&format!(
                    "[{}] {} ({} bytes)\n",
                    endpoint.status_code, endpoint.url, endpoint.content_length
                ));
            }
            output.push_str("```\n\n");
        }

        // Recon URLs (if not too many)
        if !self.recon_urls.is_empty() && self.recon_urls.len() <= 50 {
            output.push_str("## Original Recon URLs\n\n");
            output.push_str("```\n");
            for url in &self.recon_urls {
                output.push_str(&format!("{}\n", url));
            }
            output.push_str("```\n");
        } else if !self.recon_urls.is_empty() {
            output.push_str(&format!(
                "## Original Recon URLs\n\n{} URLs analyzed (truncated)\n\n",
                self.recon_urls.len()
            ));
        }

        output.push_str(&format!("{}\n", "═".repeat(80)));

        output
    }

    /// Generate JSON output
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}

/// Check if a path is sensitive
fn is_sensitive_path(url: &str) -> bool {
    let sensitive_patterns = [
        ".git",
        ".env",
        ".svn",
        "config",
        "admin",
        "debug",
        "backup",
        ".bak",
        ".old",
        "phpinfo",
        "actuator",
        "swagger",
        "graphql",
        "api-docs",
        "wp-admin",
        "wp-config",
        ".htaccess",
        "web.config",
        "/internal/",
        "/private/",
        "credentials",
        "secret",
        "token",
        "api/v",
        "console",
        "management",
        "healthz",
        "metrics",
        "trace",
        "heapdump",
    ];

    let url_lower = url.to_lowercase();
    sensitive_patterns.iter().any(|p| url_lower.contains(p))
}

/// Get the reason why a path is sensitive
fn get_sensitivity_reason(url: &str) -> &'static str {
    let url_lower = url.to_lowercase();

    if url_lower.contains(".git") {
        "Git repository exposure - may leak source code"
    } else if url_lower.contains(".env") {
        "Environment file - may contain secrets"
    } else if url_lower.contains("config") {
        "Configuration file - may expose sensitive settings"
    } else if url_lower.contains("admin") {
        "Admin interface - test for authentication bypass"
    } else if url_lower.contains("debug") {
        "Debug endpoint - may leak internal information"
    } else if url_lower.contains("actuator") {
        "Spring Actuator - check /env, /heapdump, /mappings"
    } else if url_lower.contains("swagger") || url_lower.contains("api-docs") {
        "API documentation - maps attack surface"
    } else if url_lower.contains("graphql") {
        "GraphQL endpoint - test introspection, batching"
    } else if url_lower.contains("backup")
        || url_lower.contains(".bak")
        || url_lower.contains(".old")
    {
        "Backup file - may contain sensitive data"
    } else if url_lower.contains("phpinfo") {
        "PHP info - exposes server configuration"
    } else if url_lower.contains("/internal/") || url_lower.contains("/private/") {
        "Internal endpoint - may lack authorization"
    } else if url_lower.contains("healthz") || url_lower.contains("metrics") {
        "Infrastructure endpoint - may leak info"
    } else {
        "Potentially sensitive endpoint"
    }
}

/// Output report to stderr
pub fn output_report(report: &PentestReport) {
    eprintln!("{}", report.generate_output());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_interesting() {
        let (interesting, notes) = PentestReport::is_interesting("/api/admin", 403, None);
        assert!(interesting);
        assert!(!notes.is_empty());

        let (interesting, _) = PentestReport::is_interesting("/.git/config", 200, None);
        assert!(interesting);

        let (interesting, _) = PentestReport::is_interesting("/normal/path", 404, None);
        assert!(!interesting);
    }

    #[test]
    fn test_sensitive_paths() {
        assert!(is_sensitive_path("/.git/config"));
        assert!(is_sensitive_path("/api/v1/admin"));
        assert!(is_sensitive_path("/actuator/env"));
        assert!(!is_sensitive_path("/images/logo.png"));
    }
}
