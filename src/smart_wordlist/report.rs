//! Comprehensive pentest report generation
//!
//! Combines recon input, attack surface analysis, and scan results
//! into an actionable pentesting report.
//!
//! Uses a signal-based scoring system to filter noise and surface
//! only high-value findings worth investigating.

use console::style;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Minimum pentest value score to be considered "interesting"
const MIN_INTERESTING_SCORE: i32 = 4;

/// Discovered endpoint from the scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredEndpoint {
    pub url: String,
    pub status_code: u16,
    pub content_length: u64,
    pub content_type: Option<String>,
    pub interesting: bool,
    pub pentest_score: i32,
    pub notes: Vec<String>,
    /// If this endpoint appears to be parameterized (e.g., /api/products/123)
    pub is_parameterized: bool,
    /// The inferred parameter pattern (e.g., /api/products/{id})
    pub param_pattern: Option<String>,
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
    pub total_filtered_noise: usize,
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

    /// Calculate pentest value score for an endpoint
    ///
    /// Scoring heuristic based on what matters for pentesting:
    /// - User input surfaces: +3
    /// - Non-200 response (indicates behavior): +2
    /// - Server-side execution potential: +3
    /// - Auth-related: +2
    /// - Dev/internal endpoint: +3
    /// - Static asset: -3
    ///
    /// Only endpoints with score >= 4 are worth investigating.
    pub fn calculate_pentest_score(
        url: &str,
        status_code: u16,
        content_type: Option<&str>,
    ) -> (i32, Vec<String>) {
        let mut score: i32 = 0;
        let mut notes = Vec::new();
        let url_lower = url.to_lowercase();

        // Static asset detection - heavily penalize noise
        if is_static_asset(&url_lower) {
            score -= 3;
            // Don't add notes for static assets - they're noise
            return (score, notes);
        }

        // User input surface - high value
        if accepts_user_input(&url_lower, status_code) {
            score += 3;
            notes.push(get_input_surface_note(&url_lower, status_code));
        }

        // Non-200 responses indicate behavior
        match status_code {
            400 => {
                score += 2;
                notes.push("400 Bad Request - endpoint expects parameters".to_string());
            }
            401 => {
                score += 2;
                notes.push("401 Unauthorized - test for auth bypass".to_string());
            }
            403 => {
                score += 2;
                notes.push("403 Forbidden - test path traversal, header manipulation".to_string());
            }
            405 => {
                score += 2;
                notes.push("405 Method Not Allowed - try GET/POST/PUT/DELETE/OPTIONS".to_string());
            }
            500 | 502 | 503 => {
                score += 2;
                notes.push("Server error - potential for info disclosure or injection".to_string());
            }
            201 | 202 | 204 => {
                score += 2;
                notes.push("Writable endpoint - test for unauthorized modifications".to_string());
            }
            _ => {}
        }

        // Server-side execution potential
        if has_server_execution_potential(&url_lower, content_type) {
            score += 3;
            notes.push(get_execution_note(&url_lower, content_type));
        }

        // Auth-related endpoints
        if is_auth_related(&url_lower) {
            score += 2;
            notes.push("Auth-related endpoint - test for bypass, session handling".to_string());
        }

        // Dev-only or internal endpoints - should never be in prod
        if is_dev_or_internal(&url_lower) {
            score += 3;
            notes.push(get_dev_internal_note(&url_lower));
        }

        // High-value sensitive paths
        if let Some(reason) = get_sensitive_path_reason(&url_lower) {
            score += 2;
            notes.push(reason);
        }

        // XML content - XXE potential
        if let Some(ct) = content_type {
            if ct.contains("xml") {
                score += 2;
                notes.push("XML endpoint - test for XXE injection".to_string());
            }
        }

        (score, notes)
    }

    /// Check if endpoint is interesting based on pentest score
    pub fn is_interesting(
        url: &str,
        status_code: u16,
        content_type: Option<&str>,
    ) -> (bool, i32, Vec<String>) {
        let (score, notes) = Self::calculate_pentest_score(url, status_code, content_type);
        (score >= MIN_INTERESTING_SCORE, score, notes)
    }

    /// Generate the final report output - attack surface with noise filtered
    /// Styled to match feroxbuster's pretty output format with colors
    pub fn generate_output(&self) -> String {
        let mut output = String::new();

        // Top divider
        output.push_str("─────────────────────────────────────────┬──────────────────────────────────────────\n");

        // Summary section - feroxbuster style: emoji + padded label + │ + value
        output.push_str(&format!(
            " 🎯  {:<22}│ {}\n",
            "Target",
            style(&self.target).cyan()
        ));
        output.push_str(&format!(
            " 📥  {:<22}│ {}\n",
            "Recon URLs",
            style(self.stats.total_recon_urls).green()
        ));
        output.push_str(&format!(
            " 🔍  {:<22}│ {}\n",
            "Paths Tested",
            style(self.stats.total_paths_tested).green()
        ));
        output.push_str(&format!(
            " ✅  {:<22}│ {}\n",
            "Endpoints Found",
            style(self.stats.total_discovered).green()
        ));
        output.push_str(&format!(
            " 🗑️   {:<22}│ {}\n",
            "Static Filtered",
            style(self.stats.total_filtered_noise).yellow()
        ));

        // Detected technologies
        if !self.technologies.is_empty() {
            for tech in &self.technologies {
                output.push_str(&format!(
                    " 🔧  {:<22}│ {}\n",
                    "Detected Tech",
                    style(tech).cyan()
                ));
            }
        }

        // Status code breakdown with colors
        if !self.stats.status_code_breakdown.is_empty() {
            let mut codes: Vec<_> = self.stats.status_code_breakdown.iter().collect();
            codes.sort_by_key(|(code, _)| *code);
            let status_summary: Vec<String> = codes
                .iter()
                .map(|(code, count)| {
                    let colored_code = colorize_status_code(**code);
                    format!("{}×{}", colored_code, count)
                })
                .collect();
            output.push_str(&format!(
                " 📊  {:<22}│ {}\n",
                "Status Codes",
                status_summary.join(", ")
            ));
        }

        // Bottom of config section
        output.push_str("─────────────────────────────────────────┴──────────────────────────────────────────\n");

        // Attack surface analysis from LLM
        if !self.attack_surface_report.is_empty()
            && self.attack_surface_report != "No notable findings."
        {
            output.push_str(&format!(" 🧠  {}\n", style("AI Analysis").bright().white()));
            output.push_str("───────────────────────────────────────────────────────────────────────────────────\n");
            for line in self.attack_surface_report.lines() {
                output.push_str(&format!("  {}\n", line));
            }
            output.push_str("───────────────────────────────────────────────────────────────────────────────────\n");
        }

        // ATTACK SURFACE - all non-noise endpoints worth pentesting
        let attack_surface: Vec<_> = self
            .discovered_endpoints
            .iter()
            .filter(|e| e.pentest_score >= 0)
            .collect();

        if !attack_surface.is_empty() {
            output.push_str(&format!(
                " 🎯  {}\n",
                style("Attack Surface").bright().white()
            ));
            output.push_str("───────────────────────────────────────────────────────────────────────────────────\n");

            for endpoint in &attack_surface {
                // Color-code status by response type (matching feroxbuster's status_colorizer)
                let colored_status = colorize_status_code(endpoint.status_code);
                let size_str = format!("{}c", endpoint.content_length);

                // Show parameterized pattern if detected
                let url_display = if endpoint.is_parameterized {
                    if let Some(ref pattern) = endpoint.param_pattern {
                        format!(
                            "{} {}",
                            endpoint.url,
                            style(format!("→ {}", pattern)).cyan()
                        )
                    } else {
                        endpoint.url.clone()
                    }
                } else {
                    endpoint.url.clone()
                };

                output.push_str(&format!(
                    "{:<7} {:>9} {}\n",
                    colored_status,
                    style(size_str).dim(),
                    url_display
                ));
            }

            output.push_str("───────────────────────────────────────────────────────────────────────────────────\n");
        }

        // Original recon URLs from katana/gospider/etc
        if !self.recon_urls.is_empty() {
            output.push_str(&format!(
                " 📡  {}\n",
                style("Recon URLs (from katana/gospider)").bright().white()
            ));
            output.push_str("───────────────────────────────────────────────────────────────────────────────────\n");

            for url in &self.recon_urls {
                output.push_str(&format!("     {}\n", style(url).dim()));
            }

            output.push_str("───────────────────────────────────────────────────────────────────────────────────\n");
        }

        output
    }

    /// Generate JSON output
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}

// =============================================================================
// STATIC ASSET DETECTION - Filter out noise
// =============================================================================

/// Check if URL is a static asset (noise)
fn is_static_asset(url: &str) -> bool {
    // File extensions that are static assets
    let static_extensions = [
        ".js", ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf", // fonts & styles
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", // images
        ".mp4", ".webm", ".mp3", ".wav", // media
        ".map", ".d.ts", ".ts", // sourcemaps & type definitions (not executable server-side)
    ];

    // Path patterns that are framework internals / static
    let static_patterns = [
        "/_next/static/",
        "/_next/image", // Note: /_next/image with params IS interesting, handled separately
        "/static/js/",
        "/static/css/",
        "/static/media/",
        "/assets/",
        "/node_modules/",
        "/vendor/",
        "/dist/",
        "/build/static/",
        "/chunks/",
        "/__webpack",
        "/turbopack/",
        "/pnpm/",
        "/.pnpm/",
        "/fonts/",
        "/images/",
        "/img/",
    ];

    // Check extensions
    for ext in &static_extensions {
        if url.ends_with(ext) {
            return true;
        }
    }

    // Check patterns
    for pattern in &static_patterns {
        if url.contains(pattern) {
            // Exception: /_next/image endpoint IS interesting (SSRF potential)
            if url.contains("/_next/image") && !url.contains("/_next/image/") {
                return false;
            }
            return true;
        }
    }

    false
}

// =============================================================================
// USER INPUT DETECTION - Where does input cross trust boundaries?
// =============================================================================

/// Check if endpoint accepts user input
fn accepts_user_input(url: &str, status_code: u16) -> bool {
    // 400 Bad Request often means "you're missing required params"
    if status_code == 400 {
        return true;
    }

    // Known input-accepting endpoints
    let input_patterns = [
        "/_next/image", // accepts url param - SSRF potential
        "/graphql",     // accepts queries
        "/api/",        // REST APIs accept input
        "/search",      // search functionality
        "/upload",      // file uploads
        "/login",       // credentials
        "/register",    // user data
        "/reset",       // password reset
        "/callback",    // OAuth callbacks
        "/webhook",     // webhook endpoints
        "/import",      // data import
        "/export",      // may accept format params
        "/proxy",       // proxy endpoints - SSRF
        "/fetch",       // fetch endpoints - SSRF
        "/redirect",    // redirect endpoints - open redirect
        "/url",         // URL params - SSRF/redirect
        "/link",        // link params
    ];

    input_patterns.iter().any(|p| url.contains(p))
}

/// Get note about what kind of input the endpoint accepts
fn get_input_surface_note(url: &str, status_code: u16) -> String {
    if url.contains("/_next/image") {
        return "Next.js image loader - test SSRF: ?url=http://127.0.0.1&w=100&q=75".to_string();
    }
    if url.contains("/graphql") {
        return "GraphQL - test introspection query, batching attacks".to_string();
    }
    if url.contains("/proxy") || url.contains("/fetch") || url.contains("/url") {
        return "Potential SSRF - test with internal URLs".to_string();
    }
    if url.contains("/redirect") || url.contains("/link") {
        return "Potential open redirect - test with external URLs".to_string();
    }
    if url.contains("/upload") || url.contains("/import") {
        return "File handling - test for path traversal, unrestricted upload".to_string();
    }
    if status_code == 400 {
        return "400 response indicates missing/invalid parameters - fuzz inputs".to_string();
    }
    "Accepts user input - test for injection vulnerabilities".to_string()
}

// =============================================================================
// SERVER-SIDE EXECUTION DETECTION
// =============================================================================

/// Check if endpoint has server-side execution potential
fn has_server_execution_potential(url: &str, content_type: Option<&str>) -> bool {
    // Server-side patterns
    let server_patterns = [
        "/api/",
        "/graphql",
        ".php",
        ".asp",
        ".aspx",
        ".jsp",
        ".do",
        ".action",
        "/cgi-bin/",
        "/servlet/",
        "/invoke/",
        "/execute/",
        "/run/",
        "/eval/",
        "/cmd/",
        "/shell/",
        "/rpc",
        "/jsonrpc",
        "/xmlrpc",
        "/soap",
    ];

    // Check URL patterns
    if server_patterns.iter().any(|p| url.contains(p)) {
        return true;
    }

    // Check content type for dynamic content
    if let Some(ct) = content_type {
        if ct.contains("json") || ct.contains("xml") || ct.contains("html") {
            // Only interesting if it's an API-like path
            if url.contains("/api") || url.contains("/v1") || url.contains("/v2") {
                return true;
            }
        }
    }

    false
}

/// Get note about server execution potential
fn get_execution_note(url: &str, content_type: Option<&str>) -> String {
    if url.contains("/graphql") {
        return "GraphQL endpoint - server-side query execution".to_string();
    }
    if url.contains(".php") {
        return "PHP endpoint - test for code injection, LFI".to_string();
    }
    if url.contains(".asp") || url.contains(".aspx") {
        return "ASP.NET endpoint - test for viewstate attacks".to_string();
    }
    if url.contains("/rpc") || url.contains("/jsonrpc") || url.contains("/xmlrpc") {
        return "RPC endpoint - test for method enumeration, injection".to_string();
    }
    if url.contains("/api/") {
        if let Some(ct) = content_type {
            if ct.contains("json") {
                return "JSON API - test for mass assignment, IDOR".to_string();
            }
        }
        return "API endpoint - test for auth bypass, IDOR".to_string();
    }
    "Server-side endpoint".to_string()
}

// =============================================================================
// AUTH-RELATED DETECTION
// =============================================================================

/// Check if endpoint is auth-related
fn is_auth_related(url: &str) -> bool {
    let auth_patterns = [
        "/auth",
        "/login",
        "/logout",
        "/signin",
        "/signout",
        "/signup",
        "/register",
        "/password",
        "/reset",
        "/forgot",
        "/token",
        "/oauth",
        "/sso",
        "/saml",
        "/cas/",
        "/session",
        "/jwt",
        "/verify",
        "/confirm",
        "/activate",
        "/.well-known/",
        "/openid",
        "/callback",
    ];

    auth_patterns.iter().any(|p| url.contains(p))
}

// =============================================================================
// DEV/INTERNAL ENDPOINT DETECTION - Should never be in production
// =============================================================================

/// Check if endpoint is dev-only or internal
fn is_dev_or_internal(url: &str) -> bool {
    let dev_patterns = [
        // Next.js dev endpoints
        "/__nextjs_",
        "/__next_",
        "/_next-dev",
        // General dev endpoints
        "/debug",
        "/__debug__",
        "/devtools",
        "/dev/",
        "/_dev/",
        "/trace",
        "/profiler",
        "/pprof",
        "/silk/", // Django Silk profiler
        "/phpinfo",
        "/info.php",
        "/test.php",
        // Internal endpoints
        "/internal/",
        "/private/",
        "/_internal/",
        "/_private/",
        // Infrastructure
        "/actuator",
        "/healthz",
        "/readyz",
        "/livez",
        "/metrics",
        "/prometheus",
        "/-/", // Prometheus/GitLab internal
        // Admin/management
        "/admin",
        "/manage",
        "/management",
        "/console",
        "/elmah",
        "/error_log",
    ];

    dev_patterns.iter().any(|p| url.contains(p))
}

/// Get note about why dev/internal endpoint is concerning
fn get_dev_internal_note(url: &str) -> String {
    if url.contains("/__nextjs_") {
        return "Next.js dev endpoint - should NOT be in production".to_string();
    }
    if url.contains("/actuator") {
        return "Spring Actuator - check /env, /heapdump, /mappings for secrets".to_string();
    }
    if url.contains("/pprof") || url.contains("/profiler") {
        return "Profiler endpoint - may leak memory contents".to_string();
    }
    if url.contains("/debug") || url.contains("/__debug__") {
        return "Debug endpoint - may expose internal state, RCE risk".to_string();
    }
    if url.contains("/healthz") || url.contains("/metrics") {
        return "Infrastructure endpoint - may leak internal info".to_string();
    }
    if url.contains("/internal/") || url.contains("/private/") {
        return "Internal endpoint - likely missing auth checks".to_string();
    }
    if url.contains("/admin") || url.contains("/console") {
        return "Admin interface - test for auth bypass".to_string();
    }
    if url.contains("/phpinfo") || url.contains("/info.php") {
        return "PHP info - exposes full server config".to_string();
    }
    "Dev/internal endpoint exposed in production".to_string()
}

// =============================================================================
// SENSITIVE PATH DETECTION - High-value targets
// =============================================================================

/// Get reason why path is sensitive (returns None if not sensitive)
fn get_sensitive_path_reason(url: &str) -> Option<String> {
    // Version control - source code exposure
    if url.contains("/.git") {
        return Some("Git exposure - dump with git-dumper, may leak source".to_string());
    }
    if url.contains("/.svn") {
        return Some("SVN exposure - may leak source code".to_string());
    }
    if url.contains("/.hg") {
        return Some("Mercurial exposure - may leak source code".to_string());
    }

    // Environment/config files
    if url.contains("/.env") {
        return Some("Environment file - likely contains secrets/credentials".to_string());
    }
    if url.contains("/config")
        && (url.contains(".json") || url.contains(".yml") || url.contains(".yaml"))
    {
        return Some("Config file - may contain credentials, API keys".to_string());
    }
    if url.contains("/.aws") || url.contains("/credentials") {
        return Some("AWS credentials - immediate compromise risk".to_string());
    }
    if url.contains("/web.config") {
        return Some("IIS config - may contain connection strings".to_string());
    }
    if url.contains("/.htaccess") || url.contains("/.htpasswd") {
        return Some("Apache config - may expose auth or rewrite rules".to_string());
    }

    // Backups
    if url.contains(".bak") || url.contains(".backup") || url.contains(".old") || url.contains("~")
    {
        return Some("Backup file - may contain sensitive data or source".to_string());
    }
    if url.contains(".sql") || url.contains(".dump") {
        return Some("Database dump - likely contains all data".to_string());
    }

    // API documentation - attack surface mapping
    if url.contains("/swagger") || url.contains("/api-docs") || url.contains("/openapi") {
        return Some("API docs - maps full attack surface, auth requirements".to_string());
    }
    if url.contains("/graphiql") || url.contains("/playground") || url.contains("/altair") {
        return Some("GraphQL IDE - interactive query interface exposed".to_string());
    }

    // Heapdump / memory
    if url.contains("/heapdump") || url.contains("/dump") {
        return Some("Heap dump - contains in-memory secrets, session tokens".to_string());
    }

    None
}

/// Output report to stderr
pub fn output_report(report: &PentestReport) {
    eprintln!("{}", report.generate_output());
}

// =============================================================================
// PARAMETERIZED ENDPOINT DETECTION
// =============================================================================

/// Common ID values used in mutation testing that indicate parameterized endpoints
const PARAM_ID_VALUES: &[&str] = &[
    "1", "2", "0", "100", "999", "1000", "-1",
    "admin", "test", "guest", "user", "root", "default",
    "null", "undefined", "current", "me", "self",
];

/// UUID patterns
const UUID_PATTERNS: &[&str] = &[
    "00000000-0000-0000-0000-000000000000",
    "00000000-0000-0000-0000-000000000001",
    "ffffffff-ffff-ffff-ffff-ffffffffffff",
];

/// Detect if a URL segment looks like an ID parameter
fn looks_like_id_segment(segment: &str) -> Option<&'static str> {
    // Check for common test IDs
    if PARAM_ID_VALUES.contains(&segment) {
        return Some("{id}");
    }

    // Check for UUID patterns
    if UUID_PATTERNS.contains(&segment) {
        return Some("{uuid}");
    }

    // Check for numeric ID
    if segment.parse::<i64>().is_ok() {
        return Some("{id}");
    }

    // Check for UUID format (8-4-4-4-12)
    if segment.len() == 36 && segment.chars().filter(|&c| c == '-').count() == 4 {
        let parts: Vec<&str> = segment.split('-').collect();
        if parts.len() == 5
            && parts[0].len() == 8
            && parts[1].len() == 4
            && parts[2].len() == 4
            && parts[3].len() == 4
            && parts[4].len() == 12
            && parts.iter().all(|p| p.chars().all(|c| c.is_ascii_hexdigit()))
        {
            return Some("{uuid}");
        }
    }

    // Check for MongoDB ObjectId (24 hex chars)
    if segment.len() == 24 && segment.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some("{objectId}");
    }

    // Check for hash-like strings (long alphanumeric)
    if segment.len() > 16 && segment.chars().all(|c| c.is_alphanumeric()) {
        return Some("{hash}");
    }

    None
}

/// Detect if a URL is parameterized and return the pattern
pub fn detect_parameterized_endpoint(url: &str) -> (bool, Option<String>) {
    // Parse the path from the URL
    let path = if let Some(idx) = url.find("://") {
        let after_scheme = &url[idx + 3..];
        if let Some(path_idx) = after_scheme.find('/') {
            &after_scheme[path_idx..]
        } else {
            return (false, None);
        }
    } else if url.starts_with('/') {
        url
    } else {
        return (false, None);
    };

    // Remove query string if present
    let path = path.split('?').next().unwrap_or(path);

    // Split into segments
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    if segments.is_empty() {
        return (false, None);
    }

    // Check each segment for parameterization
    let mut is_parameterized = false;
    let mut pattern_segments = Vec::new();

    for segment in segments {
        if let Some(param_type) = looks_like_id_segment(segment) {
            is_parameterized = true;
            pattern_segments.push(param_type.to_string());
        } else {
            pattern_segments.push(segment.to_string());
        }
    }

    if is_parameterized {
        let pattern = format!("/{}", pattern_segments.join("/"));
        (true, Some(pattern))
    } else {
        (false, None)
    }
}

/// Colorize status code matching feroxbuster's style
fn colorize_status_code(code: u16) -> String {
    let code_str = code.to_string();
    match code {
        100..=199 => style(code_str).blue().to_string(), // informational
        200..=299 => style(code_str).green().to_string(), // success
        300..=399 => style(code_str).yellow().to_string(), // redirects
        400..=499 => style(code_str).red().to_string(),  // client error
        500..=599 => style(code_str).red().to_string(),  // server error
        _ => code_str,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pentest_scoring_high_value() {
        // API endpoint with 403 = high value (input + non-200 + server-side + admin)
        let (interesting, score, notes) = PentestReport::is_interesting("/api/admin", 403, None);
        assert!(interesting);
        assert!(score >= 4);
        assert!(!notes.is_empty());

        // Git config = high value
        let (interesting, score, _) = PentestReport::is_interesting("/.git/config", 200, None);
        assert!(interesting);
        assert!(score >= 4);

        // GraphQL endpoint = high value
        let (interesting, score, _) =
            PentestReport::is_interesting("/graphql", 200, Some("application/json"));
        assert!(interesting);
        assert!(score >= 4);

        // Next.js image loader with 400 = high value (SSRF potential)
        let (interesting, score, notes) = PentestReport::is_interesting("/_next/image", 400, None);
        assert!(interesting);
        assert!(score >= 4);
        assert!(notes.iter().any(|n| n.contains("SSRF")));
    }

    #[test]
    fn test_pentest_scoring_low_value() {
        // Normal 404 = not interesting
        let (interesting, score, _) = PentestReport::is_interesting("/normal/path", 404, None);
        assert!(!interesting);
        assert!(score < 4);

        // Static JS file = noise
        let (interesting, score, _) =
            PentestReport::is_interesting("/_next/static/chunks/main.js", 200, None);
        assert!(!interesting);
        assert!(score < 0); // Negative score for static assets
    }

    #[test]
    fn test_static_asset_filtering() {
        assert!(is_static_asset("/_next/static/chunks/main.js"));
        assert!(is_static_asset("/static/css/style.css"));
        assert!(is_static_asset("/fonts/roboto.woff2"));
        assert!(is_static_asset("/images/logo.png"));
        assert!(!is_static_asset("/api/users"));
        assert!(!is_static_asset("/graphql"));
        assert!(!is_static_asset("/admin"));
    }

    #[test]
    fn test_dev_internal_detection() {
        assert!(is_dev_or_internal("/__nextjs_original-stack-frame"));
        assert!(is_dev_or_internal("/actuator/env"));
        assert!(is_dev_or_internal("/debug/pprof"));
        assert!(is_dev_or_internal("/internal/api"));
        assert!(!is_dev_or_internal("/api/users"));
        assert!(!is_dev_or_internal("/public/data"));
    }

    #[test]
    fn test_auth_detection() {
        assert!(is_auth_related("/api/auth/login"));
        assert!(is_auth_related("/oauth/callback"));
        assert!(is_auth_related("/.well-known/openid-configuration"));
        assert!(!is_auth_related("/api/users"));
    }
}
