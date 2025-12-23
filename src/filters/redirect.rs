//! HTML client-side redirect detection filter
//!
//! Detects responses that perform client-side redirects via:
//! - Meta refresh tags: `<meta http-equiv="refresh" content="0;url=...">`
//! - JavaScript redirects: `window.location`, `location.href`, `location.replace`, etc.
//!
//! These are often used as soft-404s that redirect to error pages.

use super::FeroxFilter;
use crate::response::FeroxResponse;
use regex::Regex;
use std::sync::OnceLock;

/// Compiled regex patterns for redirect detection
static META_REFRESH_RE: OnceLock<Regex> = OnceLock::new();
static JS_REDIRECT_RE: OnceLock<Regex> = OnceLock::new();

/// Filter for HTML responses that contain client-side redirects
#[derive(Debug, Clone)]
pub struct RedirectFilter {
    /// Whether the filter is enabled
    enabled: bool,
}

impl Default for RedirectFilter {
    fn default() -> Self {
        Self { enabled: true }
    }
}

impl RedirectFilter {
    /// Create a new redirect filter
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Get or initialize the meta refresh regex
    fn meta_refresh_regex() -> &'static Regex {
        META_REFRESH_RE.get_or_init(|| {
            // Match: <meta http-equiv="refresh" content="...">
            // Case insensitive, allows for various attribute orderings
            Regex::new(r#"(?i)<meta[^>]*http-equiv\s*=\s*["']?refresh["']?[^>]*>"#)
                .expect("Invalid meta refresh regex")
        })
    }

    /// Get or initialize the JavaScript redirect regex
    fn js_redirect_regex() -> &'static Regex {
        JS_REDIRECT_RE.get_or_init(|| {
            // Match common JavaScript redirect patterns:
            // - window.location = "..."
            // - window.location.href = "..."
            // - window.location.assign("...")
            // - window.location.replace("...")
            // - location.href = "..."
            // - location.assign("...")
            // - location.replace("...")
            // - document.location = "..."
            Regex::new(
                r#"(?i)(window\.location|document\.location|location)\s*(\.href)?\s*(=|\.(assign|replace)\s*\()"#,
            )
            .expect("Invalid JS redirect regex")
        })
    }

    /// Check if the response body contains a meta refresh tag
    fn has_meta_refresh(body: &str) -> bool {
        Self::meta_refresh_regex().is_match(body)
    }

    /// Check if the response body contains JavaScript redirect code
    fn has_js_redirect(body: &str) -> bool {
        Self::js_redirect_regex().is_match(body)
    }

    /// Check if content-type indicates HTML
    fn is_html_content_type(response: &FeroxResponse) -> bool {
        response
            .headers()
            .get("content-type")
            .and_then(|ct| ct.to_str().ok())
            .map(|ct| ct.contains("text/html") || ct.contains("application/xhtml"))
            .unwrap_or(false)
    }
}

impl FeroxFilter for RedirectFilter {
    fn should_filter_response(&self, response: &FeroxResponse) -> bool {
        // Only filter if enabled
        if !self.enabled {
            return false;
        }

        // Only check HTML responses
        if !Self::is_html_content_type(response) {
            return false;
        }

        let body = response.text();

        // Check for meta refresh redirect
        if Self::has_meta_refresh(body) {
            log::debug!("filtered HTML meta refresh redirect: {}", response.url());
            return true;
        }

        // Check for JavaScript redirect
        if Self::has_js_redirect(body) {
            log::debug!("filtered HTML JavaScript redirect: {}", response.url());
            return true;
        }

        false
    }

    fn box_eq(&self, other: &dyn std::any::Any) -> bool {
        other
            .downcast_ref::<Self>()
            .is_some_and(|o| o.enabled == self.enabled)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
