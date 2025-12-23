//! JSON soft-404 detection filter
//!
//! Detects HTTP 200 responses that contain JSON error bodies indicating
//! the resource doesn't exist. Common patterns:
//! - {"error": "not found"}
//! - {"status": 404}
//! - {"code": "NOT_FOUND"}
//! - {"message": "resource does not exist"}

use super::FeroxFilter;
use crate::response::FeroxResponse;
use serde_json::Value;

/// Filter for JSON responses that indicate soft-404s (200 status with error body)
#[derive(Debug, Clone)]
pub struct JsonErrorFilter {
    /// Whether the filter is enabled
    enabled: bool,
}

impl Default for JsonErrorFilter {
    fn default() -> Self {
        Self { enabled: true }
    }
}

impl JsonErrorFilter {
    /// Create a new JSON error filter
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Check if a JSON value contains soft-404 indicators
    fn is_soft_404_json(&self, json: &Value) -> bool {
        // Check for common error field patterns
        if let Some(obj) = json.as_object() {
            // Check "error" field
            if let Some(error_val) = obj.get("error") {
                if self.is_not_found_value(error_val) {
                    return true;
                }
            }

            // Check "status" field (numeric 404 or string)
            if let Some(status_val) = obj.get("status") {
                if self.is_404_status(status_val) {
                    return true;
                }
            }

            // Check "code" field
            if let Some(code_val) = obj.get("code") {
                if self.is_not_found_value(code_val) {
                    return true;
                }
            }

            // Check "statusCode" field
            if let Some(code_val) = obj.get("statusCode") {
                if self.is_404_status(code_val) {
                    return true;
                }
            }

            // Check "message" field for not found indicators
            if let Some(msg_val) = obj.get("message") {
                if self.is_not_found_value(msg_val) {
                    return true;
                }
            }

            // Check "msg" field
            if let Some(msg_val) = obj.get("msg") {
                if self.is_not_found_value(msg_val) {
                    return true;
                }
            }

            // Check nested "error" object
            if let Some(error_obj) = obj.get("error").and_then(|v| v.as_object()) {
                if let Some(code) = error_obj.get("code") {
                    if self.is_not_found_value(code) || self.is_404_status(code) {
                        return true;
                    }
                }
                if let Some(msg) = error_obj.get("message") {
                    if self.is_not_found_value(msg) {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Check if a value represents a 404 status code
    fn is_404_status(&self, value: &Value) -> bool {
        match value {
            Value::Number(n) => n.as_i64() == Some(404),
            Value::String(s) => s == "404" || s.to_lowercase() == "not_found",
            _ => false,
        }
    }

    /// Check if a string value indicates "not found"
    fn is_not_found_value(&self, value: &Value) -> bool {
        if let Some(s) = value.as_str() {
            let lower = s.to_lowercase();
            // Common patterns for "not found" in error messages
            lower.contains("not found")
                || lower.contains("not_found")
                || lower.contains("notfound")
                || lower.contains("does not exist")
                || lower.contains("doesn't exist")
                || lower.contains("cannot find")
                || lower.contains("could not find")
                || lower.contains("no such")
                || lower.contains("404")
                || lower == "resource not found"
                || lower == "page not found"
                || lower == "endpoint not found"
                || lower == "route not found"
        } else {
            false
        }
    }

    /// Check if content-type indicates JSON
    fn is_json_content_type(response: &FeroxResponse) -> bool {
        response
            .headers()
            .get("content-type")
            .and_then(|ct| ct.to_str().ok())
            .map(|ct| ct.contains("application/json") || ct.contains("text/json"))
            .unwrap_or(false)
    }
}

impl FeroxFilter for JsonErrorFilter {
    fn should_filter_response(&self, response: &FeroxResponse) -> bool {
        // Only filter if enabled
        if !self.enabled {
            return false;
        }

        // Only check 200 OK responses (soft-404s pretend to be successful)
        if response.status().as_u16() != 200 {
            return false;
        }

        // Only check JSON responses
        if !Self::is_json_content_type(response) {
            return false;
        }

        // Try to parse as JSON and check for error patterns
        if let Ok(json) = serde_json::from_str::<Value>(response.text()) {
            if self.is_soft_404_json(&json) {
                log::debug!(
                    "filtered JSON soft-404: {} (body contains error indicator)",
                    response.url()
                );
                return true;
            }
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
