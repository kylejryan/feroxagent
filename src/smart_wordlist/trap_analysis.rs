//! Post-scan LLM trap analysis
//!
//! Analyzes trap detection statistics and suspicious response patterns
//! using the Claude API to identify potential catch-alls or honeypots
//! that may have slipped through heuristic detection.

use super::llm::{ClaudeClient, UsageMetrics};
use crate::filters::{TrapDetector, TrapStats};
use anyhow::{Context, Result};
use serde::Serialize;

/// Result of trap analysis
#[derive(Debug, Serialize)]
pub struct TrapAnalysisResult {
    /// Number of trap prefixes identified
    pub trap_prefix_count: usize,
    /// Number of trap hashes (response fingerprints)
    pub trap_hash_count: usize,
    /// Total responses filtered as traps
    pub filtered_count: usize,
    /// LLM analysis summary
    pub analysis: String,
    /// Token usage for this analysis
    pub usage: UsageMetrics,
}

/// Analyze trap statistics using LLM
pub async fn analyze_traps(
    client: &ClaudeClient,
    detector: &TrapDetector,
    target_url: &str,
) -> Result<TrapAnalysisResult> {
    let stats = detector.stats();
    let trap_prefixes = detector.get_trap_prefixes();
    let prompt = build_analysis_prompt(&stats, &trap_prefixes, target_url);

    let (analysis, usage) = client
        .analyze_trap_patterns(&prompt)
        .await
        .context("Failed to analyze trap patterns")?;

    Ok(TrapAnalysisResult {
        trap_prefix_count: stats.trap_prefixes,
        trap_hash_count: stats.trap_hashes,
        filtered_count: stats.filtered,
        analysis,
        usage,
    })
}

/// Build the analysis prompt from trap statistics
fn build_analysis_prompt(stats: &TrapStats, trap_prefixes: &[String], target_url: &str) -> String {
    let mut prompt = format!(
        "Analyze the following trap detection statistics from a web content discovery scan of {}:\n\n",
        target_url
    );

    prompt.push_str(&format!(
        "## Detection Summary\n\
        - Trap prefixes detected: {}\n\
        - Unique trap response hashes: {}\n\
        - Total unique response hashes: {}\n\
        - Total responses filtered: {}\n\
        - Detection threshold: {}\n\n",
        stats.trap_prefixes,
        stats.trap_hashes,
        stats.unique_hashes,
        stats.filtered,
        stats.threshold
    ));

    if !trap_prefixes.is_empty() {
        prompt.push_str("## Trap Prefixes (URL paths that always return identical responses)\n");
        for prefix in trap_prefixes.iter().take(20) {
            prompt.push_str(&format!("- {}\n", prefix));
        }
        if trap_prefixes.len() > 20 {
            prompt.push_str(&format!("... and {} more\n", trap_prefixes.len() - 20));
        }
        prompt.push('\n');
    }

    prompt.push_str(
        "## Analysis Request\n\
        Based on this data, provide a brief analysis:\n\
        1. Are these trap patterns consistent with known catch-all/honeypot behaviors?\n\
        2. Do the detected prefixes suggest any specific application architecture or framework?\n\
        3. Are there any concerning patterns that might indicate missed traps?\n\
        4. Recommendations for improving detection on future scans of similar targets.\n\n\
        Keep the analysis concise and actionable.",
    );

    prompt
}

impl ClaudeClient {
    /// Analyze trap patterns using LLM
    pub async fn analyze_trap_patterns(&self, prompt: &str) -> Result<(String, UsageMetrics)> {
        use super::llm::{
            ClaudeRequest, ClaudeResponse, Message, ANTHROPIC_VERSION, CLAUDE_API_URL, CLAUDE_MODEL,
        };
        use anyhow::anyhow;

        let system_prompt =
            "You are a security expert analyzing web application trap detection results. \
            Your goal is to help identify catch-all responses, honeypots, and soft-404 patterns \
            that might indicate the scanner has encountered deceptive endpoints. \
            Be concise and focus on actionable insights.";

        let request = ClaudeRequest {
            model: CLAUDE_MODEL.to_string(),
            max_tokens: 1024,
            messages: vec![Message {
                role: "user".to_string(),
                content: prompt.to_string(),
            }],
            system: system_prompt.to_string(),
        };

        let response = self
            .client
            .post(CLAUDE_API_URL)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("content-type", "application/json")
            .json(&request)
            .send()
            .await
            .context("Failed to send request to Claude API")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(anyhow!("Claude API error ({}): {}", status, error_text));
        }

        let claude_response: ClaudeResponse = response
            .json()
            .await
            .context("Failed to parse Claude API response")?;

        let text = claude_response
            .content
            .first()
            .map(|c| c.text.clone())
            .unwrap_or_else(|| "No analysis generated.".to_string());

        let usage = claude_response.usage.unwrap_or_default();

        Ok((text, usage))
    }
}
