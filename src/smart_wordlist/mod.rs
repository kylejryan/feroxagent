//! Smart wordlist generation module for feroxagent
//!
//! This module provides AI-powered wordlist generation based on recon data.
//! It analyzes URLs from tools like katana/gospider, detects technologies,
//! and uses Claude API to generate targeted wordlists.
//!
//! Key features:
//! - Pentest value scoring to filter noise and surface high-signal findings
//! - HTTP method variation testing to detect behavioral anomalies
//! - Static asset filtering to reduce false positives

mod analyzer;
mod generator;
mod llm;
mod mutations;
mod probe;
mod report;

pub use analyzer::TechAnalysis;
pub use generator::{
    budget_wordlist, generate_wordlist, output_attack_report, output_wordlist, BudgetConfig,
    GenerationResult, GeneratorConfig,
};
pub use llm::ClaudeClient;
pub use mutations::{expand_parameterized_paths, generate_mutations, Framework, MutationConfig};
pub use probe::{
    discover_methods, discover_methods_for_405s, probe_urls, HeaderMutationResults,
    MethodVariations, OptionsResult, ProbeResult,
};
pub use report::{
    detect_parameterized_endpoint, generate_canonical_inventory, output_report, CanonicalEndpoint,
    DiscoveredEndpoint, PentestReport, ReportStats,
};
