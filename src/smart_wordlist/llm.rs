//! Claude API client for LLM-powered wordlist generation
//!
//! This module handles communication with the Anthropic Claude API
//! to generate intelligent wordlists based on technology analysis.

use super::analyzer::TechAnalysis;
use super::probe::ProbeResult;
use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};

const CLAUDE_API_URL: &str = "https://api.anthropic.com/v1/messages";
const CLAUDE_MODEL: &str = "claude-sonnet-4-20250514";
const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Claude API client
pub struct ClaudeClient {
    client: Client,
    api_key: String,
}

#[derive(Debug, Serialize)]
struct ClaudeRequest {
    model: String,
    max_tokens: u32,
    messages: Vec<Message>,
    system: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Message {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct ClaudeResponse {
    content: Vec<ContentBlock>,
}

#[derive(Debug, Deserialize)]
struct ContentBlock {
    text: String,
}

impl ClaudeClient {
    /// Create a new Claude client with the given API key
    pub fn new(api_key: String) -> Result<Self> {
        if api_key.is_empty() {
            return Err(anyhow!(
                "Anthropic API key is required. Set ANTHROPIC_API_KEY env var or use --anthropic-key"
            ));
        }

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self { client, api_key })
    }

    /// Generate a wordlist based on technology analysis
    pub async fn generate_wordlist(
        &self,
        analysis_summary: &str,
        target_url: &str,
    ) -> Result<Vec<String>> {
        let system_prompt = self.build_system_prompt();
        let user_prompt = self.build_user_prompt(analysis_summary, target_url);

        let request = ClaudeRequest {
            model: CLAUDE_MODEL.to_string(),
            max_tokens: 4096,
            messages: vec![Message {
                role: "user".to_string(),
                content: user_prompt,
            }],
            system: system_prompt,
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
            .unwrap_or_default();

        // Parse the wordlist from the response
        let wordlist = self.parse_wordlist_response(&text);

        Ok(wordlist)
    }

    /// Generate an attack surface report based on analysis and probe results
    pub async fn generate_attack_report(
        &self,
        analysis_summary: &str,
        target_url: &str,
        analysis: &TechAnalysis,
        probe_results: &[ProbeResult],
    ) -> Result<String> {
        let system_prompt = self.build_attack_report_system_prompt();
        let user_prompt = self.build_attack_report_user_prompt(
            analysis_summary,
            target_url,
            analysis,
            probe_results,
        );

        let request = ClaudeRequest {
            model: CLAUDE_MODEL.to_string(),
            max_tokens: 4096,
            messages: vec![Message {
                role: "user".to_string(),
                content: user_prompt,
            }],
            system: system_prompt,
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

        let report = claude_response
            .content
            .first()
            .map(|c| c.text.clone())
            .unwrap_or_default();

        Ok(report)
    }

    fn build_attack_report_system_prompt(&self) -> String {
        r#"You are an expert penetration tester analyzing reconnaissance data. Your job is to identify WHERE BEHAVIOR CHANGES - not just enumerate what exists.

CORE PRINCIPLE: Useful pentest info answers these questions:
1. Where does user input cross a trust boundary?
2. Where does auth/authorization logic exist?
3. Where does server-side code execute conditionally?
4. Where does the app behave differently than expected?

WHAT TO IGNORE (noise):
- Static assets (_next/static, .js, .css, fonts, images)
- React/Next.js internals that don't affect security
- 404s on guessed paths
- Normal 200s on public content

WHAT TO HIGHLIGHT (signal):
- Non-200 responses that expect parameters (400s indicate input surfaces)
- Endpoints accepting user input (especially URL params like /_next/image)
- Dev-only endpoints in production (__nextjs_*, actuator, debug)
- Auth-adjacent paths (but note if they're client bundles vs server routes)
- Behavioral anomalies (same path, different responses)

OUTPUT FORMAT (ONLY include sections with real findings):

### Input Surfaces
[Endpoints that accept user input - note WHAT input and WHAT to test]

### Behavioral Anomalies
[Non-200s, redirects, or responses that indicate state/logic]

### Misconfigurations
[Dev endpoints, exposed internals, missing auth]

### Attack Priority
[Numbered list of what to try FIRST with specific payloads/tests]

IMPORTANT:
- If you see client-side bundled paths (e.g., /_next/static/chunks/api/auth/*), note these are NOT server routes - suggest testing the actual server endpoint (e.g., /api/auth/login)
- For each finding, include a concrete test command or payload
- If nothing actionable, output only: "No notable findings."
- Quality over quantity - 3 real findings beats 20 theoretical ones"#.to_string()
    }

    fn build_attack_report_user_prompt(
        &self,
        analysis_summary: &str,
        target_url: &str,
        analysis: &TechAnalysis,
        probe_results: &[ProbeResult],
    ) -> String {
        // Build structured data about what we found
        let mut endpoints_info = String::new();
        if !analysis.api_endpoints.is_empty() {
            endpoints_info.push_str("API Endpoints Found:\n");
            for endpoint in &analysis.api_endpoints {
                endpoints_info.push_str(&format!("  - {}\n", endpoint));
            }
        }

        let mut probe_info = String::new();
        if !probe_results.is_empty() {
            probe_info.push_str("Probe Results:\n");
            for result in probe_results.iter().take(20) {
                probe_info.push_str(&format!("  {} -> {}\n", result.url, result.status_code));
                if let Some(ref server) = result.server {
                    probe_info.push_str(&format!("    Server: {}\n", server));
                }
                if let Some(ref powered_by) = result.powered_by {
                    probe_info.push_str(&format!("    X-Powered-By: {}\n", powered_by));
                }
            }
        }

        format!(
            r#"Target: {}

RECONNAISSANCE SUMMARY:
{}

{}

{}

Based on this data, provide an attack surface report. Remember:
- Only include actionable findings
- If nothing stands out, say "No notable findings."
- Focus on what a pentester should try FIRST
- Include specific endpoints to target
- Note any version info that suggests known vulnerabilities"#,
            target_url, analysis_summary, endpoints_info, probe_info
        )
    }

    fn build_system_prompt(&self) -> String {
        r#"You are an expert penetration tester and web security researcher specializing in content discovery. Your task is to generate targeted wordlists for directory/file enumeration based on detected technologies and patterns.

Guidelines:
1. Generate paths that are SPECIFIC to the detected technology/framework
2. Include common hidden endpoints, admin panels, debug endpoints, and sensitive files
3. Consider API versioning patterns (v1, v2, v3, also /api/latest, /api/beta)
4. Include common backup file patterns for the detected tech stack
5. Consider development/staging endpoints that may be exposed
6. Output ONLY the wordlist, one path per line, starting with /
7. Do not include explanations, comments, or markdown formatting
8. Generate between 100-300 high-value paths
9. Prioritize paths likely to expose sensitive information or functionality

Categories to consider:

SOURCE CODE & VERSION CONTROL:
- Git exposure: /.git/config, /.git/HEAD, /.gitignore
- SVN: /.svn/entries, /.svn/wc.db
- Mercurial: /.hg/hgrc
- IDE files: /.idea/, /.vscode/

CONFIGURATION & SECRETS:
- Environment files: /.env, /.env.local, /.env.production, /.env.backup
- Config files: /config.json, /config.yml, /settings.py, /application.properties
- Framework configs: /web.config, /.htaccess, /nginx.conf
- Secrets: /.aws/credentials, /.docker/config.json, /secrets.yml

CLOUD & INFRASTRUCTURE:
- AWS: /latest/meta-data/, /.aws/, /aws.yml
- Kubernetes: /api/v1/namespaces, /healthz, /readyz, /livez
- Docker: /.docker/, /docker-compose.yml, /Dockerfile
- Spring Actuator: /actuator, /actuator/env, /actuator/health, /actuator/beans, /actuator/heapdump
- Prometheus: /metrics, /-/healthy

CI/CD ARTIFACTS:
- Jenkins: /jenkins/, /script, /asynchPeople/
- GitLab: /.gitlab-ci.yml, /ci/
- GitHub: /.github/workflows/
- Build files: /Jenkinsfile, /build.gradle, /pom.xml

DEBUG & DEVELOPMENT:
- Debug endpoints: /debug, /trace, /console, /phpinfo.php, /info.php
- Profiling: /debug/pprof/, /__debug__/, /silk/
- Error pages: /elmah.axd, /error_log, /errors/
- Test files: /test, /tests/, /spec/, /_test

AUTHENTICATION & SECURITY:
- Auth endpoints: /oauth/, /oauth2/, /sso/, /saml/, /cas/
- Token endpoints: /token, /.well-known/openid-configuration, /jwks.json
- Password reset: /reset-password, /forgot-password, /password/reset
- Session: /session, /logout, /signout

ADMIN & MANAGEMENT:
- Admin panels: /admin, /administrator, /manage, /management, /portal
- Dashboard: /dashboard, /console, /cpanel, /webadmin
- CMS admin: /wp-admin, /administrator, /user/login, /admin/login

BACKUP & TEMPORARY FILES:
- Backup extensions: .bak, .backup, .old, .orig, .save, .swp, ~
- Archive files: .zip, .tar.gz, .sql, .dump
- Temporary: /tmp/, /temp/, /cache/, /backup/

FILE UPLOAD & STORAGE:
- Upload paths: /upload, /uploads, /files, /media, /attachments
- Storage: /storage, /static, /assets, /public
- User content: /user-content/, /user-uploads/

API PATTERNS:
- GraphQL: /graphql, /graphiql, /playground, /altair
- REST conventions: Follow detected patterns with CRUD variations
- Internal APIs: /internal/, /private/, /_internal/

Focus on quality over quantity - each path should have a reasonable chance of existing based on the detected patterns."#.to_string()
    }

    fn build_user_prompt(&self, analysis_summary: &str, target_url: &str) -> String {
        format!(
            r#"Target: {}

RECONNAISSANCE DATA:
{}

Generate a targeted wordlist based on the above analysis.

CRITICAL - EXTRAPOLATE ONLY FROM DISCOVERED PATTERNS:

IMPORTANT: Only generate CRUD variations (/new, /create, /edit, /delete, /search, etc.) for resources
that ACTUALLY APPEAR in the reconnaissance data above. Do NOT speculatively generate CRUD variations
for resources like /api/imports, /api/exports, /api/files unless they appear in the recon.

If you see API endpoints like /api/products or /api/users in the recon, generate:
- /admin (always include admin panel)
- /api/admin (admin API namespace)
- /api/admin/users, /api/admin/diagnostics, /api/admin/settings
- /api/auth/me, /api/auth/register, /api/auth/refresh, /api/auth/forgot-password
- /api/[discovered_resource]/{{id}} patterns for resources IN THE RECON
- /api/[discovered_resource]/{{id}}/[subresource] for resources IN THE RECON

For ONLY the resources actually found in recon data (e.g., if /api/products exists, generate):
- /api/products/{{id}}
- /api/products/new, /api/products/create, /api/products/search

DO NOT generate CRUD variations for resources not in the recon (e.g., don't add /api/imports/create
unless /api/imports was discovered).

Common related resources to try (base paths only, no CRUD suffixes):
- /api/reviews, /api/comments, /api/orders, /api/users, /api/auth

ALWAYS INCLUDE (regardless of detected stack):
- /admin
- /admin/login
- /admin/dashboard
- /api/admin
- /api/health
- /api/status
- /api/version
- /api/config
- /api/debug
- /api/metrics
- /.env
- /.git/config
- /swagger.json
- /api-docs
- /graphql

FRAMEWORK-SPECIFIC (based on detected tech):
- Next.js: /_next/data/, /api/, /__nextjs_original-stack-frame, /_next/image
- Rails: /rails/info, /rails/mailers, /sidekiq, /admin
- Django: /admin/, /__debug__/, /static/admin/
- Spring: /actuator/*, /swagger-ui.html, /v3/api-docs

OUTPUT RULES:
- Each path on its own line, starting with /
- Use {{id}} for parameterized segments (e.g., /api/products/{{id}})
- No explanations, no markdown, no comments
- Generate 150-300 paths
- Quality over quantity but DO NOT skip common patterns

Output the wordlist now:"#,
            target_url, analysis_summary
        )
    }

    fn parse_wordlist_response(&self, response: &str) -> Vec<String> {
        let mut paths: Vec<String> = Vec::new();

        for line in response.lines() {
            let line = line.trim();
            if line.is_empty() || !line.starts_with('/') {
                continue;
            }

            // Clean up any trailing comments
            let clean_line = if let Some(idx) = line.find('#') {
                line[..idx].trim()
            } else {
                line
            };

            if clean_line.is_empty() {
                continue;
            }

            // Keep parameterized paths as-is - they'll be expanded by the mutation engine
            // This includes patterns like /api/products/{id} or /api/products/{{id}}
            paths.push(clean_line.to_string());
        }

        // Deduplicate
        paths.sort();
        paths.dedup();
        paths
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_wordlist_response() {
        let client = ClaudeClient {
            client: Client::new(),
            api_key: "test".to_string(),
        };

        let response = r#"/api/admin
/api/users
/api/v1/config
# This is a comment
/debug
/api/internal  # inline comment
not-a-path
/valid/path
/api/products/{id}"#;

        let wordlist = client.parse_wordlist_response(response);

        assert_eq!(wordlist.len(), 7);
        assert!(wordlist.contains(&"/api/admin".to_string()));
        assert!(wordlist.contains(&"/api/users".to_string()));
        assert!(wordlist.contains(&"/api/v1/config".to_string()));
        assert!(wordlist.contains(&"/debug".to_string()));
        assert!(wordlist.contains(&"/api/internal".to_string()));
        assert!(wordlist.contains(&"/valid/path".to_string()));
        assert!(!wordlist.contains(&"not-a-path".to_string()));
        // Parameterized paths are now kept as-is for mutation engine to handle
        assert!(wordlist.contains(&"/api/products/{id}".to_string()));
    }
}
