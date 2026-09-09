use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechnologyDetection {
    pub name: String,
    pub version: Option<String>,
    pub confidence: f32, // 0.0 to 1.0
    pub evidence: Vec<String>,
}

pub fn fingerprint_tech(headers: &HeaderMap, body: &str, _status_code: u16) -> Vec<TechnologyDetection> {
    let mut detections = Vec::new();
    let body_lower = body.to_lowercase();

    // 1. Cloudflare WAF / CDN
    let mut cf_evidence = Vec::new();
    if let Some(server) = headers.get("server").and_then(|v| v.to_str().ok()) {
        if server.to_lowercase().contains("cloudflare") {
            cf_evidence.push(format!("Server header: {}", server));
        }
    }
    if headers.contains_key("cf-ray") {
        cf_evidence.push("CF-Ray header present".to_string());
    }
    if headers.contains_key("cf-cache-status") {
        cf_evidence.push("CF-Cache-Status header present".to_string());
    }
    if !cf_evidence.is_empty() {
        detections.push(TechnologyDetection {
            name: "Cloudflare".to_string(),
            version: None,
            confidence: 0.95,
            evidence: cf_evidence,
        });
    }

    // 2. GitHub Pages / GitHub Infrastructure
    let mut gh_evidence = Vec::new();
    if let Some(server) = headers.get("server").and_then(|v| v.to_str().ok()) {
        if server.to_lowercase().contains("github.com") || server.to_lowercase().contains("github.io") {
            gh_evidence.push(format!("Server header: {}", server));
        }
    }
    if headers.contains_key("x-github-request-id") {
        gh_evidence.push("X-GitHub-Request-Id header present".to_string());
    }
    if !gh_evidence.is_empty() {
        detections.push(TechnologyDetection {
            name: "GitHub Infrastructure".to_string(),
            version: None,
            confidence: 0.95,
            evidence: gh_evidence,
        });
    }

    // 3. Nginx Web Server
    if let Some(server) = headers.get("server").and_then(|v| v.to_str().ok()) {
        if server.to_lowercase().contains("nginx") {
            let version = server
                .split('/')
                .nth(1)
                .map(|v| v.trim().to_string());
            detections.push(TechnologyDetection {
                name: "Nginx".to_string(),
                version,
                confidence: 0.90,
                evidence: vec![format!("Server header: {}", server)],
            });
        }
    }

    // 4. Gunicorn Python Server
    if let Some(server) = headers.get("server").and_then(|v| v.to_str().ok()) {
        if server.to_lowercase().contains("gunicorn") {
            let version = server
                .split('/')
                .nth(1)
                .map(|v| v.trim().to_string());
            detections.push(TechnologyDetection {
                name: "Gunicorn".to_string(),
                version,
                confidence: 0.90,
                evidence: vec![format!("Server header: {}", server)],
            });
        }
    }

    // 5. ASP.NET / Kestrel
    if let Some(server) = headers.get("server").and_then(|v| v.to_str().ok()) {
        if server.to_lowercase().contains("kestrel") {
            detections.push(TechnologyDetection {
                name: "ASP.NET Kestrel".to_string(),
                version: None,
                confidence: 0.90,
                evidence: vec![format!("Server header: {}", server)],
            });
        }
    }

    // 6. Spring Boot Framework
    let mut spring_evidence = Vec::new();
    if body_lower.contains("whitelabel error page") {
        spring_evidence.push("Body signature: Whitelabel Error Page".to_string());
    }
    if body_lower.contains("timestamp") && body_lower.contains("status") && body_lower.contains("error") && body_lower.contains("path") {
        spring_evidence.push("Spring Boot default error JSON schema format".to_string());
    }
    if !spring_evidence.is_empty() {
        detections.push(TechnologyDetection {
            name: "Spring Boot".to_string(),
            version: None,
            confidence: 0.85,
            evidence: spring_evidence,
        });
    }

    // 7. WordPress CMS
    let mut wp_evidence = Vec::new();
    if body_lower.contains("wp-content") || body_lower.contains("wp-includes") {
        wp_evidence.push("Body signature: wp-content/wp-includes references".to_string());
    }
    if let Some(cookie) = headers.get("set-cookie").and_then(|v| v.to_str().ok()) {
        if cookie.contains("wordpress_") {
            wp_evidence.push(format!("Set-Cookie header: {}", cookie));
        }
    }
    if !wp_evidence.is_empty() {
        detections.push(TechnologyDetection {
            name: "WordPress".to_string(),
            version: None,
            confidence: 0.90,
            evidence: wp_evidence,
        });
    }

    // 8. Varnish Cache
    if let Some(server) = headers.get("server").and_then(|v| v.to_str().ok()) {
        if server.to_lowercase().contains("varnish") {
            detections.push(TechnologyDetection {
                name: "Varnish Cache".to_string(),
                version: None,
                confidence: 0.90,
                evidence: vec![format!("Server header: {}", server)],
            });
        }
    }

    // 9. Atlassian Statuspage / Edge
    if let Some(server) = headers.get("server").and_then(|v| v.to_str().ok()) {
        if server.to_lowercase().contains("atlassianedge") {
            detections.push(TechnologyDetection {
                name: "Atlassian Edge".to_string(),
                version: None,
                confidence: 0.95,
                evidence: vec![format!("Server header: {}", server)],
            });
        }
    }

    // 10. Express / Node.js
    if let Some(powered_by) = headers.get("x-powered-by").and_then(|v| v.to_str().ok()) {
        if powered_by.to_lowercase().contains("express") {
            detections.push(TechnologyDetection {
                name: "Express.js".to_string(),
                version: None,
                confidence: 0.90,
                evidence: vec![format!("X-Powered-By header: {}", powered_by)],
            });
        }
    }

    detections
}
