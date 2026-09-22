//! Local JavaScript intelligence. This module performs no network I/O and never
//! promotes an extracted string into an active request.

use crate::scan::scope::ScopePolicy;
use regex::Regex;
use reqwest::Url;
use std::collections::BTreeSet;
use std::sync::LazyLock;

static CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(fetch|axios\.(?:get|post|put|patch|delete)|XMLHttpRequest\.open)\s*\([^\"']*[\"']([^\"']{1,300})[\"']"#).unwrap()
});
static URL_LITERAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"[\"']((?:https?://|/)(?:[^\"'\s<>]{1,300}))[\"']"#).unwrap());
static WEBSOCKET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)new\s+WebSocket\s*\(\s*[\"']([^\"']{1,300})[\"']"#).unwrap()
});
static PARAMETER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:[?&]|[\{,]\s*)(([A-Za-z][A-Za-z0-9_-]{0,63}))\s*(?:=|:)"#).unwrap()
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaScriptCandidate {
    pub kind: &'static str,
    pub raw_value: String,
    pub resolved_url: Option<String>,
}

pub fn extract(script: &str, source_url: &Url, scope: &ScopePolicy) -> Vec<JavaScriptCandidate> {
    let mut candidates = Vec::new();
    for captures in CALL.captures_iter(script) {
        if let Some(value) = captures.get(2) {
            push_url_candidate(
                &mut candidates,
                "http_call",
                value.as_str(),
                source_url,
                scope,
            );
        }
    }
    for captures in URL_LITERAL.captures_iter(script) {
        if let Some(value) = captures.get(1) {
            push_url_candidate(
                &mut candidates,
                "url_literal",
                value.as_str(),
                source_url,
                scope,
            );
        }
    }
    for captures in WEBSOCKET.captures_iter(script) {
        if let Some(value) = captures.get(1) {
            let raw = value.as_str();
            let resolved = source_url.join(raw).ok();
            if resolved.as_ref().is_some_and(|url| {
                matches!(url.scheme(), "ws" | "wss")
                    && url.host_str().is_some_and(|host| {
                        crate::scan::normalize::NormalizedHostname::new(host)
                            .is_some_and(|host| scope.is_in_scope(&host))
                    })
            }) {
                candidates.push(JavaScriptCandidate {
                    kind: "websocket",
                    raw_value: raw.to_string(),
                    resolved_url: resolved.map(|url| url.to_string()),
                });
            }
        }
    }
    if Regex::new(r"(?i)\b(graphql|gql)\b")
        .unwrap()
        .is_match(script)
    {
        candidates.push(JavaScriptCandidate {
            kind: "graphql_hint",
            raw_value: "graphql".into(),
            resolved_url: None,
        });
    }
    let mut parameters = BTreeSet::new();
    for capture in PARAMETER.captures_iter(script) {
        if let Some(value) = capture.get(1) {
            parameters.insert(value.as_str().to_string());
        }
    }
    candidates.extend(parameters.into_iter().map(|raw_value| JavaScriptCandidate {
        kind: "parameter_name",
        raw_value,
        resolved_url: None,
    }));
    candidates.sort_by(|a, b| {
        (a.kind, &a.raw_value, &a.resolved_url).cmp(&(b.kind, &b.raw_value, &b.resolved_url))
    });
    candidates.dedup_by(|a, b| {
        a.kind == b.kind && a.raw_value == b.raw_value && a.resolved_url == b.resolved_url
    });
    candidates
}

fn push_url_candidate(
    candidates: &mut Vec<JavaScriptCandidate>,
    kind: &'static str,
    raw: &str,
    source_url: &Url,
    scope: &ScopePolicy,
) {
    let Ok(url) = source_url.join(raw) else {
        return;
    };
    if scope.allows_redirect_url(&url)
        && crate::scan::normalize::normalize_endpoint(url.as_str(), None).is_some()
    {
        candidates.push(JavaScriptCandidate {
            kind,
            raw_value: raw.to_string(),
            resolved_url: Some(url.to_string()),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_in_scope_intelligence_without_activating_candidates() {
        let scope = ScopePolicy::new(vec!["example.com".into()]);
        let source = Url::parse("https://app.example.com/assets/app.js").unwrap();
        let candidates = extract(
            "fetch('/api/users?id=1'); axios.post('https://api.example.com/v1/orders', {accountId: 1}); new WebSocket('wss://ws.example.com/socket'); const g = 'graphql';",
            &source,
            &scope,
        );
        assert!(candidates.iter().any(|c| c.kind == "http_call"
            && c.resolved_url.as_deref() == Some("https://app.example.com/api/users?id=1")));
        assert!(candidates.iter().any(|c| c.kind == "websocket"));
        assert!(candidates.iter().any(|c| c.kind == "graphql_hint"));
        assert!(
            candidates
                .iter()
                .any(|c| c.kind == "parameter_name" && c.raw_value == "accountId")
        );
    }
}
