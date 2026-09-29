//! Bounded local JavaScript request intelligence. This module performs no
//! network I/O and never promotes extracted non-GET calls into active traffic.

use crate::scan::scope::ScopePolicy;
use regex::Regex;
use reqwest::Url;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

static ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)(?:\b(?:const|let|var)\s+)?([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*=\s*[\"']([^\"'\r\n]{0,500})[\"']"#).unwrap()
});
static MEMBER_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:[A-Za-z_$][\w$]*\.)+?(get|post|put|patch|delete|request)\s*\("#).unwrap()
});
static FETCH_CALL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)\bfetch\s*\("#).unwrap());
static XHR_OPEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:XMLHttpRequest|[A-Za-z_$][\w$]*)\.open\s*\("#).unwrap()
});
static STRING_LITERAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"[\"']([^\"'\r\n]{1,300})[\"']"#).unwrap());
static STATIC_TEMPLATE_LITERAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"`([^`\r\n$]{1,300})`"#).unwrap());
static WEBSOCKET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)new\s+WebSocket\s*\(\s*[\"']([^\"']{1,300})[\"']"#).unwrap()
});
static OBJECT_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?:^|[,{}]\s*)([A-Za-z_$][A-Za-z0-9_$-]{0,63})\s*:"#).unwrap());

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct JavaScriptCandidate {
    pub kind: &'static str,
    pub raw_value: String,
    pub resolved_url: Option<String>,
    pub method: Option<String>,
    pub parameters: BTreeSet<(String, String)>,
}

pub fn extract(
    script: &str,
    _source_url: &Url,
    resolution_base: &Url,
    scope: &ScopePolicy,
) -> Vec<JavaScriptCandidate> {
    let constants = string_constants(script);
    let mut candidates = Vec::new();
    for captures in MEMBER_CALL.captures_iter(script) {
        let Some(whole) = captures.get(0) else {
            continue;
        };
        let call_method = captures.get(1).unwrap().as_str().to_ascii_uppercase();
        let Some(arguments) = call_arguments(script, whole.end()) else {
            continue;
        };
        let parts = split_top_level(arguments, ',');
        let (method, url_index) = if call_method == "REQUEST" {
            let explicit = parts
                .first()
                .and_then(|value| literal_or_constant(value, &constants));
            if explicit.as_deref().is_some_and(is_http_method) {
                (explicit.unwrap().to_ascii_uppercase(), 1)
            } else {
                (
                    option_method(arguments).unwrap_or_else(|| "UNKNOWN".into()),
                    0,
                )
            }
        } else {
            (call_method, 0)
        };
        if let Some(expression) = parts.get(url_index)
            && let Some(raw) = static_expression(expression, &constants)
        {
            push_http_call(
                &mut candidates,
                &raw,
                &method,
                parts.get(url_index + 1).copied().unwrap_or_default(),
                resolution_base,
                scope,
            );
        }
    }
    for whole in FETCH_CALL.find_iter(script) {
        let Some(arguments) = call_arguments(script, whole.end()) else {
            continue;
        };
        let parts = split_top_level(arguments, ',');
        if let Some(raw) = parts
            .first()
            .and_then(|value| static_expression(value, &constants))
        {
            push_http_call(
                &mut candidates,
                &raw,
                &option_method(arguments).unwrap_or_else(|| "GET".into()),
                parts.get(1).copied().unwrap_or_default(),
                resolution_base,
                scope,
            );
        }
    }
    for whole in XHR_OPEN.find_iter(script) {
        let Some(arguments) = call_arguments(script, whole.end()) else {
            continue;
        };
        let parts = split_top_level(arguments, ',');
        if let (Some(method), Some(raw)) = (
            parts
                .first()
                .and_then(|value| literal_or_constant(value, &constants)),
            parts
                .get(1)
                .and_then(|value| static_expression(value, &constants)),
        ) {
            push_http_call(
                &mut candidates,
                &raw,
                &method.to_ascii_uppercase(),
                "",
                resolution_base,
                scope,
            );
        }
    }
    for captures in STRING_LITERAL.captures_iter(script) {
        if let Some(value) = captures.get(1)
            && is_likely_route(value.as_str())
        {
            push_url_candidate(
                &mut candidates,
                "url_literal",
                value.as_str(),
                resolution_base,
                scope,
            );
        }
    }
    for captures in STATIC_TEMPLATE_LITERAL.captures_iter(script) {
        if let Some(value) = captures.get(1)
            && is_likely_route(value.as_str())
        {
            push_url_candidate(
                &mut candidates,
                "url_literal",
                value.as_str(),
                resolution_base,
                scope,
            );
        }
    }
    for captures in WEBSOCKET.captures_iter(script) {
        if let Some(value) = captures.get(1) {
            let raw = value.as_str();
            let resolved = resolution_base.join(raw).ok();
            if resolved.as_ref().is_some_and(|url| {
                matches!(url.scheme(), "ws" | "wss")
                    && url.host_str().is_some_and(|host| {
                        crate::scan::normalize::NormalizedHostname::new(host)
                            .is_some_and(|host| scope.is_in_scope(&host))
                    })
            }) {
                candidates.push(JavaScriptCandidate {
                    kind: "websocket",
                    raw_value: raw.into(),
                    resolved_url: resolved.map(|url| url.to_string()),
                    method: None,
                    parameters: BTreeSet::new(),
                });
            }
        }
    }
    if script.to_ascii_lowercase().contains("graphql") {
        candidates.push(JavaScriptCandidate {
            kind: "graphql_hint",
            raw_value: "graphql".into(),
            resolved_url: None,
            method: None,
            parameters: BTreeSet::new(),
        });
    }
    candidates.sort();
    candidates.dedup();
    candidates
}

fn string_constants(script: &str) -> BTreeMap<String, String> {
    ASSIGNMENT
        .captures_iter(script)
        .filter_map(|capture| {
            Some((
                capture.get(1)?.as_str().into(),
                capture.get(2)?.as_str().into(),
            ))
        })
        .collect()
}

fn call_arguments(script: &str, start: usize) -> Option<&str> {
    let bytes = script.as_bytes();
    let mut quote = None;
    let mut escaped = false;
    let mut depth = 1usize;
    for (index, byte) in bytes
        .iter()
        .copied()
        .enumerate()
        .take(bytes.len().min(start + 2_000))
        .skip(start)
    {
        if let Some(active) = quote {
            if escaped {
                escaped = false;
                continue;
            }
            if byte == b'\\' {
                escaped = true;
                continue;
            }
            if byte == active {
                quote = None;
            }
            continue;
        }
        match byte {
            b'\'' | b'"' | b'`' => quote = Some(byte),
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return script.get(start..index);
                }
            }
            _ => {}
        }
    }
    None
}

fn split_top_level(value: &str, separator: char) -> Vec<&str> {
    let mut result = Vec::new();
    let mut start = 0;
    let mut depth = 0i32;
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in value.char_indices() {
        if let Some(active) = quote {
            if escaped {
                escaped = false;
                continue;
            }
            if character == '\\' {
                escaped = true;
                continue;
            }
            if character == active {
                quote = None;
            }
            continue;
        }
        match character {
            '\'' | '"' | '`' => quote = Some(character),
            '(' | '{' | '[' => depth += 1,
            ')' | '}' | ']' => depth -= 1,
            found if found == separator && depth == 0 => {
                result.push(value[start..index].trim());
                start = index + found.len_utf8();
            }
            _ => {}
        }
    }
    result.push(value[start..].trim());
    result
}

fn static_expression(expression: &str, constants: &BTreeMap<String, String>) -> Option<String> {
    let expression = expression.trim();
    if expression.starts_with('`') && expression.ends_with('`') {
        let mut output = String::new();
        let mut rest = &expression[1..expression.len() - 1];
        while let Some(start) = rest.find("${") {
            output.push_str(&rest[..start]);
            let end = rest[start + 2..].find('}')? + start + 2;
            let name = rest[start + 2..end].trim();
            output.push_str(constants.get(name).map(String::as_str).unwrap_or("{value}"));
            rest = &rest[end + 1..];
        }
        output.push_str(rest);
        return normalize_static_route(output);
    }
    let mut output = String::new();
    for part in split_top_level(expression, '+') {
        let part = part.trim();
        if part.len() >= 2
            && matches!(part.as_bytes()[0], b'\'' | b'"')
            && part.as_bytes()[0] == *part.as_bytes().last().unwrap()
        {
            output.push_str(&part[1..part.len() - 1]);
        } else if let Some(value) = constants.get(part) {
            output.push_str(value);
        } else if !part.is_empty()
            && part
                .chars()
                .all(|value| value.is_ascii_alphanumeric() || matches!(value, '_' | '$' | '.'))
        {
            output.push_str("{value}");
        } else {
            return None;
        }
    }
    normalize_static_route(output)
}

fn normalize_static_route(mut value: String) -> Option<String> {
    if value.starts_with("{value}") {
        let marker = ["/api/", "/rest/", "/b2b/", "/graphql", "/oauth/"]
            .into_iter()
            .filter_map(|marker| value.find(marker))
            .min()?;
        value = value[marker..].to_string();
    }
    let has_static_content = value
        .replace("{value}", "")
        .chars()
        .any(|character| character.is_ascii_alphanumeric());
    (has_static_content && is_likely_route(&value)).then_some(value)
}

fn literal_or_constant(expression: &str, constants: &BTreeMap<String, String>) -> Option<String> {
    let expression = expression.trim();
    if expression.len() >= 2
        && matches!(expression.as_bytes()[0], b'\'' | b'"')
        && expression.as_bytes()[0] == *expression.as_bytes().last()?
    {
        Some(expression[1..expression.len() - 1].into())
    } else {
        constants.get(expression).cloned()
    }
}

fn option_method(value: &str) -> Option<String> {
    Regex::new(r#"(?i)\bmethod\s*:\s*[\"'](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)[\"']"#)
        .unwrap()
        .captures(value)
        .and_then(|capture| capture.get(1))
        .map(|value| value.as_str().to_ascii_uppercase())
}

fn is_http_method(value: &str) -> bool {
    matches!(
        value.to_ascii_uppercase().as_str(),
        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
    )
}

fn push_http_call(
    candidates: &mut Vec<JavaScriptCandidate>,
    raw: &str,
    method: &str,
    body: &str,
    source_url: &Url,
    scope: &ScopePolicy,
) {
    let Some(resolved_url) = resolve_route(raw, source_url, scope) else {
        return;
    };
    let mut parameters = Url::parse(&resolved_url)
        .ok()
        .into_iter()
        .flat_map(|url| {
            url.query_pairs()
                .map(|(name, _)| ("query".into(), name.into_owned()))
                .collect::<Vec<_>>()
        })
        .collect::<BTreeSet<_>>();
    if matches!(method, "POST" | "PUT" | "PATCH" | "DELETE") {
        parameters.extend(OBJECT_KEY.captures_iter(body).filter_map(|capture| {
            let name = capture.get(1)?.as_str();
            (!matches!(
                name,
                "headers" | "method" | "body" | "params" | "observe" | "responseType"
            ))
            .then(|| ("body".into(), name.into()))
        }));
    }
    candidates.push(JavaScriptCandidate {
        kind: "http_call",
        raw_value: raw.into(),
        resolved_url: Some(resolved_url),
        method: Some(if is_http_method(method) {
            method.to_ascii_uppercase()
        } else {
            "UNKNOWN".into()
        }),
        parameters,
    });
}

fn push_url_candidate(
    candidates: &mut Vec<JavaScriptCandidate>,
    kind: &'static str,
    raw: &str,
    source_url: &Url,
    scope: &ScopePolicy,
) {
    if let Some(resolved_url) = resolve_route(raw, source_url, scope) {
        candidates.push(JavaScriptCandidate {
            kind,
            raw_value: raw.into(),
            resolved_url: Some(resolved_url),
            method: None,
            parameters: BTreeSet::new(),
        });
    }
}

fn resolve_route(raw: &str, source_url: &Url, scope: &ScopePolicy) -> Option<String> {
    if !is_likely_route(raw) {
        return None;
    }
    let url = if raw.starts_with("http://")
        || raw.starts_with("https://")
        || raw.starts_with('/')
        || raw.starts_with("./")
        || raw.starts_with("../")
    {
        source_url.join(raw).ok()?
    } else {
        let mut root = source_url.clone();
        root.set_path("/");
        root.set_query(None);
        root.set_fragment(None);
        root.join(raw).ok()?
    };
    (scope.allows_redirect_url(&url)
        && crate::scan::normalize::normalize_endpoint(url.as_str(), None).is_some())
    .then(|| url.to_string())
}

fn is_likely_route(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 300
        || value.contains("&quot;")
        || value.chars().any(char::is_whitespace)
    {
        return false;
    }
    if value
        .chars()
        .any(|character| matches!(character, '(' | ')' | '[' | ']' | '\\' | '`' | ',' | ';'))
    {
        return false;
    }
    if value.starts_with("http://")
        || value.starts_with("https://")
        || value.starts_with('/')
        || value.starts_with("./")
        || value.starts_with("../")
    {
        return true;
    }
    let first = value
        .split('/')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    value.contains('/')
        && !matches!(
            first.as_str(),
            "application" | "audio" | "font" | "image" | "text" | "video"
        )
        && first.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '{' | '}')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_modern_spa_calls_and_rejects_minified_code_fragments() {
        let scope = ScopePolicy::new(vec!["example.com".into()]);
        let source = Url::parse("https://app.example.com/assets/main.js").unwrap();
        let script = r#"
            const apiBase = "/rest";
            this.http.get(apiBase + "/products/search?q=juice");
            httpClient.post("/rest/user/login", {email: user, password: pass});
            service.get("rest/products/search");
            e.get("/api/user-profile");
            client.request("PUT", `/b2b/v2/orders/${id}`, {status: next});
            fetch("/api/Users", {method: "DELETE", body: {userId: id}});
            const broken = "/g,%60&quot;%60).replace/";
        "#;
        let candidates = extract(script, &source, &source, &scope);
        let calls: Vec<_> = candidates
            .iter()
            .filter(|value| value.kind == "http_call")
            .collect();
        assert_eq!(calls.len(), 6);
        assert!(calls.iter().any(|value| value.resolved_url.as_deref()
            == Some("https://app.example.com/rest/user/login")
            && value.method.as_deref() == Some("POST")
            && value.parameters.contains(&("body".into(), "email".into()))));
        assert!(calls.iter().any(|value| value.resolved_url.as_deref()
            == Some("https://app.example.com/rest/products/search")
            && value.method.as_deref() == Some("GET")));
        assert!(
            calls
                .iter()
                .any(|value| value.raw_value.contains("/b2b/v2/orders/")
                    && value.method.as_deref() == Some("PUT"))
        );
        assert!(
            !candidates
                .iter()
                .any(|value| value.raw_value.contains("replace"))
        );
        assert!(
            !candidates
                .iter()
                .any(|value| value.kind == "parameter_name")
        );
    }

    #[test]
    fn resolves_browser_requests_against_document_not_script_or_map() {
        let scope = ScopePolicy::new(vec!["example.com".into()]);
        let document = Url::parse("https://example.com/app/").unwrap();
        let script = Url::parse("https://example.com/assets/main.js").unwrap();
        let map = Url::parse("https://example.com/assets/main.js.map").unwrap();

        for source in [&script, &map] {
            let candidates = extract(r#"fetch("./api/users")"#, source, &document, &scope);
            assert!(candidates.iter().any(|candidate| {
                candidate.kind == "http_call"
                    && candidate.resolved_url.as_deref()
                        == Some("https://example.com/app/api/users")
            }));
            assert!(
                !candidates
                    .iter()
                    .any(|candidate| candidate.resolved_url.as_deref()
                        == Some("https://example.com/assets/api/users"))
            );
        }
    }

    #[test]
    fn extracts_static_backtick_route_literals() {
        let scope = ScopePolicy::new(vec!["example.com".into()]);
        let source = Url::parse("https://example.com/main.js").unwrap();
        let candidates = extract(
            "const link = `./redirect?to=https://allowed.example/path`;",
            &source,
            &source,
            &scope,
        );
        let candidate = candidates
            .iter()
            .find(|candidate| candidate.kind == "url_literal")
            .unwrap();
        let resolved = Url::parse(candidate.resolved_url.as_deref().unwrap()).unwrap();
        assert_eq!(resolved.path(), "/redirect");
        assert_eq!(
            resolved
                .query_pairs()
                .find(|(name, _)| name == "to")
                .unwrap()
                .1,
            "https://allowed.example/path"
        );
    }
}
